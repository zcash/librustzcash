//! Functions for creating transactions.
//!
use rusqlite::{named_params, Row};
use std::convert::TryInto;

use ff::PrimeField;

use zcash_primitives::{
    consensus::BlockHeight,
    merkle_tree::IncrementalWitness,
    sapling::{Diversifier, Rseed},
    transaction::components::Amount,
};

use zcash_client_backend::wallet::{AccountId, SpendableNote};

use crate::{error::SqliteClientError, WalletDb};

fn to_spendable_note(row: &Row) -> Result<SpendableNote, SqliteClientError> {
    let diversifier = {
        let d: Vec<_> = row.get(0)?;
        if d.len() != 11 {
            return Err(SqliteClientError::CorruptedData(
                "Invalid diversifier length".to_string(),
            ));
        }
        let mut tmp = [0; 11];
        tmp.copy_from_slice(&d);
        Diversifier(tmp)
    };

    let note_value = Amount::from_i64(row.get(1)?).unwrap();

    let rseed = {
        let rcm_bytes: Vec<_> = row.get(2)?;

        // We store rcm directly in the data DB, regardless of whether the note
        // used a v1 or v2 note plaintext, so for the purposes of spending let's
        // pretend this is a pre-ZIP 212 note.
        let rcm = jubjub::Fr::from_repr(
            rcm_bytes[..]
                .try_into()
                .map_err(|_| SqliteClientError::InvalidNote)?,
        )
        .ok_or(SqliteClientError::InvalidNote)?;
        Rseed::BeforeZip212(rcm)
    };

    let witness = {
        let d: Vec<_> = row.get(3)?;
        IncrementalWitness::read(&d[..])?
    };

    Ok(SpendableNote {
        diversifier,
        note_value,
        rseed,
        witness,
    })
}

pub fn get_spendable_notes<P>(
    wdb: &WalletDb<P>,
    account: AccountId,
    anchor_height: BlockHeight,
) -> Result<Vec<SpendableNote>, SqliteClientError> {
    let mut stmt_select_notes = wdb.conn.prepare(
        "SELECT diversifier, value, rcm, witness
            FROM received_notes
            INNER JOIN transactions ON transactions.id_tx = received_notes.tx
            INNER JOIN sapling_witnesses ON sapling_witnesses.note = received_notes.id_note
            WHERE account = :account
            AND spent IS NULL
            AND transactions.block <= :anchor_height
            AND sapling_witnesses.block = :anchor_height",
    )?;

    // Select notes
    let notes = stmt_select_notes.query_and_then_named::<_, SqliteClientError, _>(
        named_params![
            ":account": &i64::from(account.0),
            ":anchor_height": &u32::from(anchor_height),
        ],
        to_spendable_note,
    )?;

    notes.collect::<Result<_, _>>()
}

pub fn select_spendable_notes<P>(
    wdb: &WalletDb<P>,
    account: AccountId,
    target_value: Amount,
    anchor_height: BlockHeight,
) -> Result<Vec<SpendableNote>, SqliteClientError> {
    // The goal of this SQL statement is to select the oldest notes until the required
    // value has been reached, and then fetch the witnesses at the desired height for the
    // selected notes. This is achieved in several steps:
    //
    // 1) Use a window function to create a view of all notes, ordered from oldest to
    //    newest, with an additional column containing a running sum:
    //    - Unspent notes accumulate the values of all unspent notes in that note's
    //      account, up to itself.
    //    - Spent notes accumulate the values of all notes in the transaction they were
    //      spent in, up to itself.
    //
    // 2) Select all unspent notes in the desired account, along with their running sum.
    //
    // 3) Select all notes for which the running sum was less than the required value, as
    //    well as a single note for which the sum was greater than or equal to the
    //    required value, bringing the sum of all selected notes across the threshold.
    //
    // 4) Match the selected notes against the witnesses at the desired height.
    let mut stmt_select_notes = wdb.conn.prepare(
        "WITH selected AS (
            WITH eligible AS (
                SELECT id_note, diversifier, value, rcm,
                    SUM(value) OVER
                        (PARTITION BY account, spent ORDER BY id_note) AS so_far
                FROM received_notes
                INNER JOIN transactions ON transactions.id_tx = received_notes.tx
                WHERE account = :account AND spent IS NULL AND transactions.block <= :anchor_height
            )
            SELECT * FROM eligible WHERE so_far < :target_value
            UNION
            SELECT * FROM (SELECT * FROM eligible WHERE so_far >= :target_value LIMIT 1)
        ), witnesses AS (
            SELECT note, witness FROM sapling_witnesses
            WHERE block = :anchor_height
        )
        SELECT selected.diversifier, selected.value, selected.rcm, witnesses.witness
        FROM selected
        INNER JOIN witnesses ON selected.id_note = witnesses.note",
    )?;

    // Select notes
    let notes = stmt_select_notes.query_and_then_named::<_, SqliteClientError, _>(
        named_params![
            ":account": &i64::from(account.0),
            ":anchor_height": &u32::from(anchor_height),
            ":target_value": &i64::from(target_value),
        ],
        to_spendable_note,
    )?;

    notes.collect::<Result<_, _>>()
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, BranchId},
        legacy::TransparentAddress,
        sapling::{note_encryption::try_sapling_output_recovery, prover::TxProver},
        transaction::{components::Amount, Transaction},
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use zcash_proofs::prover::LocalTxProver;

    use zcash_client_backend::{
        data_api::{chain::scan_cached_blocks, wallet::create_spend_to_address, WalletRead},
        wallet::OvkPolicy,
    };

    use crate::{
        chain::init::init_cache_database,
        tests::{self, fake_compact_block, insert_into_cache, sapling_activation_height},
        wallet::{
            get_balance, get_balance_at,
            init::{init_accounts_table, init_blocks_table, init_wallet_db},
        },
        AccountId, BlockDb, DataConnStmtCache, WalletDb,
    };

    fn test_prover() -> impl TxProver {
        match LocalTxProver::with_default_location() {
            Some(tx_prover) => tx_prover,
            None => {
                panic!("Cannot locate the Zcash parameters. Please run zcash-fetch-params or fetch-params.sh to download the parameters, and then re-run the tests.");
            }
        }
    }

    #[test]
    fn create_to_address_fails_on_incorrect_extsk() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();

        // Add two accounts to the wallet
        let extsk0 = ExtendedSpendingKey::master(&[]);
        let extsk1 = ExtendedSpendingKey::master(&[0]);
        let extfvks = [
            ExtendedFullViewingKey::from(&extsk0),
            ExtendedFullViewingKey::from(&extsk1),
        ];
        init_accounts_table(&db_data, &extfvks).unwrap();
        let to = extsk0.default_address().unwrap().1.into();

        // Invalid extsk for the given account should cause an error
        let mut db_write = db_data.get_update_ops().unwrap();
        match create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk1,
            &to,
            Amount::from_u64(1).unwrap(),
            None,
            OvkPolicy::Sender,
        ) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => assert_eq!(e.to_string(), "Incorrect ExtendedSpendingKey for account 0"),
        }

        match create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(1),
            &extsk0,
            &to,
            Amount::from_u64(1).unwrap(),
            None,
            OvkPolicy::Sender,
        ) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => assert_eq!(e.to_string(), "Incorrect ExtendedSpendingKey for account 1"),
        }
    }

    #[test]
    fn create_to_address_fails_with_no_blocks() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvks = [ExtendedFullViewingKey::from(&extsk)];
        init_accounts_table(&db_data, &extfvks).unwrap();
        let to = extsk.default_address().unwrap().1.into();

        // We cannot do anything if we aren't synchronised
        let mut db_write = db_data.get_update_ops().unwrap();
        match create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk,
            &to,
            Amount::from_u64(1).unwrap(),
            None,
            OvkPolicy::Sender,
        ) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => assert_eq!(e.to_string(), "Must scan blocks first"),
        }
    }

    #[test]
    fn create_to_address_fails_on_insufficient_balance() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();
        init_blocks_table(
            &db_data,
            BlockHeight::from(1u32),
            BlockHash([1; 32]),
            1,
            &[],
        )
        .unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvks = [ExtendedFullViewingKey::from(&extsk)];
        init_accounts_table(&db_data, &extfvks).unwrap();
        let to = extsk.default_address().unwrap().1.into();

        // Account balance should be zero
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), Amount::zero());

        // We cannot spend anything
        let mut db_write = db_data.get_update_ops().unwrap();
        match create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk,
            &to,
            Amount::from_u64(1).unwrap(),
            None,
            OvkPolicy::Sender,
        ) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => assert_eq!(
                e.to_string(),
                "Insufficient balance (have 0, need 1001 including fee)"
            ),
        }
    }

    #[test]
    fn create_to_address_fails_on_unverified_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Add funds to the wallet in a single note
        let value = Amount::from_u64(50000).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb);
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Verified balance matches total balance
        let (_, anchor_height) = (&db_data).get_target_and_anchor_heights().unwrap().unwrap();
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);
        assert_eq!(
            get_balance_at(&db_data, AccountId(0), anchor_height).unwrap(),
            value
        );

        // Add more funds to the wallet in a second note
        let (cb, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb);
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Verified balance does not include the second note
        let (_, anchor_height2) = (&db_data).get_target_and_anchor_heights().unwrap().unwrap();
        assert_eq!(
            get_balance(&db_data, AccountId(0)).unwrap(),
            (value + value).unwrap()
        );
        assert_eq!(
            get_balance_at(&db_data, AccountId(0), anchor_height2).unwrap(),
            value
        );

        // Spend fails because there are insufficient verified notes
        let extsk2 = ExtendedSpendingKey::master(&[]);
        let to = extsk2.default_address().unwrap().1.into();
        match create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk,
            &to,
            Amount::from_u64(70000).unwrap(),
            None,
            OvkPolicy::Sender,
        ) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => assert_eq!(
                e.to_string(),
                "Insufficient balance (have 50000, need 71000 including fee)"
            ),
        }

        // Mine blocks SAPLING_ACTIVATION_HEIGHT + 2 to 9 until just before the second
        // note is verified
        for i in 2..10 {
            let (cb, _) = fake_compact_block(
                sapling_activation_height() + i,
                cb.hash(),
                extfvk.clone(),
                value,
            );
            insert_into_cache(&db_cache, &cb);
        }
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Second spend still fails
        match create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk,
            &to,
            Amount::from_u64(70000).unwrap(),
            None,
            OvkPolicy::Sender,
        ) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => assert_eq!(
                e.to_string(),
                "Insufficient balance (have 50000, need 71000 including fee)"
            ),
        }

        // Mine block 11 so that the second note becomes verified
        let (cb, _) =
            fake_compact_block(sapling_activation_height() + 10, cb.hash(), extfvk, value);
        insert_into_cache(&db_cache, &cb);
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Second spend should now succeed
        create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk,
            &to,
            Amount::from_u64(70000).unwrap(),
            None,
            OvkPolicy::Sender,
        )
        .unwrap();
    }

    #[test]
    fn create_to_address_fails_on_locked_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Add funds to the wallet in a single note
        let value = Amount::from_u64(50000).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk,
            value,
        );
        insert_into_cache(&db_cache, &cb);
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);

        // Send some of the funds to another address
        let extsk2 = ExtendedSpendingKey::master(&[]);
        let to = extsk2.default_address().unwrap().1.into();
        create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk,
            &to,
            Amount::from_u64(15000).unwrap(),
            None,
            OvkPolicy::Sender,
        )
        .unwrap();

        // A second spend fails because there are no usable notes
        match create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk,
            &to,
            Amount::from_u64(2000).unwrap(),
            None,
            OvkPolicy::Sender,
        ) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => assert_eq!(
                e.to_string(),
                "Insufficient balance (have 0, need 3000 including fee)"
            ),
        }

        // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 21 (that don't send us funds)
        // until just before the first transaction expires
        for i in 1..22 {
            let (cb, _) = fake_compact_block(
                sapling_activation_height() + i,
                cb.hash(),
                ExtendedFullViewingKey::from(&ExtendedSpendingKey::master(&[i as u8])),
                value,
            );
            insert_into_cache(&db_cache, &cb);
        }
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Second spend still fails
        match create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk,
            &to,
            Amount::from_u64(2000).unwrap(),
            None,
            OvkPolicy::Sender,
        ) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => assert_eq!(
                e.to_string(),
                "Insufficient balance (have 0, need 3000 including fee)"
            ),
        }

        // Mine block SAPLING_ACTIVATION_HEIGHT + 22 so that the first transaction expires
        let (cb, _) = fake_compact_block(
            sapling_activation_height() + 22,
            cb.hash(),
            ExtendedFullViewingKey::from(&ExtendedSpendingKey::master(&[22])),
            value,
        );
        insert_into_cache(&db_cache, &cb);
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Second spend should now succeed
        create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk,
            &to,
            Amount::from_u64(2000).unwrap(),
            None,
            OvkPolicy::Sender,
        )
        .unwrap();
    }

    #[test]
    fn ovk_policy_prevents_recovery_from_chain() {
        let network = tests::network();
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), network).unwrap();
        init_wallet_db(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Add funds to the wallet in a single note
        let value = Amount::from_u64(50000).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb);
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);

        let extsk2 = ExtendedSpendingKey::master(&[]);
        let addr2 = extsk2.default_address().unwrap().1;
        let to = addr2.clone().into();

        let send_and_recover_with_policy = |db_write: &mut DataConnStmtCache<'_, _>, ovk_policy| {
            let tx_row = create_spend_to_address(
                db_write,
                &tests::network(),
                test_prover(),
                AccountId(0),
                &extsk,
                &to,
                Amount::from_u64(15000).unwrap(),
                None,
                ovk_policy,
            )
            .unwrap();

            // Fetch the transaction from the database
            let raw_tx: Vec<_> = db_write
                .wallet_db
                .conn
                .query_row(
                    "SELECT raw FROM transactions
                    WHERE id_tx = ?",
                    &[tx_row],
                    |row| row.get(0),
                )
                .unwrap();
            let tx = Transaction::read(&raw_tx[..], BranchId::Canopy).unwrap();

            // Fetch the output index from the database
            let output_index: i64 = db_write
                .wallet_db
                .conn
                .query_row(
                    "SELECT output_index FROM sent_notes
                    WHERE tx = ?",
                    &[tx_row],
                    |row| row.get(0),
                )
                .unwrap();

            let output = &tx.sapling_bundle().unwrap().shielded_outputs[output_index as usize];

            try_sapling_output_recovery(
                &network,
                sapling_activation_height(),
                &extfvk.fvk.ovk,
                output,
            )
        };

        // Send some of the funds to another address, keeping history.
        // The recipient output is decryptable by the sender.
        let (_, recovered_to, _) =
            send_and_recover_with_policy(&mut db_write, OvkPolicy::Sender).unwrap();
        assert_eq!(&recovered_to, &addr2);

        // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 22 (that don't send us funds)
        // so that the first transaction expires
        for i in 1..=22 {
            let (cb, _) = fake_compact_block(
                sapling_activation_height() + i,
                cb.hash(),
                ExtendedFullViewingKey::from(&ExtendedSpendingKey::master(&[i as u8])),
                value,
            );
            insert_into_cache(&db_cache, &cb);
        }
        scan_cached_blocks(&network, &db_cache, &mut db_write, None).unwrap();

        // Send the funds again, discarding history.
        // Neither transaction output is decryptable by the sender.
        assert!(send_and_recover_with_policy(&mut db_write, OvkPolicy::Discard).is_none());
    }

    #[test]
    fn create_to_address_succeeds_to_t_addr_zero_change() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &[extfvk.clone()]).unwrap();

        // Add funds to the wallet in a single note
        let value = Amount::from_u64(51000).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk,
            value,
        );
        insert_into_cache(&db_cache, &cb);
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Verified balance matches total balance
        let (_, anchor_height) = (&db_data).get_target_and_anchor_heights().unwrap().unwrap();
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);
        assert_eq!(
            get_balance_at(&db_data, AccountId(0), anchor_height).unwrap(),
            value
        );

        let to = TransparentAddress::PublicKey([7; 20]).into();
        create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            AccountId(0),
            &extsk,
            &to,
            Amount::from_u64(50000).unwrap(),
            None,
            OvkPolicy::Sender,
        )
        .unwrap();
    }
}
