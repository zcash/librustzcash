//! Functions for creating transactions.
//!
use rusqlite::{named_params, types::Value, Row};
use std::rc::Rc;

use group::ff::PrimeField;

use zcash_primitives::{
    consensus::BlockHeight,
    merkle_tree::read_incremental_witness,
    sapling::{Diversifier, Rseed},
    transaction::components::Amount,
    zip32::AccountId,
};

use zcash_client_backend::wallet::SpendableNote;

use crate::{error::SqliteClientError, NoteId, WalletDb};

fn to_spendable_note(row: &Row) -> Result<SpendableNote<NoteId>, SqliteClientError> {
    let note_id = NoteId::ReceivedNoteId(row.get(0)?);
    let diversifier = {
        let d: Vec<_> = row.get(1)?;
        if d.len() != 11 {
            return Err(SqliteClientError::CorruptedData(
                "Invalid diversifier length".to_string(),
            ));
        }
        let mut tmp = [0; 11];
        tmp.copy_from_slice(&d);
        Diversifier(tmp)
    };

    let note_value = Amount::from_i64(row.get(2)?).unwrap();

    let rseed = {
        let rcm_bytes: Vec<_> = row.get(3)?;

        // We store rcm directly in the data DB, regardless of whether the note
        // used a v1 or v2 note plaintext, so for the purposes of spending let's
        // pretend this is a pre-ZIP 212 note.
        let rcm = Option::from(jubjub::Fr::from_repr(
            rcm_bytes[..]
                .try_into()
                .map_err(|_| SqliteClientError::InvalidNote)?,
        ))
        .ok_or(SqliteClientError::InvalidNote)?;
        Rseed::BeforeZip212(rcm)
    };

    let witness = {
        let d: Vec<_> = row.get(4)?;
        read_incremental_witness(&d[..])?
    };

    Ok(SpendableNote {
        note_id,
        diversifier,
        note_value,
        rseed,
        witness,
    })
}

pub(crate) fn get_spendable_sapling_notes<P>(
    wdb: &WalletDb<P>,
    account: AccountId,
    anchor_height: BlockHeight,
    exclude: &[NoteId],
) -> Result<Vec<SpendableNote<NoteId>>, SqliteClientError> {
    let mut stmt_select_notes = wdb.conn.prepare(
        "SELECT id_note, diversifier, value, rcm, witness
            FROM sapling_received_notes
            INNER JOIN transactions ON transactions.id_tx = sapling_received_notes.tx
            INNER JOIN sapling_witnesses ON sapling_witnesses.note = sapling_received_notes.id_note
            WHERE account = :account
            AND spent IS NULL
            AND transactions.block <= :anchor_height
            AND sapling_witnesses.block = :anchor_height
            AND id_note NOT IN rarray(:exclude)",
    )?;

    let excluded: Vec<Value> = exclude
        .iter()
        .filter_map(|n| match n {
            NoteId::ReceivedNoteId(i) => Some(Value::from(*i)),
            NoteId::SentNoteId(_) => None,
        })
        .collect();
    let excluded_ptr = Rc::new(excluded);

    let notes = stmt_select_notes.query_and_then(
        named_params![
            ":account": &u32::from(account),
            ":anchor_height": &u32::from(anchor_height),
            ":exclude": &excluded_ptr,
        ],
        to_spendable_note,
    )?;

    notes.collect::<Result<_, _>>()
}

pub(crate) fn select_spendable_sapling_notes<P>(
    wdb: &WalletDb<P>,
    account: AccountId,
    target_value: Amount,
    anchor_height: BlockHeight,
    exclude: &[NoteId],
) -> Result<Vec<SpendableNote<NoteId>>, SqliteClientError> {
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
                FROM sapling_received_notes
                INNER JOIN transactions ON transactions.id_tx = sapling_received_notes.tx
                WHERE account = :account 
                AND spent IS NULL 
                AND transactions.block <= :anchor_height
                AND id_note NOT IN rarray(:exclude)
            )
            SELECT * FROM eligible WHERE so_far < :target_value
            UNION
            SELECT * FROM (SELECT * FROM eligible WHERE so_far >= :target_value LIMIT 1)
        ), witnesses AS (
            SELECT note, witness FROM sapling_witnesses
            WHERE block = :anchor_height
        )
        SELECT selected.id_note, selected.diversifier, selected.value, selected.rcm, witnesses.witness
        FROM selected
        INNER JOIN witnesses ON selected.id_note = witnesses.note",
    )?;

    let excluded: Vec<Value> = exclude
        .iter()
        .filter_map(|n| match n {
            NoteId::ReceivedNoteId(i) => Some(Value::from(*i)),
            NoteId::SentNoteId(_) => None,
        })
        .collect();
    let excluded_ptr = Rc::new(excluded);

    let notes = stmt_select_notes.query_and_then(
        named_params![
            ":account": &u32::from(account),
            ":anchor_height": &u32::from(anchor_height),
            ":target_value": &i64::from(target_value),
            ":exclude": &excluded_ptr
        ],
        to_spendable_note,
    )?;

    notes.collect::<Result<_, _>>()
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use rusqlite::Connection;
    use secrecy::Secret;
    use tempfile::NamedTempFile;

    use zcash_proofs::prover::LocalTxProver;

    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, BranchId},
        legacy::TransparentAddress,
        sapling::{note_encryption::try_sapling_output_recovery, prover::TxProver},
        transaction::{components::Amount, fees::zip317::FeeRule as Zip317FeeRule, Transaction},
        zip32::{sapling::ExtendedSpendingKey, Scope},
    };

    use zcash_client_backend::{
        address::RecipientAddress,
        data_api::{
            self,
            chain::scan_cached_blocks,
            error::Error,
            wallet::{create_spend_to_address, input_selection::GreedyInputSelector, spend},
            WalletRead, WalletWrite,
        },
        fees::{zip317, DustOutputPolicy},
        keys::UnifiedSpendingKey,
        wallet::OvkPolicy,
        zip321::{Payment, TransactionRequest},
    };

    use crate::{
        chain::init::init_cache_database,
        tests::{
            self, fake_compact_block, insert_into_cache, network, sapling_activation_height,
            AddressType,
        },
        wallet::{
            get_balance, get_balance_at,
            init::{init_blocks_table, init_wallet_db},
        },
        AccountId, BlockDb, DataConnStmtCache, WalletDb,
    };

    #[cfg(feature = "transparent-inputs")]
    use {
        zcash_client_backend::{
            data_api::wallet::shield_transparent_funds, fees::fixed,
            wallet::WalletTransparentOutput,
        },
        zcash_primitives::{
            memo::MemoBytes,
            transaction::{
                components::{amount::NonNegativeAmount, OutPoint, TxOut},
                fees::fixed::FeeRule as FixedFeeRule,
            },
        },
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
    fn create_to_address_fails_on_incorrect_usk() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let mut ops = db_data.get_update_ops().unwrap();
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = ops.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1.into();

        // Create a USK that doesn't exist in the wallet
        let acct1 = AccountId::from(1);
        let usk1 = UnifiedSpendingKey::from_seed(&network(), &[1u8; 32], acct1).unwrap();

        // Attempting to spend with a USK that is not in the wallet results in an error
        let mut db_write = db_data.get_update_ops().unwrap();
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk1,
                &to,
                Amount::from_u64(1).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Err(data_api::error::Error::KeyNotRecognized)
        );
    }

    #[test]
    fn create_to_address_fails_with_no_blocks() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        // Add an account to the wallet
        let mut ops = db_data.get_update_ops().unwrap();
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = ops.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1.into();

        // We cannot do anything if we aren't synchronised
        let mut db_write = db_data.get_update_ops().unwrap();
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(1).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Err(data_api::error::Error::ScanRequired)
        );
    }

    #[test]
    fn create_to_address_fails_on_insufficient_balance() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();
        init_blocks_table(
            &db_data,
            BlockHeight::from(1u32),
            BlockHash([1; 32]),
            1,
            &[],
        )
        .unwrap();

        // Add an account to the wallet
        let mut ops = db_data.get_update_ops().unwrap();
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = ops.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1.into();

        // Account balance should be zero
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            Amount::zero()
        );

        // We cannot spend anything
        let mut db_write = db_data.get_update_ops().unwrap();
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(1).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == Amount::zero() && required == Amount::from_u64(10001).unwrap()
        );
    }

    #[test]
    fn create_to_address_fails_on_unverified_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        // Add an account to the wallet
        let mut ops = db_data.get_update_ops().unwrap();
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = ops.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();

        // Add funds to the wallet in a single note
        let value = Amount::from_u64(50000).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb);
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Verified balance matches total balance
        let (_, anchor_height) = db_data.get_target_and_anchor_heights(10).unwrap().unwrap();
        assert_eq!(get_balance(&db_data, AccountId::from(0)).unwrap(), value);
        assert_eq!(
            get_balance_at(&db_data, AccountId::from(0), anchor_height).unwrap(),
            value
        );

        // Add more funds to the wallet in a second note
        let (cb, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb);
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Verified balance does not include the second note
        let (_, anchor_height2) = db_data.get_target_and_anchor_heights(10).unwrap().unwrap();
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            (value + value).unwrap()
        );
        assert_eq!(
            get_balance_at(&db_data, AccountId::from(0), anchor_height2).unwrap(),
            value
        );

        // Spend fails because there are insufficient verified notes
        let extsk2 = ExtendedSpendingKey::master(&[]);
        let to = extsk2.default_address().1.into();
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(70000).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == Amount::from_u64(50000).unwrap()
                && required == Amount::from_u64(80000).unwrap()
        );

        // Mine blocks SAPLING_ACTIVATION_HEIGHT + 2 to 9 until just before the second
        // note is verified
        for i in 2..10 {
            let (cb, _) = fake_compact_block(
                sapling_activation_height() + i,
                cb.hash(),
                &dfvk,
                AddressType::DefaultExternal,
                value,
            );
            insert_into_cache(&db_cache, &cb);
        }
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Second spend still fails
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(70000).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == Amount::from_u64(50000).unwrap()
                && required == Amount::from_u64(80000).unwrap()
        );

        // Mine block 11 so that the second note becomes verified
        let (cb, _) = fake_compact_block(
            sapling_activation_height() + 10,
            cb.hash(),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb);
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Second spend should now succeed
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(70000).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Ok(_)
        );
    }

    #[test]
    fn create_to_address_fails_on_locked_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        let mut ops = db_data.get_update_ops().unwrap();
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = ops.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();

        // Add funds to the wallet in a single note
        let value = Amount::from_u64(50000).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb);
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();
        assert_eq!(get_balance(&db_data, AccountId::from(0)).unwrap(), value);

        // Send some of the funds to another address
        let extsk2 = ExtendedSpendingKey::master(&[]);
        let to = extsk2.default_address().1.into();
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(15000).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Ok(_)
        );

        // A second spend fails because there are no usable notes
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(2000).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == Amount::zero() && required == Amount::from_u64(12000).unwrap()
        );

        // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 41 (that don't send us funds)
        // until just before the first transaction expires
        for i in 1..42 {
            let (cb, _) = fake_compact_block(
                sapling_activation_height() + i,
                cb.hash(),
                &ExtendedSpendingKey::master(&[i as u8]).to_diversifiable_full_viewing_key(),
                AddressType::DefaultExternal,
                value,
            );
            insert_into_cache(&db_cache, &cb);
        }
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Second spend still fails
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(2000).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == Amount::zero() && required == Amount::from_u64(12000).unwrap()
        );

        // Mine block SAPLING_ACTIVATION_HEIGHT + 42 so that the first transaction expires
        let (cb, _) = fake_compact_block(
            sapling_activation_height() + 42,
            cb.hash(),
            &ExtendedSpendingKey::master(&[42]).to_diversifiable_full_viewing_key(),
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb);
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Second spend should now succeed
        create_spend_to_address(
            &mut db_write,
            &tests::network(),
            test_prover(),
            &usk,
            &to,
            Amount::from_u64(2000).unwrap(),
            None,
            OvkPolicy::Sender,
            10,
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
        let mut db_data = WalletDb::for_path(data_file.path(), network).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        // Add an account to the wallet
        let mut ops = db_data.get_update_ops().unwrap();
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = ops.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();

        // Add funds to the wallet in a single note
        let value = Amount::from_u64(50000).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb);
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();
        assert_eq!(get_balance(&db_data, AccountId::from(0)).unwrap(), value);

        let extsk2 = ExtendedSpendingKey::master(&[]);
        let addr2 = extsk2.default_address().1;
        let to = addr2.into();

        let send_and_recover_with_policy = |db_write: &mut DataConnStmtCache<'_, _>, ovk_policy| {
            let tx_row = create_spend_to_address(
                db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(15000).unwrap(),
                None,
                ovk_policy,
                10,
            )
            .unwrap();

            // Fetch the transaction from the database
            let raw_tx: Vec<_> = db_write
                .wallet_db
                .conn
                .query_row(
                    "SELECT raw FROM transactions
                    WHERE id_tx = ?",
                    [tx_row],
                    |row| row.get(0),
                )
                .unwrap();
            let tx = Transaction::read(&raw_tx[..], BranchId::Canopy).unwrap();

            for output in tx.sapling_bundle().unwrap().shielded_outputs() {
                // Find the output that decrypts with the external OVK
                let result = try_sapling_output_recovery(
                    &network,
                    sapling_activation_height(),
                    &dfvk.to_ovk(Scope::External),
                    output,
                );

                if result.is_some() {
                    return result;
                }
            }

            None
        };

        // Send some of the funds to another address, keeping history.
        // The recipient output is decryptable by the sender.
        let (_, recovered_to, _) =
            send_and_recover_with_policy(&mut db_write, OvkPolicy::Sender).unwrap();
        assert_eq!(&recovered_to, &addr2);

        // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 42 (that don't send us funds)
        // so that the first transaction expires
        for i in 1..=42 {
            let (cb, _) = fake_compact_block(
                sapling_activation_height() + i,
                cb.hash(),
                &ExtendedSpendingKey::master(&[i as u8]).to_diversifiable_full_viewing_key(),
                AddressType::DefaultExternal,
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
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        // Add an account to the wallet
        let mut ops = db_data.get_update_ops().unwrap();
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = ops.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();

        // Add funds to the wallet in a single note
        let value = Amount::from_u64(60000).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::DefaultExternal,
            value,
        );
        insert_into_cache(&db_cache, &cb);
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Verified balance matches total balance
        let (_, anchor_height) = db_data.get_target_and_anchor_heights(10).unwrap().unwrap();
        assert_eq!(get_balance(&db_data, AccountId::from(0)).unwrap(), value);
        assert_eq!(
            get_balance_at(&db_data, AccountId::from(0), anchor_height).unwrap(),
            value
        );

        let to = TransparentAddress::PublicKey([7; 20]).into();
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(50000).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Ok(_)
        );
    }

    #[test]
    fn create_to_address_spends_a_change_note() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        // Add an account to the wallet
        let mut ops = db_data.get_update_ops().unwrap();
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = ops.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();

        // Add funds to the wallet in a single note
        let value = Amount::from_u64(60000).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::Internal,
            value,
        );
        insert_into_cache(&db_cache, &cb);
        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Verified balance matches total balance
        let (_, anchor_height) = db_data.get_target_and_anchor_heights(10).unwrap().unwrap();
        assert_eq!(get_balance(&db_data, AccountId::from(0)).unwrap(), value);
        assert_eq!(
            get_balance_at(&db_data, AccountId::from(0), anchor_height).unwrap(),
            value
        );

        let to = TransparentAddress::PublicKey([7; 20]).into();
        assert_matches!(
            create_spend_to_address(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &usk,
                &to,
                Amount::from_u64(50000).unwrap(),
                None,
                OvkPolicy::Sender,
                10,
            ),
            Ok(_)
        );
    }

    #[test]
    fn zip317_spend() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        // Add an account to the wallet
        let mut ops = db_data.get_update_ops().unwrap();
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = ops.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();

        // Add funds to the wallet
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::Internal,
            Amount::from_u64(50000).unwrap(),
        );
        insert_into_cache(&db_cache, &cb);

        // Add 10 dust notes to the wallet
        for i in 1..=10 {
            let (cb, _) = fake_compact_block(
                sapling_activation_height() + i,
                cb.hash(),
                &dfvk,
                AddressType::DefaultExternal,
                Amount::from_u64(1000).unwrap(),
            );
            insert_into_cache(&db_cache, &cb);
        }

        let mut db_write = db_data.get_update_ops().unwrap();
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        // Verified balance matches total balance
        let total = Amount::from_u64(60000).unwrap();
        let (_, anchor_height) = db_data.get_target_and_anchor_heights(1).unwrap().unwrap();
        assert_eq!(get_balance(&db_data, AccountId::from(0)).unwrap(), total);
        assert_eq!(
            get_balance_at(&db_data, AccountId::from(0), anchor_height).unwrap(),
            total
        );

        let input_selector = GreedyInputSelector::new(
            zip317::SingleOutputChangeStrategy::new(Zip317FeeRule::standard()),
            DustOutputPolicy::default(),
        );

        // This first request will fail due to insufficient non-dust funds
        let req = TransactionRequest::new(vec![Payment {
            recipient_address: RecipientAddress::Shielded(dfvk.default_address().1),
            amount: Amount::from_u64(50000).unwrap(),
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        }])
        .unwrap();

        assert_matches!(
            spend(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &input_selector,
                &usk,
                req,
                OvkPolicy::Sender,
                1,
            ),
            Err(Error::InsufficientFunds { available, required })
                if available == Amount::from_u64(51000).unwrap()
                && required == Amount::from_u64(60000).unwrap()
        );

        // This request will succeed, spending a single dust input to pay the 10000
        // ZAT fee in addition to the 41000 ZAT output to the recipient
        let req = TransactionRequest::new(vec![Payment {
            recipient_address: RecipientAddress::Shielded(dfvk.default_address().1),
            amount: Amount::from_u64(41000).unwrap(),
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        }])
        .unwrap();

        assert_matches!(
            spend(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &input_selector,
                &usk,
                req,
                OvkPolicy::Sender,
                1,
            ),
            Ok(_)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn shield_transparent() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = BlockDb(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();

        // Add an account to the wallet
        let mut db_write = db_data.get_update_ops().unwrap();
        let seed = Secret::new([0u8; 32].to_vec());
        let (account_id, usk) = db_write.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();
        let uaddr = db_data.get_current_address(account_id).unwrap().unwrap();
        let taddr = uaddr.transparent().unwrap();

        let utxo = WalletTransparentOutput::from_parts(
            OutPoint::new([1u8; 32], 1),
            TxOut {
                value: Amount::from_u64(10000).unwrap(),
                script_pubkey: taddr.script(),
            },
            sapling_activation_height(),
        )
        .unwrap();

        let res0 = db_write.put_received_transparent_utxo(&utxo);
        assert!(matches!(res0, Ok(_)));

        let input_selector = GreedyInputSelector::new(
            fixed::SingleOutputChangeStrategy::new(FixedFeeRule::standard()),
            DustOutputPolicy::default(),
        );

        // Add funds to the wallet
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            &dfvk,
            AddressType::Internal,
            Amount::from_u64(50000).unwrap(),
        );
        insert_into_cache(&db_cache, &cb);
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_write, None).unwrap();

        assert_matches!(
            shield_transparent_funds(
                &mut db_write,
                &tests::network(),
                test_prover(),
                &input_selector,
                NonNegativeAmount::from_u64(10000).unwrap(),
                &usk,
                &[*taddr],
                &MemoBytes::empty(),
                0
            ),
            Ok(_)
        );
    }
}
