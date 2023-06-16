//! Functions for Sapling support in the wallet.
use group::ff::PrimeField;
use rusqlite::{named_params, params, types::Value, Connection, OptionalExtension, Row};
use std::rc::Rc;

use zcash_primitives::{
    consensus::BlockHeight,
    memo::MemoBytes,
    merkle_tree::{read_commitment_tree, read_incremental_witness, write_incremental_witness},
    sapling::{self, Diversifier, Note, Nullifier, Rseed},
    transaction::components::Amount,
    zip32::AccountId,
};

use zcash_client_backend::{
    wallet::{ReceivedSaplingNote, WalletSaplingOutput},
    DecryptedOutput, TransferType,
};

use crate::{error::SqliteClientError, NoteId};

use super::memo_repr;

/// This trait provides a generalization over shielded output representations.
pub(crate) trait ReceivedSaplingOutput {
    fn index(&self) -> usize;
    fn account(&self) -> AccountId;
    fn note(&self) -> &Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> bool;
    fn nullifier(&self) -> Option<&Nullifier>;
}

impl ReceivedSaplingOutput for WalletSaplingOutput<Nullifier> {
    fn index(&self) -> usize {
        self.index()
    }
    fn account(&self) -> AccountId {
        WalletSaplingOutput::account(self)
    }
    fn note(&self) -> &Note {
        WalletSaplingOutput::note(self)
    }
    fn memo(&self) -> Option<&MemoBytes> {
        None
    }
    fn is_change(&self) -> bool {
        WalletSaplingOutput::is_change(self)
    }

    fn nullifier(&self) -> Option<&Nullifier> {
        Some(self.nf())
    }
}

impl ReceivedSaplingOutput for DecryptedOutput<Note> {
    fn index(&self) -> usize {
        self.index
    }
    fn account(&self) -> AccountId {
        self.account
    }
    fn note(&self) -> &Note {
        &self.note
    }
    fn memo(&self) -> Option<&MemoBytes> {
        Some(&self.memo)
    }
    fn is_change(&self) -> bool {
        self.transfer_type == TransferType::WalletInternal
    }
    fn nullifier(&self) -> Option<&Nullifier> {
        None
    }
}

fn to_spendable_note(row: &Row) -> Result<ReceivedSaplingNote<NoteId>, SqliteClientError> {
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

    Ok(ReceivedSaplingNote {
        note_id,
        diversifier,
        note_value,
        rseed,
        witness,
    })
}

pub(crate) fn get_spendable_sapling_notes(
    conn: &Connection,
    account: AccountId,
    anchor_height: BlockHeight,
    exclude: &[NoteId],
) -> Result<Vec<ReceivedSaplingNote<NoteId>>, SqliteClientError> {
    let mut stmt_select_notes = conn.prepare_cached(
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

pub(crate) fn select_spendable_sapling_notes(
    conn: &Connection,
    account: AccountId,
    target_value: Amount,
    anchor_height: BlockHeight,
    exclude: &[NoteId],
) -> Result<Vec<ReceivedSaplingNote<NoteId>>, SqliteClientError> {
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
    let mut stmt_select_notes = conn.prepare_cached(
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

/// Returns the commitment tree for the block at the specified height,
/// if any.
pub(crate) fn get_sapling_commitment_tree(
    conn: &Connection,
    block_height: BlockHeight,
) -> Result<Option<sapling::CommitmentTree>, SqliteClientError> {
    conn.query_row_and_then(
        "SELECT sapling_tree FROM blocks WHERE height = ?",
        [u32::from(block_height)],
        |row| {
            let row_data: Vec<u8> = row.get(0)?;
            read_commitment_tree(&row_data[..]).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    row_data.len(),
                    rusqlite::types::Type::Blob,
                    Box::new(e),
                )
            })
        },
    )
    .optional()
    .map_err(SqliteClientError::from)
}

/// Returns the incremental witnesses for the block at the specified height,
/// if any.
pub(crate) fn get_sapling_witnesses(
    conn: &Connection,
    block_height: BlockHeight,
) -> Result<Vec<(NoteId, sapling::IncrementalWitness)>, SqliteClientError> {
    let mut stmt_fetch_witnesses =
        conn.prepare_cached("SELECT note, witness FROM sapling_witnesses WHERE block = ?")?;

    let witnesses = stmt_fetch_witnesses
        .query_map([u32::from(block_height)], |row| {
            let id_note = NoteId::ReceivedNoteId(row.get(0)?);
            let witness_data: Vec<u8> = row.get(1)?;
            Ok(read_incremental_witness(&witness_data[..]).map(|witness| (id_note, witness)))
        })
        .map_err(SqliteClientError::from)?;

    // unwrap database error & IO error from IncrementalWitness::read
    let res: Vec<_> = witnesses.collect::<Result<Result<_, _>, _>>()??;
    Ok(res)
}

/// Records the incremental witness for the specified note,
/// as of the given block height.
pub(crate) fn insert_witness(
    conn: &Connection,
    note_id: i64,
    witness: &sapling::IncrementalWitness,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let mut stmt_insert_witness = conn.prepare_cached(
        "INSERT INTO sapling_witnesses (note, block, witness)
                    VALUES (?, ?, ?)",
    )?;

    let mut encoded = Vec::new();
    write_incremental_witness(witness, &mut encoded).unwrap();

    stmt_insert_witness.execute(params![note_id, u32::from(height), encoded])?;

    Ok(())
}

/// Retrieves the set of nullifiers for "potentially spendable" Sapling notes that the
/// wallet is tracking.
///
/// "Potentially spendable" means:
/// - The transaction in which the note was created has been observed as mined.
/// - No transaction in which the note's nullifier appears has been observed as mined.
pub(crate) fn get_sapling_nullifiers(
    conn: &Connection,
) -> Result<Vec<(AccountId, Nullifier)>, SqliteClientError> {
    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers = conn.prepare(
        "SELECT rn.id_note, rn.account, rn.nf, tx.block as block
         FROM sapling_received_notes rn
         LEFT OUTER JOIN transactions tx
         ON tx.id_tx = rn.spent
         WHERE block IS NULL
         AND nf IS NOT NULL",
    )?;
    let nullifiers = stmt_fetch_nullifiers.query_map([], |row| {
        let account: u32 = row.get(1)?;
        let nf_bytes: Vec<u8> = row.get(2)?;
        Ok((
            AccountId::from(account),
            Nullifier::from_slice(&nf_bytes).unwrap(),
        ))
    })?;

    let res: Vec<_> = nullifiers.collect::<Result<_, _>>()?;
    Ok(res)
}

/// Returns the nullifiers for the notes that this wallet is tracking.
pub(crate) fn get_all_sapling_nullifiers(
    conn: &Connection,
) -> Result<Vec<(AccountId, Nullifier)>, SqliteClientError> {
    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers = conn.prepare(
        "SELECT rn.id_note, rn.account, rn.nf
         FROM sapling_received_notes rn
         WHERE nf IS NOT NULL",
    )?;
    let nullifiers = stmt_fetch_nullifiers.query_map([], |row| {
        let account: u32 = row.get(1)?;
        let nf_bytes: Vec<u8> = row.get(2)?;
        Ok((
            AccountId::from(account),
            Nullifier::from_slice(&nf_bytes).unwrap(),
        ))
    })?;

    let res: Vec<_> = nullifiers.collect::<Result<_, _>>()?;
    Ok(res)
}

/// Marks a given nullifier as having been revealed in the construction
/// of the specified transaction.
///
/// Marking a note spent in this fashion does NOT imply that the
/// spending transaction has been mined.
pub(crate) fn mark_sapling_note_spent(
    conn: &Connection,
    tx_ref: i64,
    nf: &Nullifier,
) -> Result<bool, SqliteClientError> {
    let mut stmt_mark_sapling_note_spent =
        conn.prepare_cached("UPDATE sapling_received_notes SET spent = ? WHERE nf = ?")?;

    match stmt_mark_sapling_note_spent.execute(params![tx_ref, &nf.0[..]])? {
        0 => Ok(false),
        1 => Ok(true),
        _ => unreachable!("nf column is marked as UNIQUE"),
    }
}

/// Records the specified shielded output as having been received.
///
/// This implementation relies on the facts that:
/// - A transaction will not contain more than 2^63 shielded outputs.
/// - A note value will never exceed 2^63 zatoshis.
pub(crate) fn put_received_note<T: ReceivedSaplingOutput>(
    conn: &Connection,
    output: &T,
    tx_ref: i64,
) -> Result<NoteId, SqliteClientError> {
    let mut stmt_upsert_received_note = conn.prepare_cached(
        "INSERT INTO sapling_received_notes
        (tx, output_index, account, diversifier, value, rcm, memo, nf, is_change)
        VALUES
        (:tx, :output_index, :account, :diversifier, :value, :rcm, :memo, :nf, :is_change)
        ON CONFLICT (tx, output_index) DO UPDATE
        SET account = :account,
            diversifier = :diversifier,
            value = :value,
            rcm = :rcm,
            nf = IFNULL(:nf, nf),
            memo = IFNULL(:memo, memo),
            is_change = IFNULL(:is_change, is_change)
        RETURNING id_note",
    )?;

    let rcm = output.note().rcm().to_repr();
    let to = output.note().recipient();
    let diversifier = to.diversifier();

    let sql_args = named_params![
        ":tx": &tx_ref,
        ":output_index": i64::try_from(output.index()).expect("output indices are representable as i64"),
        ":account": u32::from(output.account()),
        ":diversifier": &diversifier.0.as_ref(),
        ":value": output.note().value().inner(),
        ":rcm": &rcm.as_ref(),
        ":nf": output.nullifier().map(|nf| nf.0.as_ref()),
        ":memo": memo_repr(output.memo()),
        ":is_change": output.is_change()
    ];

    stmt_upsert_received_note
        .query_row(sql_args, |row| {
            row.get::<_, i64>(0).map(NoteId::ReceivedNoteId)
        })
        .map_err(SqliteClientError::from)
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
        AccountId, BlockDb, WalletDb,
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
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = db_data.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1.into();

        // Create a USK that doesn't exist in the wallet
        let acct1 = AccountId::from(1);
        let usk1 = UnifiedSpendingKey::from_seed(&network(), &[1u8; 32], acct1).unwrap();

        // Attempting to spend with a USK that is not in the wallet results in an error
        assert_matches!(
            create_spend_to_address(
                &mut db_data,
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
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = db_data.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1.into();

        // We cannot do anything if we aren't synchronised
        assert_matches!(
            create_spend_to_address(
                &mut db_data,
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
            &mut db_data,
            BlockHeight::from(1u32),
            BlockHash([1; 32]),
            1,
            &[],
        )
        .unwrap();

        // Add an account to the wallet
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = db_data.create_account(&seed).unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1.into();

        // Account balance should be zero
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            Amount::zero()
        );

        // We cannot spend anything
        assert_matches!(
            create_spend_to_address(
                &mut db_data,
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
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = db_data.create_account(&seed).unwrap();
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();

        // Verified balance matches total balance
        let (_, anchor_height) = db_data.get_target_and_anchor_heights(10).unwrap().unwrap();
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            value
        );
        assert_eq!(
            get_balance_at(&db_data.conn, AccountId::from(0), anchor_height).unwrap(),
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();

        // Verified balance does not include the second note
        let (_, anchor_height2) = db_data.get_target_and_anchor_heights(10).unwrap().unwrap();
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            (value + value).unwrap()
        );
        assert_eq!(
            get_balance_at(&db_data.conn, AccountId::from(0), anchor_height2).unwrap(),
            value
        );

        // Spend fails because there are insufficient verified notes
        let extsk2 = ExtendedSpendingKey::master(&[]);
        let to = extsk2.default_address().1.into();
        assert_matches!(
            create_spend_to_address(
                &mut db_data,
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();

        // Second spend still fails
        assert_matches!(
            create_spend_to_address(
                &mut db_data,
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();

        // Second spend should now succeed
        assert_matches!(
            create_spend_to_address(
                &mut db_data,
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
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = db_data.create_account(&seed).unwrap();
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            value
        );

        // Send some of the funds to another address
        let extsk2 = ExtendedSpendingKey::master(&[]);
        let to = extsk2.default_address().1.into();
        assert_matches!(
            create_spend_to_address(
                &mut db_data,
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
                &mut db_data,
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();

        // Second spend still fails
        assert_matches!(
            create_spend_to_address(
                &mut db_data,
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();

        // Second spend should now succeed
        create_spend_to_address(
            &mut db_data,
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
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = db_data.create_account(&seed).unwrap();
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            value
        );

        let extsk2 = ExtendedSpendingKey::master(&[]);
        let addr2 = extsk2.default_address().1;
        let to = addr2.into();

        let send_and_recover_with_policy = |db_data: &mut WalletDb<Connection, _>, ovk_policy| {
            let tx_row = create_spend_to_address(
                db_data,
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
            let raw_tx: Vec<_> = db_data
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
            send_and_recover_with_policy(&mut db_data, OvkPolicy::Sender).unwrap();
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
        scan_cached_blocks(&network, &db_cache, &mut db_data, None).unwrap();

        // Send the funds again, discarding history.
        // Neither transaction output is decryptable by the sender.
        assert!(send_and_recover_with_policy(&mut db_data, OvkPolicy::Discard).is_none());
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
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = db_data.create_account(&seed).unwrap();
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();

        // Verified balance matches total balance
        let (_, anchor_height) = db_data.get_target_and_anchor_heights(10).unwrap().unwrap();
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            value
        );
        assert_eq!(
            get_balance_at(&db_data.conn, AccountId::from(0), anchor_height).unwrap(),
            value
        );

        let to = TransparentAddress::PublicKey([7; 20]).into();
        assert_matches!(
            create_spend_to_address(
                &mut db_data,
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
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = db_data.create_account(&seed).unwrap();
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();

        // Verified balance matches total balance
        let (_, anchor_height) = db_data.get_target_and_anchor_heights(10).unwrap().unwrap();
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            value
        );
        assert_eq!(
            get_balance_at(&db_data.conn, AccountId::from(0), anchor_height).unwrap(),
            value
        );

        let to = TransparentAddress::PublicKey([7; 20]).into();
        assert_matches!(
            create_spend_to_address(
                &mut db_data,
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
        let seed = Secret::new([0u8; 32].to_vec());
        let (_, usk) = db_data.create_account(&seed).unwrap();
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

        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();

        // Verified balance matches total balance
        let total = Amount::from_u64(60000).unwrap();
        let (_, anchor_height) = db_data.get_target_and_anchor_heights(1).unwrap().unwrap();
        assert_eq!(
            get_balance(&db_data.conn, AccountId::from(0)).unwrap(),
            total
        );
        assert_eq!(
            get_balance_at(&db_data.conn, AccountId::from(0), anchor_height).unwrap(),
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
                &mut db_data,
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
                &mut db_data,
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
        let seed = Secret::new([0u8; 32].to_vec());
        let (account_id, usk) = db_data.create_account(&seed).unwrap();
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

        let res0 = db_data.put_received_transparent_utxo(&utxo);
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
        scan_cached_blocks(&tests::network(), &db_cache, &mut db_data, None).unwrap();

        assert_matches!(
            shield_transparent_funds(
                &mut db_data,
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
