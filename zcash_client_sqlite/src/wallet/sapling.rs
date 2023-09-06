//! Functions for Sapling support in the wallet.

use group::ff::PrimeField;
use incrementalmerkletree::Position;
use rusqlite::{named_params, params, types::Value, Connection, Row};
use std::rc::Rc;

use zcash_primitives::{
    consensus::BlockHeight,
    memo::MemoBytes,
    sapling::{self, Diversifier, Note, Nullifier, Rseed},
    transaction::components::Amount,
    zip32::AccountId,
};

use zcash_client_backend::{
    wallet::{ReceivedSaplingNote, WalletSaplingOutput},
    DecryptedOutput, TransferType,
};

use crate::{error::SqliteClientError, ReceivedNoteId};

use super::{memo_repr, wallet_birthday};

/// This trait provides a generalization over shielded output representations.
pub(crate) trait ReceivedSaplingOutput {
    fn index(&self) -> usize;
    fn account(&self) -> AccountId;
    fn note(&self) -> &Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> bool;
    fn nullifier(&self) -> Option<&sapling::Nullifier>;
    fn note_commitment_tree_position(&self) -> Option<Position>;
}

impl ReceivedSaplingOutput for WalletSaplingOutput<sapling::Nullifier> {
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
    fn nullifier(&self) -> Option<&sapling::Nullifier> {
        Some(self.nf())
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        Some(WalletSaplingOutput::note_commitment_tree_position(self))
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
    fn nullifier(&self) -> Option<&sapling::Nullifier> {
        None
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        None
    }
}

fn to_spendable_note(row: &Row) -> Result<ReceivedSaplingNote<ReceivedNoteId>, SqliteClientError> {
    let note_id = ReceivedNoteId(row.get(0)?);
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

    let note_commitment_tree_position =
        Position::from(u64::try_from(row.get::<_, i64>(4)?).map_err(|_| {
            SqliteClientError::CorruptedData("Note commitment tree position invalid.".to_string())
        })?);

    Ok(ReceivedSaplingNote {
        note_id,
        diversifier,
        note_value,
        rseed,
        note_commitment_tree_position,
    })
}

/// Utility method for determining whether we have any spendable notes
///
/// If the tip shard has unscanned ranges below the anchor height and greater than or equal to
/// the wallet birthday, none of our notes can be spent because we cannot construct witnesses at
/// the provided anchor height.
fn unscanned_tip_exists(
    conn: &Connection,
    anchor_height: BlockHeight,
) -> Result<bool, rusqlite::Error> {
    // v_sapling_shard_unscanned_ranges only returns ranges ending on or after wallet birthday, so
    // we don't need to refer to the birthday in this query.
    conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM v_sapling_shard_unscanned_ranges range
             WHERE range.block_range_start <= :anchor_height
             AND :anchor_height BETWEEN 
                range.subtree_start_height 
                AND IFNULL(range.subtree_end_height, :anchor_height)
         )",
        named_params![":anchor_height": u32::from(anchor_height),],
        |row| row.get::<_, bool>(0),
    )
}

pub(crate) fn get_spendable_sapling_notes(
    conn: &Connection,
    account: AccountId,
    anchor_height: BlockHeight,
    exclude: &[ReceivedNoteId],
) -> Result<Vec<ReceivedSaplingNote<ReceivedNoteId>>, SqliteClientError> {
    let birthday_height = match wallet_birthday(conn)? {
        Some(birthday) => birthday,
        None => {
            // the wallet birthday can only be unknown if there are no accounts in the wallet; in
            // such a case, the wallet has no notes to spend.
            return Ok(vec![]);
        }
    };

    if unscanned_tip_exists(conn, anchor_height)? {
        return Ok(vec![]);
    }

    let mut stmt_select_notes = conn.prepare_cached(
        "SELECT id_note, diversifier, value, rcm, commitment_tree_position
         FROM sapling_received_notes
         INNER JOIN transactions ON transactions.id_tx = sapling_received_notes.tx
         WHERE account = :account
         AND commitment_tree_position IS NOT NULL
         AND spent IS NULL
         AND transactions.block <= :anchor_height
         AND id_note NOT IN rarray(:exclude)
         AND NOT EXISTS (
            SELECT 1 FROM v_sapling_shard_unscanned_ranges unscanned
            -- select all the unscanned ranges involving the shard containing this note
            WHERE sapling_received_notes.commitment_tree_position >= unscanned.start_position
            AND sapling_received_notes.commitment_tree_position < unscanned.end_position_exclusive
            -- exclude unscanned ranges that start above the anchor height (they don't affect spendability)
            AND unscanned.block_range_start <= :anchor_height
            -- exclude unscanned ranges that end below the wallet birthday
            AND unscanned.block_range_end > :wallet_birthday
         )",
    )?;

    let excluded: Vec<Value> = exclude.iter().map(|n| Value::from(n.0)).collect();
    let excluded_ptr = Rc::new(excluded);

    let notes = stmt_select_notes.query_and_then(
        named_params![
            ":account": u32::from(account),
            ":anchor_height": u32::from(anchor_height),
            ":exclude": &excluded_ptr,
            ":wallet_birthday": u32::from(birthday_height)
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
    exclude: &[ReceivedNoteId],
) -> Result<Vec<ReceivedSaplingNote<ReceivedNoteId>>, SqliteClientError> {
    let birthday_height = match wallet_birthday(conn)? {
        Some(birthday) => birthday,
        None => {
            // the wallet birthday can only be unknown if there are no accounts in the wallet; in
            // such a case, the wallet has no notes to spend.
            return Ok(vec![]);
        }
    };

    if unscanned_tip_exists(conn, anchor_height)? {
        return Ok(vec![]);
    }

    // The goal of this SQL statement is to select the oldest notes until the required
    // value has been reached.
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
        "WITH eligible AS (
             SELECT id_note, diversifier, value, rcm, commitment_tree_position,
                 SUM(value)
                    OVER (PARTITION BY account, spent ORDER BY id_note) AS so_far
             FROM sapling_received_notes
             INNER JOIN transactions
                ON transactions.id_tx = sapling_received_notes.tx
             WHERE account = :account
             AND commitment_tree_position IS NOT NULL
             AND spent IS NULL
             AND transactions.block <= :anchor_height
             AND id_note NOT IN rarray(:exclude)
             AND NOT EXISTS (
                SELECT 1 FROM v_sapling_shard_unscanned_ranges unscanned
                -- select all the unscanned ranges involving the shard containing this note
                WHERE sapling_received_notes.commitment_tree_position >= unscanned.start_position
                AND sapling_received_notes.commitment_tree_position < unscanned.end_position_exclusive
                -- exclude unscanned ranges that start above the anchor height (they don't affect spendability)
                AND unscanned.block_range_start <= :anchor_height
                -- exclude unscanned ranges that end below the wallet birthday
                AND unscanned.block_range_end > :wallet_birthday
             )
         )
         SELECT id_note, diversifier, value, rcm, commitment_tree_position
         FROM eligible WHERE so_far < :target_value
         UNION
         SELECT id_note, diversifier, value, rcm, commitment_tree_position
         FROM (SELECT * from eligible WHERE so_far >= :target_value LIMIT 1)",
    )?;

    let excluded: Vec<Value> = exclude.iter().map(|n| Value::from(n.0)).collect();
    let excluded_ptr = Rc::new(excluded);

    let notes = stmt_select_notes.query_and_then(
        named_params![
            ":account": &u32::from(account),
            ":anchor_height": &u32::from(anchor_height),
            ":target_value": &i64::from(target_value),
            ":exclude": &excluded_ptr,
            ":wallet_birthday": u32::from(birthday_height)
        ],
        to_spendable_note,
    )?;

    notes.collect::<Result<_, _>>()
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
            sapling::Nullifier::from_slice(&nf_bytes).unwrap(),
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
            sapling::Nullifier::from_slice(&nf_bytes).unwrap(),
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
    nf: &sapling::Nullifier,
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
    spent_in: Option<i64>,
) -> Result<(), SqliteClientError> {
    let mut stmt_upsert_received_note = conn.prepare_cached(
        "INSERT INTO sapling_received_notes
        (tx, output_index, account, diversifier, value, rcm, memo, nf, is_change, spent, commitment_tree_position)
        VALUES (
            :tx,
            :output_index,
            :account,
            :diversifier,
            :value,
            :rcm,
            :memo,
            :nf,
            :is_change,
            :spent,
            :commitment_tree_position
        )
        ON CONFLICT (tx, output_index) DO UPDATE
        SET account = :account,
            diversifier = :diversifier,
            value = :value,
            rcm = :rcm,
            nf = IFNULL(:nf, nf),
            memo = IFNULL(:memo, memo),
            is_change = IFNULL(:is_change, is_change),
            spent = IFNULL(:spent, spent),
            commitment_tree_position = IFNULL(:commitment_tree_position, commitment_tree_position)",
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
        ":is_change": output.is_change(),
        ":spent": spent_in,
        ":commitment_tree_position": output.note_commitment_tree_position().map(u64::from),
    ];

    stmt_upsert_received_note
        .execute(sql_args)
        .map_err(SqliteClientError::from)?;

    Ok(())
}

#[cfg(test)]
#[allow(deprecated)]
pub(crate) mod tests {
    use std::{convert::Infallible, num::NonZeroU32};

    use incrementalmerkletree::Hashable;
    use zcash_proofs::prover::LocalTxProver;

    use zcash_primitives::{
        block::BlockHash,
        consensus::BranchId,
        legacy::TransparentAddress,
        memo::{Memo, MemoBytes},
        sapling::{
            note_encryption::try_sapling_output_recovery, prover::TxProver, Node, Note,
            PaymentAddress,
        },
        transaction::{
            components::{
                amount::{BalanceError, NonNegativeAmount},
                Amount,
            },
            fees::{fixed::FeeRule as FixedFeeRule, zip317::FeeRule as Zip317FeeRule},
            Transaction,
        },
        zip32::{sapling::ExtendedSpendingKey, Scope},
    };

    use zcash_client_backend::{
        address::RecipientAddress,
        data_api::{
            self,
            chain::CommitmentTreeRoot,
            error::Error,
            wallet::input_selection::{GreedyInputSelector, GreedyInputSelectorError},
            AccountBirthday, Ratio, ShieldedProtocol, WalletCommitmentTrees, WalletRead,
        },
        decrypt_transaction,
        fees::{fixed, zip317, DustOutputPolicy},
        keys::UnifiedSpendingKey,
        wallet::OvkPolicy,
        zip321::{self, Payment, TransactionRequest},
    };

    use crate::{
        error::SqliteClientError,
        testing::{AddressType, BlockCache, TestBuilder, TestState},
        wallet::{
            block_max_scanned, commitment_tree, sapling::select_spendable_sapling_notes,
            scanning::tests::test_with_canopy_birthday,
        },
        AccountId, NoteId, ReceivedNoteId,
    };

    #[cfg(feature = "transparent-inputs")]
    use {
        zcash_client_backend::{data_api::WalletWrite, wallet::WalletTransparentOutput},
        zcash_primitives::transaction::components::{OutPoint, TxOut},
    };

    pub(crate) fn test_prover() -> impl TxProver {
        match LocalTxProver::with_default_location() {
            Some(tx_prover) => tx_prover,
            None => {
                panic!("Cannot locate the Zcash parameters. Please run zcash-fetch-params or fetch-params.sh to download the parameters, and then re-run the tests.");
            }
        }
    }

    #[test]
    fn send_proposed_transfer() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Add funds to the wallet in a single note
        let value = NonNegativeAmount::from_u64(60000).unwrap();
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value.into());
        st.scan_cached_blocks(h, 1);

        // Verified balance matches total balance
        assert_eq!(st.get_total_balance(account), value);
        assert_eq!(
            block_max_scanned(&st.wallet().conn)
                .unwrap()
                .unwrap()
                .block_height(),
            h
        );

        let to_extsk = ExtendedSpendingKey::master(&[]);
        let to: RecipientAddress = to_extsk.default_address().1.into();
        let request = zip321::TransactionRequest::new(vec![Payment {
            recipient_address: to,
            amount: Amount::from_u64(10000).unwrap(),
            memo: None, // this should result in the creation of an empty memo
            label: None,
            message: None,
            other_params: vec![],
        }])
        .unwrap();

        let fee_rule = FixedFeeRule::standard();
        let change_strategy = fixed::SingleOutputChangeStrategy::new(fee_rule);
        let input_selector =
            &GreedyInputSelector::new(change_strategy, DustOutputPolicy::default());
        let proposal_result = st.propose_transfer(
            account,
            input_selector,
            request,
            NonZeroU32::new(1).unwrap(),
        );
        assert_matches!(proposal_result, Ok(_));

        let change_memo = "Test change memo".parse::<Memo>().unwrap();
        let create_proposed_result = st.create_proposed_transaction(
            &usk,
            OvkPolicy::Sender,
            proposal_result.unwrap(),
            NonZeroU32::new(1).unwrap(),
            Some(change_memo.clone().into()),
        );
        assert_matches!(create_proposed_result, Ok(_));

        let sent_tx_id = create_proposed_result.unwrap();

        // Verify that the sent transaction was stored and that we can decrypt the memos
        let tx = st
            .wallet()
            .get_transaction(sent_tx_id)
            .expect("Created transaction was stored.");
        let ufvks = [(account, usk.to_unified_full_viewing_key())]
            .into_iter()
            .collect();
        let decrypted_outputs = decrypt_transaction(&st.network(), h + 1, &tx, &ufvks);
        assert_eq!(decrypted_outputs.len(), 2);

        let mut found_tx_change_memo = false;
        let mut found_tx_empty_memo = false;
        for output in decrypted_outputs {
            if output.memo == change_memo.clone().into() {
                found_tx_change_memo = true
            }
            if output.memo == Memo::Empty.into() {
                found_tx_empty_memo = true
            }
        }
        assert!(found_tx_change_memo);
        assert!(found_tx_empty_memo);

        // Verify that the stored sent notes match what we're expecting
        let mut stmt_sent_notes = st
            .wallet()
            .conn
            .prepare(
                "SELECT output_index
                FROM sent_notes
                JOIN transactions ON transactions.id_tx = sent_notes.tx
                WHERE transactions.txid = ?",
            )
            .unwrap();

        let sent_note_ids = stmt_sent_notes
            .query(rusqlite::params![sent_tx_id.as_ref()])
            .unwrap()
            .mapped(|row| {
                Ok(NoteId::new(
                    sent_tx_id,
                    ShieldedProtocol::Sapling,
                    row.get(0)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(sent_note_ids.len(), 2);

        // The sent memo should be the empty memo for the sent output, and the
        // change output's memo should be as specified.
        let mut found_sent_change_memo = false;
        let mut found_sent_empty_memo = false;
        for sent_note_id in sent_note_ids {
            match st
                .wallet()
                .get_memo(sent_note_id)
                .expect("Note id is valid")
                .as_ref()
            {
                Some(m) if m == &change_memo => {
                    found_sent_change_memo = true;
                }
                Some(m) if m == &Memo::Empty => {
                    found_sent_empty_memo = true;
                }
                Some(other) => panic!("Unexpected memo value: {:?}", other),
                None => panic!("Memo should not be stored as NULL"),
            }
        }
        assert!(found_sent_change_memo);
        assert!(found_sent_empty_memo);

        // Check that querying for a nonexistent sent note returns None
        assert_matches!(
            st.wallet()
                .get_memo(NoteId::new(sent_tx_id, ShieldedProtocol::Sapling, 12345)),
            Ok(None)
        );
    }

    #[test]
    fn create_to_address_fails_on_incorrect_usk() {
        let mut st = TestBuilder::new()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();
        let dfvk = st.test_account_sapling().unwrap();
        let to = dfvk.default_address().1.into();

        // Create a USK that doesn't exist in the wallet
        let acct1 = AccountId::from(1);
        let usk1 = UnifiedSpendingKey::from_seed(&st.network(), &[1u8; 32], acct1).unwrap();

        // Attempting to spend with a USK that is not in the wallet results in an error
        assert_matches!(
            st.create_spend_to_address(
                &usk1,
                &to,
                Amount::from_u64(1).unwrap(),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
            ),
            Err(data_api::error::Error::KeyNotRecognized)
        );
    }

    #[test]
    fn create_to_address_fails_with_no_blocks() {
        let mut st = TestBuilder::new()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (_, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();
        let to = dfvk.default_address().1.into();

        // Wallet summary is not yet available
        assert_eq!(st.get_wallet_summary(0), None);

        // We cannot do anything if we aren't synchronised
        assert_matches!(
            st.create_spend_to_address(
                &usk,
                &to,
                Amount::from_u64(1).unwrap(),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
            ),
            Err(data_api::error::Error::ScanRequired)
        );
    }

    #[test]
    fn create_to_address_fails_on_unverified_notes() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Add funds to the wallet in a single note
        let value = NonNegativeAmount::from_u64(50000).unwrap();
        let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value.into());
        st.scan_cached_blocks(h1, 1);

        // Verified balance matches total balance
        assert_eq!(st.get_total_balance(account), value);

        // Value is considered pending
        assert_eq!(st.get_pending_shielded_balance(account, 10), value);

        // Wallet is fully scanned
        let summary = st.get_wallet_summary(1);
        assert_eq!(
            summary.and_then(|s| s.scan_progress()),
            Some(Ratio::new(1, 1))
        );

        // Add more funds to the wallet in a second note
        let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value.into());
        st.scan_cached_blocks(h2, 1);

        // Verified balance does not include the second note
        let total = (value + value).unwrap();
        assert_eq!(st.get_spendable_balance(account, 2), value);
        assert_eq!(st.get_pending_shielded_balance(account, 2), value);
        assert_eq!(st.get_total_balance(account), total);

        // Wallet is still fully scanned
        let summary = st.get_wallet_summary(1);
        assert_eq!(
            summary.and_then(|s| s.scan_progress()),
            Some(Ratio::new(2, 2))
        );

        // Spend fails because there are insufficient verified notes
        let extsk2 = ExtendedSpendingKey::master(&[]);
        let to = extsk2.default_address().1.into();
        assert_matches!(
            st.create_spend_to_address(
                &usk,
                &to,
                Amount::from_u64(70000).unwrap(),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(10).unwrap(),
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
        for _ in 2..10 {
            st.generate_next_block(&dfvk, AddressType::DefaultExternal, value.into());
        }
        st.scan_cached_blocks(h2 + 1, 8);

        // Second spend still fails
        assert_matches!(
            st.create_spend_to_address(
                &usk,
                &to,
                Amount::from_u64(70000).unwrap(),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(10).unwrap(),
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == Amount::from_u64(50000).unwrap()
                && required == Amount::from_u64(80000).unwrap()
        );

        // Mine block 11 so that the second note becomes verified
        let (h11, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value.into());
        st.scan_cached_blocks(h11, 1);

        // Second spend should now succeed
        assert_matches!(
            st.create_spend_to_address(
                &usk,
                &to,
                Amount::from_u64(70000).unwrap(),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(10).unwrap(),
            ),
            Ok(_)
        );
    }

    #[test]
    fn create_to_address_fails_on_locked_notes() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Add funds to the wallet in a single note
        let value = NonNegativeAmount::from_u64(50000).unwrap();
        let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value.into());
        st.scan_cached_blocks(h1, 1);
        assert_eq!(st.get_total_balance(account), value);

        // Send some of the funds to another address
        let extsk2 = ExtendedSpendingKey::master(&[]);
        let to = extsk2.default_address().1.into();
        assert_matches!(
            st.create_spend_to_address(
                &usk,
                &to,
                Amount::from_u64(15000).unwrap(),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
            ),
            Ok(_)
        );

        // A second spend fails because there are no usable notes
        assert_matches!(
            st.create_spend_to_address(
                &usk,
                &to,
                Amount::from_u64(2000).unwrap(),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
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
            st.generate_next_block(
                &ExtendedSpendingKey::master(&[i as u8]).to_diversifiable_full_viewing_key(),
                AddressType::DefaultExternal,
                value.into(),
            );
        }
        st.scan_cached_blocks(h1 + 1, 41);

        // Second spend still fails
        assert_matches!(
            st.create_spend_to_address(
                &usk,
                &to,
                Amount::from_u64(2000).unwrap(),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == Amount::zero() && required == Amount::from_u64(12000).unwrap()
        );

        // Mine block SAPLING_ACTIVATION_HEIGHT + 42 so that the first transaction expires
        let (h43, _, _) = st.generate_next_block(
            &ExtendedSpendingKey::master(&[42]).to_diversifiable_full_viewing_key(),
            AddressType::DefaultExternal,
            value.into(),
        );
        st.scan_cached_blocks(h43, 1);

        // Second spend should now succeed
        st.create_spend_to_address(
            &usk,
            &to,
            Amount::from_u64(2000).unwrap(),
            None,
            OvkPolicy::Sender,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn ovk_policy_prevents_recovery_from_chain() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Add funds to the wallet in a single note
        let value = NonNegativeAmount::from_u64(50000).unwrap();
        let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value.into());
        st.scan_cached_blocks(h1, 1);
        assert_eq!(st.get_total_balance(account), value);

        let extsk2 = ExtendedSpendingKey::master(&[]);
        let addr2 = extsk2.default_address().1;
        let to = addr2.into();

        #[allow(clippy::type_complexity)]
        let send_and_recover_with_policy = |st: &mut TestState<BlockCache>,
                                            ovk_policy|
         -> Result<
            Option<(Note, PaymentAddress, MemoBytes)>,
            Error<
                SqliteClientError,
                commitment_tree::Error,
                GreedyInputSelectorError<BalanceError, ReceivedNoteId>,
                Infallible,
                ReceivedNoteId,
            >,
        > {
            let txid = st.create_spend_to_address(
                &usk,
                &to,
                Amount::from_u64(15000).unwrap(),
                None,
                ovk_policy,
                NonZeroU32::new(1).unwrap(),
            )?;

            // Fetch the transaction from the database
            let raw_tx: Vec<_> = st
                .wallet()
                .conn
                .query_row(
                    "SELECT raw FROM transactions
                    WHERE txid = ?",
                    [txid.as_ref()],
                    |row| row.get(0),
                )
                .unwrap();
            let tx = Transaction::read(&raw_tx[..], BranchId::Canopy).unwrap();

            for output in tx.sapling_bundle().unwrap().shielded_outputs() {
                // Find the output that decrypts with the external OVK
                let result = try_sapling_output_recovery(
                    &st.network(),
                    h1,
                    &dfvk.to_ovk(Scope::External),
                    output,
                );

                if result.is_some() {
                    return Ok(result);
                }
            }

            Ok(None)
        };

        // Send some of the funds to another address, keeping history.
        // The recipient output is decryptable by the sender.
        assert_matches!(
            send_and_recover_with_policy(&mut st, OvkPolicy::Sender),
            Ok(Some((_, recovered_to, _))) if recovered_to == addr2
        );

        // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 42 (that don't send us funds)
        // so that the first transaction expires
        for i in 1..=42 {
            st.generate_next_block(
                &ExtendedSpendingKey::master(&[i as u8]).to_diversifiable_full_viewing_key(),
                AddressType::DefaultExternal,
                value.into(),
            );
        }
        st.scan_cached_blocks(h1 + 1, 42);

        // Send the funds again, discarding history.
        // Neither transaction output is decryptable by the sender.
        assert_matches!(
            send_and_recover_with_policy(&mut st, OvkPolicy::Discard),
            Ok(None)
        );
    }

    #[test]
    fn create_to_address_succeeds_to_t_addr_zero_change() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Add funds to the wallet in a single note
        let value = Amount::from_u64(60000).unwrap();
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        // Verified balance matches total balance
        assert_eq!(
            st.get_total_balance(account),
            NonNegativeAmount::try_from(value).unwrap()
        );

        let to = TransparentAddress::PublicKey([7; 20]).into();
        assert_matches!(
            st.create_spend_to_address(
                &usk,
                &to,
                Amount::from_u64(50000).unwrap(),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
            ),
            Ok(_)
        );
    }

    #[test]
    fn create_to_address_spends_a_change_note() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Add funds to the wallet in a single note owned by the internal spending key
        let value = Amount::from_u64(60000).unwrap();
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::Internal, value);
        st.scan_cached_blocks(h, 1);

        // Verified balance matches total balance
        assert_eq!(
            st.get_total_balance(account),
            NonNegativeAmount::try_from(value).unwrap()
        );

        // the balance is considered pending
        assert_eq!(
            st.get_pending_shielded_balance(account, 10),
            NonNegativeAmount::try_from(value).unwrap()
        );

        let to = TransparentAddress::PublicKey([7; 20]).into();
        assert_matches!(
            st.create_spend_to_address(
                &usk,
                &to,
                Amount::from_u64(50000).unwrap(),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
            ),
            Ok(_)
        );
    }

    #[test]
    fn zip317_spend() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Add funds to the wallet
        let (h1, _, _) = st.generate_next_block(
            &dfvk,
            AddressType::Internal,
            Amount::from_u64(50000).unwrap(),
        );

        // Add 10 dust notes to the wallet
        for _ in 1..=10 {
            st.generate_next_block(
                &dfvk,
                AddressType::DefaultExternal,
                Amount::from_u64(1000).unwrap(),
            );
        }

        st.scan_cached_blocks(h1, 11);

        // Verified balance matches total balance
        let total = Amount::from_u64(60000).unwrap();
        assert_eq!(
            st.get_total_balance(account),
            NonNegativeAmount::try_from(total).unwrap()
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
            st.spend(
                &input_selector,
                &usk,
                req,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
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
            st.spend(
                &input_selector,
                &usk,
                req,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
            ),
            Ok(_)
        );
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn shield_transparent() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account_id, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        let uaddr = st
            .wallet()
            .get_current_address(account_id)
            .unwrap()
            .unwrap();
        let taddr = uaddr.transparent().unwrap();

        // Ensure that the wallet has at least one block
        let (h, _, _) = st.generate_next_block(
            &dfvk,
            AddressType::Internal,
            Amount::from_u64(50000).unwrap(),
        );
        st.scan_cached_blocks(h, 1);

        let utxo = WalletTransparentOutput::from_parts(
            OutPoint::new([1u8; 32], 1),
            TxOut {
                value: Amount::from_u64(10000).unwrap(),
                script_pubkey: taddr.script(),
            },
            h,
        )
        .unwrap();

        let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
        assert!(matches!(res0, Ok(_)));

        let input_selector = GreedyInputSelector::new(
            fixed::SingleOutputChangeStrategy::new(FixedFeeRule::standard()),
            DustOutputPolicy::default(),
        );

        assert_matches!(
            st.shield_transparent_funds(
                &input_selector,
                NonNegativeAmount::from_u64(10000).unwrap(),
                &usk,
                &[*taddr],
                &MemoBytes::empty(),
                NonZeroU32::new(1).unwrap()
            ),
            Ok(_)
        );
    }

    #[test]
    fn birthday_in_anchor_shard() {
        let (mut st, dfvk, birthday, _) = test_with_canopy_birthday();

        // Set up the following situation:
        //
        //        |<------ 500 ------->|<--- 10 --->|<--- 10 --->|
        // last_shard_start   wallet_birthday  received_tx  anchor_height
        //
        // Set up some shard root history before the wallet birthday.
        let prev_shard_start = birthday.height() - 500;
        st.wallet_mut()
            .put_sapling_subtree_roots(
                0,
                &[CommitmentTreeRoot::from_parts(
                    prev_shard_start,
                    // fake a hash, the value doesn't matter
                    Node::empty_leaf(),
                )],
            )
            .unwrap();

        let received_tx_height = birthday.height() + 10;

        let initial_sapling_tree_size =
            u64::from(birthday.sapling_frontier().value().unwrap().position() + 1)
                .try_into()
                .unwrap();

        // Generate 9 blocks that have no value for us, starting at the birthday height.
        let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
        let not_our_value = Amount::const_from_i64(10000);
        st.generate_block_at(
            birthday.height(),
            BlockHash([0; 32]),
            &not_our_key,
            AddressType::DefaultExternal,
            not_our_value,
            initial_sapling_tree_size,
        );
        for _ in 1..9 {
            st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
        }

        // Now, generate a block that belongs to our wallet
        st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            Amount::const_from_i64(500000),
        );

        // Generate some more blocks to get above our anchor height
        for _ in 0..15 {
            st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
        }

        // Scan a block range that includes our received note, but skips some blocks we need to
        // make it spendable.
        st.scan_cached_blocks(birthday.height() + 5, 20);

        // Verify that the received note is not considered spendable
        let spendable = select_spendable_sapling_notes(
            &st.wallet().conn,
            AccountId::from(0),
            Amount::const_from_i64(300000),
            received_tx_height + 10,
            &[],
        )
        .unwrap();

        assert_eq!(spendable.len(), 0);

        // Scan the blocks we skipped
        st.scan_cached_blocks(birthday.height(), 5);

        // Verify that the received note is now considered spendable
        let spendable = select_spendable_sapling_notes(
            &st.wallet().conn,
            AccountId::from(0),
            Amount::const_from_i64(300000),
            received_tx_height + 10,
            &[],
        )
        .unwrap();

        assert_eq!(spendable.len(), 1);
    }
}
