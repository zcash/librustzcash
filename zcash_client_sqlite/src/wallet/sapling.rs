//! Functions for Sapling support in the wallet.

use group::ff::PrimeField;
use incrementalmerkletree::Position;
use rusqlite::{named_params, params, types::Value, Connection, Row};
use std::rc::Rc;

use zcash_primitives::{
    consensus::BlockHeight,
    memo::MemoBytes,
    sapling::{self, Diversifier, Note, Nullifier, Rseed},
    transaction::{
        components::{amount::NonNegativeAmount, Amount},
        TxId,
    },
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
    let txid = row.get::<_, [u8; 32]>(1).map(TxId::from_bytes)?;
    let output_index = row.get(2)?;
    let diversifier = {
        let d: Vec<_> = row.get(3)?;
        if d.len() != 11 {
            return Err(SqliteClientError::CorruptedData(
                "Invalid diversifier length".to_string(),
            ));
        }
        let mut tmp = [0; 11];
        tmp.copy_from_slice(&d);
        Diversifier(tmp)
    };

    let note_value = NonNegativeAmount::from_nonnegative_i64(row.get(4)?).map_err(|_e| {
        SqliteClientError::CorruptedData("Note values must be nonnegative".to_string())
    })?;

    let rseed = {
        let rcm_bytes: Vec<_> = row.get(5)?;

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
        Position::from(u64::try_from(row.get::<_, i64>(6)?).map_err(|_| {
            SqliteClientError::CorruptedData("Note commitment tree position invalid.".to_string())
        })?);

    Ok(ReceivedSaplingNote::from_parts(
        note_id,
        txid,
        output_index,
        diversifier,
        note_value,
        rseed,
        note_commitment_tree_position,
    ))
}

// The `clippy::let_and_return` lint is explicitly allowed here because a bug in Clippy
// (https://github.com/rust-lang/rust-clippy/issues/11308) means it fails to identify that the `result` temporary
// is required in order to resolve the borrows involved in the `query_and_then` call.
#[allow(clippy::let_and_return)]
pub(crate) fn get_spendable_sapling_note(
    conn: &Connection,
    txid: &TxId,
    index: u32,
) -> Result<Option<ReceivedSaplingNote<ReceivedNoteId>>, SqliteClientError> {
    let mut stmt_select_note = conn.prepare_cached(
        "SELECT id_note, txid, output_index, diversifier, value, rcm, commitment_tree_position
         FROM sapling_received_notes
         INNER JOIN transactions ON transactions.id_tx = sapling_received_notes.tx
         WHERE txid = :txid
         AND output_index = :output_index
         AND spent IS NULL",
    )?;

    let result = stmt_select_note
        .query_and_then(
            named_params![
               ":txid": txid.as_ref(),
               ":output_index": index,
            ],
            to_spendable_note,
        )?
        .next()
        .transpose();

    result
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
             SELECT id_note, txid, output_index, diversifier, value, rcm, commitment_tree_position,
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
         SELECT id_note, txid, output_index, diversifier, value, rcm, commitment_tree_position
         FROM eligible WHERE so_far < :target_value
         UNION
         SELECT id_note, txid, output_index, diversifier, value, rcm, commitment_tree_position
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
    let nullifiers = stmt_fetch_nullifiers.query_and_then([], |row| {
        let account: u32 = row.get(1)?;
        let nf_bytes: Vec<u8> = row.get(2)?;
        AccountId::try_from(account)
            .map_err(|_| SqliteClientError::AccountIdOutOfRange)
            .map(|a| (a, sapling::Nullifier::from_slice(&nf_bytes).unwrap()))
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
    let nullifiers = stmt_fetch_nullifiers.query_and_then([], |row| {
        let account: u32 = row.get(1)?;
        let nf_bytes: Vec<u8> = row.get(2)?;
        AccountId::try_from(account)
            .map_err(|_| SqliteClientError::AccountIdOutOfRange)
            .map(|a| (a, sapling::Nullifier::from_slice(&nf_bytes).unwrap()))
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
pub(crate) mod tests {
    use std::{convert::Infallible, num::NonZeroU32};

    use incrementalmerkletree::Hashable;
    use secrecy::Secret;
    use zcash_proofs::prover::LocalTxProver;

    use zcash_primitives::{
        block::BlockHash,
        consensus::{sapling_zip212_enforcement, BranchId},
        legacy::TransparentAddress,
        memo::{Memo, MemoBytes},
        sapling::{
            note_encryption::try_sapling_output_recovery,
            prover::{OutputProver, SpendProver},
            zip32::ExtendedSpendingKey,
            Node, Note, PaymentAddress,
        },
        transaction::{
            components::{amount::NonNegativeAmount, Amount},
            fees::{
                fixed::FeeRule as FixedFeeRule, zip317::FeeError as Zip317FeeError, StandardFeeRule,
            },
            Transaction,
        },
        zip32::Scope,
    };

    use zcash_client_backend::{
        address::RecipientAddress,
        data_api::{
            self,
            chain::CommitmentTreeRoot,
            error::Error,
            wallet::input_selection::{GreedyInputSelector, GreedyInputSelectorError},
            AccountBirthday, Ratio, ShieldedProtocol, WalletCommitmentTrees, WalletRead,
            WalletWrite,
        },
        decrypt_transaction,
        fees::{fixed, standard, DustOutputPolicy},
        keys::UnifiedSpendingKey,
        wallet::OvkPolicy,
        zip321::{self, Payment, TransactionRequest},
    };

    use crate::{
        error::SqliteClientError,
        testing::{input_selector, AddressType, BlockCache, TestBuilder, TestState},
        wallet::{
            block_max_scanned, commitment_tree, sapling::select_spendable_sapling_notes,
            scanning::tests::test_with_canopy_birthday,
        },
        AccountId, NoteId, ReceivedNoteId,
    };

    #[cfg(feature = "transparent-inputs")]
    use {
        zcash_client_backend::wallet::WalletTransparentOutput,
        zcash_primitives::transaction::components::{OutPoint, TxOut},
    };

    pub(crate) fn test_prover() -> impl SpendProver + OutputProver {
        LocalTxProver::bundled()
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
        let value = NonNegativeAmount::const_from_u64(60000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        // Spendable balance matches total balance
        assert_eq!(st.get_total_balance(account), value);
        assert_eq!(st.get_spendable_balance(account, 1), value);

        assert_eq!(
            block_max_scanned(&st.wallet().conn, &st.wallet().params)
                .unwrap()
                .unwrap()
                .block_height(),
            h
        );

        let to_extsk = ExtendedSpendingKey::master(&[]);
        let to: RecipientAddress = to_extsk.default_address().1.into();
        let request = zip321::TransactionRequest::new(vec![Payment {
            recipient_address: to,
            amount: NonNegativeAmount::const_from_u64(10000),
            memo: None, // this should result in the creation of an empty memo
            label: None,
            message: None,
            other_params: vec![],
        }])
        .unwrap();

        // TODO: This test was originally written to use the pre-zip-313 fee rule
        // and has not yet been updated.
        #[allow(deprecated)]
        let fee_rule = StandardFeeRule::PreZip313;

        let change_memo = "Test change memo".parse::<Memo>().unwrap();
        let change_strategy =
            standard::SingleOutputChangeStrategy::new(fee_rule, Some(change_memo.clone().into()));
        let input_selector =
            &GreedyInputSelector::new(change_strategy, DustOutputPolicy::default());

        let proposal = st
            .propose_transfer(
                account,
                input_selector,
                request,
                NonZeroU32::new(1).unwrap(),
            )
            .unwrap();

        let create_proposed_result =
            st.create_proposed_transaction::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal);
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
    #[allow(deprecated)]
    fn create_to_address_fails_on_incorrect_usk() {
        let mut st = TestBuilder::new()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();
        let dfvk = st.test_account_sapling().unwrap();
        let to = dfvk.default_address().1.into();

        // Create a USK that doesn't exist in the wallet
        let acct1 = AccountId::try_from(1).unwrap();
        let usk1 = UnifiedSpendingKey::from_seed(&st.network(), &[1u8; 32], acct1).unwrap();

        // Attempting to spend with a USK that is not in the wallet results in an error
        assert_matches!(
            st.create_spend_to_address(
                &usk1,
                &to,
                NonNegativeAmount::const_from_u64(1),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
                None
            ),
            Err(data_api::error::Error::KeyNotRecognized)
        );
    }

    #[test]
    #[allow(deprecated)]
    fn proposal_fails_with_no_blocks() {
        let mut st = TestBuilder::new()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, _, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();
        let to = dfvk.default_address().1.into();

        // Wallet summary is not yet available
        assert_eq!(st.get_wallet_summary(0), None);

        // We cannot do anything if we aren't synchronised
        assert_matches!(
            st.propose_standard_transfer::<Infallible>(
                account,
                StandardFeeRule::PreZip313,
                NonZeroU32::new(1).unwrap(),
                &to,
                NonNegativeAmount::const_from_u64(1),
                None,
                None
            ),
            Err(data_api::error::Error::ScanRequired)
        );
    }

    #[test]
    fn spend_fails_on_unverified_notes() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Add funds to the wallet in a single note
        let value = NonNegativeAmount::const_from_u64(50000);
        let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);

        // Spendable balance matches total balance at 1 confirmation.
        assert_eq!(st.get_total_balance(account), value);
        assert_eq!(st.get_spendable_balance(account, 1), value);

        // Value is considered pending at 10 confirmations.
        assert_eq!(st.get_pending_shielded_balance(account, 10), value);
        assert_eq!(
            st.get_spendable_balance(account, 10),
            NonNegativeAmount::ZERO
        );

        // Wallet is fully scanned
        let summary = st.get_wallet_summary(1);
        assert_eq!(
            summary.and_then(|s| s.scan_progress()),
            Some(Ratio::new(1, 1))
        );

        // Add more funds to the wallet in a second note
        let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
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
            st.propose_standard_transfer::<Infallible>(
                account,
                StandardFeeRule::Zip317,
                NonZeroU32::new(2).unwrap(),
                &to,
                NonNegativeAmount::const_from_u64(70000),
                None,
                None
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == NonNegativeAmount::const_from_u64(50000)
                && required == NonNegativeAmount::const_from_u64(80000)
        );

        // Mine blocks SAPLING_ACTIVATION_HEIGHT + 2 to 9 until just before the second
        // note is verified
        for _ in 2..10 {
            st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        }
        st.scan_cached_blocks(h2 + 1, 8);

        // Total balance is value * number of blocks scanned (10).
        assert_eq!(st.get_total_balance(account), (value * 10).unwrap());

        // Spend still fails
        assert_matches!(
            st.propose_standard_transfer::<Infallible>(
                account,
                StandardFeeRule::Zip317,
                NonZeroU32::new(10).unwrap(),
                &to,
                NonNegativeAmount::const_from_u64(70000),
                None,
                None
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == NonNegativeAmount::const_from_u64(50000)
                && required == NonNegativeAmount::const_from_u64(80000)
        );

        // Mine block 11 so that the second note becomes verified
        let (h11, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h11, 1);

        // Total balance is value * number of blocks scanned (11).
        assert_eq!(st.get_total_balance(account), (value * 11).unwrap());
        // Spendable balance at 10 confirmations is value * 2.
        assert_eq!(st.get_spendable_balance(account, 10), (value * 2).unwrap());
        assert_eq!(
            st.get_pending_shielded_balance(account, 10),
            (value * 9).unwrap()
        );

        // Should now be able to generate a proposal
        let amount_sent = NonNegativeAmount::from_u64(70000).unwrap();
        let min_confirmations = NonZeroU32::new(10).unwrap();
        let proposal = st
            .propose_standard_transfer::<Infallible>(
                account,
                StandardFeeRule::Zip317,
                min_confirmations,
                &to,
                amount_sent,
                None,
                None,
            )
            .unwrap();

        // Executing the proposal should succeed
        let txid = st
            .create_proposed_transaction::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal)
            .unwrap();

        let (h, _) = st.generate_next_block_including(txid);
        st.scan_cached_blocks(h, 1);

        // TODO: send to an account so that we can check its balance.
        assert_eq!(
            st.get_total_balance(account),
            ((value * 11).unwrap()
                - (amount_sent + NonNegativeAmount::from_u64(10000).unwrap()).unwrap())
            .unwrap()
        );
    }

    #[test]
    fn spend_fails_on_locked_notes() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // TODO: This test was originally written to use the pre-zip-313 fee rule
        // and has not yet been updated.
        #[allow(deprecated)]
        let fee_rule = StandardFeeRule::PreZip313;

        // Add funds to the wallet in a single note
        let value = NonNegativeAmount::const_from_u64(50000);
        let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);

        // Spendable balance matches total balance at 1 confirmation.
        assert_eq!(st.get_total_balance(account), value);
        assert_eq!(st.get_spendable_balance(account, 1), value);

        // Send some of the funds to another address, but don't mine the tx.
        let extsk2 = ExtendedSpendingKey::master(&[]);
        let to = extsk2.default_address().1.into();
        let min_confirmations = NonZeroU32::new(1).unwrap();
        let proposal = st
            .propose_standard_transfer::<Infallible>(
                account,
                fee_rule,
                min_confirmations,
                &to,
                NonNegativeAmount::const_from_u64(15000),
                None,
                None,
            )
            .unwrap();

        // Executing the proposal should succeed
        assert_matches!(
            st.create_proposed_transaction::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal,),
            Ok(_)
        );

        // A second proposal fails because there are no usable notes
        assert_matches!(
            st.propose_standard_transfer::<Infallible>(
                account,
                fee_rule,
                NonZeroU32::new(1).unwrap(),
                &to,
                NonNegativeAmount::const_from_u64(2000),
                None,
                None
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == NonNegativeAmount::ZERO && required == NonNegativeAmount::const_from_u64(12000)
        );

        // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 41 (that don't send us funds)
        // until just before the first transaction expires
        for i in 1..42 {
            st.generate_next_block(
                &ExtendedSpendingKey::master(&[i as u8]).to_diversifiable_full_viewing_key(),
                AddressType::DefaultExternal,
                value,
            );
        }
        st.scan_cached_blocks(h1 + 1, 41);

        // Second proposal still fails
        assert_matches!(
            st.propose_standard_transfer::<Infallible>(
                account,
                fee_rule,
                NonZeroU32::new(1).unwrap(),
                &to,
                NonNegativeAmount::const_from_u64(2000),
                None,
                None
            ),
            Err(data_api::error::Error::InsufficientFunds {
                available,
                required
            })
            if available == NonNegativeAmount::ZERO && required == NonNegativeAmount::const_from_u64(12000)
        );

        // Mine block SAPLING_ACTIVATION_HEIGHT + 42 so that the first transaction expires
        let (h43, _, _) = st.generate_next_block(
            &ExtendedSpendingKey::master(&[42]).to_diversifiable_full_viewing_key(),
            AddressType::DefaultExternal,
            value,
        );
        st.scan_cached_blocks(h43, 1);

        // Spendable balance matches total balance at 1 confirmation.
        assert_eq!(st.get_total_balance(account), value);
        assert_eq!(st.get_spendable_balance(account, 1), value);

        // Second spend should now succeed
        let amount_sent2 = NonNegativeAmount::const_from_u64(2000);
        let min_confirmations = NonZeroU32::new(1).unwrap();
        let proposal = st
            .propose_standard_transfer::<Infallible>(
                account,
                fee_rule,
                min_confirmations,
                &to,
                amount_sent2,
                None,
                None,
            )
            .unwrap();

        let txid2 = st
            .create_proposed_transaction::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal)
            .unwrap();

        let (h, _) = st.generate_next_block_including(txid2);
        st.scan_cached_blocks(h, 1);

        // TODO: send to an account so that we can check its balance.
        assert_eq!(
            st.get_total_balance(account),
            (value - (amount_sent2 + NonNegativeAmount::from_u64(10000).unwrap()).unwrap())
                .unwrap()
        );
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
        let value = NonNegativeAmount::const_from_u64(50000);
        let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);

        // Spendable balance matches total balance at 1 confirmation.
        assert_eq!(st.get_total_balance(account), value);
        assert_eq!(st.get_spendable_balance(account, 1), value);

        let extsk2 = ExtendedSpendingKey::master(&[]);
        let addr2 = extsk2.default_address().1;
        let to = addr2.into();

        // TODO: This test was originally written to use the pre-zip-313 fee rule
        // and has not yet been updated.
        #[allow(deprecated)]
        let fee_rule = StandardFeeRule::PreZip313;

        #[allow(clippy::type_complexity)]
        let send_and_recover_with_policy = |st: &mut TestState<BlockCache>,
                                            ovk_policy|
         -> Result<
            Option<(Note, PaymentAddress, MemoBytes)>,
            Error<
                SqliteClientError,
                commitment_tree::Error,
                GreedyInputSelectorError<Zip317FeeError, ReceivedNoteId>,
                Zip317FeeError,
            >,
        > {
            let min_confirmations = NonZeroU32::new(1).unwrap();
            let proposal = st.propose_standard_transfer(
                account,
                fee_rule,
                min_confirmations,
                &to,
                NonNegativeAmount::const_from_u64(15000),
                None,
                None,
            )?;

            // Executing the proposal should succeed
            let txid = st.create_proposed_transaction(&usk, ovk_policy, &proposal)?;

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
                    &dfvk.to_ovk(Scope::External),
                    output,
                    sapling_zip212_enforcement(&st.network(), h1),
                );

                if result.is_some() {
                    return Ok(result.map(|(note, addr, memo)| {
                        (
                            note,
                            addr,
                            MemoBytes::from_bytes(&memo).expect("correct length"),
                        )
                    }));
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
                value,
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
    fn spend_succeeds_to_t_addr_zero_change() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Add funds to the wallet in a single note
        let value = NonNegativeAmount::const_from_u64(60000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        // Spendable balance matches total balance at 1 confirmation.
        assert_eq!(st.get_total_balance(account), value);
        assert_eq!(st.get_spendable_balance(account, 1), value);

        // TODO: This test was originally written to use the pre-zip-313 fee rule
        // and has not yet been updated.
        #[allow(deprecated)]
        let fee_rule = StandardFeeRule::PreZip313;

        // TODO: generate_next_block_from_tx does not currently support transparent outputs.
        let to = TransparentAddress::PublicKey([7; 20]).into();
        let min_confirmations = NonZeroU32::new(1).unwrap();
        let proposal = st
            .propose_standard_transfer::<Infallible>(
                account,
                fee_rule,
                min_confirmations,
                &to,
                NonNegativeAmount::const_from_u64(50000),
                None,
                None,
            )
            .unwrap();

        // Executing the proposal should succeed
        assert_matches!(
            st.create_proposed_transaction::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal),
            Ok(_)
        );
    }

    #[test]
    fn change_note_spends_succeed() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, _) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Add funds to the wallet in a single note owned by the internal spending key
        let value = NonNegativeAmount::const_from_u64(60000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::Internal, value);
        st.scan_cached_blocks(h, 1);

        // Spendable balance matches total balance at 1 confirmation.
        assert_eq!(st.get_total_balance(account), value);
        assert_eq!(st.get_spendable_balance(account, 1), value);

        // Value is considered pending at 10 confirmations.
        assert_eq!(st.get_pending_shielded_balance(account, 10), value);
        assert_eq!(
            st.get_spendable_balance(account, 10),
            NonNegativeAmount::ZERO
        );

        // TODO: This test was originally written to use the pre-zip-313 fee rule
        // and has not yet been updated.
        #[allow(deprecated)]
        let fee_rule = StandardFeeRule::PreZip313;

        // TODO: generate_next_block_from_tx does not currently support transparent outputs.
        let to = TransparentAddress::PublicKey([7; 20]).into();
        let min_confirmations = NonZeroU32::new(1).unwrap();
        let proposal = st
            .propose_standard_transfer::<Infallible>(
                account,
                fee_rule,
                min_confirmations,
                &to,
                NonNegativeAmount::const_from_u64(50000),
                None,
                None,
            )
            .unwrap();

        // Executing the proposal should succeed
        assert_matches!(
            st.create_proposed_transaction::<Infallible, _>(&usk, OvkPolicy::Sender, &proposal),
            Ok(_)
        );
    }

    #[test]
    fn external_address_change_spends_detected_in_restore_from_seed() {
        let mut st = TestBuilder::new().with_block_cache().build();

        // Add two accounts to the wallet.
        let seed = Secret::new([0u8; 32].to_vec());
        let birthday = AccountBirthday::from_sapling_activation(&st.network());
        let (_, usk) = st
            .wallet_mut()
            .create_account(&seed, birthday.clone())
            .unwrap();
        let dfvk = usk.sapling().to_diversifiable_full_viewing_key();

        let (_, usk2) = st
            .wallet_mut()
            .create_account(&seed, birthday.clone())
            .unwrap();
        let dfvk2 = usk2.sapling().to_diversifiable_full_viewing_key();

        // Add funds to the wallet in a single note
        let value = NonNegativeAmount::from_u64(100000).unwrap();
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        // Spendable balance matches total balance
        assert_eq!(st.get_total_balance(AccountId::ZERO), value);
        assert_eq!(st.get_spendable_balance(AccountId::ZERO, 1), value);
        assert_eq!(
            st.get_total_balance(AccountId::try_from(1).unwrap()),
            NonNegativeAmount::ZERO,
        );

        let amount_sent = NonNegativeAmount::from_u64(20000).unwrap();
        let amount_legacy_change = NonNegativeAmount::from_u64(30000).unwrap();
        let addr = dfvk.default_address().1;
        let addr2 = dfvk2.default_address().1;
        let req = TransactionRequest::new(vec![
            // payment to an external recipient
            Payment {
                recipient_address: RecipientAddress::Shielded(addr2),
                amount: amount_sent,
                memo: None,
                label: None,
                message: None,
                other_params: vec![],
            },
            // payment back to the originating wallet, simulating legacy change
            Payment {
                recipient_address: RecipientAddress::Shielded(addr),
                amount: amount_legacy_change,
                memo: None,
                label: None,
                message: None,
                other_params: vec![],
            },
        ])
        .unwrap();

        #[allow(deprecated)]
        let fee_rule = FixedFeeRule::standard();
        let input_selector = GreedyInputSelector::new(
            fixed::SingleOutputChangeStrategy::new(fee_rule, None),
            DustOutputPolicy::default(),
        );

        let txid = st
            .spend(
                &input_selector,
                &usk,
                req,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
            )
            .unwrap();

        let amount_left = (value - (amount_sent + fee_rule.fixed_fee()).unwrap()).unwrap();
        let pending_change = (amount_left - amount_legacy_change).unwrap();

        // The "legacy change" is not counted by get_pending_change().
        assert_eq!(st.get_pending_change(AccountId::ZERO, 1), pending_change);
        // We spent the only note so we only have pending change.
        assert_eq!(st.get_total_balance(AccountId::ZERO), pending_change);

        let (h, _) = st.generate_next_block_including(txid);
        st.scan_cached_blocks(h, 1);

        assert_eq!(
            st.get_total_balance(AccountId::try_from(1).unwrap()),
            amount_sent,
        );
        assert_eq!(st.get_total_balance(AccountId::ZERO), amount_left);

        st.reset();

        // Account creation and DFVK derivation should be deterministic.
        let (_, restored_usk) = st
            .wallet_mut()
            .create_account(&seed, birthday.clone())
            .unwrap();
        assert_eq!(
            restored_usk
                .sapling()
                .to_diversifiable_full_viewing_key()
                .to_bytes(),
            dfvk.to_bytes()
        );

        let (_, restored_usk2) = st.wallet_mut().create_account(&seed, birthday).unwrap();
        assert_eq!(
            restored_usk2
                .sapling()
                .to_diversifiable_full_viewing_key()
                .to_bytes(),
            dfvk2.to_bytes()
        );

        st.scan_cached_blocks(st.sapling_activation_height(), 2);

        assert_eq!(
            st.get_total_balance(AccountId::try_from(1).unwrap()),
            amount_sent,
        );
        assert_eq!(st.get_total_balance(AccountId::ZERO), amount_left);
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
            NonNegativeAmount::const_from_u64(50000),
        );

        // Add 10 dust notes to the wallet
        for _ in 1..=10 {
            st.generate_next_block(
                &dfvk,
                AddressType::DefaultExternal,
                NonNegativeAmount::const_from_u64(1000),
            );
        }

        st.scan_cached_blocks(h1, 11);

        // Spendable balance matches total balance
        let total = NonNegativeAmount::const_from_u64(60000);
        assert_eq!(st.get_total_balance(account), total);
        assert_eq!(st.get_spendable_balance(account, 1), total);

        let input_selector = input_selector(StandardFeeRule::Zip317, None);

        // This first request will fail due to insufficient non-dust funds
        let req = TransactionRequest::new(vec![Payment {
            recipient_address: RecipientAddress::Shielded(dfvk.default_address().1),
            amount: NonNegativeAmount::const_from_u64(50000),
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
                if available == NonNegativeAmount::const_from_u64(51000)
                && required == NonNegativeAmount::const_from_u64(60000)
        );

        // This request will succeed, spending a single dust input to pay the 10000
        // ZAT fee in addition to the 41000 ZAT output to the recipient
        let req = TransactionRequest::new(vec![Payment {
            recipient_address: RecipientAddress::Shielded(dfvk.default_address().1),
            amount: NonNegativeAmount::const_from_u64(41000),
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        }])
        .unwrap();

        let txid = st
            .spend(
                &input_selector,
                &usk,
                req,
                OvkPolicy::Sender,
                NonZeroU32::new(1).unwrap(),
            )
            .unwrap();

        let (h, _) = st.generate_next_block_including(txid);
        st.scan_cached_blocks(h, 1);

        // TODO: send to an account so that we can check its balance.
        // We sent back to the same account so the amount_sent should be included
        // in the total balance.
        assert_eq!(
            st.get_total_balance(account),
            (total - NonNegativeAmount::const_from_u64(10000)).unwrap()
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
            NonNegativeAmount::const_from_u64(50000),
        );
        st.scan_cached_blocks(h, 1);

        let utxo = WalletTransparentOutput::from_parts(
            OutPoint::new([1u8; 32], 1),
            TxOut {
                value: NonNegativeAmount::const_from_u64(10000),
                script_pubkey: taddr.script(),
            },
            h,
        )
        .unwrap();

        let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
        assert!(matches!(res0, Ok(_)));

        // TODO: This test was originally written to use the pre-zip-313 fee rule
        // and has not yet been updated.
        #[allow(deprecated)]
        let fee_rule = StandardFeeRule::PreZip313;

        let input_selector = GreedyInputSelector::new(
            standard::SingleOutputChangeStrategy::new(fee_rule, None),
            DustOutputPolicy::default(),
        );

        assert_matches!(
            st.shield_transparent_funds(
                &input_selector,
                NonNegativeAmount::from_u64(10000).unwrap(),
                &usk,
                &[*taddr],
                1
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
        let not_our_value = NonNegativeAmount::const_from_u64(10000);
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
            NonNegativeAmount::const_from_u64(500000),
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
            AccountId::ZERO,
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
            AccountId::ZERO,
            Amount::const_from_i64(300000),
            received_tx_height + 10,
            &[],
        )
        .unwrap();

        assert_eq!(spendable.len(), 1);
    }

    #[test]
    fn checkpoint_gaps() {
        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_test_account(AccountBirthday::from_sapling_activation)
            .build();

        let (account, usk, birthday) = st.test_account().unwrap();
        let dfvk = st.test_account_sapling().unwrap();

        // Generate a block with funds belonging to our wallet.
        st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            NonNegativeAmount::const_from_u64(500000),
        );
        st.scan_cached_blocks(birthday.height(), 1);

        // Create a gap of 10 blocks having no shielded outputs, then add a block that doesn't
        // belong to us so that we can get a checkpoint in the tree.
        let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
        let not_our_value = NonNegativeAmount::const_from_u64(10000);
        st.generate_block_at(
            birthday.height() + 10,
            BlockHash([0; 32]),
            &not_our_key,
            AddressType::DefaultExternal,
            not_our_value,
            st.latest_cached_block().unwrap().2,
        );

        // Scan the block
        st.scan_cached_blocks(birthday.height() + 10, 1);

        // Fake that everything has been scanned
        st.wallet()
            .conn
            .execute_batch("UPDATE scan_queue SET priority = 10")
            .unwrap();

        // Verify that our note is considered spendable
        let spendable = select_spendable_sapling_notes(
            &st.wallet().conn,
            account,
            Amount::const_from_i64(300000),
            birthday.height() + 5,
            &[],
        )
        .unwrap();
        assert_eq!(spendable.len(), 1);

        // Attempt to spend the note with 5 confirmations
        let to = not_our_key.default_address().1.into();
        assert_matches!(
            st.create_spend_to_address(
                &usk,
                &to,
                NonNegativeAmount::const_from_u64(10000),
                None,
                OvkPolicy::Sender,
                NonZeroU32::new(5).unwrap(),
                None
            ),
            Ok(_)
        );
    }
}
