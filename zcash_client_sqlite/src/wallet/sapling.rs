//! Functions for Sapling support in the wallet.

use group::ff::PrimeField;
use incrementalmerkletree::Position;
use rusqlite::{named_params, params, types::Value, Connection, Row};
use std::rc::Rc;

use sapling::{self, Diversifier, Nullifier, Rseed};
use zcash_client_backend::{
    data_api::NullifierQuery,
    wallet::{Note, ReceivedNote, WalletSaplingOutput},
    DecryptedOutput, ShieldedProtocol, TransferType,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{components::amount::NonNegativeAmount, TxId};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
};
use zip32::Scope;

use crate::{error::SqliteClientError, AccountId, ReceivedNoteId};

use super::{memo_repr, parse_scope, scope_code, wallet_birthday};

/// This trait provides a generalization over shielded output representations.
pub(crate) trait ReceivedSaplingOutput {
    fn index(&self) -> usize;
    fn account_id(&self) -> AccountId;
    fn note(&self) -> &sapling::Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> bool;
    fn nullifier(&self) -> Option<&sapling::Nullifier>;
    fn note_commitment_tree_position(&self) -> Option<Position>;
    fn recipient_key_scope(&self) -> Option<Scope>;
}

impl ReceivedSaplingOutput for WalletSaplingOutput<AccountId> {
    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> AccountId {
        *WalletSaplingOutput::account_id(self)
    }
    fn note(&self) -> &sapling::Note {
        WalletSaplingOutput::note(self)
    }
    fn memo(&self) -> Option<&MemoBytes> {
        None
    }
    fn is_change(&self) -> bool {
        WalletSaplingOutput::is_change(self)
    }
    fn nullifier(&self) -> Option<&sapling::Nullifier> {
        self.nf()
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        Some(WalletSaplingOutput::note_commitment_tree_position(self))
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        self.recipient_key_scope()
    }
}

impl ReceivedSaplingOutput for DecryptedOutput<sapling::Note, AccountId> {
    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> AccountId {
        *self.account()
    }
    fn note(&self) -> &sapling::Note {
        self.note()
    }
    fn memo(&self) -> Option<&MemoBytes> {
        Some(self.memo())
    }
    fn is_change(&self) -> bool {
        self.transfer_type() == TransferType::WalletInternal
    }
    fn nullifier(&self) -> Option<&sapling::Nullifier> {
        None
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        None
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        if self.transfer_type() == TransferType::WalletInternal {
            Some(Scope::Internal)
        } else {
            Some(Scope::External)
        }
    }
}

fn to_spendable_note<P: consensus::Parameters>(
    params: &P,
    row: &Row,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    let note_id = ReceivedNoteId(ShieldedProtocol::Sapling, row.get(0)?);
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

    let note_value: u64 = row.get::<_, i64>(4)?.try_into().map_err(|_e| {
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

    let ufvk_str: Option<String> = row.get(7)?;
    let scope_code: Option<i64> = row.get(8)?;

    // If we don't have information about the recipient key scope or the ufvk we can't determine
    // which spending key to use. This may be because the received note was associated with an
    // imported viewing key, so we treat such notes as not spendable. Although this method is
    // presently only called using the results of queries where both the ufvk and
    // recipient_key_scope columns are checked to be non-null, this is method is written
    // defensively to account for the fact that both of these are nullable columns in case it
    // is used elsewhere in the future.
    ufvk_str
        .zip(scope_code)
        .map(|(ufvk_str, scope_code)| {
            let ufvk = UnifiedFullViewingKey::decode(params, &ufvk_str)
                .map_err(SqliteClientError::CorruptedData)?;

            let spending_key_scope = parse_scope(scope_code).ok_or_else(|| {
                SqliteClientError::CorruptedData(format!("Invalid key scope code {}", scope_code))
            })?;

            let recipient = match spending_key_scope {
                Scope::Internal => ufvk
                    .sapling()
                    .and_then(|dfvk| dfvk.diversified_change_address(diversifier)),
                Scope::External => ufvk
                    .sapling()
                    .and_then(|dfvk| dfvk.diversified_address(diversifier)),
            }
            .ok_or_else(|| SqliteClientError::CorruptedData("Diversifier invalid.".to_owned()))?;

            Ok(ReceivedNote::from_parts(
                note_id,
                txid,
                output_index,
                Note::Sapling(sapling::Note::from_parts(
                    recipient,
                    sapling::value::NoteValue::from_raw(note_value),
                    rseed,
                )),
                spending_key_scope,
                note_commitment_tree_position,
            ))
        })
        .transpose()
}

// The `clippy::let_and_return` lint is explicitly allowed here because a bug in Clippy
// (https://github.com/rust-lang/rust-clippy/issues/11308) means it fails to identify that the `result` temporary
// is required in order to resolve the borrows involved in the `query_and_then` call.
#[allow(clippy::let_and_return)]
pub(crate) fn get_spendable_sapling_note<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    txid: &TxId,
    index: u32,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    let result = conn.query_row_and_then(
        "SELECT sapling_received_notes.id, txid, output_index,
                diversifier, value, rcm, commitment_tree_position,
                accounts.ufvk, recipient_key_scope
         FROM sapling_received_notes
         INNER JOIN accounts on accounts.id = sapling_received_notes.account_id
         INNER JOIN transactions ON transactions.id_tx = sapling_received_notes.tx
         WHERE txid = :txid
         AND accounts.ufvk IS NOT NULL
         AND recipient_key_scope IS NOT NULL
         AND output_index = :output_index
         AND spent IS NULL",
        named_params![
           ":txid": txid.as_ref(),
           ":output_index": index,
        ],
        |row| to_spendable_note(params, row),
    );

    // `OptionalExtension` doesn't work here because the error type of `Result` is already
    // `SqliteClientError`
    match result {
        Ok(r) => Ok(r),
        Err(SqliteClientError::DbError(rusqlite::Error::QueryReturnedNoRows)) => Ok(None),
        Err(e) => Err(e),
    }
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

pub(crate) fn select_spendable_sapling_notes<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountId,
    target_value: NonNegativeAmount,
    anchor_height: BlockHeight,
    exclude: &[ReceivedNoteId],
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
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
             SELECT
                 sapling_received_notes.id AS id, txid, output_index, diversifier, value, rcm, commitment_tree_position,
                 SUM(value)
                    OVER (PARTITION BY sapling_received_notes.account_id, spent ORDER BY sapling_received_notes.id) AS so_far,
                 accounts.ufvk as ufvk, recipient_key_scope
             FROM sapling_received_notes
             INNER JOIN accounts on accounts.id = sapling_received_notes.account_id
             INNER JOIN transactions
                ON transactions.id_tx = sapling_received_notes.tx
             WHERE sapling_received_notes.account_id = :account
             AND ufvk IS NOT NULL
             AND recipient_key_scope IS NOT NULL
             AND commitment_tree_position IS NOT NULL
             AND spent IS NULL
             AND transactions.block <= :anchor_height
             AND sapling_received_notes.id NOT IN rarray(:exclude)
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
         SELECT id, txid, output_index, diversifier, value, rcm, commitment_tree_position, ufvk, recipient_key_scope
         FROM eligible WHERE so_far < :target_value
         UNION
         SELECT id, txid, output_index, diversifier, value, rcm, commitment_tree_position, ufvk, recipient_key_scope
         FROM (SELECT * from eligible WHERE so_far >= :target_value LIMIT 1)",
    )?;

    let excluded: Vec<Value> = exclude.iter().map(|n| Value::from(n.1)).collect();
    let excluded_ptr = Rc::new(excluded);

    let notes = stmt_select_notes.query_and_then(
        named_params![
            ":account": account.0,
            ":anchor_height": &u32::from(anchor_height),
            ":target_value": &u64::from(target_value),
            ":exclude": &excluded_ptr,
            ":wallet_birthday": u32::from(birthday_height)
        ],
        |r| to_spendable_note(params, r),
    )?;

    notes
        .filter_map(|r| r.transpose())
        .collect::<Result<_, _>>()
}

/// Retrieves the set of nullifiers for "potentially spendable" Sapling notes that the
/// wallet is tracking.
///
/// "Potentially spendable" means:
/// - The transaction in which the note was created has been observed as mined.
/// - No transaction in which the note's nullifier appears has been observed as mined.
pub(crate) fn get_sapling_nullifiers(
    conn: &Connection,
    query: NullifierQuery,
) -> Result<Vec<(AccountId, Nullifier)>, SqliteClientError> {
    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers = match query {
        NullifierQuery::Unspent => conn.prepare(
            "SELECT rn.account_id, rn.nf
             FROM sapling_received_notes rn
             LEFT OUTER JOIN transactions tx
             ON tx.id_tx = rn.spent
             WHERE tx.block IS NULL
             AND nf IS NOT NULL",
        ),
        NullifierQuery::All => conn.prepare(
            "SELECT rn.account_id, rn.nf
             FROM sapling_received_notes rn
             WHERE nf IS NOT NULL",
        ),
    }?;

    let nullifiers = stmt_fetch_nullifiers.query_and_then([], |row| {
        let account = AccountId(row.get(0)?);
        let nf_bytes: Vec<u8> = row.get(1)?;
        Ok::<_, rusqlite::Error>((account, sapling::Nullifier::from_slice(&nf_bytes).unwrap()))
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
        (tx, output_index, account_id, diversifier, value, rcm, memo, nf,
         is_change, spent, commitment_tree_position,
         recipient_key_scope)
        VALUES (
            :tx,
            :output_index,
            :account_id,
            :diversifier,
            :value,
            :rcm,
            :memo,
            :nf,
            :is_change,
            :spent,
            :commitment_tree_position,
            :recipient_key_scope
        )
        ON CONFLICT (tx, output_index) DO UPDATE
        SET account_id = :account_id,
            diversifier = :diversifier,
            value = :value,
            rcm = :rcm,
            nf = IFNULL(:nf, nf),
            memo = IFNULL(:memo, memo),
            is_change = IFNULL(:is_change, is_change),
            spent = IFNULL(:spent, spent),
            commitment_tree_position = IFNULL(:commitment_tree_position, commitment_tree_position),
            recipient_key_scope = :recipient_key_scope",
    )?;

    let rcm = output.note().rcm().to_repr();
    let to = output.note().recipient();
    let diversifier = to.diversifier();

    let sql_args = named_params![
        ":tx": &tx_ref,
        ":output_index": i64::try_from(output.index()).expect("output indices are representable as i64"),
        ":account_id": output.account_id().0,
        ":diversifier": &diversifier.0.as_ref(),
        ":value": output.note().value().inner(),
        ":rcm": &rcm.as_ref(),
        ":nf": output.nullifier().map(|nf| nf.0.as_ref()),
        ":memo": memo_repr(output.memo()),
        ":is_change": output.is_change(),
        ":spent": spent_in,
        ":commitment_tree_position": output.note_commitment_tree_position().map(u64::from),
        ":recipient_key_scope": output.recipient_key_scope().map(scope_code)
    ];

    stmt_upsert_received_note
        .execute(sql_args)
        .map_err(SqliteClientError::from)?;

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use incrementalmerkletree::{Hashable, Level};
    use shardtree::error::ShardTreeError;
    use zcash_proofs::prover::LocalTxProver;

    use sapling::{
        self,
        note_encryption::try_sapling_output_recovery,
        prover::{OutputProver, SpendProver},
        zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey},
    };
    use zcash_primitives::{
        consensus::BlockHeight,
        memo::MemoBytes,
        transaction::{
            components::{amount::NonNegativeAmount, sapling::zip212_enforcement},
            Transaction,
        },
        zip32::Scope,
    };

    use zcash_client_backend::{
        address::Address,
        data_api::{
            chain::CommitmentTreeRoot, DecryptedTransaction, WalletCommitmentTrees, WalletSummary,
        },
        keys::UnifiedSpendingKey,
        wallet::{Note, ReceivedNote},
        ShieldedProtocol,
    };

    use crate::{
        error::SqliteClientError,
        testing::{
            self,
            pool::{OutputRecoveryError, ShieldedPoolTester},
            TestState,
        },
        wallet::{commitment_tree, sapling::select_spendable_sapling_notes},
        AccountId, ReceivedNoteId, SAPLING_TABLES_PREFIX,
    };

    pub(crate) struct SaplingPoolTester;
    impl ShieldedPoolTester for SaplingPoolTester {
        const SHIELDED_PROTOCOL: ShieldedProtocol = ShieldedProtocol::Sapling;
        const TABLES_PREFIX: &'static str = SAPLING_TABLES_PREFIX;

        type Sk = ExtendedSpendingKey;
        type Fvk = DiversifiableFullViewingKey;
        type MerkleTreeHash = sapling::Node;

        fn test_account_fvk<Cache>(st: &TestState<Cache>) -> Self::Fvk {
            st.test_account_sapling().unwrap()
        }

        fn usk_to_sk(usk: &UnifiedSpendingKey) -> &Self::Sk {
            usk.sapling()
        }

        fn sk(seed: &[u8]) -> Self::Sk {
            ExtendedSpendingKey::master(seed)
        }

        fn sk_to_fvk(sk: &Self::Sk) -> Self::Fvk {
            sk.to_diversifiable_full_viewing_key()
        }

        fn sk_default_address(sk: &Self::Sk) -> Address {
            sk.default_address().1.into()
        }

        fn fvk_default_address(fvk: &Self::Fvk) -> Address {
            fvk.default_address().1.into()
        }

        fn fvks_equal(a: &Self::Fvk, b: &Self::Fvk) -> bool {
            a.to_bytes() == b.to_bytes()
        }

        fn empty_tree_leaf() -> Self::MerkleTreeHash {
            sapling::Node::empty_leaf()
        }

        fn empty_tree_root(level: Level) -> Self::MerkleTreeHash {
            sapling::Node::empty_root(level)
        }

        fn put_subtree_roots<Cache>(
            st: &mut TestState<Cache>,
            start_index: u64,
            roots: &[CommitmentTreeRoot<Self::MerkleTreeHash>],
        ) -> Result<(), ShardTreeError<commitment_tree::Error>> {
            st.wallet_mut()
                .put_sapling_subtree_roots(start_index, roots)
        }

        fn next_subtree_index(s: &WalletSummary<AccountId>) -> u64 {
            s.next_sapling_subtree_index()
        }

        fn select_spendable_notes<Cache>(
            st: &TestState<Cache>,
            account: AccountId,
            target_value: NonNegativeAmount,
            anchor_height: BlockHeight,
            exclude: &[ReceivedNoteId],
        ) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
            select_spendable_sapling_notes(
                &st.wallet().conn,
                &st.wallet().params,
                account,
                target_value,
                anchor_height,
                exclude,
            )
        }

        fn decrypted_pool_outputs_count(d_tx: &DecryptedTransaction<'_, AccountId>) -> usize {
            d_tx.sapling_outputs().len()
        }

        fn with_decrypted_pool_memos(
            d_tx: &DecryptedTransaction<'_, AccountId>,
            mut f: impl FnMut(&MemoBytes),
        ) {
            for output in d_tx.sapling_outputs() {
                f(output.memo());
            }
        }

        fn try_output_recovery<Cache>(
            st: &TestState<Cache>,
            height: BlockHeight,
            tx: &Transaction,
            fvk: &Self::Fvk,
        ) -> Result<Option<(Note, Address, MemoBytes)>, OutputRecoveryError> {
            for output in tx.sapling_bundle().unwrap().shielded_outputs() {
                // Find the output that decrypts with the external OVK
                let result = try_sapling_output_recovery(
                    &fvk.to_ovk(Scope::External),
                    output,
                    zip212_enforcement(&st.network(), height),
                );

                if result.is_some() {
                    return Ok(result.map(|(note, addr, memo)| {
                        (
                            Note::Sapling(note),
                            addr.into(),
                            MemoBytes::from_bytes(&memo).expect("correct length"),
                        )
                    }));
                }
            }

            Ok(None)
        }

        fn received_note_count(
            summary: &zcash_client_backend::data_api::chain::ScanSummary,
        ) -> usize {
            summary.received_sapling_note_count()
        }
    }

    pub(crate) fn test_prover() -> impl SpendProver + OutputProver {
        LocalTxProver::bundled()
    }

    #[test]
    fn send_single_step_proposed_transfer() {
        testing::pool::send_single_step_proposed_transfer::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn send_multi_step_proposed_transfer() {
        testing::pool::send_multi_step_proposed_transfer::<SaplingPoolTester>()
    }

    #[test]
    #[allow(deprecated)]
    fn create_to_address_fails_on_incorrect_usk() {
        testing::pool::create_to_address_fails_on_incorrect_usk::<SaplingPoolTester>()
    }

    #[test]
    #[allow(deprecated)]
    fn proposal_fails_with_no_blocks() {
        testing::pool::proposal_fails_with_no_blocks::<SaplingPoolTester>()
    }

    #[test]
    fn spend_fails_on_unverified_notes() {
        testing::pool::spend_fails_on_unverified_notes::<SaplingPoolTester>()
    }

    #[test]
    fn spend_fails_on_locked_notes() {
        testing::pool::spend_fails_on_locked_notes::<SaplingPoolTester>()
    }

    #[test]
    fn ovk_policy_prevents_recovery_from_chain() {
        testing::pool::ovk_policy_prevents_recovery_from_chain::<SaplingPoolTester>()
    }

    #[test]
    fn spend_succeeds_to_t_addr_zero_change() {
        testing::pool::spend_succeeds_to_t_addr_zero_change::<SaplingPoolTester>()
    }

    #[test]
    fn change_note_spends_succeed() {
        testing::pool::change_note_spends_succeed::<SaplingPoolTester>()
    }

    #[test]
    fn external_address_change_spends_detected_in_restore_from_seed() {
        testing::pool::external_address_change_spends_detected_in_restore_from_seed::<
            SaplingPoolTester,
        >()
    }

    #[test]
    fn zip317_spend() {
        testing::pool::zip317_spend::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn shield_transparent() {
        testing::pool::shield_transparent::<SaplingPoolTester>()
    }

    #[test]
    fn birthday_in_anchor_shard() {
        testing::pool::birthday_in_anchor_shard::<SaplingPoolTester>()
    }

    #[test]
    fn checkpoint_gaps() {
        testing::pool::checkpoint_gaps::<SaplingPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_detects_spends_out_of_order() {
        testing::pool::scan_cached_blocks_detects_spends_out_of_order::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn cross_pool_exchange() {
        use crate::wallet::orchard::tests::OrchardPoolTester;

        testing::pool::cross_pool_exchange::<SaplingPoolTester, OrchardPoolTester>()
    }
}
