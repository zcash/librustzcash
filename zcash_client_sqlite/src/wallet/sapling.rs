//! Functions for Sapling support in the wallet.

use std::{collections::HashSet, rc::Rc};

use group::ff::PrimeField;
use incrementalmerkletree::Position;
use rusqlite::{named_params, types::Value, Connection, Row, Transaction};

use sapling::{self, Diversifier, Nullifier, Rseed};
use zcash_client_backend::{
    data_api::NullifierQuery,
    wallet::{ReceivedNote, WalletSaplingOutput},
    DecryptedOutput, ShieldedProtocol, TransferType,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{components::amount::NonNegativeAmount, TxId};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
};
use zip32::Scope;

use crate::{error::SqliteClientError, AccountId, ReceivedNoteId, TxRef};

use super::{memo_repr, parse_scope, scope_code};

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
) -> Result<Option<ReceivedNote<ReceivedNoteId, sapling::Note>>, SqliteClientError> {
    let note_id = ReceivedNoteId(ShieldedProtocol::Sapling, row.get("id")?);
    let txid = row.get::<_, [u8; 32]>("txid").map(TxId::from_bytes)?;
    let output_index = row.get("output_index")?;
    let diversifier = {
        let d: Vec<_> = row.get("diversifier")?;
        if d.len() != 11 {
            return Err(SqliteClientError::CorruptedData(
                "Invalid diversifier length".to_string(),
            ));
        }
        let mut tmp = [0; 11];
        tmp.copy_from_slice(&d);
        Diversifier(tmp)
    };

    let note_value: u64 = row.get::<_, i64>("value")?.try_into().map_err(|_e| {
        SqliteClientError::CorruptedData("Note values must be nonnegative".to_string())
    })?;

    let rseed = {
        let rcm_bytes: Vec<_> = row.get("rcm")?;

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

    let note_commitment_tree_position = Position::from(
        u64::try_from(row.get::<_, i64>("commitment_tree_position")?).map_err(|_| {
            SqliteClientError::CorruptedData("Note commitment tree position invalid.".to_string())
        })?,
    );

    let ufvk_str: Option<String> = row.get("ufvk")?;
    let scope_code: Option<i64> = row.get("recipient_key_scope")?;

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
                sapling::Note::from_parts(
                    recipient,
                    sapling::value::NoteValue::from_raw(note_value),
                    rseed,
                ),
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
) -> Result<Option<ReceivedNote<ReceivedNoteId, sapling::Note>>, SqliteClientError> {
    super::common::get_spendable_note(
        conn,
        params,
        txid,
        index,
        ShieldedProtocol::Sapling,
        to_spendable_note,
    )
}

/// Utility method for determining whether we have any spendable notes
///
/// If the tip shard has unscanned ranges below the anchor height and greater than or equal to
/// the wallet birthday, none of our notes can be spent because we cannot construct witnesses at
/// the provided anchor height.
pub(crate) fn select_spendable_sapling_notes<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountId,
    target_value: NonNegativeAmount,
    anchor_height: BlockHeight,
    exclude: &[ReceivedNoteId],
) -> Result<Vec<ReceivedNote<ReceivedNoteId, sapling::Note>>, SqliteClientError> {
    super::common::select_spendable_notes(
        conn,
        params,
        account,
        target_value,
        anchor_height,
        exclude,
        ShieldedProtocol::Sapling,
        to_spendable_note,
    )
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
             JOIN transactions tx ON tx.id_tx = rn.tx
             WHERE rn.nf IS NOT NULL
             AND tx.block IS NOT NULL
             AND rn.id NOT IN (
               SELECT spends.sapling_received_note_id
               FROM sapling_received_note_spends spends
               JOIN transactions stx ON stx.id_tx = spends.transaction_id
               WHERE stx.block IS NOT NULL  -- the spending tx is mined
               OR stx.expiry_height IS NULL -- the spending tx will not expire
             )",
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

pub(crate) fn detect_spending_accounts<'a>(
    conn: &Connection,
    nfs: impl Iterator<Item = &'a Nullifier>,
) -> Result<HashSet<AccountId>, rusqlite::Error> {
    let mut account_q = conn.prepare_cached(
        "SELECT rn.account_id
        FROM sapling_received_notes rn
        WHERE rn.nf IN rarray(:nf_ptr)",
    )?;

    let nf_values: Vec<Value> = nfs.map(|nf| Value::Blob(nf.to_vec())).collect();
    let nf_ptr = Rc::new(nf_values);
    let res = account_q
        .query_and_then(named_params![":nf_ptr": &nf_ptr], |row| {
            row.get::<_, u32>(0).map(AccountId)
        })?
        .collect::<Result<HashSet<_>, _>>()?;

    Ok(res)
}

/// Marks a given nullifier as having been revealed in the construction
/// of the specified transaction.
///
/// Marking a note spent in this fashion does NOT imply that the
/// spending transaction has been mined.
pub(crate) fn mark_sapling_note_spent(
    conn: &Connection,
    tx_ref: TxRef,
    nf: &sapling::Nullifier,
) -> Result<bool, SqliteClientError> {
    let mut stmt_mark_sapling_note_spent = conn.prepare_cached(
        "INSERT INTO sapling_received_note_spends (sapling_received_note_id, transaction_id)
         SELECT id, :transaction_id FROM sapling_received_notes WHERE nf = :nf
         ON CONFLICT (sapling_received_note_id, transaction_id) DO NOTHING",
    )?;

    match stmt_mark_sapling_note_spent.execute(named_params![
       ":nf": &nf.0[..],
       ":transaction_id": tx_ref.0
    ])? {
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
    conn: &Transaction,
    output: &T,
    tx_ref: TxRef,
    spent_in: Option<TxRef>,
) -> Result<(), SqliteClientError> {
    let mut stmt_upsert_received_note = conn.prepare_cached(
        "INSERT INTO sapling_received_notes
        (tx, output_index, account_id, diversifier, value, rcm, memo, nf,
         is_change, commitment_tree_position,
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
            commitment_tree_position = IFNULL(:commitment_tree_position, commitment_tree_position),
            recipient_key_scope = :recipient_key_scope
        RETURNING sapling_received_notes.id",
    )?;

    let rcm = output.note().rcm().to_repr();
    let to = output.note().recipient();
    let diversifier = to.diversifier();

    let sql_args = named_params![
        ":tx": tx_ref.0,
        ":output_index": i64::try_from(output.index()).expect("output indices are representable as i64"),
        ":account_id": output.account_id().0,
        ":diversifier": &diversifier.0.as_ref(),
        ":value": output.note().value().inner(),
        ":rcm": &rcm.as_ref(),
        ":nf": output.nullifier().map(|nf| nf.0.as_ref()),
        ":memo": memo_repr(output.memo()),
        ":is_change": output.is_change(),
        ":commitment_tree_position": output.note_commitment_tree_position().map(u64::from),
        ":recipient_key_scope": output.recipient_key_scope().map(scope_code)
    ];

    let received_note_id = stmt_upsert_received_note
        .query_row(sql_args, |row| row.get::<_, i64>(0))
        .map_err(SqliteClientError::from)?;

    if let Some(spent_in) = spent_in {
        conn.execute(
            "INSERT INTO sapling_received_note_spends (sapling_received_note_id, transaction_id)
             VALUES (:sapling_received_note_id, :transaction_id)
             ON CONFLICT (sapling_received_note_id, transaction_id) DO NOTHING",
            named_params![
                ":sapling_received_note_id": received_note_id,
                ":transaction_id": spent_in.0
            ],
        )?;
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use zcash_client_backend::data_api::testing::sapling::SaplingPoolTester;

    use crate::testing;

    #[cfg(feature = "orchard")]
    use zcash_client_backend::data_api::testing::orchard::OrchardPoolTester;

    #[test]
    fn send_single_step_proposed_transfer() {
        testing::pool::send_single_step_proposed_transfer::<SaplingPoolTester>()
    }

    #[test]
    fn send_with_multiple_change_outputs() {
        testing::pool::send_with_multiple_change_outputs::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn send_multi_step_proposed_transfer() {
        testing::pool::send_multi_step_proposed_transfer::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn proposal_fails_if_not_all_ephemeral_outputs_consumed() {
        testing::pool::proposal_fails_if_not_all_ephemeral_outputs_consumed::<SaplingPoolTester>()
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
    #[ignore] // FIXME: #1316 This requires support for dust outputs.
    #[cfg(not(feature = "expensive-tests"))]
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
    fn pool_crossing_required() {
        testing::pool::pool_crossing_required::<SaplingPoolTester, OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn fully_funded_fully_private() {
        testing::pool::fully_funded_fully_private::<SaplingPoolTester, OrchardPoolTester>()
    }

    #[test]
    #[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
    fn fully_funded_send_to_t() {
        testing::pool::fully_funded_send_to_t::<SaplingPoolTester, OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn multi_pool_checkpoint() {
        testing::pool::multi_pool_checkpoint::<SaplingPoolTester, OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn multi_pool_checkpoints_with_pruning() {
        testing::pool::multi_pool_checkpoints_with_pruning::<SaplingPoolTester, OrchardPoolTester>()
    }
}
