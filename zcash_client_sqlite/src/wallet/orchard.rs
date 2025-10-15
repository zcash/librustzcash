use std::{collections::HashSet, rc::Rc};

use incrementalmerkletree::Position;
use orchard::{
    keys::Diversifier,
    note::{Note, Nullifier, RandomSeed, Rho},
};
use rusqlite::{named_params, types::Value, Connection, Row};

use zcash_client_backend::{
    data_api::{
        wallet::{ConfirmationsPolicy, TargetHeight},
        Account as _, NullifierQuery, TargetValue,
    },
    wallet::{ReceivedNote, WalletOrchardOutput},
    DecryptedOutput, TransferType,
};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    ShieldedProtocol,
};
use zip32::Scope;

use crate::{error::SqliteClientError, AccountRef, AccountUuid, AddressRef, ReceivedNoteId, TxRef};

use super::{
    common::UnspentNoteMeta, get_account, get_account_ref, memo_repr, upsert_address, KeyScope,
};

/// This trait provides a generalization over shielded output representations.
pub(crate) trait ReceivedOrchardOutput {
    type AccountId;

    fn index(&self) -> usize;
    fn account_id(&self) -> Self::AccountId;
    fn note(&self) -> &Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> bool;
    fn nullifier(&self) -> Option<&Nullifier>;
    fn note_commitment_tree_position(&self) -> Option<Position>;
    fn recipient_key_scope(&self) -> Option<Scope>;
}

impl<AccountId: Copy> ReceivedOrchardOutput for WalletOrchardOutput<AccountId> {
    type AccountId = AccountId;

    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> Self::AccountId {
        *WalletOrchardOutput::account_id(self)
    }
    fn note(&self) -> &Note {
        WalletOrchardOutput::note(self)
    }
    fn memo(&self) -> Option<&MemoBytes> {
        None
    }
    fn is_change(&self) -> bool {
        WalletOrchardOutput::is_change(self)
    }
    fn nullifier(&self) -> Option<&Nullifier> {
        self.nf()
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        Some(WalletOrchardOutput::note_commitment_tree_position(self))
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        self.recipient_key_scope()
    }
}

impl<AccountId: Copy> ReceivedOrchardOutput for DecryptedOutput<Note, AccountId> {
    type AccountId = AccountId;

    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> Self::AccountId {
        *self.account()
    }
    fn note(&self) -> &orchard::note::Note {
        self.note()
    }
    fn memo(&self) -> Option<&MemoBytes> {
        Some(self.memo())
    }
    fn is_change(&self) -> bool {
        self.transfer_type() == TransferType::WalletInternal
    }
    fn nullifier(&self) -> Option<&Nullifier> {
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

pub(crate) fn to_received_note<P: consensus::Parameters>(
    params: &P,
    row: &Row,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    let note_id = ReceivedNoteId(ShieldedProtocol::Orchard, row.get("id")?);
    let txid = row.get::<_, [u8; 32]>("txid").map(TxId::from_bytes)?;
    let action_index = row.get("action_index")?;
    let diversifier = {
        let d: Vec<_> = row.get("diversifier")?;
        if d.len() != 11 {
            return Err(SqliteClientError::CorruptedData(
                "Invalid diversifier length".to_string(),
            ));
        }
        let mut tmp = [0; 11];
        tmp.copy_from_slice(&d);
        Diversifier::from_bytes(tmp)
    };

    let note_value: u64 = row.get::<_, i64>("value")?.try_into().map_err(|_e| {
        SqliteClientError::CorruptedData("Note values must be nonnegative".to_string())
    })?;

    let rho = {
        let rho_bytes: [u8; 32] = row.get("rho")?;
        Option::from(Rho::from_bytes(&rho_bytes))
            .ok_or_else(|| SqliteClientError::CorruptedData("Invalid rho.".to_string()))
    }?;

    let rseed = {
        let rseed_bytes: [u8; 32] = row.get("rseed")?;
        Option::from(RandomSeed::from_bytes(rseed_bytes, &rho)).ok_or_else(|| {
            SqliteClientError::CorruptedData("Invalid Orchard random seed.".to_string())
        })
    }?;

    let note_commitment_tree_position = Position::from(
        u64::try_from(row.get::<_, i64>("commitment_tree_position")?).map_err(|_| {
            SqliteClientError::CorruptedData("Note commitment tree position invalid.".to_string())
        })?,
    );

    let ufvk_str: Option<String> = row.get("ufvk")?;
    let scope_code: Option<i64> = row.get("recipient_key_scope")?;
    let mined_height = row
        .get::<_, Option<u32>>("mined_height")?
        .map(BlockHeight::from);
    let max_shielding_input_height = row
        .get::<_, Option<u32>>("max_shielding_input_height")?
        .map(BlockHeight::from);

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

            let spending_key_scope = zip32::Scope::try_from(KeyScope::decode(scope_code)?)
                .map_err(|_| {
                    SqliteClientError::CorruptedData(format!("Invalid key scope code {scope_code}"))
                })?;

            let recipient = ufvk
                .orchard()
                .map(|fvk| fvk.to_ivk(spending_key_scope).address(diversifier))
                .ok_or_else(|| {
                    SqliteClientError::CorruptedData("Diversifier invalid.".to_owned())
                })?;

            let note = Option::from(Note::from_parts(
                recipient,
                orchard::value::NoteValue::from_raw(note_value),
                rho,
                rseed,
            ))
            .ok_or_else(|| SqliteClientError::CorruptedData("Invalid Orchard note.".to_string()))?;

            Ok(ReceivedNote::from_parts(
                note_id,
                txid,
                action_index,
                note,
                spending_key_scope,
                note_commitment_tree_position,
                mined_height,
                max_shielding_input_height,
            ))
        })
        .transpose()
}

pub(crate) fn get_spendable_orchard_note<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    txid: &TxId,
    index: u32,
    target_height: TargetHeight,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    super::common::get_spendable_note(
        conn,
        params,
        txid,
        index,
        ShieldedProtocol::Orchard,
        target_height,
        to_received_note,
    )
}

pub(crate) fn select_spendable_orchard_notes<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    target_value: TargetValue,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    super::common::select_spendable_notes(
        conn,
        params,
        account,
        target_value,
        target_height,
        confirmations_policy,
        exclude,
        ShieldedProtocol::Orchard,
        to_received_note,
    )
}

pub(crate) fn ensure_address<
    T: ReceivedOrchardOutput<AccountId = AccountUuid>,
    P: consensus::Parameters,
>(
    conn: &rusqlite::Transaction,
    params: &P,
    output: &T,
    exposure_height: Option<BlockHeight>,
) -> Result<Option<AddressRef>, SqliteClientError> {
    if output.recipient_key_scope() != Some(Scope::Internal) {
        let account = get_account(conn, params, output.account_id())?
            .ok_or(SqliteClientError::AccountUnknown)?;

        let uivk = account.uivk();
        let ivk = uivk
            .orchard()
            .as_ref()
            .expect("uivk decrypted this output.");
        let to = output.note().recipient();
        let diversifier_index = ivk
            .diversifier_index(&to)
            .expect("address corresponds to account");

        let ua = account
            .uivk()
            .address(diversifier_index, UnifiedAddressRequest::ALLOW_ALL)?;
        upsert_address(
            conn,
            params,
            account.internal_id(),
            diversifier_index,
            &ua,
            exposure_height,
            false,
        )
        .map(Some)
    } else {
        Ok(None)
    }
}

pub(crate) fn select_unspent_note_meta(
    conn: &Connection,
    wallet_birthday: BlockHeight,
    anchor_height: BlockHeight,
) -> Result<Vec<UnspentNoteMeta>, SqliteClientError> {
    super::common::select_unspent_note_meta(
        conn,
        ShieldedProtocol::Orchard,
        wallet_birthday,
        anchor_height,
    )
}

/// Records the specified shielded output as having been received.
///
/// This implementation relies on the facts that:
/// - A transaction will not contain more than 2^63 shielded outputs.
/// - A note value will never exceed 2^63 zatoshis.
///
/// Returns the internal account identifier of the account that received the output.
pub(crate) fn put_received_note<
    T: ReceivedOrchardOutput<AccountId = AccountUuid>,
    P: consensus::Parameters,
>(
    conn: &rusqlite::Transaction,
    params: &P,
    output: &T,
    tx_ref: TxRef,
    target_or_mined_height: Option<BlockHeight>,
    spent_in: Option<TxRef>,
) -> Result<AccountRef, SqliteClientError> {
    let account_id = get_account_ref(conn, output.account_id())?;
    let address_id = ensure_address(conn, params, output, target_or_mined_height)?;
    let mut stmt_upsert_received_note = conn.prepare_cached(
        "INSERT INTO orchard_received_notes (
            tx, action_index, account_id, address_id,
            diversifier, value, rho, rseed, memo, nf,
            is_change, commitment_tree_position,
            recipient_key_scope
        )
        VALUES (
            :tx, :action_index, :account_id, :address_id,
            :diversifier, :value, :rho, :rseed, :memo, :nf,
            :is_change, :commitment_tree_position,
            :recipient_key_scope
        )
        ON CONFLICT (tx, action_index) DO UPDATE
        SET account_id = :account_id,
            address_id = :address_id,
            diversifier = :diversifier,
            value = :value,
            rho = :rho,
            rseed = :rseed,
            nf = IFNULL(:nf, nf),
            memo = IFNULL(:memo, memo),
            is_change = MAX(:is_change, is_change),
            commitment_tree_position = IFNULL(:commitment_tree_position, commitment_tree_position),
            recipient_key_scope = :recipient_key_scope
        RETURNING orchard_received_notes.id",
    )?;

    let rseed = output.note().rseed();
    let to = output.note().recipient();
    let diversifier = to.diversifier();

    let sql_args = named_params![
        ":tx": tx_ref.0,
        ":action_index": i64::try_from(output.index()).expect("output indices are representable as i64"),
        ":account_id": account_id.0,
        ":address_id": address_id.map(|a| a.0),
        ":diversifier": diversifier.as_array(),
        ":value": output.note().value().inner(),
        ":rho": output.note().rho().to_bytes(),
        ":rseed": &rseed.as_bytes(),
        ":nf": output.nullifier().map(|nf| nf.to_bytes()),
        ":memo": memo_repr(output.memo()),
        ":is_change": output.is_change(),
        ":commitment_tree_position": output.note_commitment_tree_position().map(u64::from),
        ":recipient_key_scope": output.recipient_key_scope().map(|s| KeyScope::from(s).encode()),
    ];

    let received_note_id = stmt_upsert_received_note
        .query_row(sql_args, |row| row.get::<_, i64>(0))
        .map_err(SqliteClientError::from)?;

    if let Some(spent_in) = spent_in {
        conn.execute(
            "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id)
             VALUES (:orchard_received_note_id, :transaction_id)
             ON CONFLICT (orchard_received_note_id, transaction_id) DO NOTHING",
            named_params![
                ":orchard_received_note_id": received_note_id,
                ":transaction_id": spent_in.0
            ],
        )?;
    }
    Ok(account_id)
}

/// Retrieves the set of nullifiers for "potentially spendable" Orchard notes that the
/// wallet is tracking.
///
/// "Potentially spendable" means:
/// - The transaction in which the note was created has been observed as mined.
/// - No transaction in which the note's nullifier appears has been observed as mined.
pub(crate) fn get_orchard_nullifiers(
    conn: &Connection,
    query: NullifierQuery,
) -> Result<Vec<(AccountUuid, Nullifier)>, SqliteClientError> {
    super::common::get_nullifiers(conn, ShieldedProtocol::Orchard, query, |nf_bytes| {
        Nullifier::from_bytes(<&[u8; 32]>::try_from(nf_bytes).map_err(|_| {
            SqliteClientError::CorruptedData(
                "unable to parse Orchard nullifier: expected 32 bytes".to_string(),
            )
        })?)
        .into_option()
        .ok_or(SqliteClientError::CorruptedData(
            "unable to parse Orchard nullifier".to_string(),
        ))
    })
}

pub(crate) fn detect_spending_accounts<'a>(
    conn: &Connection,
    nfs: impl Iterator<Item = &'a Nullifier>,
) -> Result<HashSet<AccountUuid>, rusqlite::Error> {
    let mut account_q = conn.prepare_cached(
        "SELECT a.uuid
         FROM orchard_received_notes rn
         JOIN accounts a ON a.id = rn.account_id
         WHERE rn.nf IN rarray(:nf_ptr)",
    )?;

    let nf_values: Vec<Value> = nfs.map(|nf| Value::Blob(nf.to_bytes().to_vec())).collect();
    let nf_ptr = Rc::new(nf_values);
    let res = account_q
        .query_and_then(named_params![":nf_ptr": &nf_ptr], |row| {
            row.get(0).map(AccountUuid)
        })?
        .collect::<Result<HashSet<_>, _>>()?;

    Ok(res)
}

/// Marks a given nullifier as having been revealed in the construction
/// of the specified transaction.
///
/// Marking a note spent in this fashion does NOT imply that the
/// spending transaction has been mined.
pub(crate) fn mark_orchard_note_spent(
    conn: &Connection,
    tx_ref: TxRef,
    nf: &Nullifier,
) -> Result<bool, SqliteClientError> {
    let mut stmt_mark_orchard_note_spent = conn.prepare_cached(
        "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id)
         SELECT id, :transaction_id FROM orchard_received_notes WHERE nf = :nf
         ON CONFLICT (orchard_received_note_id, transaction_id) DO NOTHING",
    )?;

    match stmt_mark_orchard_note_spent.execute(named_params![
       ":nf": nf.to_bytes(),
       ":transaction_id": tx_ref.0
    ])? {
        0 => Ok(false),
        1 => Ok(true),
        _ => unreachable!("nf column is marked as UNIQUE"),
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use zcash_client_backend::data_api::testing::{
        orchard::OrchardPoolTester, sapling::SaplingPoolTester,
    };

    use crate::testing::{self};

    #[test]
    fn send_single_step_proposed_transfer() {
        testing::pool::send_single_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    fn spend_max_spendable_single_step_proposed_transfer() {
        testing::pool::spend_max_spendable_single_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    fn spend_everything_single_step_proposed_transfer() {
        testing::pool::spend_everything_single_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn fails_to_send_max_to_transparent_with_memo() {
        testing::pool::fails_to_send_max_to_transparent_with_memo::<OrchardPoolTester>()
    }

    #[test]
    fn send_max_proposal_fails_when_unconfirmed_funds_present() {
        testing::pool::send_max_proposal_fails_when_unconfirmed_funds_present::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn spend_everything_multi_step_single_note_proposed_transfer() {
        testing::pool::spend_everything_multi_step_single_note_proposed_transfer::<OrchardPoolTester>(
        )
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn spend_everything_multi_step_many_notes_proposed_transfer() {
        testing::pool::spend_everything_multi_step_many_notes_proposed_transfer::<OrchardPoolTester>(
        )
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn spend_everything_multi_step_with_marginal_notes_proposed_transfer() {
        testing::pool::spend_everything_multi_step_with_marginal_notes_proposed_transfer::<
            OrchardPoolTester,
        >()
    }

    #[test]
    fn send_with_multiple_change_outputs() {
        testing::pool::send_with_multiple_change_outputs::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn send_multi_step_proposed_transfer() {
        testing::pool::send_multi_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    fn spend_all_funds_single_step_proposed_transfer() {
        testing::pool::spend_all_funds_single_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn spend_all_funds_multi_step_proposed_transfer() {
        testing::pool::spend_all_funds_multi_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn proposal_fails_if_not_all_ephemeral_outputs_consumed() {
        testing::pool::proposal_fails_if_not_all_ephemeral_outputs_consumed::<OrchardPoolTester>()
    }

    #[test]
    fn create_to_address_fails_on_incorrect_usk() {
        testing::pool::create_to_address_fails_on_incorrect_usk::<OrchardPoolTester>()
    }

    #[test]
    fn proposal_fails_with_no_blocks() {
        testing::pool::proposal_fails_with_no_blocks::<OrchardPoolTester>()
    }

    #[test]
    fn spend_fails_on_unverified_notes() {
        testing::pool::spend_fails_on_unverified_notes::<OrchardPoolTester>()
    }

    #[test]
    fn spend_fails_on_locked_notes() {
        testing::pool::spend_fails_on_locked_notes::<OrchardPoolTester>()
    }

    #[test]
    fn ovk_policy_prevents_recovery_from_chain() {
        testing::pool::ovk_policy_prevents_recovery_from_chain::<OrchardPoolTester>()
    }

    #[test]
    fn spend_succeeds_to_t_addr_zero_change() {
        testing::pool::spend_succeeds_to_t_addr_zero_change::<OrchardPoolTester>()
    }

    #[test]
    fn change_note_spends_succeed() {
        testing::pool::change_note_spends_succeed::<OrchardPoolTester>()
    }

    #[test]
    fn external_address_change_spends_detected_in_restore_from_seed() {
        testing::pool::external_address_change_spends_detected_in_restore_from_seed::<
            OrchardPoolTester,
        >()
    }

    #[test]
    #[ignore] // FIXME: #1316 This requires support for dust outputs.
    fn zip317_spend() {
        testing::pool::zip317_spend::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn shield_transparent() {
        testing::pool::shield_transparent::<OrchardPoolTester>()
    }

    #[test]
    fn birthday_in_anchor_shard() {
        testing::pool::birthday_in_anchor_shard::<OrchardPoolTester>()
    }

    #[test]
    fn checkpoint_gaps() {
        testing::pool::checkpoint_gaps::<OrchardPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_detects_spends_out_of_order() {
        testing::pool::scan_cached_blocks_detects_spends_out_of_order::<OrchardPoolTester>()
    }

    #[test]
    fn metadata_queries_exclude_unwanted_notes() {
        testing::pool::metadata_queries_exclude_unwanted_notes::<OrchardPoolTester>()
    }

    #[test]
    fn pool_crossing_required() {
        testing::pool::pool_crossing_required::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[test]
    fn fully_funded_fully_private() {
        testing::pool::fully_funded_fully_private::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn fully_funded_send_to_t() {
        testing::pool::fully_funded_send_to_t::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[test]
    fn multi_pool_checkpoint() {
        testing::pool::multi_pool_checkpoint::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[test]
    fn multi_pool_checkpoints_with_pruning() {
        testing::pool::multi_pool_checkpoints_with_pruning::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[cfg(feature = "pczt-tests")]
    #[test]
    fn pczt_single_step_orchard_only() {
        testing::pool::pczt_single_step::<OrchardPoolTester, OrchardPoolTester>()
    }

    #[cfg(feature = "pczt-tests")]
    #[test]
    fn pczt_single_step_orchard_to_sapling() {
        testing::pool::pczt_single_step::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn wallet_recovery_compute_fees() {
        testing::pool::wallet_recovery_computes_fees::<OrchardPoolTester>();
    }

    #[test]
    fn zip315_can_spend_inputs_by_confirmations_policy() {
        testing::pool::can_spend_inputs_by_confirmations_policy::<OrchardPoolTester>();
    }

    #[test]
    fn receive_two_notes_with_same_value() {
        testing::pool::receive_two_notes_with_same_value::<OrchardPoolTester>();
    }
}
