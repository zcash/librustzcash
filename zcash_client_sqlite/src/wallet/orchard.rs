use std::{collections::HashSet, rc::Rc};

use incrementalmerkletree::Position;
use orchard::{
    keys::Diversifier,
    note::{Note, NoteVersion, Nullifier, RandomSeed, Rho},
};
use rusqlite::{Connection, Row, named_params, types::Value};

use zcash_client_backend::{
    data_api::{
        Account as _, NullifierQuery, TargetValue,
        ll::ReceivedOrchardOutput,
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::ReceivedNote,
};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight},
};
use zip32::Scope;

use crate::{
    AccountRef, AccountUuid, AddressRef, IRONWOOD_TABLES_PREFIX, ORCHARD_TABLES_PREFIX,
    ReceivedNoteId, TxRef, error::SqliteClientError,
};

use super::{
    KeyScope, common::UnspentNoteMeta, get_account, get_account_ref, memo_repr, upsert_address,
};

pub(crate) fn to_received_note<P: consensus::Parameters>(
    params: &P,
    row: &Row,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    let note_id = ReceivedNoteId(ShieldedPool::Orchard, row.get("id")?);
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

    let note_version = {
        let code: i64 = row.get("note_version")?;
        parse_note_version(code).ok_or_else(|| {
            SqliteClientError::CorruptedData(format!("Unrecognized note version code {code}"))
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
                note_version,
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
        ShieldedPool::Orchard,
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
        ShieldedPool::Orchard,
        to_received_note,
    )
}

/// Return all Orchard notes that were received at or before `height`
/// and unspent as of `height`, for the given account.
///
/// Unlike `select_spendable_notes` (which applies confirmation, dust, and
/// expiry filters for transaction construction), this returns every note
/// that existed and was unspent at the given height.
///
/// Height filtering uses `transactions.mined_height`, not `transactions.block`.
/// A transaction is considered to have occurred at its mined height as soon
/// as the wallet learns of that height (for example, from transparent UTXO
/// retrieval), even if the containing compact block has not been fully
/// scanned. In practice the two columns are equivalent for the notes this
/// query can return, because `nf IS NOT NULL` and
/// `commitment_tree_position IS NOT NULL` already require a scan of the
/// block that contains the receiving transaction.
///
/// This function does not verify that a Merkle witness can be constructed
/// for each returned note at `height`. Witness construction is a separate
/// concern intended to be handled by the callers. As an example, a companion
/// `WalletDb::generate_orchard_witnesses_at_historical_height` returns an
/// actionable error for any position the wallet cannot witness at `height`
/// (for example, because the wallet has not synced through `height`, the checkpoint was pruned,
/// or the position does not belong to the wallet).
pub(crate) fn get_unspent_orchard_notes_at_historical_height<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    height: BlockHeight,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    let external_scope = KeyScope::EXTERNAL.encode();
    let internal_scope = KeyScope::INTERNAL.encode();

    let mut stmt = conn.prepare_cached(&format!(
        "SELECT
             rn.id AS id, t.txid, rn.action_index,
             rn.diversifier, rn.value, rn.rho, rn.rseed, rn.note_version,
             rn.commitment_tree_position,
             accounts.ufvk AS ufvk, rn.recipient_key_scope,
             t.mined_height,
             NULL AS max_shielding_input_height
         FROM orchard_received_notes rn
         INNER JOIN accounts ON accounts.id = rn.account_id
         INNER JOIN transactions t ON t.id_tx = rn.transaction_id
         WHERE accounts.uuid = :account_uuid
           AND t.mined_height <= :height
           AND rn.nf IS NOT NULL
           AND rn.commitment_tree_position IS NOT NULL
           AND rn.recipient_key_scope IN ({external_scope}, {internal_scope})
           AND accounts.ufvk IS NOT NULL
           AND rn.id NOT IN (
               SELECT rns.orchard_received_note_id
               FROM orchard_received_note_spends rns
               JOIN transactions t_spend ON t_spend.id_tx = rns.transaction_id
               WHERE t_spend.mined_height <= :height
           )
         ORDER BY rn.commitment_tree_position",
    ))?;

    let rows = stmt.query_and_then(
        named_params![
            ":account_uuid": account.0,
            ":height": u32::from(height),
        ],
        |row| to_received_note(params, row),
    )?;

    rows.filter_map(|r| r.transpose()).collect()
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
        ShieldedPool::Orchard,
        wallet_birthday,
        anchor_height,
    )
}

/// Encodes a note plaintext version for storage in the `note_version` column of a received-notes
/// table. The encoding matches the note plaintext lead byte signaling the version.
pub(crate) fn note_version_code(version: NoteVersion) -> i64 {
    match version {
        NoteVersion::V2 => 2,
        NoteVersion::V3 => 3,
    }
}

/// Decodes a note plaintext version from its `note_version` column encoding, returning `None` if
/// the code is not a recognized version.
pub(crate) fn parse_note_version(code: i64) -> Option<NoteVersion> {
    match code {
        2 => Some(NoteVersion::V2),
        3 => Some(NoteVersion::V3),
        _ => None,
    }
}

/// Records the specified shielded output as having been received.
///
/// The output's note plaintext version determines the pool to which the note belongs — version 2
/// note plaintexts can be obtained only under the Orchard note encryption domain, and version 3
/// note plaintexts only under the Ironwood domain — so the note is recorded in
/// `orchard_received_notes` or `ironwood_received_notes` accordingly.
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
    let note_version = output.note().version();
    let table_prefix = match note_version {
        NoteVersion::V2 => ORCHARD_TABLES_PREFIX,
        NoteVersion::V3 => IRONWOOD_TABLES_PREFIX,
    };
    let mut stmt_upsert_received_note = conn.prepare_cached(&format!(
        "INSERT INTO {table_prefix}_received_notes (
            transaction_id, action_index, account_id, address_id,
            diversifier, value, rho, rseed, memo, nf,
            is_change, commitment_tree_position,
            recipient_key_scope, note_version
        )
        VALUES (
            :transaction_id, :action_index, :account_id, :address_id,
            :diversifier, :value, :rho, :rseed, :memo, :nf,
            :is_change, :commitment_tree_position,
            :recipient_key_scope, :note_version
        )
        ON CONFLICT (transaction_id, action_index) DO UPDATE
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
            recipient_key_scope = :recipient_key_scope,
            note_version = :note_version
        RETURNING id",
    ))?;

    let rseed = output.note().rseed();
    let to = output.note().recipient();
    let diversifier = to.diversifier();

    let sql_args = named_params![
        ":transaction_id": tx_ref.0,
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
        ":note_version": note_version_code(note_version),
    ];

    let received_note_id = stmt_upsert_received_note
        .query_row(sql_args, |row| row.get::<_, i64>(0))
        .map_err(SqliteClientError::from)?;

    if let Some(spent_in) = spent_in {
        conn.execute(
            &format!(
                "INSERT INTO {table_prefix}_received_note_spends
                    ({table_prefix}_received_note_id, transaction_id)
                 VALUES (:received_note_id, :transaction_id)
                 ON CONFLICT ({table_prefix}_received_note_id, transaction_id) DO NOTHING"
            ),
            named_params![
                ":received_note_id": received_note_id,
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
    super::common::get_nullifiers(conn, ShieldedPool::Orchard, query, |nf_bytes| {
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
    let sql_params = named_params![
       ":nf": nf.to_bytes(),
       ":transaction_id": tx_ref.0
    ];
    let has_collision = conn.query_row(
        "WITH possible_conflicts AS (
            SELECT s.transaction_id
            FROM orchard_received_notes n
            JOIN orchard_received_note_spends s ON s.orchard_received_note_id = n.id
            JOIN transactions t ON t.id_tx = s.transaction_id
            WHERE n.nf = :nf
            AND t.id_tx != :transaction_id
            AND t.mined_height IS NOT NULL
        ),
        mined_tx AS (
            SELECT t.id_tx AS transaction_id
            FROM transactions t
            WHERE t.id_tx = :transaction_id
            AND t.mined_height IS NOT NULL
        )
        SELECT EXISTS(SELECT 1 FROM possible_conflicts) AND EXISTS(SELECT 1 FROM mined_tx)",
        sql_params,
        |row| row.get::<_, bool>(0),
    )?;

    if has_collision {
        return Err(SqliteClientError::CorruptedData(format!(
            "A different mined transaction revealing Orchard nullifier {} already exists",
            hex::encode(nf.to_bytes())
        )));
    }

    let mut stmt_mark_orchard_note_spent = conn.prepare_cached(
        "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id)
         SELECT id, :transaction_id FROM orchard_received_notes WHERE nf = :nf
         ON CONFLICT (orchard_received_note_id, transaction_id) DO NOTHING",
    )?;

    match stmt_mark_orchard_note_spent.execute(sql_params)? {
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
    fn scan_full_block_detects_outputs() {
        testing::pool::scan_full_block_detects_outputs::<OrchardPoolTester>()
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
    fn account_deletion() {
        testing::pool::account_deletion::<OrchardPoolTester>()
    }

    #[test]
    fn account_deletion_with_internal_transfer() {
        testing::pool::account_deletion_with_internal_transfer::<OrchardPoolTester>()
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

    #[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
    #[test]
    fn immature_coinbase_outputs_are_excluded_from_note_selection() {
        testing::pool::immature_coinbase_outputs_are_excluded_from_note_selection::<
            OrchardPoolTester,
        >();
    }

    #[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
    #[test]
    fn coinbase_only_filtering() {
        testing::pool::coinbase_only_filtering::<OrchardPoolTester>();
    }

    #[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
    #[test]
    fn propose_shielding_coinbase_succeeds() {
        testing::pool::propose_shielding_coinbase_succeeds::<OrchardPoolTester>();
    }

    #[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
    #[test]
    fn propose_shielding_coinbase_transparent_recipient_rejected() {
        testing::pool::propose_shielding_coinbase_transparent_recipient_rejected::<OrchardPoolTester>(
        );
    }

    #[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
    #[test]
    fn propose_shielding_coinbase_with_memo_succeeds() {
        testing::pool::propose_shielding_coinbase_with_memo_succeeds::<OrchardPoolTester>();
    }

    #[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
    #[test]
    fn propose_shielding_coinbase_with_limit_truncates_inputs() {
        testing::pool::propose_shielding_coinbase_with_limit_truncates_inputs::<OrchardPoolTester>(
        );
    }

    #[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
    #[test]
    fn propose_shielding_coinbase_with_zero_limit_insufficient_funds() {
        testing::pool::propose_shielding_coinbase_with_zero_limit_insufficient_funds::<
            OrchardPoolTester,
        >();
    }

    #[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
    #[test]
    fn propose_and_build_shielding_coinbase_succeeds() {
        testing::pool::propose_and_build_shielding_coinbase_succeeds::<OrchardPoolTester>();
    }

    /// `put_received_note` must record a note in the received-notes table for the pool implied
    /// by the note's plaintext version: version 2 notes belong to the Orchard pool and version 3
    /// notes to the Ironwood pool.
    #[test]
    fn put_received_note_routes_by_note_plaintext_version() {
        use orchard::{
            keys::{FullViewingKey, SpendingKey},
            note::{Note, NoteVersion, RandomSeed, Rho},
            value::NoteValue,
        };
        use rusqlite::named_params;
        use zcash_client_backend::{
            DecryptedOutput, TransferType,
            data_api::{Account as _, testing::TestBuilder},
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::memo::MemoBytes;

        use crate::{TxRef, testing::db::TestDbFactory};

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account_uuid = st.test_account().unwrap().id();
        let network = *st.network();

        // The recipient need not correspond to the receiving account here: internally-scoped
        // outputs skip address derivation, and this test exercises only note storage.
        let sk: SpendingKey = Option::from(SpendingKey::from_bytes([0x2a; 32])).unwrap();
        let recipient = FullViewingKey::from(&sk).address_at(0u32, zip32::Scope::External);
        let rho = Option::from(Rho::from_bytes(&[0; 32])).unwrap();
        let rseed = Option::from(RandomSeed::from_bytes([0x1b; 32], &rho)).unwrap();
        let note = |value: u64, version: NoteVersion| {
            Option::from(Note::from_parts(
                recipient,
                NoteValue::from_raw(value),
                rho,
                rseed,
                version,
            ))
            .unwrap()
        };
        let output = |index: usize, note: Note| {
            DecryptedOutput::new(
                index,
                note,
                account_uuid,
                MemoBytes::empty(),
                TransferType::AccountInternal,
            )
        };

        let conn = st.wallet_mut().conn_mut();
        let tx = conn.transaction().unwrap();
        let tx_ref = tx
            .query_row(
                "INSERT INTO transactions (txid, min_observed_height)
                 VALUES (:txid, 0)
                 RETURNING id_tx",
                named_params![":txid": [0x7fu8; 32].as_slice()],
                |row| row.get::<_, i64>(0).map(TxRef),
            )
            .unwrap();

        // An Orchard note and an Ironwood note sharing an action index may both be recorded.
        super::put_received_note(
            &tx,
            &network,
            &output(0, note(10_000, NoteVersion::V2)),
            tx_ref,
            None,
            None,
        )
        .unwrap();
        super::put_received_note(
            &tx,
            &network,
            &output(0, note(20_000, NoteVersion::V3)),
            tx_ref,
            None,
            None,
        )
        .unwrap();

        let note_row = |table: &str| {
            tx.query_row(
                &format!("SELECT value, note_version FROM {table}_received_notes"),
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap()
        };
        assert_eq!(note_row("orchard"), (10_000, 2));
        assert_eq!(note_row("ironwood"), (20_000, 3));
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn get_unspent_orchard_notes_at_historical_height_boundary_heights() {
        use zcash_client_backend::data_api::Account;
        use zcash_client_backend::data_api::testing::{
            AddressType, TestBuilder, pool::ShieldedPoolTester,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;

        use crate::testing::{BlockCache, db::TestDbFactory};

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        // Receive a note at h1
        let value = Zatoshis::const_from_u64(50000);
        let (h1, _, nf) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);

        // Spend that note at h2 (produces change back to us)
        let not_our_key = OrchardPoolTester::sk_to_fvk(&OrchardPoolTester::sk(&[0xf5; 32]));
        let to = OrchardPoolTester::fvk_default_address(&not_our_key);
        let spend_value = Zatoshis::const_from_u64(20000);
        let (h2, _) = st.generate_next_block_spending(&dfvk, (nf, value), to, spend_value);
        st.scan_cached_blocks(h2, 1);

        // Receive another note at h3
        let value3 = Zatoshis::const_from_u64(70000);
        let (h3, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value3);
        st.scan_cached_blocks(h3, 1);

        let db = st.wallet().db();

        // Before any notes: nothing (h1 - 1 is before the note was mined)
        let notes = db
            .get_unspent_orchard_notes_at_historical_height(account.id(), h1 - 1)
            .unwrap();
        assert_eq!(notes.len(), 0);

        // At h1: original note received and unspent
        let notes = db
            .get_unspent_orchard_notes_at_historical_height(account.id(), h1)
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note_value().unwrap(), value);

        // At h2: original spent, only change note remains
        let notes = db
            .get_unspent_orchard_notes_at_historical_height(account.id(), h2)
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes[0].note_value().unwrap(),
            (value - spend_value).unwrap()
        );

        // At h3: change note + new note
        let notes = db
            .get_unspent_orchard_notes_at_historical_height(account.id(), h3)
            .unwrap();
        assert_eq!(notes.len(), 2);
        let total: Zatoshis = notes
            .iter()
            .map(|n| n.note_value().unwrap())
            .sum::<Option<Zatoshis>>()
            .unwrap();
        assert_eq!(total, ((value - spend_value).unwrap() + value3).unwrap());
    }
}
