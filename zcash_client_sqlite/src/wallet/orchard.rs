use std::{collections::HashSet, rc::Rc};

use incrementalmerkletree::Position;
use orchard::{
    ValuePool,
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
    PoolType, ShieldedPool,
    consensus::{self, BlockHeight},
};
use zip32::Scope;

use crate::{
    AccountRef, AccountUuid, AddressRef, ReceivedNoteId, TxRef,
    error::SqliteClientError,
    wallet::common::{TableConstants, table_constants},
};

use super::{
    KeyScope, common::UnspentNoteMeta, get_account, get_account_ref, memo_repr, upsert_address,
};

pub(crate) fn to_received_note<P: consensus::Parameters>(
    params: &P,
    pool: ShieldedPool,
    row: &Row,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    // Orchard and Ironwood notes are both reconstructed here (they are Orchard-shaped); the
    // `ReceivedNoteId` must carry the pool the note was selected from, so that pool-filtered
    // exclusion (see `select_unspent_notes`) matches it rather than misrouting it to Orchard.
    let note_id = ReceivedNoteId(pool, row.get("id")?);
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
    include_locked: bool,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    super::common::get_spendable_note(
        conn,
        params,
        txid,
        index,
        ShieldedPool::Orchard,
        target_height,
        to_received_note,
        include_locked,
    )
}

/// Returns a single spendable Ironwood note, identified by the transaction that produced it and
/// its action index. Ironwood notes are Orchard-shaped, so this reuses the Orchard note
/// reconstruction; only the pool (and thus the `ironwood_received_notes` table) differs.
pub(crate) fn get_spendable_ironwood_note<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    txid: &TxId,
    index: u32,
    target_height: TargetHeight,
    include_locked: bool,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    super::common::get_spendable_note(
        conn,
        params,
        txid,
        index,
        ShieldedPool::Ironwood,
        target_height,
        to_received_note,
        include_locked,
    )
}

/// Selects spendable Ironwood notes to satisfy the given target value. Ironwood notes are
/// Orchard-shaped, so this reuses the Orchard note reconstruction; only the pool (and thus the
/// `ironwood_received_notes` table) differs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn select_spendable_ironwood_notes<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    target_value: TargetValue,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
    include_locked: bool,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    super::common::select_spendable_notes(
        conn,
        params,
        account,
        target_value,
        target_height,
        confirmations_policy,
        exclude,
        ShieldedPool::Ironwood,
        to_received_note,
        include_locked,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn select_spendable_orchard_notes<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    target_value: TargetValue,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
    include_locked: bool,
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
        include_locked,
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
    get_unspent_orchard_shaped_notes_at_historical_height(
        conn,
        params,
        ValuePool::Orchard,
        account,
        height,
    )
}

pub(crate) fn get_unspent_ironwood_notes_at_historical_height<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    height: BlockHeight,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    get_unspent_orchard_shaped_notes_at_historical_height(
        conn,
        params,
        ValuePool::Ironwood,
        account,
        height,
    )
}

fn get_unspent_orchard_shaped_notes_at_historical_height<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    pool: ValuePool,
    account: AccountUuid,
    height: BlockHeight,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    let shielded_pool = match pool {
        ValuePool::Orchard => ShieldedPool::Orchard,
        ValuePool::Ironwood => ShieldedPool::Ironwood,
    };
    let TableConstants { table_prefix, .. } = table_constants::<SqliteClientError>(shielded_pool)?;
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
         FROM {table_prefix}_received_notes rn
         INNER JOIN accounts ON accounts.id = rn.account_id
         INNER JOIN transactions t ON t.id_tx = rn.transaction_id
         WHERE accounts.uuid = :account_uuid
           AND t.mined_height <= :height
           AND rn.nf IS NOT NULL
           AND rn.commitment_tree_position IS NOT NULL
           AND rn.recipient_key_scope IN ({external_scope}, {internal_scope})
           AND accounts.ufvk IS NOT NULL
           AND rn.id NOT IN (
               SELECT rns.{table_prefix}_received_note_id
               FROM {table_prefix}_received_note_spends rns
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
        |row| to_received_note(params, shielded_pool, row),
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
///
/// The caller selects the target pool's table (`orchard` or `ironwood`); the note's own plaintext
/// version is recorded in the `note_version` column but does not influence table selection. This
/// lets the scanner route its separate Orchard and Ironwood output streams to their respective
/// tables while the decrypted-transaction path selects the table from the note version.
pub(crate) fn put_received_note<
    T: ReceivedOrchardOutput<AccountId = AccountUuid>,
    P: consensus::Parameters,
>(
    conn: &rusqlite::Transaction,
    params: &P,
    shielded_pool: ShieldedPool,
    output: &T,
    tx_ref: TxRef,
    target_or_mined_height: Option<BlockHeight>,
    spent_in: Option<TxRef>,
) -> Result<AccountRef, SqliteClientError> {
    let TableConstants { table_prefix, .. } = table_constants::<SqliteClientError>(shielded_pool)?;

    let account_id = get_account_ref(conn, output.account_id())?;
    let address_id = ensure_address(conn, params, output, target_or_mined_height)?;
    let note_version = output.note().version();
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

/// Retrieves the set of nullifiers for "potentially spendable" Ironwood notes that the wallet is
/// tracking. Ironwood nullifiers are Orchard-shaped; see [`get_orchard_nullifiers`] for the
/// meaning of "potentially spendable".
pub(crate) fn get_ironwood_nullifiers(
    conn: &Connection,
    query: NullifierQuery,
) -> Result<Vec<(AccountUuid, Nullifier)>, SqliteClientError> {
    super::common::get_nullifiers(conn, ShieldedPool::Ironwood, query, |nf_bytes| {
        Nullifier::from_bytes(<&[u8; 32]>::try_from(nf_bytes).map_err(|_| {
            SqliteClientError::CorruptedData(
                "unable to parse Ironwood nullifier: expected 32 bytes".to_string(),
            )
        })?)
        .into_option()
        .ok_or(SqliteClientError::CorruptedData(
            "unable to parse Ironwood nullifier".to_string(),
        ))
    })
}

pub(crate) fn detect_spending_accounts<'a>(
    conn: &Connection,
    table_prefix: &str,
    nfs: impl Iterator<Item = &'a Nullifier>,
) -> Result<HashSet<AccountUuid>, rusqlite::Error> {
    // Orchard and Ironwood notes share the Orchard nullifier type but live in separate tables;
    // the caller selects which via `table_prefix`.
    let mut account_q = conn.prepare_cached(&format!(
        "SELECT a.uuid
         FROM {table_prefix}_received_notes rn
         JOIN accounts a ON a.id = rn.account_id
         WHERE rn.nf IN rarray(:nf_ptr)",
    ))?;

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
    mark_note_spent(conn, ShieldedPool::Orchard, tx_ref, nf)
}

/// Marks a given Ironwood nullifier as having been revealed in the construction of the specified
/// transaction. Ironwood nullifiers are Orchard-shaped; see [`mark_orchard_note_spent`].
pub(crate) fn mark_ironwood_note_spent(
    conn: &Connection,
    tx_ref: TxRef,
    nf: &Nullifier,
) -> Result<bool, SqliteClientError> {
    mark_note_spent(conn, ShieldedPool::Ironwood, tx_ref, nf)
}

/// Marks the received note in the given shielded pool's received-notes table with the given
/// nullifier as spent in the referenced transaction.
fn mark_note_spent(
    conn: &Connection,
    shielded_pool: ShieldedPool,
    tx_ref: TxRef,
    nf: &Nullifier,
) -> Result<bool, SqliteClientError> {
    let TableConstants { table_prefix, .. } = table_constants::<SqliteClientError>(shielded_pool)?;
    let pool_name = PoolType::Shielded(shielded_pool);

    let sql_params = named_params![
       ":nf": nf.to_bytes(),
       ":transaction_id": tx_ref.0
    ];
    let has_collision = conn.query_row(
        &format!(
            "WITH possible_conflicts AS (
                SELECT s.transaction_id
                FROM {table_prefix}_received_notes n
                JOIN {table_prefix}_received_note_spends s
                    ON s.{table_prefix}_received_note_id = n.id
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
            SELECT EXISTS(SELECT 1 FROM possible_conflicts) AND EXISTS(SELECT 1 FROM mined_tx)"
        ),
        sql_params,
        |row| row.get::<_, bool>(0),
    )?;

    if has_collision {
        return Err(SqliteClientError::CorruptedData(format!(
            "A different mined transaction revealing {pool_name} nullifier {} already exists",
            hex::encode(nf.to_bytes())
        )));
    }

    let mut stmt_mark_note_spent = conn.prepare_cached(&format!(
        "INSERT INTO {table_prefix}_received_note_spends
            ({table_prefix}_received_note_id, transaction_id)
         SELECT id, :transaction_id FROM {table_prefix}_received_notes WHERE nf = :nf
         ON CONFLICT ({table_prefix}_received_note_id, transaction_id) DO NOTHING"
    ))?;

    match stmt_mark_note_spent.execute(sql_params)? {
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
    fn send_max_spendable_to_transparent() {
        testing::pool::send_max_spendable_to_transparent::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(not(feature = "transparent-inputs"))]
    fn send_max_to_tex_fails_without_transparent_inputs() {
        testing::pool::send_max_to_tex_fails_without_transparent_inputs::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn send_max_fee_overflow_is_an_error() {
        testing::pool::send_max_fee_overflow_is_an_error::<OrchardPoolTester>()
    }

    #[test]
    fn send_max_spends_inputs_across_pools() {
        testing::pool::send_max_spends_inputs_across_pools::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[test]
    fn send_max_fails_when_balance_is_consumed_by_fees() {
        testing::pool::send_max_fails_when_balance_is_consumed_by_fees::<OrchardPoolTester>()
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
    fn explicit_note_locking() {
        testing::pool::explicit_note_locking::<OrchardPoolTester>()
    }

    #[test]
    fn note_locking_height_boundary() {
        testing::pool::note_locking_height_boundary::<OrchardPoolTester>()
    }

    #[test]
    fn clear_locked_outputs() {
        testing::pool::clear_locked_outputs::<OrchardPoolTester>()
    }

    #[test]
    fn proposal_level_note_locking() {
        testing::pool::proposal_level_note_locking::<OrchardPoolTester>()
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
    fn anchor_checkpoints_retained_across_deep_scan() {
        testing::pool::anchor_checkpoints_retained_across_deep_scan::<OrchardPoolTester>()
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
        testing::pool::pczt_single_step::<OrchardPoolTester, OrchardPoolTester>(None)
    }

    #[cfg(feature = "pczt-tests")]
    #[test]
    fn pczt_single_step_orchard_to_sapling() {
        testing::pool::pczt_single_step::<OrchardPoolTester, SaplingPoolTester>(None)
    }

    // Regression: pinned expiry must still extract when Orchard adds a dummy action.
    #[cfg(feature = "pczt-tests")]
    #[test]
    fn pczt_single_step_orchard_pinned_expiry() {
        testing::pool::pczt_single_step::<OrchardPoolTester, OrchardPoolTester>(Some(100))
    }

    #[cfg(feature = "pczt-tests")]
    #[test]
    fn create_pczt_supports_ironwood_output() {
        testing::pool::create_pczt_supports_ironwood_output();
    }

    #[test]
    fn proposal_records_and_serializes_proposed_version() {
        testing::pool::proposal_records_and_serializes_proposed_version();
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
    fn proposal_without_confirmations_policy_builds() {
        testing::pool::proposal_without_confirmations_policy_builds::<OrchardPoolTester>();
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

    #[cfg(all(feature = "pczt-tests", feature = "transparent-inputs"))]
    #[test]
    fn shielding_coinbase_to_orchard_receiver_delivers_via_ironwood() {
        testing::pool::shielding_coinbase_to_orchard_receiver_delivers_via_ironwood();
    }

    #[test]
    fn propose_v5_payment_to_orchard_receiver_is_rejected() {
        testing::pool::propose_v5_payment_to_orchard_receiver_is_rejected();
    }

    /// `put_received_note` records a note in the received-notes table chosen by the caller,
    /// preserving the note's plaintext version in the `note_version` column. An Orchard-pool note
    /// and an Ironwood-pool note sharing an action index may both be recorded in their respective
    /// tables.
    #[test]
    fn put_received_note_records_to_caller_selected_table() {
        use orchard::{
            ValuePool,
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
        use zcash_protocol::{ShieldedPool, memo::MemoBytes};

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
        let output = |index: usize, note: Note, pool: ValuePool| {
            let shielded_pool = match pool {
                ValuePool::Orchard => ShieldedPool::Orchard,
                ValuePool::Ironwood => ShieldedPool::Ironwood,
            };
            DecryptedOutput::new(
                index,
                (note, pool),
                shielded_pool,
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
            ShieldedPool::Orchard,
            &output(0, note(10_000, NoteVersion::V2), ValuePool::Orchard),
            tx_ref,
            None,
            None,
        )
        .unwrap();
        super::put_received_note(
            &tx,
            &network,
            ShieldedPool::Ironwood,
            &output(0, note(20_000, NoteVersion::V3), ValuePool::Ironwood),
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

    /// End-to-end: a wallet that scans a block containing an Ironwood (version 3) note stores it in
    /// `ironwood_received_notes` as note version 3, counts it in the wallet balance, persists the
    /// Ironwood note commitment tree, and records nothing in the Orchard tables.
    #[test]
    #[cfg(feature = "orchard")]
    fn scan_block_stores_received_ironwood_note() {
        use zcash_client_backend::data_api::{
            Account,
            testing::{
                AddressType, IronwoodFvk, TestBuilder, orchard::OrchardPoolTester,
                pool::ShieldedPoolTester,
            },
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;

        use crate::testing::{BlockCache, db::TestDbFactory};

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account_id = st.test_account().unwrap().id();
        // The account's Ironwood outputs are trial-decrypted with its Orchard viewing key.
        let recipient = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));

        let value = Zatoshis::const_from_u64(60_000);
        let (h, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        // The note is stored in `ironwood_received_notes` as note version 3, with its value.
        let (ironwood_count, stored_value, note_version): (i64, i64, i64) = st
            .wallet_mut()
            .conn_mut()
            .query_row(
                "SELECT COUNT(*), COALESCE(MIN(value), 0), COALESCE(MIN(note_version), 0)
                 FROM ironwood_received_notes",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(ironwood_count, 1);
        assert_eq!(stored_value as u64, value.into_u64());
        assert_eq!(note_version, 3);

        // The note went to the Ironwood pool, not Orchard.
        let orchard_count: i64 = st
            .wallet_mut()
            .conn_mut()
            .query_row("SELECT COUNT(*) FROM orchard_received_notes", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(orchard_count, 0);

        // The received Ironwood note is reflected in the wallet balance.
        assert_eq!(st.get_total_balance(account_id), value);

        // The Ironwood note commitment tree was persisted.
        let ironwood_shards: i64 = st
            .wallet_mut()
            .conn_mut()
            .query_row("SELECT COUNT(*) FROM ironwood_tree_shards", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(ironwood_shards > 0);
    }

    /// End-to-end: a wallet that has received an Ironwood note can select and spend it. The
    /// resulting transaction spends the Ironwood note (it carries an Ironwood bundle), pays a
    /// nonzero fee, records the note as spent, and reduces the account balance.
    #[test]
    #[cfg(feature = "orchard")]
    fn spend_received_ironwood_note() {
        use std::convert::Infallible;

        use zcash_client_backend::{
            data_api::{
                Account, WalletRead,
                testing::{
                    AddressType, IronwoodFvk, TestBuilder, orchard::OrchardPoolTester,
                    pool::ShieldedPoolTester,
                },
                wallet::ConfirmationsPolicy,
                wallet::input_selection::GreedyInputSelector,
            },
            fees::{DustOutputPolicy, StandardFeeRule, standard},
            wallet::OvkPolicy,
        };
        use zcash_keys::address::Address;
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::{
            ShieldedPool, consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis,
        };
        use zip321::{Payment, TransactionRequest};

        use crate::testing::{BlockCache, db::TestDbFactory};

        // A network on which Ironwood (NU6.3) is active from the same height as Sapling, so
        // received Ironwood notes are offered by input selection (which gates on NU6.3 activation)
        // and can be spent.
        let activation = BlockHeight::from_u32(100_000);
        let network = LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        };

        let mut st = TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let account_id = account.id();

        // Receive an Ironwood note, comfortably larger than the payment and fee.
        let received = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
        let note_value = Zatoshis::const_from_u64(100_000);
        let (h, _, _) = st.generate_next_block(&received, AddressType::DefaultExternal, note_value);
        st.scan_cached_blocks(h, 1);
        assert_eq!(st.get_total_balance(account_id), note_value);

        // Advance the chain so the note's shard is fully scanned and an anchor is available.
        for _ in 0..5 {
            let (h, _) = st.generate_empty_block();
            st.scan_cached_blocks(h, 1);
        }

        // Propose and create a transfer that must spend the Ironwood note.
        let to_sk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to: Address = OrchardPoolTester::sk_default_address(&to_sk);
        let payment_value = Zatoshis::const_from_u64(10_000);
        let request = TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            payment_value,
        )])
        .unwrap();

        let fee_rule = StandardFeeRule::Zip317;
        let change_strategy = standard::SingleOutputChangeStrategy::new(
            fee_rule,
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();

        let proposal = st
            .propose_transfer(
                account_id,
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        // Change from spending Ironwood notes stays in the Ironwood pool rather than crossing
        // the turnstile back into Orchard.
        let change = proposal.steps().last().balance().proposed_change();
        assert!(!change.is_empty(), "the spend must produce change");
        assert!(
            change
                .iter()
                .all(|c| c.output_pool() == zcash_protocol::PoolType::IRONWOOD),
            "change from an Ironwood spend must stay in the Ironwood pool"
        );

        // The Orchard-receiver payment is represented in the proposal as an Ironwood-pool
        // output, since Ironwood is active; a user inspecting the proposal sees the Ironwood
        // output being created.
        assert!(
            proposal
                .steps()
                .last()
                .payment_pools()
                .values()
                .all(|p| *p == zcash_protocol::PoolType::IRONWOOD),
            "the Orchard-receiver payment must be represented as an Ironwood output"
        );

        // A wallet application serializes the proposal to protobuf (e.g. to hand it across
        // FFI for review/signing) before creating the transaction. A proposal that spends
        // Ironwood notes must survive that round-trip.
        let proposal_proto =
            zcash_client_backend::proto::proposal::Proposal::from_standard_proposal(&proposal);
        let roundtripped = proposal_proto
            .try_into_standard_proposal(st.network(), st.wallet())
            .expect("Ironwood proposal round-trips through protobuf");
        assert_eq!(roundtripped, proposal);

        let fee = proposal.steps().last().balance().fee_required();
        assert!(fee.into_u64() > 0, "the transaction must pay a fee");

        let created = st
            .create_proposed_transactions::<Infallible, _, Infallible, _>(
                account.usk(),
                OvkPolicy::Sender,
                &proposal,
            )
            .unwrap();
        assert_eq!(created.len(), 1);
        let sent_txid = created[0];

        // The created transaction spends into the Ironwood bundle.
        let tx = st
            .wallet()
            .get_transaction(sent_txid)
            .unwrap()
            .expect("The sent transaction was stored.");
        assert!(
            tx.ironwood_bundle().is_some(),
            "the transaction must contain an Ironwood bundle"
        );

        // The received Ironwood note is now recorded as spent.
        let ironwood_spends: i64 = st
            .wallet_mut()
            .conn_mut()
            .query_row(
                "SELECT COUNT(*) FROM ironwood_received_note_spends",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ironwood_spends, 1, "the Ironwood note must be spent");

        // The balance decreased by at least the payment plus the fee.
        assert!(
            st.get_total_balance(account_id) <= (note_value - payment_value - fee).unwrap(),
            "the account balance must decrease by the payment and fee"
        );
    }

    /// `decrypt_transaction` must decrypt a transaction's Ironwood bundle under the Ironwood
    /// note-encryption domain, detecting a wallet-owned Ironwood output as an Ironwood note (and
    /// not as Orchard). Decrypting under the Orchard domain would silently detect nothing.
    #[test]
    #[cfg(feature = "orchard")]
    fn decrypt_transaction_detects_ironwood_output() {
        use std::collections::HashMap;
        use std::convert::Infallible;

        use zcash_client_backend::{
            data_api::{
                Account, WalletRead,
                testing::{
                    AddressType, IronwoodFvk, TestBuilder, orchard::OrchardPoolTester,
                    pool::ShieldedPoolTester,
                },
                wallet::ConfirmationsPolicy,
                wallet::input_selection::GreedyInputSelector,
            },
            decrypt_transaction,
            fees::{DustOutputPolicy, StandardFeeRule, standard},
            wallet::OvkPolicy,
        };
        use zcash_keys::address::Address;
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::{
            ShieldedPool, consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis,
        };
        use zip321::{Payment, TransactionRequest};

        use crate::testing::{BlockCache, db::TestDbFactory};

        let activation = BlockHeight::from_u32(100_000);
        let network = LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        };

        let mut st = TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let account_id = account.id();
        let account_fvk = OrchardPoolTester::test_account_fvk(&st);

        // Receive an Ironwood note to fund the transfer.
        let received = IronwoodFvk(account_fvk.clone());
        let note_value = Zatoshis::const_from_u64(100_000);
        let (h, _, _) = st.generate_next_block(&received, AddressType::DefaultExternal, note_value);
        st.scan_cached_blocks(h, 1);
        for _ in 0..5 {
            let (h, _) = st.generate_empty_block();
            st.scan_cached_blocks(h, 1);
        }

        // Pay the account's own Orchard address; while Ironwood is active this produces a
        // wallet-owned Ironwood output.
        let to: Address = OrchardPoolTester::fvk_default_address(&account_fvk);
        let payment_value = Zatoshis::const_from_u64(10_000);
        let request = TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            payment_value,
        )])
        .unwrap();

        let change_strategy = standard::SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();
        let proposal = st
            .propose_transfer(
                account_id,
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();
        let created = st
            .create_proposed_transactions::<Infallible, _, Infallible, _>(
                account.usk(),
                OvkPolicy::Sender,
                &proposal,
            )
            .unwrap();
        let tx = st
            .wallet()
            .get_transaction(created[0])
            .unwrap()
            .expect("The sent transaction was stored.");

        // Decrypt the full transaction with the account's viewing keys.
        let mut ufvks = HashMap::new();
        ufvks.insert(account_id, account.ufvk().unwrap().clone());
        let d_tx = decrypt_transaction(st.network(), None, None, &tx, &ufvks);

        // The wallet-owned Ironwood outputs are detected under the Ironwood domain (not
        // Orchard). Spending Ironwood funds to the account's own Orchard receiver produces both
        // an Ironwood payment output and Ironwood change, so the payment is detected among them.
        let ironwood: Vec<_> = d_tx
            .ironwood_outputs()
            .iter()
            .filter(|o| o.value_pool() == ShieldedPool::Ironwood)
            .collect();
        assert!(
            !ironwood.is_empty(),
            "wallet-owned Ironwood outputs must be detected under the Ironwood domain"
        );
        assert!(
            ironwood
                .iter()
                .any(|o| o.note().0.value().inner() == payment_value.into_u64()),
            "the Ironwood self-payment output must be detected"
        );
        assert!(
            d_tx.orchard_outputs()
                .iter()
                .all(|o| o.value_pool() == ShieldedPool::Orchard),
            "Ironwood notes must not be misfiled as Orchard outputs"
        );
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

    #[test]
    #[cfg(feature = "orchard")]
    fn get_unspent_ironwood_notes_at_historical_height_boundary_heights() {
        use orchard::note::NoteVersion;
        use zcash_client_backend::data_api::{
            Account,
            testing::{
                AddressType, IronwoodFvk, TestBuilder, orchard::OrchardPoolTester,
                pool::ShieldedPoolTester,
            },
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::{
            ShieldedPool, consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis,
        };

        use crate::testing::{BlockCache, db::TestDbFactory};

        let activation = BlockHeight::from_u32(100_000);
        let network = LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        };

        let mut st = TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));

        let value = Zatoshis::const_from_u64(50000);
        let (h1, _, nf) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        assert_eq!(h1, activation);
        st.scan_cached_blocks(h1, 1);

        // Use Sapling so the only wallet-owned output is Ironwood change.
        let not_our_key = SaplingPoolTester::sk_to_fvk(&SaplingPoolTester::sk(&[0xf5; 32]));
        let to = SaplingPoolTester::fvk_default_address(&not_our_key);
        let spend_value = Zatoshis::const_from_u64(20000);
        let (h2, _) = st.generate_next_block_spending(&dfvk, (nf, value), to, spend_value);
        st.scan_cached_blocks(h2, 1);

        let value3 = Zatoshis::const_from_u64(70000);
        let (h3, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value3);
        st.scan_cached_blocks(h3, 1);

        let db = st.wallet().db();

        let notes = db
            .get_unspent_ironwood_notes_at_historical_height(account.id(), h1 - 1)
            .unwrap();
        assert!(notes.is_empty());

        let notes = db
            .get_unspent_ironwood_notes_at_historical_height(account.id(), h1)
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note_value().unwrap(), value);
        assert_eq!(notes[0].internal_note_id().0, ShieldedPool::Ironwood);
        assert_eq!(notes[0].note().version(), NoteVersion::V3);

        let notes = db
            .get_unspent_ironwood_notes_at_historical_height(account.id(), h2)
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes[0].note_value().unwrap(),
            (value - spend_value).unwrap()
        );

        let notes = db
            .get_unspent_ironwood_notes_at_historical_height(account.id(), h3)
            .unwrap();
        assert_eq!(notes.len(), 2);
        let total: Zatoshis = notes
            .iter()
            .map(|n| n.note_value().unwrap())
            .sum::<Option<Zatoshis>>()
            .unwrap();
        assert_eq!(total, ((value - spend_value).unwrap() + value3).unwrap());
        assert!(notes.iter().all(|note| {
            note.internal_note_id().0 == ShieldedPool::Ironwood
                && note.note().version() == NoteVersion::V3
        }));

        assert!(
            db.get_unspent_orchard_notes_at_historical_height(account.id(), h3)
                .unwrap()
                .is_empty()
        );
    }

    /// Property tests for the Orchard-turnstile behavior of input selection and transaction
    /// construction once the Ironwood pool (NU6.3) is active. The governing consensus rule is
    /// that the Orchard value pool balance must be nonnegative: value may leave the Orchard
    /// pool, but may not enter it. Consequently:
    ///
    /// 1. A payment to an Orchard receiver is delivered via the Ironwood bundle (no new
    ///    Orchard payment outputs), and such a transaction builds successfully.
    /// 2. Pool crossing is minimized: when a single pool's notes can cover a payment, notes
    ///    are spent from that pool alone, preferring the pool that matches the payment's
    ///    outputs.
    /// 3. Pools may be combined to fund a payment — including the legacy Orchard pool —
    ///    with change directed to the Orchard pool only when strictly less value returns to
    ///    that pool than the transaction's Orchard inputs remove from it.
    #[cfg(feature = "orchard")]
    mod ironwood_privacy_invariants {
        use std::convert::Infallible;

        use proptest::prelude::*;

        use zcash_client_backend::{
            data_api::{
                Account, WalletRead,
                testing::{
                    AddressType, IronwoodFvk, TestBuilder, orchard::OrchardPoolTester,
                    pool::ShieldedPoolTester, sapling::SaplingPoolTester,
                },
                wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
            },
            fees::{DustOutputPolicy, StandardFeeRule, standard},
            wallet::OvkPolicy,
        };
        use zcash_keys::address::Address;
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::{
            PoolType, ShieldedPool, consensus::BlockHeight, local_consensus::LocalNetwork,
            value::Zatoshis,
        };
        use zip321::{Payment, TransactionRequest};

        use crate::testing::{
            BlockCache,
            db::{TestDb, TestDbFactory},
        };

        // A network on which Ironwood (NU6.3) is active from the Sapling activation height, so
        // received Ironwood notes are offered by input selection (which gates on NU6.3 activation).
        fn ironwood_active_network() -> LocalNetwork {
            let activation = BlockHeight::from_u32(100_000);
            LocalNetwork {
                nu6: Some(activation),
                nu6_1: Some(activation),
                nu6_2: Some(activation),
                nu6_3: Some(activation),
                ..TestBuilder::<(), ()>::DEFAULT_NETWORK
            }
        }

        // A single-output ZIP 317 change strategy. Its nominal change pool is Orchard, but once
        // Ironwood is active the change strategy observes the Orchard turnstile: change goes to
        // Orchard only when Orchard notes are spent and strictly less value returns to the pool
        // than the notes remove; otherwise Orchard-preferred change flows onward to Ironwood.
        fn orchard_change_strategy() -> standard::SingleOutputChangeStrategy<TestDb> {
            standard::SingleOutputChangeStrategy::new(
                StandardFeeRule::Zip317,
                None,
                ShieldedPool::Orchard,
                DustOutputPolicy::default(),
            )
        }

        // Returns the shielded input notes selected across a proposal as a
        // (sapling, orchard, ironwood) tuple, using `Proposal::input_count_in_pool`.
        fn input_pool_counts<FeeRuleT, NoteRef>(
            proposal: &zcash_client_backend::proposal::Proposal<FeeRuleT, NoteRef>,
        ) -> (usize, usize, usize) {
            (
                proposal.input_count_in_pool(PoolType::SAPLING),
                proposal.input_count_in_pool(PoolType::ORCHARD),
                proposal.input_count_in_pool(PoolType::IRONWOOD),
            )
        }

        // Requests a payment of `payment_zats` to an Orchard receiver that is not owned by the
        // wallet.
        fn orchard_payment_request(
            st_network: &LocalNetwork,
            payment_zats: u64,
        ) -> TransactionRequest {
            let to_sk = OrchardPoolTester::sk(&[0xf5; 32]);
            let to: Address = OrchardPoolTester::sk_default_address(&to_sk);
            TransactionRequest::new(vec![Payment::without_memo(
                to.to_zcash_address(st_network),
                Zatoshis::from_u64(payment_zats).unwrap(),
            )])
            .unwrap()
        }

        /// When the caller restricts the spend policy to the Orchard pool, input selection may
        /// not cross into another pool to cover a shortfall: if the wallet's Orchard notes cannot
        /// fund the payment on their own, the proposal fails with `InsufficientFunds` even though
        /// an ample Sapling note exists. Crossing a pool boundary is privacy-breaking and must be
        /// an explicit choice, expressed by permitting the other pool in the `SpendPolicy`.
        #[test]
        fn restricting_spend_policy_to_orchard_forbids_crossing_into_sapling() {
            use zcash_client_backend::data_api::wallet::input_selection::SpendPolicy;

            let mut st = TestBuilder::new()
                .with_network(ironwood_active_network())
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            let account = st.test_account().cloned().unwrap();
            let account_id = account.id();

            // A small Orchard note that cannot fund the payment on its own, plus a large Sapling
            // note that easily could.
            let (h, _, _) = st.generate_next_block(
                &OrchardPoolTester::test_account_fvk(&st),
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(30_000),
            );
            st.generate_next_block(
                &SaplingPoolTester::test_account_fvk(&st),
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(200_000),
            );
            st.scan_cached_blocks(h, 2);

            for _ in 0..5 {
                let (h, _) = st.generate_empty_block();
                st.scan_cached_blocks(h, 1);
            }

            // Pay more than the Orchard note holds, so covering it would require crossing into
            // Sapling — which the restricted policy forbids.
            let request = orchard_payment_request(st.network(), 80_000);
            let change_strategy = orchard_change_strategy();
            let input_selector = GreedyInputSelector::new();

            let result = st.propose_transfer_with_policy(
                account_id,
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
                &SpendPolicy::shielded_pools([ShieldedPool::Orchard]),
            );

            let err = result.expect_err(
                "restricting to Orchard must forbid crossing into Sapling to cover the shortfall",
            );
            assert!(
                format!("{err:?}").contains("InsufficientFunds"),
                "expected InsufficientFunds, got: {err:?}",
            );
        }

        /// A transaction that spends an Orchard note (producing an Orchard bundle) and returns
        /// wallet-owned Ironwood change must record that change at the same action index the
        /// scanner assigns — the raw index within the Ironwood bundle. The send path shifted the
        /// Ironwood index by the Orchard action count (mapping into a "combined Orchard-family
        /// space"), so the send-stored index disagreed with the scanned index and, when both were
        /// written, the change was recorded twice (inflating the balance). The two indices must
        /// agree.
        #[test]
        fn ironwood_change_is_stored_at_the_raw_bundle_index() {
            use std::collections::HashMap;
            use std::convert::Infallible;

            use zcash_client_backend::{TransferType, data_api::WalletRead, decrypt_transaction};

            let mut st = TestBuilder::new()
                .with_network(ironwood_active_network())
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            let account = st.test_account().cloned().unwrap();
            let account_id = account.id();

            // A small Orchard note (so returning the change to Orchard would violate the turnstile,
            // spilling it into Ironwood) plus Ironwood and Sapling notes that are jointly required
            // to cover the payment, forcing the Orchard note to be spent (and an Orchard bundle to
            // be built).
            let (h, _, _) = st.generate_next_block(
                &OrchardPoolTester::test_account_fvk(&st),
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(10_000),
            );
            st.generate_next_block(
                &IronwoodFvk(OrchardPoolTester::test_account_fvk(&st)),
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(60_000),
            );
            st.generate_next_block(
                &SaplingPoolTester::test_account_fvk(&st),
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(90_000),
            );
            st.scan_cached_blocks(h, 3);
            for _ in 0..5 {
                let (h, _) = st.generate_empty_block();
                st.scan_cached_blocks(h, 1);
            }

            // No single note covers the payment, so all three pools are combined; the small
            // Orchard note is drained and its change spills into Ironwood.
            let request = orchard_payment_request(st.network(), 100_000);
            let change_strategy = orchard_change_strategy();
            let input_selector = GreedyInputSelector::new();
            let proposal = st
                .propose_transfer(
                    account_id,
                    &input_selector,
                    &change_strategy,
                    request,
                    ConfirmationsPolicy::MIN,
                )
                .unwrap();

            let created = st
                .create_proposed_transactions::<Infallible, _, Infallible, _>(
                    account.usk(),
                    OvkPolicy::Sender,
                    &proposal,
                )
                .unwrap();
            let tx = st
                .wallet()
                .get_transaction(created[0])
                .unwrap()
                .expect("the sent transaction was stored");
            assert!(
                tx.orchard_bundle().is_some(),
                "the Orchard spend must produce an Orchard bundle",
            );
            assert!(
                tx.ironwood_bundle().is_some(),
                "the Ironwood change must produce an Ironwood bundle",
            );

            // The send path recorded the wallet-owned Ironwood change as a received note. It is
            // distinguished from the spent 60k input note (also in this table) by having no
            // nullifier recorded: the change note has not been scanned, so no `nf` is known yet.
            let stored_index: i64 = st
                .wallet_mut()
                .conn_mut()
                .query_row(
                    "SELECT action_index FROM ironwood_received_notes WHERE nf IS NULL",
                    [],
                    |r| r.get(0),
                )
                .expect("the Ironwood change must be recorded on the send path");

            // The canonical index is the raw within-bundle index the decrypt/scan path assigns.
            // Both Ironwood outputs are decryptable by this wallet: the change with the internal
            // IVK (an `AccountInternal` transfer) and the Orchard-receiver payment via the wallet's
            // own OVK (an `Outgoing` transfer, because the transaction was created with
            // `OvkPolicy::Sender`). Select the change specifically, since the two actions are
            // shuffled and either may come first.
            let mut ufvks = HashMap::new();
            ufvks.insert(account_id, account.ufvk().unwrap().clone());
            let d_tx = decrypt_transaction(st.network(), None, None, &tx, &ufvks);
            let change = d_tx
                .ironwood_outputs()
                .iter()
                .find(|o| {
                    o.value_pool() == ShieldedPool::Ironwood
                        && o.transfer_type() == TransferType::AccountInternal
                })
                .expect("the wallet-owned Ironwood change is detected on decryption");
            let raw_index = i64::try_from(change.index()).unwrap();

            assert_eq!(
                stored_index, raw_index,
                "the send path must record the Ironwood change at the raw bundle index the \
                 scanner uses, so the two write paths agree and the note is not counted twice",
            );
        }

        /// Ironwood notes are Orchard-shaped, but a selected note's `ReceivedNoteId` must carry the
        /// Ironwood pool, not Orchard. Pool-filtered exclusion during input selection matches an
        /// excluded id only when its pool equals the pool being queried, so an Orchard-tagged
        /// Ironwood id would silently escape exclusion and be re-selected.
        #[test]
        fn ironwood_received_note_id_carries_the_ironwood_pool() {
            use std::num::NonZeroU32;

            use zcash_client_backend::data_api::{TargetValue, WalletRead};

            use crate::wallet::orchard::select_spendable_ironwood_notes;

            let mut st = TestBuilder::new()
                .with_network(ironwood_active_network())
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            let account = st.test_account().cloned().unwrap();
            let account_id = account.id();
            let network = *st.network();

            // Receive two Ironwood notes so exclusion can be exercised as well as the pool tag.
            let fvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
            let (h, _, _) = st.generate_next_block(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(100_000),
            );
            st.generate_next_block(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(100_000),
            );
            st.scan_cached_blocks(h, 2);
            for _ in 0..5 {
                let (h, _) = st.generate_empty_block();
                st.scan_cached_blocks(h, 1);
            }

            let (target_height, _) = st
                .wallet()
                .get_target_and_anchor_heights(NonZeroU32::MIN)
                .unwrap()
                .unwrap();

            // Both notes are jointly required to cover the target, so both are selected.
            let notes = select_spendable_ironwood_notes(
                st.wallet().conn(),
                &network,
                account_id,
                TargetValue::AtLeast(Zatoshis::const_from_u64(150_000)),
                target_height,
                ConfirmationsPolicy::MIN,
                &[],
                false,
            )
            .unwrap();
            assert_eq!(notes.len(), 2, "both Ironwood notes are spendable");
            for note in &notes {
                assert_eq!(
                    note.internal_note_id().0,
                    ShieldedPool::Ironwood,
                    "an Ironwood note's ReceivedNoteId must carry the Ironwood pool, not Orchard",
                );
            }

            // With the pool correctly recorded, excluding a note by its identifier drops exactly
            // that note from a re-selection (an Orchard-tagged id would fail to match the
            // Ironwood-pool query and leave the note selectable).
            let excluded = *notes[0].internal_note_id();
            let remaining = select_spendable_ironwood_notes(
                st.wallet().conn(),
                &network,
                account_id,
                TargetValue::AtLeast(Zatoshis::const_from_u64(100_000)),
                target_height,
                ConfirmationsPolicy::MIN,
                &[excluded],
                false,
            )
            .unwrap();
            assert!(
                remaining.iter().all(|n| n.internal_note_id() != &excluded),
                "excluding an Ironwood note must remove it from the selection",
            );
        }

        /// Once Ironwood is active, a payment may not be directed to the Orchard pool: input
        /// selection routes Orchard-receiver payments to the Ironwood pool. A proposal that
        /// nonetheless directs a payment to the Orchard pool can only arise from a programming
        /// error or untrusted/legacy input. Decoding such a proposal must return a
        /// `ProposalDecodingError` rather than panicking — the internal `Step::from_parts`
        /// invariant is a `debug_assert!`, so the untrusted decode boundary must reject it first.
        #[test]
        fn decoding_an_orchard_payment_after_activation_is_rejected() {
            use zcash_client_backend::proto::{ProposalDecodingError, proposal};

            let mut st = TestBuilder::new()
                .with_network(ironwood_active_network())
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            let account = st.test_account().cloned().unwrap();
            let account_id = account.id();

            let (h, _, _) = st.generate_next_block(
                &OrchardPoolTester::test_account_fvk(&st),
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(100_000),
            );
            st.scan_cached_blocks(h, 1);
            for _ in 0..5 {
                let (h, _) = st.generate_empty_block();
                st.scan_cached_blocks(h, 1);
            }

            // A payment to an Orchard receiver post-NU6.3 is classified as an Ironwood-pool output.
            let request = orchard_payment_request(st.network(), 50_000);
            let change_strategy = orchard_change_strategy();
            let input_selector = GreedyInputSelector::new();
            let proposal = st
                .propose_transfer(
                    account_id,
                    &input_selector,
                    &change_strategy,
                    request,
                    ConfirmationsPolicy::MIN,
                )
                .unwrap();

            let mut proto = proposal::Proposal::from_standard_proposal(&proposal);
            assert_eq!(
                proto.steps[0].payment_output_pools[0].value_pool,
                proposal::ValuePool::Ironwood as i32,
                "the Orchard-receiver payment must be represented as an Ironwood-pool output",
            );

            // Simulate a malicious or legacy proposal that directs the payment to the Orchard pool.
            proto.steps[0].payment_output_pools[0].value_pool = proposal::ValuePool::Orchard as i32;

            let decoded = proto.try_into_standard_proposal(st.network(), st.wallet());
            assert!(
                matches!(
                    decoded,
                    Err(ProposalDecodingError::OrchardPaymentProhibited)
                ),
                "decoding a post-activation Orchard payment must be rejected, not panic",
            );
        }

        /// A reorg truncation must roll back the Ironwood note commitment tree along with the
        /// Sapling and Orchard trees. If it does not, checkpoints (and commitments) for the
        /// rolled-back blocks remain, and a later re-scan appends onto a stale frontier,
        /// corrupting the Ironwood anchors.
        #[test]
        fn truncate_rolls_back_the_ironwood_tree() {
            use zcash_client_backend::data_api::WalletWrite;

            let mut st = TestBuilder::new()
                .with_network(ironwood_active_network())
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            // Receive Ironwood notes in three consecutive blocks and scan them, so the Ironwood
            // tree gains a checkpoint at each height.
            let fvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
            let (h0, _, _) = st.generate_next_block(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(100_000),
            );
            st.generate_next_block(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(100_000),
            );
            st.generate_next_block(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(100_000),
            );
            st.scan_cached_blocks(h0, 3);

            // A reorg truncates the wallet back to h0; the Ironwood tree must roll back with the
            // Sapling and Orchard trees.
            st.wallet_mut().truncate_to_height(h0).unwrap();

            let stale_checkpoints: i64 = st
                .wallet_mut()
                .conn_mut()
                .query_row(
                    "SELECT COUNT(*) FROM ironwood_tree_checkpoints WHERE checkpoint_id > ?1",
                    [u32::from(h0)],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                stale_checkpoints, 0,
                "truncation must remove Ironwood tree checkpoints above the truncation height",
            );
        }

        /// A transaction may be connected to the wallet solely by spending one of its Ironwood
        /// notes: it produces an Ironwood bundle revealing that note's nullifier, but has no
        /// wallet-owned outputs. `get_funding_accounts` must recognize such a spend, otherwise
        /// storing the decrypted transaction sees no wallet involvement, drops it, and never
        /// records the note as spent — leaving the spent note counted as spendable.
        #[test]
        fn get_funding_accounts_detects_ironwood_only_spends() {
            use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey};
            use rand_core::OsRng;
            use transparent::builder::TransparentSigningSet;
            use zcash_client_backend::data_api::{
                TargetValue, WalletCommitmentTrees,
                wallet::{TargetHeight, decrypt_and_store_transaction},
            };
            use zcash_primitives::transaction::{
                builder::{BuildConfig, Builder},
                fees::zip317,
            };
            use zcash_protocol::memo::MemoBytes;

            use crate::error::SqliteClientError;
            use crate::wallet::orchard::select_spendable_ironwood_notes;

            let mut st = TestBuilder::new()
                .with_network(ironwood_active_network())
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            let account = st.test_account().cloned().unwrap();
            let account_id = account.id();
            let network = *st.network();

            // Receive a single Ironwood note, scan it, then add confirmations.
            let fvk = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
            let (received_height, _, _) = st.generate_next_block(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(100_000),
            );
            st.scan_cached_blocks(received_height, 1);
            for _ in 0..5 {
                let (h, _) = st.generate_empty_block();
                st.scan_cached_blocks(h, 1);
            }

            // The anchor is the Ironwood tree state as of the height at which the note was
            // received, and the spend targets the next block.
            let anchor_height = received_height;
            let target_height = TargetHeight::from(anchor_height + 1);

            // Retrieve the received note (and its commitment tree position) from the wallet.
            let received = select_spendable_ironwood_notes(
                st.wallet().conn(),
                &network,
                account_id,
                TargetValue::AtLeast(Zatoshis::const_from_u64(1)),
                target_height,
                ConfirmationsPolicy::MIN,
                &[],
                false,
            )
            .unwrap()
            .into_iter()
            .next()
            .expect("the received Ironwood note is spendable");
            let note = *received.note();
            let position = received.note_commitment_tree_position();

            // Build the anchor and Merkle path from the wallet's Ironwood tree at the note's
            // receipt height.
            let (anchor, merkle_path) = st
                .wallet_mut()
                .with_ironwood_tree_mut::<_, _, SqliteClientError>(|tree| {
                    let anchor: orchard::Anchor = tree
                        .root_at_checkpoint_id(&anchor_height)?
                        .expect("a checkpoint exists at the note's receipt height")
                        .into();
                    let merkle_path: orchard::tree::MerklePath = tree
                        .witness_at_checkpoint_id_caching(position, &anchor_height)?
                        .expect("the received note can be witnessed at its receipt height")
                        .into();
                    Ok((anchor, merkle_path))
                })
                .unwrap()
                .expect("the wallet tracks an Ironwood tree");

            // Spend the note, sending its whole balance less the fee to an external Ironwood
            // recipient. The transaction thus has no wallet-owned outputs: its only connection to
            // the wallet is the Ironwood spend.
            let usk = account.usk();
            let spend_fvk = FullViewingKey::from(usk.orchard());
            let orchard_sak = SpendAuthorizingKey::from(usk.orchard());

            let external_sk = OrchardPoolTester::sk(&[0xf5; 32]);
            let external_recipient =
                FullViewingKey::from(&external_sk).address_at(0u32, Scope::External);

            let mut builder = Builder::new(
                network,
                BlockHeight::from(target_height),
                BuildConfig::Standard {
                    sapling_anchor: None,
                    orchard_anchor: None,
                    ironwood_anchor: Some(anchor),
                    orchard_bundle_type: orchard::builder::BundleType::DEFAULT,
                    ironwood_bundle_type: orchard::builder::BundleType::DEFAULT,
                },
            );
            builder
                .add_ironwood_spend::<zip317::FeeRule>(spend_fvk, note, merkle_path)
                .unwrap();
            builder
                .add_ironwood_output::<zip317::FeeRule>(
                    None,
                    external_recipient,
                    Zatoshis::const_from_u64(90_000),
                    MemoBytes::empty(),
                )
                .unwrap();
            let tx = builder
                .mock_build(&TransparentSigningSet::new(), &[], &[orchard_sak], OsRng)
                .unwrap()
                .transaction()
                .clone();

            let spends_before: i64 = st
                .wallet()
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM ironwood_received_note_spends",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(spends_before, 0, "the note has not yet been spent");

            // Storing the decrypted (unmined) transaction must detect the Ironwood spend as
            // wallet-funded and record the note as spent.
            decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None).unwrap();

            let spends_after: i64 = st
                .wallet()
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM ironwood_received_note_spends",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                spends_after, 1,
                "storing a transaction that spends an Ironwood note must record the note as \
                 spent, which requires get_funding_accounts to detect the Ironwood spend",
            );
        }

        prop_compose! {
            // An Orchard note value (which may or may not, on its own, cover the payment) alongside
            // large Sapling and Ironwood notes that always cover it, plus a small payment. This lets
            // input selection freely choose between spending Orchard alone or the Sapling+Ironwood
            // group.
            fn arb_mixed_pool_amounts()(
                orchard_zats in 5_000u64..300_000u64,
                payment_zats in 10_000u64..40_000u64,
            ) -> (u64, u64) {
                (orchard_zats, payment_zats)
            }
        }

        prop_compose! {
            // Two moderate note values (used for Sapling and Ironwood) and a payment that exceeds
            // either note on its own but is covered by the two together, with a comfortable fee
            // margin: `2 * pool_zats - payment == pool_zats - extra_zats >= 50_000`, which safely
            // exceeds the fee of a multi-bundle transaction.
            fn arb_combined_amounts()(
                pool_zats in 70_000u64..90_000u64,
                extra_zats in 5_000u64..20_000u64,
            ) -> (u64, u64) {
                // payment is strictly greater than a single note but below the two combined.
                (pool_zats, pool_zats + extra_zats)
            }
        }

        prop_compose! {
            // A single Orchard note value large enough to fund the payment and fee, leaving change,
            // plus the payment amount.
            fn arb_single_pool_amount()(
                note_zats in 80_000u64..400_000u64,
                payment_zats in 10_000u64..40_000u64,
            ) -> (u64, u64) {
                (note_zats, payment_zats)
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(8))]

            /// A payment to an Orchard receiver is funded from the Ironwood pool when an Ironwood
            /// note can cover it alone: the pool matching the payment's (Ironwood-routed) output
            /// is preferred, and the other pools are left untouched.
            #[test]
            fn orchard_family_payment_prefers_ironwood_inputs(
                (orchard_zats, payment_zats) in arb_mixed_pool_amounts(),
            ) {
                let mut st = TestBuilder::new()
                    .with_network(ironwood_active_network())
                    .with_data_store_factory(TestDbFactory::default())
                    .with_block_cache(BlockCache::new())
                    .with_account_from_sapling_activation(BlockHash([0; 32]))
                    .build();

                let account = st.test_account().cloned().unwrap();
                let account_id = account.id();

                // Receive one Orchard note, one Sapling note, and one Ironwood note. The Sapling and
                // Ironwood notes are large enough to fund the payment on their own.
                let (h, _, _) = st.generate_next_block(
                    &OrchardPoolTester::test_account_fvk(&st),
                    AddressType::DefaultExternal,
                    Zatoshis::from_u64(orchard_zats).unwrap(),
                );
                st.generate_next_block(
                    &SaplingPoolTester::test_account_fvk(&st),
                    AddressType::DefaultExternal,
                    Zatoshis::const_from_u64(200_000),
                );
                st.generate_next_block(
                    &IronwoodFvk(OrchardPoolTester::test_account_fvk(&st)),
                    AddressType::DefaultExternal,
                    Zatoshis::const_from_u64(200_000),
                );
                st.scan_cached_blocks(h, 3);

                for _ in 0..5 {
                    let (h, _) = st.generate_empty_block();
                    st.scan_cached_blocks(h, 1);
                }

                let request = orchard_payment_request(st.network(), payment_zats);
                let change_strategy = orchard_change_strategy();
                let input_selector = GreedyInputSelector::new();
                let proposal = st
                    .propose_transfer(
                        account_id,
                        &input_selector,
                        &change_strategy,
                        request,
                        ConfirmationsPolicy::MIN,
                    )
                    .unwrap();

                let (sapling, orchard, ironwood) = input_pool_counts(&proposal);
                prop_assert!(
                    ironwood > 0,
                    "the Ironwood note must fund the payment"
                );
                prop_assert_eq!(
                    (sapling, orchard),
                    (0, 0),
                    "the Ironwood note covers the payment alone; Sapling ({}) and Orchard ({}) \
                     notes must be left untouched",
                    sapling,
                    orchard,
                );
            }

            /// Sapling and Ironwood inputs may be combined. The wallet holds only a Sapling
            /// note and an Ironwood note, each too small to fund the payment alone; the transaction
            /// spends both, and no Orchard note is involved.
            #[test]
            fn sapling_and_ironwood_inputs_may_be_combined(
                (pool_zats, payment_zats) in arb_combined_amounts(),
            ) {
                let mut st = TestBuilder::new()
                    .with_network(ironwood_active_network())
                    .with_data_store_factory(TestDbFactory::default())
                    .with_block_cache(BlockCache::new())
                    .with_account_from_sapling_activation(BlockHash([0; 32]))
                    .build();

                let account = st.test_account().cloned().unwrap();
                let account_id = account.id();

                let (h, _, _) = st.generate_next_block(
                    &SaplingPoolTester::test_account_fvk(&st),
                    AddressType::DefaultExternal,
                    Zatoshis::from_u64(pool_zats).unwrap(),
                );
                st.generate_next_block(
                    &IronwoodFvk(OrchardPoolTester::test_account_fvk(&st)),
                    AddressType::DefaultExternal,
                    Zatoshis::from_u64(pool_zats).unwrap(),
                );
                st.scan_cached_blocks(h, 2);

                for _ in 0..5 {
                    let (h, _) = st.generate_empty_block();
                    st.scan_cached_blocks(h, 1);
                }

                let request = orchard_payment_request(st.network(), payment_zats);
                let change_strategy = orchard_change_strategy();
                let input_selector = GreedyInputSelector::new();
                let proposal = st
                    .propose_transfer(
                        account_id,
                        &input_selector,
                        &change_strategy,
                        request,
                        ConfirmationsPolicy::MIN,
                    )
                    .unwrap();

                let (sapling, orchard, ironwood) = input_pool_counts(&proposal);
                prop_assert_eq!(orchard, 0, "no Orchard note is present to spend");
                prop_assert!(sapling > 0, "a Sapling note must be spent");
                prop_assert!(
                    ironwood > 0,
                    "an Ironwood note must be spent (combined with Sapling)"
                );
            }

            /// An amount that no single pool can cover is funded by combining pools — including
            /// the legacy Orchard pool. The wallet holds an Orchard note and a Sapling note, each
            /// too small to fund the payment alone; the transaction spends both, observes the
            /// turnstile (strictly less value returns to the Orchard pool as change than the
            /// Orchard inputs remove from it), and builds successfully.
            #[test]
            fn orchard_combines_with_other_pools_within_turnstile(
                (pool_zats, payment_zats) in arb_combined_amounts(),
            ) {
                let mut st = TestBuilder::new()
                    .with_network(ironwood_active_network())
                    .with_data_store_factory(TestDbFactory::default())
                    .with_block_cache(BlockCache::new())
                    .with_account_from_sapling_activation(BlockHash([0; 32]))
                    .build();

                let account = st.test_account().cloned().unwrap();
                let account_id = account.id();

                let (h, _, _) = st.generate_next_block(
                    &OrchardPoolTester::test_account_fvk(&st),
                    AddressType::DefaultExternal,
                    Zatoshis::from_u64(pool_zats).unwrap(),
                );
                st.generate_next_block(
                    &SaplingPoolTester::test_account_fvk(&st),
                    AddressType::DefaultExternal,
                    Zatoshis::from_u64(pool_zats).unwrap(),
                );
                st.scan_cached_blocks(h, 2);

                for _ in 0..5 {
                    let (h, _) = st.generate_empty_block();
                    st.scan_cached_blocks(h, 1);
                }

                let request = orchard_payment_request(st.network(), payment_zats);
                let change_strategy = orchard_change_strategy();
                let input_selector = GreedyInputSelector::new();
                let proposal = st
                    .propose_transfer(
                        account_id,
                        &input_selector,
                        &change_strategy,
                        request,
                        ConfirmationsPolicy::MIN,
                    )
                    .unwrap();

                let (sapling, orchard, ironwood) = input_pool_counts(&proposal);
                prop_assert!(
                    orchard > 0 && sapling > 0,
                    "the payment requires combining the Orchard note ({orchard}) with the \
                     Sapling note ({sapling})",
                );
                prop_assert_eq!(ironwood, 0, "no Ironwood note is present to spend");

                // Every step observes the turnstile: strictly less value returns to the Orchard
                // pool as change than the step's Orchard inputs remove from it. (Proposal
                // construction validates this; the check here guards against the selector and
                // that validation drifting apart.)
                for step in proposal.steps() {
                    let orchard_in = step
                        .shielded_inputs()
                        .iter()
                        .flat_map(|s_in| s_in.notes().iter())
                        .filter(|n| n.note().pool() == ShieldedPool::Orchard)
                        .map(|n| n.note().value())
                        .try_fold(Zatoshis::ZERO, |acc, v| acc + v)
                        .unwrap();
                    let orchard_change = step
                        .balance()
                        .proposed_change()
                        .iter()
                        .filter(|c| c.output_pool() == PoolType::ORCHARD)
                        .map(|c| c.value())
                        .try_fold(Zatoshis::ZERO, |acc, v| acc + v)
                        .unwrap();
                    if orchard_change.into_u64() > 0 {
                        prop_assert!(
                            orchard_change < orchard_in,
                            "Orchard change {:?} must be strictly less than the Orchard input \
                             total {:?}",
                            orchard_change,
                            orchard_in,
                        );
                    }
                }

                // The mixed-pool transaction builds: the same-address Orchard change output is
                // anchored by the transaction's real Orchard spend.
                let created = st
                    .create_proposed_transactions::<Infallible, _, Infallible, _>(
                        account.usk(),
                        OvkPolicy::Sender,
                        &proposal,
                    )
                    .unwrap();
                prop_assert_eq!(created.len(), 1);
            }

            /// Orchard and Ironwood inputs may be combined in a single transaction, with both
            /// Orchard-family bundles carrying spends: the Orchard bundle carries the legacy
            /// spend and its same-address change, and the Ironwood bundle carries the Ironwood
            /// spend and the routed payment output.
            #[test]
            fn orchard_and_ironwood_inputs_combine_and_build(
                (pool_zats, payment_zats) in arb_combined_amounts(),
            ) {
                let mut st = TestBuilder::new()
                    .with_network(ironwood_active_network())
                    .with_data_store_factory(TestDbFactory::default())
                    .with_block_cache(BlockCache::new())
                    .with_account_from_sapling_activation(BlockHash([0; 32]))
                    .build();

                let account = st.test_account().cloned().unwrap();
                let account_id = account.id();

                let (h, _, _) = st.generate_next_block(
                    &OrchardPoolTester::test_account_fvk(&st),
                    AddressType::DefaultExternal,
                    Zatoshis::from_u64(pool_zats).unwrap(),
                );
                st.generate_next_block(
                    &IronwoodFvk(OrchardPoolTester::test_account_fvk(&st)),
                    AddressType::DefaultExternal,
                    Zatoshis::from_u64(pool_zats).unwrap(),
                );
                st.scan_cached_blocks(h, 2);

                for _ in 0..5 {
                    let (h, _) = st.generate_empty_block();
                    st.scan_cached_blocks(h, 1);
                }

                let request = orchard_payment_request(st.network(), payment_zats);
                let change_strategy = orchard_change_strategy();
                let input_selector = GreedyInputSelector::new();
                let proposal = st
                    .propose_transfer(
                        account_id,
                        &input_selector,
                        &change_strategy,
                        request,
                        ConfirmationsPolicy::MIN,
                    )
                    .unwrap();

                let (sapling, orchard, ironwood) = input_pool_counts(&proposal);
                prop_assert!(
                    orchard > 0 && ironwood > 0,
                    "the payment requires combining the Orchard note ({orchard}) with the \
                     Ironwood note ({ironwood})",
                );
                prop_assert_eq!(sapling, 0, "no Sapling note is present to spend");

                let created = st
                    .create_proposed_transactions::<Infallible, _, Infallible, _>(
                        account.usk(),
                        OvkPolicy::Sender,
                        &proposal,
                    )
                    .unwrap();
                prop_assert_eq!(created.len(), 1);

                let tx = st
                    .wallet()
                    .get_transaction(created[0])
                    .unwrap()
                    .expect("the sent transaction was stored");
                prop_assert!(
                    tx.orchard_bundle().is_some(),
                    "the Orchard spend must be carried by the Orchard bundle",
                );
                prop_assert!(
                    tx.ironwood_bundle().is_some(),
                    "the Ironwood spend and routed payment must be carried by the Ironwood bundle",
                );
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2))]

            /// Rule 4 at the built-transaction level: when the wallet spends an Orchard note to pay
            /// an Orchard receiver, the payment is carried by the Ironwood bundle while the change
            /// stays in the Orchard bundle (returned to the spent note's own address), and the
            /// transaction builds successfully. This proves the transaction the builder actually
            /// constructs, not just the proposal.
            #[test]
            fn orchard_payment_routes_to_ironwood_and_builds(
                (note_zats, payment_zats) in arb_single_pool_amount(),
            ) {
                let mut st = TestBuilder::new()
                    .with_network(ironwood_active_network())
                    .with_data_store_factory(TestDbFactory::default())
                    .with_block_cache(BlockCache::new())
                    .with_account_from_sapling_activation(BlockHash([0; 32]))
                    .build();

                let account = st.test_account().cloned().unwrap();
                let account_id = account.id();

                let (h, _, _) = st.generate_next_block(
                    &OrchardPoolTester::test_account_fvk(&st),
                    AddressType::DefaultExternal,
                    Zatoshis::from_u64(note_zats).unwrap(),
                );
                st.scan_cached_blocks(h, 1);

                for _ in 0..5 {
                    let (h, _) = st.generate_empty_block();
                    st.scan_cached_blocks(h, 1);
                }

                let request = orchard_payment_request(st.network(), payment_zats);
                let change_strategy = orchard_change_strategy();
                let input_selector = GreedyInputSelector::new();
                let proposal = st
                    .propose_transfer(
                        account_id,
                        &input_selector,
                        &change_strategy,
                        request,
                        ConfirmationsPolicy::MIN,
                    )
                    .unwrap();

                // Only the Orchard note is spent (single-pool inputs).
                let (sapling, orchard, ironwood) = input_pool_counts(&proposal);
                prop_assert!(orchard > 0, "the Orchard note must be spent");
                prop_assert_eq!(
                    (sapling, ironwood),
                    (0, 0),
                    "only Orchard notes should be spent"
                );

                let created = st
                    .create_proposed_transactions::<Infallible, _, Infallible, _>(
                        account.usk(),
                        OvkPolicy::Sender,
                        &proposal,
                    )
                    .unwrap();
                prop_assert_eq!(created.len(), 1);

                let tx = st
                    .wallet()
                    .get_transaction(created[0])
                    .unwrap()
                    .expect("the sent transaction was stored");

                // The Orchard-receiver payment is carried by the Ironwood bundle; the Orchard bundle
                // carries the Orchard spend and the same-address change.
                prop_assert!(
                    tx.ironwood_bundle().is_some(),
                    "the payment to an Orchard receiver must be routed to the Ironwood bundle",
                );

                // The spend of the received Orchard note must be represented in the Orchard
                // bundle, not mistakenly in the Ironwood bundle (an easy protocol confusion):
                // the nullifier the wallet recorded for the note must appear among the Orchard
                // bundle's action nullifiers and be absent from the Ironwood bundle's.
                let spent_nf: [u8; 32] = st
                    .wallet_mut()
                    .conn_mut()
                    .query_row(
                        // The spent note is the only one that has been scanned, and thus the
                        // only one whose nullifier has been recorded; the change note stored
                        // when the transaction was sent has not yet been mined.
                        "SELECT nf FROM orchard_received_notes WHERE nf IS NOT NULL",
                        [],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .unwrap()
                    .try_into()
                    .expect("nullifiers are 32 bytes");
                prop_assert!(
                    tx.orchard_bundle()
                        .into_iter()
                        .flat_map(|bundle| bundle.actions())
                        .any(|action| action.nullifier().to_bytes() == spent_nf),
                    "the Orchard spend must remain in the Orchard bundle",
                );
                prop_assert!(
                    !tx.ironwood_bundle()
                        .into_iter()
                        .flat_map(|bundle| bundle.actions())
                        .any(|action| action.nullifier().to_bytes() == spent_nf),
                    "the Orchard spend must not be represented in the Ironwood bundle",
                );

                // The change stays in the Orchard pool. Only the payment crosses the turnstile into
                // Ironwood (to a receiver the wallet does not own), so the wallet owns no Ironwood
                // note, and the retained change is recorded as an Orchard note of the expected value.
                let fee = proposal.steps().head.balance().fee_required();
                let expected_change = (Zatoshis::from_u64(note_zats).unwrap()
                    - Zatoshis::from_u64(payment_zats).unwrap()
                    - fee)
                    .unwrap();
                prop_assume!(expected_change.into_u64() > 0);

                let conn = st.wallet_mut().conn_mut();
                let ironwood_notes: i64 = conn
                    .query_row("SELECT COUNT(*) FROM ironwood_received_notes", [], |r| r.get(0))
                    .unwrap();
                prop_assert_eq!(
                    ironwood_notes,
                    0,
                    "the change must not cross the turnstile into the Ironwood pool"
                );
                let orchard_change: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM orchard_received_notes WHERE value = ?1",
                        [i64::try_from(expected_change.into_u64()).unwrap()],
                        |r| r.get(0),
                    )
                    .unwrap();
                prop_assert_eq!(
                    orchard_change,
                    1,
                    "the change must be retained as an Orchard note of the expected value"
                );

                // The payment output is carried by the Ironwood bundle, so its sent-note record
                // must be attributed to the Ironwood pool. Post-NU6.3 an Orchard-pool payment
                // output is forbidden when spending Orchard (only change may return to Orchard),
                // so a payment tagged Orchard here is both a mis-file and a protocol violation.
                let payment_pool: i64 = conn
                    .query_row(
                        "SELECT output_pool FROM sent_notes WHERE value = ?1",
                        [i64::try_from(payment_zats).unwrap()],
                        |r| r.get(0),
                    )
                    .unwrap();
                prop_assert_eq!(
                    payment_pool,
                    crate::wallet::encoding::pool_code(PoolType::IRONWOOD),
                    "the Ironwood-bundle payment must be recorded as an Ironwood-pool sent output",
                );
            }
        }
    }
}
