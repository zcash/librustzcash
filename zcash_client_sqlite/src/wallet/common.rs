//! Functions common to Sapling and Orchard support in the wallet.

use incrementalmerkletree::Position;
use rusqlite::{Connection, Row, named_params, types::Value};
use std::{num::NonZeroU64, rc::Rc};
use zip32::Scope;

use zcash_client_backend::{
    data_api::{
        MaxSpendMode, NoteFilter, NullifierQuery, PoolMeta, SAPLING_SHARD_HEIGHT, TargetValue,
        scanning::ScanPriority,
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::ReceivedNote,
};
use zcash_primitives::transaction::{TxId, builder::DEFAULT_TX_EXPIRY_DELTA, fees::zip317};
use zcash_protocol::{
    PoolType, ShieldedProtocol,
    consensus::{self, BlockHeight},
    value::{BalanceError, Zatoshis},
};

use crate::{
    AccountUuid, ReceivedNoteId, SAPLING_TABLES_PREFIX,
    error::SqliteClientError,
    wallet::{
        get_anchor_height, pool_code,
        scanning::{parse_priority_code, priority_code},
    },
};

#[cfg(feature = "orchard")]
use {crate::ORCHARD_TABLES_PREFIX, zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT};

pub(crate) struct TableConstants {
    pub(crate) table_prefix: &'static str,
    pub(crate) output_index_col: &'static str,
    pub(crate) output_count_col: &'static str,
    pub(crate) note_reconstruction_cols: &'static str,
    pub(crate) shard_height: u8,
}

const SAPLING_TABLE_CONSTANTS: TableConstants = TableConstants {
    table_prefix: SAPLING_TABLES_PREFIX,
    output_index_col: "output_index",
    output_count_col: "sapling_output_count",
    note_reconstruction_cols: "rcm",
    shard_height: SAPLING_SHARD_HEIGHT,
};

#[cfg(feature = "orchard")]
const ORCHARD_TABLE_CONSTANTS: TableConstants = TableConstants {
    table_prefix: ORCHARD_TABLES_PREFIX,
    output_index_col: "action_index",
    output_count_col: "orchard_action_count",
    note_reconstruction_cols: "rho, rseed",
    shard_height: ORCHARD_SHARD_HEIGHT,
};

#[allow(dead_code)]
pub(crate) trait ErrUnsupportedPool {
    fn unsupported_pool_type(pool_type: PoolType) -> Self;
}

pub(crate) fn table_constants<E: ErrUnsupportedPool>(
    shielded_protocol: ShieldedProtocol,
) -> Result<TableConstants, E> {
    match shielded_protocol {
        ShieldedProtocol::Sapling => Ok(SAPLING_TABLE_CONSTANTS),
        #[cfg(feature = "orchard")]
        ShieldedProtocol::Orchard => Ok(ORCHARD_TABLE_CONSTANTS),
        #[cfg(not(feature = "orchard"))]
        ShieldedProtocol::Orchard => Err(E::unsupported_pool_type(PoolType::ORCHARD)),
    }
}

/// Generates an SQL condition that a transaction is unexpired.
///
/// # Usage requirements
/// - `tx` must be set to the SQL variable name for the transaction in the parent.
/// - The parent must provide `:target_height` as a named argument.
/// - The parent is responsible for enclosing this condition in parentheses as appropriate.
///
/// If the wallet doesn't know an actual mined height or expiry height for a transaction, it will
/// be treated as unexpired _only_ if we just observed it in the last DEFAULT_TX_EXPIRY_DELTA
/// blocks, guessing that the wallet creating the transaction used the same expiry delta as our
/// default. If our guess is wrong (and the wallet used a larger expiry delta or disabled expiry),
/// then the transaction will be treated as unexpired when it shouldn't be for as long as it takes
/// this wallet to either observe the transaction being mined, or enhance it to learn its expiry
/// height.
pub(crate) fn tx_unexpired_condition(tx: &str) -> String {
    format!(
        r#"
        {tx}.mined_height < :target_height  -- the transaction is mined
        OR {tx}.expiry_height = 0  -- the tx will not expire
        OR {tx}.expiry_height >= :target_height  -- the tx is unexpired
        OR (
            {tx}.expiry_height IS NULL -- the expiry height is unknown
            AND {tx}.min_observed_height + {DEFAULT_TX_EXPIRY_DELTA} >= :target_height
        )
        "#
    )
}

// Generates a SQL expression that returns the identifiers of all spent notes in the wallet.
///
/// # Usage requirements
/// - `table_prefix` must be set to the table prefix for the shielded protocol under which the
///   query is being performed.
/// - The parent must provide `:target_height` as a named argument.
/// - The parent is responsible for enclosing this condition in parentheses as appropriate.
pub(crate) fn spent_notes_clause(table_prefix: &str) -> String {
    format!(
        r#"
        SELECT rns.{table_prefix}_received_note_id
        FROM {table_prefix}_received_note_spends rns
        JOIN transactions stx ON stx.id_tx = rns.transaction_id
        WHERE {}
        "#,
        tx_unexpired_condition("stx")
    )
}

fn unscanned_tip_exists(
    conn: &Connection,
    anchor_height: BlockHeight,
    table_prefix: &'static str,
) -> Result<bool, rusqlite::Error> {
    // v_sapling_shard_unscanned_ranges only returns ranges ending on or after wallet birthday, so
    // we don't need to refer to the birthday in this query.
    conn.query_row(
        &format!(
            "SELECT EXISTS (
                 SELECT 1 FROM v_{table_prefix}_shard_unscanned_ranges range
                 WHERE range.block_range_start <= :anchor_height
                 AND :anchor_height BETWEEN
                    range.subtree_start_height
                    AND IFNULL(range.subtree_end_height, :anchor_height)
             )"
        ),
        named_params![":anchor_height": u32::from(anchor_height),],
        |row| row.get::<_, bool>(0),
    )
}

/// Retrieves the set of nullifiers for "potentially spendable" notes that the wallet is tracking.
///
/// "Potentially spendable" means:
/// - The transaction in which the note was created has been observed as mined.
/// - No transaction in which the note's nullifier appears has been observed as mined.
///
/// This may over-select nullifiers and return those that have been spent in un-mined transactions
/// that have not yet expired, or for which the expiry height is unknown. This is fine because
/// these nullifiers are primarily used to detect the spends of our own notes in scanning; if we
/// select a few too many nullifiers, it's not a big deal.
pub(crate) fn get_nullifiers<N, F: Fn(&[u8]) -> Result<N, SqliteClientError>>(
    conn: &Connection,
    protocol: ShieldedProtocol,
    query: NullifierQuery,
    parse_nf: F,
) -> Result<Vec<(AccountUuid, N)>, SqliteClientError> {
    let TableConstants { table_prefix, .. } = table_constants::<SqliteClientError>(protocol)?;

    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers = match query {
        NullifierQuery::Unspent => conn.prepare(&format!(
            // See the method documentation for why this does not use `spent_notes_clause`.
            // We prefer to be more restrictive in determining whether a note is spent here.
            "SELECT a.uuid, rn.nf
                 FROM {table_prefix}_received_notes rn
                 JOIN accounts a ON a.id = rn.account_id
                 JOIN transactions tx ON tx.id_tx = rn.transaction_id
                 WHERE rn.nf IS NOT NULL
                 AND tx.mined_height IS NOT NULL
                 AND rn.id NOT IN (
                   SELECT rns.{table_prefix}_received_note_id
                   FROM {table_prefix}_received_note_spends rns
                   JOIN transactions stx ON stx.id_tx = rns.transaction_id
                   WHERE stx.mined_height IS NOT NULL  -- the spending tx is mined
                   OR stx.expiry_height = 0 -- the spending tx will not expire
                 )"
        )),
        NullifierQuery::All => conn.prepare(&format!(
            "SELECT a.uuid, rn.nf
             FROM {table_prefix}_received_notes rn
             JOIN accounts a ON a.id = rn.account_id
             WHERE nf IS NOT NULL",
        )),
    }?;

    let nullifiers = stmt_fetch_nullifiers.query_and_then([], |row| {
        let account = AccountUuid(row.get(0)?);
        let nf_bytes: Vec<u8> = row.get(1)?;
        Ok::<_, SqliteClientError>((account, parse_nf(&nf_bytes)?))
    })?;

    let res: Vec<_> = nullifiers.collect::<Result<_, _>>()?;
    Ok(res)
}
// The `clippy::let_and_return` lint is explicitly allowed here because a bug in Clippy
// (https://github.com/rust-lang/rust-clippy/issues/11308) means it fails to identify that the `result` temporary
// is required in order to resolve the borrows involved in the `query_and_then` call.
#[allow(clippy::let_and_return)]
pub(crate) fn get_spendable_note<P: consensus::Parameters, F, Note>(
    conn: &Connection,
    params: &P,
    txid: &TxId,
    index: u32,
    protocol: ShieldedProtocol,
    target_height: TargetHeight,
    to_spendable_note: F,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(&P, &Row) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
{
    let TableConstants {
        table_prefix,
        output_index_col,
        note_reconstruction_cols,
        ..
    } = table_constants::<SqliteClientError>(protocol)?;

    let result = conn.query_row_and_then(
        &format!(
            "SELECT rn.id, t.txid, rn.{output_index_col},
                rn.diversifier, rn.value, {note_reconstruction_cols}, rn.commitment_tree_position,
                accounts.ufvk, rn.recipient_key_scope, t.mined_height,
                MAX(tt.mined_height) AS max_shielding_input_height
             FROM {table_prefix}_received_notes rn
             INNER JOIN accounts ON accounts.id = rn.account_id
             INNER JOIN transactions t ON t.id_tx = rn.transaction_id
             LEFT OUTER JOIN transparent_received_output_spends ros
                ON ros.transaction_id = t.id_tx
             LEFT OUTER JOIN transparent_received_outputs tro
                ON tro.id = ros.transparent_received_output_id
                AND tro.account_id = accounts.id
             LEFT OUTER JOIN transactions tt
                ON tt.id_tx = tro.transaction_id
             WHERE t.txid = :txid
             AND t.block IS NOT NULL
             AND rn.{output_index_col} = :output_index
             AND accounts.ufvk IS NOT NULL
             AND rn.recipient_key_scope IS NOT NULL
             AND rn.nf IS NOT NULL
             AND rn.commitment_tree_position IS NOT NULL
             AND rn.id NOT IN ({})
             GROUP BY rn.id",
            spent_notes_clause(table_prefix)
        ),
        named_params![
           ":txid": txid.as_ref(),
           ":output_index": index,
           ":target_height": u32::from(target_height),
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

/// A directive that specifies how `select_unspent_notes` should filter and/or error on unspendable
/// notes.
#[derive(Debug, Clone, Copy)]
pub(crate) enum NoteRequest {
    /// Retrieve all currently spendable notes, ignoring those for which the wallet does not yet
    /// have enough information to construct spends, given the provided anchor height.
    Spendable { anchor_height: BlockHeight },
    /// Retrieve all currently unspent notes, including those for which the wallet does not yet
    /// have enough information to construct spends.
    Unspent,
    /// Retrieve all currently unspent notes, or an error if any notes exist for which the wallet
    /// does not yet have enough information to construct spends.
    UnspentOrError { anchor_height: BlockHeight },
}

impl NoteRequest {
    pub(crate) fn from_max_spend_mode(value: MaxSpendMode, anchor_height: BlockHeight) -> Self {
        match value {
            MaxSpendMode::MaxSpendable => NoteRequest::Spendable { anchor_height },
            MaxSpendMode::Everything => NoteRequest::UnspentOrError { anchor_height },
        }
    }

    pub(crate) fn anchor_height(&self) -> Option<BlockHeight> {
        match self {
            NoteRequest::Spendable { anchor_height } => Some(*anchor_height),
            NoteRequest::Unspent => None,
            NoteRequest::UnspentOrError { anchor_height } => Some(*anchor_height),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn select_spendable_notes<P: consensus::Parameters, F, Note>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    target_value: TargetValue,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
    protocol: ShieldedProtocol,
    to_spendable_note: F,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(&P, &Row) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
{
    let Some(anchor_height) =
        get_anchor_height(conn, target_height, confirmations_policy.trusted())?
    else {
        return Ok(vec![]);
    };

    match target_value {
        TargetValue::AllFunds(mode) => select_unspent_notes(
            conn,
            params,
            account,
            target_height,
            confirmations_policy,
            exclude,
            protocol,
            &to_spendable_note,
            NoteRequest::from_max_spend_mode(mode, anchor_height),
        ),
        TargetValue::AtLeast(zats) => select_spendable_notes_matching_value(
            conn,
            params,
            account,
            zats,
            target_height,
            anchor_height,
            confirmations_policy,
            exclude,
            protocol,
            &to_spendable_note,
        ),
    }
}
/// Selects all the unspent notes with value greater than [`zip317::MARGINAL_FEE`] and for the
/// specified shielded protocols from a given account, excepting any explicitly excluded note
/// identifiers.
///
/// Implementation details:
///
/// - Notes with individual value *below* the ``MARGINAL_FEE`` will be ignored
/// - Note spendability is determined using the `target_height`. If the note is mined at a height
///   greater than or equal to the target height, it will still be returned by this query.
/// - The `to_spendable_note` function is expected to return `Ok(None)` in the case that spending
///   key details cannot be determined.
#[allow(clippy::too_many_arguments)]
pub(crate) fn select_unspent_notes<P: consensus::Parameters, F, Note>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
    protocol: ShieldedProtocol,
    to_received_note: F,
    note_request: NoteRequest,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(&P, &Row) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
{
    let TableConstants {
        table_prefix,
        output_index_col,
        note_reconstruction_cols,
        ..
    } = table_constants::<SqliteClientError>(protocol)?;

    // Select all unspent notes belonging to the given account, ignoring dust notes.
    let mut stmt_select_notes = conn.prepare_cached(&format!(
        "SELECT
             rn.id AS id, t.txid, rn.{output_index_col},
             rn.diversifier, rn.value, {note_reconstruction_cols}, rn.commitment_tree_position,
             accounts.ufvk as ufvk, rn.recipient_key_scope,
             t.block AS mined_height,
             scan_state.max_priority,
             IFNULL(t.trust_status, 0) AS trust_status,
             MAX(tt.mined_height) AS max_shielding_input_height,
             MIN(IFNULL(tt.trust_status, 0)) AS min_shielding_input_trust
         FROM {table_prefix}_received_notes rn
         INNER JOIN accounts ON accounts.id = rn.account_id
         INNER JOIN transactions t ON t.id_tx = rn.transaction_id
         LEFT OUTER JOIN v_{table_prefix}_shards_scan_state scan_state
            ON rn.commitment_tree_position >= scan_state.start_position
            AND rn.commitment_tree_position < scan_state.end_position_exclusive
         LEFT OUTER JOIN transparent_received_output_spends ros
            ON ros.transaction_id = t.id_tx
         LEFT OUTER JOIN transparent_received_outputs tro
            ON tro.id = ros.transparent_received_output_id
            AND tro.account_id = accounts.id
         LEFT OUTER JOIN transactions tt
            ON tt.id_tx = tro.transaction_id
         WHERE accounts.uuid = :account_uuid
         AND rn.value > :min_value
         AND accounts.ufvk IS NOT NULL
         AND recipient_key_scope IS NOT NULL
         AND nf IS NOT NULL
         AND ({})  -- the transaction is unexpired
         AND rn.id NOT IN rarray(:exclude)  -- the note is not excluded
         AND rn.id NOT IN ({})  -- the note is unspent
         GROUP BY rn.id",
        tx_unexpired_condition("t"),
        spent_notes_clause(table_prefix)
    ))?;

    let excluded: Vec<Value> = exclude
        .iter()
        .filter_map(|ReceivedNoteId(p, n)| {
            if *p == protocol {
                Some(Value::from(*n))
            } else {
                None
            }
        })
        .collect();
    let excluded_ptr = Rc::new(excluded);

    let row_results = stmt_select_notes.query_and_then(
        named_params![
            ":account_uuid": account.0,
            ":target_height": &u32::from(target_height),
            ":exclude": &excluded_ptr,
            ":min_value": u64::from(zip317::MARGINAL_FEE)
        ],
        |row| -> Result<_, SqliteClientError> {
            let result_note = to_received_note(params, row)?;
            let max_priority_raw = row.get::<_, Option<i64>>("max_priority")?;
            let tx_trust_status = row.get::<_, bool>("trust_status")?;
            let tx_shielding_inputs_trusted = row.get::<_, bool>("min_shielding_input_trust")?;
            let shard_scan_priority = max_priority_raw
                .map(|code| {
                    parse_priority_code(code).ok_or_else(|| {
                        SqliteClientError::CorruptedData(format!(
                            "Priority code {code} not recognized."
                        ))
                    })
                })
                .transpose()?;

            Ok((
                result_note,
                shard_scan_priority,
                tx_trust_status,
                tx_shielding_inputs_trusted,
            ))
        },
    )?;

    let trusted_height = target_height.saturating_sub(u32::from(confirmations_policy.trusted()));
    let untrusted_height =
        target_height.saturating_sub(u32::from(confirmations_policy.untrusted()));

    row_results
        .map(|t| match t? {
            (Some(note), max_shard_priority, trusted, tx_shielding_inputs_trusted) => {
                let shard_scanned = max_shard_priority
                    .iter()
                    .any(|p| *p <= ScanPriority::Scanned);

                let mined_at_anchor = note
                    .mined_height()
                    .zip(note_request.anchor_height())
                    .is_some_and(|(h, ah)| h <= ah);

                let has_confirmations = match (note.mined_height(), note.spending_key_scope()) {
                    (None, _) => false,
                    (Some(received_height), Scope::Internal) => {
                        // The note has the required number of confirmations for a trusted note.
                        received_height <= trusted_height &&
                        // if the note was the output of a shielding transaction
                        note.max_shielding_input_height().iter().all(|h| {
                            // its inputs have at least `untrusted` confirmations
                            h <= &untrusted_height ||
                            // or its inputs are trusted and have at least `trusted` confirmations
                            (h <= &trusted_height && tx_shielding_inputs_trusted)
                        })
                    }
                    (Some(received_height), Scope::External) => {
                        // The note has the required number of confirmations for an untrusted note.
                        received_height <= untrusted_height ||
                        // or it is the output of an explicitly trusted tx and has at least
                        // `trusted` confirmations
                        (received_height <= trusted_height && trusted)
                    }
                };

                match (
                    note_request,
                    shard_scanned && mined_at_anchor && has_confirmations,
                ) {
                    (NoteRequest::UnspentOrError { .. }, false) => {
                        Err(SqliteClientError::IneligibleNotes)
                    }
                    (NoteRequest::Spendable { .. }, false) => Ok(None),
                    (NoteRequest::Unspent, false) | (_, true) => Ok(Some(note)),
                }
            }
            _ => Err(SqliteClientError::IneligibleNotes),
        })
        .filter_map(|r| r.transpose())
        .collect()
}

/// Selects the set of spendable notes whose sum will be equal or greater that the
/// specified ``target_value`` in Zatoshis from the specified shielded protocols excluding
/// the ones present in the ``exclude`` slice.
///
/// - Implementation details
///   - Notes with individual value *below* the ``MARGINAL_FEE`` will be ignored
///   - Note spendability is determined using the `anchor_height`
#[allow(clippy::too_many_arguments)]
fn select_spendable_notes_matching_value<P: consensus::Parameters, F, Note>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    target_value: Zatoshis,
    target_height: TargetHeight,
    anchor_height: BlockHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
    protocol: ShieldedProtocol,
    to_spendable_note: F,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(&P, &Row) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
{
    let TableConstants {
        table_prefix,
        output_index_col,
        note_reconstruction_cols,
        ..
    } = table_constants::<SqliteClientError>(protocol)?;
    if unscanned_tip_exists(conn, anchor_height, table_prefix)? {
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
    let mut stmt_select_notes = conn.prepare_cached(&format!(
        "WITH eligible AS (
             SELECT
                 rn.id AS id, t.txid, rn.{output_index_col},
                 rn.diversifier, rn.value,
                 {note_reconstruction_cols}, rn.commitment_tree_position,
                 SUM(value) OVER (ROWS UNBOUNDED PRECEDING) AS so_far,
                 accounts.ufvk as ufvk, rn.recipient_key_scope,
                 t.block AS mined_height,
                 IFNULL(t.trust_status, 0) AS trust_status,
                 MAX(tt.mined_height) AS max_shielding_input_height,
                 MIN(IFNULL(tt.trust_status, 0)) AS min_shielding_input_trust
             FROM {table_prefix}_received_notes rn
             INNER JOIN accounts ON accounts.id = rn.account_id
             INNER JOIN transactions t ON t.id_tx = rn.transaction_id
             LEFT OUTER JOIN v_{table_prefix}_shards_scan_state scan_state
                ON rn.commitment_tree_position >= scan_state.start_position
                AND rn.commitment_tree_position < scan_state.end_position_exclusive
             LEFT OUTER JOIN transparent_received_output_spends ros
                ON ros.transaction_id = t.id_tx
             LEFT OUTER JOIN transparent_received_outputs tro
                ON tro.id = ros.transparent_received_output_id
                AND tro.account_id = accounts.id
             LEFT OUTER JOIN transactions tt
                ON tt.id_tx = tro.transaction_id
             WHERE accounts.uuid = :account_uuid
             AND rn.value > :min_value
             AND accounts.ufvk IS NOT NULL
             AND recipient_key_scope IS NOT NULL
             AND nf IS NOT NULL
             -- the shard containing the note is fully scanned; this condition will exclude
             -- notes for which `scan_state.max_priority IS NULL` (which will also arise if
             -- `rn.commitment_tree_position IS NULL`; hence we don't need that explicit filter)
             AND scan_state.max_priority <= :scanned_priority
             AND t.block <= :anchor_height
             AND rn.id NOT IN rarray(:exclude)
             AND rn.id NOT IN ({})
             GROUP BY rn.id
         )
         SELECT id, txid, {output_index_col},
                diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                ufvk, recipient_key_scope,
                mined_height, trust_status,
                max_shielding_input_height, min_shielding_input_trust
         FROM eligible WHERE so_far < :target_value
         UNION
         SELECT id, txid, {output_index_col},
                diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                ufvk, recipient_key_scope,
                mined_height, trust_status,
                max_shielding_input_height, min_shielding_input_trust
         FROM (SELECT * from eligible WHERE so_far >= :target_value LIMIT 1)",
        spent_notes_clause(table_prefix)
    ))?;

    let excluded: Vec<Value> = exclude
        .iter()
        .filter_map(|ReceivedNoteId(p, n)| {
            if *p == protocol {
                Some(Value::from(*n))
            } else {
                None
            }
        })
        .collect();
    let excluded_ptr = Rc::new(excluded);

    let notes = stmt_select_notes.query_and_then(
        named_params![
            ":account_uuid": account.0,
            ":anchor_height": &u32::from(anchor_height),
            ":target_height": &u32::from(target_height),
            ":target_value": &u64::from(target_value),
            ":exclude": &excluded_ptr,
            ":scanned_priority": priority_code(&ScanPriority::Scanned),
            ":min_value": u64::from(zip317::MARGINAL_FEE)
        ],
        |row| {
            let tx_trust_status = row.get::<_, bool>("trust_status")?;
            let tx_shielding_inputs_trusted = row.get::<_, bool>("min_shielding_input_trust")?;
            let note = to_spendable_note(params, row)?;

            Ok(note.map(|n| (n, tx_trust_status, tx_shielding_inputs_trusted)))
        },
    )?;

    let trusted_height = target_height.saturating_sub(u32::from(confirmations_policy.trusted()));
    let untrusted_height =
        target_height.saturating_sub(u32::from(confirmations_policy.untrusted()));

    notes
        .filter_map(|result_maybe_note| {
            let result_note = result_maybe_note.transpose()?;
            result_note
                .map(|(note, trusted, tx_shielding_inputs_trusted)| {
                    let received_height = note
                        .mined_height()
                        .expect("mined height checked to be non-null");

                    let has_confirmations = match note.spending_key_scope() {
                        Scope::Internal => {
                            // The note was has at least `trusted` confirmations.
                            received_height <= trusted_height &&
                            // And, if the note was the output of a shielding transaction, its
                            // transparent inputs have at least `untrusted` confirmations.
                            note.max_shielding_input_height().iter().all(|h| {
                                // its inputs have at least `untrusted` confirmations
                                h <= &untrusted_height ||
                                // or its inputs are trusted and have at least `trusted` confirmations
                                (h <= &trusted_height && tx_shielding_inputs_trusted)
                            })
                        }
                        Scope::External => {
                            // The note has the required number of confirmations for an untrusted note.
                            received_height <= untrusted_height ||
                            // or it is the output of an explicitly trusted tx and has at least
                            // `trusted` confirmations
                            (received_height <= trusted_height && trusted)
                        }
                    };

                    has_confirmations.then_some(note)
                })
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()
}

#[allow(dead_code)]
pub(crate) struct UnspentNoteMeta {
    note_id: ReceivedNoteId,
    txid: TxId,
    output_index: u32,
    commitment_tree_position: Position,
    value: Zatoshis,
}

#[allow(dead_code)]
impl UnspentNoteMeta {
    pub(crate) fn note_id(&self) -> ReceivedNoteId {
        self.note_id
    }

    pub(crate) fn txid(&self) -> TxId {
        self.txid
    }

    pub(crate) fn output_index(&self) -> u32 {
        self.output_index
    }

    pub(crate) fn commitment_tree_position(&self) -> Position {
        self.commitment_tree_position
    }

    pub(crate) fn value(&self) -> Zatoshis {
        self.value
    }
}

pub(crate) fn select_unspent_note_meta(
    conn: &rusqlite::Connection,
    protocol: ShieldedProtocol,
    wallet_birthday: BlockHeight,
    anchor_height: BlockHeight,
) -> Result<Vec<UnspentNoteMeta>, SqliteClientError> {
    let TableConstants {
        table_prefix,
        output_index_col,
        ..
    } = table_constants::<SqliteClientError>(protocol)?;

    // This query is effectively the same as the internal `eligible` subquery
    // used in `select_spendable_notes`.
    //
    // TODO: Deduplicate this in the future by introducing a view?
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT rn.id AS id, txid, {output_index_col},
                commitment_tree_position, value
         FROM {table_prefix}_received_notes rn
         INNER JOIN transactions ON transactions.id_tx = rn.transaction_id
         WHERE value > 5000 -- FIXME #1316, allow selection of dust inputs
         AND recipient_key_scope IS NOT NULL
         AND nf IS NOT NULL
         AND commitment_tree_position IS NOT NULL
         AND rn.id NOT IN ({})
         AND NOT EXISTS (
            SELECT 1 FROM v_{table_prefix}_shard_unscanned_ranges unscanned
            -- select all the unscanned ranges involving the shard containing this note
            WHERE rn.commitment_tree_position >= unscanned.start_position
            AND rn.commitment_tree_position < unscanned.end_position_exclusive
            -- exclude unscanned ranges that start above the anchor height (they don't affect spendability)
            AND unscanned.block_range_start <= :anchor_height
            -- exclude unscanned ranges that end below the wallet birthday
            AND unscanned.block_range_end > :wallet_birthday
         )",
         spent_notes_clause(table_prefix)
    ))?;

    let res = stmt
        .query_and_then::<_, SqliteClientError, _, _>(
            named_params![
                ":wallet_birthday": u32::from(wallet_birthday),
                ":anchor_height": u32::from(anchor_height),
            ],
            |row| {
                Ok(UnspentNoteMeta {
                    note_id: row.get("id").map(|id| ReceivedNoteId(protocol, id))?,
                    txid: row.get("txid").map(TxId::from_bytes)?,
                    output_index: row.get(output_index_col)?,
                    commitment_tree_position: row
                        .get::<_, u64>("commitment_tree_position")
                        .map(Position::from)?,
                    value: Zatoshis::from_nonnegative_i64(row.get("value")?)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(res)
}

pub(crate) fn unspent_notes_meta(
    conn: &rusqlite::Connection,
    protocol: ShieldedProtocol,
    target_height: TargetHeight,
    account: AccountUuid,
    filter: &NoteFilter,
    exclude: &[ReceivedNoteId],
) -> Result<Option<PoolMeta>, SqliteClientError> {
    let TableConstants { table_prefix, .. } = table_constants::<SqliteClientError>(protocol)?;

    let excluded: Vec<Value> = exclude
        .iter()
        .filter_map(|ReceivedNoteId(p, n)| {
            if *p == protocol {
                Some(Value::from(*n))
            } else {
                None
            }
        })
        .collect();
    let excluded_ptr = Rc::new(excluded);

    fn zatoshis(value: i64) -> Result<Zatoshis, SqliteClientError> {
        Zatoshis::from_nonnegative_i64(value).map_err(|_| {
            SqliteClientError::CorruptedData(format!("Negative received note value: {value}"))
        })
    }

    let run_selection = |min_value| {
        conn.query_row_and_then::<_, SqliteClientError, _, _>(
            &format!(
                "SELECT COUNT(*), SUM(rn.value)
                 FROM {table_prefix}_received_notes rn
                 INNER JOIN accounts a ON a.id = rn.account_id
                 INNER JOIN transactions ON transactions.id_tx = rn.transaction_id
                 WHERE a.uuid = :account_uuid
                 AND a.ufvk IS NOT NULL
                 AND rn.value >= :min_value
                 AND transactions.mined_height IS NOT NULL
                 AND rn.id NOT IN rarray(:exclude)
                 AND rn.id NOT IN ({})",
                spent_notes_clause(table_prefix)
            ),
            named_params![
                ":account_uuid": account.0,
                ":min_value": u64::from(min_value),
                ":exclude": &excluded_ptr,
                ":target_height": u32::from(target_height)
            ],
            |row| {
                Ok((
                    row.get::<_, usize>(0)?,
                    row.get::<_, Option<i64>>(1)?.map(zatoshis).transpose()?,
                ))
            },
        )
    };

    // Evaluates the provided note filter conditions against the wallet database in order to
    // determine the minimum value of notes to be produced by note splitting.
    fn min_note_value(
        conn: &rusqlite::Connection,
        account: AccountUuid,
        filter: &NoteFilter,
        target_height: TargetHeight,
    ) -> Result<Option<Zatoshis>, SqliteClientError> {
        match filter {
            NoteFilter::ExceedsMinValue(v) => Ok(Some(*v)),
            NoteFilter::ExceedsPriorSendPercentile(n) => {
                let mut bucket_query = conn.prepare(
                    "WITH bucketed AS (
                        SELECT s.value, NTILE(10) OVER (ORDER BY s.value) AS bucket_index
                        FROM sent_notes s
                        JOIN transactions t ON s.transaction_id = t.id_tx
                        JOIN accounts a on a.id = s.from_account_id
                        WHERE a.uuid = :account_uuid
                        -- only count mined transactions
                        AND t.mined_height IS NOT NULL
                        -- exclude change and account-internal sends
                        AND (s.to_account_id IS NULL OR s.from_account_id != s.to_account_id)
                    )
                    SELECT MAX(value) as value
                    FROM bucketed
                    GROUP BY bucket_index
                    ORDER BY bucket_index",
                )?;

                let bucket_maxima = bucket_query
                    .query_and_then::<_, SqliteClientError, _, _>(
                        named_params![":account_uuid": account.0],
                        |row| {
                            Zatoshis::from_nonnegative_i64(row.get::<_, i64>(0)?).map_err(|_| {
                                SqliteClientError::CorruptedData(format!(
                                    "Negative received note value: {}",
                                    n.value()
                                ))
                            })
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?;

                // Pick a bucket index by scaling the requested percentile to the number of buckets
                let i = (bucket_maxima.len() * usize::from(*n) / 100).saturating_sub(1);
                Ok(bucket_maxima.get(i).copied())
            }
            NoteFilter::ExceedsBalancePercentage(p) => {
                let balance = conn.query_row_and_then::<_, SqliteClientError, _, _>(
                    &format!(
                        "SELECT SUM(rn.value)
                         FROM v_received_outputs rn
                         INNER JOIN accounts a ON a.id = rn.account_id
                         INNER JOIN transactions ON transactions.id_tx = rn.transaction_id
                         WHERE a.uuid = :account_uuid
                         AND a.ufvk IS NOT NULL
                         AND transactions.mined_height IS NOT NULL
                         AND rn.pool != :transparent_pool
                         AND (rn.pool, rn.id_within_pool_table) NOT IN (
                            SELECT rns.pool, rns.received_output_id
                            FROM v_received_output_spends rns
                            JOIN transactions stx ON stx.id_tx = rns.transaction_id
                            WHERE ({})  -- the spending transaction is unexpired
                         )",
                        tx_unexpired_condition("stx")
                    ),
                    named_params![
                        ":account_uuid": account.0,
                        ":transparent_pool": pool_code(PoolType::Transparent),
                        ":target_height": u32::from(target_height),
                    ],
                    |row| row.get::<_, Option<i64>>(0)?.map(zatoshis).transpose(),
                )?;

                Ok(match balance {
                    None => None,
                    Some(b) => {
                        let numerator = (b * u64::from(p.value())).ok_or(BalanceError::Overflow)?;
                        Some(numerator / NonZeroU64::new(100).expect("Constant is nonzero."))
                    }
                })
            }
            NoteFilter::Combine(a, b) => {
                // All the existing note selectors set lower bounds on note value, so the "and"
                // operation is just taking the maximum of the two lower bounds.
                let a_min_value = min_note_value(conn, account, a.as_ref(), target_height)?;
                let b_min_value = min_note_value(conn, account, b.as_ref(), target_height)?;
                Ok(a_min_value
                    .zip(b_min_value)
                    .map(|(av, bv)| std::cmp::max(av, bv))
                    .or(a_min_value)
                    .or(b_min_value))
            }
            NoteFilter::Attempt {
                condition,
                fallback,
            } => {
                let cond = min_note_value(conn, account, condition.as_ref(), target_height)?;
                if cond.is_none() {
                    min_note_value(conn, account, fallback, target_height)
                } else {
                    Ok(cond)
                }
            }
        }
    }

    // TODO: Simplify the query before executing it. Not worrying about this now because queries
    // will be developer-configured, not end-user defined.
    if let Some(min_value) = min_note_value(conn, account, filter, target_height)? {
        let (note_count, total_value) = run_selection(min_value)?;

        Ok(Some(PoolMeta::new(
            note_count,
            total_value.unwrap_or(Zatoshis::ZERO),
        )))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use zcash_client_backend::data_api::testing::{
        AddressType, TestBuilder, pool::ShieldedPoolTester, sapling::SaplingPoolTester,
    };
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{ShieldedProtocol, value::Zatoshis};

    use crate::testing::{BlockCache, db::TestDbFactory};

    #[test]
    fn select_unspent_note_meta() {
        let cache = BlockCache::new();
        let mut st = TestBuilder::new()
            .with_block_cache(cache)
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let birthday_height = st.test_account().unwrap().birthday().height();
        let dfvk = SaplingPoolTester::test_account_fvk(&st);

        // Add funds to the wallet in a single note
        let value = Zatoshis::const_from_u64(60000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        let unspent_note_meta = super::select_unspent_note_meta(
            st.wallet().conn(),
            ShieldedProtocol::Sapling,
            birthday_height,
            h,
        )
        .unwrap();

        assert_eq!(unspent_note_meta.len(), 1);
    }
}
