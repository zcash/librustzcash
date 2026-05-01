//! Functions common to Sapling and Orchard support in the wallet.

use incrementalmerkletree::Position;
use rusqlite::{Connection, Row, named_params, types::Value};
use std::{num::NonZeroU64, rc::Rc};

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
    PoolType, ShieldedPool,
    consensus::{self, BlockHeight},
    value::{BalanceError, Zatoshis},
};

use crate::{
    AccountUuid, ReceivedNoteId, SAPLING_TABLES_PREFIX,
    error::SqliteClientError,
    wallet::{get_anchor_height, pool_code},
};

#[cfg(feature = "orchard")]
use {
    crate::IRONWOOD_TABLES_PREFIX, crate::ORCHARD_TABLES_PREFIX,
    zcash_client_backend::data_api::IRONWOOD_SHARD_HEIGHT,
    zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT,
};

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
    note_reconstruction_cols: "rho, rseed, note_version",
    shard_height: ORCHARD_SHARD_HEIGHT,
};

// Ironwood notes are Orchard-shaped, so the Ironwood tables mirror the Orchard tables; they differ
// only in the table prefix and the block-level action-count column.
#[cfg(feature = "orchard")]
const IRONWOOD_TABLE_CONSTANTS: TableConstants = TableConstants {
    table_prefix: IRONWOOD_TABLES_PREFIX,
    output_index_col: "action_index",
    output_count_col: "ironwood_action_count",
    note_reconstruction_cols: "rho, rseed, note_version",
    shard_height: IRONWOOD_SHARD_HEIGHT,
};

#[allow(dead_code)]
pub(crate) trait ErrUnsupportedPool {
    fn unsupported_pool_type(pool_type: PoolType) -> Self;
}

pub(crate) fn table_constants<E: ErrUnsupportedPool>(
    shielded_protocol: ShieldedPool,
) -> Result<TableConstants, E> {
    match shielded_protocol {
        ShieldedPool::Sapling => Ok(SAPLING_TABLE_CONSTANTS),
        #[cfg(feature = "orchard")]
        ShieldedPool::Orchard => Ok(ORCHARD_TABLE_CONSTANTS),
        #[cfg(not(feature = "orchard"))]
        ShieldedPool::Orchard => Err(E::unsupported_pool_type(PoolType::ORCHARD)),
        #[cfg(feature = "orchard")]
        ShieldedPool::Ironwood => Ok(IRONWOOD_TABLE_CONSTANTS),
        #[cfg(not(feature = "orchard"))]
        ShieldedPool::Ironwood => Err(E::unsupported_pool_type(PoolType::IRONWOOD)),
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
    protocol: ShieldedPool,
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
    protocol: ShieldedPool,
    target_height: TargetHeight,
    to_spendable_note: F,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(
        &P,
        ShieldedPool,
        &Row,
    ) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
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
        |row| to_spendable_note(params, protocol, row),
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

/// Returns whether the wallet's shardtree has a frontier at the given anchor height for
/// the specified pool — i.e. whether a tree-state checkpoint exists from which a witness
/// against this anchor can be reconstructed.
///
/// After a deep rewind that drops the chain tip below the lowest surviving tree
/// checkpoint, no checkpoint exists at the anchor height and the wallet treats the
/// anchor as unavailable for spendability purposes.
pub(crate) fn anchor_frontier_available(
    conn: &Connection,
    anchor_height: BlockHeight,
    protocol: ShieldedPool,
) -> Result<bool, SqliteClientError> {
    let table_prefix = match protocol {
        ShieldedPool::Sapling => SAPLING_TABLES_PREFIX,
        #[cfg(feature = "orchard")]
        ShieldedPool::Orchard => ORCHARD_TABLES_PREFIX,
        #[cfg(feature = "orchard")]
        ShieldedPool::Ironwood => IRONWOOD_TABLES_PREFIX,
        #[cfg(not(feature = "orchard"))]
        ShieldedPool::Orchard | ShieldedPool::Ironwood => return Ok(true),
    };
    Ok(
        super::commitment_tree::get_checkpoint(conn, table_prefix, anchor_height)
            .map_err(|e| {
                SqliteClientError::CommitmentTree(shardtree::error::ShardTreeError::Storage(e))
            })?
            .is_some(),
    )
}

/// Encodes the wallet's spendability rule for a single note, given the orthogonal predicates
/// that compose it. All must hold for the note to be spendable.
///
/// 1. **Stored floor at or below the chosen anchor.** `witness_anchor_stable` (the note's
///    *anchor floor* — the lowest anchor height for which the wallet has the data needed to
///    construct this note's witness) must be set, and must lie at or below the chosen anchor.
/// 2. **Pruning window fully scanned.** No `scan_queue` range above `Scanned` priority overlaps
///    the chain-tip pruning window. The window is at most `PRUNING_DEPTH` blocks and is scanned
///    at [`ScanPriority::Anchor`] (so ahead of everything else); verifying it is fully scanned
///    proves the hash chain is intact from the bottom of the window through the anchor. The
///    caller computes this wallet-state-wide predicate once per call.
/// 3. **Witness region below the window is durable.** Either the note's shard is complete — so
///    it is witnessable from that shard's server-supplied subtree root regardless of gaps below
///    the window — or its stored floor reaches the bottom of the window: no `scan_queue` range
///    above `Scanned` separates `witness_anchor_stable` from the window. `pruning_region_gap_top`
///    (the top of the highest such gap, computed once per call) encodes that boundary; a note in
///    an incomplete (chain-tip) shard is durable iff its floor lies at or above it.
/// 4. **Anchor frontier available.** The wallet's shardtree must have a frontier at the chosen
///    anchor height (a checkpoint from which a witness against that anchor can be reconstructed).
///    Use [`anchor_frontier_available`] to compute this once per pool per call.
/// 5. **Confirmations met.** The note must have met its confirmations-policy threshold, which
///    also implies `note.mined_height <= anchor_height` (so the note exists in the tree at the
///    chosen anchor).
///
/// [`ScanPriority::Anchor`]: zcash_client_backend::data_api::scanning::ScanPriority::Anchor
pub(crate) fn is_note_spendable_at_anchor(
    witness_anchor_stable: Option<BlockHeight>,
    anchor_height: Option<BlockHeight>,
    prunable_window_scanned: bool,
    anchor_available: bool,
    confirmations_met: bool,
    shard_complete: bool,
    pruning_region_gap_top: Option<BlockHeight>,
) -> bool {
    let stored_at_or_below_chosen = witness_anchor_stable
        .zip(anchor_height)
        .is_some_and(|(stored, chosen)| stored <= chosen);

    // Check 3. A completed shard is witnessable via its server-supplied root regardless of gaps
    // below the window. An as-yet-incomplete (chain-tip) shard is witnessable only if no
    // unscanned range separates the note's stable floor from the bottom of the pruning window.
    let region_below_window_durable = shard_complete
        || match (pruning_region_gap_top, witness_anchor_stable) {
            (None, _) => true,
            (Some(gap_top), Some(stored)) => stored >= gap_top,
            (Some(_), None) => false,
        };

    stored_at_or_below_chosen
        && prunable_window_scanned
        && region_below_window_durable
        && anchor_available
        && confirmations_met
}

/// Returns the top of the highest unscanned region at or below the pruning floor: the maximum
/// `block_range_end` over `scan_queue` ranges above `Scanned` priority that begin at or below
/// the floor (`None` if there is none). See [`is_note_spendable_at_anchor`] check 3.
pub(crate) fn pruning_region_gap_top(
    conn: &Connection,
    chain_tip: BlockHeight,
) -> Result<Option<BlockHeight>, SqliteClientError> {
    let pruning_floor = u32::from(super::scanning::pruning_floor(chain_tip));
    let scanned = super::scanning::priority_code(&ScanPriority::Scanned);
    conn.query_row(
        "SELECT MAX(block_range_end) FROM scan_queue
         WHERE priority > :scanned AND block_range_start <= :pruning_floor",
        named_params![":scanned": scanned, ":pruning_floor": pruning_floor],
        |row| Ok(row.get::<_, Option<u32>>(0)?.map(BlockHeight::from)),
    )
    .map_err(SqliteClientError::from)
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
    protocol: ShieldedPool,
    to_spendable_note: F,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(
        &P,
        ShieldedPool,
        &Row,
    ) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
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
/// - The `to_received_note` function is expected to return `Ok(None)` in the case that spending
///   key details cannot be determined.
#[allow(clippy::too_many_arguments)]
pub(crate) fn select_unspent_notes<P: consensus::Parameters, F, Note>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
    protocol: ShieldedPool,
    to_received_note: F,
    note_request: NoteRequest,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(
        &P,
        ShieldedPool,
        &Row,
    ) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
{
    let TableConstants {
        table_prefix,
        output_index_col,
        note_reconstruction_cols,
        shard_height,
        ..
    } = table_constants::<SqliteClientError>(protocol)?;

    // Select all unspent notes belonging to the given account, ignoring dust notes.
    let mut stmt_select_notes = conn.prepare_cached(&format!(
        "SELECT
             rn.id AS id, t.txid, rn.{output_index_col},
             rn.diversifier, rn.value, {note_reconstruction_cols}, rn.commitment_tree_position,
             accounts.ufvk as ufvk, rn.recipient_key_scope,
             t.block AS mined_height,
             rn.witness_anchor_stable,
             shard.subtree_end_height AS shard_end_height,
             IFNULL(t.trust_status, 0) AS trust_status,
             MAX(tt.mined_height) AS max_shielding_input_height,
             MIN(IFNULL(tt.trust_status, 0)) AS min_shielding_input_trust
         FROM {table_prefix}_received_notes rn
         INNER JOIN accounts ON accounts.id = rn.account_id
         INNER JOIN transactions t ON t.id_tx = rn.transaction_id
         LEFT OUTER JOIN {table_prefix}_tree_shards shard
            ON shard.shard_index = (rn.commitment_tree_position >> {shard_height})
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
            let result_note = to_received_note(params, protocol, row)?;
            let witness_anchor_stable = row
                .get::<_, Option<u32>>("witness_anchor_stable")?
                .map(BlockHeight::from);
            let shard_complete = row.get::<_, Option<u32>>("shard_end_height")?.is_some();
            let tx_trust_status = row.get::<_, bool>("trust_status")?;
            let tx_shielding_inputs_trusted = row.get::<_, bool>("min_shielding_input_trust")?;

            Ok((
                result_note,
                witness_anchor_stable,
                tx_trust_status,
                tx_shielding_inputs_trusted,
                shard_complete,
            ))
        },
    )?;

    let chain_tip = super::chain_tip_height(conn)?;
    let prunable_window_scanned = match chain_tip {
        Some(h) => super::scanning::prunable_window_fully_scanned(conn, h)?,
        None => false,
    };
    // The top of the highest unscanned region at or below the pruning floor; bounds check 3
    // for notes in incomplete shards. Computed once per call alongside the window check.
    let pruning_gap_top = match chain_tip {
        Some(h) => pruning_region_gap_top(conn, h)?,
        None => None,
    };
    // Compute anchor_available once per call: it's a per-pool, per-anchor-height check.
    // For `NoteRequest::Unspent` (no anchor in the request) the spendability gate doesn't
    // run, so the value is irrelevant; default to `false` in that case.
    let anchor_available = match note_request.anchor_height() {
        Some(h) => anchor_frontier_available(conn, h, protocol)?,
        None => false,
    };

    row_results
        .map(|t| match t? {
            (
                Some(note),
                witness_anchor_stable,
                tx_trusted,
                tx_shielding_inputs_trusted,
                shard_complete,
            ) => {
                let confirmations_met = confirmations_policy.confirmations_until_spendable(
                    target_height,
                    PoolType::Shielded(protocol),
                    Some(note.spending_key_scope()),
                    note.mined_height(),
                    tx_trusted,
                    note.max_shielding_input_height(),
                    tx_shielding_inputs_trusted,
                ) == 0;

                let is_spendable = is_note_spendable_at_anchor(
                    witness_anchor_stable,
                    note_request.anchor_height(),
                    prunable_window_scanned,
                    anchor_available,
                    confirmations_met,
                    shard_complete,
                    pruning_gap_top,
                );

                match (note_request, is_spendable) {
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
    protocol: ShieldedPool,
    to_spendable_note: F,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(
        &P,
        ShieldedPool,
        &Row,
    ) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
{
    let TableConstants {
        table_prefix,
        output_index_col,
        note_reconstruction_cols,
        shard_height,
        ..
    } = table_constants::<SqliteClientError>(protocol)?;

    // The chain-tip pruning window must be fully scanned for any stabilized note to be
    // selectable; otherwise the anchor that note selection is about to use sits inside a
    // window with non-`Scanned` overlap, and witness construction can't reliably trust
    // its cap state. If `chain_tip_height` is unset there's no spendable balance anyway,
    // so treat the predicate as false.
    let chain_tip = super::chain_tip_height(conn)?;
    let prunable_window_scanned = match chain_tip {
        Some(h) => super::scanning::prunable_window_fully_scanned(conn, h)?,
        None => false,
    };
    // The top of the highest unscanned region at or below the pruning floor (see check 3 of
    // `is_note_spendable_at_anchor`); bound to `:pruning_region_gap_top` below. `NULL` when
    // there is no chain tip or no such range, in which case the predicate admits all notes.
    let pruning_gap_top = match chain_tip {
        Some(h) => pruning_region_gap_top(conn, h)?,
        None => None,
    };
    // Compute anchor_available once per call: a per-pool, per-anchor-height check on the
    // shardtree's cap state. The SQL pre-filter doesn't gate on this (it has no access to
    // the shardtree), so we must check it in Rust.
    let anchor_available = anchor_frontier_available(conn, anchor_height, protocol)?;

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
                 rn.witness_anchor_stable,
                 shard.subtree_end_height AS shard_end_height,
                 IFNULL(t.trust_status, 0) AS trust_status,
                 MAX(tt.mined_height) AS max_shielding_input_height,
                 MIN(IFNULL(tt.trust_status, 0)) AS min_shielding_input_trust
             FROM {table_prefix}_received_notes rn
             INNER JOIN accounts ON accounts.id = rn.account_id
             INNER JOIN transactions t ON t.id_tx = rn.transaction_id
             LEFT OUTER JOIN {table_prefix}_tree_shards shard
                ON shard.shard_index = (rn.commitment_tree_position >> {shard_height})
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
             -- The note must be mined at or below the anchor for the anchor's tree
             -- frontier to witness it
             AND t.block <= :anchor_height
             -- The stored floor must lie at or below the chosen anchor, and the chain-tip
             -- pruning window must have no range above `Scanned` priority (so the wallet has
             -- fully scanned through any disturbance left by truncate, rewind, or
             -- account-import, and the hash chain is intact through the anchor).
             AND rn.witness_anchor_stable IS NOT NULL
             AND rn.witness_anchor_stable <= :anchor_height
             AND :prunable_window_scanned = 1
             -- Check 3: a completed shard is witnessable via its server-supplied root; an
             -- incomplete (chain-tip) shard requires the stored floor to reach the bottom of
             -- the pruning window (no unscanned range separating it from the window).
             AND (shard.subtree_end_height IS NOT NULL
                  OR :pruning_region_gap_top IS NULL
                  OR rn.witness_anchor_stable >= :pruning_region_gap_top)
             AND rn.id NOT IN rarray(:exclude)
             AND rn.id NOT IN ({})
             GROUP BY rn.id
         )
         SELECT id, txid, {output_index_col},
                diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                ufvk, recipient_key_scope,
                mined_height, witness_anchor_stable, shard_end_height, trust_status,
                max_shielding_input_height, min_shielding_input_trust
         FROM eligible WHERE so_far < :target_value
         UNION
         SELECT id, txid, {output_index_col},
                diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                ufvk, recipient_key_scope,
                mined_height, witness_anchor_stable, shard_end_height, trust_status,
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

    // The chain-tip-pruning-window check is wallet-state-wide; if no chain tip is
    // recorded the SQL returns no rows (the `:prunable_window_scanned = 1` predicate
    // compares against 0).
    let notes = stmt_select_notes.query_and_then(
        named_params![
            ":account_uuid": account.0,
            ":anchor_height": &u32::from(anchor_height),
            ":target_height": &u32::from(target_height),
            ":target_value": &u64::from(target_value),
            ":exclude": &excluded_ptr,
            ":prunable_window_scanned": i64::from(prunable_window_scanned),
            ":pruning_region_gap_top": pruning_gap_top.map(u32::from),
            ":min_value": u64::from(zip317::MARGINAL_FEE)
        ],
        |row| {
            let witness_anchor_stable = row
                .get::<_, Option<u32>>("witness_anchor_stable")?
                .map(BlockHeight::from);
            let tx_trust_status = row.get::<_, bool>("trust_status")?;
            let max_shielding_input_height = row
                .get::<_, Option<u32>>("max_shielding_input_height")?
                .map(BlockHeight::from);
            let tx_shielding_inputs_trusted = row.get::<_, bool>("min_shielding_input_trust")?;
            let shard_complete = row.get::<_, Option<u32>>("shard_end_height")?.is_some();
            let note = to_spendable_note(params, protocol, row)?;

            Ok(note.map(|n| {
                (
                    n,
                    witness_anchor_stable,
                    tx_trust_status,
                    max_shielding_input_height,
                    tx_shielding_inputs_trusted,
                    shard_complete,
                )
            }))
        },
    )?;

    notes
        .filter_map(|result_maybe_note| {
            let result_note = result_maybe_note.transpose()?;
            result_note
                .map(
                    |(
                        note,
                        witness_anchor_stable,
                        tx_trusted,
                        max_shielding_input_height,
                        tx_shielding_inputs_trusted,
                        shard_complete,
                    )| {
                        let confirmations_met = confirmations_policy.confirmations_until_spendable(
                            target_height,
                            PoolType::Shielded(protocol),
                            Some(note.spending_key_scope()),
                            note.mined_height(),
                            tx_trusted,
                            max_shielding_input_height,
                            tx_shielding_inputs_trusted,
                        ) == 0;

                        // The SQL pre-filter already enforced `stored_at_or_below_chosen`,
                        // `prunable_window_scanned`, and check 3; the helper re-evaluates them
                        // defensively against the row's actual values and adds the
                        // `anchor_available` and confirmations gates.
                        is_note_spendable_at_anchor(
                            witness_anchor_stable,
                            Some(anchor_height),
                            prunable_window_scanned,
                            anchor_available,
                            confirmations_met,
                            shard_complete,
                            pruning_gap_top,
                        )
                        .then_some(note)
                    },
                )
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
    protocol: ShieldedPool,
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
    protocol: ShieldedPool,
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
                 AND rn.value > :min_value
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
    use zcash_protocol::{ShieldedPool, value::Zatoshis};

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
            ShieldedPool::Sapling,
            birthday_height,
            h,
        )
        .unwrap();

        assert_eq!(unspent_note_meta.len(), 1);
    }

    /// Check 3 of the spendability rule: a note in an incomplete (chain-tip) shard is durable
    /// only if its stored floor reaches the bottom of the pruning window (no unscanned region
    /// separates it), while a completed shard is durable regardless.
    #[test]
    fn is_note_spendable_check3_pruning_region_gate() {
        use zcash_protocol::consensus::BlockHeight;
        let h = BlockHeight::from;

        // All gates other than check 3 satisfied: floor <= anchor (110), window scanned,
        // anchor available, confirmations met. Vary only (shard_complete, gap_top, floor).
        let spendable = |shard_complete, gap_top: Option<u32>, floor: u32| {
            super::is_note_spendable_at_anchor(
                Some(h(floor)),
                Some(h(110)),
                true,
                true,
                true,
                shard_complete,
                gap_top.map(h),
            )
        };

        // No unscanned region below the window: any stable note is durable.
        assert!(spendable(false, None, 100));
        // Incomplete shard, floor at or above the top of the gap: durable.
        assert!(spendable(false, Some(100), 100));
        assert!(spendable(false, Some(90), 100));
        // Incomplete shard, floor below the gap top: NOT durable — the hole check 3 closes.
        assert!(!spendable(false, Some(101), 100));
        // A completed shard is witnessable via its server-supplied root regardless of the gap.
        assert!(spendable(true, Some(101), 100));

        // Check 3 passing does not override the other gates.
        let other = |window, anchor_avail, confs| {
            super::is_note_spendable_at_anchor(
                Some(h(100)),
                Some(h(110)),
                window,
                anchor_avail,
                confs,
                true,
                None,
            )
        };
        assert!(other(true, true, true));
        assert!(!other(false, true, true)); // window not fully scanned
        assert!(!other(true, false, true)); // anchor frontier unavailable
        assert!(!other(true, true, false)); // confirmations not met
    }

    /// `pruning_region_gap_top` returns the highest `block_range_end` among ranges above
    /// `Scanned` that begin at or below the pruning floor, and ignores ranges starting above it.
    #[test]
    fn pruning_region_gap_top_finds_highest_gap_below_floor() {
        use rusqlite::named_params;
        use zcash_client_backend::data_api::scanning::ScanPriority;
        use zcash_protocol::consensus::BlockHeight;

        use crate::{PRUNING_DEPTH, wallet::scanning::priority_code};

        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let conn = st.wallet().conn();

        let base: u32 = 2_000_000;
        let chain_tip = BlockHeight::from(base + PRUNING_DEPTH + 500);
        let floor = base + 500; // pruning_floor(chain_tip) = chain_tip - PRUNING_DEPTH

        conn.execute("DELETE FROM scan_queue", []).unwrap();
        let scanned = priority_code(&ScanPriority::Scanned);
        let historic = priority_code(&ScanPriority::Historic);
        conn.execute(
            "INSERT INTO scan_queue (block_range_start, block_range_end, priority) VALUES
                 (:s1, :e1, :scanned),    -- scanned, ignored
                 (:s2, :e2, :historic),   -- gap below the floor: counted
                 (:s3, :e3, :historic)    -- range above the floor: ignored (start > floor)",
            named_params![
                ":s1": base, ":e1": floor - 100, ":scanned": scanned,
                ":s2": floor - 100, ":e2": floor - 50, ":historic": historic,
                ":s3": floor + 10, ":e3": u32::from(chain_tip) + 1,
            ],
        )
        .unwrap();

        assert_eq!(
            super::pruning_region_gap_top(conn, chain_tip).unwrap(),
            Some(BlockHeight::from(floor - 50)),
        );

        // With no range above `Scanned` below the floor, the result is `None`.
        conn.execute("DELETE FROM scan_queue", []).unwrap();
        conn.execute(
            "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
             VALUES (:s, :e, :scanned)",
            named_params![":s": base, ":e": u32::from(chain_tip) + 1, ":scanned": scanned],
        )
        .unwrap();
        assert_eq!(
            super::pruning_region_gap_top(conn, chain_tip).unwrap(),
            None
        );
    }
}
