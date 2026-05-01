//! Functions common to Sapling and Orchard support in the wallet.

use incrementalmerkletree::Position;
use rusqlite::{Connection, Row, ToSql, named_params, types::Value};
use std::{num::NonZeroU64, rc::Rc};

use zcash_client_backend::{
    data_api::{
        MaxSpendMode, NoteFilter, NullifierQuery, PoolMeta, SAPLING_SHARD_HEIGHT, TargetValue,
        scanning::ScanPriority,
        wallet::{ConfirmationsPolicy, TargetHeight, input_selection::LockFilter},
    },
    wallet::ReceivedNote,
};
use zcash_primitives::transaction::{TxId, builder::default_tx_expiry_delta, fees::zip317};
use zcash_protocol::{
    PoolType, ShieldedPool,
    consensus::{self, BlockHeight, BranchId, UPGRADES_IN_ORDER},
    value::{BalanceError, Zatoshis},
};

use crate::{
    AccountUuid, ReceivedNoteId, SAPLING_TABLES_PREFIX,
    error::SqliteClientError,
    wallet::{
        get_anchor_height,
        locking::{
            locked_tier_expr, output_eligible_condition, overridable_owners_rarray,
            push_lock_params,
        },
        pool_code,
        scanning::priority_code,
    },
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

/// Generates an SQL expression for the default expiry delta of a transaction that targets the
/// height given by the SQL expression `height`.
///
/// The result is the [`default_tx_expiry_delta`] for the consensus branch that `params` puts in
/// effect at that height.
pub(crate) fn default_tx_expiry_delta_sql<P: consensus::Parameters>(
    params: &P,
    height: &str,
) -> String {
    let base_delta = default_tx_expiry_delta(BranchId::Sprout);

    let mut activation_heights = UPGRADES_IN_ORDER
        .iter()
        .filter_map(|nu| params.activation_height(*nu))
        .collect::<Vec<_>>();
    activation_heights.sort();
    activation_heights.dedup();

    // Each entry is a height at which the default delta changes, and the delta from that height.
    let mut delta_changes = vec![];
    let mut current_delta = base_delta;
    for activation_height in activation_heights {
        let delta = default_tx_expiry_delta(BranchId::for_height(params, activation_height));
        if delta != current_delta {
            delta_changes.push((activation_height, delta));
            current_delta = delta;
        }
    }

    if delta_changes.is_empty() {
        base_delta.to_string()
    } else {
        let arms = delta_changes
            .iter()
            .rev()
            .map(|(activation_height, delta)| {
                format!(
                    "WHEN {height} >= {} THEN {delta}",
                    u32::from(*activation_height)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        format!("(CASE {arms} ELSE {base_delta} END)")
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
/// be treated as unexpired _only_ if we observed it within the default expiry delta for the height
/// at which we first observed it, guessing that the wallet creating the transaction used that
/// default. If our guess is wrong (and the wallet used a larger expiry delta or disabled expiry),
/// then the transaction will be treated as unexpired when it shouldn't be for as long as it takes
/// this wallet to either observe the transaction being mined, or enhance it to learn its expiry
/// height.
pub(crate) fn tx_unexpired_condition<P: consensus::Parameters>(params: &P, tx: &str) -> String {
    let default_expiry_delta =
        default_tx_expiry_delta_sql(params, &format!("{tx}.min_observed_height"));
    format!(
        r#"
        {tx}.mined_height < :target_height  -- the transaction is mined
        OR {tx}.expiry_height = 0  -- the tx will not expire
        OR {tx}.expiry_height >= :target_height  -- the tx is unexpired
        OR (
            {tx}.expiry_height IS NULL -- the expiry height is unknown
            AND {tx}.min_observed_height + {default_expiry_delta} >= :target_height
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
pub(crate) fn spent_notes_clause<P: consensus::Parameters>(
    params: &P,
    table_prefix: &str,
) -> String {
    format!(
        r#"
        SELECT rns.{table_prefix}_received_note_id
        FROM {table_prefix}_received_note_spends rns
        JOIN transactions stx ON stx.id_tx = rns.transaction_id
        WHERE {}
        "#,
        tx_unexpired_condition(params, "stx")
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn get_spendable_note<P: consensus::Parameters, F, Note>(
    conn: &Connection,
    params: &P,
    txid: &TxId,
    index: u32,
    protocol: ShieldedPool,
    target_height: TargetHeight,
    to_spendable_note: F,
    lock_filter: LockFilter<'_>,
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

    let txid_bytes = txid.as_ref();
    let target_height_arg = u32::from(target_height);
    let overridable_owners = overridable_owners_rarray(lock_filter);
    let mut sql_params: Vec<(&str, &dyn ToSql)> = vec![
        (":txid", &txid_bytes),
        (":output_index", &index),
        (":target_height", &target_height_arg),
    ];
    push_lock_params(&mut sql_params, lock_filter, &overridable_owners);

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
             AND rn.id NOT IN ({}) -- the note is unspent
             AND ({}) -- the note is eligible under the lock filter
             GROUP BY rn.id",
            spent_notes_clause(params, table_prefix),
            output_eligible_condition(lock_filter, "rn"),
        ),
        &sql_params[..],
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
/// anchor as unavailable for spendability purposes. A pool that this build does not support
/// has no tree, so its anchor is unavailable.
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
        ShieldedPool::Orchard | ShieldedPool::Ironwood => return Ok(false),
    };
    Ok(
        super::commitment_tree::get_checkpoint(conn, table_prefix, anchor_height)
            .map_err(|e| {
                SqliteClientError::CommitmentTree(shardtree::error::ShardTreeError::Storage(e))
            })?
            .is_some(),
    )
}

/// Encodes the wallet's spendability rule for a single note at the chosen anchor height `a`,
/// given the predicates that compose it. All must hold for the note to be spendable.
///
/// 1. **Settled height set.** `witness_settled_height` (`s`) is the height through which the
///    note's witness data is settled: every block after the note's own block, through `s`, has
///    been scanned. For a note in a completed shard it is the shard's end height; for a note in
///    the open shard it is the pruning floor as of the last scan that reached the tip, never
///    below the note's own height.
/// 2. **Pruning window fully scanned.** No `scan_queue` range above `Scanned` priority overlaps
///    the chain-tip pruning window. The window is at most `PRUNING_DEPTH` blocks and is scanned
///    at [`ScanPriority::Anchor`], ahead of every range except `Verify` ranges; verifying it is
///    fully scanned proves the hash chain is intact from the bottom of the window through the
///    anchor. The caller computes this wallet-state-wide predicate once per call.
/// 3. **Witness region scanned.** The note's witness at `a` needs every leaf to the note's right
///    within its shard, up to the end of block `min(a, E)`, where `E` is the shard's end height
///    (unbounded while the shard is open). The frontier inserted when the note's block was
///    scanned supplies the leaves to its left. If `s >= min(a, E)`, the settled height covers
///    this region; otherwise no `scan_queue` range above `Scanned` priority may overlap
///    `(s, min(a, E)]`. Use [`note_witness_region_scanned_condition`] to compute this in SQL.
/// 4. **Anchor frontier available.** The wallet's shardtree must have a frontier at the chosen
///    anchor height (a checkpoint from which a witness against that anchor can be reconstructed).
///    Use [`anchor_frontier_available`] to compute this once per pool per call.
/// 5. **Confirmations met.** The note must have met its confirmations-policy threshold, which
///    also implies `note.mined_height <= anchor_height` (so the note exists in the tree at the
///    chosen anchor).
///
/// [`ScanPriority::Anchor`]: zcash_client_backend::data_api::scanning::ScanPriority::Anchor
pub(crate) fn is_note_spendable_at_anchor(
    witness_settled_height: Option<BlockHeight>,
    prunable_window_scanned: bool,
    witness_region_scanned: bool,
    anchor_available: bool,
    confirmations_met: bool,
) -> bool {
    witness_settled_height.is_some()
        && prunable_window_scanned
        && witness_region_scanned
        && anchor_available
        && confirmations_met
}

/// Returns the SQL condition for check 3 of [`is_note_spendable_at_anchor`], over a
/// received-notes row `rn` and its shard row `shard` (all columns `NULL` when the wallet holds no
/// row for the note's shard), at the anchor height bound to `:anchor_height`: either the note's
/// settled height covers the blocks that its witness at the anchor needs, or no `scan_queue`
/// range above `Scanned` priority overlaps the blocks that it does not cover.
///
/// The condition holds when `rn.witness_settled_height` or `:anchor_height` is `NULL`; check 1,
/// and the absence of an anchor, decide those cases.
pub(crate) fn note_witness_region_scanned_condition() -> String {
    let region_end = "MIN(:anchor_height, IFNULL(shard.subtree_end_height, :anchor_height))";
    format!(
        "(rn.witness_settled_height >= {region_end}
          OR NOT EXISTS (
              SELECT 1 FROM scan_queue q
              WHERE q.priority > {scanned}
                AND q.block_range_end > rn.witness_settled_height + 1
                AND q.block_range_start <= {region_end}
          ))",
        scanned = priority_code(&ScanPriority::Scanned),
    )
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
    lock_filter: LockFilter<'_>,
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
            lock_filter,
        ),
        TargetValue::AtLeast(zats) => select_spendable_notes_matching_value(
            conn,
            params,
            account,
            zats,
            ValueSelection::Accumulate,
            target_height,
            anchor_height,
            confirmations_policy,
            exclude,
            protocol,
            &to_spendable_note,
            lock_filter,
        ),
    }
}

/// Selects the single OLDEST spendable note of the given protocol whose value alone is at least
/// `value`, or `None` when no single eligible note covers it. Age is the note's commitment tree
/// position, which is assigned in strict chain order.
#[allow(clippy::too_many_arguments)]
pub(crate) fn select_single_spendable_note<P: consensus::Parameters, F, Note>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    value: Zatoshis,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
    protocol: ShieldedPool,
    to_spendable_note: F,
    lock_filter: LockFilter<'_>,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
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
        return Ok(None);
    };

    Ok(select_spendable_notes_matching_value(
        conn,
        params,
        account,
        value,
        ValueSelection::SingleCovering,
        target_height,
        anchor_height,
        confirmations_policy,
        exclude,
        protocol,
        &to_spendable_note,
        lock_filter,
    )?
    .into_iter()
    .next())
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
    lock_filter: LockFilter<'_>,
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
             rn.witness_settled_height,
             {} AS witness_region_scanned,
             IFNULL(t.trust_status, 0) AS trust_status,
             MAX(tt.mined_height) AS max_shielding_input_height,
             MIN(IFNULL(tt.trust_status, 0)) AS min_shielding_input_trust
         FROM {table_prefix}_received_notes rn
         INNER JOIN accounts ON accounts.id = rn.account_id
         INNER JOIN transactions t ON t.id_tx = rn.transaction_id
         LEFT OUTER JOIN {table_prefix}_tree_shards shard
            ON shard.shard_index = rn.commitment_tree_position >> {shard_height}
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
         AND ({}) -- the note is eligible under the lock filter
         GROUP BY rn.id",
        note_witness_region_scanned_condition(),
        tx_unexpired_condition(params, "t"),
        spent_notes_clause(params, table_prefix),
        output_eligible_condition(lock_filter, "rn")
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

    let account_uuid = account.0;
    let target_height_arg = u32::from(target_height);
    let anchor_height_arg = note_request.anchor_height().map(u32::from);
    let min_value = u64::from(zip317::MARGINAL_FEE);
    let overridable_owners = overridable_owners_rarray(lock_filter);
    let mut sql_params: Vec<(&str, &dyn ToSql)> = vec![
        (":account_uuid", &account_uuid),
        (":target_height", &target_height_arg),
        (":anchor_height", &anchor_height_arg),
        (":exclude", &excluded_ptr),
        (":min_value", &min_value),
    ];
    push_lock_params(&mut sql_params, lock_filter, &overridable_owners);

    let row_results = stmt_select_notes.query_and_then(
        &sql_params[..],
        |row| -> Result<_, SqliteClientError> {
            let result_note = to_received_note(params, protocol, row)?;
            let witness_settled_height = row
                .get::<_, Option<u32>>("witness_settled_height")?
                .map(BlockHeight::from);
            let witness_region_scanned = row
                .get::<_, Option<bool>>("witness_region_scanned")?
                .unwrap_or(false);
            let tx_trust_status = row.get::<_, bool>("trust_status")?;
            let tx_shielding_inputs_trusted = row.get::<_, bool>("min_shielding_input_trust")?;

            Ok((
                result_note,
                witness_settled_height,
                tx_trust_status,
                tx_shielding_inputs_trusted,
                witness_region_scanned,
            ))
        },
    )?;

    let chain_tip = super::chain_tip_height(conn)?;
    let prunable_window_scanned = match chain_tip {
        Some(h) => super::scanning::prunable_window_fully_scanned(conn, h)?,
        None => false,
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
                witness_settled_height,
                tx_trusted,
                tx_shielding_inputs_trusted,
                witness_region_scanned,
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
                    witness_settled_height,
                    prunable_window_scanned,
                    witness_region_scanned,
                    anchor_available,
                    confirmations_met,
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

/// The shape of a value-targeted note selection: accumulate the oldest notes toward the target,
/// or draw only the single oldest note that covers it alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueSelection {
    /// Accumulate the oldest eligible notes until the target value is covered.
    Accumulate,
    /// Select only the oldest eligible notes whose individual values cover the target alone,
    /// oldest first.
    SingleCovering,
}

/// Selects the set of spendable notes whose sum will be equal or greater that the
/// specified ``target_value`` in Zatoshis from the specified shielded protocols excluding
/// the ones present in the ``exclude`` slice.
///
/// Under [`ValueSelection::SingleCovering`], instead returns the notes whose individual value
/// covers ``target_value`` alone, oldest first; callers take the head.
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
    selection: ValueSelection,
    target_height: TargetHeight,
    anchor_height: BlockHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
    protocol: ShieldedPool,
    to_spendable_note: F,
    lock_filter: LockFilter<'_>,
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
    //
    // AGE is the note's commitment tree position: positions are assigned in strict chain
    // order, so ordering by position is ordering by the age of the note on chain. The row
    // id is NOT a usable proxy for age — ids are assigned in SCAN order, and priority
    // scanning visits recent blocks before back-filling history, so a restored wallet's
    // newest notes carry its lowest ids.
    //
    // A `LockFilter::Policy` that prefers one lock tier (`PreferUnlocked`/`PreferLocked`)
    // accumulates the running sum in tier order (via the leading window `ORDER BY` key) so
    // that the preferred tier is drawn upon first; age order is retained as the secondary
    // key so that within each tier the oldest notes are still selected first. Because the
    // window order need not match the CTE's physical output order, the threshold-crossing
    // note is chosen as the note with the smallest running sum at or above the target
    // (`ORDER BY so_far`).
    let tier = locked_tier_expr(lock_filter, "rn");
    let window_frame = match &tier {
        Some((expr, direction)) => format!(
            "ORDER BY {expr} {direction}, rn.commitment_tree_position ROWS UNBOUNDED PRECEDING"
        ),
        None => "ORDER BY rn.commitment_tree_position ROWS UNBOUNDED PRECEDING".to_string(),
    };
    // The single-covering tail selects FROM the CTE, where `rn` is out of scope, so the tier
    // expression is materialized as a CTE column with the direction applied at the ordering
    // site; a constant stands in when the lock filter admits only one tier and no preference
    // applies.
    let (tier_column, tier_direction) = tier
        .as_ref()
        .map(|(expr, direction)| (expr.as_str(), *direction))
        .unwrap_or(("0", "ASC"));
    let crossing_note_subquery =
        "SELECT * from eligible WHERE so_far >= :target_value ORDER BY so_far LIMIT 1";
    let result_columns = format!(
        "id, txid, {output_index_col},
                diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                ufvk, recipient_key_scope,
                mined_height, witness_settled_height, witness_region_scanned, trust_status,
                max_shielding_input_height, min_shielding_input_trust"
    );
    // The `eligible` CTE is shared; only the selection over it differs by shape. Accumulation
    // takes every note below the running-sum threshold plus the threshold-crossing note;
    // single-covering takes the individually sufficient notes ordered by lock tier first and
    // age second — the same key order the accumulation window uses, so a `PreferUnlocked` or
    // `PreferLocked` caller draws its preferred tier before an older note of the other tier —
    // and relies on the caller to take the head (the Rust-side confirmations filter below may
    // drop leading rows, so the limit cannot be applied in SQL).
    let selection_tail = match selection {
        ValueSelection::Accumulate => format!(
            "SELECT {result_columns}
         FROM eligible WHERE so_far < :target_value
         UNION
         SELECT {result_columns}
         FROM ({crossing_note_subquery})"
        ),
        ValueSelection::SingleCovering => format!(
            "SELECT {result_columns}
         FROM eligible WHERE value >= :target_value
         ORDER BY lock_tier {tier_direction}, commitment_tree_position"
        ),
    };
    let eligible_condition = output_eligible_condition(lock_filter, "rn");
    let witness_region_scanned = note_witness_region_scanned_condition();
    let mut stmt_select_notes = conn.prepare_cached(&format!(
        "WITH eligible AS (
             SELECT
                 rn.id AS id, t.txid, rn.{output_index_col},
                 rn.diversifier, rn.value,
                 {note_reconstruction_cols}, rn.commitment_tree_position,
                 {tier_column} AS lock_tier,
                 SUM(value) OVER ({window_frame}) AS so_far,
                 accounts.ufvk as ufvk, rn.recipient_key_scope,
                 t.block AS mined_height,
                 rn.witness_settled_height,
                 {witness_region_scanned} AS witness_region_scanned,
                 IFNULL(t.trust_status, 0) AS trust_status,
                 MAX(tt.mined_height) AS max_shielding_input_height,
                 MIN(IFNULL(tt.trust_status, 0)) AS min_shielding_input_trust
             FROM {table_prefix}_received_notes rn
             INNER JOIN accounts ON accounts.id = rn.account_id
             INNER JOIN transactions t ON t.id_tx = rn.transaction_id
             LEFT OUTER JOIN {table_prefix}_tree_shards shard
                ON shard.shard_index = rn.commitment_tree_position >> {shard_height}
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
             -- Checks 1 to 3 of `is_note_spendable_at_anchor`: the note's settled height is
             -- set, the chain-tip pruning window has no range above `Scanned` priority, and the
             -- blocks that the note's witness at the anchor needs are scanned.
             AND rn.witness_settled_height IS NOT NULL
             AND :prunable_window_scanned = 1
             AND {witness_region_scanned}
             AND rn.id NOT IN rarray(:exclude)
             AND rn.id NOT IN ({}) -- the note is not spent
             AND ({eligible_condition}) -- the note is eligible under the lock filter
             GROUP BY rn.id
         )
         {selection_tail}",
        spent_notes_clause(params, table_prefix),
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
    let account_uuid = account.0;
    let anchor_height_arg = u32::from(anchor_height);
    let target_height_arg = u32::from(target_height);
    let target_value_arg = u64::from(target_value);
    let prunable_window_scanned_arg = i64::from(prunable_window_scanned);
    let min_value = u64::from(zip317::MARGINAL_FEE);
    let overridable_owners = overridable_owners_rarray(lock_filter);
    let mut sql_params: Vec<(&str, &dyn ToSql)> = vec![
        (":account_uuid", &account_uuid),
        (":anchor_height", &anchor_height_arg),
        (":target_height", &target_height_arg),
        (":target_value", &target_value_arg),
        (":exclude", &excluded_ptr),
        (":prunable_window_scanned", &prunable_window_scanned_arg),
        (":min_value", &min_value),
    ];
    push_lock_params(&mut sql_params, lock_filter, &overridable_owners);

    let notes = stmt_select_notes.query_and_then(&sql_params[..], |row| {
        let witness_settled_height = row
            .get::<_, Option<u32>>("witness_settled_height")?
            .map(BlockHeight::from);
        let tx_trust_status = row.get::<_, bool>("trust_status")?;
        let max_shielding_input_height = row
            .get::<_, Option<u32>>("max_shielding_input_height")?
            .map(BlockHeight::from);
        let tx_shielding_inputs_trusted = row.get::<_, bool>("min_shielding_input_trust")?;
        let witness_region_scanned = row
            .get::<_, Option<bool>>("witness_region_scanned")?
            .unwrap_or(false);
        let note = to_spendable_note(params, protocol, row)?;

        Ok(note.map(|n| {
            (
                n,
                witness_settled_height,
                tx_trust_status,
                max_shielding_input_height,
                tx_shielding_inputs_trusted,
                witness_region_scanned,
            )
        }))
    })?;

    notes
        .filter_map(|result_maybe_note| {
            let result_note = result_maybe_note.transpose()?;
            result_note
                .map(
                    |(
                        note,
                        witness_settled_height,
                        tx_trusted,
                        max_shielding_input_height,
                        tx_shielding_inputs_trusted,
                        witness_region_scanned,
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

                        // The SQL pre-filter already enforced checks 1 to 3; the helper adds the
                        // `anchor_available` and confirmations gates.
                        is_note_spendable_at_anchor(
                            witness_settled_height,
                            prunable_window_scanned,
                            witness_region_scanned,
                            anchor_available,
                            confirmations_met,
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

pub(crate) fn select_unspent_note_meta<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
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
         spent_notes_clause(params, table_prefix)
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn unspent_notes_meta<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    protocol: ShieldedPool,
    target_height: TargetHeight,
    account: AccountUuid,
    filter: &NoteFilter,
    exclude: &[ReceivedNoteId],
    lock_filter: LockFilter<'_>,
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

    // This is an aggregation, not a value-target selection, so no tier ordering applies; only the
    // eligibility filter (Part A) is imposed.
    let eligible_condition = output_eligible_condition(lock_filter, "rn");
    let overridable_owners = overridable_owners_rarray(lock_filter);
    let account_uuid = account.0;
    let target_height_arg = u32::from(target_height);

    let run_selection = |min_value: Zatoshis| {
        let min_value = u64::from(min_value);
        let mut sql_params: Vec<(&str, &dyn ToSql)> = vec![
            (":account_uuid", &account_uuid),
            (":min_value", &min_value),
            (":exclude", &excluded_ptr),
            (":target_height", &target_height_arg),
        ];
        push_lock_params(&mut sql_params, lock_filter, &overridable_owners);
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
                 AND rn.id NOT IN ({}) -- the note is unspent
                 AND ({eligible_condition}) -- the note is eligible under the lock filter",
                spent_notes_clause(params, table_prefix),
            ),
            &sql_params[..],
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
    fn min_note_value<P: consensus::Parameters>(
        conn: &rusqlite::Connection,
        params: &P,
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
                        tx_unexpired_condition(params, "stx")
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
                let a_min_value = min_note_value(conn, params, account, a.as_ref(), target_height)?;
                let b_min_value = min_note_value(conn, params, account, b.as_ref(), target_height)?;
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
                let cond =
                    min_note_value(conn, params, account, condition.as_ref(), target_height)?;
                if cond.is_none() {
                    min_note_value(conn, params, account, fallback, target_height)
                } else {
                    Ok(cond)
                }
            }
        }
    }

    // TODO: Simplify the query before executing it. Not worrying about this now because queries
    // will be developer-configured, not end-user defined.
    if let Some(min_value) = min_note_value(conn, params, account, filter, target_height)? {
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
    use rusqlite::{Connection, named_params};
    use zcash_client_backend::data_api::{
        scanning::ScanPriority,
        testing::{AddressType, TestBuilder, pool::ShieldedPoolTester, sapling::SaplingPoolTester},
    };
    use zcash_primitives::{block::BlockHash, transaction::builder::default_tx_expiry_delta};
    use zcash_protocol::{
        ShieldedPool,
        consensus::{BlockHeight, BranchId},
        local_consensus::LocalNetwork,
        value::Zatoshis,
    };

    use crate::{
        testing::{BlockCache, db::TestDbFactory},
        wallet::scanning::priority_code,
    };

    use super::default_tx_expiry_delta_sql;

    /// The highest height at which the SQL expression is compared against the default delta.
    /// It lies above every activation height that the test networks set.
    const LAST_CHECKED_HEIGHT: u32 = 20;

    fn local_network(nu7: Option<BlockHeight>) -> LocalNetwork {
        LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(2)),
            blossom: Some(BlockHeight::from_u32(3)),
            heartwood: Some(BlockHeight::from_u32(4)),
            canopy: Some(BlockHeight::from_u32(5)),
            nu5: Some(BlockHeight::from_u32(6)),
            nu6: Some(BlockHeight::from_u32(7)),
            nu6_1: Some(BlockHeight::from_u32(8)),
            nu6_2: Some(BlockHeight::from_u32(9)),
            nu6_3: Some(BlockHeight::from_u32(10)),
            nu7,
            #[cfg(zcash_unstable = "nutachyon")]
            nu_tachyon: None,
        }
    }

    #[test]
    fn default_tx_expiry_delta_sql_matches_default_tx_expiry_delta() {
        let conn = Connection::open_in_memory().unwrap();
        for params in [
            local_network(Some(BlockHeight::from_u32(11))),
            local_network(None),
        ] {
            let expr = default_tx_expiry_delta_sql(&params, ":height");
            for height in 0..=LAST_CHECKED_HEIGHT {
                let sql_delta: u32 = conn
                    .query_row(
                        &format!("SELECT {expr}"),
                        rusqlite::named_params![":height": height],
                        |row| row.get(0),
                    )
                    .unwrap();
                let height = BlockHeight::from_u32(height);
                assert_eq!(
                    sql_delta,
                    default_tx_expiry_delta(BranchId::for_height(&params, height)),
                    "default expiry delta at height {height:?}",
                );
            }
        }
    }

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
            st.network(),
            ShieldedPool::Sapling,
            birthday_height,
            h,
        )
        .unwrap();

        assert_eq!(unspent_note_meta.len(), 1);
    }

    /// A note is spendable only when every check of the spendability rule holds.
    #[test]
    fn is_note_spendable_requires_every_check() {
        let settled = Some(BlockHeight::from(100));
        let spendable = |settled, window, region, anchor_available, confirmations| {
            super::is_note_spendable_at_anchor(
                settled,
                window,
                region,
                anchor_available,
                confirmations,
            )
        };
        assert!(spendable(settled, true, true, true, true));
        assert!(!spendable(None, true, true, true, true)); // no settled height
        assert!(!spendable(settled, false, true, true, true)); // window not fully scanned
        assert!(!spendable(settled, true, false, true, true)); // witness region not scanned
        assert!(!spendable(settled, true, true, false, true)); // anchor frontier unavailable
        assert!(!spendable(settled, true, true, true, false)); // confirmations not met
    }

    /// Check 3 holds when the note's settled height `s` reaches `min(a, E)`, and otherwise when
    /// no range above `Scanned` overlaps `(s, min(a, E)]`.
    #[test]
    fn note_witness_region_scanned_condition_checks_only_the_uncovered_region() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let conn = st.wallet().conn();

        // The scan queue holds one unscanned range, `[gap_start, gap_end)`.
        let base: u32 = 2_000_000;
        let gap_start = base + 100;
        let gap_end = base + 120;
        let tip_end = base + 1_000;
        let scanned = priority_code(&ScanPriority::Scanned);
        let historic = priority_code(&ScanPriority::Historic);
        conn.execute("DELETE FROM scan_queue", []).unwrap();
        conn.execute(
            "INSERT INTO scan_queue (block_range_start, block_range_end, priority) VALUES
                 (:base, :gap_start, :scanned),
                 (:gap_start, :gap_end, :historic),
                 (:gap_end, :tip_end, :scanned)",
            named_params![
                ":base": base,
                ":gap_start": gap_start,
                ":gap_end": gap_end,
                ":tip_end": tip_end,
                ":scanned": scanned,
                ":historic": historic,
            ],
        )
        .unwrap();

        let region_scanned = |settled: u32, shard_end: Option<u32>, anchor: u32| -> bool {
            conn.query_row(
                &format!(
                    "SELECT {} FROM (SELECT :settled AS witness_settled_height) rn
                     LEFT OUTER JOIN (SELECT :shard_end AS subtree_end_height) shard",
                    super::note_witness_region_scanned_condition()
                ),
                named_params![
                    ":settled": settled,
                    ":shard_end": shard_end,
                    ":anchor_height": anchor,
                ],
                |row| row.get(0),
            )
            .unwrap()
        };

        let anchor = base + 900;
        // A completed shard that ends below the gap: the gap is outside the region.
        assert!(region_scanned(base + 50, Some(base + 90), anchor));
        // A completed shard whose remaining region `(s, E]` crosses the gap.
        assert!(!region_scanned(base + 50, Some(base + 150), anchor));
        // The settled height already reaches the shard's end, above the gap.
        assert!(region_scanned(base + 150, Some(base + 150), anchor));
        // An open shard: the region `(s, a]` crosses the gap, unless `s` is above it.
        assert!(!region_scanned(base + 50, None, anchor));
        assert!(region_scanned(base + 130, None, anchor));
        // A settled height at or above the anchor covers the region even though the gap range
        // spans heights on both sides of the anchor.
        assert!(region_scanned(gap_end, None, gap_start + 5));
    }
}
