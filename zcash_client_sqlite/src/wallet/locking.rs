//! SQLite storage layer for output locking.
//!
//! This module implements the storage side of the locking contracts defined in
//! [`zcash_client_backend::data_api::locking`]: the lock-mutation statements
//! backing [`OutputLockStore::lock_outputs`], [`OutputLockStore::unlock_output`], and
//! [`OutputLockStore::clear_locked_outputs`], the unlock-on-store path, and the SQL
//! fragments through which the spendable-output queries apply a
//! [`LockFilter`]. See the backend module's documentation for the semantic
//! invariants (the locked/eligible complement, the acquisition rules, and the
//! release paths) that these implementations realize.
//!
//! [`OutputLockStore::lock_outputs`]: zcash_client_backend::data_api::OutputLockStore::lock_outputs
//! [`OutputLockStore::unlock_output`]: zcash_client_backend::data_api::OutputLockStore::unlock_output
//! [`OutputLockStore::clear_locked_outputs`]: zcash_client_backend::data_api::OutputLockStore::clear_locked_outputs

use std::rc::Rc;

use rusqlite::{ToSql, named_params, types::Value};

use zcash_client_backend::{
    data_api::wallet::{TargetHeight, input_selection::LockFilter},
    wallet::{LockOwner, OutputRef},
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{PoolType, ShieldedPool, consensus::BlockHeight};

use crate::{AccountUuid, TxRef, error::SqliteClientError, wallet::chain_tip_height};

#[cfg(any(test, feature = "test-dependencies"))]
pub(crate) fn get_locked_outputs(
    conn: &rusqlite::Connection,
    account: AccountUuid,
) -> Result<Vec<OutputRef>, SqliteClientError> {
    let chain_tip = chain_tip_height(conn)?
        .map(u32::from)
        .ok_or(SqliteClientError::ChainHeightUnknown)?;

    let mut result = Vec::new();

    // `lock_expiry_height > chain_tip` is `lock_expiry_height >= chain_tip + 1`, i.e. the
    // locked-balance condition evaluated at the standard target height.
    for pool in [
        PoolType::SAPLING,
        PoolType::ORCHARD,
        PoolType::IRONWOOD,
        PoolType::TRANSPARENT,
    ] {
        let (table, index_col) = received_outputs_table(pool);
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT t.txid, rn.{index_col}
             FROM {table} rn
             JOIN transactions t ON t.id_tx = rn.transaction_id
             JOIN accounts a ON a.id = rn.account_id
             WHERE rn.lock_expiry_height > :chain_tip
             AND a.uuid = :account_uuid"
        ))?;
        let rows = stmt.query_map(
            named_params![
                ":account_uuid": account.0,
                ":chain_tip": chain_tip
            ],
            |row| {
                let txid: [u8; 32] = row.get(0)?;
                let output_index: u32 = row.get(1)?;
                Ok(OutputRef::new(TxId::from_bytes(txid), pool, output_index))
            },
        )?;
        for row in rows {
            result.push(row?);
        }
    }

    Ok(result)
}

pub(crate) fn lock_outputs(
    conn: &rusqlite::Transaction,
    outputs: &[OutputRef],
    owner: LockOwner,
    lock_expiry_height: BlockHeight,
) -> Result<usize, crate::error::LockError> {
    // When the chain tip is unknown, `:chain_tip` binds to SQL NULL and the
    // `lock_expiry_height <= :chain_tip` clause evaluates to NULL (falsy). In that case only
    // outputs that are not already locked (`lock_expiry_height IS NULL`) or whose lock is
    // already held by the requesting owner can be locked; an existing lock cannot be treated
    // as expired because we have no height against which to judge expiry. This is the
    // conservative choice: locking generally requires a synced wallet.
    let chain_tip = chain_tip_height(conn)?.map(u32::from);

    let mut rows_updated = 0;
    for output in outputs {
        let (table, index_col) = received_outputs_table(output.pool());
        let updated = conn
            .execute(
                &format!(
                    "UPDATE {table} SET
                        lock_expiry_height = :expiry_height,
                        lock_owner = :owner
                    WHERE {index_col} = :idx
                    AND transaction_id = (SELECT id_tx FROM transactions WHERE txid = :txid)
                    AND ({})",
                    output_lockable_condition(),
                ),
                named_params![
                    ":expiry_height": u32::from(lock_expiry_height),
                    ":owner": owner.as_bytes(),
                    ":idx": output.output_index(),
                    ":txid": output.txid().as_ref(),
                    ":chain_tip": chain_tip
                ],
            )
            .map_err(crate::error::LockError::Storage)?;

        if updated == 0 {
            return Err(crate::error::LockError::LockFailure(*output));
        } else {
            rows_updated += updated;
        }
    }

    Ok(rows_updated)
}

/// Returns the received notes/outputs table and its output-index column for the given pool.
fn received_outputs_table(pool: PoolType) -> (&'static str, &'static str) {
    match pool {
        PoolType::Shielded(ShieldedPool::Sapling) => ("sapling_received_notes", "output_index"),
        PoolType::Shielded(ShieldedPool::Orchard) => ("orchard_received_notes", "action_index"),
        PoolType::Shielded(ShieldedPool::Ironwood) => ("ironwood_received_notes", "action_index"),
        PoolType::Transparent => ("transparent_received_outputs", "output_index"),
    }
}

pub(crate) fn unlock_output(
    conn: &rusqlite::Transaction,
    output: &OutputRef,
    owner: LockOwner,
) -> Result<bool, SqliteClientError> {
    let (table, index_col) = received_outputs_table(output.pool());
    // Unlocking is scoped to the owner: a lock held by a different owner is left in place, so
    // one flow cannot accidentally release another's locks. An expired lock held by the owner
    // is still cleared (and reported as such), tidying the stale row.
    let rows_updated = conn.execute(
        &format!(
            "UPDATE {table} SET lock_expiry_height = NULL, lock_owner = NULL
             WHERE {index_col} = :idx
               AND transaction_id = (SELECT id_tx FROM transactions WHERE txid = :txid)
               AND lock_owner = :owner"
        ),
        named_params![
            ":idx": output.output_index(),
            ":txid": output.txid().as_ref(),
            ":owner": owner.as_bytes(),
        ],
    )?;
    Ok(rows_updated > 0)
}

/// Unlocks every currently-locked output belonging to the given account, across all pools,
/// regardless of lock expiry height. Returns the total number of outputs unlocked.
///
/// This is the storage-layer implementation of [`OutputLockStore::clear_locked_outputs`], and is
/// intended as a recovery mechanism for callers that have lost track of their in-flight proposals.
///
/// [`OutputLockStore::clear_locked_outputs`]: zcash_client_backend::data_api::OutputLockStore::clear_locked_outputs
pub(crate) fn clear_locked_outputs(
    conn: &rusqlite::Transaction,
    account: AccountUuid,
) -> Result<usize, SqliteClientError> {
    let mut rows_updated = 0;
    for table in [
        "sapling_received_notes",
        "orchard_received_notes",
        "ironwood_received_notes",
        "transparent_received_outputs",
    ] {
        rows_updated += conn.execute(
            &format!(
                "UPDATE {table} SET lock_expiry_height = NULL, lock_owner = NULL
                 WHERE lock_expiry_height IS NOT NULL
                   AND account_id = (SELECT id FROM accounts WHERE uuid = :account_uuid)"
            ),
            named_params![":account_uuid": account.0],
        )?;
    }

    Ok(rows_updated)
}

/// Unlocks all notes that have been recorded as spent by the given transaction.
/// This is called after marking notes as spent in `store_transaction_to_be_sent`,
/// since the spend records now prevent them from being selected by subsequent proposals.
pub(crate) fn unlock_spent_notes(
    conn: &rusqlite::Connection,
    tx_ref: TxRef,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE sapling_received_notes SET lock_expiry_height = NULL, lock_owner = NULL
         WHERE id IN (
             SELECT sapling_received_note_id FROM sapling_received_note_spends
             WHERE transaction_id = :tx_ref
         )",
        named_params![":tx_ref": tx_ref.0],
    )?;

    conn.execute(
        "UPDATE orchard_received_notes SET lock_expiry_height = NULL, lock_owner = NULL
         WHERE id IN (
             SELECT orchard_received_note_id FROM orchard_received_note_spends
             WHERE transaction_id = :tx_ref
         )",
        named_params![":tx_ref": tx_ref.0],
    )?;

    conn.execute(
        "UPDATE ironwood_received_notes SET lock_expiry_height = NULL, lock_owner = NULL
         WHERE id IN (
             SELECT ironwood_received_note_id FROM ironwood_received_note_spends
             WHERE transaction_id = :tx_ref
         )",
        named_params![":tx_ref": tx_ref.0],
    )?;

    conn.execute(
        "UPDATE transparent_received_outputs SET lock_expiry_height = NULL, lock_owner = NULL
         WHERE id IN (
             SELECT transparent_received_output_id FROM transparent_received_output_spends
             WHERE transaction_id = :tx_ref
         )",
        named_params![":tx_ref": tx_ref.0],
    )?;

    Ok(())
}

/// Returns whether an output bearing the given `lock_expiry_height` is locked as of
/// `target_height`.
///
/// An output is locked while `lock_expiry_height >= target_height`; selection eligibility is
/// the exact complement of this predicate (see [`output_eligible_condition`]). Balance
/// computations use this single definition to tally locked value separately from spendable
/// value.
pub(crate) fn is_locked_at(lock_expiry_height: Option<u32>, target_height: TargetHeight) -> bool {
    lock_expiry_height.is_some_and(|h| h >= u32::from(target_height))
}

/// Generates the SQL condition under which an output is eligible for selection, given the
/// active [`LockFilter`].
///
/// An output is *locked for selection* when its `lock_expiry_height` is set and greater than or
/// equal to the target height; equivalently, it becomes selectable again once the target height
/// has advanced strictly beyond its `lock_expiry_height`. This matches the
/// [`OutputLockStore::lock_outputs`] contract, which prevents selection "at any height less than or
/// equal to" the lock expiry height, and is the exact complement of the locked-balance condition
/// (`lock_expiry_height >= target_height`) used in balance computation.
///
/// - [`LockFilter::Unfiltered`] admits every output: the fragment is the constant `1`, so neither
///   `:target_height` nor `:overridable_owners` is referenced on account of the lock filter and
///   neither must be bound for its sake.
/// - [`LockFilter::Policy`] admits an output when it carries no lock, when its lock has expired as
///   of `:target_height`, or when its `lock_owner` is one of the policy's overridable owners. For
///   [`LockedInputPolicy::Exclude`] the overridable-owner set is empty, so the `IN rarray(...)`
///   term is always false and only unlocked outputs are eligible; for the preference variants the
///   set carries the owners whose locks may be drawn upon. An output locked by any other owner is
///   never eligible.
///
/// # Usage requirements
/// - `tbl` must be set to the SQL alias for the received notes/outputs table.
/// - Under a [`LockFilter::Policy`] the parent must provide `:target_height` and must bind
///   `:overridable_owners` to the rarray produced by [`overridable_owners_rarray`]. Under
///   [`LockFilter::Unfiltered`] neither is referenced by this fragment, and (rusqlite rejecting an
///   unused named parameter) `:overridable_owners` must not be bound for its sake.
///
/// [`OutputLockStore::lock_outputs`]: zcash_client_backend::data_api::OutputLockStore::lock_outputs
/// [`LockedInputPolicy::Exclude`]: zcash_client_backend::data_api::wallet::input_selection::LockedInputPolicy::Exclude
pub(crate) fn output_eligible_condition(lock_filter: LockFilter<'_>, tbl: &str) -> String {
    match lock_filter {
        LockFilter::Unfiltered => "1".to_string(),
        LockFilter::Policy(_) => format!(
            "{tbl}.lock_expiry_height IS NULL \
             OR {tbl}.lock_expiry_height < :target_height \
             OR {tbl}.lock_owner IN rarray(:overridable_owners)"
        ),
    }
}

/// Builds the `:overridable_owners` rarray for the given [`LockFilter`]: the byte strings of the
/// lock owners whose locked outputs the filter's policy admits.
///
/// The set is empty under [`LockFilter::Unfiltered`] (which does not reference the parameter) and
/// under [`LockedInputPolicy::Exclude`] (which admits no locked owner). The returned `Rc` must be
/// kept alive and bound by reference for the duration of the query, following the same pattern as
/// the `:exclude` rarray.
///
/// [`LockedInputPolicy::Exclude`]: zcash_client_backend::data_api::wallet::input_selection::LockedInputPolicy::Exclude
pub(crate) fn overridable_owners_rarray(lock_filter: LockFilter<'_>) -> Rc<Vec<Value>> {
    let owners = match lock_filter {
        LockFilter::Unfiltered => Vec::new(),
        LockFilter::Policy(policy) => policy
            .overridable_owners()
            .iter()
            .map(|owner| Value::from(owner.as_bytes().to_vec()))
            .collect(),
    };
    Rc::new(owners)
}

/// Appends the lock-filter-dependent named parameters that [`output_eligible_condition`]
/// references to a selection query's parameter list.
///
/// This is the single source of truth pairing the eligibility SQL with its bindings: it binds
/// `:overridable_owners` (to the `overridable_owners` rarray from [`overridable_owners_rarray`],
/// which must outlive the query) exactly when the fragment references it, i.e. under a
/// [`LockFilter::Policy`]. Because rusqlite rejects a provided-but-unreferenced named parameter,
/// keeping this in lockstep with [`output_eligible_condition`] in one place — rather than repeating
/// the `matches!` and the `:overridable_owners` literal at each call site — prevents the SQL and
/// its bindings from silently drifting apart.
///
/// `:target_height` is deliberately NOT handled here: every query that uses the eligibility
/// fragment also references `:target_height` independently of the lock filter (via
/// `spent_notes_clause` / `tx_unexpired_condition` and the like), so it is always present in the
/// SQL and is bound unconditionally by the caller.
pub(crate) fn push_lock_params<'a>(
    params: &mut Vec<(&'a str, &'a dyn ToSql)>,
    lock_filter: LockFilter<'_>,
    overridable_owners: &'a Rc<Vec<Value>>,
) {
    if matches!(lock_filter, LockFilter::Policy(_)) {
        params.push((":overridable_owners", overridable_owners as &dyn ToSql));
    }
}

/// Returns the tier-preference sort key `(<lock tier>) ASC|DESC` for a [`LockFilter`] that prefers
/// one lock tier over the other, or `None` when no tier preference applies
/// ([`LockedInputPolicy::Exclude`] and [`LockFilter::Unfiltered`], which draw on a single admitted
/// tier or apply no lock filtering).
///
/// The tier expression evaluates to `1` for an output that is locked for selection as of
/// `:target_height` and `0` otherwise. [`LockedInputPolicy::PreferUnlocked`] sorts it ascending
/// (unlocked first) and [`LockedInputPolicy::PreferLocked`] descending (owned-locked first).
/// Because a [`LockFilter::Policy`] `WHERE` clause (see [`output_eligible_condition`]) has already
/// excluded foreign-owner locks, the `1` tier contains only owned-locked outputs.
///
/// This key is a *preference* over an eligible set: callers must combine it with the existing
/// within-tier ordering (age or value) as a secondary key so that ordering is preserved within
/// each tier.
///
/// # Usage requirements
/// - `tbl` must be set to the SQL alias for the received notes/outputs table.
/// - When this returns `Some(_)`, the parent must provide `:target_height`.
///
/// [`LockedInputPolicy::Exclude`]: zcash_client_backend::data_api::wallet::input_selection::LockedInputPolicy::Exclude
/// [`LockedInputPolicy::PreferUnlocked`]: zcash_client_backend::data_api::wallet::input_selection::LockedInputPolicy::PreferUnlocked
/// [`LockedInputPolicy::PreferLocked`]: zcash_client_backend::data_api::wallet::input_selection::LockedInputPolicy::PreferLocked
pub(crate) fn locked_tier_order_key(lock_filter: LockFilter<'_>, tbl: &str) -> Option<String> {
    match lock_filter {
        LockFilter::Policy(policy) if policy.admits_locked() => {
            let direction = if policy.prefers_locked() {
                "DESC"
            } else {
                "ASC"
            };
            Some(format!(
                "(CASE WHEN {tbl}.lock_expiry_height IS NOT NULL \
                  AND {tbl}.lock_expiry_height >= :target_height THEN 1 ELSE 0 END) {direction}"
            ))
        }
        _ => None,
    }
}

/// Generates the SQL condition under which an output's lock may be (re)acquired.
///
/// A lock may be taken when no lock exists (`lock_expiry_height IS NULL`), when the existing
/// lock has expired as of the chain tip (`lock_expiry_height <= :chain_tip`), or when the
/// existing lock is held by the requesting owner (`lock_owner = :owner`), which makes
/// re-locking by the same owner idempotent. Because balance and selection evaluate lock state
/// against `target_height = chain_tip + 1`, "expired as of the chain tip" (`h <= chain_tip`)
/// is exactly "not locked for selection" (`h < target_height`): a lock can never be stolen by
/// a DIFFERENT owner while the output is still excluded from selection.
///
/// When the chain tip is unknown, `:chain_tip` binds to SQL NULL and the expiry comparison
/// evaluates to NULL (falsy), so only outputs with no existing lock, or whose lock the
/// requesting owner already holds, can be locked; a foreign lock cannot be judged expired
/// without a height to compare against.
///
/// # Usage requirements
/// - This condition uses the bare `lock_expiry_height` and `lock_owner` column names, so it
///   must be used in a single-table statement (such as the `UPDATE`s in `lock_outputs`).
/// - The parent must provide `:chain_tip` (possibly NULL) and `:owner` as named arguments.
pub(crate) fn output_lockable_condition() -> &'static str {
    "lock_expiry_height IS NULL OR lock_expiry_height <= :chain_tip OR lock_owner = :owner"
}

#[cfg(test)]
mod tests {
    use zcash_client_backend::data_api::wallet::TargetHeight;

    use super::is_locked_at;

    /// The boundary of the locked predicate: a lock expiring exactly at the target height is
    /// still locked (`h == t`), a lock expiring just below it has expired (`h == t - 1`), and
    /// an absent lock is never locked.
    #[test]
    fn is_locked_at_boundary() {
        let target = TargetHeight::from(100);
        assert!(is_locked_at(Some(100), target));
        assert!(!is_locked_at(Some(99), target));
        assert!(!is_locked_at(None, target));
    }

    /// Tests for the lock-state SQL predicates.
    ///
    /// These pin the semantics of the lock columns against executable models, evaluating the actual
    /// SQL fragments in SQLite (including their NULL behavior, `rarray` owner matching, and window
    /// ordering) rather than a Rust re-implementation of them:
    ///
    /// - An output is LOCKED for balance purposes while `lock_expiry_height >= target_height`.
    /// - Selection eligibility (`output_eligible_condition`) is owner-scoped:
    ///   - `Unfiltered` admits every output;
    ///   - `Policy(Exclude)` admits only outputs with no active lock as of the target height (the
    ///     exact complement of the locked-balance predicate), so once the target height passes the
    ///     lock expiry height an output is eligible again with no unlock call, even though the stale
    ///     column value remains until replaced or cleared;
    ///   - `Policy(PreferUnlocked | PreferLocked)` additionally admits outputs whose `lock_owner` is
    ///     one of the policy's overridable owners, and never an output locked by any other owner.
    /// - Greedy value-target selection is TIERED under a preference policy
    ///   (`locked_tier_order_key`): `PreferUnlocked` draws unlocked outputs before owned-locked
    ///   ones and `PreferLocked` the reverse, each retaining age order within a tier; `Exclude` and
    ///   `Unfiltered` impose no tier preference.
    /// - A lock may be (re)acquired when no lock exists, when the existing lock has expired as of
    ///   the chain tip (`lock_expiry_height <= chain_tip`), or when the existing lock is held by
    ///   the requesting owner (idempotent same-owner re-lock); with an unknown chain tip a
    ///   foreign lock can never be judged expired.
    /// - No lock stealing: whenever a lock held by a DIFFERENT owner is replaceable, the output
    ///   is already selectable at the next target height, so replacing an expired lock never
    ///   removes protection from a still-protected output.
    mod lock_predicate_tests {
        use proptest::prelude::*;
        use rusqlite::{Connection, ToSql, named_params};
        use zcash_client_backend::{
            data_api::wallet::input_selection::{LockFilter, LockedInputPolicy, NonEmptyBTreeSet},
            wallet::LockOwner,
        };

        use crate::wallet::locking::{
            locked_tier_order_key, output_eligible_condition, output_lockable_condition,
            overridable_owners_rarray, push_lock_params,
        };

        /// A distinguished lock owner whose locks the preference policies in these tests admit.
        const OWNER_A: LockOwner = LockOwner::new([0xA1; 32]);
        /// A distinguished lock owner NOT admitted by the policies, standing in for "some other
        /// flow's" lock; an output it holds must never be eligible under a `Policy`.
        const OWNER_B: LockOwner = LockOwner::new([0xB2; 32]);

        fn lock_state_db(
            lock_expiry_height: Option<u32>,
            lock_owner: Option<[u8; 32]>,
        ) -> Connection {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch("CREATE TABLE t (lock_expiry_height INTEGER, lock_owner BLOB)")
                .unwrap();
            conn.execute(
                "INSERT INTO t (lock_expiry_height, lock_owner) VALUES (:h, :owner)",
                named_params![":h": lock_expiry_height, ":owner": lock_owner],
            )
            .unwrap();
            conn
        }

        /// A candidate output for the selection-eligibility and tiering tests: its stable `id`
        /// (also its age order, oldest first), value, and lock state (`lock_expiry_height` set with
        /// a `lock_owner` when locked).
        struct Candidate {
            id: i64,
            value: i64,
            lock_expiry_height: Option<u32>,
            lock_owner: Option<LockOwner>,
        }

        fn unlocked(id: i64, value: i64) -> Candidate {
            Candidate {
                id,
                value,
                lock_expiry_height: None,
                lock_owner: None,
            }
        }

        fn locked(id: i64, value: i64, expiry: u32, owner: LockOwner) -> Candidate {
            Candidate {
                id,
                value,
                lock_expiry_height: Some(expiry),
                lock_owner: Some(owner),
            }
        }

        /// Builds an in-memory table of candidate outputs, with the `rarray` module loaded so that
        /// the `:overridable_owners` binding used by [`output_eligible_condition`] can be evaluated.
        fn candidates_db(candidates: &[Candidate]) -> Connection {
            let conn = Connection::open_in_memory().unwrap();
            rusqlite::vtab::array::load_module(&conn).unwrap();
            conn.execute_batch(
                "CREATE TABLE t (
                     id INTEGER PRIMARY KEY,
                     value INTEGER NOT NULL,
                     lock_expiry_height INTEGER,
                     lock_owner BLOB
                 )",
            )
            .unwrap();
            for c in candidates {
                conn.execute(
                    "INSERT INTO t (id, value, lock_expiry_height, lock_owner)
                     VALUES (:id, :value, :h, :owner)",
                    named_params![
                        ":id": c.id,
                        ":value": c.value,
                        ":h": c.lock_expiry_height,
                        ":owner": c.lock_owner.map(|o| o.as_bytes().to_vec()),
                    ],
                )
                .unwrap();
            }
            conn
        }

        /// A preference policy admitting only [`OWNER_A`]'s locks.
        fn owner_a_policy(prefer_locked: bool) -> LockedInputPolicy {
            let owners = NonEmptyBTreeSet::singleton(OWNER_A);
            if prefer_locked {
                LockedInputPolicy::PreferLocked(owners)
            } else {
                LockedInputPolicy::PreferUnlocked(owners)
            }
        }

        /// The set of candidate ids the eligibility fragment admits under `lock_filter`, in id
        /// order. `:target_height` and `:overridable_owners` are bound only under a `Policy`, since
        /// the `Unfiltered` fragment (`1`) references neither and rusqlite rejects unused
        /// parameters.
        fn eligible_ids(
            candidates: &[Candidate],
            target_height: u32,
            lock_filter: LockFilter<'_>,
        ) -> Vec<i64> {
            let conn = candidates_db(candidates);
            let sql = format!(
                "SELECT id FROM t WHERE ({}) ORDER BY id",
                output_eligible_condition(lock_filter, "t"),
            );
            let overridable_owners = overridable_owners_rarray(lock_filter);
            let mut params: Vec<(&str, &dyn ToSql)> = Vec::new();
            // Unlike the production queries, this isolated table references `:target_height` only
            // through the eligibility fragment, so it too is bound only under a policy.
            if matches!(lock_filter, LockFilter::Policy(_)) {
                params.push((":target_height", &target_height));
            }
            push_lock_params(&mut params, lock_filter, &overridable_owners);
            let mut stmt = conn.prepare(&sql).unwrap();
            stmt.query_map(&params[..], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        }

        /// The ids selected by a greedy value-target selection composed exactly as
        /// `select_spendable_notes_matching_value` composes it (eligibility fragment + tiered
        /// window `so_far` + threshold-crossing note), returned in selection (running-sum) order.
        fn selection_order(
            candidates: &[Candidate],
            target_height: u32,
            target_value: i64,
            lock_filter: LockFilter<'_>,
        ) -> Vec<i64> {
            let conn = candidates_db(candidates);
            let eligible_condition = output_eligible_condition(lock_filter, "t");
            let tier_key = locked_tier_order_key(lock_filter, "t");
            let window_frame = match &tier_key {
                Some(k) => format!("ORDER BY {k}, t.id ROWS UNBOUNDED PRECEDING"),
                None => "ROWS UNBOUNDED PRECEDING".to_string(),
            };
            // The crossing note is wrapped in its own subquery (as in the production query) so that
            // its `LIMIT 1` binds to the crossing selection alone, not to the whole `UNION`.
            let crossing = if tier_key.is_some() {
                "SELECT * FROM eligible WHERE so_far >= :target_value ORDER BY so_far LIMIT 1"
            } else {
                "SELECT * FROM eligible WHERE so_far >= :target_value LIMIT 1"
            };
            let sql = format!(
                "WITH eligible AS (
                     SELECT t.id AS id, SUM(t.value) OVER ({window_frame}) AS so_far
                     FROM t WHERE ({eligible_condition})
                 )
                 SELECT id FROM (
                     SELECT id, so_far FROM eligible WHERE so_far < :target_value
                     UNION
                     SELECT id, so_far FROM ({crossing})
                 ) ORDER BY so_far",
            );
            // `:target_value` is always referenced; the isolated table references `:target_height`
            // only through the eligibility fragment and tier window, so it is bound only under a
            // policy.
            let overridable_owners = overridable_owners_rarray(lock_filter);
            let mut params: Vec<(&str, &dyn ToSql)> = vec![(":target_value", &target_value)];
            if matches!(lock_filter, LockFilter::Policy(_)) {
                params.push((":target_height", &target_height));
            }
            push_lock_params(&mut params, lock_filter, &overridable_owners);
            let mut stmt = conn.prepare(&sql).unwrap();
            stmt.query_map(&params[..], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        }

        /// Evaluates `output_lockable_condition` in SQLite. A NULL result is falsy, as it would
        /// be in the `UPDATE ... WHERE` clause of `lock_outputs`.
        fn sql_lockable(
            lock_expiry_height: Option<u32>,
            lock_owner: Option<[u8; 32]>,
            chain_tip: Option<u32>,
            requesting_owner: [u8; 32],
        ) -> bool {
            let conn = lock_state_db(lock_expiry_height, lock_owner);
            conn.query_row(
                &format!("SELECT ({}) FROM t", output_lockable_condition()),
                named_params![":chain_tip": chain_tip, ":owner": requesting_owner],
                |row| row.get::<_, Option<bool>>(0),
            )
            .unwrap()
            .unwrap_or(false)
        }

        /// The balance-side model: an output is counted as locked value while its lock expiry
        /// height has not been passed as of the target height.
        fn model_locked(lock_expiry_height: Option<u32>, target_height: u32) -> bool {
            lock_expiry_height.is_some_and(|h| h >= target_height)
        }

        /// Whether a note with the given lock expiry height is eligible for selection under
        /// `Policy(Exclude)` (i.e. unlocked for selection) at `target_height`. The owner is
        /// irrelevant under `Exclude`, which admits no owner's lock, so a locked candidate records
        /// [`OWNER_A`].
        fn exclude_eligible(lock_expiry_height: Option<u32>, target_height: u32) -> bool {
            let candidate = match lock_expiry_height {
                None => unlocked(1, 100),
                Some(h) => locked(1, 100, h, OWNER_A),
            };
            !eligible_ids(
                &[candidate],
                target_height,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .is_empty()
        }

        /// A height strategy biased toward the boundary around the given height, where the
        /// interesting semantics (expiry exactly at the target, one below, one above) live.
        fn arb_height_near(height: u32) -> impl Strategy<Value = u32> {
            prop_oneof![
                3 => height.saturating_sub(3)..=height.saturating_add(3),
                1 => any::<u32>(),
            ]
        }

        fn arb_lock_expiry(target_height: u32) -> impl Strategy<Value = Option<u32>> {
            prop_oneof![
                1 => Just(None),
                4 => arb_height_near(target_height).prop_map(Some),
            ]
        }

        /// Owners drawn from a two-element pool, so that the requesting owner frequently matches
        /// (and frequently differs from) the owner recorded on the row.
        fn arb_owner() -> impl Strategy<Value = [u8; 32]> {
            prop_oneof![Just([0xAA; 32]), Just([0xBB; 32])]
        }

        /// Two unlocked notes, two locked by [`OWNER_A`] (the admitted owner), and one locked by
        /// [`OWNER_B`] (a foreign owner). All ids are assigned in age order (oldest first), all
        /// values are equal, and all locks expire at 105, safely above [`TARGET_HEIGHT`], so every
        /// locked note is "locked for selection".
        const TARGET_HEIGHT: u32 = 100;

        fn mixed_candidates() -> Vec<Candidate> {
            vec![
                unlocked(1, 100),
                locked(2, 100, 105, OWNER_A),
                unlocked(3, 100),
                locked(4, 100, 105, OWNER_B),
                locked(5, 100, 105, OWNER_A),
            ]
        }

        /// `Exclude` admits only unlocked notes, regardless of owner.
        #[test]
        fn exclude_selects_only_unlocked() {
            assert_eq!(
                eligible_ids(
                    &mixed_candidates(),
                    TARGET_HEIGHT,
                    LockFilter::Policy(&LockedInputPolicy::Exclude),
                ),
                vec![1, 3]
            );
        }

        /// `Unfiltered` admits every note, locked or not, by any owner.
        #[test]
        fn unfiltered_selects_everything() {
            assert_eq!(
                eligible_ids(&mixed_candidates(), TARGET_HEIGHT, LockFilter::Unfiltered),
                vec![1, 2, 3, 4, 5]
            );
        }

        /// Both preference policies admit unlocked notes and the admitted owner's locked notes, but
        /// never a note locked by a foreign owner (id 4).
        #[test]
        fn prefer_policies_admit_unlocked_and_owned_locks_not_foreign() {
            for prefer_locked in [false, true] {
                let policy = owner_a_policy(prefer_locked);
                assert_eq!(
                    eligible_ids(
                        &mixed_candidates(),
                        TARGET_HEIGHT,
                        LockFilter::Policy(&policy),
                    ),
                    vec![1, 2, 3, 5],
                    "prefer_locked = {prefer_locked}"
                );
            }
        }

        /// `PreferUnlocked` draws the unlocked notes first (in age order), reaching into the
        /// admitted owner's locked notes only to cross the target; the foreign lock never appears.
        #[test]
        fn prefer_unlocked_draws_unlocked_before_owned_locks() {
            let policy = owner_a_policy(false);
            assert_eq!(
                selection_order(
                    &mixed_candidates(),
                    TARGET_HEIGHT,
                    250,
                    LockFilter::Policy(&policy),
                ),
                vec![1, 3, 2]
            );
        }

        /// `PreferLocked` is the mirror image: the admitted owner's locked notes are drawn first,
        /// reaching into the unlocked notes only to cross the target; the foreign lock never appears.
        #[test]
        fn prefer_locked_draws_owned_locks_before_unlocked() {
            let policy = owner_a_policy(true);
            assert_eq!(
                selection_order(
                    &mixed_candidates(),
                    TARGET_HEIGHT,
                    250,
                    LockFilter::Policy(&policy),
                ),
                vec![2, 5, 1]
            );
        }

        /// A preference is only a preference: when the preferred tier alone covers the target, the
        /// other tier is not drawn upon at all.
        #[test]
        fn preference_stays_within_preferred_tier_when_sufficient() {
            assert_eq!(
                selection_order(
                    &mixed_candidates(),
                    TARGET_HEIGHT,
                    150,
                    LockFilter::Policy(&owner_a_policy(false)),
                ),
                vec![1, 3],
                "PreferUnlocked draws only unlocked notes"
            );
            assert_eq!(
                selection_order(
                    &mixed_candidates(),
                    TARGET_HEIGHT,
                    150,
                    LockFilter::Policy(&owner_a_policy(true)),
                ),
                vec![2, 5],
                "PreferLocked draws only the admitted owner's locked notes"
            );
        }

        /// `Unfiltered` imposes no tier preference: it draws purely in age order, so a locked note
        /// can be selected ahead of a later unlocked one.
        #[test]
        fn unfiltered_draws_in_age_order() {
            assert_eq!(
                selection_order(
                    &mixed_candidates(),
                    TARGET_HEIGHT,
                    150,
                    LockFilter::Unfiltered
                ),
                vec![1, 2]
            );
        }

        proptest! {
            /// `LockFilter::Unfiltered` ignores lock state entirely: a candidate is eligible
            /// whatever its lock expiry height or owner.
            #[test]
            fn unfiltered_admits_all_lock_states(
                target in any::<u32>(),
                lock in prop::option::of(any::<u32>()),
            ) {
                let candidate = match lock {
                    None => unlocked(1, 100),
                    Some(h) => locked(1, 100, h, OWNER_A),
                };
                prop_assert_eq!(
                    eligible_ids(&[candidate], target, LockFilter::Unfiltered),
                    vec![1]
                );
            }

            /// Under `Policy(Exclude)`, eligibility is the exact complement of the locked-balance
            /// predicate: an output is eligible for selection iff it is not counted as locked value
            /// at the target height. Once the target height passes the lock expiry height the output
            /// is eligible again with no unlock call, while the stale column value is ignored.
            #[test]
            fn exclude_selection_is_complement_of_locked_balance(
                (target, lock) in any::<u32>().prop_flat_map(|t| (Just(t), arb_lock_expiry(t))),
            ) {
                let candidate = match lock {
                    None => unlocked(1, 100),
                    Some(h) => locked(1, 100, h, OWNER_A),
                };
                let eligible = !eligible_ids(
                    &[candidate],
                    target,
                    LockFilter::Policy(&LockedInputPolicy::Exclude),
                )
                .is_empty();
                let locked_balance = model_locked(lock, target);
                prop_assert!(
                    eligible ^ locked_balance,
                    "eligible = {eligible}, locked = {locked_balance} for lock {lock:?}, target {target}"
                );
            }

            /// The lock-acquisition predicate matches its model: a lock slot is free when no
            /// lock exists, when the existing lock has expired as of the chain tip, or when the
            /// existing lock is held by the requesting owner; when the chain tip is unknown a
            /// foreign lock can never be judged expired.
            #[test]
            fn lockable_matches_model(
                (tip, lock) in prop::option::of(any::<u32>()).prop_flat_map(|tip| {
                    (Just(tip), arb_lock_expiry(tip.unwrap_or(u32::MAX / 2)))
                }),
                row_owner in arb_owner(),
                requesting_owner in arb_owner(),
            ) {
                // A row with a lock height always records its owner; a row without one records
                // no owner (the invariant maintained by lock/unlock/clear).
                let row_owner = lock.map(|_| row_owner);
                let expected = match lock {
                    None => true,
                    Some(h) => {
                        tip.is_some_and(|tip| h <= tip) || row_owner == Some(requesting_owner)
                    }
                };
                prop_assert_eq!(
                    sql_lockable(lock, row_owner, tip, requesting_owner),
                    expected
                );
            }

            /// Same-owner re-locking is always permitted, regardless of expiry state and even
            /// when the chain tip is unknown: this is what makes lock acquisition idempotent for
            /// the flow that holds the lock.
            #[test]
            fn same_owner_relock_always_permitted(
                (tip, lock) in prop::option::of(any::<u32>()).prop_flat_map(|tip| {
                    (Just(tip), arb_lock_expiry(tip.unwrap_or(u32::MAX / 2)))
                }),
                owner in arb_owner(),
            ) {
                let row_owner = lock.map(|_| owner);
                prop_assert!(sql_lockable(lock, row_owner, tip, owner));
            }

            /// No lock stealing: whenever an existing lock held by a DIFFERENT owner may be
            /// replaced (as of chain tip `tip`), the output is already selectable at the
            /// corresponding target height `tip + 1`. Acquiring a lock therefore never displaces
            /// a foreign lock that still protects its output.
            #[test]
            fn lockable_implies_selectable(
                (tip, lock) in (0..u32::MAX).prop_flat_map(|tip| {
                    (Just(tip), arb_lock_expiry(tip))
                }),
            ) {
                let row_owner = lock.map(|_| [0xAA; 32]);
                if sql_lockable(lock, row_owner, Some(tip), [0xBB; 32]) {
                    prop_assert!(exclude_eligible(lock, tip + 1));
                }
            }
        }
    }

    mod concurrency_tests {
        use assert_matches::assert_matches;

        use zcash_client_backend::{
            data_api::{
                Account as _, InputSource as _, OutputLockStore as _, WalletRead as _,
                WalletTest as _,
                error::LockError,
                testing::{
                    AddressType, TestBuilder, pool::ShieldedPoolTester, sapling::SaplingPoolTester,
                },
                wallet::{
                    TargetHeight,
                    input_selection::{LockFilter, LockedInputPolicy},
                },
            },
            wallet::{LockOwner, OutputRef},
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::{PoolType, ShieldedPool, consensus::BlockHeight, value::Zatoshis};

        use crate::{
            WalletDb,
            testing::{
                BlockCache,
                db::{TestDbFactory, test_clock, test_rng},
            },
        };

        /// Two independent `WalletDb` connections to the same wallet database resolve a lock race
        /// at the storage layer: both handles observe the same spendable note (the shared
        /// select-before-lock state of the TOCTOU window), only the first `lock_outputs` succeeds,
        /// the loser's failure names the contested note, and lock state changes are immediately
        /// visible across handles. Also pins the ownerless-lock property across connections: the
        /// losing handle is able to release the winner's lock.
        #[test]
        fn concurrent_handles_resolve_lock_conflict() {
            let mut st = TestBuilder::new()
                .with_block_cache(BlockCache::new())
                .with_data_store_factory(TestDbFactory::default())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            // Fund the wallet with a single note.
            let dfvk = SaplingPoolTester::test_account_fvk(&st);
            let value = Zatoshis::const_from_u64(60000);
            let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
            st.scan_cached_blocks(h, 1);

            let account_id = st.test_account().unwrap().id();
            let notes = st.wallet().get_notes(ShieldedPool::Sapling).unwrap();
            assert_eq!(notes.len(), 1);
            let note = &notes[0];
            let txid = *note.txid();
            let output_index = u32::from(note.output_index());
            let output_ref = OutputRef::new(txid, PoolType::SAPLING, output_index);

            let tip = st.wallet().chain_height().unwrap().unwrap();
            let target_height = TargetHeight::from(tip + 1);

            // Open a second, independent connection to the same wallet database file.
            let network = *st.network();
            let mut db2 = WalletDb::for_path(
                st.wallet().data_file_path(),
                network,
                test_clock(),
                test_rng(),
            )
            .unwrap();

            // Both handles observe the note as spendable: this is the shared state from which two
            // concurrent proposal flows would each select the same input.
            assert!(
                st.wallet()
                    .get_spendable_note(
                        &txid,
                        ShieldedPool::Sapling,
                        output_index,
                        target_height,
                        LockFilter::Policy(&LockedInputPolicy::Exclude)
                    )
                    .unwrap()
                    .is_some()
            );
            assert!(
                db2.get_spendable_note(
                    &txid,
                    ShieldedPool::Sapling,
                    output_index,
                    target_height,
                    LockFilter::Policy(&LockedInputPolicy::Exclude)
                )
                .unwrap()
                .is_some()
            );

            // The second handle locks first, under its own owner...
            let owner_a = LockOwner::new([0xA1; 32]);
            let owner_b = LockOwner::new([0xB2; 32]);
            assert_eq!(
                db2.lock_outputs(&[output_ref], owner_b, BlockHeight::from(u32::MAX))
                    .unwrap(),
                1
            );

            // ... so the first handle's lock (under a different owner) fails, naming the
            // contested output: the race is resolved at the storage layer, across connections.
            assert_matches!(
                st.wallet_mut()
                    .lock_outputs(&[output_ref], owner_a, BlockHeight::from(u32::MAX)),
                Err(LockError::LockFailure(r)) if r == output_ref
            );

            // The winner's lock is immediately visible to the losing handle.
            assert!(
                st.wallet()
                    .get_spendable_note(
                        &txid,
                        ShieldedPool::Sapling,
                        output_index,
                        target_height,
                        LockFilter::Policy(&LockedInputPolicy::Exclude)
                    )
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                st.wallet().get_locked_outputs(account_id).unwrap(),
                vec![output_ref]
            );

            // Locks are owner-scoped, so the losing handle CANNOT release the winner's lock:
            // its unlock is a no-op and the note stays locked.
            assert!(!st.wallet_mut().unlock_output(&output_ref, owner_a).unwrap());
            assert!(
                st.wallet()
                    .get_spendable_note(
                        &txid,
                        ShieldedPool::Sapling,
                        output_index,
                        target_height,
                        LockFilter::Policy(&LockedInputPolicy::Exclude)
                    )
                    .unwrap()
                    .is_none()
            );

            // The winning handle releases its own lock; the release is visible to the losing
            // handle, whose retry then succeeds.
            assert!(db2.unlock_output(&output_ref, owner_b).unwrap());
            assert!(
                db2.get_spendable_note(
                    &txid,
                    ShieldedPool::Sapling,
                    output_index,
                    target_height,
                    LockFilter::Policy(&LockedInputPolicy::Exclude)
                )
                .unwrap()
                .is_some()
            );
            assert_eq!(
                st.wallet_mut()
                    .lock_outputs(&[output_ref], owner_a, BlockHeight::from(u32::MAX))
                    .unwrap(),
                1
            );
        }
    }

    mod sapling {
        use zcash_client_backend::data_api::testing::{pool, sapling::SaplingPoolTester};

        use crate::testing::{BlockCache, db::TestDbFactory};

        #[test]
        fn spend_fails_on_locked_notes() {
            pool::spend_fails_on_locked_notes::<SaplingPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn explicit_note_locking() {
            pool::explicit_note_locking::<SaplingPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn note_locking_height_boundary() {
            pool::note_locking_height_boundary::<SaplingPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn clear_locked_outputs() {
            pool::clear_locked_outputs::<SaplingPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn proposal_level_note_locking() {
            pool::proposal_level_note_locking::<SaplingPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn locked_proposal_proto_roundtrip() {
            pool::locked_proposal_proto_roundtrip::<SaplingPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn lock_expiry_restores_spendability() {
            pool::lock_expiry_restores_spendability::<SaplingPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn lock_conflict_and_batch_atomicity() {
            pool::lock_conflict_and_batch_atomicity::<SaplingPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn unlock_proposal_inputs_releases_locks() {
            pool::unlock_proposal_inputs_releases_locks::<SaplingPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn spend_policy_locked_input_policy_reaches_selection() {
            pool::spend_policy_locked_input_policy_reaches_selection::<SaplingPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        proptest::proptest! {
            // Each case builds a fresh wallet and replays an operation sequence, so keep the
            // case count moderate; the sequences themselves explore the expiry boundaries.
            #![proptest_config(proptest::prelude::ProptestConfig::with_cases(12))]

            #[test]
            fn note_locking_model(ops in pool::arb_lock_ops(3, 10)) {
                pool::check_note_locking_model::<SaplingPoolTester>(
                    TestDbFactory::default(),
                    BlockCache::new(),
                    &ops,
                )
            }
        }
    }

    #[cfg(feature = "orchard")]
    mod orchard {
        use zcash_client_backend::data_api::testing::{orchard::OrchardPoolTester, pool};

        use crate::testing::{BlockCache, db::TestDbFactory};

        #[test]
        fn spend_fails_on_locked_notes() {
            pool::spend_fails_on_locked_notes::<OrchardPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn explicit_note_locking() {
            pool::explicit_note_locking::<OrchardPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn note_locking_height_boundary() {
            pool::note_locking_height_boundary::<OrchardPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn clear_locked_outputs() {
            pool::clear_locked_outputs::<OrchardPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn proposal_level_note_locking() {
            pool::proposal_level_note_locking::<OrchardPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn locked_proposal_proto_roundtrip() {
            pool::locked_proposal_proto_roundtrip::<OrchardPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn lock_expiry_restores_spendability() {
            pool::lock_expiry_restores_spendability::<OrchardPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn lock_conflict_and_batch_atomicity() {
            pool::lock_conflict_and_batch_atomicity::<OrchardPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn unlock_proposal_inputs_releases_locks() {
            pool::unlock_proposal_inputs_releases_locks::<OrchardPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        #[test]
        fn spend_policy_locked_input_policy_reaches_selection() {
            pool::spend_policy_locked_input_policy_reaches_selection::<OrchardPoolTester>(
                TestDbFactory::default(),
                BlockCache::new(),
            )
        }

        proptest::proptest! {
            // Each case builds a fresh wallet and replays an operation sequence, so keep the
            // case count moderate; the sequences themselves explore the expiry boundaries.
            #![proptest_config(proptest::prelude::ProptestConfig::with_cases(12))]

            #[test]
            fn note_locking_model(ops in pool::arb_lock_ops(3, 10)) {
                pool::check_note_locking_model::<OrchardPoolTester>(
                    TestDbFactory::default(),
                    BlockCache::new(),
                    &ops,
                )
            }
        }
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn transparent_note_locking() {
        zcash_client_backend::data_api::testing::transparent::transparent_note_locking(
            crate::testing::db::TestDbFactory::default(),
        );
    }
}
