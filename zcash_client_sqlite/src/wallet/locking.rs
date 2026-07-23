//! SQLite storage layer for output locking.
//!
//! This module implements the storage side of the locking contracts defined in
//! [`zcash_client_backend::data_api::locking`]: the lock-mutation statements
//! backing [`WalletWrite::lock_outputs`], [`WalletWrite::unlock_output`], and
//! [`WalletWrite::clear_locked_outputs`], the unlock-on-store path, and the SQL
//! fragments through which the spendable-output queries apply a
//! [`LockFilter`]. See the backend module's documentation for the semantic
//! invariants (the locked/eligible complement, the acquisition rules, and the
//! release paths) that these implementations realize.
//!
//! [`WalletWrite::lock_outputs`]: zcash_client_backend::data_api::WalletWrite::lock_outputs
//! [`WalletWrite::unlock_output`]: zcash_client_backend::data_api::WalletWrite::unlock_output
//! [`WalletWrite::clear_locked_outputs`]: zcash_client_backend::data_api::WalletWrite::clear_locked_outputs

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
/// This is the storage-layer implementation of [`WalletWrite::clear_locked_outputs`], and is
/// intended as a recovery mechanism for callers that have lost track of their in-flight proposals.
///
/// [`WalletWrite::clear_locked_outputs`]: zcash_client_backend::data_api::WalletWrite::clear_locked_outputs
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
/// [`WalletWrite::lock_outputs`] contract, which prevents selection "at any height less than or
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
/// [`WalletWrite::lock_outputs`]: zcash_client_backend::data_api::WalletWrite::lock_outputs
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
}
