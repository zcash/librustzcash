//! Functions for transparent input support in the wallet.
use std::collections::HashSet;

use rusqlite::{named_params, Connection};
use zcash_primitives::transaction::components::OutPoint;

use crate::AccountId;

pub(crate) fn detect_spending_accounts<'a>(
    conn: &Connection,
    spent: impl Iterator<Item = &'a OutPoint>,
) -> Result<HashSet<AccountId>, rusqlite::Error> {
    let mut account_q = conn.prepare_cached(
        "SELECT received_by_account_id
        FROM utxos
        WHERE prevout_txid = :prevout_txid
        AND prevout_idx = :prevout_idx",
    )?;

    let mut acc = HashSet::new();
    for prevout in spent {
        for account in account_q.query_and_then(
            named_params![
                ":prevout_txid": prevout.hash(),
                ":prevout_idx": prevout.n()
            ],
            |row| row.get::<_, u32>(0).map(AccountId),
        )? {
            acc.insert(account?);
        }
    }

    Ok(acc)
}
