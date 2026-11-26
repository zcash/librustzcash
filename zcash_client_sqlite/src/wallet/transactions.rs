//! Local transaction abandonment and reconciliation with network observations.

use std::collections::HashSet;

use rusqlite::{OptionalExtension, named_params};
use zcash_protocol::{TxId, consensus::BlockHeight};

use crate::{TxRef, error::SqliteClientError};

use super::queue_tx_status;

/// Note/output and spend-table names for each stored pool, including feature-disabled pools.
const POOLS: &[(&str, &str, &str)] = &[
    (
        "sapling_received_notes",
        "sapling_received_note_spends",
        "sapling_received_note_id",
    ),
    (
        "orchard_received_notes",
        "orchard_received_note_spends",
        "orchard_received_note_id",
    ),
    (
        "ironwood_received_notes",
        "ironwood_received_note_spends",
        "ironwood_received_note_id",
    ),
    (
        "transparent_received_outputs",
        "transparent_received_output_spends",
        "transparent_received_output_id",
    ),
];

/// Conflicts involving transparent inputs whose prevouts were not yet recognized.
const TRANSPARENT_MAP_CONFLICTS: &[&str] = &[
    "SELECT other.spending_transaction_id
     FROM transparent_spend_map ours JOIN transparent_spend_map other
       ON other.prevout_txid = ours.prevout_txid
      AND other.prevout_output_index = ours.prevout_output_index
     WHERE ours.spending_transaction_id = ?",
    "SELECT other.transaction_id
     FROM transparent_spend_map ours
     JOIN transactions parent ON parent.txid = ours.prevout_txid
     JOIN transparent_received_outputs n
       ON n.transaction_id = parent.id_tx AND n.output_index = ours.prevout_output_index
     JOIN transparent_received_output_spends other ON other.transparent_received_output_id = n.id
     WHERE ours.spending_transaction_id = ?",
    "SELECT other.spending_transaction_id
     FROM transparent_received_output_spends ours
     JOIN transparent_received_outputs n ON n.id = ours.transparent_received_output_id
     JOIN transactions parent ON parent.id_tx = n.transaction_id
     JOIN transparent_spend_map other
       ON other.prevout_txid = parent.txid AND other.prevout_output_index = n.output_index
     WHERE ours.transaction_id = ?",
];

struct StoredTransaction {
    id: TxRef,
    txid: TxId,
    mined_height: Option<BlockHeight>,
}

#[derive(Clone, Copy)]
enum Direction {
    Ancestors,
    Descendants,
}

pub(crate) fn get_tx_ref(
    conn: &rusqlite::Connection,
    txid: TxId,
) -> Result<Option<TxRef>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT id_tx FROM transactions WHERE txid = ?",
            [txid.as_ref()],
            |row| row.get(0).map(TxRef),
        )
        .optional()?)
}

/// Includes the root and follows each dependency at most once.
fn related(
    conn: &rusqlite::Connection,
    root: TxRef,
    direction: Direction,
) -> Result<Vec<StoredTransaction>, SqliteClientError> {
    let (source, destination) = match direction {
        Direction::Ancestors => ("s.transaction_id", "n.transaction_id"),
        Direction::Descendants => ("n.transaction_id", "s.transaction_id"),
    };
    let mut pending = vec![root];
    let mut visited = HashSet::new();
    let mut result = Vec::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let tx = conn.query_row(
            "SELECT txid, mined_height FROM transactions WHERE id_tx = ?",
            [id.0],
            |row| {
                Ok(StoredTransaction {
                    id,
                    txid: TxId::from_bytes(row.get(0)?),
                    mined_height: row.get::<_, Option<u32>>(1)?.map(BlockHeight::from),
                })
            },
        )?;
        let stop =
            id != root && matches!(direction, Direction::Ancestors) && tx.mined_height.is_some();
        result.push(tx);
        if stop {
            continue;
        }
        // Query each pool from its transaction-id indexes. Joining the cross-pool UNION
        // views instead would materialize the wallet's entire output history at each step.
        for (notes, spends, output_id) in POOLS {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {destination}
                 FROM {notes} n JOIN {spends} s ON s.{output_id} = n.id
                 WHERE {source} = :root"
            ))?;
            pending.extend(
                stmt.query_map(named_params![":root": id.0], |row| row.get(0).map(TxRef))?
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        // A stored transaction can depend on a transparent prevout whose ownership is
        // not yet known, or that does not belong to this wallet at all.
        let (source, destination) = match direction {
            Direction::Ancestors => ("s.spending_transaction_id", "t.id_tx"),
            Direction::Descendants => ("t.id_tx", "s.spending_transaction_id"),
        };
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {destination}
             FROM transparent_spend_map s JOIN transactions t ON t.txid = s.prevout_txid
             WHERE {source} = ?"
        ))?;
        pending.extend(
            stmt.query_map([id.0], |row| row.get(0).map(TxRef))?
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    Ok(result)
}

fn mark_abandoned(
    conn: &rusqlite::Transaction<'_>,
    transactions: &[StoredTransaction],
) -> Result<(), SqliteClientError> {
    // Validate the entire closure before changing any of it.
    if let Some(tx) = transactions.iter().find(|tx| tx.mined_height.is_some()) {
        return Err(SqliteClientError::TransactionMined(tx.txid));
    }
    for tx in transactions {
        let changed = conn.execute(
            "UPDATE transactions SET abandoned = 1 WHERE id_tx = ? AND abandoned = 0",
            [tx.id.0],
        )?;
        if changed == 0 {
            continue;
        }
        // Preserve existing observation intents, but avoid adding txid probes for
        // transactions that the wallet can discover privately through compact-block scanning.
        let detectable: bool = conn.query_row(
            "SELECT EXISTS (
                 SELECT 1 FROM sapling_received_notes WHERE transaction_id = :id
                 UNION ALL
                 SELECT 1 FROM sapling_received_note_spends WHERE transaction_id = :id
                 UNION ALL
                 SELECT 1 FROM orchard_received_notes
                     WHERE :orchard_enabled AND transaction_id = :id
                 UNION ALL
                 SELECT 1 FROM orchard_received_note_spends
                     WHERE :orchard_enabled AND transaction_id = :id
                 UNION ALL
                 SELECT 1 FROM ironwood_received_notes
                     WHERE :orchard_enabled AND transaction_id = :id
                 UNION ALL
                 SELECT 1 FROM ironwood_received_note_spends
                     WHERE :orchard_enabled AND transaction_id = :id
             )",
            named_params![":id": tx.id.0, ":orchard_enabled": cfg!(feature = "orchard")],
            |row| row.get(0),
        )?;
        if !detectable {
            queue_tx_status(conn, tx.txid)?;
        }
    }
    Ok(())
}

pub(crate) fn abandon(
    conn: &rusqlite::Transaction<'_>,
    txid: TxId,
) -> Result<(), SqliteClientError> {
    let root = get_tx_ref(conn, txid)?.ok_or(SqliteClientError::TransactionUnknown(txid))?;
    mark_abandoned(conn, &related(conn, root, Direction::Descendants)?)
}

/// Reactivates a positively observed transaction and its ancestors, abandoning competing
/// unmined spends and their descendants. Descendants of the observed transaction stay unchanged.
pub(crate) fn observe(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: TxRef,
) -> Result<(), SqliteClientError> {
    let ancestors = related(conn, tx_ref, Direction::Ancestors)?;
    let ancestor_ids: HashSet<_> = ancestors.iter().map(|tx| tx.id).collect();
    let root_mined = ancestors
        .iter()
        .any(|tx| tx.id == tx_ref && tx.mined_height.is_some());
    let mut competitors = HashSet::new();
    for ancestor in &ancestors {
        for (_, spends, output_id) in POOLS {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT other.transaction_id
                 FROM {spends} ours JOIN {spends} other
                   ON other.{output_id} = ours.{output_id}
                 WHERE ours.transaction_id = ?"
            ))?;
            for competitor in stmt.query_map([ancestor.id.0], |row| row.get(0).map(TxRef))? {
                let competitor = competitor?;
                if !ancestor_ids.contains(&competitor) {
                    competitors.insert(competitor);
                }
            }
        }
        for sql in TRANSPARENT_MAP_CONFLICTS {
            let mut stmt = conn.prepare_cached(sql)?;
            for competitor in stmt.query_map([ancestor.id.0], |row| row.get(0).map(TxRef))? {
                let competitor = competitor?;
                if !ancestor_ids.contains(&competitor) {
                    competitors.insert(competitor);
                }
            }
        }
    }
    let mut losing_transactions = Vec::new();
    for competitor in competitors {
        losing_transactions.extend(related(conn, competitor, Direction::Descendants)?);
    }
    if let Some(mined) = losing_transactions
        .iter()
        .find(|tx| tx.mined_height.is_some())
    {
        // An out-of-date mempool observation must not override the wallet's chain view.
        if !root_mined {
            return Ok(());
        }
        return Err(SqliteClientError::TransactionMined(mined.txid));
    }
    mark_abandoned(conn, &losing_transactions)?;
    for ancestor in ancestors {
        conn.execute(
            "UPDATE transactions SET abandoned = 0 WHERE id_tx = ? AND abandoned = 1",
            [ancestor.id.0],
        )?;
    }
    Ok(())
}

/// Reconciles newly discovered spend relationships only when the spender is mined.
pub(crate) fn observe_mined(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: TxRef,
) -> Result<(), SqliteClientError> {
    let mined: bool = conn.query_row(
        "SELECT mined_height IS NOT NULL FROM transactions WHERE id_tx = ?",
        [tx_ref.0],
        |row| row.get(0),
    )?;
    if mined {
        observe(conn, tx_ref)?;
    }
    Ok(())
}

/// Propagates abandonment when a previously unknown transparent dependency is linked.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn inherit_abandonment(
    conn: &rusqlite::Transaction<'_>,
    spender: TxRef,
    parent: TxId,
) -> Result<(), SqliteClientError> {
    let txid = conn
        .query_row(
            "SELECT child.txid FROM transactions child
         WHERE child.id_tx = :spender AND child.mined_height IS NULL
           AND EXISTS (
               SELECT 1 FROM transactions parent
               WHERE parent.txid = :parent AND parent.abandoned = 1
                 AND parent.mined_height IS NULL
           )",
            named_params![":spender": spender.0, ":parent": parent.as_ref()],
            |row| row.get(0).map(TxId::from_bytes),
        )
        .optional()?;
    if let Some(txid) = txid {
        abandon(conn, txid)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
