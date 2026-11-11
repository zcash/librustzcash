//! Adds `orchard_change` to `orchard_ironwood_migration_transactions` — the value a migration
//! transaction returns to the Orchard pool as change, `NULL` for a transaction that produces none,
//! which is every row this migration finds — and recreates `v_migration_transactions` so a
//! transfer's `value_received` includes that change, its `fee` is the fee buffer net of it, and
//! `has_change` reports whether it has any. `v_transactions_with_pending_migrations` selects from
//! that view by name, so its stored text is unchanged and it is not recreated.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::{fix_v_transactions_multi_account_totals, orchard_ironwood_migration_txid_blob};
use crate::wallet::init::WalletMigrationError;

/// Identifies this migration in the wallet's schema-migration DAG.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x8ab5f970_9898_49db_a48b_87e5f57f48ca);

/// `orchard_ironwood_migration_txid_blob` last rebuilt the table this adds a column to, and
/// `fix_v_transactions_multi_account_totals` last recreated the view that selects from the view
/// this recreates.
pub(super) const DEPENDENCIES: &[Uuid] = &[
    orchard_ironwood_migration_txid_blob::MIGRATION_ID,
    fix_v_transactions_multi_account_totals::MIGRATION_ID,
];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Records the Orchard change of pool-migration transactions and nets it out of their fee."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(&format!(
            "ALTER TABLE orchard_ironwood_migration_transactions ADD COLUMN orchard_change INTEGER;
             DROP VIEW v_migration_transactions;
             {};",
            crate::pool_migration::orchard_ironwood::migration_tx_view_sql(),
        ))?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, named_params};
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;

    use super::*;
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// The per-note fee buffer of the fixture migration: the canonical crossing fee before
    /// ZIP 2009 (three logical actions at 5000 zatoshis).
    const FEE_BUFFER: u64 = 15_000;
    /// The crossing value of the fixture transfers.
    const CROSSING: u64 = 100_000;
    /// The change a transfer built at the ZIP 2009 fee (three logical actions at 1000 zatoshis)
    /// returns from that buffer.
    const ORCHARD_CHANGE: u64 = 12_000;

    /// Insert a proved transfer of the fixture migration in the shape every row has before this
    /// migration runs.
    fn insert_transfer(conn: &Connection, transfer_id: u32, scheduled_height: u32, txid: &[u8]) {
        conn.execute(
            "INSERT INTO orchard_ironwood_migration_transactions
                (migration_id, transfer_id, kind, kind_crossing, pczt, scheduled_height,
                 expiry_height, state, txid)
             VALUES (10, :transfer_id, 'transfer', 0, X'02', :scheduled_height, 40000, 'proved',
                     :txid)",
            named_params![
                ":transfer_id": transfer_id,
                ":scheduled_height": scheduled_height,
                ":txid": txid,
            ],
        )
        .unwrap();
    }

    /// A wallet upgraded with a transfer already stored reads that row as `NULL` change and
    /// projects it as before (its whole fee buffer is its fee), while a transfer stored with
    /// `orchard_change` afterwards projects the change as received and the fee net of it, in both
    /// the dedicated view and the union view's balance columns.
    #[test]
    fn rows_report_fee_net_of_orchard_change() {
        let network = Network::TestNetwork;
        let seed = [0xab; 32];
        let data_file = NamedTempFile::new().unwrap();
        let mut db = WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();
        WalletMigrator::new()
            .with_seed(Secret::new(seed.to_vec()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db, DEPENDENCIES)
            .unwrap();
        // The migrator checks every account's keys against the network, so the UIVK is a real one.
        let uivk = UnifiedSpendingKey::from_seed(&network, &seed, zip32::AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key()
            .to_unified_incoming_viewing_key()
            .encode(&network)
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO accounts (id, uuid, account_kind, uivk, birthday_height)
                 VALUES (1, X'11', 1, :uivk, 0)",
                named_params![":uivk": uivk],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO orchard_ironwood_migrations
                    (id, account_id, status, note_split_fee_buffer, note_split_change,
                     note_split_prep_fees, note_split_total_input, note_split_total_migratable,
                     uuid)
                 VALUES (10, 1, 'in_progress', :fee_buffer, NULL, 30000, 500000, 400000, X'AA')",
                named_params![":fee_buffer": FEE_BUFFER],
            )
            .unwrap();
        db.conn
            .execute(
                "INSERT INTO orchard_ironwood_migration_crossing_values
                    (migration_id, ordinal, value) VALUES (10, 0, :crossing)",
                named_params![":crossing": CROSSING],
            )
            .unwrap();
        insert_transfer(&db.conn, 0, 1100, &[0xA1]);

        WalletMigrator::new()
            .with_seed(Secret::new(seed.to_vec()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db, &[MIGRATION_ID])
            .unwrap();

        insert_transfer(&db.conn, 1, 1200, &[0xA2]);
        db.conn
            .execute(
                "UPDATE orchard_ironwood_migration_transactions SET orchard_change = :change
                  WHERE transfer_id = 1",
                named_params![":change": ORCHARD_CHANGE],
            )
            .unwrap();

        let rows: Vec<(i64, i64, i64, i64)> = db
            .conn
            .prepare(
                "SELECT value_spent, value_received, fee, has_change
                   FROM v_migration_transactions ORDER BY scheduled_height",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let spent = (CROSSING + FEE_BUFFER) as i64;
        let net_fee = (FEE_BUFFER - ORCHARD_CHANGE) as i64;
        assert_eq!(
            rows,
            vec![
                (spent, CROSSING as i64, FEE_BUFFER as i64, 0),
                (spent, (CROSSING + ORCHARD_CHANGE) as i64, net_fee, 1),
            ]
        );

        let union_rows: Vec<(i64, i64, i64, i64, i64)> = db
            .conn
            .prepare(
                "SELECT total_spent, total_received, fee_paid, account_balance_delta, has_change
                   FROM v_transactions_with_pending_migrations ORDER BY total_received",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            union_rows,
            vec![
                (spent, CROSSING as i64, FEE_BUFFER as i64, -(FEE_BUFFER as i64), 0),
                (spent, (CROSSING + ORCHARD_CHANGE) as i64, net_fee, -net_fee, 1),
            ]
        );
    }
}
