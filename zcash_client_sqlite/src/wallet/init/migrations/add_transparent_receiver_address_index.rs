//! Adds a `UNIQUE` index on `addresses.cached_transparent_receiver_address`.
//!
//! The `addresses` table stores `cached_transparent_receiver_address` as a denormalized cache of
//! the transparent receiver for each row that represents (or contains) a transparent address.
//! Lookups by this value — for example, resolving the account that controls a transparent address
//! during scanning and transaction construction — previously had no supporting index and so
//! required a full table scan, which becomes a severe bottleneck for wallets that hold very large
//! numbers of transparent addresses.
//!
//! In addition to making these lookups index-backed, the `UNIQUE` constraint enforces the
//! invariant that a given transparent receiver is associated with at most one address record.
//! Any pre-existing duplicates (for example, the same address both HD-derived and standalone
//! imported) are resolved by the migration: a single canonical record is retained, the
//! received-output foreign keys of the others are repointed to it, and the redundant records are
//! deleted. A receiver duplicated across more than one account cannot be safely merged and aborts
//! the migration. `NULL` values do not participate in SQLite's `UNIQUE` semantics, so rows without
//! a transparent receiver are unaffected.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::standalone_p2sh;
use crate::wallet::init::WalletMigrationError;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x3d4f12d6_3da9_4ace_ac65_a0dd0a7adc32);

// `standalone_p2sh` is the topologically-latest migration that rebuilds the `addresses` table, so
// depending on it is sufficient to ensure the table is in its final form (including the
// `cached_transparent_receiver_address` column) before this index is created. No later migration
// modifies the `addresses` table, so the index will not be dropped by a subsequent table rebuild.
const DEPENDENCIES: &[Uuid] = &[standalone_p2sh::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a UNIQUE index on addresses.cached_transparent_receiver_address."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Resolve any pre-existing violations of the uniqueness invariant before adding the
        // constraint, so that a database that already contains duplicate transparent receivers is
        // repaired in place rather than rendered permanently unopenable. For each transparent
        // receiver associated with more than one address record, we keep a single canonical record
        // (preferring an HD-derived record, which is recoverable from the seed, over an imported
        // one, and breaking ties by lowest id), repoint every received-output foreign key to it,
        // and delete the redundant records. A receiver associated with records in more than one
        // account cannot be safely merged, so in that case we abort the migration.
        let mut duplicates_stmt = transaction.prepare(
            "SELECT cached_transparent_receiver_address
             FROM addresses
             WHERE cached_transparent_receiver_address IS NOT NULL
             GROUP BY cached_transparent_receiver_address
             HAVING COUNT(*) > 1",
        )?;
        let duplicate_addrs = duplicates_stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(duplicates_stmt);

        for addr in duplicate_addrs {
            // The address records sharing this receiver, ordered so that the canonical record
            // (HD-derived before imported, then lowest id) comes first.
            let mut group_stmt = transaction.prepare(
                "SELECT id, account_id
                 FROM addresses
                 WHERE cached_transparent_receiver_address = :addr
                 ORDER BY (transparent_child_index IS NULL), id",
            )?;
            let group = group_stmt
                .query_map(named_params! { ":addr": addr }, |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(group_stmt);

            let (canonical_id, canonical_account) = group[0];

            // A receiver duplicated across accounts cannot be safely merged: the received outputs
            // referencing each record carry their own `account_id`, which would no longer match
            // the kept address record.
            if group
                .iter()
                .any(|(_, account_id)| *account_id != canonical_account)
            {
                return Err(WalletMigrationError::CorruptedData(format!(
                    "The transparent address {addr} is associated with address records in more \
                     than one account; this cannot be resolved automatically."
                )));
            }

            // Carry the earliest observed exposure across the merged records onto the canonical
            // one, so that upgrading an imported receiver to its derived form does not discard an
            // earlier exposure height recorded against the imported record. Run this before
            // deleting the redundant rows, while the whole group is still present.
            transaction.execute(
                "UPDATE addresses
                 SET exposed_at_height = (
                     SELECT MIN(exposed_at_height)
                     FROM addresses
                     WHERE cached_transparent_receiver_address = :addr
                 )
                 WHERE id = :canonical",
                named_params! { ":addr": addr, ":canonical": canonical_id },
            )?;

            for (dup_id, _) in group.iter().skip(1) {
                for table in [
                    "transparent_received_outputs",
                    "sapling_received_notes",
                    "orchard_received_notes",
                ] {
                    transaction.execute(
                        &format!(
                            "UPDATE {table} SET address_id = :canonical WHERE address_id = :dup"
                        ),
                        named_params! { ":canonical": canonical_id, ":dup": dup_id },
                    )?;
                }
                transaction.execute(
                    "DELETE FROM addresses WHERE id = :dup",
                    named_params! { ":dup": dup_id },
                )?;
            }
        }

        transaction.execute_batch(
            "CREATE UNIQUE INDEX idx_addresses_cached_transparent_receiver_address
                 ON addresses (cached_transparent_receiver_address ASC);",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// Inserts a test account at the given ZIP 32 account index with a valid UFVK/UIVK (so that the
    /// migrator's network-compatibility check passes) and returns its row id.
    fn insert_account(conn: &rusqlite::Connection, account_index: u32, uuid: [u8; 16]) -> i64 {
        let network = Network::TestNetwork;
        let seed_bytes = [0xab; 32];
        let usk = UnifiedSpendingKey::from_seed(
            &network,
            &seed_bytes[..],
            zip32::AccountId::try_from(account_index).unwrap(),
        )
        .unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let ufvk_str = ufvk.encode(&network);
        let uivk_str = ufvk.to_unified_incoming_viewing_key().encode(&network);

        conn.execute(
            "INSERT INTO accounts (uuid, account_kind, hd_seed_fingerprint,
                 hd_account_index, ufvk, uivk, has_spend_key, birthday_height)
                 VALUES (?1, 0,
                 X'00000000000000000000000000000000000000000000000000000000000000AB',
                 ?2, ?3, ?4, 1, 1)",
            rusqlite::params![uuid.to_vec(), account_index, ufvk_str, uivk_str],
        )
        .unwrap();

        conn.last_insert_rowid()
    }

    /// After the migration, two derived addresses that share a transparent receiver must be
    /// rejected, while rows with a `NULL` receiver remain unconstrained.
    #[test]
    fn enforces_uniqueness() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        let account_id = insert_account(&db_data.conn, 0, [0xAA; 16]);

        // A derived transparent address with cached receiver `t_shared`.
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
                 transparent_child_index, cached_transparent_receiver_address, receiver_flags)
                 VALUES (?1, 0, X'00000000000000000000000000', 'addr_a', 0, 't_shared', 5)",
                [account_id],
            )
            .unwrap();

        // A second, distinct address row that reuses the same transparent receiver must be
        // rejected by the new UNIQUE index.
        let duplicate = db_data.conn.execute(
            "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
             transparent_child_index, cached_transparent_receiver_address, receiver_flags)
             VALUES (?1, 0, X'00000000000000000000000001', 'addr_b', 1, 't_shared', 5)",
            [account_id],
        );
        assert_matches!(duplicate, Err(_));

        // Rows with a NULL transparent receiver are not constrained: multiple are allowed.
        for div in [
            "X'00000000000000000000000010'",
            "X'00000000000000000000000011'",
        ] {
            db_data
                .conn
                .execute(
                    &format!(
                        "INSERT INTO addresses (account_id, key_scope, diversifier_index_be,
                         address, receiver_flags)
                         VALUES (?1, 0, {div}, 'addr_shielded', 0)"
                    ),
                    [account_id],
                )
                .unwrap();
        }
    }

    /// A database that already contains a transparent receiver duplicated within a single account
    /// (for example, the same address both HD-derived and standalone-imported) is repaired by the
    /// migration: the HD-derived record is retained, the imported record's received-output foreign
    /// keys are repointed to it, and the imported record is deleted.
    #[test]
    fn resolves_preexisting_duplicates() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        // Migrate to the state just prior to this migration (no UNIQUE index yet).
        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        let account_id = insert_account(&db_data.conn, 0, [0xAA; 16]);

        // An HD-derived record for the shared receiver (the canonical record we expect to keep).
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
                 transparent_child_index, cached_transparent_receiver_address, receiver_flags)
                 VALUES (?1, 0, X'00000000000000000000000000', 'addr_derived', 0, 't_dup', 5)",
                [account_id],
            )
            .unwrap();
        let derived_id = db_data.conn.last_insert_rowid();

        // A standalone-imported record for the same receiver (to be merged away).
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, address,
                 cached_transparent_receiver_address, imported_transparent_receiver_pubkey,
                 receiver_flags)
                 VALUES (?1, -1, 'addr_imported', 't_dup',
                 X'020000000000000000000000000000000000000000000000000000000000000001', 5)",
                [account_id],
            )
            .unwrap();
        let imported_id = db_data.conn.last_insert_rowid();

        // A received output that references the imported (non-canonical) record.
        db_data
            .conn
            .execute(
                "INSERT INTO transactions (id_tx, txid, min_observed_height) VALUES (1, X'00', 1)",
                [],
            )
            .unwrap();
        db_data
            .conn
            .execute(
                "INSERT INTO transparent_received_outputs
                 (transaction_id, output_index, account_id, address, script, value_zat, address_id)
                 VALUES (1, 0, ?1, 't_dup', X'00', 100000, ?2)",
                rusqlite::params![account_id, imported_id],
            )
            .unwrap();

        // The migration repairs the duplicate rather than failing.
        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        // Only the derived record remains for the shared receiver.
        let mut stmt = db_data
            .conn
            .prepare("SELECT id FROM addresses WHERE cached_transparent_receiver_address = 't_dup'")
            .unwrap();
        let remaining: Vec<i64> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(remaining, vec![derived_id]);
        drop(stmt);

        // The received output now references the canonical (derived) record.
        let repointed: i64 = db_data
            .conn
            .query_row(
                "SELECT address_id FROM transparent_received_outputs
                 WHERE transaction_id = 1 AND output_index = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(repointed, derived_id);

        // The imported record is gone.
        let imported_count: i64 = db_data
            .conn
            .query_row(
                "SELECT COUNT(*) FROM addresses WHERE id = ?1",
                [imported_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(imported_count, 0);
    }

    /// When repairing a duplicate, the surviving canonical record keeps the earliest
    /// `exposed_at_height` observed across the merged records.
    #[test]
    fn repair_carries_min_exposed_at_height() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        let account_id = insert_account(&db_data.conn, 0, [0xAA; 16]);

        // Derived (canonical) record exposed at height 200.
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
                 transparent_child_index, cached_transparent_receiver_address, receiver_flags,
                 exposed_at_height)
                 VALUES (?1, 0, X'00000000000000000000000000', 'addr_derived', 0, 't_exp', 5, 200)",
                [account_id],
            )
            .unwrap();
        let derived_id = db_data.conn.last_insert_rowid();

        // Imported record exposed earlier, at height 100.
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, address,
                 cached_transparent_receiver_address, imported_transparent_receiver_pubkey,
                 receiver_flags, exposed_at_height)
                 VALUES (?1, -1, 'addr_imported', 't_exp',
                 X'020000000000000000000000000000000000000000000000000000000000000001', 5, 100)",
                [account_id],
            )
            .unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        // The canonical (derived) record now carries the earliest exposure.
        let exposed: Option<i64> = db_data
            .conn
            .query_row(
                "SELECT exposed_at_height FROM addresses WHERE id = ?1",
                [derived_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(exposed, Some(100));
    }

    /// A transparent receiver duplicated across more than one account cannot be safely merged, so
    /// the migration aborts.
    #[test]
    fn rejects_cross_account_duplicates() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        let account_0 = insert_account(&db_data.conn, 0, [0xAA; 16]);
        let account_1 = insert_account(&db_data.conn, 1, [0xBB; 16]);

        // The same receiver associated with a derived record in each of two distinct accounts.
        for (account_id, addr) in [(account_0, "addr_0"), (account_1, "addr_1")] {
            db_data
                .conn
                .execute(
                    &format!(
                        "INSERT INTO addresses (account_id, key_scope, diversifier_index_be,
                         address, transparent_child_index, cached_transparent_receiver_address,
                         receiver_flags)
                         VALUES (?1, 0, X'00000000000000000000000000', '{addr}', 0, 't_cross', 5)"
                    ),
                    [account_id],
                )
                .unwrap();
        }

        let result = WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID]);
        assert_matches!(result, Err(_));
    }
}
