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
//! deleted. A receiver duplicated across more than one account is resolved by derivation: if
//! exactly one of the records reproduces the receiver when its address is derived from its own
//! account's viewing key at its recorded child index, that record is definitively correct and is
//! retained (with the received outputs of the others reattributed to it); otherwise the conflict
//! cannot be resolved automatically and the migration aborts. `NULL` values do not participate in
//! SQLite's `UNIQUE` semantics, so rows without a transparent receiver are unaffected.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus;

use super::standalone_p2sh;
use crate::wallet::init::WalletMigrationError;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x3d4f12d6_3da9_4ace_ac65_a0dd0a7adc32);

// `standalone_p2sh` is the topologically-latest migration that rebuilds the `addresses` table, so
// depending on it is sufficient to ensure the table is in its final form (including the
// `cached_transparent_receiver_address` column) before this index is created. No later migration
// modifies the `addresses` table, so the index will not be dropped by a subsequent table rebuild.
const DEPENDENCIES: &[Uuid] = &[standalone_p2sh::MIGRATION_ID];

pub(super) struct Migration<P> {
    pub(super) params: P,
}

/// An address record participating in a duplicated-receiver group: its row id, its account's row
/// id, its key scope code, its transparent child index, and its account's UFVK and UIVK
/// encodings.
type AddressRecord = (i64, i64, i64, Option<u32>, Option<String>, String);

/// The error reported when a duplicated receiver cannot be resolved automatically.
fn unresolvable_duplicate(addr: &str) -> WalletMigrationError {
    WalletMigrationError::CorruptedData(format!(
        "The transparent address {addr} is associated with address records in more \
         than one account; this cannot be resolved automatically."
    ))
}

/// Whether deriving a transparent address from the record's own account viewing key, at the
/// record's key scope and child index, reproduces the duplicated receiver — which definitively
/// establishes the record as the correct one for that receiver.
#[cfg(feature = "transparent-inputs")]
fn record_derives_receiver<P: consensus::Parameters>(
    params: &P,
    key_scope: i64,
    child_index: Option<u32>,
    ufvk: Option<&str>,
    uivk: &str,
    addr: &str,
) -> bool {
    use transparent::keys::{IncomingViewingKey as _, NonHardenedChildIndex};
    use zcash_keys::{
        encoding::AddressCodec as _,
        keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey},
    };

    let Some(idx) = child_index.and_then(NonHardenedChildIndex::from_index) else {
        return false;
    };

    let derived = match key_scope {
        // External scope: prefer the UFVK's account pubkey, falling back to the UIVK's
        // external IVK.
        0 => ufvk
            .and_then(|s| UnifiedFullViewingKey::decode(params, s).ok())
            .and_then(|k| {
                k.transparent()
                    .and_then(|apk| apk.derive_external_ivk().ok())
            })
            .and_then(|ivk| ivk.derive_address(idx).ok())
            .or_else(|| {
                UnifiedIncomingViewingKey::decode(params, uivk)
                    .ok()
                    .and_then(|k| {
                        k.transparent()
                            .as_ref()
                            .and_then(|ivk| ivk.derive_address(idx).ok())
                    })
            }),
        // Internal scope: derivable only from the UFVK's account pubkey.
        1 => ufvk
            .and_then(|s| UnifiedFullViewingKey::decode(params, s).ok())
            .and_then(|k| {
                k.transparent()
                    .and_then(|apk| apk.derive_internal_ivk().ok())
            })
            .and_then(|ivk| ivk.derive_address(idx).ok()),
        // Foreign and ephemeral records cannot be verified by scope derivation.
        _ => None,
    };

    derived.is_some_and(|d| d.encode(params) == addr)
}

/// Resolves a receiver duplicated across more than one account by derivation: the unique record
/// (if any) whose address is reproduced by derivation from its own account's viewing key is
/// definitively the correct one. Returns the winning record's `(id, account_id)`, or an error if
/// no unique record can be verified.
#[cfg(feature = "transparent-inputs")]
fn resolve_cross_account_duplicate<P: consensus::Parameters>(
    params: &P,
    addr: &str,
    group: &[AddressRecord],
) -> Result<(i64, i64), WalletMigrationError> {
    let verified = group
        .iter()
        .filter(|(_, _, key_scope, child_index, ufvk, uivk)| {
            record_derives_receiver(
                params,
                *key_scope,
                *child_index,
                ufvk.as_deref(),
                uivk,
                addr,
            )
        })
        .collect::<Vec<_>>();

    match verified[..] {
        [(id, account_id, ..)] => Ok((*id, *account_id)),
        _ => Err(unresolvable_duplicate(addr)),
    }
}

/// Without `transparent-inputs`, the key APIs needed for derivation-based verification are
/// unavailable, so a cross-account duplicate cannot be resolved automatically.
#[cfg(not(feature = "transparent-inputs"))]
fn resolve_cross_account_duplicate<P: consensus::Parameters>(
    _params: &P,
    addr: &str,
    _group: &[AddressRecord],
) -> Result<(i64, i64), WalletMigrationError> {
    Err(unresolvable_duplicate(addr))
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
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

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Resolve any pre-existing violations of the uniqueness invariant before adding the
        // constraint, so that a database that already contains duplicate transparent receivers is
        // repaired in place rather than rendered permanently unopenable. For each transparent
        // receiver associated with more than one address record within a single account, we keep
        // a single canonical record (preferring an HD-derived record, which is recoverable from
        // the seed, over an imported one, and breaking ties by lowest id). For a receiver
        // duplicated across accounts, the canonical record is the unique one verified by
        // derivation from its own account's viewing key; the received outputs of the redundant
        // records follow the canonical record, including their account attribution.
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
            // The address records sharing this receiver, ordered so that the single-account
            // canonical record (HD-derived before imported, then lowest id) comes first.
            let mut group_stmt = transaction.prepare(
                "SELECT a.id, a.account_id, a.key_scope, a.transparent_child_index,
                        accounts.ufvk, accounts.uivk
                 FROM addresses a
                 JOIN accounts ON accounts.id = a.account_id
                 WHERE a.cached_transparent_receiver_address = :addr
                 ORDER BY (a.transparent_child_index IS NULL), a.id",
            )?;
            let group: Vec<AddressRecord> = group_stmt
                .query_map(named_params! { ":addr": addr }, |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(group_stmt);

            let single_account = group
                .iter()
                .all(|(_, account_id, ..)| *account_id == group[0].1);

            let (canonical_id, canonical_account) = if single_account {
                (group[0].0, group[0].1)
            } else {
                // The received outputs referencing each record carry their own `account_id`, so a
                // cross-account merge is only safe when derivation definitively establishes which
                // record (and thus which account) the receiver belongs to.
                resolve_cross_account_duplicate(&self.params, &addr, &group)?
            };

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

            for (dup_id, ..) in group.iter().filter(|(id, ..)| *id != canonical_id) {
                for table in [
                    "transparent_received_outputs",
                    "sapling_received_notes",
                    "orchard_received_notes",
                ] {
                    transaction.execute(
                        &format!(
                            "UPDATE {table}
                             SET address_id = :canonical, account_id = :canonical_account
                             WHERE address_id = :dup"
                        ),
                        named_params! {
                            ":canonical": canonical_id,
                            ":canonical_account": canonical_account,
                            ":dup": dup_id,
                        },
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

    /// The encoded transparent address actually derivable by the [`insert_account`] test account
    /// at the given ZIP 32 account index, at external child index 0 — i.e. an address for which
    /// derivation-based verification of an address record will succeed.
    #[cfg(feature = "transparent-inputs")]
    fn account_external_address(network: &Network, account_index: u32) -> String {
        use transparent::keys::{IncomingViewingKey as _, NonHardenedChildIndex};
        use zcash_keys::encoding::AddressCodec as _;

        let usk = UnifiedSpendingKey::from_seed(
            network,
            &[0xab; 32][..],
            zip32::AccountId::try_from(account_index).unwrap(),
        )
        .unwrap();
        usk.to_unified_full_viewing_key()
            .transparent()
            .unwrap()
            .derive_external_ivk()
            .unwrap()
            .derive_address(NonHardenedChildIndex::ZERO)
            .unwrap()
            .encode(network)
    }

    /// A receiver duplicated across two accounts is resolved when exactly one of the records is
    /// verified by derivation: deriving from its own account's viewing key at its recorded child
    /// index yields the duplicated receiver. The verified record wins; the other account's record
    /// is deleted, its received outputs are repointed to the winner (including their account
    /// attribution), and the earliest exposure height is preserved.
    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn resolves_cross_account_duplicate_by_derivation() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        let account_a = insert_account(&db_data.conn, 0, [0xAA; 16]);
        let account_l = insert_account(&db_data.conn, 0x7FFF_FFFF, [0xBB; 16]);

        // The receiver genuinely derivable by account A at external index 0.
        let taddr = account_external_address(&network, 0);

        // Account A's derived record for the receiver: verification will succeed.
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
                 transparent_child_index, cached_transparent_receiver_address, receiver_flags,
                 exposed_at_height)
                 VALUES (?1, 0, X'00000000000000000000000000', ?2, 0, ?2, 5, 200)",
                rusqlite::params![account_a, taddr],
            )
            .unwrap();
        let derived_id = db_data.conn.last_insert_rowid();

        // The same receiver imported standalone into the other account, with an earlier
        // exposure height.
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, address,
                 cached_transparent_receiver_address, imported_transparent_receiver_pubkey,
                 receiver_flags, exposed_at_height)
                 VALUES (?1, -1, ?2, ?2,
                 X'020000000000000000000000000000000000000000000000000000000000000002', 5, 100)",
                rusqlite::params![account_l, taddr],
            )
            .unwrap();
        let imported_id = db_data.conn.last_insert_rowid();

        // A received output attached to the imported record, attributed to the other account.
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
                 VALUES (1, 0, ?1, ?2, X'00', 100000, ?3)",
                rusqlite::params![account_l, taddr, imported_id],
            )
            .unwrap();

        // The migration resolves the cross-account duplicate rather than failing.
        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        // Only the derivation-verified record remains, carrying the earliest exposure height.
        let remaining: Vec<(i64, Option<u32>)> = db_data
            .conn
            .prepare(
                "SELECT id, exposed_at_height FROM addresses
                 WHERE cached_transparent_receiver_address = ?1",
            )
            .unwrap()
            .query_map([&taddr], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(remaining, vec![(derived_id, Some(100))]);

        // The received output was repointed to the winning record, and its account attribution
        // moved with it.
        let (address_id, account_id): (i64, i64) = db_data
            .conn
            .query_row(
                "SELECT address_id, account_id FROM transparent_received_outputs
                 WHERE transaction_id = 1 AND output_index = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((address_id, account_id), (derived_id, account_a));
    }

    /// Derivation-based verification is the sole criterion for resolving a cross-account
    /// duplicate: an address genuinely derived under the ZIP 32 account index 0x7FFFFFFF (the
    /// index used for the `zcashd` legacy account) wins over another account's imported record,
    /// exactly as any other account's derived address would.
    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn cross_account_winner_may_be_legacy_account() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        let account_a = insert_account(&db_data.conn, 0, [0xAA; 16]);
        let account_l = insert_account(&db_data.conn, 0x7FFF_FFFF, [0xBB; 16]);

        // The receiver genuinely derivable by the 0x7FFFFFFF-indexed account.
        let taddr = account_external_address(&network, 0x7FFF_FFFF);

        // The 0x7FFFFFFF account's derived record: verification will succeed.
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, diversifier_index_be, address,
                 transparent_child_index, cached_transparent_receiver_address, receiver_flags,
                 exposed_at_height)
                 VALUES (?1, 0, X'00000000000000000000000000', ?2, 0, ?2, 5, 200)",
                rusqlite::params![account_l, taddr],
            )
            .unwrap();
        let derived_id = db_data.conn.last_insert_rowid();

        // The same receiver imported standalone into the other account.
        db_data
            .conn
            .execute(
                "INSERT INTO addresses (account_id, key_scope, address,
                 cached_transparent_receiver_address, imported_transparent_receiver_pubkey,
                 receiver_flags, exposed_at_height)
                 VALUES (?1, -1, ?2, ?2,
                 X'020000000000000000000000000000000000000000000000000000000000000003', 5, 100)",
                rusqlite::params![account_a, taddr],
            )
            .unwrap();
        let imported_id = db_data.conn.last_insert_rowid();

        // A received output attached to the imported record.
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
                 VALUES (1, 0, ?1, ?2, X'00', 100000, ?3)",
                rusqlite::params![account_a, taddr, imported_id],
            )
            .unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        // The 0x7FFFFFFF account's verified record wins, and the output's account attribution
        // follows it.
        let remaining: Vec<i64> = db_data
            .conn
            .prepare("SELECT id FROM addresses WHERE cached_transparent_receiver_address = ?1")
            .unwrap()
            .query_map([&taddr], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(remaining, vec![derived_id]);

        let (address_id, account_id): (i64, i64) = db_data
            .conn
            .query_row(
                "SELECT address_id, account_id FROM transparent_received_outputs
                 WHERE transaction_id = 1 AND output_index = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((address_id, account_id), (derived_id, account_l));
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
