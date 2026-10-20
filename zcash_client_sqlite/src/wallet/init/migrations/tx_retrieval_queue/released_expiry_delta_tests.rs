//! Tests that pin the expiry delta this migration was released with.

use rusqlite::named_params;
use secrecy::Secret;
use tempfile::NamedTempFile;

use zcash_protocol::consensus::Network;

use crate::{
    WalletDb,
    testing::db::{test_clock, test_rng},
    wallet::init::WalletMigrator,
};

use super::{DEPENDENCIES, MIGRATION_ID};

/// The migration estimates the target height of each wallet-created transaction as its
/// expiry height less the default expiry delta in effect when the migration was released.
#[test]
fn migrate_estimates_target_height_from_the_released_expiry_delta() {
    /// The default expiry delta, in blocks, in effect when this migration was released.
    const RELEASED_DEFAULT_EXPIRY_DELTA: u32 = 40;
    /// Expiry height of the wallet-created transaction inserted below.
    const EXPIRY_HEIGHT: u32 = 2_000_000;
    /// Txid of the wallet-created transaction inserted below.
    const TXID: [u8; 32] = [1; 32];
    /// Creation time of the transaction inserted below; only its presence matters.
    const CREATED: &str = "2024-01-01 00:00:00";
    /// An arbitrary wallet seed; the wallet has no accounts.
    const SEED: [u8; 32] = [0xab; 32];

    let data_file = NamedTempFile::new().unwrap();
    let mut db_data = WalletDb::for_path(
        data_file.path(),
        Network::TestNetwork,
        test_clock(),
        test_rng(),
    )
    .unwrap();

    WalletMigrator::new()
        .with_seed(Secret::new(SEED.to_vec()))
        .ignore_seed_relevance()
        .init_or_migrate_to(&mut db_data, DEPENDENCIES)
        .unwrap();

    db_data
        .conn
        .execute(
            "INSERT INTO transactions (txid, created, expiry_height)
             VALUES (:txid, :created, :expiry_height)",
            named_params! {
                ":txid": &TXID[..],
                ":created": CREATED,
                ":expiry_height": EXPIRY_HEIGHT,
            },
        )
        .unwrap();

    WalletMigrator::new()
        .with_seed(Secret::new(SEED.to_vec()))
        .ignore_seed_relevance()
        .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
        .unwrap();

    let target_height: u32 = db_data
        .conn
        .query_row(
            "SELECT target_height FROM transactions WHERE txid = :txid",
            named_params! {":txid": &TXID[..]},
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(target_height, EXPIRY_HEIGHT - RELEASED_DEFAULT_EXPIRY_DELTA);
}
