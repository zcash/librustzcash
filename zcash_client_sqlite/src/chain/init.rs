//! Functions for initializing the various databases.
use crate::BlockDb;

#[cfg(feature = "unstable")]
use {
    super::migrations,
    crate::FsBlockDb,
    schemerz::{Migrator, MigratorError},
    schemerz_rusqlite::RusqliteAdapter,
};

/// Sets up the internal structure of the cache database.
///
/// # Examples
///
/// ```
/// # let rt = tokio::runtime::Runtime::new().unwrap();
/// # rt.block_on(async {
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{
///     BlockDb,
///     chain::init::init_cache_database,
/// };
///
/// let cache_file = NamedTempFile::new().unwrap();
/// let db = BlockDb::for_path(cache_file.path()).unwrap();
/// init_cache_database(&db).await.unwrap();
/// # });
/// ```
pub async fn init_cache_database(db_cache: &BlockDb) -> Result<(), rusqlite::Error> {
    db_cache.0.lock().await.execute(
        "CREATE TABLE IF NOT EXISTS compactblocks (
            height INTEGER PRIMARY KEY,
            data BLOB NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Sets up the internal structure of the metadata cache database.
///
/// This will automatically apply any available migrations that have not yet been applied to the
/// database as part of its operation.
///
/// # Examples
///
/// ```
/// # let rt = tokio::runtime::Runtime::new().unwrap();
/// # rt.block_on(async {
/// use tempfile::{tempdir, NamedTempFile};
/// use zcash_client_sqlite::{
///     FsBlockDb,
///     chain::init::init_blockmeta_db,
/// };
///
/// let cache_file = NamedTempFile::new().unwrap();
/// let blocks_dir = tempdir().unwrap();
/// let mut db = FsBlockDb::for_path(blocks_dir.path()).unwrap();
/// init_blockmeta_db(&mut db).await.unwrap();
/// # });
/// ```
#[cfg(feature = "unstable")]
pub async fn init_blockmeta_db(
    db: &mut FsBlockDb,
) -> Result<(), MigratorError<uuid::Uuid, rusqlite::Error>> {
    let mut connector = db.conn.lock().await;
    let adapter = RusqliteAdapter::new(&mut connector, Some("schemer_migrations".to_string()));
    adapter.init().expect("Migrations table setup succeeds.");

    let mut migrator = Migrator::new(adapter);
    migrator
        .register_multiple(migrations::blockmeta::all_migrations().into_iter())
        .expect("Migration registration should have been successful.");
    migrator.up(None)?;
    Ok(())
}
