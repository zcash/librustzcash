//! Functions for initializing the various databases.

use rusqlite::NO_PARAMS;
use std::path::Path;

use crate::{BlockDb, FsBlockDb};

/// Sets up the internal structure of the cache database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{
///     BlockDb,
///     chain::init::init_cache_database,
/// };
///
/// let cache_file = NamedTempFile::new().unwrap();
/// let db = BlockDb::for_path(cache_file.path()).unwrap();
/// init_cache_database(&db).unwrap();
/// ```
pub fn init_cache_database(db_cache: &BlockDb) -> Result<(), rusqlite::Error> {
    db_cache.0.execute(
        "CREATE TABLE IF NOT EXISTS compactblocks (
            height INTEGER PRIMARY KEY,
            data BLOB NOT NULL
        )",
        NO_PARAMS,
    )?;
    Ok(())
}

/// Sets up the internal structure of the metadata cache database.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use tempfile::{NamedTempFile, tempdir};
/// use zcash_client_sqlite::{
///     FsBlockDb,
///     chain::init::init_cachemeta_db,
/// };
///
/// let cache_file = NamedTempFile::new().unwrap();
/// let blocks_dir = tempdir().unwrap();
/// let db = FsBlockDb::for_paths(cache_file.path(), blocks_dir.path()).unwrap();
/// init_cachemeta_db(&db).unwrap();
/// ```
pub fn init_cachemeta_db<P: AsRef<Path>>(db_cache: &FsBlockDb<P>) -> Result<(), rusqlite::Error> {
    db_cache.conn.execute(
        "CREATE TABLE IF NOT EXISTS compactblocks_meta (
            height INTEGER PRIMARY KEY,
            blockhash BLOB NOT NULL,
            time INTEGER NOT NULL,
            sapling_outputs_count INTEGER NOT NULL,
            orchard_actions_count INTEGER NOT NULL
        )",
        NO_PARAMS,
    )?;
    Ok(())
}
