//! Functions for initializing the various databases.

use rusqlite::NO_PARAMS;

use crate::BlockDB;

/// Sets up the internal structure of the cache database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{
///     BlockDB,
///     chain::init::init_cache_database,
/// };
///
/// let cache_file = NamedTempFile::new().unwrap();
/// let db = BlockDB::for_path(cache_file.path()).unwrap();
/// init_cache_database(&db).unwrap();
/// ```
pub fn init_cache_database(db_cache: &BlockDB) -> Result<(), rusqlite::Error> {
    db_cache.0.execute(
        "CREATE TABLE IF NOT EXISTS compactblocks (
            height INTEGER PRIMARY KEY,
            data BLOB NOT NULL
        )",
        NO_PARAMS,
    )?;
    Ok(())
}
