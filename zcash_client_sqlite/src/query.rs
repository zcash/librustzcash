//! Functions for querying information in the data database.

use rusqlite::Connection;
use std::path::Path;

use crate::error::Error;

/// Returns the address for the account.
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::query::get_address;
///
/// let addr = get_address("/path/to/data.db", 0);
/// ```
pub fn get_address<P: AsRef<Path>>(db_data: P, account: u32) -> Result<String, Error> {
    let data = Connection::open(db_data)?;

    let addr = data.query_row(
        "SELECT address FROM accounts
        WHERE account = ?",
        &[account],
        |row| row.get(0),
    )?;

    Ok(addr)
}
