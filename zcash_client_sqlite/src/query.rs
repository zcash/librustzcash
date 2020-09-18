//! Functions for querying information in the data database.

use rusqlite::Connection;
use std::path::Path;
use zcash_primitives::{note_encryption::Memo, transaction::components::Amount};

use crate::{
    error::{Error, ErrorKind},
    get_target_and_anchor_heights,
};

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

/// Returns the balance for the account, including all mined unspent notes that we know
/// about.
///
/// WARNING: This balance is potentially unreliable, as mined notes may become unmined due
/// to chain reorgs. You should generally not show this balance to users without some
/// caveat. Use [`get_verified_balance`] where you need a more reliable indication of the
/// wallet balance.
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::query::get_balance;
///
/// let addr = get_balance("/path/to/data.db", 0);
/// ```
pub fn get_balance<P: AsRef<Path>>(db_data: P, account: u32) -> Result<Amount, Error> {
    let data = Connection::open(db_data)?;

    let balance = data.query_row(
        "SELECT SUM(value) FROM received_notes
        INNER JOIN transactions ON transactions.id_tx = received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block IS NOT NULL",
        &[account],
        |row| row.get(0).or(Ok(0)),
    )?;

    match Amount::from_i64(balance) {
        Ok(amount) if !amount.is_negative() => Ok(amount),
        _ => Err(Error(ErrorKind::CorruptedData(
            "Sum of values in received_notes is out of range",
        ))),
    }
}

/// Returns the verified balance for the account, which ignores notes that have been
/// received too recently and are not yet deemed spendable.
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::query::get_verified_balance;
///
/// let addr = get_verified_balance("/path/to/data.db", 0);
/// ```
pub fn get_verified_balance<P: AsRef<Path>>(db_data: P, account: u32) -> Result<Amount, Error> {
    let data = Connection::open(db_data)?;

    let (_, anchor_height) = get_target_and_anchor_heights(&data)?;

    let balance = data.query_row(
        "SELECT SUM(value) FROM received_notes
        INNER JOIN transactions ON transactions.id_tx = received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block <= ?",
        &[account, u32::from(anchor_height)],
        |row| row.get(0).or(Ok(0)),
    )?;

    match Amount::from_i64(balance) {
        Ok(amount) if !amount.is_negative() => Ok(amount),
        _ => Err(Error(ErrorKind::CorruptedData(
            "Sum of values in received_notes is out of range",
        ))),
    }
}

/// Returns the memo for a received note, if it is known and a valid UTF-8 string.
///
/// The note is identified by its row index in the `received_notes` table within the data
/// database.
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::query::get_received_memo_as_utf8;
///
/// let memo = get_received_memo_as_utf8("/path/to/data.db", 27);
pub fn get_received_memo_as_utf8<P: AsRef<Path>>(
    db_data: P,
    id_note: i64,
) -> Result<Option<String>, Error> {
    let data = Connection::open(db_data)?;

    let memo: Vec<_> = data.query_row(
        "SELECT memo FROM received_notes
        WHERE id_note = ?",
        &[id_note],
        |row| row.get(0),
    )?;

    match Memo::from_bytes(&memo) {
        Some(memo) => match memo.to_utf8() {
            Some(Ok(res)) => Ok(Some(res)),
            Some(Err(e)) => Err(Error(ErrorKind::InvalidMemo(e))),
            None => Ok(None),
        },
        None => Ok(None),
    }
}

/// Returns the memo for a sent note, if it is known and a valid UTF-8 string.
///
/// The note is identified by its row index in the `sent_notes` table within the data
/// database.
///
/// # Examples
///
/// ```
/// use zcash_client_sqlite::query::get_sent_memo_as_utf8;
///
/// let memo = get_sent_memo_as_utf8("/path/to/data.db", 12);
pub fn get_sent_memo_as_utf8<P: AsRef<Path>>(
    db_data: P,
    id_note: i64,
) -> Result<Option<String>, Error> {
    let data = Connection::open(db_data)?;

    let memo: Vec<_> = data.query_row(
        "SELECT memo FROM sent_notes
        WHERE id_note = ?",
        &[id_note],
        |row| row.get(0),
    )?;

    match Memo::from_bytes(&memo) {
        Some(memo) => match memo.to_utf8() {
            Some(Ok(res)) => Ok(Some(res)),
            Some(Err(e)) => Err(Error(ErrorKind::InvalidMemo(e))),
            None => Ok(None),
        },
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use zcash_primitives::{
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use super::{get_address, get_balance, get_verified_balance};
    use crate::{
        error::ErrorKind,
        init::{init_accounts_table, init_data_database},
        tests,
    };

    #[test]
    fn empty_database_has_no_balance() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = data_file.path();
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvks = [ExtendedFullViewingKey::from(&extsk)];
        init_accounts_table(&db_data, &tests::network(), &extfvks).unwrap();

        // The account should be empty
        assert_eq!(get_balance(db_data, 0).unwrap(), Amount::zero());

        // The account should have no verified balance, as we haven't scanned any blocks
        let e = get_verified_balance(db_data, 0).unwrap_err();
        match e.kind() {
            ErrorKind::ScanRequired => (),
            _ => panic!("Unexpected error: {:?}", e),
        }

        // An invalid account has zero balance
        assert!(get_address(db_data, 1).is_err());
        assert_eq!(get_balance(db_data, 1).unwrap(), Amount::zero());
    }
}
