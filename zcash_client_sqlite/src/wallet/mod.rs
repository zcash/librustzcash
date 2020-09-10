//! Functions for querying information in the data database.

use rusqlite::{OptionalExtension, ToSql, NO_PARAMS};

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, NetworkUpgrade},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    note_encryption::Memo,
    primitives::PaymentAddress,
    sapling::Node,
    transaction::{components::Amount, TxId},
    zip32::ExtendedFullViewingKey,
};

use zcash_client_backend::{
    data_api::error::Error,
    encoding::{
        decode_extended_full_viewing_key, decode_payment_address, encode_extended_full_viewing_key,
    },
};

use crate::{error::SqliteClientError, AccountId, DataConnection, NoteId};

pub mod init;
pub mod transact;

/// Returns the address for the account.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::{
///     consensus::{self, Network},
/// };
/// use zcash_client_sqlite::{
///     AccountId,
///     DataConnection,
///     query::get_address,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = DataConnection::for_path(data_file).unwrap();
/// let addr = get_address(&db, &Network::TestNetwork, AccountId(0));
/// ```
pub fn get_address<P: consensus::Parameters>(
    data: &DataConnection,
    params: &P,
    account: AccountId,
) -> Result<Option<PaymentAddress>, SqliteClientError> {
    let addr: String = data.0.query_row(
        "SELECT address FROM accounts
        WHERE account = ?",
        &[account.0],
        |row| row.get(0),
    )?;

    decode_payment_address(params.hrp_sapling_payment_address(), &addr)
        .map_err(|e| SqliteClientError(e.into()))
}

pub fn get_extended_full_viewing_keys<P: consensus::Parameters>(
    data: &DataConnection,
    params: &P,
) -> Result<Vec<ExtendedFullViewingKey>, SqliteClientError> {
    // Fetch the ExtendedFullViewingKeys we are tracking
    let mut stmt_fetch_accounts = data
        .0
        .prepare("SELECT extfvk FROM accounts ORDER BY account ASC")?;

    let rows = stmt_fetch_accounts
        .query_map(NO_PARAMS, |row| {
            row.get(0).map(|extfvk: String| {
                decode_extended_full_viewing_key(
                    params.hrp_sapling_extended_full_viewing_key(),
                    &extfvk,
                )
                .map_err(|e| Error::Bech32(e))
                .and_then(|k| k.ok_or(Error::IncorrectHRPExtFVK))
                .map_err(SqliteClientError)
            })
        })
        .map_err(SqliteClientError::from)?;

    rows.collect::<Result<Result<_, _>, _>>()?
}

pub fn is_valid_account_extfvk<P: consensus::Parameters>(
    data: &DataConnection,
    params: &P,
    account: AccountId,
    extfvk: &ExtendedFullViewingKey,
) -> Result<bool, SqliteClientError> {
    data.0
        .prepare("SELECT * FROM accounts WHERE account = ? AND extfvk = ?")?
        .exists(&[
            account.0.to_sql()?,
            encode_extended_full_viewing_key(
                params.hrp_sapling_extended_full_viewing_key(),
                extfvk,
            )
            .to_sql()?,
        ])
        .map_err(SqliteClientError::from)
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
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{
///     AccountId,
///     DataConnection,
///     query::get_balance,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = DataConnection::for_path(data_file).unwrap();
/// let addr = get_balance(&db, AccountId(0));
/// ```
pub fn get_balance(data: &DataConnection, account: AccountId) -> Result<Amount, SqliteClientError> {
    let balance = data.0.query_row(
        "SELECT SUM(value) FROM received_notes
        INNER JOIN transactions ON transactions.id_tx = received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block IS NOT NULL",
        &[account.0],
        |row| row.get(0).or(Ok(0)),
    )?;

    match Amount::from_i64(balance) {
        Ok(amount) if !amount.is_negative() => Ok(amount),
        _ => Err(SqliteClientError(Error::CorruptedData(
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
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{
///     AccountId,
///     DataConnection,
///     query::get_verified_balance,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = DataConnection::for_path(data_file).unwrap();
/// let addr = get_verified_balance(&db, AccountId(0));
/// ```
pub fn get_verified_balance(
    data: &DataConnection,
    account: AccountId,
    anchor_height: BlockHeight,
) -> Result<Amount, SqliteClientError> {
    let balance = data.0.query_row(
        "SELECT SUM(value) FROM received_notes
        INNER JOIN transactions ON transactions.id_tx = received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block <= ?",
        &[account.0, u32::from(anchor_height)],
        |row| row.get(0).or(Ok(0)),
    )?;

    match Amount::from_i64(balance) {
        Ok(amount) if !amount.is_negative() => Ok(amount),
        _ => Err(SqliteClientError(Error::CorruptedData(
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
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{
///     NoteId,
///     DataConnection,
///     query::get_received_memo_as_utf8,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = DataConnection::for_path(data_file).unwrap();
/// let memo = get_received_memo_as_utf8(&db, NoteId(27));
/// ```
pub fn get_received_memo_as_utf8(
    data: &DataConnection,
    id_note: NoteId,
) -> Result<Option<String>, SqliteClientError> {
    let memo: Vec<_> = data.0.query_row(
        "SELECT memo FROM received_notes
        WHERE id_note = ?",
        &[id_note.0],
        |row| row.get(0),
    )?;

    match Memo::from_bytes(&memo) {
        Some(memo) => match memo.to_utf8() {
            Some(Ok(res)) => Ok(Some(res)),
            Some(Err(e)) => Err(SqliteClientError(Error::InvalidMemo(e))),
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
/// use tempfile::NamedTempFile;
/// use zcash_client_sqlite::{
///     NoteId,
///     DataConnection,
///     query::get_sent_memo_as_utf8,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = DataConnection::for_path(data_file).unwrap();
/// let memo = get_sent_memo_as_utf8(&db, NoteId(12));
/// ```
pub fn get_sent_memo_as_utf8(
    data: &DataConnection,
    id_note: NoteId,
) -> Result<Option<String>, SqliteClientError> {
    let memo: Vec<_> = data.0.query_row(
        "SELECT memo FROM sent_notes
        WHERE id_note = ?",
        &[id_note.0],
        |row| row.get(0),
    )?;

    match Memo::from_bytes(&memo) {
        Some(memo) => match memo.to_utf8() {
            Some(Ok(res)) => Ok(Some(res)),
            Some(Err(e)) => Err(SqliteClientError(Error::InvalidMemo(e))),
            None => Ok(None),
        },
        None => Ok(None),
    }
}

pub fn block_height_extrema(
    conn: &DataConnection,
) -> Result<Option<(BlockHeight, BlockHeight)>, rusqlite::Error> {
    conn.0
        .query_row(
            "SELECT MIN(height), MAX(height) FROM blocks",
            NO_PARAMS,
            |row| {
                let min_height: u32 = row.get(0)?;
                let max_height: u32 = row.get(1)?;
                Ok(Some((
                    BlockHeight::from(min_height),
                    BlockHeight::from(max_height),
                )))
            },
        )
        //.optional() doesn't work here because a failed aggregate function
        //produces a runtime error, not an empty set of rows.
        .or(Ok(None))
}

pub fn get_tx_height(
    conn: &DataConnection,
    txid: TxId,
) -> Result<Option<BlockHeight>, rusqlite::Error> {
    conn.0
        .query_row(
            "SELECT block FROM transactions WHERE txid = ?",
            &[txid.0.to_vec()],
            |row| row.get(0).map(u32::into),
        )
        .optional()
}

pub fn get_block_hash(
    conn: &DataConnection,
    block_height: BlockHeight,
) -> Result<Option<BlockHash>, rusqlite::Error> {
    conn.0
        .query_row(
            "SELECT hash FROM blocks WHERE height = ?",
            &[u32::from(block_height)],
            |row| {
                let row_data = row.get::<_, Vec<_>>(0)?;
                Ok(BlockHash::from_slice(&row_data))
            },
        )
        .optional()
}

/// Rewinds the database to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
pub fn rewind_to_height<P: consensus::Parameters>(
    conn: &DataConnection,
    parameters: &P,
    block_height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let sapling_activation_height = parameters
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(SqliteClientError(Error::SaplingNotActive))?;

    // Recall where we synced up to previously.
    // If we have never synced, use Sapling activation height.
    let last_scanned_height =
        conn.0
            .query_row("SELECT MAX(height) FROM blocks", NO_PARAMS, |row| {
                row.get(0)
                    .map(u32::into)
                    .or(Ok(sapling_activation_height - 1))
            })?;

    if block_height >= last_scanned_height {
        // Nothing to do.
        return Ok(());
    }

    // Start an SQL transaction for rewinding.
    let tx = conn.0.unchecked_transaction()?;

    // Decrement witnesses.
    tx.execute(
        "DELETE FROM sapling_witnesses WHERE block > ?",
        &[u32::from(block_height)],
    )?;

    // Un-mine transactions.
    tx.execute(
        "UPDATE transactions SET block = NULL, tx_index = NULL WHERE block > ?",
        &[u32::from(block_height)],
    )?;

    // Now that they aren't depended on, delete scanned blocks.
    tx.execute(
        "DELETE FROM blocks WHERE height > ?",
        &[u32::from(block_height)],
    )?;

    // Commit the SQL transaction, rewinding atomically.
    tx.commit()?;

    Ok(())
}

pub fn get_commitment_tree(
    data: &DataConnection,
    block_height: BlockHeight,
) -> Result<Option<CommitmentTree<Node>>, SqliteClientError> {
    data.0
        .query_row_and_then(
            "SELECT sapling_tree FROM blocks WHERE height = ?",
            &[u32::from(block_height)],
            |row| {
                let row_data: Vec<u8> = row.get(0)?;
                CommitmentTree::read(&row_data[..]).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        row_data.len(),
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })
            },
        )
        .optional()
        .map_err(SqliteClientError::from)
}

pub fn get_witnesses(
    data: &DataConnection,
    block_height: BlockHeight,
) -> Result<Vec<(NoteId, IncrementalWitness<Node>)>, SqliteClientError> {
    let mut stmt_fetch_witnesses = data
        .0
        .prepare("SELECT note, witness FROM sapling_witnesses WHERE block = ?")?;
    let witnesses = stmt_fetch_witnesses
        .query_map(&[u32::from(block_height)], |row| {
            let id_note = NoteId(row.get(0)?);
            let data: Vec<u8> = row.get(1)?;
            Ok(IncrementalWitness::read(&data[..]).map(|witness| (id_note, witness)))
        })
        .map_err(SqliteClientError::from)?;

    let mut res = vec![];
    for witness in witnesses {
        // unwrap database error & IO error from IncrementalWitness::read
        res.push(witness??);
    }

    Ok(res)
}

pub fn get_nullifiers(
    data: &DataConnection,
) -> Result<Vec<(Vec<u8>, AccountId)>, SqliteClientError> {
    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers = data
        .0
        .prepare("SELECT id_note, nf, account FROM received_notes WHERE spent IS NULL")?;
    let nullifiers = stmt_fetch_nullifiers.query_map(NO_PARAMS, |row| {
        let nf: Vec<u8> = row.get(1)?;
        let account = AccountId(row.get(2)?);
        Ok((nf, account))
    })?;

    let mut res = vec![];
    for nullifier in nullifiers {
        // unwrap database error
        res.push(nullifier?);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use tempfile::NamedTempFile;

    use zcash_primitives::{
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use zcash_client_backend::data_api::DBOps;

    use crate::{
        tests,
        wallet::init::{init_accounts_table, init_data_database},
        AccountId, DataConnection,
    };

    use super::{get_address, get_balance};

    #[test]
    fn empty_database_has_no_balance() {
        let data_file = NamedTempFile::new().unwrap();
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvks = [ExtendedFullViewingKey::from(&extsk)];
        init_accounts_table(&db_data, &tests::network(), &extfvks).unwrap();

        // The account should be empty
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), Amount::zero());

        // We can't get an anchor height, as we have not scanned any blocks.
        assert_eq!((&db_data).get_target_and_anchor_heights().unwrap(), None);

        // An invalid account has zero balance
        assert!(get_address(&db_data, &tests::network(), AccountId(1)).is_err());
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), Amount::zero());
    }
}
