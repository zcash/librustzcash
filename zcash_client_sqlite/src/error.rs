use std::error;
use std::fmt;

use zcash_client_backend::data_api::error::Error;

use crate::NoteId;

#[derive(Debug)]
pub enum SqliteClientError {
    /// Decoding of a stored value from its serialized form has failed.
    CorruptedData(String),
    /// Decoding of the extended full viewing key has failed (for the specified network)
    IncorrectHRPExtFVK,
    /// The rcm value for a note cannot be decoded to a valid JubJub point.
    InvalidNote,
    /// Bech32 decoding error
    Bech32(bech32::Error),
    /// Base58 decoding error
    Base58(bs58::decode::Error),
    /// Illegal attempt to reinitialize an already-initialized wallet database.
    TableNotEmpty,
    /// Wrapper for rusqlite errors.
    DbError(rusqlite::Error),
    /// Wrapper for errors from the IO subsystem
    Io(std::io::Error),
    /// A received memo cannot be interpreted as a UTF-8 string.
    InvalidMemo(std::str::Utf8Error),
}

impl error::Error for SqliteClientError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            SqliteClientError::InvalidMemo(e) => Some(e),
            SqliteClientError::Bech32(e) => Some(e),
            SqliteClientError::DbError(e) => Some(e),
            SqliteClientError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for SqliteClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            SqliteClientError::CorruptedData(reason) => {
                write!(f, "Data DB is corrupted: {}", reason)
            }
            SqliteClientError::IncorrectHRPExtFVK => write!(f, "Incorrect HRP for extfvk"),
            SqliteClientError::InvalidNote => write!(f, "Invalid note"),
            SqliteClientError::Bech32(e) => write!(f, "{}", e),
            SqliteClientError::Base58(e) => write!(f, "{}", e),
            SqliteClientError::TableNotEmpty => write!(f, "Table is not empty"),
            SqliteClientError::DbError(e) => write!(f, "{}", e),
            SqliteClientError::Io(e) => write!(f, "{}", e),
            SqliteClientError::InvalidMemo(e) => write!(f, "{}", e),
        }
    }
}

impl From<rusqlite::Error> for SqliteClientError {
    fn from(e: rusqlite::Error) -> Self {
        SqliteClientError::DbError(e)
    }
}

impl From<std::io::Error> for SqliteClientError {
    fn from(e: std::io::Error) -> Self {
        SqliteClientError::Io(e)
    }
}

impl From<bech32::Error> for SqliteClientError {
    fn from(e: bech32::Error) -> Self {
        SqliteClientError::Bech32(e)
    }
}

impl From<bs58::decode::Error> for SqliteClientError {
    fn from(e: bs58::decode::Error) -> Self {
        SqliteClientError::Base58(e)
    }
}

pub fn db_error(r: rusqlite::Error) -> Error<SqliteClientError, NoteId> {
    Error::Database(SqliteClientError::DbError(r))
}
