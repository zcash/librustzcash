//! Error types for problems that may arise when reading or storing wallet data to SQLite.

use std::error;
use std::fmt;

use zcash_client_backend::{data_api, encoding::TransparentCodecError};
use zcash_primitives::consensus::BlockHeight;

use crate::{NoteId, PRUNING_HEIGHT};

/// The primary error type for the SQLite wallet backend.
#[derive(Debug)]
pub enum SqliteClientError {
    /// Decoding of a stored value from its serialized form has failed.
    CorruptedData(String),

    /// Decoding of the extended full viewing key has failed (for the specified network)
    IncorrectHrpExtFvk,

    /// The rcm value for a note cannot be decoded to a valid JubJub point.
    InvalidNote,

    /// The note id associated with a witness being stored corresponds to a
    /// sent note, not a received note.
    InvalidNoteId,

    /// Illegal attempt to reinitialize an already-initialized wallet database.
    TableNotEmpty,

    /// Bech32 decoding error
    Bech32(bech32::Error),

    /// Base58 decoding error
    Base58(bs58::decode::Error),

    /// Base58 decoding error
    TransparentAddress(TransparentCodecError),

    /// Wrapper for rusqlite errors.
    DbError(rusqlite::Error),

    /// Wrapper for errors from the IO subsystem
    Io(std::io::Error),

    /// A received memo cannot be interpreted as a UTF-8 string.
    InvalidMemo(zcash_primitives::memo::Error),

    /// A requested rewind would violate invariants of the
    /// storage layer. The payload returned with this error is
    /// (safe rewind height, requested height).
    RequestedRewindInvalid(BlockHeight, BlockHeight),

    /// Wrapper for errors from zcash_client_backend
    BackendError(data_api::error::Error<NoteId>),
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
            SqliteClientError::IncorrectHrpExtFvk => write!(f, "Incorrect HRP for extfvk"),
            SqliteClientError::InvalidNote => write!(f, "Invalid note"),
            SqliteClientError::InvalidNoteId =>
                write!(f, "The note ID associated with an inserted witness must correspond to a received note."),
            SqliteClientError::RequestedRewindInvalid(h, r) =>
                write!(f, "A rewind must be either of less than {} blocks, or at least back to block {} for your wallet; the requested height was {}.", PRUNING_HEIGHT, h, r),
            SqliteClientError::Bech32(e) => write!(f, "{}", e),
            SqliteClientError::Base58(e) => write!(f, "{}", e),
            SqliteClientError::TransparentAddress(e) => write!(f, "{}", e),
            SqliteClientError::TableNotEmpty => write!(f, "Table is not empty"),
            SqliteClientError::DbError(e) => write!(f, "{}", e),
            SqliteClientError::Io(e) => write!(f, "{}", e),
            SqliteClientError::InvalidMemo(e) => write!(f, "{}", e),
            SqliteClientError::BackendError(e) => write!(f, "{}", e),
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

impl From<zcash_primitives::memo::Error> for SqliteClientError {
    fn from(e: zcash_primitives::memo::Error) -> Self {
        SqliteClientError::InvalidMemo(e)
    }
}

impl From<data_api::error::Error<NoteId>> for SqliteClientError {
    fn from(e: data_api::error::Error<NoteId>) -> Self {
        SqliteClientError::BackendError(e)
    }
}
