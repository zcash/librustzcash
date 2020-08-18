use std::fmt;

use zcash_primitives::transaction::builder;

use zcash_client_backend::data_api::error::Error;

use crate::NoteId;

#[derive(Debug)]
pub struct SqliteClientError(pub Error<rusqlite::Error, NoteId>);

impl fmt::Display for SqliteClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Error<rusqlite::Error, NoteId>> for SqliteClientError {
    fn from(e: Error<rusqlite::Error, NoteId>) -> Self {
        SqliteClientError(e)
    }
}

impl From<bech32::Error> for SqliteClientError {
    fn from(e: bech32::Error) -> Self {
        SqliteClientError(Error::Bech32(e))
    }
}

impl From<rusqlite::Error> for SqliteClientError {
    fn from(e: rusqlite::Error) -> Self {
        SqliteClientError(Error::Database(e))
    }
}

impl From<bs58::decode::Error> for SqliteClientError {
    fn from(e: bs58::decode::Error) -> Self {
        SqliteClientError(Error::Base58(e))
    }
}

impl From<builder::Error> for SqliteClientError {
    fn from(e: builder::Error) -> Self {
        SqliteClientError(Error::Builder(e))
    }
}

impl From<std::io::Error> for SqliteClientError {
    fn from(e: std::io::Error) -> Self {
        SqliteClientError(Error::Io(e))
    }
}

impl From<protobuf::ProtobufError> for SqliteClientError {
    fn from(e: protobuf::ProtobufError) -> Self {
        SqliteClientError(Error::Protobuf(e))
    }
}
