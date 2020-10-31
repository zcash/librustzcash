use std::fmt;

use zcash_client_backend::{
    data_api::{error::Error as WalletError, wallet::input_selection::GreedyInputSelectorError},
    keys::DerivationError,
    zip321::Zip321Error,
};
use zcash_client_sqlite::{error::SqliteClientError, FsBlockDbError, NoteId};
use zcash_primitives::transaction::fees::zip317::FeeError;

pub(crate) type WalletErrorT =
    WalletError<SqliteClientError, GreedyInputSelectorError<FeeError, NoteId>, FeeError, NoteId>;

#[derive(Debug)]
pub enum Error {
    Cache(FsBlockDbError),
    Derivation(DerivationError),
    InvalidAmount,
    InvalidRecipient,
    InvalidKeysFile,
    MissingParameters,
    SendFailed { code: i32, reason: String },
    Wallet(WalletErrorT),
    Zip321(Zip321Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cache(e) => write!(f, "{:?}", e),
            Error::Derivation(e) => write!(f, "{:?}", e),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::InvalidRecipient => write!(f, "Invalid recipient"),
            Error::InvalidKeysFile => write!(f, "Invalid keys file"),
            Error::MissingParameters => write!(f, "Missing proving parameters"),
            Error::SendFailed { code, reason } => write!(f, "Send failed: ({}) {}", code, reason),
            Error::Wallet(e) => e.fmt(f),
            Error::Zip321(e) => write!(f, "{:?}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<DerivationError> for Error {
    fn from(e: DerivationError) -> Self {
        Error::Derivation(e)
    }
}

impl From<FsBlockDbError> for Error {
    fn from(e: FsBlockDbError) -> Self {
        Error::Cache(e)
    }
}

impl From<WalletErrorT> for Error {
    fn from(e: WalletErrorT) -> Self {
        Error::Wallet(e)
    }
}

impl From<Zip321Error> for Error {
    fn from(e: Zip321Error) -> Self {
        Error::Zip321(e)
    }
}
