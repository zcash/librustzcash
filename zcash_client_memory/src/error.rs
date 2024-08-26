use zcash_keys::keys::{AddressGenerationError, DerivationError};
use zcash_primitives::transaction::TxId;
use zcash_protocol::memo;

use crate::mem_wallet::AccountId;

type Type = AddressGenerationError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Account not found: {0:?}")]
    AccountUnknown(AccountId),
    #[error("Viewing key not found for account: {0:?}")]
    ViewingKeyNotFound(AccountId),
    #[error("No address found for account: {0}")]
    MemoDecryption(memo::Error),
    #[error("Error deriving key: {0}")]
    KeyDerivation(DerivationError),
    #[error("Error generating address: {0}")]
    AddressGeneration(Type),
    #[error("Seed must be between 32 and 252 bytes in length.")]
    InvalidSeedLength,
    #[error("Account out of range.")]
    AccountOutOfRange,
    #[error("Transaction not in table: {0}")]
    TransactionNotFound(TxId),
    #[error("Note not found")]
    NoteNotFound,
    #[error("Conflicting Tx Locator map entry")]
    ConflictingTxLocator,
    #[error("Io Error: {0}")]
    IoError(std::io::Error),
    #[error("Corrupted Data: {0}")]
    CorruptedData(String),
    #[error("Other error: {0}")]
    Other(String),
}

impl From<DerivationError> for Error {
    fn from(value: DerivationError) -> Self {
        Error::KeyDerivation(value)
    }
}

impl From<AddressGenerationError> for Error {
    fn from(value: AddressGenerationError) -> Self {
        Error::AddressGeneration(value)
    }
}

impl From<memo::Error> for Error {
    fn from(value: memo::Error) -> Self {
        Error::MemoDecryption(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::IoError(value)
    }
}
