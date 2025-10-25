use std::{array::TryFromSliceError, convert::Infallible};

use shardtree::error::ShardTreeError;
use transparent::address::TransparentAddress;
use zcash_address::ConversionError;
use zcash_keys::{
    encoding::TransparentCodecError,
    keys::{AddressGenerationError, DerivationError},
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{consensus::BlockHeight, memo};

use crate::AccountId;

pub type Result<T> = std::result::Result<T, Error>;

/// Helper macro for reading optional fields from a protobuf messages
/// it will return a Result type with a custom error based on the
/// field name
#[macro_export]
macro_rules! read_optional {
    ($proto:expr, $field:ident) => {
        $proto
            .$field
            .ok_or(Error::ProtoMissingField(stringify!($field)))
    };
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Account not found: {0:?}")]
    AccountUnknown(AccountId),
    #[error("Account out of range.")]
    AccountOutOfRange,
    #[error("Address Conversion error: {0}")]
    ConversionError(ConversionError<&'static str>),
    #[error("Address not recognized: {0:?}")]
    AddressNotRecognized(TransparentAddress),
    #[error("Error generating address: {0}")]
    AddressGeneration(AddressGenerationError),
    #[error("Balance error: {0}")]
    Balance(#[from] zcash_protocol::value::BalanceError),
    #[error(
        "An error occurred while processing an account due to a failure in deriving the account's keys: {0}"
    )]
    BadAccountData(String),
    #[error("Error converting byte vec to array: {0:?}")]
    ByteVecToArrayConversion(Vec<u8>),
    #[error("Chain height unknown")]
    ChainHeightUnknown,
    #[error("Conflicting Tx Locator map entry")]
    ConflictingTxLocator,
    #[error("Corrupted Data: {0}")]
    CorruptedData(String),
    #[error("Error deriving key: {0}")]
    KeyDerivation(DerivationError),
    #[error("Failed to convert between integer types")]
    IntegerConversion(#[from] std::num::TryFromIntError),
    #[error("Infallible")]
    Infallible(#[from] Infallible),
    #[error("Invalid scan range start {0}, end {1}: {2}")]
    InvalidScanRange(BlockHeight, BlockHeight, String),
    #[error("Seed must be between 32 and 252 bytes in length.")]
    InvalidSeedLength,
    #[error("Io Error: {0}")]
    Io(std::io::Error),
    #[error("Memo decryption failed: {0}")]
    MemoDecryption(memo::Error),
    #[error("Expected field missing: {0}")]
    Missing(String),
    #[error("Note not found")]
    NoteNotFound,
    #[error("Blocks are non sequental")]
    NonSequentialBlocks,
    #[error("Orchard specific code was called without the 'orchard' feature enabled")]
    OrchardNotEnabled,
    #[error("Other error: {0}")]
    Other(String),
    #[error("Proto Decoding Error: {0}")]
    ProtoDecodingError(#[from] prost::DecodeError),
    #[error("Proto Encoding Error: {0}")]
    ProtoEncodingError(#[from] prost::EncodeError),
    #[error("Missing proto field: {0}")]
    ProtoMissingField(&'static str),
    #[error("Requested rewind to invalid block height. Safe height: {0:?}, requested height {1:?}")]
    RequestedRewindInvalid(Option<BlockHeight>, BlockHeight),
    #[cfg(feature = "transparent-inputs")]
    #[error("Requested gap limit {1} reached for account {0:?}")]
    ReachedGapLimit(AccountId, u32),
    #[error("ShardTree error: {0}")]
    ShardTree(ShardTreeError<Infallible>),
    #[error("String Conversion error: {0}")]
    StringConversion(#[from] std::string::FromUtf8Error),
    #[error("Transaction not in table: {0}")]
    TransactionNotFound(TxId),
    #[error("Error converting transparent address: {0}")]
    TransparentCodec(#[from] TransparentCodecError),
    #[cfg(feature = "transparent-inputs")]
    #[error("Transparent derivation: {0}")]
    TransparentDerivation(bip32::Error),
    #[error("Unsupported proto version: {1} (expected {0})")]
    UnsupportedProtoVersion(u32, u32),
    #[error("Error converting nullifier from slice: {0}")]
    NullifierFromSlice(#[from] TryFromSliceError),
    #[error("Error decoding ufvk string: {0}")]
    UfvkDecodeError(String),
    #[error("Viewing key not found for account: {0:?}")]
    ViewingKeyNotFound(AccountId),
    #[error("Error parsing zcash address: {0}")]
    ParseZcashAddress(zcash_address::ParseError),
    #[error("Unknown zip32 derivation error")]
    UnknownZip32Derivation,

    #[error("Error converting int to zip32: {0}")]
    Zip32FromInt(zip32::TryFromIntError),
}

impl From<zcash_address::ParseError> for Error {
    fn from(e: zcash_address::ParseError) -> Self {
        Error::ParseZcashAddress(e)
    }
}

#[cfg(feature = "transparent-inputs")]
impl From<bip32::Error> for Error {
    fn from(value: bip32::Error) -> Self {
        Error::TransparentDerivation(value)
    }
}
impl From<ConversionError<&'static str>> for Error {
    fn from(value: ConversionError<&'static str>) -> Self {
        Error::ConversionError(value)
    }
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
        Error::Io(value)
    }
}

impl From<ShardTreeError<Infallible>> for Error {
    fn from(value: ShardTreeError<Infallible>) -> Self {
        Error::ShardTree(value)
    }
}

impl From<Vec<u8>> for Error {
    fn from(value: Vec<u8>) -> Self {
        Error::ByteVecToArrayConversion(value)
    }
}

impl From<zip32::TryFromIntError> for Error {
    fn from(value: zip32::TryFromIntError) -> Self {
        Error::Zip32FromInt(value)
    }
}
