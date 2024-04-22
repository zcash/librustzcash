//! Error types for problems that may arise when reading or storing wallet data to SQLite.

use std::error;
use std::fmt;

use shardtree::error::ShardTreeError;
use zcash_address::ParseError;
use zcash_client_backend::PoolType;
use zcash_keys::keys::AddressGenerationError;
use zcash_primitives::zip32;
use zcash_primitives::{consensus::BlockHeight, transaction::components::amount::BalanceError};

use crate::wallet::commitment_tree;
use crate::PRUNING_DEPTH;

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::encoding::TransparentCodecError,
    zcash_primitives::legacy::TransparentAddress,
};

/// The primary error type for the SQLite wallet backend.
#[derive(Debug)]
pub enum SqliteClientError {
    /// Decoding of a stored value from its serialized form has failed.
    CorruptedData(String),

    /// An error occurred decoding a protobuf message.
    Protobuf(prost::DecodeError),

    /// The rcm value for a note cannot be decoded to a valid JubJub point.
    InvalidNote,

    /// Illegal attempt to reinitialize an already-initialized wallet database.
    TableNotEmpty,

    /// A Zcash key or address decoding error
    DecodingError(ParseError),

    /// An error produced in legacy transparent address derivation
    #[cfg(feature = "transparent-inputs")]
    HdwalletError(hdwallet::error::Error),

    /// An error encountered in decoding a transparent address from its
    /// serialized form.
    #[cfg(feature = "transparent-inputs")]
    TransparentAddress(TransparentCodecError),

    /// Wrapper for rusqlite errors.
    DbError(rusqlite::Error),

    /// Wrapper for errors from the IO subsystem
    Io(std::io::Error),

    /// A received memo cannot be interpreted as a UTF-8 string.
    InvalidMemo(zcash_primitives::memo::Error),

    /// An attempt to update block data would overwrite the current hash for a block with a
    /// different hash. This indicates that a required rewind was not performed.
    BlockConflict(BlockHeight),

    /// A range of blocks provided to the database as a unit was non-sequential
    NonSequentialBlocks,

    /// A requested rewind would violate invariants of the storage layer. The payload returned with
    /// this error is (safe rewind height, requested height).
    RequestedRewindInvalid(BlockHeight, BlockHeight),

    /// An error occurred in generating a Zcash address.
    AddressGeneration(AddressGenerationError),

    /// The account for which information was requested does not belong to the wallet.
    AccountUnknown,

    /// The account was imported, and ZIP-32 derivation information is not known for it.
    UnknownZip32Derivation,

    /// An error occurred deriving a spending key from a seed and a ZIP-32 account index.
    KeyDerivationError(zip32::AccountId),

    /// An error occurred while processing an account due to a failure in deriving the account's keys.
    BadAccountData(String),

    /// A caller attempted to initialize the accounts table with a discontinuous
    /// set of account identifiers.
    AccountIdDiscontinuity,

    /// A caller attempted to construct a new account with an invalid account identifier.
    AccountIdOutOfRange,

    /// The address associated with a record being inserted was not recognized as
    /// belonging to the wallet
    #[cfg(feature = "transparent-inputs")]
    AddressNotRecognized(TransparentAddress),

    /// An error occurred in inserting data into or accessing data from one of the wallet's note
    /// commitment trees.
    CommitmentTree(ShardTreeError<commitment_tree::Error>),

    /// The block at the specified height was not available from the block cache.
    CacheMiss(BlockHeight),

    /// The height of the chain was not available; a call to [`WalletWrite::update_chain_tip`] is
    /// required before the requested operation can succeed.
    ///
    /// [`WalletWrite::update_chain_tip`]:
    /// zcash_client_backend::data_api::WalletWrite::update_chain_tip
    ChainHeightUnknown,

    /// Unsupported pool type
    UnsupportedPoolType(PoolType),

    /// An error occurred in computing wallet balance
    BalanceError(BalanceError),
}

impl error::Error for SqliteClientError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            SqliteClientError::InvalidMemo(e) => Some(e),
            SqliteClientError::DbError(e) => Some(e),
            SqliteClientError::Io(e) => Some(e),
            SqliteClientError::BalanceError(e) => Some(e),
            SqliteClientError::AddressGeneration(e) => Some(e),
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
            SqliteClientError::Protobuf(e) => write!(f, "Failed to parse protobuf-encoded record: {}", e),
            SqliteClientError::InvalidNote => write!(f, "Invalid note"),
            SqliteClientError::RequestedRewindInvalid(h, r) =>
                write!(f, "A rewind must be either of less than {} blocks, or at least back to block {} for your wallet; the requested height was {}.", PRUNING_DEPTH, h, r),
            SqliteClientError::DecodingError(e) => write!(f, "{}", e),
            #[cfg(feature = "transparent-inputs")]
            SqliteClientError::HdwalletError(e) => write!(f, "{:?}", e),
            #[cfg(feature = "transparent-inputs")]
            SqliteClientError::TransparentAddress(e) => write!(f, "{}", e),
            SqliteClientError::TableNotEmpty => write!(f, "Table is not empty"),
            SqliteClientError::DbError(e) => write!(f, "{}", e),
            SqliteClientError::Io(e) => write!(f, "{}", e),
            SqliteClientError::InvalidMemo(e) => write!(f, "{}", e),
            SqliteClientError::BlockConflict(h) => write!(f, "A block hash conflict occurred at height {}; rewind required.", u32::from(*h)),
            SqliteClientError::NonSequentialBlocks => write!(f, "`put_blocks` requires that the provided block range be sequential"),
            SqliteClientError::AddressGeneration(e) => write!(f, "{}", e),
            SqliteClientError::AccountUnknown => write!(f, "The account with the given ID does not belong to this wallet."),
            SqliteClientError::UnknownZip32Derivation => write!(f, "ZIP-32 derivation information is not known for this account."),
            SqliteClientError::KeyDerivationError(acct_id) => write!(f, "Key derivation failed for account {}", u32::from(*acct_id)),
            SqliteClientError::BadAccountData(e) => write!(f, "Failed to add account: {}", e),
            SqliteClientError::AccountIdDiscontinuity => write!(f, "Wallet account identifiers must be sequential."),
            SqliteClientError::AccountIdOutOfRange => write!(f, "Wallet account identifiers must be less than 0x7FFFFFFF."),
            #[cfg(feature = "transparent-inputs")]
            SqliteClientError::AddressNotRecognized(_) => write!(f, "The address associated with a received txo is not identifiable as belonging to the wallet."),
            SqliteClientError::CommitmentTree(err) => write!(f, "An error occurred accessing or updating note commitment tree data: {}.", err),
            SqliteClientError::CacheMiss(height) => write!(f, "Requested height {} does not exist in the block cache.", height),
            SqliteClientError::ChainHeightUnknown => write!(f, "Chain height unknown; please call `update_chain_tip`"),
            SqliteClientError::UnsupportedPoolType(t) => write!(f, "Pool type is not currently supported: {}", t),
            SqliteClientError::BalanceError(e) => write!(f, "Balance error: {}", e),
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
impl From<ParseError> for SqliteClientError {
    fn from(e: ParseError) -> Self {
        SqliteClientError::DecodingError(e)
    }
}

impl From<prost::DecodeError> for SqliteClientError {
    fn from(e: prost::DecodeError) -> Self {
        SqliteClientError::Protobuf(e)
    }
}

#[cfg(feature = "transparent-inputs")]
impl From<hdwallet::error::Error> for SqliteClientError {
    fn from(e: hdwallet::error::Error) -> Self {
        SqliteClientError::HdwalletError(e)
    }
}

#[cfg(feature = "transparent-inputs")]
impl From<TransparentCodecError> for SqliteClientError {
    fn from(e: TransparentCodecError) -> Self {
        SqliteClientError::TransparentAddress(e)
    }
}

impl From<zcash_primitives::memo::Error> for SqliteClientError {
    fn from(e: zcash_primitives::memo::Error) -> Self {
        SqliteClientError::InvalidMemo(e)
    }
}

impl From<ShardTreeError<commitment_tree::Error>> for SqliteClientError {
    fn from(e: ShardTreeError<commitment_tree::Error>) -> Self {
        SqliteClientError::CommitmentTree(e)
    }
}

impl From<BalanceError> for SqliteClientError {
    fn from(e: BalanceError) -> Self {
        SqliteClientError::BalanceError(e)
    }
}

impl From<AddressGenerationError> for SqliteClientError {
    fn from(e: AddressGenerationError) -> Self {
        SqliteClientError::AddressGeneration(e)
    }
}
