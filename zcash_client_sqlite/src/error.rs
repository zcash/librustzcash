//! Error types for problems that may arise when reading or storing wallet data to SQLite.

use std::error;
use std::fmt;

use shardtree::error::ShardTreeError;
use zcash_client_backend::encoding::{Bech32DecodeError, TransparentCodecError};
use zcash_primitives::{consensus::BlockHeight, zip32::AccountId};

use crate::wallet::commitment_tree;
use crate::PRUNING_DEPTH;

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::legacy::TransparentAddress;

/// The primary error type for the SQLite wallet backend.
#[derive(Debug)]
pub enum SqliteClientError {
    /// Decoding of a stored value from its serialized form has failed.
    CorruptedData(String),

    /// An error occurred decoding a protobuf message.
    Protobuf(prost::DecodeError),

    /// The rcm value for a note cannot be decoded to a valid JubJub point.
    InvalidNote,

    /// The note id associated with a witness being stored corresponds to a
    /// sent note, not a received note.
    InvalidNoteId,

    /// Illegal attempt to reinitialize an already-initialized wallet database.
    TableNotEmpty,

    /// A Bech32-encoded key or address decoding error
    Bech32DecodeError(Bech32DecodeError),

    /// An error produced in legacy transparent address derivation
    #[cfg(feature = "transparent-inputs")]
    HdwalletError(hdwallet::error::Error),

    /// An error encountered in decoding a transparent address from its
    /// serialized form.
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

    /// The space of allocatable diversifier indices has been exhausted for the given account.
    DiversifierIndexOutOfRange,

    /// The account for which information was requested does not belong to the wallet.
    AccountUnknown(AccountId),

    /// An error occurred deriving a spending key from a seed and an account
    /// identifier.
    KeyDerivationError(AccountId),

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
}

impl error::Error for SqliteClientError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            SqliteClientError::InvalidMemo(e) => Some(e),
            SqliteClientError::Bech32DecodeError(Bech32DecodeError::Bech32Error(e)) => Some(e),
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
            SqliteClientError::Protobuf(e) => write!(f, "Failed to parse protobuf-encoded record: {}", e),
            SqliteClientError::InvalidNote => write!(f, "Invalid note"),
            SqliteClientError::InvalidNoteId =>
                write!(f, "The note ID associated with an inserted witness must correspond to a received note."),
            SqliteClientError::RequestedRewindInvalid(h, r) =>
                write!(f, "A rewind must be either of less than {} blocks, or at least back to block {} for your wallet; the requested height was {}.", PRUNING_DEPTH, h, r),
            SqliteClientError::Bech32DecodeError(e) => write!(f, "{}", e),
            #[cfg(feature = "transparent-inputs")]
            SqliteClientError::HdwalletError(e) => write!(f, "{:?}", e),
            SqliteClientError::TransparentAddress(e) => write!(f, "{}", e),
            SqliteClientError::TableNotEmpty => write!(f, "Table is not empty"),
            SqliteClientError::DbError(e) => write!(f, "{}", e),
            SqliteClientError::Io(e) => write!(f, "{}", e),
            SqliteClientError::InvalidMemo(e) => write!(f, "{}", e),
            SqliteClientError::BlockConflict(h) => write!(f, "A block hash conflict occurred at height {}; rewind required.", u32::from(*h)),
            SqliteClientError::NonSequentialBlocks => write!(f, "`put_blocks` requires that the provided block range be sequential"),
            SqliteClientError::DiversifierIndexOutOfRange => write!(f, "The space of available diversifier indices is exhausted"),
            SqliteClientError::AccountUnknown(acct_id) => write!(f, "Account {} does not belong to this wallet.", u32::from(*acct_id)),

            SqliteClientError::KeyDerivationError(acct_id) => write!(f, "Key derivation failed for account {}", u32::from(*acct_id)),
            SqliteClientError::AccountIdDiscontinuity => write!(f, "Wallet account identifiers must be sequential."),
            SqliteClientError::AccountIdOutOfRange => write!(f, "Wallet account identifiers must be less than 0x7FFFFFFF."),
            #[cfg(feature = "transparent-inputs")]
            SqliteClientError::AddressNotRecognized(_) => write!(f, "The address associated with a received txo is not identifiable as belonging to the wallet."),
            SqliteClientError::CommitmentTree(err) => write!(f, "An error occurred accessing or updating note commitment tree data: {}.", err),
            SqliteClientError::CacheMiss(height) => write!(f, "Requested height {} does not exist in the block cache.", height),
            SqliteClientError::ChainHeightUnknown => write!(f, "Chain height unknown; please call `update_chain_tip`")
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

impl From<Bech32DecodeError> for SqliteClientError {
    fn from(e: Bech32DecodeError) -> Self {
        SqliteClientError::Bech32DecodeError(e)
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
