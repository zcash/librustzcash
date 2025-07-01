//! Error types for problems that may arise when reading or storing wallet data to SQLite.

use std::error;
use std::fmt;

use nonempty::NonEmpty;
use shardtree::error::ShardTreeError;

use zcash_address::ParseError;
use zcash_client_backend::data_api::NoteFilter;
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::AddressGenerationError;
use zcash_protocol::{consensus::BlockHeight, value::BalanceError, PoolType, TxId};
use zip32::DiversifierIndex;

use crate::{
    wallet::{commitment_tree, common::ErrUnsupportedPool},
    AccountUuid,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::transparent::SchedulingError,
    ::transparent::{address::TransparentAddress, keys::TransparentKeyScope},
    zcash_keys::encoding::TransparentCodecError,
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
    TransparentDerivation(bip32::Error),

    /// An error encountered in decoding a transparent address from its
    /// serialized form.
    #[cfg(feature = "transparent-inputs")]
    TransparentAddress(TransparentCodecError),

    /// Wrapper for rusqlite errors.
    DbError(rusqlite::Error),

    /// Wrapper for errors from the IO subsystem
    Io(std::io::Error),

    /// A received memo cannot be interpreted as a UTF-8 string.
    InvalidMemo(zcash_protocol::memo::Error),

    /// An attempt to update block data would overwrite the current hash for a block with a
    /// different hash. This indicates that a required rewind was not performed.
    BlockConflict(BlockHeight),

    /// A range of blocks provided to the database as a unit was non-sequential
    NonSequentialBlocks,

    /// A requested rewind would violate invariants of the storage layer. The payload returned with
    /// this error is (safe rewind height, requested height). If no safe rewind height can be
    /// determined, the safe rewind height member will be `None`.
    RequestedRewindInvalid {
        safe_rewind_height: Option<BlockHeight>,
        requested_height: BlockHeight,
    },

    /// An error occurred in generating a Zcash address.
    AddressGeneration(AddressGenerationError),

    /// The account for which information was requested does not belong to the wallet.
    AccountUnknown,

    /// The account being added collides with an existing account in the wallet with the given ID.
    /// The collision can be on the seed and ZIP-32 account index, or a shared FVK component.
    AccountCollision(AccountUuid),

    /// The account was imported, and ZIP-32 derivation information is not known for it.
    UnknownZip32Derivation,

    /// An error occurred deriving a spending key from a seed and a ZIP-32 account index.
    KeyDerivationError(zip32::AccountId),

    /// An error occurred while processing an account due to a failure in deriving the account's keys.
    BadAccountData(String),

    /// A caller attempted to construct a new account with an invalid ZIP 32 account identifier.
    Zip32AccountIndexOutOfRange,

    /// The address associated with a record being inserted was not recognized as
    /// belonging to the wallet.
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

    /// A note selection query contained an invalid constant or was otherwise not supported.
    NoteFilterInvalid(NoteFilter),

    /// An address cannot be reserved, or a proposal cannot be constructed until a transaction
    /// containing outputs belonging to a previously reserved address has been mined. The error
    /// contains the index that could not safely be reserved.
    #[cfg(feature = "transparent-inputs")]
    ReachedGapLimit(TransparentKeyScope, u32),

    /// The backend encountered an attempt to reuse a diversifier index to generate an address
    /// having different receivers from an address that had previously been exposed for that
    /// diversifier index. Returns the previously exposed address.
    DiversifierIndexReuse(DiversifierIndex, Box<UnifiedAddress>),

    /// The wallet attempted to create a transaction that would use of one of the wallet's
    /// previously-used addresses, potentially creating a problem with on-chain transaction
    /// linkability. The returned value contains the string encoding of the address and the txid(s)
    /// of the transactions in which it is known to have been used.
    AddressReuse(String, NonEmpty<TxId>),

    /// The wallet found one or more notes that given a certain context would be
    /// ineligible and shouldn't be considered in the involved db operation.
    IneligibleNotes,
    /// The wallet encountered an error when attempting to schedule wallet operations.
    #[cfg(feature = "transparent-inputs")]
    Scheduling(SchedulingError),
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
                write!(f, "Data DB is corrupted: {reason}")
            }
            SqliteClientError::Protobuf(e) => write!(f, "Failed to parse protobuf-encoded record: {e}"),
            SqliteClientError::InvalidNote => write!(f, "Invalid note"),
            SqliteClientError::RequestedRewindInvalid { safe_rewind_height,  requested_height } => write!(
                f,
                "A rewind for your wallet may only target height {} or greater; the requested height was {}.",
                safe_rewind_height.map_or("<unavailable>".to_owned(), |h0| format!("{h0}")),
               requested_height
            ),
            SqliteClientError::DecodingError(e) => write!(f, "{e}"),
            #[cfg(feature = "transparent-inputs")]
            SqliteClientError::TransparentDerivation(e) => write!(f, "{e:?}"),
            #[cfg(feature = "transparent-inputs")]
            SqliteClientError::TransparentAddress(e) => write!(f, "{e}"),
            SqliteClientError::TableNotEmpty => write!(f, "Table is not empty"),
            SqliteClientError::DbError(e) => write!(f, "{e}"),
            SqliteClientError::Io(e) => write!(f, "{e}"),
            SqliteClientError::InvalidMemo(e) => write!(f, "{e}"),
            SqliteClientError::BlockConflict(h) => write!(f, "A block hash conflict occurred at height {}; rewind required.", u32::from(*h)),
            SqliteClientError::NonSequentialBlocks => write!(f, "`put_blocks` requires that the provided block range be sequential"),
            SqliteClientError::AddressGeneration(e) => write!(f, "{e}"),
            SqliteClientError::AccountUnknown => write!(f, "The account with the given ID does not belong to this wallet."),
            SqliteClientError::UnknownZip32Derivation => write!(f, "ZIP-32 derivation information is not known for this account."),
            SqliteClientError::KeyDerivationError(zip32_index) => write!(f, "Key derivation failed for ZIP 32 account index {}", u32::from(*zip32_index)),
            SqliteClientError::BadAccountData(e) => write!(f, "Failed to add account: {e}"),
            SqliteClientError::Zip32AccountIndexOutOfRange => write!(f, "ZIP 32 account identifiers must be less than 0x7FFFFFFF."),
            SqliteClientError::AccountCollision(account_uuid) => write!(f, "An account corresponding to the data provided already exists in the wallet with UUID {account_uuid:?}."),
            #[cfg(feature = "transparent-inputs")]
            SqliteClientError::AddressNotRecognized(_) => write!(f, "The address associated with a received txo is not identifiable as belonging to the wallet."),
            SqliteClientError::CommitmentTree(err) => write!(f, "An error occurred accessing or updating note commitment tree data: {err}."),
            SqliteClientError::CacheMiss(height) => write!(f, "Requested height {height} does not exist in the block cache."),
            SqliteClientError::ChainHeightUnknown => write!(f, "Chain height unknown; please call `update_chain_tip`"),
            SqliteClientError::UnsupportedPoolType(t) => write!(f, "Pool type is not currently supported: {t}"),
            SqliteClientError::BalanceError(e) => write!(f, "Balance error: {e}"),
            SqliteClientError::NoteFilterInvalid(s) => write!(f, "Could not evaluate filter query: {s:?}"),
            #[cfg(feature = "transparent-inputs")]
            SqliteClientError::ReachedGapLimit(key_scope, bad_index) => write!(f,
                "The proposal cannot be constructed until a transaction with outputs to a previously reserved {} address has been mined. \
                 The address at index {bad_index} could not be safely reserved.",
                 match *key_scope {
                     TransparentKeyScope::EXTERNAL => "external transparent",
                     TransparentKeyScope::INTERNAL => "transparent change",
                     TransparentKeyScope::EPHEMERAL => "ephemeral transparent",
                     _ => panic!("Unsupported transparent key scope.")
                 }
            ),
            SqliteClientError::DiversifierIndexReuse(i, _) => {
                write!(
                    f,
                    "An address has already been exposed for diversifier index {}",
                    u128::from(*i)
                )
            }
            SqliteClientError::AddressReuse(address_str, txids) => {
                write!(f, "The address {address_str} previously used in txid(s) {txids:?} would be reused.")
            }
            #[cfg(feature = "transparent-inputs")]
            SqliteClientError::Scheduling(err) => {
                write!(f, "The wallet was unable to schedule an event: {err}")
            },
            SqliteClientError::IneligibleNotes => {
                write!(f, "Query found notes that are considered ineligible in its context")
            }
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
impl From<bip32::Error> for SqliteClientError {
    fn from(e: bip32::Error) -> Self {
        SqliteClientError::TransparentDerivation(e)
    }
}

#[cfg(feature = "transparent-inputs")]
impl From<TransparentCodecError> for SqliteClientError {
    fn from(e: TransparentCodecError) -> Self {
        SqliteClientError::TransparentAddress(e)
    }
}

impl From<zcash_protocol::memo::Error> for SqliteClientError {
    fn from(e: zcash_protocol::memo::Error) -> Self {
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

#[cfg(feature = "transparent-inputs")]
impl From<SchedulingError> for SqliteClientError {
    fn from(value: SchedulingError) -> Self {
        SqliteClientError::Scheduling(value)
    }
}

impl ErrUnsupportedPool for SqliteClientError {
    fn unsupported_pool_type(pool_type: PoolType) -> Self {
        SqliteClientError::UnsupportedPoolType(pool_type)
    }
}
