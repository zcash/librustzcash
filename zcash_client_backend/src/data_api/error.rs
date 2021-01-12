//! Types for wallet error handling.

use std::error;
use std::fmt;
use zcash_primitives::{
    consensus::BlockHeight,
    sapling::Node,
    transaction::{builder, components::amount::Amount, TxId},
};

use crate::wallet::AccountId;

#[derive(Debug)]
pub enum ChainInvalid {
    /// The hash of the parent block given by a proposed new chain tip does
    /// not match the hash of the current chain tip.
    PrevHashMismatch,
    /// The block height field of the proposed new chain tip is not equal 
    /// to the height of the previous chain tip + 1. This variant stores
    /// a copy of the incorrect height value for reporting purposes.
    BlockHeightDiscontinuity(BlockHeight),
}

#[derive(Debug)]
pub enum Error<DbError, NoteId> {
    /// Decoding of a stored value from its serialized form has failed.
    CorruptedData(String),
    /// Decoding of the extended full viewing key has failed (for the specified network)
    IncorrectHRPExtFVK,
    /// Unable to create a new spend because the wallet balance is not sufficient.
    InsufficientBalance(Amount, Amount),
    /// Chain validation detected an error in the block at the specified block height.
    InvalidChain(BlockHeight, ChainInvalid),
    /// A provided extfvk is not associated with the specified account.
    InvalidExtSK(AccountId),
    /// A received memo cannot be interpreted as a UTF-8 string.
    InvalidMemo(std::str::Utf8Error),
    /// The root of an output's witness tree in a newly arrived transaction does not correspond to 
    /// root of the stored commitment tree at the recorded height.
    InvalidNewWitnessAnchor(usize, TxId, BlockHeight, Node),
    /// The rcm value for a note cannot be decoded to a valid JubJub point.
    InvalidNote,
    /// The root of an output's witness tree in a previously stored transaction does not correspond to 
    /// root of the current commitment tree.
    InvalidWitnessAnchor(NoteId, BlockHeight),
    /// The wallet must first perform a scan of the blockchain before other
    /// operations can be performed.
    ScanRequired,
    /// Illegal attempt to reinitialize an already-initialized wallet database.
    //TODO: This ought to be moved to the database backend error type.
    TableNotEmpty,
    /// Bech32 decoding error
    Bech32(bech32::Error),
    /// Base58 decoding error
    Base58(bs58::decode::Error),
    /// An error occurred building a new transaction.
    Builder(builder::Error),
    /// Wrapper for errors from the underlying data store.
    Database(DbError),
    /// Wrapper for errors from the IO subsystem
    Io(std::io::Error),
    /// An error occurred decoding a protobuf message.
    Protobuf(protobuf::ProtobufError),
    /// The wallet attempted a sapling-only operation at a block
    /// height when Sapling was not yet active.
    SaplingNotActive,
}

impl ChainInvalid {
    pub fn prev_hash_mismatch<E, N>(at_height: BlockHeight) -> Error<E, N> {
        Error::InvalidChain(at_height, ChainInvalid::PrevHashMismatch)
    }

    pub fn block_height_discontinuity<E, N>(
        at_height: BlockHeight,
        found: BlockHeight,
    ) -> Error<E, N> {
        Error::InvalidChain(at_height, ChainInvalid::BlockHeightDiscontinuity(found))
    }
}

impl<E: fmt::Display, N: fmt::Display> fmt::Display for Error<E, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Error::CorruptedData(reason) => write!(f, "Data DB is corrupted: {}", reason),
            Error::IncorrectHRPExtFVK => write!(f, "Incorrect HRP for extfvk"),
            Error::InsufficientBalance(have, need) => write!(
                f,
                "Insufficient balance (have {}, need {} including fee)",
                i64::from(*have), i64::from(*need)
            ),
            Error::InvalidChain(upper_bound, cause) => {
                write!(f, "Invalid chain (upper bound: {}): {:?}", u32::from(*upper_bound), cause)
            }
            Error::InvalidExtSK(account) => {
                write!(f, "Incorrect ExtendedSpendingKey for account {}", account.0)
            }
            Error::InvalidMemo(e) => write!(f, "{}", e),
            Error::InvalidNewWitnessAnchor(output, txid, last_height, anchor) => write!(
                f,
                "New witness for output {} in tx {} has incorrect anchor after scanning block {}: {:?}",
                output, txid, last_height, anchor,
            ),
            Error::InvalidNote => write!(f, "Invalid note"),
            Error::InvalidWitnessAnchor(id_note, last_height) => write!(
                f,
                "Witness for note {} has incorrect anchor after scanning block {}",
                id_note, last_height
            ),
            Error::ScanRequired => write!(f, "Must scan blocks first"),
            Error::TableNotEmpty => write!(f, "Table is not empty"),
            Error::Bech32(e) => write!(f, "{}", e),
            Error::Base58(e) => write!(f, "{}", e),
            Error::Builder(e) => write!(f, "{:?}", e),
            Error::Database(e) => write!(f, "{}", e),
            Error::Io(e) => write!(f, "{}", e),
            Error::Protobuf(e) => write!(f, "{}", e),
            Error::SaplingNotActive => write!(f, "Could not determine Sapling upgrade activation height."),
        }
    }
}

impl<E: error::Error + 'static, N: error::Error + 'static> error::Error for Error<E, N> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::InvalidMemo(e) => Some(e),
            Error::Bech32(e) => Some(e),
            Error::Builder(e) => Some(e),
            Error::Database(e) => Some(e),
            Error::Io(e) => Some(e),
            Error::Protobuf(e) => Some(e),
            _ => None,
        }
    }
}

impl<E, N> From<bech32::Error> for Error<E, N> {
    fn from(e: bech32::Error) -> Self {
        Error::Bech32(e)
    }
}

impl<E, N> From<bs58::decode::Error> for Error<E, N> {
    fn from(e: bs58::decode::Error) -> Self {
        Error::Base58(e)
    }
}

impl<E, N> From<builder::Error> for Error<E, N> {
    fn from(e: builder::Error) -> Self {
        Error::Builder(e)
    }
}

impl<E, N> From<std::io::Error> for Error<E, N> {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl<E, N> From<protobuf::ProtobufError> for Error<E, N> {
    fn from(e: protobuf::ProtobufError) -> Self {
        Error::Protobuf(e)
    }
}
