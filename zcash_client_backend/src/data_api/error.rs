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
    PrevHashMismatch,
    /// (expected_height, actual_height)
    BlockHeightMismatch(BlockHeight),
}

#[derive(Debug)]
pub enum Error<DbError, NoteId> {
    CorruptedData(&'static str),
    IncorrectHRPExtFVK,
    InsufficientBalance(Amount, Amount),
    InvalidChain(BlockHeight, ChainInvalid),
    InvalidExtSK(AccountId),
    InvalidMemo(std::str::Utf8Error),
    InvalidNewWitnessAnchor(usize, TxId, BlockHeight, Node),
    InvalidNote,
    InvalidWitnessAnchor(NoteId, BlockHeight),
    ScanRequired,
    TableNotEmpty,
    Bech32(bech32::Error),
    Base58(bs58::decode::Error),
    Builder(builder::Error),
    Database(DbError),
    Io(std::io::Error),
    Protobuf(protobuf::ProtobufError),
    SaplingNotActive,
}

impl ChainInvalid {
    pub fn prev_hash_mismatch<E, N>(at_height: BlockHeight) -> Error<E, N> {
        Error::InvalidChain(at_height, ChainInvalid::PrevHashMismatch)
    }

    pub fn block_height_mismatch<E, N>(at_height: BlockHeight, found: BlockHeight) -> Error<E, N> {
        Error::InvalidChain(at_height, ChainInvalid::BlockHeightMismatch(found))
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
