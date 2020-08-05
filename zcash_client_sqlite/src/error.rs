use std::error;
use std::fmt;
use zcash_primitives::{
    consensus::BlockHeight,
    sapling::Node,
    transaction::{builder, TxId},
};

#[derive(Debug)]
pub enum ErrorKind {
    CorruptedData(&'static str),
    IncorrectHRPExtFVK,
    InsufficientBalance(u64, u64),
    InvalidChain(BlockHeight, crate::chain::ChainInvalidCause),
    InvalidExtSK(u32),
    InvalidHeight(BlockHeight, BlockHeight),
    InvalidMemo(std::str::Utf8Error),
    InvalidNewWitnessAnchor(usize, TxId, BlockHeight, Node),
    InvalidNote,
    InvalidWitnessAnchor(i64, BlockHeight),
    ScanRequired,
    TableNotEmpty,
    Bech32(bech32::Error),
    Base58(bs58::decode::Error),
    Builder(builder::Error),
    Database(rusqlite::Error),
    Io(std::io::Error),
    Protobuf(protobuf::ProtobufError),
    SaplingNotActive,
}

#[derive(Debug)]
pub struct Error(pub(crate) ErrorKind);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            ErrorKind::CorruptedData(reason) => write!(f, "Data DB is corrupted: {}", reason),
            ErrorKind::IncorrectHRPExtFVK => write!(f, "Incorrect HRP for extfvk"),
            ErrorKind::InsufficientBalance(have, need) => write!(
                f,
                "Insufficient balance (have {}, need {} including fee)",
                have, need
            ),
            ErrorKind::InvalidChain(upper_bound, cause) => {
                write!(f, "Invalid chain (upper bound: {}): {:?}", upper_bound, cause)
            }
            ErrorKind::InvalidExtSK(account) => {
                write!(f, "Incorrect ExtendedSpendingKey for account {}", account)
            }
            ErrorKind::InvalidHeight(expected, actual) => write!(
                f,
                "Expected height of next CompactBlock to be {}, but was {}",
                expected, actual
            ),
            ErrorKind::InvalidMemo(e) => write!(f, "{}", e),
            ErrorKind::InvalidNewWitnessAnchor(output, txid, last_height, anchor) => write!(
                f,
                "New witness for output {} in tx {} has incorrect anchor after scanning block {}: {:?}",
                output, txid, last_height, anchor,
            ),
            ErrorKind::InvalidNote => write!(f, "Invalid note"),
            ErrorKind::InvalidWitnessAnchor(id_note, last_height) => write!(
                f,
                "Witness for note {} has incorrect anchor after scanning block {}",
                id_note, last_height
            ),
            ErrorKind::ScanRequired => write!(f, "Must scan blocks first"),
            ErrorKind::TableNotEmpty => write!(f, "Table is not empty"),
            ErrorKind::Bech32(e) => write!(f, "{}", e),
            ErrorKind::Base58(e) => write!(f, "{}", e),
            ErrorKind::Builder(e) => write!(f, "{:?}", e),
            ErrorKind::Database(e) => write!(f, "{}", e),
            ErrorKind::Io(e) => write!(f, "{}", e),
            ErrorKind::Protobuf(e) => write!(f, "{}", e),
            ErrorKind::SaplingNotActive => write!(f, "Sapling activation height not specified for network."),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self.0 {
            ErrorKind::InvalidMemo(e) => Some(e),
            ErrorKind::Bech32(e) => Some(e),
            ErrorKind::Builder(e) => Some(e),
            ErrorKind::Database(e) => Some(e),
            ErrorKind::Io(e) => Some(e),
            ErrorKind::Protobuf(e) => Some(e),
            _ => None,
        }
    }
}

impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Self {
        Error(ErrorKind::Bech32(e))
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(e: bs58::decode::Error) -> Self {
        Error(ErrorKind::Base58(e))
    }
}

impl From<builder::Error> for Error {
    fn from(e: builder::Error) -> Self {
        Error(ErrorKind::Builder(e))
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error(ErrorKind::Database(e))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(ErrorKind::Io(e))
    }
}

impl From<protobuf::ProtobufError> for Error {
    fn from(e: protobuf::ProtobufError) -> Self {
        Error(ErrorKind::Protobuf(e))
    }
}

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }
}
