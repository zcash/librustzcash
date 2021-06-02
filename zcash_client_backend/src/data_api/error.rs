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
pub enum Error<NoteId> {
    /// The amount specified exceeds the allowed range.
    InvalidAmount,

    /// Unable to create a new spend because the wallet balance is not sufficient.
    InsufficientBalance(Amount, Amount),

    /// Chain validation detected an error in the block at the specified block height.
    InvalidChain(BlockHeight, ChainInvalid),

    /// A provided extsk is not associated with the specified account.
    InvalidExtSk(AccountId),

    /// The root of an output's witness tree in a newly arrived transaction does
    /// not correspond to root of the stored commitment tree at the recorded height.
    ///
    /// The `usize` member of this struct is the index of the shielded output within
    /// the transaction where the witness root does not match.
    InvalidNewWitnessAnchor(usize, TxId, BlockHeight, Node),

    /// The root of an output's witness tree in a previously stored transaction
    /// does not correspond to root of the current commitment tree.
    InvalidWitnessAnchor(NoteId, BlockHeight),

    /// The wallet must first perform a scan of the blockchain before other
    /// operations can be performed.
    ScanRequired,

    /// An error occurred building a new transaction.
    Builder(builder::Error),

    /// An error occurred decoding a protobuf message.
    Protobuf(protobuf::ProtobufError),

    /// The wallet attempted a sapling-only operation at a block
    /// height when Sapling was not yet active.
    SaplingNotActive,
}

impl ChainInvalid {
    pub fn prev_hash_mismatch<N>(at_height: BlockHeight) -> Error<N> {
        Error::InvalidChain(at_height, ChainInvalid::PrevHashMismatch)
    }

    pub fn block_height_discontinuity<N>(at_height: BlockHeight, found: BlockHeight) -> Error<N> {
        Error::InvalidChain(at_height, ChainInvalid::BlockHeightDiscontinuity(found))
    }
}

impl<N: fmt::Display> fmt::Display for Error<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Error::InvalidAmount => write!(
                f,
                "The value lies outside the valid range of Zcash amounts."
            ),
            Error::InsufficientBalance(have, need) => write!(
                f,
                "Insufficient balance (have {}, need {} including fee)",
                i64::from(*have), i64::from(*need)
            ),
            Error::InvalidChain(upper_bound, cause) => {
                write!(f, "Invalid chain (upper bound: {}): {:?}", u32::from(*upper_bound), cause)
            }
            Error::InvalidExtSk(account) => {
                write!(f, "Incorrect ExtendedSpendingKey for account {}", account.0)
            }
            Error::InvalidNewWitnessAnchor(output, txid, last_height, anchor) => write!(
                f,
                "New witness for output {} in tx {} has incorrect anchor after scanning block {}: {:?}",
                output, txid, last_height, anchor,
            ),
            Error::InvalidWitnessAnchor(id_note, last_height) => write!(
                f,
                "Witness for note {} has incorrect anchor after scanning block {}",
                id_note, last_height
            ),
            Error::ScanRequired => write!(f, "Must scan blocks first"),
            Error::Builder(e) => write!(f, "{:?}", e),
            Error::Protobuf(e) => write!(f, "{}", e),
            Error::SaplingNotActive => write!(f, "Could not determine Sapling upgrade activation height."),
        }
    }
}

impl<N: error::Error + 'static> error::Error for Error<N> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::Builder(e) => Some(e),
            Error::Protobuf(e) => Some(e),
            _ => None,
        }
    }
}

impl<N> From<builder::Error> for Error<N> {
    fn from(e: builder::Error) -> Self {
        Error::Builder(e)
    }
}

impl<N> From<protobuf::ProtobufError> for Error<N> {
    fn from(e: protobuf::ProtobufError) -> Self {
        Error::Protobuf(e)
    }
}
