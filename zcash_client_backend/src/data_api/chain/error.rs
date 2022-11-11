//! Types for chain scanning error handling.

use std::error;
use std::fmt::{self, Debug, Display};

use zcash_primitives::{consensus::BlockHeight, sapling, transaction::TxId};

/// The underlying cause of a [`ChainError`].
#[derive(Copy, Clone, Debug)]
pub enum Cause<NoteRef> {
    /// The hash of the parent block given by a proposed new chain tip does not match the hash of
    /// the current chain tip.
    PrevHashMismatch,

    /// The block height field of the proposed new chain tip is not equal to the height of the
    /// previous chain tip + 1. This variant stores a copy of the incorrect height value for
    /// reporting purposes.
    BlockHeightDiscontinuity(BlockHeight),

    /// The root of an output's witness tree in a newly arrived transaction does not correspond to
    /// root of the stored commitment tree at the recorded height.
    ///
    /// This error is currently only produced when performing the slow checks that are enabled by
    /// compiling with `-C debug-assertions`.
    InvalidNewWitnessAnchor {
        /// The id of the transaction containing the mismatched witness.
        txid: TxId,
        /// The index of the shielded output within the transaction where the witness root does not
        /// match.
        index: usize,
        /// The root of the witness that failed to match the root of the current note commitment
        /// tree.
        node: sapling::Node,
    },

    /// The root of an output's witness tree in a previously stored transaction does not correspond
    /// to root of the current commitment tree.
    ///
    /// This error is currently only produced when performing the slow checks that are enabled by
    /// compiling with `-C debug-assertions`.
    InvalidWitnessAnchor(NoteRef),
}

/// Errors that may occur in chain scanning or validation.
#[derive(Copy, Clone, Debug)]
pub struct ChainError<NoteRef> {
    at_height: BlockHeight,
    cause: Cause<NoteRef>,
}

impl<N: Display> fmt::Display for ChainError<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.cause {
            Cause::PrevHashMismatch => write!(
                f,
                "The parent hash of proposed block does not correspond to the block hash at height {}.",
                self.at_height
            ),
            Cause::BlockHeightDiscontinuity(h) => {
                write!(f, "Block height discontinuity at height {}; next height is : {}", self.at_height, h)
            }
            Cause::InvalidNewWitnessAnchor { txid, index, node } => write!(
                f,
                "New witness for output {} in tx {} at height {} has incorrect anchor: {:?}",
                index, txid, self.at_height, node,
            ),
            Cause::InvalidWitnessAnchor(id_note) => {
                write!(f, "Witness for note {} has incorrect anchor for height {}", id_note, self.at_height)
            }
        }
    }
}

impl<NoteRef> ChainError<NoteRef> {
    /// Constructs an error that indicates block hashes failed to chain.
    ///
    /// * `at_height` the height of the block whose parent hash does not match the hash of the
    ///   previous block
    pub fn prev_hash_mismatch(at_height: BlockHeight) -> Self {
        ChainError {
            at_height,
            cause: Cause::PrevHashMismatch,
        }
    }

    /// Constructs an error that indicates a gap in block heights.
    ///
    /// * `at_height` the height of the block being added to the chain.
    /// * `prev_chain_tip` the height of the previous chain tip.
    pub fn block_height_discontinuity(at_height: BlockHeight, prev_chain_tip: BlockHeight) -> Self {
        ChainError {
            at_height,
            cause: Cause::BlockHeightDiscontinuity(prev_chain_tip),
        }
    }

    /// Constructs an error that indicates a mismatch between an updated note's witness and the
    /// root of the current note commitment tree.
    pub fn invalid_witness_anchor(at_height: BlockHeight, note_ref: NoteRef) -> Self {
        ChainError {
            at_height,
            cause: Cause::InvalidWitnessAnchor(note_ref),
        }
    }

    /// Constructs an error that indicates a mismatch between a new note's witness and the root of
    /// the current note commitment tree.
    pub fn invalid_new_witness_anchor(
        at_height: BlockHeight,
        txid: TxId,
        index: usize,
        node: sapling::Node,
    ) -> Self {
        ChainError {
            at_height,
            cause: Cause::InvalidNewWitnessAnchor { txid, index, node },
        }
    }

    /// Returns the block height at which this error was discovered.
    pub fn at_height(&self) -> BlockHeight {
        self.at_height
    }

    /// Returns the cause of this error.
    pub fn cause(&self) -> &Cause<NoteRef> {
        &self.cause
    }
}

/// Errors related to chain validation and scanning.
#[derive(Debug)]
pub enum Error<WalletError, BlockSourceError, NoteRef> {
    /// An error that was produced by wallet operations in the course of scanning the chain.
    Wallet(WalletError),

    /// An error that was produced by the underlying block data store in the process of validation
    /// or scanning.
    BlockSource(BlockSourceError),

    /// A block that was received violated rules related to chain continuity or contained note
    /// commitments that could not be reconciled with the note commitment tree(s) maintained by the
    /// wallet.
    Chain(ChainError<NoteRef>),
}

impl<WE: fmt::Display, BE: fmt::Display, N: Display> fmt::Display for Error<WE, BE, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Error::Wallet(e) => {
                write!(
                    f,
                    "The underlying datasource produced the following error: {}",
                    e
                )
            }
            Error::BlockSource(e) => {
                write!(
                    f,
                    "The underlying block store produced the following error: {}",
                    e
                )
            }
            Error::Chain(err) => {
                write!(f, "{}", err)
            }
        }
    }
}

impl<WE, BE, N> error::Error for Error<WE, BE, N>
where
    WE: Debug + Display + error::Error + 'static,
    BE: Debug + Display + error::Error + 'static,
    N: Debug + Display,
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::Wallet(e) => Some(e),
            Error::BlockSource(e) => Some(e),
            _ => None,
        }
    }
}

impl<WE, BSE, N> From<ChainError<N>> for Error<WE, BSE, N> {
    fn from(e: ChainError<N>) -> Self {
        Error::Chain(e)
    }
}
