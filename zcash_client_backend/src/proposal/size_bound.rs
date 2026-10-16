//! Bounds on the size and shape of the transactions a proposal describes.

use core::fmt::{self, Display};

use zcash_protocol::{ShieldedPool, constants::MAX_BLOCK_BYTES};

/// An upper bound on the size and shape of each transaction a [`Proposal`] describes.
///
/// The consensus rules bound a transaction only by the size of the block that must carry it,
/// [`TransactionSizeBound::CONSENSUS`]. A wallet may need a tighter bound, for example to meet
/// a relay policy, the memory available for proving, or the per-transaction limits of an
/// external signer. Such a bound is built from `CONSENSUS` with the `with_*` methods, and
/// bounds from several sources are combined with [`TransactionSizeBound::intersect`]:
///
/// ```
/// use zcash_client_backend::proposal::TransactionSizeBound;
/// use zcash_protocol::ShieldedPool;
///
/// let relay = TransactionSizeBound::CONSENSUS.with_max_bytes(100_000);
/// let prover = TransactionSizeBound::CONSENSUS.with_max_shielded_actions(50);
/// let signer = TransactionSizeBound::CONSENSUS
///     .with_max_pool_actions(ShieldedPool::Sapling, 0)
///     .with_max_shielded_payment_outputs(1);
///
/// let bound = relay.intersect(&prover).intersect(&signer);
/// assert_eq!(bound.max_bytes(), 100_000);
/// assert_eq!(bound.max_shielded_actions(), Some(50));
/// assert_eq!(bound.max_pool_actions(ShieldedPool::Sapling), Some(0));
/// assert_eq!(bound.max_pool_actions(ShieldedPool::Orchard), None);
/// ```
///
/// The bound is checked against the conservative estimates that
/// [`Proposal::check_transaction_size_within`] computes for each step: the estimated
/// serialized size and the per-pool action counts never under-count what the transaction
/// builder will produce, so a proposal that satisfies the bound produces transactions that do.
/// Every limit is satisfied by a transaction spending fewer notes whenever it is satisfied by
/// one spending more, which is what lets [`MaxSpendMode::WithinSizeBound`] search for the
/// largest set of notes that fits.
///
/// [`Proposal`]: super::Proposal
/// [`Proposal::check_transaction_size_within`]: super::Proposal::check_transaction_size_within
/// [`MaxSpendMode::WithinSizeBound`]: crate::data_api::MaxSpendMode::WithinSizeBound
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionSizeBound {
    max_bytes: usize,
    max_shielded_actions: Option<usize>,
    max_sapling_actions: Option<usize>,
    max_orchard_actions: Option<usize>,
    max_ironwood_actions: Option<usize>,
    max_transparent_inputs: Option<usize>,
    max_transparent_outputs: Option<usize>,
    max_shielded_payment_outputs: Option<usize>,
}

/// Returns the smaller of two optional limits, where `None` is no limit.
fn min_limit(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

impl TransactionSizeBound {
    /// The bound the consensus rules impose: each transaction's estimated serialized size is
    /// at most [`MAX_BLOCK_BYTES`], with no limit on the number of inputs, outputs, or
    /// actions. This is the [`Default`].
    pub const CONSENSUS: Self = Self {
        max_bytes: MAX_BLOCK_BYTES,
        max_shielded_actions: None,
        max_sapling_actions: None,
        max_orchard_actions: None,
        max_ironwood_actions: None,
        max_transparent_inputs: None,
        max_transparent_outputs: None,
        max_shielded_payment_outputs: None,
    };

    /// Returns this bound with each transaction's estimated serialized size limited to `n`
    /// bytes.
    ///
    /// A limit above [`MAX_BLOCK_BYTES`] is reduced to it, so that no bound admits a
    /// transaction that no block can carry.
    pub fn with_max_bytes(self, n: usize) -> Self {
        Self {
            max_bytes: n.min(MAX_BLOCK_BYTES),
            ..self
        }
    }

    /// Returns this bound with the total number of shielded actions in each transaction
    /// limited to `n`.
    ///
    /// The total is the number of Sapling spend and output descriptions plus the number of
    /// Orchard and Ironwood actions, counted after padding and dummy outputs, as estimated by
    /// [`Step::estimated_pool_actions`]. The cost of proving a transaction grows with this
    /// count.
    ///
    /// [`Step::estimated_pool_actions`]: super::Step::estimated_pool_actions
    pub fn with_max_shielded_actions(self, n: usize) -> Self {
        Self {
            max_shielded_actions: Some(n),
            ..self
        }
    }

    /// Returns this bound with the number of shielded actions each transaction carries in
    /// `pool` limited to `n`, counted as for [`Self::with_max_shielded_actions`].
    ///
    /// A limit of zero forbids a transaction from having a bundle in `pool` at all: it may
    /// neither spend from, pay to, nor return change to that pool.
    pub fn with_max_pool_actions(self, pool: ShieldedPool, n: usize) -> Self {
        match pool {
            ShieldedPool::Sapling => Self {
                max_sapling_actions: Some(n),
                ..self
            },
            ShieldedPool::Orchard => Self {
                max_orchard_actions: Some(n),
                ..self
            },
            ShieldedPool::Ironwood => Self {
                max_ironwood_actions: Some(n),
                ..self
            },
        }
    }

    /// Returns this bound with the number of transparent inputs each transaction spends,
    /// including outputs of earlier steps of the same proposal, limited to `n`.
    pub fn with_max_transparent_inputs(self, n: usize) -> Self {
        Self {
            max_transparent_inputs: Some(n),
            ..self
        }
    }

    /// Returns this bound with the number of transparent outputs each transaction creates,
    /// payments and change alike, limited to `n`.
    pub fn with_max_transparent_outputs(self, n: usize) -> Self {
        Self {
            max_transparent_outputs: Some(n),
            ..self
        }
    }

    /// Returns this bound with the number of shielded outputs each transaction creates to pay
    /// a requested payment limited to `n`. Wallet-internal change outputs and dummy outputs
    /// are not counted; this bounds the outputs that a signer must present for review.
    pub fn with_max_shielded_payment_outputs(self, n: usize) -> Self {
        Self {
            max_shielded_payment_outputs: Some(n),
            ..self
        }
    }

    /// Returns the bound that a transaction satisfies exactly when it satisfies both `self`
    /// and `other`: each limit is the smaller of the two, and a limit set in only one of them
    /// is kept.
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            max_bytes: self.max_bytes.min(other.max_bytes),
            max_shielded_actions: min_limit(self.max_shielded_actions, other.max_shielded_actions),
            max_sapling_actions: min_limit(self.max_sapling_actions, other.max_sapling_actions),
            max_orchard_actions: min_limit(self.max_orchard_actions, other.max_orchard_actions),
            max_ironwood_actions: min_limit(self.max_ironwood_actions, other.max_ironwood_actions),
            max_transparent_inputs: min_limit(
                self.max_transparent_inputs,
                other.max_transparent_inputs,
            ),
            max_transparent_outputs: min_limit(
                self.max_transparent_outputs,
                other.max_transparent_outputs,
            ),
            max_shielded_payment_outputs: min_limit(
                self.max_shielded_payment_outputs,
                other.max_shielded_payment_outputs,
            ),
        }
    }

    /// Returns the limit on each transaction's estimated serialized size, in bytes.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Returns the limit on the total number of shielded actions in each transaction, if any.
    pub fn max_shielded_actions(&self) -> Option<usize> {
        self.max_shielded_actions
    }

    /// Returns the limit on the number of shielded actions each transaction carries in
    /// `pool`, if any.
    pub fn max_pool_actions(&self, pool: ShieldedPool) -> Option<usize> {
        match pool {
            ShieldedPool::Sapling => self.max_sapling_actions,
            ShieldedPool::Orchard => self.max_orchard_actions,
            ShieldedPool::Ironwood => self.max_ironwood_actions,
        }
    }

    /// Returns the limit on the number of transparent inputs each transaction spends, if any.
    pub fn max_transparent_inputs(&self) -> Option<usize> {
        self.max_transparent_inputs
    }

    /// Returns the limit on the number of transparent outputs each transaction creates, if
    /// any.
    pub fn max_transparent_outputs(&self) -> Option<usize> {
        self.max_transparent_outputs
    }

    /// Returns the limit on the number of shielded payment outputs each transaction creates,
    /// if any.
    pub fn max_shielded_payment_outputs(&self) -> Option<usize> {
        self.max_shielded_payment_outputs
    }

    /// Returns the first limit other than the byte limit that a transaction with the given
    /// shape violates, checking them in the order of the [`SizeBoundViolation`] variants.
    pub(super) fn count_violation(&self, shape: &super::StepShape) -> Option<SizeBoundViolation> {
        let exceeds = |count: usize, limit: Option<usize>| limit.filter(|limit| count > *limit);

        let pools = [
            ShieldedPool::Sapling,
            ShieldedPool::Orchard,
            ShieldedPool::Ironwood,
        ];
        let shielded_actions = pools.iter().map(|pool| shape.pool_actions(*pool)).sum();
        if let Some(limit) = exceeds(shielded_actions, self.max_shielded_actions) {
            return Some(SizeBoundViolation::ShieldedActions {
                count: shielded_actions,
                limit,
            });
        }
        for pool in pools {
            let count = shape.pool_actions(pool);
            if let Some(limit) = exceeds(count, self.max_pool_actions(pool)) {
                return Some(SizeBoundViolation::PoolActions { pool, count, limit });
            }
        }
        let count = shape.transparent_input_count();
        if let Some(limit) = exceeds(count, self.max_transparent_inputs) {
            return Some(SizeBoundViolation::TransparentInputs { count, limit });
        }
        let count = shape.transparent_output_count();
        if let Some(limit) = exceeds(count, self.max_transparent_outputs) {
            return Some(SizeBoundViolation::TransparentOutputs { count, limit });
        }
        let count = shape.shielded_payment_outputs();
        if let Some(limit) = exceeds(count, self.max_shielded_payment_outputs) {
            return Some(SizeBoundViolation::ShieldedPaymentOutputs { count, limit });
        }
        None
    }
}

impl Default for TransactionSizeBound {
    fn default() -> Self {
        Self::CONSENSUS
    }
}

/// A limit of a [`TransactionSizeBound`], other than its byte limit, that a transaction
/// exceeds. Each variant carries the transaction's estimated count and the limit it exceeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeBoundViolation {
    /// The total number of shielded actions exceeds
    /// [`TransactionSizeBound::max_shielded_actions`].
    ShieldedActions { count: usize, limit: usize },
    /// The number of shielded actions in `pool` exceeds
    /// [`TransactionSizeBound::max_pool_actions`].
    PoolActions {
        pool: ShieldedPool,
        count: usize,
        limit: usize,
    },
    /// The number of transparent inputs exceeds
    /// [`TransactionSizeBound::max_transparent_inputs`].
    TransparentInputs { count: usize, limit: usize },
    /// The number of transparent outputs exceeds
    /// [`TransactionSizeBound::max_transparent_outputs`].
    TransparentOutputs { count: usize, limit: usize },
    /// The number of shielded payment outputs exceeds
    /// [`TransactionSizeBound::max_shielded_payment_outputs`].
    ShieldedPaymentOutputs { count: usize, limit: usize },
}

impl Display for SizeBoundViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SizeBoundViolation::ShieldedActions { count, limit } => {
                write!(f, "{count} shielded actions exceed the limit of {limit}")
            }
            SizeBoundViolation::PoolActions { pool, count, limit } => {
                write!(f, "{count} {pool:?} actions exceed the limit of {limit}")
            }
            SizeBoundViolation::TransparentInputs { count, limit } => {
                write!(f, "{count} transparent inputs exceed the limit of {limit}")
            }
            SizeBoundViolation::TransparentOutputs { count, limit } => {
                write!(f, "{count} transparent outputs exceed the limit of {limit}")
            }
            SizeBoundViolation::ShieldedPaymentOutputs { count, limit } => write!(
                f,
                "{count} shielded payment outputs exceed the limit of {limit}"
            ),
        }
    }
}
