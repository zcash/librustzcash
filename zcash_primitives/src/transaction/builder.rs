//! Structs for building transactions.

use core::{cmp::Ordering, fmt};

use rand_core::{CryptoRng, Rng};

use ::sapling::{Note, PaymentAddress, builder::SaplingMetadata};
use ::transparent::{
    address::TransparentAddress, builder::TransparentBuilder, bundle::TxOut, coinbase,
};
use zcash_protocol::{
    PoolType,
    consensus::{self, BlockHeight, BranchId, Parameters},
    memo::MemoBytes,
    value::{BalanceError, ZatBalance, Zatoshis},
    zip218::{self, ShieldedActionCounts, ShieldedLimitExceeded},
};
use zcash_script::opcode::PushValue;

use crate::transaction::{
    Transaction, TxVersion,
    components::orchard::bundle_version_for_branch,
    fees::{
        FeeRule,
        transparent::{InputView, OutputView},
    },
};

#[cfg(feature = "std")]
use std::sync::mpsc::Sender;

#[cfg(feature = "circuits")]
use {
    crate::transaction::{
        Authorization, Coinbase, TransactionData, TxDigests, Unauthorized,
        sighash::{SignableInput, signature_hash},
        txid::TxIdDigester,
    },
    ::sapling::prover::{OutputProver, SpendProver},
    ::transparent::builder::TransparentSigningSet,
    alloc::vec::Vec,
};

#[cfg(feature = "transparent-inputs")]
use {::transparent::builder::TransparentInputInfo, zcash_script::script};

#[cfg(not(feature = "transparent-inputs"))]
use core::convert::Infallible;

use super::components::sapling::zip212_enforcement;

/// Since Blossom activation, the default transaction expiry delta should be 40 blocks.
/// <https://zips.z.cash/zip-0203#changes-for-blossom>
pub const DEFAULT_TX_EXPIRY_DELTA: u32 = 40;

/// Errors that can occur during fee calculation.
#[derive(Debug)]
pub enum FeeError<FE> {
    FeeRule(FE),
    Bundle(&'static str),
}

impl<FE: fmt::Display> fmt::Display for FeeError<FE> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FeeError::FeeRule(e) => write!(f, "An error occurred in fee calculation: {e}"),
            FeeError::Bundle(b) => write!(f, "Bundle structure invalid in fee calculation: {b}"),
        }
    }
}

/// Errors that can occur during transaction construction.
#[derive(Debug)]
pub enum Error<FE> {
    /// Insufficient funds were provided to the transaction builder; the given
    /// additional amount is required in order to construct the transaction.
    InsufficientFunds(ZatBalance),
    /// PCZT does not preserve a nonzero ZIP 233 amount.
    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    Zip233UnsupportedByPczt,
    /// The transaction has inputs in excess of outputs and fees; the user must
    /// add a change output.
    ChangeRequired(ZatBalance),
    /// An error occurred in computing the fees for a transaction.
    Fee(FeeError<FE>),
    /// An overflow or underflow occurred when computing value balances
    Balance(BalanceError),
    /// An error occurred in constructing the transparent parts of a transaction.
    TransparentBuild(transparent::builder::Error),
    /// An error occurred in constructing the Sapling parts of a transaction.
    SaplingBuild(sapling::builder::Error),
    /// An error occurred in constructing the Orchard parts of a transaction.
    OrchardBuild(orchard::builder::BuildError),
    /// An error occurred in constructing the Ironwood parts of a transaction.
    IronwoodBuild(orchard::builder::BuildError),
    /// An error occurred in adding an Orchard Spend to a transaction.
    OrchardSpend(orchard::builder::SpendError),
    /// An error occurred in adding an Orchard Output to a transaction.
    OrchardRecipient(orchard::builder::OutputError),
    /// An error occurred in adding an Ironwood Spend to a transaction.
    IronwoodSpend(orchard::builder::SpendError),
    /// An Ironwood spend note used an unsupported note plaintext version.
    IronwoodSpendUnsupportedNoteVersion(orchard::NoteVersion),
    /// An error occurred in adding an Ironwood Output to a transaction.
    IronwoodRecipient(orchard::builder::OutputError),
    /// The builder was constructed without support for the Sapling pool, but a Sapling
    /// spend or output was added.
    SaplingBuilderNotAvailable,
    /// The builder was constructed with a target height before NU5 activation, but an Orchard
    /// spend or output was added.
    OrchardBuilderNotAvailable,
    /// The builder was constructed with a target height before NU6.3 activation,
    /// or without an Ironwood anchor, but an Ironwood spend or output was added.
    IronwoodBuilderNotAvailable,
    /// Anchors can be deferred to proving time only under a transaction version whose
    /// txid and sighash exclude shielded anchors (V6, NU6.3 onward); this version commits
    /// its signatures to the anchors, so they must be supplied at build time (use
    /// [`Builder`]).
    AnchorDeferralUnsupported(TxVersion),
    /// An error occurred in constructing a coinbase transaction.
    Coinbase(coinbase::Error),
    /// A coinbase transaction's expiry height does not match its target block height.
    CoinbaseExpiryHeightMismatch {
        target_height: BlockHeight,
        expiry_height: BlockHeight,
    },
    /// The proposed transaction version or the consensus branch id for the target height does not
    /// support a feature required by the transaction under construction, or the proposed
    /// transaction version is not supported on the given consensus branch.
    TargetIncompatible(BranchId, TxVersion, Option<PoolType>),
    /// NU7 is active at the target height, and the transaction would contain more shielded
    /// components than [ZIP 218] allows in a block. The padding and dummy components that the
    /// builder adds are counted. To recover, build a transaction with fewer spends and outputs,
    /// for example after consolidating notes in transactions that each stay within the limits.
    ///
    /// [ZIP 218]: https://zips.z.cash/zip-0218
    ShieldedLimitExceeded(ShieldedLimitExceeded),
}

impl<FE: fmt::Display> fmt::Display for Error<FE> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InsufficientFunds(amount) => write!(
                f,
                "Insufficient funds for transaction construction; need an additional {amount:?} zatoshis"
            ),
            #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
            Error::Zip233UnsupportedByPczt => {
                write!(f, "PCZT does not support a nonzero ZIP 233 amount")
            }
            Error::ChangeRequired(amount) => write!(
                f,
                "The transaction requires an additional change output of {amount:?} zatoshis"
            ),
            Error::Balance(e) => write!(f, "Invalid amount {e:?}"),
            Error::Fee(e) => write!(f, "An error occurred in fee calculation: {e}"),
            Error::TransparentBuild(err) => err.fmt(f),
            Error::SaplingBuild(err) => err.fmt(f),
            Error::OrchardBuild(err) => write!(f, "{err:?}"),
            Error::IronwoodBuild(err) => write!(f, "{err:?}"),
            Error::OrchardSpend(err) => write!(f, "Could not add Orchard spend: {err}"),
            Error::OrchardRecipient(err) => write!(f, "Could not add Orchard recipient: {err}"),
            Error::IronwoodSpend(err) => write!(f, "Could not add Ironwood spend: {err}"),
            Error::IronwoodSpendUnsupportedNoteVersion(version) => write!(
                f,
                "Could not add Ironwood spend: note version {version:?} is unsupported"
            ),
            Error::IronwoodRecipient(err) => {
                write!(f, "Could not add Ironwood recipient: {err}")
            }
            Error::SaplingBuilderNotAvailable => write!(
                f,
                "Cannot create Sapling transactions without a Sapling anchor"
            ),
            Error::OrchardBuilderNotAvailable => write!(
                f,
                "Cannot create Orchard transactions without an Orchard anchor, or before NU5 activation"
            ),
            Error::IronwoodBuilderNotAvailable => write!(
                f,
                "Cannot create Ironwood transactions without an Ironwood anchor, or before NU6.3 activation"
            ),
            Error::AnchorDeferralUnsupported(version) => write!(
                f,
                "Transaction version {version:?} commits its signatures to shielded anchors, so anchors cannot be deferred to proving time"
            ),
            Error::Coinbase(err) => write!(
                f,
                "An error occurred in constructing a coinbase transaction: {err}"
            ),
            Error::CoinbaseExpiryHeightMismatch {
                target_height,
                expiry_height,
            } => write!(
                f,
                "Coinbase transaction expiry height {expiry_height} does not match target block height {target_height}"
            ),
            Error::TargetIncompatible(branch_id, version, pool_type) => match pool_type {
                None => write!(
                    f,
                    "Proposed transaction version {version:?} is not valid for consensus branch {branch_id:?}"
                ),
                Some(t) => write!(
                    f,
                    "{t} is not supported for proposed transaction version {version:?} or consensus branch {branch_id:?}"
                ),
            },
            Error::ShieldedLimitExceeded(err) => err.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl<FE: fmt::Debug + fmt::Display> std::error::Error for Error<FE> {}

impl<FE> From<BalanceError> for Error<FE> {
    fn from(e: BalanceError) -> Self {
        Error::Balance(e)
    }
}

impl<FE> From<FeeError<FE>> for Error<FE> {
    fn from(e: FeeError<FE>) -> Self {
        Error::Fee(e)
    }
}

impl<FE> From<sapling::builder::Error> for Error<FE> {
    fn from(e: sapling::builder::Error) -> Self {
        Error::SaplingBuild(e)
    }
}

impl<FE> From<orchard::builder::SpendError> for Error<FE> {
    fn from(e: orchard::builder::SpendError) -> Self {
        Error::OrchardSpend(e)
    }
}

impl<FE> From<coinbase::Error> for Error<FE> {
    fn from(e: coinbase::Error) -> Self {
        Error::Coinbase(e)
    }
}

/// Reports on the progress made by the builder towards building a transaction.
pub struct Progress {
    /// The number of steps completed.
    cur: u32,
    /// The expected total number of steps (as of this progress update), if known.
    end: Option<u32>,
}

impl From<(u32, u32)> for Progress {
    fn from((cur, end): (u32, u32)) -> Self {
        Self {
            cur,
            end: Some(end),
        }
    }
}

impl Progress {
    /// Returns the number of steps completed so far while building the transaction.
    ///
    /// Note that each step may not be of the same complexity/duration.
    pub fn cur(&self) -> u32 {
        self.cur
    }

    /// Returns the total expected number of steps before this transaction will be ready,
    /// or `None` if the end is unknown as of this progress update.
    ///
    /// Note that each step may not be of the same complexity/duration.
    pub fn end(&self) -> Option<u32> {
        self.end
    }
}

/// The padding policy for a transactional Orchard-family (Orchard or Ironwood) bundle.
///
/// This selects only the parameters that vary between transactional bundles: whether a
/// bundle is produced even when empty, and the minimum action count it is padded to. It
/// deliberately cannot express an [`orchard::builder::BundleType::Coinbase`] bundle:
/// coinbase construction is a property of the whole transaction, selected by
/// [`BuildConfig::Coinbase`], never of an individual pool. Storing padding here rather
/// than a full `BundleType` keeps the per-pool coinbase state unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundlePadding {
    /// Produce a bundle even when no spends or outputs have been added; the resulting
    /// bundle then consists entirely of dummy actions.
    pub bundle_required: bool,
    /// The minimum number of actions to pad the bundle to. `None` uses the orchard
    /// builder's default 2-action minimum; `Some(1)` leaves the bundle unpadded, so its
    /// action count reveals the transaction shape (acceptable when that shape is already
    /// public, e.g. pool migrations).
    pub pad_to_minimum: Option<u8>,
}

impl BundlePadding {
    /// The default padding, matching [`orchard::builder::BundleType::DEFAULT`]: an empty
    /// bundle is not produced, and a non-empty bundle is padded to the default minimum.
    pub const DEFAULT: BundlePadding = BundlePadding {
        bundle_required: false,
        pad_to_minimum: None,
    };

    /// Unpadded transactional padding, matching [`orchard::builder::BundleType::UNPADDED`]:
    /// the bundle is padded only to the one-action consensus minimum, so it contains
    /// exactly the requested actions.
    pub const UNPADDED: BundlePadding = BundlePadding {
        bundle_required: false,
        pad_to_minimum: Some(1),
    };

    /// Returns the orchard [`BundleType`](orchard::builder::BundleType) selecting this
    /// padding. The result is always a `Transactional` bundle type.
    pub fn bundle_type(self) -> orchard::builder::BundleType {
        orchard::builder::BundleType::Transactional {
            bundle_required: self.bundle_required,
            pad_to_minimum: self.pad_to_minimum,
        }
    }
}

/// Rules for how the builder should be configured for each shielded pool or coinbase tx.
#[derive(Clone)]
pub enum BuildConfig {
    Standard {
        sapling_anchor: Option<sapling::Anchor>,
        orchard_anchor: Option<orchard::Anchor>,
        ironwood_anchor: Option<orchard::Anchor>,
        orchard_padding: BundlePadding,
        ironwood_padding: BundlePadding,
    },
    Coinbase {
        miner_data: Option<PushValue>,
    },
}

impl BuildConfig {
    /// Returns the Sapling bundle type and anchor for this configuration.
    pub fn sapling_builder_config(
        &self,
    ) -> Option<(sapling::builder::BundleType, sapling::Anchor)> {
        match self {
            BuildConfig::Standard { sapling_anchor, .. } => sapling_anchor
                .as_ref()
                .map(|a| (sapling::builder::BundleType::DEFAULT, *a)),
            BuildConfig::Coinbase { .. } => Some((
                sapling::builder::BundleType::Coinbase,
                sapling::Anchor::empty_tree(),
            )),
        }
    }

    /// Returns the Orchard builder for this configuration.
    fn orchard_builder(
        &self,
        bundle_version: orchard::bundle::BundleVersion,
    ) -> Option<orchard::builder::Builder> {
        match self {
            BuildConfig::Standard {
                orchard_anchor,
                orchard_padding,
                ..
            } => orchard_anchor.as_ref().map(|a| {
                orchard::builder::Builder::new(
                    orchard_padding.bundle_type(),
                    bundle_version,
                    bundle_version.default_flags(),
                    *a,
                )
                .expect("a transactional bundle type with default flags is always representable")
            }),
            BuildConfig::Coinbase { .. }
                if bundle_version == orchard::bundle::BundleVersion::orchard_v3() =>
            {
                None
            }
            BuildConfig::Coinbase { .. } => Some(
                orchard::builder::Builder::new(
                    orchard::builder::BundleType::Coinbase,
                    bundle_version,
                    // Coinbase transactions have `enableSpends = 0`. Every protocol version
                    // for which a coinbase Orchard-pool bundle can be built (pre-NU6.3) permits
                    // cross-address transfers, so the spends-disabled flag set is representable.
                    orchard::bundle::Flags::SPENDS_DISABLED,
                    orchard::Anchor::empty_tree(),
                )
                .expect("spends-disabled flags are valid for a non-Orchard coinbase bundle"),
            ),
        }
    }

    /// Returns the Ironwood builder for this configuration.
    fn ironwood_builder(&self) -> Option<orchard::builder::Builder> {
        let bundle_version = orchard::bundle::BundleVersion::ironwood_v3();
        match self {
            BuildConfig::Standard {
                ironwood_anchor,
                ironwood_padding,
                ..
            } => ironwood_anchor.as_ref().map(|a| {
                orchard::builder::Builder::new(
                    ironwood_padding.bundle_type(),
                    bundle_version,
                    bundle_version.default_flags(),
                    *a,
                )
                .expect("a transactional bundle type with default flags is always representable")
            }),
            BuildConfig::Coinbase { .. } => Some(
                orchard::builder::Builder::new(
                    orchard::builder::BundleType::Coinbase,
                    bundle_version,
                    orchard::bundle::Flags::SPENDS_DISABLED,
                    orchard::Anchor::empty_tree(),
                )
                .expect("spends-disabled flags are valid for an Ironwood coinbase bundle"),
            ),
        }
    }

    /// Returns `true` if this configuration is for building a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        matches!(self, BuildConfig::Coinbase { .. })
    }
}

fn orchard_action_count(
    builder: &orchard::builder::Builder,
    is_coinbase: bool,
    bundle_version: orchard::bundle::BundleVersion,
) -> Result<usize, &'static str> {
    let num_spends = builder.spends().len();
    let num_outputs = builder
        .outputs()
        .len()
        .checked_add(builder.changes().len())
        .ok_or("num_outputs + num_changes overflowed")?;

    // The bundle type must match the one the builder was constructed with (see
    // `orchard_builder` / `ironwood_builder`); read it back from the builder so
    // the two cannot drift.
    let bundle_type = builder.bundle_type();

    // The flags must match those the builder constructs for each configuration (see
    // `orchard_builder`). For a `Coinbase` bundle `num_actions` ignores the flags, but supplying
    // the matching set keeps the two paths consistent.
    let flags = if is_coinbase {
        orchard::bundle::Flags::SPENDS_DISABLED
    } else {
        bundle_version.default_flags()
    };

    bundle_type.num_actions(flags, num_spends, num_outputs)
}

/// Returns `true` if any spend, output, or change output has been added to `builder`.
fn orchard_builder_in_use(builder: &orchard::builder::Builder) -> bool {
    !builder.spends().is_empty() || !builder.outputs().is_empty() || !builder.changes().is_empty()
}

/// Verifies that, if the [ZIP 218] limits apply at `target_height`, the shielded components that
/// `counts` returns for the transaction under construction stay within them. `counts` is called
/// only if the limits apply.
///
/// [ZIP 218]: https://zips.z.cash/zip-0218
fn check_shielded_limits<P: consensus::Parameters, FE>(
    params: &P,
    target_height: BlockHeight,
    counts: impl FnOnce() -> Result<ShieldedActionCounts, &'static str>,
) -> Result<(), Error<FE>> {
    if !zip218::limits_apply(params, target_height) {
        return Ok(());
    }

    counts()
        .map_err(|e| Error::Fee(FeeError::Bundle(e)))?
        .check()
        .map_err(Error::ShieldedLimitExceeded)
}

/// A builder for V6 and later transactions constructed as PCZTs with their
/// Orchard-family anchors DEFERRED to proving time, per [ZIP 374].
///
/// [`Builder`] requires each shielded pool's anchor in its [`BuildConfig`] and a Merkle
/// witness rooting to it for every spend it adds. This builder takes no anchors at all:
/// spends are added as bare `(fvk, note)` pairs through the `orchard` crate's own
/// deferred-anchor support ([`orchard::builder::Builder::new_with_anchor_deferred`]), and the
/// emitted PCZT carries ABSENT anchor and witness fields, which the PCZT Updater role
/// (`set_{orchard,ironwood}_anchor` / `set_*_spend_witnesses`) fills in at proving time,
/// after the transaction has been finalized and SIGNED. This is sound exactly for V6 and later
/// transaction formats, whose txid and sighash exclude Sapling and Orchard-family anchors (they are
/// committed only by the authorizing-data digest), so neither the transaction id nor any
/// signature commits to the deferred values; [`Self::new`] refuses any earlier format.
/// The witness-to-anchor consistency check that [`Builder`] performs per spend at
/// add-spend time is performed instead by the PCZT Prover role, once the real anchor and
/// witnesses are present.
///
/// The builder is deliberately restricted to the two Orchard-family pools (Orchard and
/// Ironwood): their nullifiers are derived from the note alone, so a spend can be signed
/// before its witness is known. A Sapling nullifier commits to the note's tree position,
/// so Sapling spends can never defer their witnesses, and transparent inputs are out of
/// scope for the pre-signing flows this builder serves; use [`Builder`] for those.
///
/// [ZIP 374]: https://zips.z.cash/zip-0374
pub struct DeferredPcztBuilder<P> {
    params: P,
    tx_version: TxVersion,
    consensus_branch_id: BranchId,
    target_height: BlockHeight,
    expiry_height: BlockHeight,
    orchard_builder: orchard::builder::Builder,
    orchard_bundle_version: orchard::bundle::BundleVersion,
    ironwood_builder: orchard::builder::Builder,
}

impl<P: consensus::Parameters> DeferredPcztBuilder<P> {
    /// Creates a builder targeting the block at `target_height`, with the given
    /// transactional bundle padding for each Orchard-family pool.
    ///
    /// The expiry height defaults to `target_height` plus the default transaction expiry
    /// delta; override it with [`Self::with_expiry_height`].
    ///
    /// Returns [`Error::AnchorDeferralUnsupported`] if the consensus branch in effect at
    /// `target_height` uses a transaction format older than V6, whose txid and sighash include
    /// Sapling and Orchard-family anchors; under those formats the anchors cannot outlive
    /// signing.
    pub fn new<FE>(
        params: P,
        target_height: BlockHeight,
        orchard_padding: BundlePadding,
        ironwood_padding: BundlePadding,
    ) -> Result<Self, Error<FE>> {
        let consensus_branch_id = BranchId::for_height(&params, target_height);
        let tx_version = TxVersion::suggested_for_branch(consensus_branch_id);
        if !tx_version.has_ironwood() {
            return Err(Error::AnchorDeferralUnsupported(tx_version));
        }
        let orchard_bundle_version =
            bundle_version_for_branch(consensus_branch_id, orchard::ValuePool::Orchard)
                .expect("a branch with the V6 format supports the Orchard pool");
        let orchard_builder = orchard::builder::Builder::new_with_anchor_deferred(
            orchard_padding.bundle_type(),
            orchard_bundle_version,
            orchard_bundle_version.default_flags(),
            orchard::bundle::TxVersion::V6,
        )
        .map_err(Error::OrchardBuild)?;
        let ironwood_bundle_version = orchard::bundle::BundleVersion::ironwood_v3();
        let ironwood_builder = orchard::builder::Builder::new_with_anchor_deferred(
            ironwood_padding.bundle_type(),
            ironwood_bundle_version,
            ironwood_bundle_version.default_flags(),
            orchard::bundle::TxVersion::V6,
        )
        .map_err(Error::IronwoodBuild)?;
        Ok(DeferredPcztBuilder {
            params,
            tx_version,
            consensus_branch_id,
            target_height,
            expiry_height: target_height + DEFAULT_TX_EXPIRY_DELTA,
            orchard_builder,
            orchard_bundle_version,
            ironwood_builder,
        })
    }

    /// Overrides the expiry height for the transaction under construction.
    ///
    /// A pre-signed transaction is often broadcast well after it is built, so the caller
    /// typically sets an expiry derived from the intended broadcast schedule rather than
    /// the build height; the signatures commit to it.
    pub fn with_expiry_height(mut self, expiry_height: BlockHeight) -> Self {
        self.expiry_height = expiry_height;
        self
    }

    /// Adds an Orchard note to be spent in this bundle, WITHOUT a witness: the witness,
    /// like the bundle's anchor, is installed at proving time through the PCZT Updater
    /// role.
    pub fn add_orchard_spend<FE>(
        &mut self,
        fvk: orchard::keys::FullViewingKey,
        note: orchard::Note,
    ) -> Result<(), Error<FE>> {
        self.orchard_builder.add_spend_unwitnessed(fvk, note)?;
        Ok(())
    }

    /// Adds an Orchard recipient to the transaction.
    pub fn add_orchard_output<FE>(
        &mut self,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: orchard::Address,
        value: Zatoshis,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.orchard_builder
            .add_output(
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value.into()),
                memo.into_bytes(),
            )
            .map_err(Error::OrchardRecipient)
    }

    /// Adds a wallet-controlled Orchard change output to the transaction.
    pub fn add_orchard_change_output<FE>(
        &mut self,
        fvk: orchard::keys::FullViewingKey,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: orchard::Address,
        value: Zatoshis,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.orchard_builder
            .add_change_output(
                fvk,
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value.into()),
                memo.into_bytes(),
            )
            .map_err(Error::OrchardRecipient)
    }

    /// Adds an Ironwood note to be spent in this bundle, WITHOUT a witness (see
    /// [`Self::add_orchard_spend`]).
    ///
    /// The note must use [`orchard::note::NoteVersion::V3`], the Ironwood note plaintext
    /// format.
    pub fn add_ironwood_spend<FE>(
        &mut self,
        fvk: orchard::keys::FullViewingKey,
        note: orchard::Note,
    ) -> Result<(), Error<FE>> {
        if note.version() != orchard::note::NoteVersion::V3 {
            return Err(Error::IronwoodSpendUnsupportedNoteVersion(note.version()));
        }
        self.ironwood_builder
            .add_spend_unwitnessed(fvk, note)
            .map_err(Error::IronwoodSpend)
    }

    /// Adds an Ironwood recipient to the transaction.
    ///
    /// This uses [`orchard::note::NoteVersion::V3`], the Ironwood note plaintext format.
    pub fn add_ironwood_output<FE>(
        &mut self,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: orchard::Address,
        value: Zatoshis,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.ironwood_builder
            .add_output(
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value.into()),
                memo.into_bytes(),
            )
            .map_err(Error::IronwoodRecipient)
    }

    /// Reports the calculated fee given the specified fee rule, as a function of the
    /// spends and outputs added so far (each pool's action count includes the padding its
    /// bundle type prescribes).
    pub fn get_fee<FR: FeeRule>(&self, fee_rule: &FR) -> Result<Zatoshis, FeeError<FR::Error>> {
        fee_rule
            .fee_required(
                &self.params,
                self.target_height,
                core::iter::empty::<crate::transaction::fees::transparent::InputSize>(),
                core::iter::empty::<usize>(),
                0,
                0,
                orchard_action_count(&self.orchard_builder, false, self.orchard_bundle_version)
                    .map_err(FeeError::Bundle)?,
                orchard_action_count(
                    &self.ironwood_builder,
                    false,
                    orchard::bundle::BundleVersion::ironwood_v3(),
                )
                .map_err(FeeError::Bundle)?,
            )
            .map_err(FeeError::FeeRule)
    }

    /// Returns the numbers of shielded components that [`Self::build_for_pczt`] will produce,
    /// including the padding that the bundle types add. A pool to which nothing has been added
    /// produces no bundle, and so no components; this builder constructs no Sapling or Sprout
    /// components.
    ///
    /// # Errors
    ///
    /// Returns an error if a bundle type cannot represent the spends and outputs added so far.
    pub(crate) fn shielded_action_counts(&self) -> Result<ShieldedActionCounts, &'static str> {
        let orchard_actions = if orchard_builder_in_use(&self.orchard_builder) {
            orchard_action_count(&self.orchard_builder, false, self.orchard_bundle_version)?
        } else {
            0
        };

        let ironwood_actions = if orchard_builder_in_use(&self.ironwood_builder) {
            orchard_action_count(
                &self.ironwood_builder,
                false,
                orchard::bundle::BundleVersion::ironwood_v3(),
            )?
        } else {
            0
        };

        Ok(ShieldedActionCounts::ZERO
            .with_orchard_actions(orchard_actions)
            .with_ironwood_actions(ironwood_actions))
    }

    /// Builds the added spends and outputs into the parts of an unproven PCZT whose
    /// anchors and real-spend witnesses are ABSENT, deferred to proving time: pass the
    /// result to the PCZT Creator (`build_from_parts`), then finalize, sign, and — at
    /// proving time — install the real anchor and witnesses through the PCZT Updater
    /// role before proving.
    ///
    /// Returns [`Error::ShieldedLimitExceeded`] if NU7 is active at the target height and the
    /// PCZT would exceed a [ZIP 218] limit on the shielded components of a block.
    ///
    /// [ZIP 218]: https://zips.z.cash/zip-0218
    pub fn build_for_pczt<R: Rng + CryptoRng, FR: FeeRule>(
        self,
        mut rng: R,
        fee_rule: &FR,
    ) -> Result<PcztResult<P>, Error<FR::Error>> {
        check_shielded_limits::<_, FR::Error>(&self.params, self.target_height, || {
            self.shielded_action_counts()
        })?;

        let fee = self.get_fee(fee_rule).map_err(Error::Fee)?;

        // After fees are accounted for, the value balance of the transaction must be zero.
        let value_balance = [
            self.orchard_builder
                .value_balance::<ZatBalance>()
                .map_err(|_| BalanceError::Overflow)?,
            self.ironwood_builder
                .value_balance::<ZatBalance>()
                .map_err(|_| BalanceError::Overflow)?,
        ]
        .into_iter()
        .sum::<Option<ZatBalance>>()
        .ok_or(BalanceError::Overflow)?;
        let balance_after_fees = (value_balance - fee).ok_or(BalanceError::Underflow)?;
        match balance_after_fees.cmp(&ZatBalance::zero()) {
            Ordering::Less => {
                return Err(Error::InsufficientFunds(-balance_after_fees));
            }
            Ordering::Greater => {
                return Err(Error::ChangeRequired(balance_after_fees));
            }
            Ordering::Equal => (),
        };

        let (orchard_bundle, orchard_meta) = if orchard_builder_in_use(&self.orchard_builder) {
            let (bundle, meta) = self
                .orchard_builder
                .build_for_pczt(&mut rng)
                .map_err(Error::OrchardBuild)?;
            (Some(bundle), meta)
        } else {
            (None, orchard::builder::BundleMetadata::empty())
        };
        let (ironwood_bundle, ironwood_meta) = if orchard_builder_in_use(&self.ironwood_builder) {
            let (bundle, meta) = self
                .ironwood_builder
                .build_for_pczt(&mut rng)
                .map_err(Error::IronwoodBuild)?;
            (Some(bundle), meta)
        } else {
            (None, orchard::builder::BundleMetadata::empty())
        };

        Ok(PcztResult {
            pczt_parts: PcztParts {
                params: self.params,
                version: self.tx_version,
                consensus_branch_id: self.consensus_branch_id,
                lock_time: 0,
                expiry_height: self.expiry_height,
                transparent: None,
                sapling: None,
                orchard: orchard_bundle,
                ironwood: ironwood_bundle,
            },
            sapling_meta: SaplingMetadata::empty(),
            orchard_meta,
            ironwood_meta,
        })
    }
}

/// The result of a transaction build operation, which includes the resulting transaction along
/// with metadata describing how spends and outputs were shuffled in creating the transaction's
/// shielded bundles.
#[derive(Debug)]
pub struct BuildResult {
    transaction: Transaction,
    sapling_meta: SaplingMetadata,
    orchard_meta: orchard::builder::BundleMetadata,
    ironwood_meta: orchard::builder::BundleMetadata,
}

impl BuildResult {
    /// Returns the transaction that was constructed by the builder.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Returns the mapping from Sapling inputs and outputs to their randomized positions in the
    /// Sapling bundle in the newly constructed transaction.
    pub fn sapling_meta(&self) -> &SaplingMetadata {
        &self.sapling_meta
    }

    /// Returns the mapping from Orchard inputs and outputs to the randomized positions of the
    /// Actions that contain them in the Orchard bundle in the newly constructed transaction.
    pub fn orchard_meta(&self) -> &orchard::builder::BundleMetadata {
        &self.orchard_meta
    }

    /// Returns the mapping from Ironwood inputs and outputs to the randomized
    /// positions of the Actions that contain them in the Ironwood bundle in
    /// the newly constructed transaction.
    pub fn ironwood_meta(&self) -> &orchard::builder::BundleMetadata {
        &self.ironwood_meta
    }
}

/// The result of [`Builder::build_for_pczt`].
///
/// It includes the PCZT components along with metadata describing how spends and outputs
/// were shuffled in creating the transaction's shielded bundles.
#[derive(Debug)]
pub struct PcztResult<P: Parameters> {
    pub pczt_parts: PcztParts<P>,
    pub sapling_meta: SaplingMetadata,
    pub orchard_meta: orchard::builder::BundleMetadata,
    pub ironwood_meta: orchard::builder::BundleMetadata,
}

/// The components of a PCZT.
#[derive(Debug)]
pub struct PcztParts<P: Parameters> {
    pub params: P,
    pub version: TxVersion,
    pub consensus_branch_id: BranchId,
    pub lock_time: u32,
    pub expiry_height: BlockHeight,
    pub transparent: Option<transparent::pczt::Bundle>,
    pub sapling: Option<sapling::pczt::Bundle>,
    pub orchard: Option<orchard::pczt::Bundle>,
    pub ironwood: Option<orchard::pczt::Bundle>,
}

/// Generates a [`Transaction`] from its inputs and outputs.
pub struct Builder<P, U> {
    params: P,
    tx_version: TxVersion,
    consensus_branch_id: BranchId,
    build_config: BuildConfig,
    target_height: BlockHeight,
    expiry_height: BlockHeight,
    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    zip233_amount: Zatoshis,
    transparent_builder: TransparentBuilder,
    sapling_builder: Option<sapling::builder::Builder>,
    orchard_builder: Option<orchard::builder::Builder>,
    orchard_bundle_version: Option<orchard::bundle::BundleVersion>,
    ironwood_builder: Option<orchard::builder::Builder>,
    _progress_notifier: U,
}

impl<P, U> Builder<P, U> {
    /// Returns the network parameters that the builder has been configured for.
    pub fn params(&self) -> &P {
        &self.params
    }

    /// Returns the target height of the transaction under construction.
    pub fn target_height(&self) -> BlockHeight {
        self.target_height
    }

    /// Returns the set of transparent inputs currently committed to be consumed
    /// by the transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent_inputs(&self) -> &[TransparentInputInfo] {
        self.transparent_builder.inputs()
    }

    /// Returns the set of transparent outputs currently set to be produced by
    /// the transaction.
    pub fn transparent_outputs(&self) -> &[TxOut] {
        self.transparent_builder.outputs()
    }

    /// Returns the set of Sapling inputs currently committed to be consumed
    /// by the transaction.
    pub fn sapling_inputs(&self) -> &[sapling::builder::SpendInfo] {
        self.sapling_builder
            .as_ref()
            .map_or_else(|| &[][..], |b| b.inputs())
    }

    /// Returns the set of Sapling outputs currently set to be produced by
    /// the transaction.
    pub fn sapling_outputs(&self) -> &[sapling::builder::OutputInfo] {
        self.sapling_builder
            .as_ref()
            .map_or_else(|| &[][..], |b| b.outputs())
    }

    /// Returns `true` if any Orchard spend, output, or change output has been
    /// added to this builder (i.e. the transaction will carry an Orchard bundle).
    fn orchard_in_use(&self) -> bool {
        self.orchard_builder.as_ref().is_some_and(|b| {
            !b.spends().is_empty() || !b.outputs().is_empty() || !b.changes().is_empty()
        })
    }

    /// Returns `true` if any Ironwood spend, output, or change output has been
    /// added to this builder (i.e. the transaction will carry an Ironwood bundle).
    fn ironwood_in_use(&self) -> bool {
        self.ironwood_builder.as_ref().is_some_and(|b| {
            !b.spends().is_empty() || !b.outputs().is_empty() || !b.changes().is_empty()
        })
    }

    /// Returns the numbers of shielded components in the transaction or PCZT that this builder
    /// will build, including the padding and dummy components that its bundle types add. A
    /// builder constructs no Sprout components. Under a proposed transaction version without an
    /// Ironwood bundle, [`Self::build_for_pczt`] omits an Ironwood bundle that is required but
    /// empty, which this count still includes (an over-count).
    ///
    /// # Errors
    ///
    /// Returns an error if a bundle type cannot represent the spends and outputs added so far.
    pub(crate) fn shielded_action_counts(&self) -> Result<ShieldedActionCounts, &'static str> {
        let (sapling_spends, sapling_outputs) = match self
            .sapling_builder
            .as_ref()
            .zip(self.build_config.sapling_builder_config())
        {
            Some((builder, (bundle_type, _))) => {
                let requested_spends = builder.inputs().len();
                (
                    bundle_type.num_spends(requested_spends)?,
                    bundle_type.num_outputs(requested_spends, builder.outputs().len())?,
                )
            }
            None => (0, 0),
        };

        let orchard_actions = self.orchard_builder.as_ref().map_or(Ok(0), |builder| {
            orchard_action_count(
                builder,
                self.build_config.is_coinbase(),
                self.orchard_bundle_version
                    .expect("orchard builder present implies bundle version"),
            )
        })?;

        let ironwood_actions = self.ironwood_builder.as_ref().map_or(Ok(0), |builder| {
            orchard_action_count(
                builder,
                self.build_config.is_coinbase(),
                orchard::bundle::BundleVersion::ironwood_v3(),
            )
        })?;

        Ok(ShieldedActionCounts::ZERO
            .with_sapling(sapling_spends, sapling_outputs)
            .with_orchard_actions(orchard_actions)
            .with_ironwood_actions(ironwood_actions))
    }

    /// Checks that the given version supports all features required by the inputs and
    /// outputs already added to the builder.
    fn check_version_compatibility<FE>(&self, version: TxVersion) -> Result<(), Error<FE>> {
        if !version.valid_in_branch(self.consensus_branch_id) {
            return Err(Error::TargetIncompatible(
                self.consensus_branch_id,
                version,
                None,
            ));
        }

        #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
        if self.zip233_amount != Zatoshis::ZERO && !version.has_zip233(self.consensus_branch_id) {
            return Err(Error::TargetIncompatible(
                self.consensus_branch_id,
                version,
                None,
            ));
        }

        let sapling_available = version.has_sapling() && self.consensus_branch_id.has_sapling();
        if !sapling_available
            && (!self.sapling_inputs().is_empty() || !self.sapling_outputs().is_empty())
        {
            return Err(Error::TargetIncompatible(
                self.consensus_branch_id,
                version,
                Some(PoolType::SAPLING),
            ));
        }

        let orchard_available = version.has_orchard() && self.consensus_branch_id.has_orchard();
        if !orchard_available && self.orchard_in_use() {
            return Err(Error::TargetIncompatible(
                self.consensus_branch_id,
                version,
                Some(PoolType::ORCHARD),
            ));
        }

        {
            // Ironwood is available only when the target version carries an Ironwood bundle
            // and the consensus branch is one in which Ironwood is active.
            let ironwood_branch = match self.consensus_branch_id {
                BranchId::Nu6_3 => true,
                BranchId::Nu7 => true,
                #[cfg(zcash_unstable = "nutachyon")]
                BranchId::NuTachyon => true,
                _ => false,
            };
            let ironwood_available = version.has_ironwood() && ironwood_branch;
            if !ironwood_available && self.ironwood_in_use() {
                return Err(Error::TargetIncompatible(
                    self.consensus_branch_id,
                    version,
                    None,
                ));
            }
        }

        Ok(())
    }

    /// Proposes a specific transaction version.
    ///
    /// Validates that the proposed version supports all features required by
    /// the inputs and outputs already added to the builder. Returns
    /// [`Error::TargetIncompatible`] if validation fails.
    ///
    /// The same validation is performed at build time to catch inputs/outputs
    /// added after this call.
    pub fn propose_version<FE>(&mut self, version: TxVersion) -> Result<(), Error<FE>> {
        self.check_version_compatibility(version)?;
        self.tx_version = version;
        Ok(())
    }
}

impl<P: consensus::Parameters> Builder<P, ()> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height,
    /// using default values for general transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    pub fn new(params: P, target_height: BlockHeight, build_config: BuildConfig) -> Self {
        let consensus_branch_id = BranchId::for_height(&params, target_height);
        // `bundle_version_for_branch` returns `Some` exactly for the branches in
        // which the Orchard pool is supported (NU5 onward), so this also gates
        // Orchard builder construction on NU5 activation.
        let bundle_version =
            bundle_version_for_branch(consensus_branch_id, orchard::ValuePool::Orchard);
        // Default transaction version for the branch.
        let tx_version = TxVersion::suggested_for_branch(consensus_branch_id);

        let orchard_builder = bundle_version.and_then(|v| build_config.orchard_builder(v));
        let orchard_bundle_version = orchard_builder.as_ref().and(bundle_version);

        // The Ironwood builder exists exactly when the branch's transaction version
        // carries an Ironwood bundle.
        let ironwood_builder = if tx_version.has_ironwood() {
            build_config.ironwood_builder()
        } else {
            None
        };

        let sapling_builder = build_config
            .sapling_builder_config()
            .map(|(bundle_type, anchor)| {
                sapling::builder::Builder::new(
                    zip212_enforcement(&params, target_height),
                    bundle_type,
                    anchor,
                )
            });

        // # Consensus Rules
        //
        // > [NU5 onward] The `nExpiryHeight` field of a coinbase transaction MUST be equal to its
        // > block height.
        //
        // ## Notes
        //
        // We set the expiry height for coinbase txs to the block height regardless of the network
        // upgrade.
        let expiry_height = if build_config.is_coinbase() {
            target_height
        } else {
            target_height + DEFAULT_TX_EXPIRY_DELTA
        };

        Builder {
            params,
            tx_version,
            consensus_branch_id,
            build_config,
            target_height,
            expiry_height,
            #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
            zip233_amount: Zatoshis::ZERO,
            transparent_builder: TransparentBuilder::empty(),
            sapling_builder,
            orchard_builder,
            orchard_bundle_version,
            ironwood_builder,
            _progress_notifier: (),
        }
    }

    /// Sets the notifier channel, where progress of building the transaction is sent.
    ///
    /// An update is sent after every Sapling Spend or Output is computed, and the `u32`
    /// sent represents the total steps completed so far. It will eventually send number
    /// of spends + outputs. If there's an error building the transaction, the channel is
    /// closed.
    #[cfg(feature = "std")]
    pub fn with_progress_notifier(
        self,
        _progress_notifier: Sender<Progress>,
    ) -> Builder<P, Sender<Progress>> {
        Builder {
            params: self.params,
            tx_version: self.tx_version,
            consensus_branch_id: self.consensus_branch_id,
            build_config: self.build_config,
            target_height: self.target_height,
            expiry_height: self.expiry_height,
            #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
            zip233_amount: self.zip233_amount,
            transparent_builder: self.transparent_builder,
            sapling_builder: self.sapling_builder,
            orchard_builder: self.orchard_builder,
            orchard_bundle_version: self.orchard_bundle_version,
            ironwood_builder: self.ironwood_builder,
            _progress_notifier,
        }
    }
}

impl<P: consensus::Parameters, U> Builder<P, U> {
    /// Overrides the expiry height for the transaction under construction.
    ///
    /// For non-coinbase transactions, setting this to `BlockHeight::from(0)`
    /// disables transaction expiry. Coinbase builders reject overridden expiry
    /// heights that do not match the target block height.
    ///
    /// Disabling expiry by setting the height to `BlockHeight::from(0)` is not
    /// recommended: non-expiring transactions are not yet well tested
    /// end-to-end and are known to cause bugs elsewhere in the stack. Callers
    /// should avoid a zero expiry height unless they specifically need it.
    pub fn with_expiry_height(mut self, expiry_height: BlockHeight) -> Self {
        self.expiry_height = expiry_height;
        self
    }

    /// Verifies that a coinbase transaction's expiry height matches its target
    /// block height, as required for coinbase transactions.
    fn check_coinbase_expiry_height<FE>(&self) -> Result<(), Error<FE>> {
        if self.build_config.is_coinbase() && self.expiry_height != self.target_height {
            Err(Error::CoinbaseExpiryHeightMismatch {
                target_height: self.target_height,
                expiry_height: self.expiry_height,
            })
        } else {
            Ok(())
        }
    }

    /// Adds an Orchard note to be spent in this bundle.
    ///
    /// Returns an error if the given Merkle path does not have the required anchor for
    /// the given note.
    pub fn add_orchard_spend<FE>(
        &mut self,
        fvk: orchard::keys::FullViewingKey,
        note: orchard::Note,
        merkle_path: orchard::tree::MerklePath,
    ) -> Result<(), Error<FE>> {
        if let Some(builder) = self.orchard_builder.as_mut() {
            builder.add_spend(fvk, note, merkle_path)?;
            Ok(())
        } else {
            Err(Error::OrchardBuilderNotAvailable)
        }
    }

    /// Adds an Orchard recipient to the transaction.
    pub fn add_orchard_output<FE>(
        &mut self,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: orchard::Address,
        value: Zatoshis,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.orchard_builder
            .as_mut()
            .ok_or(Error::OrchardBuilderNotAvailable)?
            .add_output(
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value.into()),
                memo.into_bytes(),
            )
            .map_err(Error::OrchardRecipient)
    }

    /// Adds a wallet-controlled Orchard change output to the transaction.
    ///
    /// Returns [`Error::OrchardBuilderNotAvailable`] if this builder is not
    /// configured with an Orchard bundle builder. Returns
    /// [`Error::OrchardRecipient`] if the Orchard builder rejects the recipient
    /// or cannot construct the output.
    pub fn add_orchard_change_output<FE>(
        &mut self,
        fvk: orchard::keys::FullViewingKey,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: orchard::Address,
        value: Zatoshis,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.orchard_builder
            .as_mut()
            .ok_or(Error::OrchardBuilderNotAvailable)?
            .add_change_output(
                fvk,
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value.into()),
                memo.into_bytes(),
            )
            .map_err(Error::OrchardRecipient)
    }

    /// Adds an Ironwood note to be spent in this bundle.
    ///
    /// The note must use [`orchard::note::NoteVersion::V3`], the Ironwood
    /// note plaintext format.
    ///
    /// Returns an error if the given note has an unsupported version, or if
    /// the given Merkle path does not have the required Ironwood anchor for the
    /// note.
    pub fn add_ironwood_spend<FE>(
        &mut self,
        fvk: orchard::keys::FullViewingKey,
        note: orchard::Note,
        merkle_path: orchard::tree::MerklePath,
    ) -> Result<(), Error<FE>> {
        let builder = self
            .ironwood_builder
            .as_mut()
            .ok_or(Error::IronwoodBuilderNotAvailable)?;

        if note.version() != orchard::note::NoteVersion::V3 {
            return Err(Error::IronwoodSpendUnsupportedNoteVersion(note.version()));
        }

        builder
            .add_spend(fvk, note, merkle_path)
            .map_err(Error::IronwoodSpend)?;
        Ok(())
    }

    /// Adds an Ironwood recipient to the transaction.
    ///
    /// This uses [`orchard::note::NoteVersion::V3`], the Ironwood note
    /// plaintext format.
    pub fn add_ironwood_output<FE>(
        &mut self,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: orchard::Address,
        value: Zatoshis,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.ironwood_builder
            .as_mut()
            .ok_or(Error::IronwoodBuilderNotAvailable)?
            .add_output(
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value.into()),
                memo.into_bytes(),
            )
            .map_err(Error::IronwoodRecipient)
    }

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_sapling_spend<FE>(
        &mut self,
        fvk: sapling::keys::FullViewingKey,
        note: Note,
        merkle_path: sapling::MerklePath,
    ) -> Result<(), Error<FE>> {
        if let Some(builder) = self.sapling_builder.as_mut() {
            builder.add_spend(fvk, note, merkle_path)?;
            Ok(())
        } else {
            Err(Error::SaplingBuilderNotAvailable)
        }
    }

    /// Adds a Sapling address to send funds to.
    pub fn add_sapling_output<FE>(
        &mut self,
        ovk: Option<sapling::keys::OutgoingViewingKey>,
        to: PaymentAddress,
        value: Zatoshis,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.sapling_builder
            .as_mut()
            .ok_or(Error::SaplingBuilderNotAvailable)?
            .add_output(
                ovk,
                to,
                sapling::value::NoteValue::from_raw(u64::from(value)),
                memo.into_bytes(),
            )
            .map_err(Error::SaplingBuild)
    }

    /// Adds a transparent coin to be spent in this transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_transparent_input(&mut self, input: TransparentInputInfo) {
        self.transparent_builder.add_input(input)
    }

    /// Adds a transparent P2PKH coin to be spent in this transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_transparent_p2pkh_input(
        &mut self,
        pubkey: secp256k1::PublicKey,
        utxo: transparent::bundle::OutPoint,
        coin: TxOut,
    ) -> Result<(), transparent::builder::Error> {
        self.transparent_builder.add_p2pkh_input(pubkey, utxo, coin)
    }

    /// Adds a transparent P2SH coin to be spent in this transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_transparent_p2sh_input(
        &mut self,
        redeem_script: script::FromChain,
        utxo: transparent::bundle::OutPoint,
        coin: TxOut,
    ) -> Result<(), transparent::builder::Error> {
        self.transparent_builder
            .add_p2sh_input(redeem_script, utxo, coin)
    }

    /// Adds a transparent address to send funds to.
    pub fn add_transparent_output(
        &mut self,
        to: &TransparentAddress,
        value: Zatoshis,
    ) -> Result<(), transparent::builder::Error> {
        self.transparent_builder.add_output(to, value)
    }

    /// Adds a transparent "null data" (OP_RETURN) output with the given data payload.
    pub fn add_transparent_null_data_output<FE>(&mut self, data: &[u8]) -> Result<(), Error<FE>> {
        self.transparent_builder
            .add_null_data_output(data)
            .map_err(Error::TransparentBuild)
    }

    /// Returns the sum of the transparent, Sapling, Orchard, Ironwood, and any
    /// experimental ZIP 233 value balances.
    fn value_balance(&self) -> Result<ZatBalance, BalanceError> {
        let value_balances = [
            self.transparent_builder.value_balance()?,
            self.sapling_builder
                .as_ref()
                .map_or_else(ZatBalance::zero, |builder| {
                    builder.value_balance::<ZatBalance>()
                }),
            self.orchard_builder.as_ref().map_or_else(
                || Ok(ZatBalance::zero()),
                |builder| {
                    builder
                        .value_balance::<ZatBalance>()
                        .map_err(|_| BalanceError::Overflow)
                },
            )?,
            self.ironwood_builder.as_ref().map_or_else(
                || Ok(ZatBalance::zero()),
                |builder| {
                    builder
                        .value_balance::<ZatBalance>()
                        .map_err(|_| BalanceError::Overflow)
                },
            )?,
            #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
            -ZatBalance::from(self.zip233_amount),
        ];

        value_balances
            .into_iter()
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)
    }

    /// Reports the calculated fee given the specified fee rule.
    ///
    /// This fee is a function of the spends and outputs that have been added to the builder,
    /// pursuant to the specified [`FeeRule`].
    pub fn get_fee<FR: FeeRule>(&self, fee_rule: &FR) -> Result<Zatoshis, FeeError<FR::Error>> {
        #[cfg(feature = "transparent-inputs")]
        let transparent_inputs = self.transparent_builder.inputs();

        #[cfg(not(feature = "transparent-inputs"))]
        let transparent_inputs: &[Infallible] = &[];

        let sapling_spends = self
            .sapling_builder
            .as_ref()
            .map_or(0, |builder| builder.inputs().len());

        let ironwood_actions = self
            .ironwood_builder
            .as_ref()
            .map_or(Ok(0), |builder| {
                orchard_action_count(
                    builder,
                    self.build_config.is_coinbase(),
                    orchard::bundle::BundleVersion::ironwood_v3(),
                )
            })
            .map_err(FeeError::Bundle)?;

        fee_rule
            .fee_required(
                &self.params,
                self.target_height,
                transparent_inputs.iter().map(|i| i.serialized_size()),
                self.transparent_builder
                    .outputs()
                    .iter()
                    .map(|i| i.serialized_size()),
                sapling_spends,
                self.sapling_builder
                    .as_ref()
                    .zip(self.build_config.sapling_builder_config())
                    .map_or(Ok(0), |(builder, (bundle_type, _))| {
                        bundle_type
                            .num_outputs(sapling_spends, builder.outputs().len())
                            .map_err(FeeError::Bundle)
                    })?,
                self.orchard_builder
                    .as_ref()
                    .map_or(Ok(0), |builder| {
                        orchard_action_count(
                            builder,
                            self.build_config.is_coinbase(),
                            self.orchard_bundle_version
                                .expect("orchard builder present implies bundle version"),
                        )
                    })
                    .map_err(FeeError::Bundle)?,
                ironwood_actions,
            )
            .map_err(FeeError::FeeRule)
    }

    #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
    /// Sets the experimental ZIP 233 amount. No implemented transaction format supports
    /// a nonzero amount; transaction construction rejects it.
    pub fn set_zip233_amount(&mut self, zip233_amount: Zatoshis) {
        self.zip233_amount = zip233_amount;
    }
}

impl<P: consensus::Parameters, U: sapling::builder::ProverProgress> Builder<P, U> {
    /// Builds a transaction from the configured spends and outputs.
    ///
    /// Upon success, returns a [`BuildResult`] containing:
    ///
    /// - the [final transaction],
    /// - the [Sapling metadata], and
    /// - the [Orchard metadata]
    ///
    /// generated during the build process.
    ///
    /// Returns [`Error::ShieldedLimitExceeded`] if NU7 is active at the target height and the
    /// transaction would exceed a [ZIP 218] limit on the shielded components of a block.
    ///
    /// [Sapling metadata]: ::sapling::builder::SaplingMetadata
    /// [Orchard metadata]: ::orchard::builder::BundleMetadata
    /// [final transaction]: Transaction
    /// [ZIP 218]: https://zips.z.cash/zip-0218
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "circuits")]
    pub fn build<R: Rng + CryptoRng, SP: SpendProver, OP: OutputProver, FR: FeeRule>(
        self,
        transparent_signing_set: &TransparentSigningSet,
        sapling_extsks: &[sapling::zip32::ExtendedSpendingKey],
        orchard_saks: &[orchard::keys::SpendAuthorizingKey],
        rng: R,
        spend_prover: &SP,
        output_prover: &OP,
        fee_rule: &FR,
    ) -> Result<BuildResult, Error<FR::Error>> {
        match &self.build_config {
            BuildConfig::Coinbase { miner_data } => {
                let target_height = self.target_height;
                let miner_data = miner_data.clone();

                self.build_internal::<Coinbase, _, _, _, _>(
                    |b| {
                        b.build_coinbase(target_height, miner_data)
                            .map(Some)
                            .map_err(Error::Coinbase)
                    },
                    |b, _, _| Ok(b.clone().map_authorization(transparent::builder::Coinbase)),
                    &[],
                    &[],
                    rng,
                    spend_prover,
                    output_prover,
                    None,
                )
            }
            BuildConfig::Standard { .. } => {
                let fee = self.get_fee(fee_rule).map_err(Error::Fee)?;

                self.build_internal::<Unauthorized, _, _, _, _>(
                    |b| Ok(b.build()),
                    |b, unauthed_tx, txid_parts| {
                        authorize_transparent(b, unauthed_tx, txid_parts, transparent_signing_set)
                    },
                    sapling_extsks,
                    orchard_saks,
                    rng,
                    spend_prover,
                    output_prover,
                    Some(fee),
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "circuits")]
    fn build_internal<A, R, SP, OP, FE>(
        self,
        build_transparent: impl FnOnce(
            TransparentBuilder,
        ) -> Result<
            Option<transparent::bundle::Bundle<A::TransparentAuth>>,
            Error<FE>,
        >,
        authorize_transparent: impl FnOnce(
            &transparent::bundle::Bundle<A::TransparentAuth>,
            &TransactionData<A>,
            &TxDigests<blake2b_simd::Hash>,
        ) -> Result<
            transparent::bundle::Bundle<transparent::bundle::Authorized>,
            transparent::builder::Error,
        >,
        sapling_extsks: &[sapling::zip32::ExtendedSpendingKey],
        orchard_saks: &[orchard::keys::SpendAuthorizingKey],
        mut rng: R,
        spend_prover: &SP,
        output_prover: &OP,
        fee: Option<Zatoshis>,
    ) -> Result<BuildResult, Error<FE>>
    where
        A: Authorization<
                SaplingAuth = sapling::builder::InProgress<
                    sapling::builder::Proven,
                    sapling::builder::Unsigned,
                >,
                OrchardAuth = orchard::builder::InProgress<
                    orchard::builder::Unproven,
                    orchard::builder::Unauthorized,
                >,
            >,
        A::TransparentAuth: transparent::sighash::TransparentAuthorizingContext,
        R: Rng + CryptoRng,
        SP: SpendProver,
        OP: OutputProver,
    {
        self.check_version_compatibility::<FE>(self.tx_version)?;
        self.check_coinbase_expiry_height::<FE>()?;
        check_shielded_limits::<_, FE>(&self.params, self.target_height, || {
            self.shielded_action_counts()
        })?;

        //
        // Consistency checks
        //

        assert_eq!(self.build_config.is_coinbase(), fee.is_none());
        if let Some(fee) = fee {
            // After fees are accounted for, the value balance of the transaction must be zero.
            let balance_after_fees =
                (self.value_balance()? - fee).ok_or(BalanceError::Underflow)?;

            match balance_after_fees.cmp(&ZatBalance::zero()) {
                Ordering::Less => {
                    return Err(Error::InsufficientFunds(-balance_after_fees));
                }
                Ordering::Greater => {
                    return Err(Error::ChangeRequired(balance_after_fees));
                }
                Ordering::Equal => (),
            };
        }

        let transparent_bundle = build_transparent(self.transparent_builder)?;

        let (sapling_bundle, sapling_meta) = match self
            .sapling_builder
            .and_then(|builder| {
                builder
                    .build::<SP, OP, _, _>(sapling_extsks, &mut rng)
                    .map_err(Error::SaplingBuild)
                    .transpose()
                    .map(|res| {
                        res.map(|(bundle, sapling_meta)| {
                            // We need to create proofs before signatures, because we still support
                            // creating V4 transactions, which commit to the Sapling proofs in the
                            // transaction digest.
                            (
                                bundle.create_proofs(
                                    spend_prover,
                                    output_prover,
                                    &mut rng,
                                    self._progress_notifier,
                                ),
                                sapling_meta,
                            )
                        })
                    })
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, SaplingMetadata::empty()),
        };

        let (orchard_bundle, orchard_meta) = match self
            .orchard_builder
            .and_then(|builder| {
                builder
                    .build(&mut rng)
                    .map_err(Error::OrchardBuild)
                    .transpose()
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, orchard::builder::BundleMetadata::empty()),
        };

        let (ironwood_bundle, ironwood_meta) = match self
            .ironwood_builder
            .and_then(|builder| {
                builder
                    .build(&mut rng)
                    .map_err(Error::IronwoodBuild)
                    .transpose()
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, orchard::builder::BundleMetadata::empty()),
        };

        let unauthed_tx: TransactionData<A> = TransactionData {
            version: self.tx_version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: 0,
            expiry_height: self.expiry_height,
            #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
            zip233_amount: self.zip233_amount,
            transparent_bundle,
            // We don't support constructing Sprout bundles.
            //
            // # Consensus
            //
            // > A coinbase transaction MUST NOT have any JoinSplit descriptions.
            //
            // > A coinbase transaction MUST NOT have any Spend descriptions.
            //
            // <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
        };

        //
        // Signatures -- everything but the signatures must already have been added.
        //
        let txid_parts = unauthed_tx.digest(TxIdDigester);

        let transparent_bundle = unauthed_tx
            .transparent_bundle
            .as_ref()
            .map(|b| authorize_transparent(b, &unauthed_tx, &txid_parts))
            .transpose()
            .map_err(Error::TransparentBuild)?;

        // the commitment being signed is shared across all Sapling inputs; once
        // V4 transactions are deprecated this should just be the txid, but
        // for now we need to continue to compute it here.
        let shielded_sig_commitment =
            signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

        let sapling_asks = sapling_extsks
            .iter()
            .map(|extsk| extsk.expsk().ask().clone())
            .collect::<Vec<_>>();
        let sapling_bundle = unauthed_tx
            .sapling_bundle
            .map(|b| b.apply_signatures(&mut rng, *shielded_sig_commitment.as_ref(), &sapling_asks))
            .transpose()
            .map_err(Error::SaplingBuild)?;

        // The Orchard and Ironwood circuit version is fixed by the transaction's
        // consensus branch (both pools share the post-NU6.3 circuit), so derive it
        // once from the branch rather than from a bundle. Only obtain the key when
        // an Orchard or Ironwood bundle is actually present.
        let orchard_circuit_version = {
            let build_proving_key =
                unauthed_tx.orchard_bundle.is_some() || unauthed_tx.ironwood_bundle.is_some();
            build_proving_key.then(|| {
                bundle_version_for_branch(
                    unauthed_tx.consensus_branch_id,
                    orchard::ValuePool::Orchard,
                )
                .expect("an Orchard or Ironwood bundle implies an NU5+ consensus branch")
                .circuit_version()
            })
        };

        // Reuse a process-wide cached proving key rather than reconstructing it on
        // every `build` call. See `cached_orchard_proving_key`.
        #[cfg(feature = "std")]
        let orchard_proving_key: Option<&orchard::circuit::ProvingKey> =
            orchard_circuit_version.map(cached_orchard_proving_key);
        // Without `std` there is no thread-safe cache; build the key once for this
        // transaction. (Proving requires `std` in practice, so this path does not
        // run when actually creating proofs.)
        #[cfg(not(feature = "std"))]
        let orchard_proving_key_storage =
            orchard_circuit_version.map(orchard::circuit::ProvingKey::build);
        #[cfg(not(feature = "std"))]
        let orchard_proving_key: Option<&orchard::circuit::ProvingKey> =
            orchard_proving_key_storage.as_ref();

        let orchard_bundle = unauthed_tx
            .orchard_bundle
            .map(|b| {
                b.create_proof(
                    orchard_proving_key
                        .expect("proving key is built when an Orchard bundle is present"),
                    &mut rng,
                )
                .and_then(|b| {
                    b.apply_signatures(&mut rng, *shielded_sig_commitment.as_ref(), orchard_saks)
                })
            })
            .transpose()
            .map_err(Error::OrchardBuild)?;

        let ironwood_bundle = unauthed_tx
            .ironwood_bundle
            .map(|b| {
                b.create_proof(
                    orchard_proving_key
                        .expect("proving key is built when an Ironwood bundle is present"),
                    &mut rng,
                )
                .and_then(|b| {
                    // Ironwood actions use the Orchard bundle type and the same
                    // Orchard spend authority. The `IronwoodNu6_3Onward` pool
                    // restrictions select the Ironwood circuit and flag rules;
                    // `apply_signatures` only signs actions whose `ak` matches
                    // a supplied spend authorizing key.
                    b.apply_signatures(&mut rng, *shielded_sig_commitment.as_ref(), orchard_saks)
                })
            })
            .transpose()
            .map_err(Error::IronwoodBuild)?;

        let authorized_tx = TransactionData {
            version: unauthed_tx.version,
            consensus_branch_id: unauthed_tx.consensus_branch_id,
            lock_time: unauthed_tx.lock_time,
            expiry_height: unauthed_tx.expiry_height,
            #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
            zip233_amount: unauthed_tx.zip233_amount,
            transparent_bundle,
            sprout_bundle: unauthed_tx.sprout_bundle,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
        };

        // The unwrap() here is safe because the txid hashing
        // of freeze() should be infalliable.
        Ok(BuildResult {
            transaction: authorized_tx.freeze().unwrap(),
            sapling_meta,
            orchard_meta,
            ironwood_meta,
        })
    }
}

impl<P: consensus::Parameters, U> Builder<P, U> {
    /// Builds a PCZT from the configured spends and outputs.
    ///
    /// Upon success, returns a struct containing the PCZT components, and the
    /// [`SaplingMetadata`] and [`orchard::builder::BundleMetadata`] generated during the
    /// build process.
    ///
    /// Experimental ZIP 233 builds reject nonzero ZIP 233 amounts because PCZT cannot
    /// preserve them through extraction.
    ///
    /// Returns [`Error::ShieldedLimitExceeded`] if NU7 is active at the target height and the
    /// PCZT would exceed a [ZIP 218] limit on the shielded components of a block.
    ///
    /// [ZIP 218]: https://zips.z.cash/zip-0218
    pub fn build_for_pczt<R: Rng + CryptoRng, FR: FeeRule>(
        self,
        mut rng: R,
        fee_rule: &FR,
    ) -> Result<PcztResult<P>, Error<FR::Error>> {
        #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
        if self.zip233_amount != Zatoshis::ZERO {
            return Err(Error::Zip233UnsupportedByPczt);
        }
        let fee = self.get_fee(fee_rule).map_err(Error::Fee)?;
        self.check_version_compatibility::<FR::Error>(self.tx_version)?;
        self.check_coinbase_expiry_height::<FR::Error>()?;
        check_shielded_limits::<_, FR::Error>(&self.params, self.target_height, || {
            self.shielded_action_counts()
        })?;

        //
        // Consistency checks
        //

        // After fees are accounted for, the value balance of the transaction must be zero.
        let balance_after_fees = (self.value_balance()? - fee).ok_or(BalanceError::Underflow)?;

        match balance_after_fees.cmp(&ZatBalance::zero()) {
            Ordering::Less => {
                return Err(Error::InsufficientFunds(-balance_after_fees));
            }
            Ordering::Greater => {
                return Err(Error::ChangeRequired(balance_after_fees));
            }
            Ordering::Equal => (),
        };

        let transparent_bundle = self.transparent_builder.build_for_pczt();

        let (sapling_bundle, sapling_meta) = match self
            .sapling_builder
            .map(|builder| {
                builder
                    .build_for_pczt(&mut rng)
                    .map_err(Error::SaplingBuild)
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, SaplingMetadata::empty()),
        };

        let (orchard_bundle, orchard_meta) = match self
            .orchard_builder
            .map(|builder| {
                builder
                    .build_for_pczt(&mut rng)
                    .map_err(Error::OrchardBuild)
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, orchard::builder::BundleMetadata::empty()),
        };

        let (ironwood_bundle, ironwood_meta) = if self.tx_version.has_ironwood() {
            match self
                .ironwood_builder
                .map(|builder| {
                    builder
                        .build_for_pczt(&mut rng)
                        .map_err(Error::IronwoodBuild)
                })
                .transpose()?
            {
                Some((bundle, meta)) => (Some(bundle), meta),
                None => (None, orchard::builder::BundleMetadata::empty()),
            }
        } else {
            (None, orchard::builder::BundleMetadata::empty())
        };

        Ok(PcztResult {
            pczt_parts: PcztParts {
                params: self.params,
                version: self.tx_version,
                consensus_branch_id: self.consensus_branch_id,
                lock_time: 0,
                expiry_height: self.expiry_height,
                transparent: transparent_bundle,
                sapling: sapling_bundle,
                orchard: orchard_bundle,
                ironwood: ironwood_bundle,
            },
            sapling_meta,
            orchard_meta,
            ironwood_meta,
        })
    }
}

/// Returns a process-wide cached Orchard proving key for the given circuit version.
///
/// Building an Orchard proving key is expensive, and the transaction builder would
/// otherwise reconstruct it on every call to [`Builder::build`]. Callers that build
/// many transactions in a process therefore share a single key per circuit version.
///
/// The cache is keyed by [`orchard::circuit::OrchardCircuitVersion`] because the
/// verifying (and hence proving) keys differ between circuit versions; mixing them
/// would produce proofs against the wrong key.
///
/// This is only available when the `std` feature is enabled, as it relies on
/// [`std::sync::OnceLock`] for thread-safe lazy initialization. Proving requires
/// `std` in practice, so this covers the paths that actually create proofs.
#[cfg(all(feature = "circuits", feature = "std"))]
use {
    orchard::circuit::{OrchardCircuitVersion, ProvingKey},
    std::sync::OnceLock,
};

#[cfg(all(feature = "circuits", feature = "std"))]
pub fn cached_orchard_proving_key(
    circuit_version: orchard::circuit::OrchardCircuitVersion,
) -> &'static orchard::circuit::ProvingKey {
    static INSECURE_PRE_NU6_2: OnceLock<ProvingKey> = OnceLock::new();
    static FIXED_POST_NU6_2: OnceLock<ProvingKey> = OnceLock::new();
    static POST_NU6_3: OnceLock<ProvingKey> = OnceLock::new();

    let cell = match circuit_version {
        OrchardCircuitVersion::InsecurePreNu6_2 => &INSECURE_PRE_NU6_2,
        OrchardCircuitVersion::FixedPostNu6_2 => &FIXED_POST_NU6_2,
        OrchardCircuitVersion::PostNu6_3 => &POST_NU6_3,
    };
    cell.get_or_init(|| ProvingKey::build(circuit_version))
}

#[cfg(feature = "circuits")]
fn authorize_transparent(
    b: &transparent::bundle::Bundle<transparent::builder::Unauthorized>,
    unauthed_tx: &TransactionData<Unauthorized>,
    txid_parts: &TxDigests<blake2b_simd::Hash>,
    transparent_signing_set: &TransparentSigningSet,
) -> Result<transparent::bundle::Bundle<transparent::bundle::Authorized>, transparent::builder::Error>
{
    b.clone().apply_signatures(
        |input| {
            *signature_hash(unauthed_tx, &SignableInput::Transparent(input), txid_parts).as_ref()
        },
        transparent_signing_set,
    )
}

#[cfg(all(any(test, feature = "test-dependencies"), feature = "circuits"))]
mod testing {
    use core::convert::Infallible;

    use rand_core::{Rng, TryCryptoRng, TryRng};

    use ::sapling::prover::mock::{MockOutputProver, MockSpendProver};
    use ::transparent::builder::TransparentSigningSet;
    use zcash_protocol::consensus;

    use super::{BuildResult, Builder, Error};
    use crate::transaction::fees::zip317;

    impl<P: consensus::Parameters, U: sapling::builder::ProverProgress> Builder<P, U> {
        /// Build the transaction using mocked randomness and proving capabilities.
        /// DO NOT USE EXCEPT FOR UNIT TESTING.
        pub fn mock_build<R: Rng>(
            self,
            transparent_signing_set: &TransparentSigningSet,
            sapling_extsks: &[sapling::zip32::ExtendedSpendingKey],
            orchard_saks: &[orchard::keys::SpendAuthorizingKey],
            rng: R,
        ) -> Result<BuildResult, Error<zip317::FeeError>> {
            struct FakeCryptoRng<R: Rng>(R);
            impl<R: Rng> TryRng for FakeCryptoRng<R> {
                type Error = Infallible;

                fn try_next_u32(&mut self) -> Result<u32, Infallible> {
                    Ok(self.0.next_u32())
                }

                fn try_next_u64(&mut self) -> Result<u64, Infallible> {
                    Ok(self.0.next_u64())
                }

                fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
                    self.0.fill_bytes(dest);
                    Ok(())
                }
            }
            impl<R: Rng> TryCryptoRng for FakeCryptoRng<R> {}

            self.build(
                transparent_signing_set,
                sapling_extsks,
                orchard_saks,
                FakeCryptoRng(rng),
                &MockSpendProver,
                &MockOutputProver,
                #[allow(deprecated)]
                &zip317::FeeRule::standard(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "circuits", feature = "std"))]
    use {super::cached_orchard_proving_key, core::ptr, orchard::circuit::OrchardCircuitVersion};

    #[cfg(feature = "circuits")]
    use {
        super::{Builder, DeferredPcztBuilder, Error, PcztParts},
        crate::transaction::{
            builder::{BuildConfig, BundlePadding},
            fees::zip317::{self, MINIMUM_FEE},
        },
        ::sapling::{Node, Rseed, zip32::ExtendedSpendingKey},
        ::transparent::{address::TransparentAddress, builder::TransparentSigningSet},
        assert_matches::assert_matches,
        core::{convert::Infallible, fmt::Debug},
        ff::Field,
        incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness},
        rand::rngs::SysRng,
        rand_core::UnwrapErr,
        zcash_protocol::{
            consensus::{BlockHeight, NetworkUpgrade, Parameters, TEST_NETWORK},
            memo::MemoBytes,
            value::{BalanceError, ZatBalance, Zatoshis},
            zip218::{
                GLOBAL_SHIELDED_BUDGET, ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT,
                SAPLING_BLOCK_IO_LIMIT, ShieldedActionCounts, ShieldedBlockLimit,
            },
        },
    };

    #[cfg(all(feature = "transparent-inputs", feature = "circuits"))]
    use {
        crate::transaction::{
            OutPoint, TxOut, TxVersion,
            builder::{self, DEFAULT_TX_EXPIRY_DELTA, TransparentBuilder},
        },
        ::transparent::keys::{AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex},
        zcash_protocol::consensus::BranchId,
        zip32::AccountId,
    };

    // The Ironwood tests below reference `TxVersion`/`BranchId` directly; without the
    // `transparent-inputs` feature these are not otherwise in scope.
    #[cfg(all(feature = "circuits", not(feature = "transparent-inputs")))]
    use {crate::transaction::TxVersion, zcash_protocol::consensus::BranchId};

    #[cfg(feature = "circuits")]
    fn nu6_3_test_network() -> zcash_protocol::local_consensus::LocalNetwork {
        zcash_protocol::local_consensus::LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(2)),
            blossom: Some(BlockHeight::from_u32(3)),
            heartwood: Some(BlockHeight::from_u32(4)),
            canopy: Some(BlockHeight::from_u32(5)),
            nu5: Some(BlockHeight::from_u32(6)),
            nu6: Some(BlockHeight::from_u32(7)),
            nu6_1: Some(BlockHeight::from_u32(8)),
            nu6_2: Some(BlockHeight::from_u32(9)),
            nu6_3: Some(BlockHeight::from_u32(10)),
            nu7: None,
            #[cfg(zcash_unstable = "nutachyon")]
            nu_tachyon: None,
        }
    }

    #[cfg(feature = "circuits")]
    fn nu7_test_network() -> zcash_protocol::local_consensus::LocalNetwork {
        zcash_protocol::local_consensus::LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(2)),
            blossom: Some(BlockHeight::from_u32(3)),
            heartwood: Some(BlockHeight::from_u32(4)),
            canopy: Some(BlockHeight::from_u32(5)),
            nu5: Some(BlockHeight::from_u32(6)),
            nu6: Some(BlockHeight::from_u32(7)),
            nu6_1: Some(BlockHeight::from_u32(8)),
            nu6_2: Some(BlockHeight::from_u32(9)),
            nu6_3: Some(BlockHeight::from_u32(10)),
            nu7: Some(BlockHeight::from_u32(11)),
            #[cfg(zcash_unstable = "nutachyon")]
            nu_tachyon: None,
        }
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu6_3_standard_builder_uses_v6_orchard_protocol() {
        let builder = Builder::new(
            nu6_3_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(10),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );

        assert_eq!(builder.tx_version, crate::transaction::TxVersion::V6);
        assert_eq!(
            builder.orchard_bundle_version,
            Some(orchard::bundle::BundleVersion::orchard_v3())
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu6_3_standard_builder_preserves_branch_orchard_protocol_for_explicit_v5() {
        let mut builder = Builder::new(
            nu6_3_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(10),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );

        builder
            .propose_version::<Infallible>(crate::transaction::TxVersion::V5)
            .unwrap();

        assert_eq!(
            builder.orchard_bundle_version,
            Some(orchard::bundle::BundleVersion::orchard_v3())
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu6_3_coinbase_builder_does_not_expose_orchard() {
        let builder = Builder::new(
            nu6_3_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(10),
            BuildConfig::Coinbase { miner_data: None },
        );

        assert!(builder.orchard_builder.is_none());
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu7_coinbase_builder_does_not_expose_orchard() {
        let builder = Builder::new(
            nu7_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(11),
            BuildConfig::Coinbase { miner_data: None },
        );

        assert!(builder.orchard_builder.is_none());
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu6_3_coinbase_builder_uses_ironwood_not_orchard() {
        let builder = Builder::new(
            nu6_3_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(10),
            BuildConfig::Coinbase { miner_data: None },
        );

        assert!(builder.orchard_builder.is_none());
        assert_eq!(
            builder
                .ironwood_builder
                .as_ref()
                .map(|_| orchard::bundle::BundleVersion::ironwood_v3()),
            Some(orchard::bundle::BundleVersion::ironwood_v3())
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn nu6_3_coinbase_builder_has_ironwood_output_option() {
        let recipient = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap(),
        )
        .address_at(0u32, orchard::keys::Scope::External);
        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Coinbase { miner_data: None },
        );

        assert_matches!(
            builder.add_orchard_output::<Infallible>(
                None,
                recipient,
                Zatoshis::const_from_u64(10_000),
                MemoBytes::empty(),
            ),
            Err(Error::OrchardBuilderNotAvailable)
        );

        builder
            .add_ironwood_output::<Infallible>(
                None,
                recipient,
                Zatoshis::const_from_u64(10_000),
                MemoBytes::empty(),
            )
            .unwrap();
        assert_eq!(
            builder.ironwood_builder.as_ref().map(|b| b.outputs().len()),
            Some(1)
        );
        assert_eq!(
            super::orchard_action_count(
                builder.ironwood_builder.as_ref().unwrap(),
                true,
                orchard::bundle::BundleVersion::ironwood_v3()
            )
            .unwrap(),
            1
        );
    }

    #[test]
    #[cfg(all(feature = "circuits", feature = "zip-233", zcash_unstable = "zip233"))]
    fn build_for_pczt_rejects_nonzero_zip233_amount() {
        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder.set_zip233_amount(Zatoshis::const_from_u64(1));
        assert!(matches!(
            builder.check_version_compatibility::<Infallible>(TxVersion::V6),
            Err(Error::TargetIncompatible(
                BranchId::Nu6_3,
                TxVersion::V6,
                None
            ))
        ));
        builder.consensus_branch_id = BranchId::Nu7;
        for version in [TxVersion::V5, TxVersion::V6] {
            assert!(matches!(
                builder.check_version_compatibility::<Infallible>(version),
                Err(Error::TargetIncompatible(BranchId::Nu7, _, None))
            ));
        }
        assert!(matches!(
            builder.build_for_pczt(
                UnwrapErr(SysRng),
                &crate::transaction::fees::zip317::FeeRule::standard()
            ),
            Err(Error::Zip233UnsupportedByPczt)
        ));
    }

    #[test]
    #[cfg(all(feature = "circuits", feature = "transparent-inputs"))]
    fn build_for_pczt_preserves_explicit_v6_without_ironwood() {
        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .propose_version::<Infallible>(TxVersion::V6)
            .unwrap();

        let mut transparent_signing_set = TransparentSigningSet::new();
        let tsk = AccountPrivKey::from_seed(&TEST_NETWORK, &[0u8; 32], AccountId::ZERO).unwrap();
        let sk = tsk
            .derive_external_secret_key(NonHardenedChildIndex::ZERO)
            .unwrap();
        let pubkey = transparent_signing_set.add_key(sk);
        let prev_coin = TxOut::new(
            Zatoshis::const_from_u64(50000),
            tsk.to_account_pubkey()
                .derive_external_ivk()
                .unwrap()
                .derive_address(NonHardenedChildIndex::ZERO)
                .unwrap()
                .script()
                .into(),
        );

        builder
            .add_transparent_p2pkh_input(pubkey, OutPoint::fake(), prev_coin)
            .unwrap();
        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                Zatoshis::const_from_u64(40000),
            )
            .unwrap();

        let res = builder
            .build_for_pczt(
                UnwrapErr(SysRng),
                &crate::transaction::fees::zip317::FeeRule::standard(),
            )
            .unwrap();
        assert_eq!(res.pczt_parts.version, TxVersion::V6);
        assert_eq!(
            res.pczt_parts.consensus_branch_id,
            zcash_protocol::consensus::BranchId::Nu6_3
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn build_for_pczt_accepts_v6_when_ironwood_is_used() {
        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        let recipient = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap(),
        )
        .address_at(0u32, orchard::keys::Scope::External);
        builder
            .add_ironwood_output::<crate::transaction::fees::zip317::FeeRule>(
                None,
                recipient,
                Zatoshis::const_from_u64(10_000),
                MemoBytes::empty(),
            )
            .unwrap();

        assert_matches!(
            builder.build_for_pczt(
                UnwrapErr(SysRng),
                &crate::transaction::fees::zip317::FeeRule::standard(),
            ),
            Err(Error::InsufficientFunds(_))
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn build_for_pczt_rejects_explicit_v5_when_ironwood_is_used() {
        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .propose_version::<Infallible>(TxVersion::V5)
            .unwrap();

        let recipient = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap(),
        )
        .address_at(0u32, orchard::keys::Scope::External);
        builder
            .add_ironwood_output::<crate::transaction::fees::zip317::FeeRule>(
                None,
                recipient,
                Zatoshis::const_from_u64(10_000),
                MemoBytes::empty(),
            )
            .unwrap();

        assert_matches!(
            builder.build_for_pczt(
                UnwrapErr(SysRng),
                &crate::transaction::fees::zip317::FeeRule::standard(),
            ),
            Err(Error::TargetIncompatible(
                BranchId::Nu6_3,
                TxVersion::V5,
                None
            ))
        );
    }

    /// Test helper: returns a full viewing key, an Orchard note carrying the given
    /// note plaintext `version`, and a dummy Merkle path, for exercising the
    /// Ironwood builder's note-version handling.
    #[cfg(feature = "circuits")]
    fn ironwood_note_with_version(
        version: orchard::note::NoteVersion,
    ) -> (
        orchard::keys::FullViewingKey,
        orchard::Note,
        orchard::tree::MerklePath,
    ) {
        let sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
        let value = orchard::value::NoteValue::from_raw(99);
        let rho = orchard::note::Rho::from_bytes(&[1; 32]).unwrap();
        let rseed = (0u8..=255)
            .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
            .expect("at least one test rseed is valid");
        let note = orchard::Note::from_parts(recipient, value, rho, rseed, version).unwrap();
        let zero = orchard::tree::MerkleHashOrchard::from_bytes(&[0; 32]).unwrap();
        let merkle_path = orchard::tree::MerklePath::from_parts(0, [zero; 32]);

        (fvk, note, merkle_path)
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn note_commitment_and_nullifier_depend_on_note_version() {
        let (fvk, v2_note, _) = ironwood_note_with_version(orchard::note::NoteVersion::V2);
        let (_, v3_note, _) = ironwood_note_with_version(orchard::note::NoteVersion::V3);

        // The notes share every field except the note plaintext version (lead byte
        // 0x02 vs 0x03), which must domain-separate both the commitment and the
        // nullifier.
        assert_ne!(
            orchard::note::ExtractedNoteCommitment::from(v2_note.commitment()).to_bytes(),
            orchard::note::ExtractedNoteCommitment::from(v3_note.commitment()).to_bytes(),
        );
        assert_ne!(
            v2_note.nullifier(&fvk).to_bytes(),
            v3_note.nullifier(&fvk).to_bytes(),
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn add_ironwood_spend_rejects_v2_note_version() {
        let mut builder = Builder::new(
            nu6_3_test_network(),
            10u32.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        let (fvk, note, merkle_path) = ironwood_note_with_version(orchard::note::NoteVersion::V2);

        assert_matches!(
            builder.add_ironwood_spend::<Infallible>(fvk, note, merkle_path),
            Err(Error::IronwoodSpendUnsupportedNoteVersion(
                orchard::note::NoteVersion::V2
            ))
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn orchard_action_count_uses_cross_address_disabled_count() {
        let spend_sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
        let spend_fvk = orchard::keys::FullViewingKey::from(&spend_sk);
        let spend_recipient = spend_fvk.address_at(0u32, orchard::keys::Scope::External);
        let rho = orchard::note::Rho::from_bytes(&[1; 32]).unwrap();
        let rseed = (0u8..=255)
            .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
            .expect("at least one test rseed is valid");
        let note = orchard::Note::from_parts(
            spend_recipient,
            orchard::value::NoteValue::from_raw(10_000),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        )
        .unwrap();
        let leaf = orchard::tree::MerkleHashOrchard::from_cmx(&note.commitment().into());
        let mut tree = CommitmentTree::<orchard::tree::MerkleHashOrchard, 32>::empty();
        tree.append(leaf).unwrap();
        let witness = IncrementalWitness::from_tree(tree).unwrap();
        let anchor = witness.root().into();
        let merkle_path = witness.path().unwrap().into();

        let mut builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            orchard::bundle::BundleVersion::orchard_v3(),
            orchard::bundle::BundleVersion::orchard_v3().default_flags(),
            anchor,
        )
        .unwrap();

        builder.add_spend(spend_fvk, note, merkle_path).unwrap();

        for seed in [[8u8; 32], [9u8; 32]] {
            let change_fvk = orchard::keys::FullViewingKey::from(
                &orchard::keys::SpendingKey::from_bytes(seed).unwrap(),
            );
            let recipient = change_fvk.address_at(0u32, orchard::keys::Scope::Internal);
            builder
                .add_change_output(
                    change_fvk,
                    None,
                    recipient,
                    orchard::value::NoteValue::from_raw(1_000),
                    [0u8; 512],
                )
                .unwrap();
        }

        assert_eq!(builder.spends().len(), 1);
        assert_eq!(builder.changes().len(), 2);
        assert_eq!(
            super::orchard_action_count(
                &builder,
                false,
                orchard::bundle::BundleVersion::orchard_v3(),
            )
            .unwrap(),
            3
        );
    }

    /// `BuildConfig::Standard`'s `orchard_padding` controls padding: the
    /// padded default counts a single-output bundle as 2 actions, while
    /// `UNPADDED` counts exactly the requested single action.
    #[test]
    #[cfg(feature = "circuits")]
    fn orchard_padding_controls_padding() {
        let recipient = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap(),
        )
        .address_at(0u32, orchard::keys::Scope::External);

        let config_with = |padding| BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_padding: padding,
            ironwood_padding: BundlePadding::DEFAULT,
        };

        // `orchard_v2` here: the NU6.3 `orchard_v3` version disables cross-address
        // transfers, so a bare output cannot be added.
        let count_for = |padding| {
            let config = config_with(padding);
            let mut builder = config
                .orchard_builder(orchard::bundle::BundleVersion::orchard_v2())
                .unwrap();
            builder
                .add_output(
                    None,
                    recipient,
                    orchard::value::NoteValue::from_raw(10_000),
                    [0u8; 512],
                )
                .unwrap();
            super::orchard_action_count(
                &builder,
                false,
                orchard::bundle::BundleVersion::orchard_v2(),
            )
            .unwrap()
        };

        assert_eq!(count_for(BundlePadding::DEFAULT), 2);
        assert_eq!(count_for(BundlePadding::UNPADDED), 1);
    }

    /// Each Orchard protocol value pool's builder takes its padding from its
    /// own `BuildConfig::Standard` field.
    #[test]
    #[cfg(feature = "circuits")]
    fn orchard_protocol_padding_is_per_pool() {
        let bundle_types = |orchard_padding, ironwood_padding| {
            let builder = Builder::new(
                nu6_3_test_network(),
                zcash_protocol::consensus::BlockHeight::from_u32(10),
                BuildConfig::Standard {
                    sapling_anchor: None,
                    orchard_anchor: Some(orchard::Anchor::empty_tree()),
                    ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                    orchard_padding,
                    ironwood_padding,
                },
            );

            (
                builder.orchard_builder.as_ref().unwrap().bundle_type(),
                builder.ironwood_builder.as_ref().unwrap().bundle_type(),
            )
        };

        for (orchard_padding, ironwood_padding) in [
            (BundlePadding::DEFAULT, BundlePadding::DEFAULT),
            (BundlePadding::UNPADDED, BundlePadding::DEFAULT),
            (BundlePadding::DEFAULT, BundlePadding::UNPADDED),
        ] {
            assert_eq!(
                bundle_types(orchard_padding, ironwood_padding),
                (
                    orchard_padding.bundle_type(),
                    ironwood_padding.bundle_type()
                ),
            );
        }
    }

    /// A padded Orchard bundle and an unpadded Ironwood bundle can be combined in
    /// one transaction: one real Orchard spend pads to 2 actions while the single
    /// Ironwood output stays at 1.
    #[test]
    #[cfg(feature = "circuits")]
    fn per_pool_bundle_types_build_two_plus_one_pczt() {
        let spend_fvk = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap(),
        );
        let recipient = spend_fvk.address_at(0u32, orchard::keys::Scope::External);
        let rho = orchard::note::Rho::from_bytes(&[1; 32]).unwrap();
        let rseed = (0u8..=255)
            .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
            .expect("at least one test rseed is valid");
        let note = orchard::Note::from_parts(
            recipient,
            orchard::value::NoteValue::from_raw(100_000),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        )
        .unwrap();
        let zero = orchard::tree::MerkleHashOrchard::from_bytes(&[0; 32]).unwrap();
        let merkle_path = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
        let orchard_anchor = merkle_path.root(note.commitment().into());

        let mut builder = Builder::new(
            nu6_3_test_network(),
            zcash_protocol::consensus::BlockHeight::from_u32(10),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard_anchor),
                ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::UNPADDED,
            },
        );
        builder
            .add_orchard_spend::<crate::transaction::fees::zip317::FeeRule>(
                spend_fvk,
                note,
                merkle_path,
            )
            .unwrap();
        builder
            .add_ironwood_output::<crate::transaction::fees::zip317::FeeRule>(
                None,
                recipient,
                Zatoshis::const_from_u64(85_000),
                MemoBytes::empty(),
            )
            .unwrap();

        let result = builder
            .build_for_pczt(
                UnwrapErr(SysRng),
                &crate::transaction::fees::zip317::FeeRule::standard(),
            )
            .unwrap();
        assert_eq!(
            result.pczt_parts.orchard.as_ref().unwrap().actions().len(),
            2
        );
        assert_eq!(
            result.pczt_parts.ironwood.as_ref().unwrap().actions().len(),
            1
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn add_orchard_change_output_records_change() {
        let target_height = TEST_NETWORK.activation_height(NetworkUpgrade::Nu5).unwrap();
        let mut builder = Builder::new(
            TEST_NETWORK,
            target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        let fvk = orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap(),
        );
        let recipient = fvk.address_at(0u32, orchard::keys::Scope::Internal);

        builder
            .add_orchard_change_output::<Infallible>(
                fvk,
                None,
                recipient,
                Zatoshis::const_from_u64(5_000),
                MemoBytes::empty(),
            )
            .unwrap();

        assert_eq!(
            builder.orchard_builder.as_ref().map(|b| b.changes().len()),
            Some(1)
        );
    }

    // This test only works with the transparent_inputs feature because we have to
    // be able to create a tx with a valid balance, without using Sapling inputs.
    #[test]
    #[cfg(all(feature = "transparent-inputs", feature = "circuits"))]
    fn binding_sig_absent_if_no_shielded_spend_or_output() {
        let sapling_activation_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        // Create a builder with 0 fee, so we can construct t outputs
        let consensus_branch_id = BranchId::for_height(&TEST_NETWORK, sapling_activation_height);
        let mut builder = builder::Builder {
            params: TEST_NETWORK,
            tx_version: TxVersion::suggested_for_branch(consensus_branch_id),
            consensus_branch_id,
            build_config: BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
            target_height: sapling_activation_height,
            expiry_height: sapling_activation_height + DEFAULT_TX_EXPIRY_DELTA,
            #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
            zip233_amount: Zatoshis::ZERO,
            transparent_builder: TransparentBuilder::empty(),
            sapling_builder: None,
            orchard_builder: None,
            orchard_bundle_version: None,
            ironwood_builder: None,
            _progress_notifier: (),
        };

        let mut transparent_signing_set = TransparentSigningSet::new();
        let tsk = AccountPrivKey::from_seed(&TEST_NETWORK, &[0u8; 32], AccountId::ZERO).unwrap();
        let sk = tsk
            .derive_external_secret_key(NonHardenedChildIndex::ZERO)
            .unwrap();
        let pubkey = transparent_signing_set.add_key(sk);
        let prev_coin = TxOut::new(
            Zatoshis::const_from_u64(50000),
            tsk.to_account_pubkey()
                .derive_external_ivk()
                .unwrap()
                .derive_address(NonHardenedChildIndex::ZERO)
                .unwrap()
                .script()
                .into(),
        );
        builder
            .add_transparent_p2pkh_input(pubkey, OutPoint::fake(), prev_coin)
            .unwrap();

        // Create a tx with only t output. No binding_sig should be present
        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                Zatoshis::const_from_u64(40000),
            )
            .unwrap();

        let res = builder
            .mock_build(&transparent_signing_set, &[], &[], UnwrapErr(SysRng))
            .unwrap();
        // No binding signature, because only t input and outputs
        assert!(res.transaction().sapling_bundle.is_none());
    }

    #[test]
    #[cfg(all(feature = "circuits", feature = "transparent-inputs"))]
    fn build_uses_overridden_expiry_height() {
        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();
        let build_config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        };
        let mut builder =
            Builder::new(TEST_NETWORK, tx_height, build_config).with_expiry_height(0u32.into());

        let mut transparent_signing_set = TransparentSigningSet::new();
        let tsk = AccountPrivKey::from_seed(&TEST_NETWORK, &[0u8; 32], AccountId::ZERO).unwrap();
        let sk = tsk
            .derive_external_secret_key(NonHardenedChildIndex::ZERO)
            .unwrap();
        let pubkey = transparent_signing_set.add_key(sk);
        let prev_coin = TxOut::new(
            Zatoshis::const_from_u64(50_000),
            tsk.to_account_pubkey()
                .derive_external_ivk()
                .unwrap()
                .derive_address(NonHardenedChildIndex::ZERO)
                .unwrap()
                .script()
                .into(),
        );
        builder
            .add_transparent_p2pkh_input(pubkey, OutPoint::fake(), prev_coin)
            .unwrap();
        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                Zatoshis::const_from_u64(40_000),
            )
            .unwrap();

        let res = builder
            .mock_build(&transparent_signing_set, &[], &[], UnwrapErr(SysRng))
            .unwrap();
        assert_eq!(res.transaction().expiry_height(), 0u32.into());
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn build_rejects_mismatched_coinbase_expiry_height() {
        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();
        let build_config = BuildConfig::Coinbase { miner_data: None };
        let mut builder =
            Builder::new(TEST_NETWORK, tx_height, build_config).with_expiry_height(0u32.into());

        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                Zatoshis::const_from_u64(50_000),
            )
            .unwrap();

        assert_matches!(
            builder.mock_build(&TransparentSigningSet::new(), &[], &[], UnwrapErr(SysRng)),
            Err(Error::CoinbaseExpiryHeightMismatch {
                target_height,
                expiry_height,
            }) if target_height == tx_height && expiry_height == 0u32.into()
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn binding_sig_present_if_shielded_spend() {
        let extsk =
            ExtendedSpendingKey::master(&[]).expect("the derivation path yields a valid key");
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1;

        let mut rng = UnwrapErr(SysRng);

        let note1 = to.create_note(
            sapling::value::NoteValue::from_raw(50000),
            Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
        );
        let cmu1 = Node::from_cmu(&note1.cmu());
        let mut tree = CommitmentTree::<Node, 32>::empty();
        tree.append(cmu1).unwrap();
        let witness1 = IncrementalWitness::from_tree(tree).unwrap();

        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        let build_config = BuildConfig::Standard {
            sapling_anchor: Some(witness1.root().into()),
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        };
        let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);

        // Create a tx with a sapling spend. binding_sig should be present
        builder
            .add_sapling_spend::<Infallible>(dfvk.fvk().clone(), note1, witness1.path().unwrap())
            .unwrap();

        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                Zatoshis::const_from_u64(35000),
            )
            .unwrap();

        // A binding signature (and bundle) is present because there is a Sapling spend.
        let res = builder
            .mock_build(
                &TransparentSigningSet::new(),
                &[extsk],
                &[],
                UnwrapErr(SysRng),
            )
            .unwrap();
        assert!(res.transaction().sapling_bundle().is_some());
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn fails_on_negative_change() {
        let mut rng = UnwrapErr(SysRng);

        // Just use the master key as the ExtendedSpendingKey for this test
        let extsk =
            ExtendedSpendingKey::master(&[]).expect("the derivation path yields a valid key");
        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        // Fails with no inputs or outputs
        // 0.0001 t-ZEC fee
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            };
            let builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            assert_matches!(
                builder.mock_build(&TransparentSigningSet::new(), &[], &[], UnwrapErr(SysRng)),
                Err(Error::InsufficientFunds(expected)) if expected == MINIMUM_FEE.into()
            );
        }

        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let ovk = Some(dfvk.fvk().ovk);
        let to = dfvk.default_address().1;

        let extsks = &[extsk];

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    Zatoshis::const_from_u64(50000),
                    MemoBytes::empty(),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(&TransparentSigningSet::new(), extsks, &[], UnwrapErr(SysRng)),
                Err(Error::InsufficientFunds(expected)) if
                    expected == (Zatoshis::const_from_u64(50000) + MINIMUM_FEE).unwrap().into()
            );
        }

        // Fail if there is only a transparent output
        // 0.0005 t-ZEC out, 0.0001 t-ZEC fee
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    Zatoshis::const_from_u64(50000),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(&TransparentSigningSet::new(), extsks, &[], UnwrapErr(SysRng)),
                Err(Error::InsufficientFunds(expected)) if expected ==
                    (Zatoshis::const_from_u64(50000) + MINIMUM_FEE).unwrap().into()
            );
        }

        // Fail if there is only a burn
        // 0.0005 burned, 0.0001 t-ZEC fee
        #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            };
            let mut builder =
                Builder::new(nu7_test_network(), BlockHeight::from_u32(11), build_config);
            builder.set_zip233_amount(Zatoshis::const_from_u64(50000));

            assert_matches!(
                builder.mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    UnwrapErr(SysRng)
                ),
                Err(Error::TargetIncompatible(BranchId::Nu7, _, None))
            );
        }

        let note1 = to.create_note(
            sapling::value::NoteValue::from_raw(59999),
            Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
        );
        let cmu1 = Node::from_cmu(&note1.cmu());
        let mut tree = CommitmentTree::<Node, 32>::empty();
        tree.append(cmu1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(tree.clone()).unwrap();

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.00015 t-ZEC out, 0.00015 t-ZEC fee, 0.00059999 z-ZEC in
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(witness1.root().into()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    Zatoshis::const_from_u64(30000),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    Zatoshis::const_from_u64(15000),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(&TransparentSigningSet::new(), extsks, &[], UnwrapErr(SysRng)),
                Err(Error::InsufficientFunds(expected)) if expected == ZatBalance::const_from_i64(1)
            );
        }

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.00005 t-ZEC out, 0.0001 burned, 0.00015 t-ZEC fee, 0.00059999 z-ZEC in
        #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(witness1.root().into()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            };
            let mut builder =
                Builder::new(nu7_test_network(), BlockHeight::from_u32(11), build_config);
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    Zatoshis::const_from_u64(30000),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    Zatoshis::const_from_u64(5000),
                )
                .unwrap();
            builder.set_zip233_amount(Zatoshis::const_from_u64(10000));
            assert_matches!(
                builder.mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    UnwrapErr(SysRng)
                ),
                Err(Error::TargetIncompatible(BranchId::Nu7, _, None))
            );
        }

        let note2 = to.create_note(
            sapling::value::NoteValue::from_raw(1),
            Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
        );
        let cmu2 = Node::from_cmu(&note2.cmu());
        tree.append(cmu2).unwrap();
        witness1.append(cmu2).unwrap();
        let witness2 = IncrementalWitness::from_tree(tree).unwrap();

        // Succeeds if there is sufficient input
        // 0.0003 z-ZEC out, 0.00015 t-ZEC out, 0.00015 t-ZEC fee, 0.0006 z-ZEC in
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(witness1.root().into()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note2.clone(),
                    witness2.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    Zatoshis::const_from_u64(30000),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    Zatoshis::const_from_u64(15000),
                )
                .unwrap();
            let res = builder
                .mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    UnwrapErr(SysRng),
                )
                .unwrap();
            assert_eq!(
                res.transaction()
                    .fee_paid(|_| Err(BalanceError::Overflow))
                    .unwrap(),
                Some(Zatoshis::const_from_u64(15_000))
            );
        }

        // NU7 rejects voluntary removal even when the inputs cover the requested amount.
        #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(witness1.root().into()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            };
            let mut builder =
                Builder::new(nu7_test_network(), BlockHeight::from_u32(11), build_config);
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note1,
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_spend::<Infallible>(
                    dfvk.fvk().clone(),
                    note2,
                    witness2.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    Zatoshis::const_from_u64(30000),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    Zatoshis::const_from_u64(5000),
                )
                .unwrap();
            builder.set_zip233_amount(Zatoshis::const_from_u64(10000));
            assert_matches!(
                builder.mock_build(
                    &TransparentSigningSet::new(),
                    extsks,
                    &[],
                    UnwrapErr(SysRng)
                ),
                Err(Error::TargetIncompatible(BranchId::Nu7, _, None))
            );
        }
    }

    /// The target height of the shielded-component tests' builds where NU7 is not active: on
    /// `nu6_3_test_network`, and on `nu7_test_network` the last height before NU7 activates.
    #[cfg(feature = "circuits")]
    const PRE_NU7_TARGET_HEIGHT: BlockHeight = BlockHeight::from_u32(10);

    /// The target height of the shielded-component tests' builds on `nu7_test_network`, where
    /// NU7 is active.
    #[cfg(feature = "circuits")]
    const NU7_TARGET_HEIGHT: BlockHeight = BlockHeight::from_u32(11);

    /// The value of each output that the shielded-component tests request.
    #[cfg(feature = "circuits")]
    const COUNTED_OUTPUT_VALUE: Zatoshis = Zatoshis::const_from_u64(100_000);

    /// The Ironwood outputs that the Ironwood counting test requests.
    #[cfg(feature = "circuits")]
    const COUNTED_IRONWOOD_OUTPUTS: usize = 3;

    /// The outputs per shielded pool that the coinbase counting test requests; a coinbase
    /// bundle is not padded, so it holds exactly this many.
    #[cfg(feature = "circuits")]
    const COUNTED_COINBASE_OUTPUTS: usize = 1;

    /// The dummy actions that the counting tests require a bundle of an otherwise unused pool to
    /// hold.
    #[cfg(feature = "circuits")]
    const COUNTED_DUMMY_ACTIONS: u8 = 3;

    /// The outputs of a Sapling bundle that has any component: a smaller request is padded
    /// with dummy outputs up to this many.
    #[cfg(feature = "circuits")]
    const SAPLING_PADDED_OUTPUTS: usize = 2;

    /// The Sapling spends that the Sapling spend counting test requests: the one note it spends.
    #[cfg(feature = "circuits")]
    const COUNTED_SAPLING_SPENDS: usize = 1;

    /// The Sapling outputs that the Sapling spend counting test requests in its second case:
    /// more than a Sapling bundle is padded to, so that it holds exactly this many.
    #[cfg(feature = "circuits")]
    const COUNTED_SAPLING_OUTPUTS: usize = 3;

    /// The spends that a shielded-component test requests of a pool to which it adds none.
    #[cfg(feature = "circuits")]
    const NO_SPENDS: usize = 0;

    /// The outputs that a shielded-component test requests of a pool to which it adds none.
    #[cfg(feature = "circuits")]
    const NO_OUTPUTS: usize = 0;

    /// The actions of a default-padded Orchard-protocol bundle that has any component: a
    /// smaller request is padded with dummy actions up to this many.
    #[cfg(feature = "circuits")]
    const DEFAULT_PADDED_ACTIONS: usize = 2;

    /// The actions of an unpadded Orchard-protocol bundle that requests one spend or one
    /// output.
    #[cfg(feature = "circuits")]
    const UNPADDED_SINGLE_ACTIONS: usize = 1;

    /// The actions of an unpadded Orchard bundle that requests one spend and one output: from
    /// NU6.3 the Orchard pool disables cross-address transfers, so they do not share an action.
    #[cfg(feature = "circuits")]
    const ORCHARD_SPEND_AND_CHANGE_ACTIONS: usize = 2;

    /// The transparent address that the counting tests pay to.
    #[cfg(feature = "circuits")]
    const COUNTED_TRANSPARENT_RECIPIENT: TransparentAddress =
        TransparentAddress::PublicKeyHash([0; 20]);

    /// The seed of the key that owns the notes that the counting tests spend.
    #[cfg(feature = "circuits")]
    const COUNTED_NOTE_OWNER_SEED: [u8; 32] = [7; 32];

    /// The `rho` of the notes that the counting tests spend.
    #[cfg(feature = "circuits")]
    const COUNTED_NOTE_RHO: [u8; 32] = [1; 32];

    /// The size in bytes of the random seed of an Orchard-protocol note.
    #[cfg(feature = "circuits")]
    const COUNTED_NOTE_RSEED_SIZE: usize = 32;

    /// The bytes of the hash that the counting tests use for every sibling in a Merkle path.
    #[cfg(feature = "circuits")]
    const COUNTED_MERKLE_SIBLING: [u8; 32] = [0; 32];

    /// The seed of the transparent account that funds the counting tests' transparent inputs.
    #[cfg(all(feature = "transparent-inputs", feature = "circuits"))]
    const COUNTED_TRANSPARENT_SEED: [u8; 32] = [0; 32];

    /// Test helper: returns the full viewing key of the counting tests' note owner.
    #[cfg(feature = "circuits")]
    fn counted_note_owner() -> orchard::keys::FullViewingKey {
        orchard::keys::FullViewingKey::from(
            &orchard::keys::SpendingKey::from_bytes(COUNTED_NOTE_OWNER_SEED).unwrap(),
        )
    }

    /// Test helper: returns the Sapling address that the shielded-component tests pay to.
    #[cfg(feature = "circuits")]
    fn counted_sapling_recipient() -> sapling::PaymentAddress {
        ExtendedSpendingKey::master(&[])
            .expect("the derivation path yields a valid key")
            .to_diversifiable_full_viewing_key()
            .default_address()
            .1
    }

    /// Test helper: returns the full viewing key of the counting tests' note owner, a note of
    /// the given `version` and `value` that it owns, a Merkle path to the note, and the anchor
    /// that the path roots to.
    #[cfg(feature = "circuits")]
    fn counted_note(
        version: orchard::note::NoteVersion,
        value: Zatoshis,
    ) -> (
        orchard::keys::FullViewingKey,
        orchard::Note,
        orchard::tree::MerklePath,
        orchard::Anchor,
    ) {
        let fvk = counted_note_owner();
        let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
        let rho = orchard::note::Rho::from_bytes(&COUNTED_NOTE_RHO).unwrap();
        let rseed = (u8::MIN..=u8::MAX)
            .find_map(|b| {
                orchard::note::RandomSeed::from_bytes([b; COUNTED_NOTE_RSEED_SIZE], &rho)
                    .into_option()
            })
            .expect("at least one test rseed is valid");
        let note = orchard::Note::from_parts(
            recipient,
            orchard::value::NoteValue::from_raw(value.into()),
            rho,
            rseed,
            version,
        )
        .unwrap();
        let sibling =
            orchard::tree::MerkleHashOrchard::from_bytes(&COUNTED_MERKLE_SIBLING).unwrap();
        let merkle_path = orchard::tree::MerklePath::from_parts(
            0,
            [sibling; orchard::NOTE_COMMITMENT_TREE_DEPTH],
        );
        let anchor = merkle_path.root(note.commitment().into());

        (fvk, note, merkle_path, anchor)
    }

    /// Test helper: counts the shielded components in the parts of a PCZT.
    #[cfg(feature = "circuits")]
    fn pczt_counts<P: Parameters>(parts: &PcztParts<P>) -> ShieldedActionCounts {
        ShieldedActionCounts::ZERO
            .with_orchard_actions(parts.orchard.as_ref().map_or(0, |b| b.actions().len()))
            .with_ironwood_actions(parts.ironwood.as_ref().map_or(0, |b| b.actions().len()))
            .with_sapling(
                parts.sapling.as_ref().map_or(0, |b| b.spends().len()),
                parts.sapling.as_ref().map_or(0, |b| b.outputs().len()),
            )
    }

    #[test]
    #[cfg(all(feature = "transparent-inputs", feature = "circuits"))]
    fn built_counts_match_the_builders_prediction_for_sapling() {
        let mut transparent_signing_set = TransparentSigningSet::new();
        let tsk =
            AccountPrivKey::from_seed(&TEST_NETWORK, &COUNTED_TRANSPARENT_SEED, AccountId::ZERO)
                .unwrap();
        let sk = tsk
            .derive_external_secret_key(NonHardenedChildIndex::ZERO)
            .unwrap();
        let pubkey = transparent_signing_set.add_key(sk);
        let coin = |value| {
            TxOut::new(
                value,
                tsk.to_account_pubkey()
                    .derive_external_ivk()
                    .unwrap()
                    .derive_address(NonHardenedChildIndex::ZERO)
                    .unwrap()
                    .script()
                    .into(),
            )
        };

        // One transparent coin funds one Sapling output.
        let builder_funded_with = |coin_value| {
            let mut builder = Builder::new(
                nu6_3_test_network(),
                PRE_NU7_TARGET_HEIGHT,
                BuildConfig::Standard {
                    sapling_anchor: Some(sapling::Anchor::empty_tree()),
                    orchard_anchor: None,
                    ironwood_anchor: None,
                    orchard_padding: BundlePadding::DEFAULT,
                    ironwood_padding: BundlePadding::DEFAULT,
                },
            );
            builder
                .add_transparent_p2pkh_input(pubkey, OutPoint::fake(), coin(coin_value))
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    None,
                    counted_sapling_recipient(),
                    COUNTED_OUTPUT_VALUE,
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
        };
        // The fee depends on which components the builder holds, not on their values.
        let fee = builder_funded_with(COUNTED_OUTPUT_VALUE)
            .get_fee(&zip317::FeeRule::standard())
            .unwrap();
        let builder = builder_funded_with((COUNTED_OUTPUT_VALUE + fee).unwrap());

        // The requested output is padded to the Sapling minimum; no spend is added.
        let predicted = builder.shielded_action_counts().unwrap();
        assert_eq!(
            predicted,
            ShieldedActionCounts::ZERO.with_sapling(NO_SPENDS, SAPLING_PADDED_OUTPUTS)
        );

        let result = builder
            .mock_build(&transparent_signing_set, &[], &[], UnwrapErr(SysRng))
            .unwrap();
        assert_eq!(result.transaction().shielded_action_counts(), predicted);
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn built_counts_match_the_builders_prediction_for_a_sapling_spend() {
        let extsk =
            ExtendedSpendingKey::master(&[]).expect("the derivation path yields a valid key");
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let recipient = dfvk.default_address().1;
        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        // One Sapling note funds one transparent output and the given number of Sapling outputs.
        let builder_funded_with = |note_value: Zatoshis, sapling_outputs: usize| {
            let mut rng = UnwrapErr(SysRng);
            let note = recipient.create_note(
                sapling::value::NoteValue::from_raw(note_value.into()),
                Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
            );
            let mut tree = sapling::CommitmentTree::empty();
            tree.append(Node::from_cmu(&note.cmu())).unwrap();
            let witness = sapling::IncrementalWitness::from_tree(tree).unwrap();

            let mut builder = Builder::new(
                TEST_NETWORK,
                tx_height,
                BuildConfig::Standard {
                    sapling_anchor: Some(witness.root().into()),
                    orchard_anchor: None,
                    ironwood_anchor: None,
                    orchard_padding: BundlePadding::DEFAULT,
                    ironwood_padding: BundlePadding::DEFAULT,
                },
            );
            builder
                .add_sapling_spend::<Infallible>(dfvk.fvk().clone(), note, witness.path().unwrap())
                .unwrap();
            builder
                .add_transparent_output(&COUNTED_TRANSPARENT_RECIPIENT, COUNTED_OUTPUT_VALUE)
                .unwrap();
            for _ in 0..sapling_outputs {
                builder
                    .add_sapling_output::<Infallible>(
                        None,
                        recipient,
                        COUNTED_OUTPUT_VALUE,
                        MemoBytes::empty(),
                    )
                    .unwrap();
            }
            builder
        };

        // Funds, predicts and builds a transaction that spends the note and requests the given
        // number of Sapling outputs.
        let check_counts = |sapling_outputs: usize, expected: ShieldedActionCounts| {
            let shielded_outputs_value = (COUNTED_OUTPUT_VALUE * sapling_outputs).unwrap();
            let outputs_value = (shielded_outputs_value + COUNTED_OUTPUT_VALUE).unwrap();
            // The fee depends on which components the builder holds, not on their values.
            let fee = builder_funded_with(outputs_value, sapling_outputs)
                .get_fee(&zip317::FeeRule::standard())
                .unwrap();
            let builder = builder_funded_with((outputs_value + fee).unwrap(), sapling_outputs);

            let predicted = builder.shielded_action_counts().unwrap();
            assert_eq!(predicted, expected);

            let result = builder
                .mock_build(
                    &TransparentSigningSet::new(),
                    core::slice::from_ref(&extsk),
                    &[],
                    UnwrapErr(SysRng),
                )
                .unwrap();
            assert_eq!(result.transaction().shielded_action_counts(), predicted);
        };

        // A spend forces the bundle to hold the minimum number of outputs even when none is
        // requested (unshielding N notes builds N spends and the padded outputs).
        check_counts(
            NO_OUTPUTS,
            ShieldedActionCounts::ZERO.with_sapling(COUNTED_SAPLING_SPENDS, SAPLING_PADDED_OUTPUTS),
        );
        // Outputs beyond the minimum are not padded.
        check_counts(
            COUNTED_SAPLING_OUTPUTS,
            ShieldedActionCounts::ZERO
                .with_sapling(COUNTED_SAPLING_SPENDS, COUNTED_SAPLING_OUTPUTS),
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn built_counts_match_the_builders_prediction_for_ironwood() {
        // One Ironwood spend funds the outputs.
        let builder_funded_with = |note_value| {
            let (fvk, note, merkle_path, anchor) =
                counted_note(orchard::note::NoteVersion::V3, note_value);
            let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
            let mut builder = Builder::new(
                nu7_test_network(),
                NU7_TARGET_HEIGHT,
                BuildConfig::Standard {
                    sapling_anchor: None,
                    orchard_anchor: None,
                    ironwood_anchor: Some(anchor),
                    orchard_padding: BundlePadding::DEFAULT,
                    ironwood_padding: BundlePadding::DEFAULT,
                },
            );
            builder
                .add_ironwood_spend::<Infallible>(fvk, note, merkle_path)
                .unwrap();
            for _ in 0..COUNTED_IRONWOOD_OUTPUTS {
                builder
                    .add_ironwood_output::<Infallible>(
                        None,
                        recipient,
                        COUNTED_OUTPUT_VALUE,
                        MemoBytes::empty(),
                    )
                    .unwrap();
            }
            builder
        };
        let outputs_value = (COUNTED_OUTPUT_VALUE * COUNTED_IRONWOOD_OUTPUTS).unwrap();
        // The fee depends on which components the builder holds, not on their values.
        let fee = builder_funded_with(outputs_value)
            .get_fee(&zip317::FeeRule::standard())
            .unwrap();
        let builder = builder_funded_with((outputs_value + fee).unwrap());

        // Ironwood permits cross-address transfers, so the spend shares an action with one of
        // the outputs: the bundle holds one action per output.
        let predicted = builder.shielded_action_counts().unwrap();
        assert_eq!(
            predicted,
            ShieldedActionCounts::ZERO.with_ironwood_actions(COUNTED_IRONWOOD_OUTPUTS)
        );

        let ask = orchard::keys::SpendAuthorizingKey::from(
            &orchard::keys::SpendingKey::from_bytes(COUNTED_NOTE_OWNER_SEED).unwrap(),
        );
        let result = builder
            .mock_build(
                &TransparentSigningSet::new(),
                &[],
                &[ask],
                UnwrapErr(SysRng),
            )
            .unwrap();
        assert_eq!(result.transaction().shielded_action_counts(), predicted);
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn built_counts_match_the_builders_prediction_for_a_coinbase() {
        let sapling_recipient = counted_sapling_recipient();
        let ironwood_recipient =
            counted_note_owner().address_at(0u32, orchard::keys::Scope::External);

        let mut builder = Builder::new(
            nu7_test_network(),
            NU7_TARGET_HEIGHT,
            BuildConfig::Coinbase { miner_data: None },
        );
        for _ in 0..COUNTED_COINBASE_OUTPUTS {
            builder
                .add_sapling_output::<Infallible>(
                    None,
                    sapling_recipient,
                    COUNTED_OUTPUT_VALUE,
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_ironwood_output::<Infallible>(
                    None,
                    ironwood_recipient,
                    COUNTED_OUTPUT_VALUE,
                    MemoBytes::empty(),
                )
                .unwrap();
        }

        let predicted = builder.shielded_action_counts().unwrap();
        assert_eq!(
            predicted,
            ShieldedActionCounts::ZERO
                .with_sapling(NO_SPENDS, COUNTED_COINBASE_OUTPUTS)
                .with_ironwood_actions(COUNTED_COINBASE_OUTPUTS)
        );

        let result = builder
            .mock_build(&TransparentSigningSet::new(), &[], &[], UnwrapErr(SysRng))
            .unwrap();
        assert_eq!(result.transaction().shielded_action_counts(), predicted);
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn pczt_counts_match_the_builders_prediction() {
        // One Orchard spend funds an Orchard change output and an Ironwood output.
        let builder_funded_with = |note_value| {
            let (fvk, note, merkle_path, anchor) =
                counted_note(orchard::note::NoteVersion::V2, note_value);
            let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
            let change_recipient = fvk.address_at(0u32, orchard::keys::Scope::Internal);
            let mut builder = Builder::new(
                nu7_test_network(),
                NU7_TARGET_HEIGHT,
                BuildConfig::Standard {
                    sapling_anchor: None,
                    orchard_anchor: Some(anchor),
                    ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                    orchard_padding: BundlePadding::UNPADDED,
                    ironwood_padding: BundlePadding::UNPADDED,
                },
            );
            builder
                .add_orchard_spend::<Infallible>(fvk.clone(), note, merkle_path)
                .unwrap();
            builder
                .add_orchard_change_output::<Infallible>(
                    fvk,
                    None,
                    change_recipient,
                    COUNTED_OUTPUT_VALUE,
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_ironwood_output::<Infallible>(
                    None,
                    recipient,
                    COUNTED_OUTPUT_VALUE,
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
        };
        let outputs_value = (COUNTED_OUTPUT_VALUE + COUNTED_OUTPUT_VALUE).unwrap();
        // The fee depends on which components the builder holds, not on their values.
        let fee = builder_funded_with(outputs_value)
            .get_fee(&zip317::FeeRule::standard())
            .unwrap();
        let builder = builder_funded_with((outputs_value + fee).unwrap());

        // The Orchard pool disables cross-address transfers, so its spend and its output do not
        // share an action; the Ironwood output is not padded.
        let predicted = builder.shielded_action_counts().unwrap();
        assert_eq!(
            predicted,
            ShieldedActionCounts::ZERO
                .with_orchard_actions(ORCHARD_SPEND_AND_CHANGE_ACTIONS)
                .with_ironwood_actions(UNPADDED_SINGLE_ACTIONS)
        );

        let result = builder
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
            .unwrap();
        assert_eq!(pczt_counts(&result.pczt_parts), predicted);
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn pczt_counts_include_a_required_bundle_of_dummy_actions() {
        // An Orchard spend pays only the fee. The Ironwood pool holds nothing, but it is required
        // to produce a bundle, which then consists of dummy actions only.
        let builder_funded_with = |note_value| {
            let (fvk, note, merkle_path, anchor) =
                counted_note(orchard::note::NoteVersion::V2, note_value);
            let mut builder = Builder::new(
                nu7_test_network(),
                NU7_TARGET_HEIGHT,
                BuildConfig::Standard {
                    sapling_anchor: None,
                    orchard_anchor: Some(anchor),
                    ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                    orchard_padding: BundlePadding::UNPADDED,
                    ironwood_padding: BundlePadding {
                        bundle_required: true,
                        pad_to_minimum: Some(COUNTED_DUMMY_ACTIONS),
                    },
                },
            );
            builder
                .add_orchard_spend::<Infallible>(fvk, note, merkle_path)
                .unwrap();
            builder
        };
        // The fee depends on which components the builder holds, not on their values.
        let fee = builder_funded_with(COUNTED_OUTPUT_VALUE)
            .get_fee(&zip317::FeeRule::standard())
            .unwrap();
        let builder = builder_funded_with(fee);

        let predicted = builder.shielded_action_counts().unwrap();
        assert_eq!(
            predicted,
            ShieldedActionCounts::ZERO
                .with_orchard_actions(UNPADDED_SINGLE_ACTIONS)
                .with_ironwood_actions(usize::from(COUNTED_DUMMY_ACTIONS))
        );

        let result = builder
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
            .unwrap();
        assert_eq!(pczt_counts(&result.pczt_parts), predicted);
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn deferred_pczt_counts_match_the_builders_prediction() {
        // One Orchard spend funds an Orchard change output and an Ironwood output.
        let builder_funded_with = |note_value| {
            let (fvk, note, _, _) = counted_note(orchard::note::NoteVersion::V2, note_value);
            let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
            let change_recipient = fvk.address_at(0u32, orchard::keys::Scope::Internal);
            let mut builder = DeferredPcztBuilder::new::<zip317::FeeError>(
                nu7_test_network(),
                NU7_TARGET_HEIGHT,
                BundlePadding::UNPADDED,
                BundlePadding::DEFAULT,
            )
            .unwrap();
            builder
                .add_orchard_spend::<zip317::FeeError>(fvk.clone(), note)
                .unwrap();
            builder
                .add_orchard_change_output::<zip317::FeeError>(
                    fvk,
                    None,
                    change_recipient,
                    COUNTED_OUTPUT_VALUE,
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_ironwood_output::<zip317::FeeError>(
                    None,
                    recipient,
                    COUNTED_OUTPUT_VALUE,
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
        };
        let outputs_value = (COUNTED_OUTPUT_VALUE + COUNTED_OUTPUT_VALUE).unwrap();
        // The fee depends on which components the builder holds, not on their values.
        let fee = builder_funded_with(outputs_value)
            .get_fee(&zip317::FeeRule::standard())
            .unwrap();
        let builder = builder_funded_with((outputs_value + fee).unwrap());

        // The Orchard pool disables cross-address transfers, so its spend and its output do not
        // share an action; the Ironwood output is padded to the default minimum.
        let predicted = builder.shielded_action_counts().unwrap();
        assert_eq!(
            predicted,
            ShieldedActionCounts::ZERO
                .with_orchard_actions(ORCHARD_SPEND_AND_CHANGE_ACTIONS)
                .with_ironwood_actions(DEFAULT_PADDED_ACTIONS)
        );

        let result = builder
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
            .unwrap();
        assert_eq!(pczt_counts(&result.pczt_parts), predicted);
    }

    /// Records current behaviour, with which `get_fee` disagrees: it prices the required padding.
    #[test]
    #[cfg(feature = "circuits")]
    fn deferred_pczt_counts_an_unused_pool_as_absent_even_when_its_bundle_is_required() {
        // An Orchard spend alone; the Ironwood pool is required to produce a bundle but holds
        // nothing.
        let builder_funded_with = |note_value| {
            let (fvk, note, _, _) = counted_note(orchard::note::NoteVersion::V2, note_value);
            let mut builder = DeferredPcztBuilder::new::<zip317::FeeError>(
                nu7_test_network(),
                NU7_TARGET_HEIGHT,
                BundlePadding::DEFAULT,
                BundlePadding {
                    bundle_required: true,
                    pad_to_minimum: None,
                },
            )
            .unwrap();
            builder
                .add_orchard_spend::<zip317::FeeError>(fvk, note)
                .unwrap();
            builder
        };
        // The note pays the fee and nothing else.
        let fee = builder_funded_with(COUNTED_OUTPUT_VALUE)
            .get_fee(&zip317::FeeRule::standard())
            .unwrap();
        let builder = builder_funded_with(fee);

        let predicted = builder.shielded_action_counts().unwrap();
        assert_eq!(
            predicted,
            ShieldedActionCounts::ZERO.with_orchard_actions(DEFAULT_PADDED_ACTIONS)
        );

        let result = builder
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
            .unwrap();
        assert!(result.pczt_parts.ironwood.is_none());
        assert_eq!(pczt_counts(&result.pczt_parts), predicted);
    }

    /// The Ironwood outputs that the global-budget test requests.
    #[cfg(feature = "circuits")]
    const BUDGET_TEST_IRONWOOD_OUTPUTS: usize = 165;

    /// The Sapling outputs that the global-budget test requests: together with the Ironwood
    /// outputs, exactly the global shielded budget.
    #[cfg(feature = "circuits")]
    const BUDGET_TEST_SAPLING_OUTPUTS: usize =
        GLOBAL_SHIELDED_BUDGET - BUDGET_TEST_IRONWOOD_OUTPUTS;

    // The budget test must overrun the global budget, not a limit of one pool: each pool stays
    // within its own limit, even with the one output that the test adds to overrun the budget.
    #[cfg(feature = "circuits")]
    const _: () = assert!(
        BUDGET_TEST_IRONWOOD_OUTPUTS < ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT
            && BUDGET_TEST_SAPLING_OUTPUTS < SAPLING_BLOCK_IO_LIMIT
    );

    /// Test helper: returns a builder on `params` that targets `target_height` and holds
    /// `ironwood_outputs` Ironwood outputs and `sapling_outputs` Sapling outputs. No input funds
    /// them, so a build that passes every check that precedes the value balance check fails on
    /// the balance.
    #[cfg(feature = "circuits")]
    fn unfunded_builder<P: Parameters>(
        params: P,
        target_height: BlockHeight,
        ironwood_outputs: usize,
        sapling_outputs: usize,
    ) -> Builder<P, ()> {
        let builder = Builder::new(
            params,
            target_height,
            BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: None,
                ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        with_outputs(builder, ironwood_outputs, sapling_outputs)
    }

    /// Test helper: adds `ironwood_outputs` Ironwood outputs and `sapling_outputs` Sapling
    /// outputs to `builder`.
    #[cfg(feature = "circuits")]
    fn with_outputs<P: Parameters>(
        mut builder: Builder<P, ()>,
        ironwood_outputs: usize,
        sapling_outputs: usize,
    ) -> Builder<P, ()> {
        let ironwood_recipient =
            counted_note_owner().address_at(0u32, orchard::keys::Scope::External);
        let sapling_recipient = counted_sapling_recipient();

        for _ in 0..ironwood_outputs {
            builder
                .add_ironwood_output::<Infallible>(
                    None,
                    ironwood_recipient,
                    COUNTED_OUTPUT_VALUE,
                    MemoBytes::empty(),
                )
                .unwrap();
        }
        for _ in 0..sapling_outputs {
            builder
                .add_sapling_output::<Infallible>(
                    None,
                    sapling_recipient,
                    COUNTED_OUTPUT_VALUE,
                    MemoBytes::empty(),
                )
                .unwrap();
        }
        builder
    }

    /// Test helper: returns a deferred-anchor builder on `params` that targets `target_height`
    /// and holds `ironwood_outputs` Ironwood outputs, which no input funds.
    #[cfg(feature = "circuits")]
    fn unfunded_deferred_builder<P: Parameters>(
        params: P,
        target_height: BlockHeight,
        ironwood_outputs: usize,
    ) -> DeferredPcztBuilder<P> {
        let recipient = counted_note_owner().address_at(0u32, orchard::keys::Scope::External);

        let mut builder = DeferredPcztBuilder::new::<zip317::FeeError>(
            params,
            target_height,
            BundlePadding::DEFAULT,
            BundlePadding::DEFAULT,
        )
        .unwrap();
        for _ in 0..ironwood_outputs {
            builder
                .add_ironwood_output::<zip317::FeeError>(
                    None,
                    recipient,
                    COUNTED_OUTPUT_VALUE,
                    MemoBytes::empty(),
                )
                .unwrap();
        }
        builder
    }

    /// Test helper: asserts that `result` is a refusal to build because the transaction exceeds
    /// `limit` with `count` components, the shielded components of the transaction being
    /// `counts`.
    #[cfg(feature = "circuits")]
    fn assert_refused<T: Debug>(
        result: Result<T, Error<zip317::FeeError>>,
        limit: ShieldedBlockLimit,
        count: usize,
        counts: ShieldedActionCounts,
    ) {
        match result {
            Err(Error::ShieldedLimitExceeded(exceeded)) => {
                assert_eq!(exceeded.limit(), limit);
                assert_eq!(exceeded.count(), count);
                assert_eq!(exceeded.counts(), counts);
            }
            other => panic!("expected a refusal for exceeding the {limit} limit, got {other:?}"),
        }
    }

    /// Test helper: asserts that `result` is not a refusal to build for exceeding a limit, but
    /// the failure of a transaction that no input funds. That failure follows the limit check,
    /// so it shows that the check passed the transaction.
    #[cfg(feature = "circuits")]
    fn assert_not_refused_for_the_limit<T: Debug>(result: Result<T, Error<zip317::FeeError>>) {
        assert_matches!(result, Err(Error::InsufficientFunds(_)));
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn ironwood_outputs_over_the_action_limit_are_refused() {
        let over = ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT + 1;
        let builder = unfunded_builder(nu7_test_network(), NU7_TARGET_HEIGHT, over, NO_OUTPUTS);

        let result = builder.mock_build(&TransparentSigningSet::new(), &[], &[], UnwrapErr(SysRng));

        assert_refused(
            result,
            ShieldedBlockLimit::IronwoodActions,
            over,
            ShieldedActionCounts::ZERO.with_ironwood_actions(over),
        );

        // Exactly at the limit, the transaction is not refused for it.
        let builder = unfunded_builder(
            nu7_test_network(),
            NU7_TARGET_HEIGHT,
            ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT,
            NO_OUTPUTS,
        );

        let result = builder.mock_build(&TransparentSigningSet::new(), &[], &[], UnwrapErr(SysRng));

        assert_not_refused_for_the_limit(result);

        // A coinbase transaction, whose bundles are not padded, is refused for the same count.
        let coinbase = Builder::new(
            nu7_test_network(),
            NU7_TARGET_HEIGHT,
            BuildConfig::Coinbase { miner_data: None },
        );
        let builder = with_outputs(coinbase, over, NO_OUTPUTS);

        let result = builder.mock_build(&TransparentSigningSet::new(), &[], &[], UnwrapErr(SysRng));

        assert_refused(
            result,
            ShieldedBlockLimit::IronwoodActions,
            over,
            ShieldedActionCounts::ZERO.with_ironwood_actions(over),
        );
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn sapling_outputs_over_the_io_limit_are_refused() {
        let over = SAPLING_BLOCK_IO_LIMIT + 1;
        let builder = unfunded_builder(nu7_test_network(), NU7_TARGET_HEIGHT, NO_OUTPUTS, over);

        let result = builder.mock_build(&TransparentSigningSet::new(), &[], &[], UnwrapErr(SysRng));

        assert_refused(
            result,
            ShieldedBlockLimit::SaplingSpendsAndOutputs,
            over,
            ShieldedActionCounts::ZERO.with_sapling(NO_SPENDS, over),
        );

        // Exactly at the limit, the transaction is not refused for it.
        let builder = unfunded_builder(
            nu7_test_network(),
            NU7_TARGET_HEIGHT,
            NO_OUTPUTS,
            SAPLING_BLOCK_IO_LIMIT,
        );

        let result = builder.mock_build(&TransparentSigningSet::new(), &[], &[], UnwrapErr(SysRng));

        assert_not_refused_for_the_limit(result);
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn pools_together_over_the_global_budget_are_refused() {
        // One more Sapling output than fills the budget: neither pool is over its own limit.
        let builder = unfunded_builder(
            nu7_test_network(),
            NU7_TARGET_HEIGHT,
            BUDGET_TEST_IRONWOOD_OUTPUTS,
            BUDGET_TEST_SAPLING_OUTPUTS + 1,
        );

        let result = builder.mock_build(&TransparentSigningSet::new(), &[], &[], UnwrapErr(SysRng));

        assert_refused(
            result,
            ShieldedBlockLimit::GlobalShieldedBudget,
            GLOBAL_SHIELDED_BUDGET + 1,
            ShieldedActionCounts::ZERO
                .with_ironwood_actions(BUDGET_TEST_IRONWOOD_OUTPUTS)
                .with_sapling(NO_SPENDS, BUDGET_TEST_SAPLING_OUTPUTS + 1),
        );

        // Exactly filling the budget, the transaction is not refused for it.
        let builder = unfunded_builder(
            nu7_test_network(),
            NU7_TARGET_HEIGHT,
            BUDGET_TEST_IRONWOOD_OUTPUTS,
            BUDGET_TEST_SAPLING_OUTPUTS,
        );

        let result = builder.mock_build(&TransparentSigningSet::new(), &[], &[], UnwrapErr(SysRng));

        assert_not_refused_for_the_limit(result);
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn limits_do_not_apply_before_nu7() {
        let over = ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT + 1;
        let params = nu6_3_test_network();
        assert!(!params.is_nu_active(NetworkUpgrade::Nu7, PRE_NU7_TARGET_HEIGHT));

        let result = unfunded_builder(params, PRE_NU7_TARGET_HEIGHT, over, NO_OUTPUTS).mock_build(
            &TransparentSigningSet::new(),
            &[],
            &[],
            UnwrapErr(SysRng),
        );
        assert_not_refused_for_the_limit(result);

        let result = unfunded_builder(params, PRE_NU7_TARGET_HEIGHT, over, NO_OUTPUTS)
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard());
        assert_not_refused_for_the_limit(result);

        let result = unfunded_deferred_builder(params, PRE_NU7_TARGET_HEIGHT, over)
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard());
        assert_not_refused_for_the_limit(result);

        // Nor at the last height before NU7 activates, on a network where it does.
        let params = nu7_test_network();
        assert_eq!(
            params.activation_height(NetworkUpgrade::Nu7),
            Some(PRE_NU7_TARGET_HEIGHT + 1)
        );

        let result = unfunded_builder(params, PRE_NU7_TARGET_HEIGHT, over, NO_OUTPUTS).mock_build(
            &TransparentSigningSet::new(),
            &[],
            &[],
            UnwrapErr(SysRng),
        );
        assert_not_refused_for_the_limit(result);
    }

    #[test]
    #[cfg(feature = "circuits")]
    fn build_for_pczt_refuses_over_the_limit() {
        let over = ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT + 1;
        let refused_counts = ShieldedActionCounts::ZERO.with_ironwood_actions(over);

        let result = unfunded_builder(nu7_test_network(), NU7_TARGET_HEIGHT, over, NO_OUTPUTS)
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard());
        assert_refused(
            result,
            ShieldedBlockLimit::IronwoodActions,
            over,
            refused_counts,
        );

        let result = unfunded_deferred_builder(nu7_test_network(), NU7_TARGET_HEIGHT, over)
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard());
        assert_refused(
            result,
            ShieldedBlockLimit::IronwoodActions,
            over,
            refused_counts,
        );

        // Exactly at the limit, neither is refused for it.
        let result = unfunded_builder(
            nu7_test_network(),
            NU7_TARGET_HEIGHT,
            ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT,
            NO_OUTPUTS,
        )
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard());
        assert_not_refused_for_the_limit(result);

        let result = unfunded_deferred_builder(
            nu7_test_network(),
            NU7_TARGET_HEIGHT,
            ORCHARD_PROTOCOL_BLOCK_ACTION_LIMIT,
        )
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard());
        assert_not_refused_for_the_limit(result);
    }

    #[cfg(all(feature = "circuits", feature = "std"))]
    #[test]
    fn cached_orchard_proving_key_reuses_one_instance_per_version() {
        // Repeated calls for the same circuit version return the very same cached
        // key, so building many transactions does not reconstruct it each time.
        let first = cached_orchard_proving_key(OrchardCircuitVersion::FixedPostNu6_2);
        let second = cached_orchard_proving_key(OrchardCircuitVersion::FixedPostNu6_2);
        assert!(ptr::eq(first, second));

        // Distinct circuit versions are cached independently.
        let other = cached_orchard_proving_key(OrchardCircuitVersion::PostNu6_3);
        assert!(!ptr::eq(first, other));
    }
}
