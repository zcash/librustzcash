//! Types related to computation of fees and change related to the Orchard components
//! of a transaction.

use std::convert::Infallible;

use orchard::bundle::BundleVersion;
use zcash_primitives::transaction::builder::transactional_bundle_type;
use zcash_protocol::value::Zatoshis;

/// Returns the number of actions the transaction builder will produce for a
/// transactional (non-coinbase) Orchard-pool bundle of the given version, carrying the
/// given numbers of requested spends and outputs.
///
/// This derives the count from [`transactional_bundle_type`], so it follows the
/// builder's padding policy per pool (Orchard padded to the 2-action minimum, Ironwood
/// unpadded); the builder enforces an exact balance against the fee computed from
/// these counts.
pub(crate) fn transactional_action_count(
    bundle_version: BundleVersion,
    num_spends: usize,
    num_outputs: usize,
) -> Result<usize, &'static str> {
    transactional_bundle_type(bundle_version).num_actions(
        bundle_version.default_flags(),
        num_spends,
        num_outputs,
    )
}

/// A trait that provides a minimized view of Orchard-style bundle configuration
/// suitable for use in fee and change calculation.
pub trait BundleView<NoteRef> {
    /// The type of inputs to the bundle.
    type In: InputView<NoteRef>;
    /// The type of inputs of the bundle.
    type Out: OutputView;

    /// Returns the bundle version for the bundle.
    fn bundle_version(&self) -> BundleVersion;
    /// Returns the inputs to the bundle.
    fn inputs(&self) -> &[Self::In];
    /// Returns the outputs of the bundle.
    fn outputs(&self) -> &[Self::Out];
}

impl<'a, NoteRef, In: InputView<NoteRef>, Out: OutputView> BundleView<NoteRef>
    for (BundleVersion, &'a [In], &'a [Out])
{
    type In = In;
    type Out = Out;

    fn bundle_version(&self) -> BundleVersion {
        self.0
    }

    fn inputs(&self) -> &[In] {
        self.1
    }

    fn outputs(&self) -> &[Out] {
        self.2
    }
}

/// A [`BundleView`] for the empty legacy Orchard bundle.
pub struct EmptyBundleView;

impl<NoteRef> BundleView<NoteRef> for EmptyBundleView {
    type In = Infallible;
    type Out = Infallible;

    fn bundle_version(&self) -> BundleVersion {
        // An empty bundle contains no spends or outputs, and therefore produces
        // zero actions under every bundle version's action-count policy, so the
        // version returned here cannot affect fee calculation.
        BundleVersion::orchard_v2()
    }

    fn inputs(&self) -> &[Self::In] {
        &[]
    }

    fn outputs(&self) -> &[Self::Out] {
        &[]
    }
}

/// A trait that provides a minimized view of an Orchard input suitable for use in fee and change
/// calculation.
pub trait InputView<NoteRef> {
    /// An identifier for the input being spent.
    fn note_id(&self) -> &NoteRef;
    /// The value of the input being spent.
    fn value(&self) -> Zatoshis;
}

impl<N> InputView<N> for Infallible {
    fn note_id(&self) -> &N {
        unreachable!()
    }
    fn value(&self) -> Zatoshis {
        unreachable!()
    }
}

/// A trait that provides a minimized view of a Orchard output suitable for use in fee and change
/// calculation.
pub trait OutputView {
    /// The value of the output being produced.
    fn value(&self) -> Zatoshis;
}

impl OutputView for Infallible {
    fn value(&self) -> Zatoshis {
        unreachable!()
    }
}

impl OutputView for Zatoshis {
    fn value(&self) -> Zatoshis {
        *self
    }
}
