//! Types related to computation of fees and change related to the Sapling components
//! of a transaction.

use std::convert::Infallible;

use sapling::builder::{BundleType, OutputInfo, SpendInfo};
use zcash_protocol::value::Zatoshis;

/// A trait that provides a minimized view of Sapling bundle configuration
/// suitable for use in fee and change calculation.
pub trait BundleView<NoteRef> {
    /// The type of inputs to the bundle.
    type In: InputView<NoteRef>;
    /// The type of inputs of the bundle.
    type Out: OutputView;

    /// Returns the type of the bundle
    fn bundle_type(&self) -> BundleType;
    /// Returns the inputs to the bundle.
    fn inputs(&self) -> &[Self::In];
    /// Returns the outputs of the bundle.
    fn outputs(&self) -> &[Self::Out];
}

impl<'a, NoteRef, In: InputView<NoteRef>, Out: OutputView> BundleView<NoteRef>
    for (BundleType, &'a [In], &'a [Out])
{
    type In = In;
    type Out = Out;

    fn bundle_type(&self) -> BundleType {
        self.0
    }

    fn inputs(&self) -> &[In] {
        self.1
    }

    fn outputs(&self) -> &[Out] {
        self.2
    }
}

/// A [`BundleView`] for the empty bundle with [`BundleType::DEFAULT`] bundle type.
pub struct EmptyBundleView;

impl<NoteRef> BundleView<NoteRef> for EmptyBundleView {
    type In = Infallible;
    type Out = Infallible;

    fn bundle_type(&self) -> BundleType {
        BundleType::DEFAULT
    }

    fn inputs(&self) -> &[Self::In] {
        &[]
    }

    fn outputs(&self) -> &[Self::Out] {
        &[]
    }
}

/// A trait that provides a minimized view of a Sapling input suitable for use in
/// fee and change calculation.
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

// `SpendDescriptionInfo` does not contain a note identifier, so we can only implement
// `InputView<()>`
impl InputView<()> for SpendInfo {
    fn note_id(&self) -> &() {
        &()
    }

    fn value(&self) -> Zatoshis {
        Zatoshis::try_from(self.value().inner())
            .expect("An existing note to be spent must have a valid amount value.")
    }
}

/// A trait that provides a minimized view of a Sapling output suitable for use in
/// fee and change calculation.
pub trait OutputView {
    /// The value of the output being produced.
    fn value(&self) -> Zatoshis;
}

impl OutputView for OutputInfo {
    fn value(&self) -> Zatoshis {
        Zatoshis::try_from(self.value().inner())
            .expect("Output values should be checked at construction.")
    }
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
