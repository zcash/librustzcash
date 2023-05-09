use crate::{
    consensus::{self, BlockHeight, NetworkUpgrade},
    transaction::components::Amount,
};
use orchard::{
    builder::{BuildError, Builder, InProgress, Unauthorized, Unproven},
    bundle::Bundle,
    value::OverflowError,
};

pub struct WithoutOrchard;

pub struct WithOrchard(pub(crate) Option<Builder>);

pub trait MaybeOrchard {
    #[allow(clippy::type_complexity)]
    fn build<V: core::convert::TryFrom<i64>>(
        self,
        rng: impl rand::RngCore,
    ) -> Option<Result<Bundle<InProgress<Unproven, Unauthorized>, V>, BuildError>>;
    fn value_balance(&self) -> Result<Amount, OverflowError>;
    fn input_count(&self) -> usize;
    fn output_count(&self) -> usize;
}

impl MaybeOrchard for WithOrchard {
    fn build<V: core::convert::TryFrom<i64>>(
        self,
        rng: impl rand::RngCore,
    ) -> Option<Result<Bundle<InProgress<Unproven, Unauthorized>, V>, BuildError>> {
        self.0.map(|builder| builder.build(rng))
    }

    fn value_balance(&self) -> Result<Amount, OverflowError> {
        match &self.0 {
            Some(builder) => builder.value_balance(),
            None => Ok(Amount::zero()),
        }
    }

    fn input_count(&self) -> usize {
        if let Some(ref builder) = self.0 {
            builder.spends().len()
        } else {
            0
        }
    }

    fn output_count(&self) -> usize {
        if let Some(ref builder) = self.0 {
            builder.outputs().len()
        } else {
            0
        }
    }
}

impl MaybeOrchard for WithoutOrchard {
    fn build<V: core::convert::TryFrom<i64>>(
        self,
        _: impl rand::RngCore,
    ) -> Option<Result<Bundle<InProgress<Unproven, Unauthorized>, V>, BuildError>> {
        None
    }

    fn value_balance(&self) -> Result<Amount, OverflowError> {
        Ok(Amount::zero())
    }

    fn input_count(&self) -> usize {
        0
    }

    fn output_count(&self) -> usize {
        0
    }
}

impl WithOrchard {
    pub(crate) fn new<P: consensus::Parameters>(
        params: &P,
        target_height: BlockHeight,
        anchor: orchard::tree::Anchor,
    ) -> Self {
        let orchard_builder = if params.is_nu_active(NetworkUpgrade::Nu5, target_height) {
            Some(orchard::builder::Builder::new(
                orchard::bundle::Flags::from_parts(true, true),
                anchor,
            ))
        } else {
            None
        };

        Self(orchard_builder)
    }
}
