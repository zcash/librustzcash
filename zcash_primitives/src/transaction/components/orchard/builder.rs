use crate::consensus::{self, BlockHeight, NetworkUpgrade};

pub struct WithoutOrchard;

pub struct WithOrchard(Option<orchard::builder::Builder>);

impl WithOrchard {
    pub(crate) fn new<P: consensus::Parameters>(
        params: P,
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
