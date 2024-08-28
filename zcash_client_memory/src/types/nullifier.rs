




use std::{
    collections::{BTreeMap},
};



use zcash_primitives::{
    consensus::{BlockHeight},
};
use zcash_protocol::{
    PoolType,
};





/// Maps a block height and transaction (i.e. transaction locator) index to a nullifier.
pub(crate) struct NullifierMap(BTreeMap<Nullifier, (BlockHeight, u32)>);

impl NullifierMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
    pub fn insert(&mut self, height: BlockHeight, index: u32, nullifier: Nullifier) {
        self.0.insert(nullifier, (height, index));
    }

    pub fn get(&self, nullifier: &Nullifier) -> Option<&(BlockHeight, u32)> {
        self.0.get(nullifier)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Nullifier {
    #[cfg(feature = "orchard")]
    Orchard(orchard::note::Nullifier),
    Sapling(sapling::Nullifier),
}

impl Nullifier {
    pub(crate) fn pool(&self) -> PoolType {
        match self {
            #[cfg(feature = "orchard")]
            Nullifier::Orchard(_) => PoolType::ORCHARD,
            Nullifier::Sapling(_) => PoolType::SAPLING,
        }
    }
}
#[cfg(feature = "orchard")]
impl From<orchard::note::Nullifier> for Nullifier {
    fn from(n: orchard::note::Nullifier) -> Self {
        Nullifier::Orchard(n)
    }
}
impl From<sapling::Nullifier> for Nullifier {
    fn from(n: sapling::Nullifier) -> Self {
        Nullifier::Sapling(n)
    }
}
