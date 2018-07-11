#[macro_use]
extern crate lazy_static;
extern crate pairing;
extern crate sapling_crypto;

use pairing::bls12_381::Bls12;
use sapling_crypto::{
    jubjub::{FixedGenerators, JubjubBls12, JubjubEngine, JubjubParams}, primitives::ViewingKey,
};

lazy_static! {
    static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}

// Sapling key components

/// An outgoing viewing key
#[derive(Clone, Copy)]
struct OutgoingViewingKey([u8; 32]);

/// A Sapling expanded spending key
struct ExpandedSpendingKey<E: JubjubEngine> {
    ask: E::Fs,
    nsk: E::Fs,
    ovk: OutgoingViewingKey,
}

/// A Sapling full viewing key
struct FullViewingKey<E: JubjubEngine> {
    vk: ViewingKey<E>,
    ovk: OutgoingViewingKey,
}

impl<E: JubjubEngine> FullViewingKey<E> {
    fn from_expanded_spending_key(xsk: &ExpandedSpendingKey<E>, params: &E::Params) -> Self {
        FullViewingKey {
            vk: ViewingKey {
                ak: params
                    .generator(FixedGenerators::SpendingKeyGenerator)
                    .mul(xsk.ask, params),
                nk: params
                    .generator(FixedGenerators::ProofGenerationKey)
                    .mul(xsk.nsk, params),
            },
            ovk: xsk.ovk,
        }
    }
}

// ZIP 32 structures

/// A Sapling full viewing key fingerprint
struct FVKFingerprint([u8; 32]);

/// A Sapling full viewing key tag
#[derive(Clone, Copy)]
struct FVKTag([u8; 4]);

impl<'a> From<&'a FVKFingerprint> for FVKTag {
    fn from(fingerprint: &FVKFingerprint) -> Self {
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&fingerprint.0[..4]);
        FVKTag(tag)
    }
}

impl From<FVKFingerprint> for FVKTag {
    fn from(fingerprint: FVKFingerprint) -> Self {
        (&fingerprint).into()
    }
}

/// A child index for a derived key
#[derive(Clone, Copy)]
pub enum ChildIndex {
    NonHardened(u32),
    Hardened(u32), // Hardened(n) == n + (1 << 31) == n' in path notation
}

impl ChildIndex {
    pub fn from_index(i: u32) -> Self {
        match i {
            n if n >= (1 << 31) => ChildIndex::Hardened(n - (1 << 31)),
            n => ChildIndex::NonHardened(n),
        }
    }
}

/// A chain code
#[derive(Clone, Copy)]
struct ChainCode([u8; 32]);

/// A key used to derive diversifiers for a particular child key
#[derive(Clone, Copy)]
struct DiversifierKey([u8; 32]);

/// A Sapling extended spending key
pub struct ExtendedSpendingKey {
    depth: u8,
    parent_fvk_tag: FVKTag,
    child_index: ChildIndex,
    chain_code: ChainCode,
    xsk: ExpandedSpendingKey<Bls12>,
    dk: DiversifierKey,
}

// A Sapling extended full viewing key
pub struct ExtendedFullViewingKey {
    depth: u8,
    parent_fvk_tag: FVKTag,
    child_index: ChildIndex,
    chain_code: ChainCode,
    fvk: FullViewingKey<Bls12>,
    dk: DiversifierKey,
}

impl<'a> From<&'a ExtendedSpendingKey> for ExtendedFullViewingKey {
    fn from(xsk: &ExtendedSpendingKey) -> Self {
        ExtendedFullViewingKey {
            depth: xsk.depth,
            parent_fvk_tag: xsk.parent_fvk_tag,
            child_index: xsk.child_index,
            chain_code: xsk.chain_code,
            fvk: FullViewingKey::from_expanded_spending_key(&xsk.xsk, &JUBJUB),
            dk: xsk.dk,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
