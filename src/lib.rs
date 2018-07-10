extern crate pairing;
extern crate sapling_crypto;

use pairing::bls12_381::Bls12;
use sapling_crypto::{jubjub::JubjubEngine, primitives::ViewingKey};

// Sapling key components

/// An outgoing viewing key
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

// ZIP 32 structures

/// A Sapling full viewing key fingerprint
struct FVKFingerprint([u8; 32]);

/// A Sapling full viewing key tag
struct FVKTag([u8; 4]);

/// A child index for a derived key
pub enum ChildIndex {
    NonHardened(u32),
    Hardened(u32), // Hardened(n) == n + (1 << 31) == n' in path notation
}

/// A chain code
struct ChainCode([u8; 32]);

/// A key used to derive diversifiers for a particular child key
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
