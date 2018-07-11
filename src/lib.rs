extern crate blake2_rfc;
#[macro_use]
extern crate lazy_static;
extern crate pairing;
extern crate sapling_crypto;

use blake2_rfc::blake2b::{Blake2b, Blake2bResult};
use pairing::bls12_381::Bls12;
use sapling_crypto::{
    jubjub::{FixedGenerators, JubjubBls12, JubjubEngine, JubjubParams, ToUniform},
    primitives::ViewingKey,
};

lazy_static! {
    static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}

pub const PRF_EXPAND_PERSONALIZATION: &'static [u8; 16] = b"Zcash_ExpandSeed";
pub const ZIP32_SAPLING_MASTER_PERSONALIZATION: &'static [u8; 16] = b"ZcashIP32Sapling";

// Sapling key components

/// PRF^expand(sk, t) := BLAKE2b-512("Zcash_ExpandSeed", sk || t)
fn prf_expand(sk: &[u8], t: &[u8]) -> Blake2bResult {
    let mut h = Blake2b::with_params(64, &[], &[], PRF_EXPAND_PERSONALIZATION);
    h.update(sk);
    h.update(t);
    h.finalize()
}

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

impl<E: JubjubEngine> ExpandedSpendingKey<E> {
    fn from_spending_key(sk: &[u8]) -> Self {
        let ask = E::Fs::to_uniform(prf_expand(sk, &[0x00]).as_bytes());
        let nsk = E::Fs::to_uniform(prf_expand(sk, &[0x01]).as_bytes());
        let mut ovk = OutgoingViewingKey([0u8; 32]);
        ovk.0
            .copy_from_slice(&prf_expand(sk, &[0x02]).as_bytes()[..32]);
        ExpandedSpendingKey { ask, nsk, ovk }
    }
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

impl FVKTag {
    fn master() -> Self {
        FVKTag([0u8; 4])
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

    fn master() -> Self {
        ChildIndex::from_index(0)
    }
}

/// A chain code
#[derive(Clone, Copy)]
struct ChainCode([u8; 32]);

/// A key used to derive diversifiers for a particular child key
#[derive(Clone, Copy)]
struct DiversifierKey([u8; 32]);

impl DiversifierKey {
    fn master(sk_m: &[u8]) -> Self {
        let mut dk_m = [0u8; 32];
        dk_m.copy_from_slice(&prf_expand(sk_m, &[0x10]).as_bytes()[..32]);
        DiversifierKey(dk_m)
    }
}

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

impl ExtendedSpendingKey {
    pub fn master(seed: &[u8]) -> Self {
        let mut h = Blake2b::with_params(64, &[], &[], ZIP32_SAPLING_MASTER_PERSONALIZATION);
        h.update(seed);
        let i = h.finalize();

        let sk_m = &i.as_bytes()[..32];
        let mut c_m = [0u8; 32];
        c_m.copy_from_slice(&i.as_bytes()[32..]);

        ExtendedSpendingKey {
            depth: 0,
            parent_fvk_tag: FVKTag::master(),
            child_index: ChildIndex::master(),
            chain_code: ChainCode(c_m),
            xsk: ExpandedSpendingKey::from_spending_key(sk_m),
            dk: DiversifierKey::master(sk_m),
        }
    }
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
