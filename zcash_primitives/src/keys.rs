use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};

pub use crate::sapling::keys::OutgoingViewingKey;

pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

/// PRF^expand(sk, t) := BLAKE2b-512("Zcash_ExpandSeed", sk || t)
pub fn prf_expand(sk: &[u8], t: &[u8]) -> Blake2bHash {
    prf_expand_vec(sk, &[t])
}

pub fn prf_expand_vec(sk: &[u8], ts: &[&[u8]]) -> Blake2bHash {
    let mut h = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    h.update(sk);
    for t in ts {
        h.update(t);
    }
    h.finalize()
}
