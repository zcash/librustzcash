//! Helper functions defined in the Zcash Protocol Specification.

use blake2s_simd::Params as Blake2sParams;
use group::GroupEncoding;

use crate::constants::{NULLIFIER_POSITION_GENERATOR, PRF_NF_PERSONALIZATION};

/// $MixingPedersenHash$.
///
/// Defined in [Zcash Protocol Spec § 5.4.1.8: Mixing Pedersen Hash Function][concretemixinghash].
///
/// [concretemixinghash]: https://zips.z.cash/protocol/protocol.pdf#concretemixinghash
pub(crate) fn mixing_pedersen_hash(
    cm: jubjub::SubgroupPoint,
    position: u64,
) -> jubjub::SubgroupPoint {
    cm + (NULLIFIER_POSITION_GENERATOR * jubjub::Fr::from(position))
}

/// $PRF^\mathsf{nfSapling}_{nk}(\rho)$
///
/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/protocol.pdf#concreteprfs
pub(crate) fn prf_nf(nk: &jubjub::SubgroupPoint, rho: &jubjub::SubgroupPoint) -> [u8; 32] {
    Blake2sParams::new()
        .hash_length(32)
        .personal(PRF_NF_PERSONALIZATION)
        .to_state()
        .update(&nk.to_bytes())
        .update(&rho.to_bytes())
        .finalize()
        .as_bytes()
        .try_into()
        .expect("output length is correct")
}
