//! Helper functions defined in the Zcash Protocol Specification.

use blake2s_simd::Params as Blake2sParams;
use group::{ff::PrimeField, Curve, GroupEncoding};

use super::{
    group_hash::group_hash,
    pedersen_hash::{pedersen_hash, Personalization},
};
use crate::constants::{
    CRH_IVK_PERSONALIZATION, KEY_DIVERSIFICATION_PERSONALIZATION,
    NOTE_COMMITMENT_RANDOMNESS_GENERATOR, NULLIFIER_POSITION_GENERATOR, PRF_NF_PERSONALIZATION,
};

/// $CRH^\mathsf{ivk}(ak, nk)$
///
/// Defined in [Zcash Protocol Spec § 5.4.1.5: CRH^ivk Hash Function][concretecrhivk].
///
/// [concretecrhivk]: https://zips.z.cash/protocol/protocol.pdf#concretecrhivk
pub(crate) fn crh_ivk(ak: [u8; 32], nk: [u8; 32]) -> jubjub::Scalar {
    let mut h: [u8; 32] = Blake2sParams::new()
        .hash_length(32)
        .personal(CRH_IVK_PERSONALIZATION)
        .to_state()
        .update(&ak)
        .update(&nk)
        .finalize()
        .as_bytes()
        .try_into()
        .expect("output length is correct");

    // Drop the most significant five bits, so it can be interpreted as a scalar.
    h[31] &= 0b0000_0111;

    jubjub::Fr::from_repr(h).unwrap()
}

/// Defined in [Zcash Protocol Spec § 5.4.1.6: DiversifyHash^Sapling and DiversifyHash^Orchard Hash Functions][concretediversifyhash].
///
/// [concretediversifyhash]: https://zips.z.cash/protocol/protocol.pdf#concretediversifyhash
pub(crate) fn diversify_hash(d: &[u8; 11]) -> Option<jubjub::SubgroupPoint> {
    group_hash(d, KEY_DIVERSIFICATION_PERSONALIZATION)
}

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

/// $WindowedPedersenCommit_r(s)$
///
/// Defined in [Zcash Protocol Spec § 5.4.8.2: Windowed Pedersen commitments][concretewindowedcommit].
///
/// [concretewindowedcommit]: https://zips.z.cash/protocol/protocol.pdf#concretewindowedcommit
pub(crate) fn windowed_pedersen_commit<I>(
    personalization: Personalization,
    s: I,
    r: jubjub::Scalar,
) -> jubjub::SubgroupPoint
where
    I: IntoIterator<Item = bool>,
{
    pedersen_hash(personalization, s) + (NOTE_COMMITMENT_RANDOMNESS_GENERATOR * r)
}

/// Coordinate extractor for Jubjub.
///
/// Defined in [Zcash Protocol Spec § 5.4.9.4: Coordinate Extractor for Jubjub][concreteextractorjubjub].
///
/// [concreteextractorjubjub]: https://zips.z.cash/protocol/protocol.pdf#concreteextractorjubjub
pub(crate) fn extract_p(point: &jubjub::SubgroupPoint) -> bls12_381::Scalar {
    // The commitment is in the prime order subgroup, so mapping the
    // commitment to the u-coordinate is an injective encoding.
    Into::<&jubjub::ExtendedPoint>::into(point)
        .to_affine()
        .get_u()
}
