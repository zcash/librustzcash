use blake2b_simd::Params;
use ff::Field;
use rand_core::{CryptoRng, RngCore};

use crate::consensus::{self, BlockHeight, NetworkUpgrade};

use super::Rseed;

pub fn hash_to_scalar(persona: &[u8], a: &[u8], b: &[u8]) -> jubjub::Fr {
    let mut hasher = Params::new().hash_length(64).personal(persona).to_state();
    hasher.update(a);
    hasher.update(b);
    let ret = hasher.finalize();
    jubjub::Fr::from_bytes_wide(ret.as_array())
}

pub fn generate_random_rseed<P: consensus::Parameters, R: RngCore + CryptoRng>(
    params: &P,
    height: BlockHeight,
    rng: &mut R,
) -> Rseed {
    generate_random_rseed_internal(params, height, rng)
}

pub(crate) fn generate_random_rseed_internal<P: consensus::Parameters, R: RngCore>(
    params: &P,
    height: BlockHeight,
    rng: &mut R,
) -> Rseed {
    if params.is_nu_active(NetworkUpgrade::Canopy, height) {
        let mut buffer = [0u8; 32];
        rng.fill_bytes(&mut buffer);
        Rseed::AfterZip212(buffer)
    } else {
        Rseed::BeforeZip212(jubjub::Fr::random(rng))
    }
}
