use blake2b_simd::Params;

use crate::{
    consensus,
    consensus::NetworkUpgrade,
    jubjub::{fs::Fs, JubjubEngine, ToUniform},
    primitives::Rseed,
};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

pub fn hash_to_scalar<E: JubjubEngine>(persona: &[u8], a: &[u8], b: &[u8]) -> E::Fs {
    let mut hasher = Params::new().hash_length(64).personal(persona).to_state();
    hasher.update(a);
    hasher.update(b);
    let ret = hasher.finalize();
    E::Fs::to_uniform(ret.as_ref())
}

pub fn generate_random_rseed<P: consensus::Parameters, R: RngCore + CryptoRng>(
    nu: NetworkUpgrade,
    height: u32,
    rng: &mut R,
) -> Rseed<Fs> {
    if P::is_nu_active(nu, height) {
        let mut buffer = [0u8; 32];
        &rng.fill_bytes(&mut buffer);
        Rseed::AfterZip212(buffer)
    } else {
        Rseed::BeforeZip212(Fs::random(rng))
    }
}
