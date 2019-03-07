use pairing::bls12_381::Bls12;
use rand::OsRng;
use sapling_crypto::{
    jubjub::{fs::Fs, FixedGenerators, JubjubBls12},
    redjubjub::{PrivateKey, PublicKey, Signature},
};

/// Create the spendAuthSig for a Sapling SpendDescription.
pub fn spend_sig(
    ask: PrivateKey<Bls12>,
    ar: Fs,
    sighash: &[u8; 32],
    params: &JubjubBls12,
) -> Signature {
    // Initialize secure RNG
    let mut rng = OsRng::new().expect("should be able to construct RNG");

    // We compute `rsk`...
    let rsk = ask.randomize(ar);

    // We compute `rk` from there (needed for key prefixing)
    let rk = PublicKey::from_private(&rsk, FixedGenerators::SpendingKeyGenerator, params);

    // Compute the signature's message for rk/spend_auth_sig
    let mut data_to_be_signed = [0u8; 64];
    rk.0.write(&mut data_to_be_signed[0..32])
        .expect("message buffer should be 32 bytes");
    (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash[..]);

    // Do the signing
    rsk.sign(
        &data_to_be_signed,
        &mut rng,
        FixedGenerators::SpendingKeyGenerator,
        params,
    )
}
