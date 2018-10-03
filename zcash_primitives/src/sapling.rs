use ff::{BitIterator, PrimeField};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use rand::OsRng;
use sapling_crypto::{
    jubjub::{fs::Fs, FixedGenerators, JubjubBls12},
    pedersen_hash::{pedersen_hash, Personalization},
    redjubjub::{PrivateKey, PublicKey, Signature},
};

use JUBJUB;

/// Compute a parent node in the Sapling commitment tree given its two children.
pub fn merkle_hash(depth: usize, lhs: &FrRepr, rhs: &FrRepr) -> FrRepr {
    let lhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().rev().zip(BitIterator::new(lhs)) {
            *a = b;
        }
        tmp
    };

    let rhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().rev().zip(BitIterator::new(rhs)) {
            *a = b;
        }
        tmp
    };

    pedersen_hash::<Bls12, _>(
        Personalization::MerkleTree(depth),
        lhs.iter()
            .map(|&x| x)
            .take(Fr::NUM_BITS as usize)
            .chain(rhs.iter().map(|&x| x).take(Fr::NUM_BITS as usize)),
        &JUBJUB,
    )
    .into_xy()
    .0
    .into_repr()
}

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
