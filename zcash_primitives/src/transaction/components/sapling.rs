use core::fmt::Debug;
use ff::PrimeField;
use group::GroupEncoding;
use std::io::{self, Read, Write};

use zcash_note_encryption::{ShieldedOutput, COMPACT_NOTE_SIZE};

use crate::{
    consensus,
    sapling::{
        note_encryption::SaplingDomain,
        redjubjub::{self, PublicKey, Signature},
        Nullifier,
    },
};

use super::{amount::Amount, GROTH_PROOF_SIZE};

pub type GrothProofBytes = [u8; GROTH_PROOF_SIZE];

pub mod builder;

pub trait Authorization: Debug {
    type Proof: Clone + Debug;
    type AuthSig: Clone + Debug;
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Unproven;

impl Authorization for Unproven {
    type Proof = ();
    type AuthSig = ();
}

#[derive(Debug, Copy, Clone)]
pub struct Authorized {
    pub binding_sig: redjubjub::Signature,
}

impl Authorization for Authorized {
    type Proof = GrothProofBytes;
    type AuthSig = redjubjub::Signature;
}

#[derive(Debug, Clone)]
pub struct Bundle<A: Authorization> {
    pub shielded_spends: Vec<SpendDescription<A>>,
    pub shielded_outputs: Vec<OutputDescription<A::Proof>>,
    pub value_balance: Amount,
    pub authorization: A,
}

#[derive(Clone)]
pub struct SpendDescription<A: Authorization> {
    pub cv: jubjub::ExtendedPoint,
    pub anchor: bls12_381::Scalar,
    pub nullifier: Nullifier,
    pub rk: PublicKey,
    pub zkproof: A::Proof,
    pub spend_auth_sig: A::AuthSig,
}

impl<A: Authorization> std::fmt::Debug for SpendDescription<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "SpendDescription(cv = {:?}, anchor = {:?}, nullifier = {:?}, rk = {:?}, spend_auth_sig = {:?})",
            self.cv, self.anchor, self.nullifier, self.rk, self.spend_auth_sig
        )
    }
}

/// Consensus rules (§4.4) & (§4.5):
/// - Canonical encoding is enforced here.
/// - "Not small order" is enforced in SaplingVerificationContext::(check_spend()/check_output())
///   (located in zcash_proofs::sapling::verifier).
pub fn read_point<R: Read>(mut reader: R, field: &str) -> io::Result<jubjub::ExtendedPoint> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let point = jubjub::ExtendedPoint::from_bytes(&bytes);

    if point.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {}", field),
        ))
    } else {
        Ok(point.unwrap())
    }
}

/// Consensus rules (§7.3) & (§7.4):
/// - Canonical encoding is enforced here
pub fn read_base<R: Read>(mut reader: R, field: &str) -> io::Result<bls12_381::Scalar> {
    let mut f = [0u8; 32];
    reader.read_exact(&mut f)?;
    bls12_381::Scalar::from_repr(f).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} not in field", field),
        )
    })
}

/// Consensus rules (§4.4) & (§4.5):
/// - Canonical encoding is enforced by the API of SaplingVerificationContext::check_spend()
///   and SaplingVerificationContext::check_output() due to the need to parse this into a
///   bellman::groth16::Proof.
/// - Proof validity is enforced in SaplingVerificationContext::check_spend()
///   and SaplingVerificationContext::check_output()
pub fn read_zkproof<R: Read>(mut reader: R) -> io::Result<GrothProofBytes> {
    let mut zkproof = [0u8; GROTH_PROOF_SIZE];
    reader.read_exact(&mut zkproof)?;
    Ok(zkproof)
}

impl SpendDescription<Authorized> {
    pub fn read_nullifier<R: Read>(mut reader: R) -> io::Result<Nullifier> {
        let mut nullifier = Nullifier([0u8; 32]);
        reader.read_exact(&mut nullifier.0)?;
        Ok(nullifier)
    }

    /// Consensus rules (§4.4):
    /// - Canonical encoding is enforced here.
    /// - "Not small order" is enforced in SaplingVerificationContext::check_spend()
    pub fn read_rk<R: Read>(mut reader: R) -> io::Result<PublicKey> {
        PublicKey::read(&mut reader)
    }

    /// Consensus rules (§4.4):
    /// - Canonical encoding is enforced here.
    /// - Signature validity is enforced in SaplingVerificationContext::check_spend()
    pub fn read_spend_auth_sig<R: Read>(mut reader: R) -> io::Result<Signature> {
        Signature::read(&mut reader)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        // Consensus rules (§4.4) & (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::(check_spend()/check_output())
        //   (located in zcash_proofs::sapling::verifier).
        let cv = read_point(&mut reader, "cv")?;
        // Consensus rules (§7.3) & (§7.4):
        // - Canonical encoding is enforced here
        let anchor = read_base(&mut reader, "anchor")?;
        let nullifier = Self::read_nullifier(&mut reader)?;
        let rk = Self::read_rk(&mut reader)?;
        let zkproof = read_zkproof(&mut reader)?;
        let spend_auth_sig = Self::read_spend_auth_sig(&mut reader)?;

        Ok(SpendDescription {
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        })
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.anchor.to_repr().as_ref())?;
        writer.write_all(&self.nullifier.0)?;
        self.rk.write(&mut writer)?;
        writer.write_all(&self.zkproof)?;
        self.spend_auth_sig.write(&mut writer)
    }

    pub fn write_v5_without_witness_data<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(&self.nullifier.0)?;
        self.rk.write(&mut writer)
    }
}

#[derive(Clone)]
pub struct SpendDescriptionV5 {
    pub cv: jubjub::ExtendedPoint,
    pub nullifier: Nullifier,
    pub rk: PublicKey,
}

impl SpendDescriptionV5 {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let cv = read_point(&mut reader, "cv")?;
        let nullifier = SpendDescription::read_nullifier(&mut reader)?;
        let rk = SpendDescription::read_rk(&mut reader)?;

        Ok(SpendDescriptionV5 { cv, nullifier, rk })
    }

    pub fn into_spend_description(
        self,
        anchor: bls12_381::Scalar,
        zkproof: GrothProofBytes,
        spend_auth_sig: Signature,
    ) -> SpendDescription<Authorized> {
        SpendDescription {
            cv: self.cv,
            anchor,
            nullifier: self.nullifier,
            rk: self.rk,
            zkproof,
            spend_auth_sig,
        }
    }
}

#[derive(Clone)]
pub struct OutputDescription<Proof> {
    pub cv: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub ephemeral_key: jubjub::ExtendedPoint,
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
    pub zkproof: Proof,
}

impl<P: consensus::Parameters, A> ShieldedOutput<SaplingDomain<P>> for OutputDescription<A> {
    fn epk(&self) -> &jubjub::ExtendedPoint {
        &self.ephemeral_key
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu.to_repr()
    }

    fn enc_ciphertext(&self) -> &[u8] {
        &self.enc_ciphertext
    }
}

impl<A> std::fmt::Debug for OutputDescription<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "OutputDescription(cv = {:?}, cmu = {:?}, ephemeral_key = {:?})",
            self.cv, self.cmu, self.ephemeral_key
        )
    }
}

impl OutputDescription<GrothProofBytes> {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        // Consensus rules (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        //   (located in zcash_proofs::sapling::verifier).
        let cv = read_point(&mut reader, "cv")?;

        // Consensus rule (§7.4): Canonical encoding is enforced here
        let cmu = read_base(&mut reader, "cmu")?;

        // Consensus rules (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        let ephemeral_key = read_point(&mut reader, "ephemeral key")?;

        let mut enc_ciphertext = [0u8; 580];
        let mut out_ciphertext = [0u8; 80];
        reader.read_exact(&mut enc_ciphertext)?;
        reader.read_exact(&mut out_ciphertext)?;

        let zkproof = read_zkproof(&mut reader)?;

        Ok(OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        })
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.cmu.to_repr().as_ref())?;
        writer.write_all(&self.ephemeral_key.to_bytes())?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)?;
        writer.write_all(&self.zkproof)
    }

    pub fn write_v5_without_proof<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.cmu.to_repr().as_ref())?;
        writer.write_all(&self.ephemeral_key.to_bytes())?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)
    }
}

#[derive(Clone)]
pub struct OutputDescriptionV5 {
    pub cv: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub ephemeral_key: jubjub::ExtendedPoint,
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
}

impl OutputDescriptionV5 {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let cv = read_point(&mut reader, "cv")?;
        let cmu = read_base(&mut reader, "cmu")?;
        let ephemeral_key = read_point(&mut reader, "ephemeral key")?;

        let mut enc_ciphertext = [0u8; 580];
        let mut out_ciphertext = [0u8; 80];
        reader.read_exact(&mut enc_ciphertext)?;
        reader.read_exact(&mut out_ciphertext)?;

        Ok(OutputDescriptionV5 {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
        })
    }

    pub fn into_output_description(
        self,
        zkproof: GrothProofBytes,
    ) -> OutputDescription<GrothProofBytes> {
        OutputDescription {
            cv: self.cv,
            cmu: self.cmu,
            ephemeral_key: self.ephemeral_key,
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
            zkproof,
        }
    }
}

pub struct CompactOutputDescription {
    pub epk: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub enc_ciphertext: Vec<u8>,
}

impl<A> From<OutputDescription<A>> for CompactOutputDescription {
    fn from(out: OutputDescription<A>) -> CompactOutputDescription {
        CompactOutputDescription {
            epk: out.ephemeral_key,
            cmu: out.cmu,
            enc_ciphertext: out.enc_ciphertext[..COMPACT_NOTE_SIZE].to_vec(),
        }
    }
}

impl<P: consensus::Parameters> ShieldedOutput<SaplingDomain<P>> for CompactOutputDescription {
    fn epk(&self) -> &jubjub::ExtendedPoint {
        &self.epk
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu.to_repr()
    }

    fn enc_ciphertext(&self) -> &[u8] {
        &self.enc_ciphertext
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use ff::Field;
    use group::GroupEncoding;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};
    use std::convert::TryFrom;

    use crate::{
        constants::{SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR},
        sapling::{
            redjubjub::{PrivateKey, PublicKey},
            Nullifier,
        },
        transaction::{
            components::{amount::testing::arb_amount, GROTH_PROOF_SIZE},
            TxVersion,
        },
    };

    use super::{Authorized, Bundle, GrothProofBytes, OutputDescription, SpendDescription};

    prop_compose! {
        /// produce a spend description with invalid data (useful only for serialization
        /// roundtrip testing).
        fn arb_spend_description()(
            cv in prop::array::uniform32(any::<u8>())
                .prop_map(|v| jubjub::ExtendedPoint::from_bytes(&v))
                .prop_filter("Must generate valid extended points.", |v| v.is_some().unwrap_u8() == 1)
                .prop_map(|v| v.unwrap()),
            anchor in vec(any::<u8>(), 64)
                .prop_map(|v| <[u8;64]>::try_from(v.as_slice()).unwrap())
                .prop_map(|v| bls12_381::Scalar::from_bytes_wide(&v)),
            nullifier in prop::array::uniform32(any::<u8>())
                .prop_map(|v| Nullifier::from_slice(&v).unwrap()),
            zkproof in vec(any::<u8>(), GROTH_PROOF_SIZE)
                .prop_map(|v| <[u8;GROTH_PROOF_SIZE]>::try_from(v.as_slice()).unwrap()),
            rng_seed in prop::array::uniform32(prop::num::u8::ANY),
            fake_sighash_bytes in prop::array::uniform32(prop::num::u8::ANY),
        ) -> SpendDescription<Authorized> {
            let mut rng = StdRng::from_seed(rng_seed);
            let sk1 = PrivateKey(jubjub::Fr::random(&mut rng));
            let rk = PublicKey::from_private(&sk1, SPENDING_KEY_GENERATOR);
            SpendDescription {
                cv,
                anchor,
                nullifier,
                rk,
                zkproof,
                spend_auth_sig: sk1.sign(&fake_sighash_bytes, &mut rng, SPENDING_KEY_GENERATOR),
            }
        }
    }

    prop_compose! {
        /// produce an output description with invalid data (useful only for serialization
        /// roundtrip testing).
        pub fn arb_output_description()(
            cv in prop::array::uniform32(any::<u8>())
                .prop_map(|v| jubjub::ExtendedPoint::from_bytes(&v))
                .prop_filter("Must generate valid extended points.", |v| v.is_some().unwrap_u8() == 1)
                .prop_map(|v| v.unwrap()),
            cmu in vec(any::<u8>(), 64)
                .prop_map(|v| <[u8;64]>::try_from(v.as_slice()).unwrap())
                .prop_map(|v| bls12_381::Scalar::from_bytes_wide(&v)),
            enc_ciphertext in vec(any::<u8>(), 580)
                .prop_map(|v| <[u8;580]>::try_from(v.as_slice()).unwrap()),
            ephemeral_key in prop::array::uniform32(any::<u8>())
                .prop_map(|v| jubjub::ExtendedPoint::from_bytes(&v))
                .prop_filter("Must generate valid extended points.", |v| v.is_some().unwrap_u8() == 1)
                .prop_map(|v| v.unwrap()),
            out_ciphertext in vec(any::<u8>(), 80)
                .prop_map(|v| <[u8;80]>::try_from(v.as_slice()).unwrap()),
            zkproof in vec(any::<u8>(), GROTH_PROOF_SIZE)
                .prop_map(|v| <[u8;GROTH_PROOF_SIZE]>::try_from(v.as_slice()).unwrap()),
        ) -> OutputDescription<GrothProofBytes> {
            OutputDescription {
                cv,
                cmu,
                ephemeral_key,
                enc_ciphertext,
                out_ciphertext,
                zkproof,
            }
        }
    }

    prop_compose! {
        pub fn arb_bundle()(
            shielded_spends in vec(arb_spend_description(), 0..30),
            shielded_outputs in vec(arb_output_description(), 0..30),
            value_balance in arb_amount(),
            rng_seed in prop::array::uniform32(prop::num::u8::ANY),
            fake_bvk_bytes in prop::array::uniform32(prop::num::u8::ANY),
        ) -> Option<Bundle<Authorized>> {
            if shielded_spends.is_empty() && shielded_outputs.is_empty() {
                None
            } else {
                let mut rng = StdRng::from_seed(rng_seed);
                let bsk = PrivateKey(jubjub::Fr::random(&mut rng));

                Some(
                    Bundle {
                        shielded_spends,
                        shielded_outputs,
                        value_balance,
                        authorization: Authorized { binding_sig: bsk.sign(&fake_bvk_bytes, &mut rng, VALUE_COMMITMENT_RANDOMNESS_GENERATOR) },
                    }
                )
            }
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<Bundle<Authorized>>> {
        if v.has_sapling() {
            Strategy::boxed(arb_bundle())
        } else {
            Strategy::boxed(Just(None))
        }
    }
}
