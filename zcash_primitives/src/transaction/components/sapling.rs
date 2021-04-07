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

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Unauthorized;

impl Authorization for Unauthorized {
    type Proof = GrothProofBytes;
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
    pub shielded_outputs: Vec<OutputDescription<A>>,
    pub value_balance: Amount,
    pub authorization: A,
}

impl Bundle<Unauthorized> {
    pub fn apply_signatures(
        self,
        spend_auth_sigs: Vec<Signature>,
        binding_sig: Signature,
    ) -> Bundle<Authorized> {
        assert!(self.shielded_spends.len() == spend_auth_sigs.len());
        Bundle {
            shielded_spends: self
                .shielded_spends
                .iter()
                .zip(spend_auth_sigs.iter())
                .map(|(spend, sig)| spend.apply_signature(*sig))
                .collect(),
            shielded_outputs: self
                .shielded_outputs
                .into_iter()
                .map(|o| o.into_authorized())
                .collect(), //TODO, is there a zero-cost way to do this?
            value_balance: self.value_balance,
            authorization: Authorized { binding_sig },
        }
    }
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

impl SpendDescription<Unauthorized> {
    pub fn apply_signature(&self, spend_auth_sig: Signature) -> SpendDescription<Authorized> {
        SpendDescription {
            cv: self.cv,
            anchor: self.anchor,
            nullifier: self.nullifier,
            rk: self.rk.clone(),
            zkproof: self.zkproof,
            spend_auth_sig,
        }
    }
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
            "invalid ".to_owned() + field,
        ))
    } else {
        Ok(point.unwrap())
    }
}

/// Consensus rules (§7.3) & (§7.4):
/// - Canonical encoding is enforced here
pub fn read_scalar<R: Read>(mut reader: R, field: &str) -> io::Result<bls12_381::Scalar> {
    let mut f = [0u8; 32];
    reader.read_exact(&mut f)?;
    bls12_381::Scalar::from_repr(f).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            field.to_owned() + " not in field",
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
        let anchor = read_scalar(&mut reader, "anchor")?;
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

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.anchor.to_repr().as_ref())?;
        writer.write_all(&self.nullifier.0)?;
        self.rk.write(&mut writer)?;
        writer.write_all(&self.zkproof)?;
        self.spend_auth_sig.write(&mut writer)
    }
}

#[derive(Clone)]
pub struct OutputDescription<A: Authorization> {
    pub cv: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub ephemeral_key: jubjub::ExtendedPoint,
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
    pub zkproof: A::Proof,
}

impl<P: consensus::Parameters, A: Authorization> ShieldedOutput<SaplingDomain<P>>
    for OutputDescription<A>
{
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

impl<A: Authorization> std::fmt::Debug for OutputDescription<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "OutputDescription(cv = {:?}, cmu = {:?}, ephemeral_key = {:?})",
            self.cv, self.cmu, self.ephemeral_key
        )
    }
}

impl OutputDescription<Authorized> {
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        // Consensus rules (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        //   (located in zcash_proofs::sapling::verifier).
        let cv = {
            let mut bytes = [0u8; 32];
            reader.read_exact(&mut bytes)?;
            let cv = jubjub::ExtendedPoint::from_bytes(&bytes);
            if cv.is_none().into() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid cv"));
            }
            cv.unwrap()
        };

        // Consensus rule (§7.4): Canonical encoding is enforced here
        let cmu = {
            let mut f = [0u8; 32];
            reader.read_exact(&mut f)?;
            bls12_381::Scalar::from_repr(f)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cmu not in field"))?
        };

        // Consensus rules (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        let ephemeral_key = {
            let mut bytes = [0u8; 32];
            reader.read_exact(&mut bytes)?;
            let ephemeral_key = jubjub::ExtendedPoint::from_bytes(&bytes);
            if ephemeral_key.is_none().into() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid ephemeral_key",
                ));
            }
            ephemeral_key.unwrap()
        };

        let mut enc_ciphertext = [0u8; 580];
        let mut out_ciphertext = [0u8; 80];
        reader.read_exact(&mut enc_ciphertext)?;
        reader.read_exact(&mut out_ciphertext)?;

        // Consensus rules (§4.5):
        // - Canonical encoding is enforced by the API of SaplingVerificationContext::check_output()
        //   due to the need to parse this into a bellman::groth16::Proof.
        // - Proof validity is enforced in SaplingVerificationContext::check_output()
        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        reader.read_exact(&mut zkproof)?;

        Ok(OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        })
    }
}

impl<A: Authorization<Proof = GrothProofBytes>> OutputDescription<A> {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.cmu.to_repr().as_ref())?;
        writer.write_all(&self.ephemeral_key.to_bytes())?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)?;
        writer.write_all(&self.zkproof)
    }
}

impl OutputDescription<Unauthorized> {
    pub fn into_authorized(self) -> OutputDescription<Authorized> {
        OutputDescription {
            cv: self.cv,
            cmu: self.cmu,
            ephemeral_key: self.ephemeral_key,
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
            zkproof: self.zkproof,
        }
    }
}

pub struct CompactOutputDescription {
    pub epk: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub enc_ciphertext: Vec<u8>,
}

impl<A: Authorization> From<OutputDescription<A>> for CompactOutputDescription {
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
