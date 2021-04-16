use ff::PrimeField;
use group::GroupEncoding;

use std::io::{self, Read, Write};

use zcash_note_encryption::ShieldedOutput;

use crate::{
    consensus,
    sapling::{
        note_encryption::SaplingDomain,
        redjubjub::{PublicKey, Signature},
        Nullifier,
    },
};

use zcash_note_encryption::COMPACT_NOTE_SIZE;

use super::GROTH_PROOF_SIZE;

#[derive(Clone)]
pub struct SpendDescription {
    pub cv: jubjub::ExtendedPoint,
    pub anchor: bls12_381::Scalar,
    pub nullifier: Nullifier,
    pub rk: PublicKey,
    pub zkproof: [u8; GROTH_PROOF_SIZE],
    pub spend_auth_sig: Option<Signature>,
}

impl std::fmt::Debug for SpendDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "SpendDescription(cv = {:?}, anchor = {:?}, nullifier = {:?}, rk = {:?}, spend_auth_sig = {:?})",
            self.cv, self.anchor, self.nullifier, self.rk, self.spend_auth_sig
        )
    }
}

impl SpendDescription {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        // Consensus rules (§4.4):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::check_spend()
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

        // Consensus rule (§7.3): Canonical encoding is enforced here
        let anchor = {
            let mut f = [0u8; 32];
            reader.read_exact(&mut f)?;
            bls12_381::Scalar::from_repr(f)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "anchor not in field"))?
        };

        let mut nullifier = Nullifier([0u8; 32]);
        reader.read_exact(&mut nullifier.0)?;

        // Consensus rules (§4.4):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::check_spend()
        let rk = PublicKey::read(&mut reader)?;

        // Consensus rules (§4.4):
        // - Canonical encoding is enforced by the API of SaplingVerificationContext::check_spend()
        //   due to the need to parse this into a bellman::groth16::Proof.
        // - Proof validity is enforced in SaplingVerificationContext::check_spend()
        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        reader.read_exact(&mut zkproof)?;

        // Consensus rules (§4.4):
        // - Canonical encoding is enforced here.
        // - Signature validity is enforced in SaplingVerificationContext::check_spend()
        let spend_auth_sig = Some(Signature::read(&mut reader)?);

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
        match self.spend_auth_sig {
            Some(sig) => sig.write(&mut writer),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Missing spend auth signature",
            )),
        }
    }
}

#[derive(Clone)]
pub struct OutputDescription {
    pub cv: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub ephemeral_key: jubjub::ExtendedPoint,
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
    pub zkproof: [u8; GROTH_PROOF_SIZE],
}

impl<P: consensus::Parameters> ShieldedOutput<SaplingDomain<P>> for OutputDescription {
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

impl std::fmt::Debug for OutputDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "OutputDescription(cv = {:?}, cmu = {:?}, ephemeral_key = {:?})",
            self.cv, self.cmu, self.ephemeral_key
        )
    }
}

impl OutputDescription {
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

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.cmu.to_repr().as_ref())?;
        writer.write_all(&self.ephemeral_key.to_bytes())?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)?;
        writer.write_all(&self.zkproof)
    }
}

pub struct CompactOutputDescription {
    pub epk: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub enc_ciphertext: Vec<u8>,
}

impl From<OutputDescription> for CompactOutputDescription {
    fn from(out: OutputDescription) -> CompactOutputDescription {
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
