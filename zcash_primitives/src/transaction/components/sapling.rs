use ff::PrimeField;

use std::io::{self, Read, Write};

use zcash_note_encryption::EphemeralKeyBytes;

use crate::sapling::{
    bundle::{
        Authorized, GrothProofBytes, OutputDescription, OutputDescriptionV5, SpendDescription,
        SpendDescriptionV5,
    },
    note::ExtractedNoteCommitment,
    redjubjub::{PublicKey, Signature},
    value::ValueCommitment,
    Nullifier,
};

use super::GROTH_PROOF_SIZE;

pub mod fees;

/// Consensus rules (§4.4) & (§4.5):
/// - Canonical encoding is enforced here.
/// - "Not small order" is enforced here.
fn read_value_commitment<R: Read>(mut reader: R) -> io::Result<ValueCommitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let cv = ValueCommitment::from_bytes_not_small_order(&bytes);

    if cv.is_none().into() {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid cv"))
    } else {
        Ok(cv.unwrap())
    }
}

/// Consensus rules (§7.3) & (§7.4):
/// - Canonical encoding is enforced here
fn read_cmu<R: Read>(mut reader: R) -> io::Result<ExtractedNoteCommitment> {
    let mut f = [0u8; 32];
    reader.read_exact(&mut f)?;
    Option::from(ExtractedNoteCommitment::from_bytes(&f))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cmu not in field"))
}

/// Consensus rules (§7.3) & (§7.4):
/// - Canonical encoding is enforced here
pub fn read_base<R: Read>(mut reader: R, field: &str) -> io::Result<bls12_381::Scalar> {
    let mut f = [0u8; 32];
    reader.read_exact(&mut f)?;
    Option::from(bls12_381::Scalar::from_repr(f)).ok_or_else(|| {
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
        let cv = read_value_commitment(&mut reader)?;
        // Consensus rules (§7.3) & (§7.4):
        // - Canonical encoding is enforced here
        let anchor = read_base(&mut reader, "anchor")?;
        let nullifier = Self::read_nullifier(&mut reader)?;
        let rk = Self::read_rk(&mut reader)?;
        let zkproof = read_zkproof(&mut reader)?;
        let spend_auth_sig = Self::read_spend_auth_sig(&mut reader)?;

        Ok(SpendDescription::from_parts(
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        ))
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv().to_bytes())?;
        writer.write_all(self.anchor().to_repr().as_ref())?;
        writer.write_all(&self.nullifier().0)?;
        self.rk().write(&mut writer)?;
        writer.write_all(self.zkproof())?;
        self.spend_auth_sig().write(&mut writer)
    }

    pub fn write_v5_without_witness_data<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv().to_bytes())?;
        writer.write_all(&self.nullifier().0)?;
        self.rk().write(&mut writer)
    }
}

impl SpendDescriptionV5 {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let cv = read_value_commitment(&mut reader)?;
        let nullifier = SpendDescription::read_nullifier(&mut reader)?;
        let rk = SpendDescription::read_rk(&mut reader)?;

        Ok(SpendDescriptionV5::from_parts(cv, nullifier, rk))
    }
}

impl OutputDescription<GrothProofBytes> {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        // Consensus rules (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        //   (located in zcash_proofs::sapling::verifier).
        let cv = read_value_commitment(&mut reader)?;

        // Consensus rule (§7.4): Canonical encoding is enforced here
        let cmu = read_cmu(&mut reader)?;

        // Consensus rules (§4.5):
        // - Canonical encoding is enforced in librustzcash_sapling_check_output by zcashd
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        let mut ephemeral_key = EphemeralKeyBytes([0u8; 32]);
        reader.read_exact(&mut ephemeral_key.0)?;

        let mut enc_ciphertext = [0u8; 580];
        let mut out_ciphertext = [0u8; 80];
        reader.read_exact(&mut enc_ciphertext)?;
        reader.read_exact(&mut out_ciphertext)?;

        let zkproof = read_zkproof(&mut reader)?;

        Ok(OutputDescription::from_parts(
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        ))
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv().to_bytes())?;
        writer.write_all(self.cmu().to_bytes().as_ref())?;
        writer.write_all(self.ephemeral_key().as_ref())?;
        writer.write_all(self.enc_ciphertext())?;
        writer.write_all(self.out_ciphertext())?;
        writer.write_all(self.zkproof())
    }

    pub fn write_v5_without_proof<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv().to_bytes())?;
        writer.write_all(self.cmu().to_bytes().as_ref())?;
        writer.write_all(self.ephemeral_key().as_ref())?;
        writer.write_all(self.enc_ciphertext())?;
        writer.write_all(self.out_ciphertext())
    }
}

impl OutputDescriptionV5 {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let cv = read_value_commitment(&mut reader)?;
        let cmu = read_cmu(&mut reader)?;

        // Consensus rules (§4.5):
        // - Canonical encoding is enforced in librustzcash_sapling_check_output by zcashd
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        let mut ephemeral_key = EphemeralKeyBytes([0u8; 32]);
        reader.read_exact(&mut ephemeral_key.0)?;

        let mut enc_ciphertext = [0u8; 580];
        let mut out_ciphertext = [0u8; 80];
        reader.read_exact(&mut enc_ciphertext)?;
        reader.read_exact(&mut out_ciphertext)?;

        Ok(OutputDescriptionV5::from_parts(
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
        ))
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use crate::{
        sapling::bundle::{testing::arb_bundle, Authorized, Bundle},
        transaction::TxVersion,
    };

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
