//! Byte-level Sprout bundle representation.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::{CompactSize, Vector};

use crate::transaction::components::GROTH_PROOF_SIZE;

use super::{read_fixed, read_vector};

/// The number of JoinSplit inputs.
const ZC_NUM_JS_INPUTS: usize = 2;
/// The number of JoinSplit outputs.
const ZC_NUM_JS_OUTPUTS: usize = 2;
/// The size in bytes of a PHGR proof.
const PHGR_PROOF_SIZE: usize = 33 + 33 + 65 + 33 + 33 + 33 + 33 + 33;
/// The size in bytes of a JoinSplit ciphertext.
const CIPHERTEXT_SIZE: usize = 601;
/// The size in bytes of a JoinSplit anchor.
const ANCHOR_SIZE: usize = 32;
/// The size in bytes of a JoinSplit nullifier.
const NULLIFIER_SIZE: usize = 32;
/// The size in bytes of a JoinSplit note commitment.
const COMMITMENT_SIZE: usize = 32;
/// The size in bytes of a JoinSplit ephemeral key.
const EPHEMERAL_KEY_SIZE: usize = 32;
/// The size in bytes of a JoinSplit random seed.
const RANDOM_SEED_SIZE: usize = 32;
/// The size in bytes of a JoinSplit MAC.
const MAC_SIZE: usize = 32;
/// The size in bytes of a JoinSplit public key.
const JOINSPLIT_PUBKEY_SIZE: usize = 32;
/// The size in bytes of a JoinSplit signature.
const JOINSPLIT_SIG_SIZE: usize = 64;

/// A Sprout JoinSplit proof in its wire representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SproutProofBytes {
    /// A Groth16 proof, used from version 4 onward.
    Groth([u8; GROTH_PROOF_SIZE]),
    /// A PHGR proof, used before version 4.
    Phgr([u8; PHGR_PROOF_SIZE]),
}

impl SproutProofBytes {
    /// Returns the proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Groth(bytes) => bytes,
            Self::Phgr(bytes) => bytes,
        }
    }

    /// Reads a proof of the given kind.
    fn read<R: Read>(mut reader: R, use_groth: bool) -> io::Result<Self> {
        if use_groth {
            Ok(Self::Groth(read_fixed::<GROTH_PROOF_SIZE, _>(&mut reader)?))
        } else {
            Ok(Self::Phgr(read_fixed::<PHGR_PROOF_SIZE, _>(&mut reader)?))
        }
    }

    /// Writes this proof.
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.as_bytes())
    }
}

/// A Sprout JoinSplit description in its wire representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SproutJoinSplitBytes {
    vpub_old: u64,
    vpub_new: u64,
    anchor: [u8; ANCHOR_SIZE],
    nullifiers: [[u8; NULLIFIER_SIZE]; ZC_NUM_JS_INPUTS],
    commitments: [[u8; COMMITMENT_SIZE]; ZC_NUM_JS_OUTPUTS],
    ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
    random_seed: [u8; RANDOM_SEED_SIZE],
    macs: [[u8; MAC_SIZE]; ZC_NUM_JS_INPUTS],
    proof: SproutProofBytes,
    ciphertexts: [[u8; CIPHERTEXT_SIZE]; ZC_NUM_JS_OUTPUTS],
}

impl SproutJoinSplitBytes {
    /// Constructs a JoinSplit description from its wire fields.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        vpub_old: u64,
        vpub_new: u64,
        anchor: [u8; ANCHOR_SIZE],
        nullifiers: [[u8; NULLIFIER_SIZE]; ZC_NUM_JS_INPUTS],
        commitments: [[u8; COMMITMENT_SIZE]; ZC_NUM_JS_OUTPUTS],
        ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
        random_seed: [u8; RANDOM_SEED_SIZE],
        macs: [[u8; MAC_SIZE]; ZC_NUM_JS_INPUTS],
        proof: SproutProofBytes,
        ciphertexts: [[u8; CIPHERTEXT_SIZE]; ZC_NUM_JS_OUTPUTS],
    ) -> Self {
        Self {
            vpub_old,
            vpub_new,
            anchor,
            nullifiers,
            commitments,
            ephemeral_key,
            random_seed,
            macs,
            proof,
            ciphertexts,
        }
    }

    /// Returns the value added to the Sprout pool by this JoinSplit.
    pub fn vpub_old(&self) -> u64 {
        self.vpub_old
    }

    /// Returns the value removed from the Sprout pool by this JoinSplit.
    pub fn vpub_new(&self) -> u64 {
        self.vpub_new
    }

    /// Returns the Sprout note commitment tree anchor.
    pub fn anchor(&self) -> &[u8; ANCHOR_SIZE] {
        &self.anchor
    }

    /// Returns the nullifiers for the input notes.
    pub fn nullifiers(&self) -> &[[u8; NULLIFIER_SIZE]; ZC_NUM_JS_INPUTS] {
        &self.nullifiers
    }

    /// Returns the note commitments for the output notes.
    pub fn commitments(&self) -> &[[u8; COMMITMENT_SIZE]; ZC_NUM_JS_OUTPUTS] {
        &self.commitments
    }

    /// Returns the ephemeral key.
    pub fn ephemeral_key(&self) -> &[u8; EPHEMERAL_KEY_SIZE] {
        &self.ephemeral_key
    }

    /// Returns the random seed.
    pub fn random_seed(&self) -> &[u8; RANDOM_SEED_SIZE] {
        &self.random_seed
    }

    /// Returns the message authentication codes.
    pub fn macs(&self) -> &[[u8; MAC_SIZE]; ZC_NUM_JS_INPUTS] {
        &self.macs
    }

    /// Returns the proof.
    pub fn proof(&self) -> &SproutProofBytes {
        &self.proof
    }

    /// Returns the ciphertexts.
    pub fn ciphertexts(&self) -> &[[u8; CIPHERTEXT_SIZE]; ZC_NUM_JS_OUTPUTS] {
        &self.ciphertexts
    }

    /// Reads a JoinSplit description.
    ///
    /// `use_groth` selects the proof encoding: Groth16 from version 4 onward,
    /// PHGR before it.
    pub fn read<R: Read>(mut reader: R, use_groth: bool) -> io::Result<Self> {
        let vpub_old = read_amount(&mut reader)?;
        let vpub_new = read_amount(&mut reader)?;
        let anchor = read_fixed::<ANCHOR_SIZE, _>(&mut reader)?;
        let nullifiers = [
            read_fixed::<NULLIFIER_SIZE, _>(&mut reader)?,
            read_fixed::<NULLIFIER_SIZE, _>(&mut reader)?,
        ];
        let commitments = [
            read_fixed::<COMMITMENT_SIZE, _>(&mut reader)?,
            read_fixed::<COMMITMENT_SIZE, _>(&mut reader)?,
        ];
        let ephemeral_key = read_fixed::<EPHEMERAL_KEY_SIZE, _>(&mut reader)?;
        let random_seed = read_fixed::<RANDOM_SEED_SIZE, _>(&mut reader)?;
        let macs = [
            read_fixed::<MAC_SIZE, _>(&mut reader)?,
            read_fixed::<MAC_SIZE, _>(&mut reader)?,
        ];
        let proof = SproutProofBytes::read(&mut reader, use_groth)?;
        let ciphertexts = [
            read_fixed::<CIPHERTEXT_SIZE, _>(&mut reader)?,
            read_fixed::<CIPHERTEXT_SIZE, _>(&mut reader)?,
        ];
        Ok(Self {
            vpub_old,
            vpub_new,
            anchor,
            nullifiers,
            commitments,
            ephemeral_key,
            random_seed,
            macs,
            proof,
            ciphertexts,
        })
    }

    /// Writes this JoinSplit description.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.vpub_old.to_le_bytes())?;
        writer.write_all(&self.vpub_new.to_le_bytes())?;
        writer.write_all(&self.anchor)?;
        writer.write_all(&self.nullifiers[0])?;
        writer.write_all(&self.nullifiers[1])?;
        writer.write_all(&self.commitments[0])?;
        writer.write_all(&self.commitments[1])?;
        writer.write_all(&self.ephemeral_key)?;
        writer.write_all(&self.random_seed)?;
        writer.write_all(&self.macs[0])?;
        writer.write_all(&self.macs[1])?;
        self.proof.write(&mut writer)?;
        writer.write_all(&self.ciphertexts[0])?;
        writer.write_all(&self.ciphertexts[1])
    }
}

/// A Sprout bundle in its wire representation.
///
/// The wire layout is a CompactSize-prefixed vector of JoinSplit descriptions,
/// followed by the JoinSplit public key and signature when the vector is
/// non-empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SproutBundleBytes {
    joinsplits: Vec<SproutJoinSplitBytes>,
    joinsplit_pubkey: [u8; JOINSPLIT_PUBKEY_SIZE],
    joinsplit_sig: [u8; JOINSPLIT_SIG_SIZE],
}

impl SproutBundleBytes {
    /// Constructs a Sprout bundle from its wire fields.
    ///
    /// Returns an error if the JoinSplit vector is empty, since an empty bundle
    /// is encoded as a bare zero count with no public key or signature.
    pub fn from_parts(
        joinsplits: Vec<SproutJoinSplitBytes>,
        joinsplit_pubkey: [u8; JOINSPLIT_PUBKEY_SIZE],
        joinsplit_sig: [u8; JOINSPLIT_SIG_SIZE],
    ) -> io::Result<Self> {
        if joinsplits.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a Sprout bundle with no JoinSplits is encoded as an empty vector",
            ));
        }
        Ok(Self {
            joinsplits,
            joinsplit_pubkey,
            joinsplit_sig,
        })
    }

    /// Returns the JoinSplit descriptions.
    pub fn joinsplits(&self) -> &[SproutJoinSplitBytes] {
        &self.joinsplits
    }

    /// Returns the JoinSplit public key.
    pub fn joinsplit_pubkey(&self) -> &[u8; JOINSPLIT_PUBKEY_SIZE] {
        &self.joinsplit_pubkey
    }

    /// Returns the JoinSplit signature.
    pub fn joinsplit_sig(&self) -> &[u8; JOINSPLIT_SIG_SIZE] {
        &self.joinsplit_sig
    }

    /// Reads a Sprout bundle, returning `None` for an empty one.
    pub fn read<R: Read>(mut reader: R, use_groth: bool) -> io::Result<Option<Self>> {
        let joinsplits = read_vector(&mut reader, |r| SproutJoinSplitBytes::read(r, use_groth))?;
        if joinsplits.is_empty() {
            return Ok(None);
        }
        let joinsplit_pubkey = read_fixed::<JOINSPLIT_PUBKEY_SIZE, _>(&mut reader)?;
        let joinsplit_sig = read_fixed::<JOINSPLIT_SIG_SIZE, _>(&mut reader)?;
        Ok(Some(Self {
            joinsplits,
            joinsplit_pubkey,
            joinsplit_sig,
        }))
    }

    /// Writes a Sprout bundle, or an empty vector if `bundle` is `None`.
    pub fn write_opt<W: Write>(mut writer: W, bundle: Option<&Self>) -> io::Result<()> {
        match bundle {
            Some(bundle) => {
                Vector::write(&mut writer, &bundle.joinsplits, |w, js| js.write(w))?;
                writer.write_all(&bundle.joinsplit_pubkey)?;
                writer.write_all(&bundle.joinsplit_sig)
            }
            None => CompactSize::write(&mut writer, 0),
        }
    }

    /// Interprets this bundle as a Sprout bundle.
    ///
    /// Each JoinSplit is decoded by the same decoder used for the legacy wire
    /// format, with the proof encoding selected by the proof variant.
    pub fn to_bundle(&self) -> io::Result<crate::transaction::components::sprout::Bundle> {
        use crate::transaction::components::sprout::JsDescription;

        let joinsplits = self
            .joinsplits
            .iter()
            .map(|js| {
                let use_groth = matches!(js.proof(), SproutProofBytes::Groth(_));
                let mut bytes = Vec::new();
                js.write(&mut bytes)?;
                JsDescription::read(&mut &bytes[..], use_groth)
            })
            .collect::<io::Result<Vec<_>>>()?;

        Ok(crate::transaction::components::sprout::Bundle {
            joinsplits,
            joinsplit_pubkey: self.joinsplit_pubkey,
            joinsplit_sig: self.joinsplit_sig,
        })
    }
}

/// Reads an unsigned 64-bit amount without narrowing it to the monetary
/// domain.
fn read_amount<R: Read>(mut reader: R) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
