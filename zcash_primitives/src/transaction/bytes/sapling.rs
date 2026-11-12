//! Byte-level Sapling bundle representations.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::{Array, CompactSize, Vector};
#[cfg(feature = "sapling")]
use zcash_protocol::value::ZatBalance;

use crate::transaction::components::GROTH_PROOF_SIZE;

use super::{read_array, read_fixed, read_vector};

/// The size in bytes of a Sapling value commitment.
const VALUE_COMMITMENT_SIZE: usize = 32;
/// The size in bytes of a Sapling nullifier.
const NULLIFIER_SIZE: usize = 32;
/// The size in bytes of a Sapling randomized validating key.
const RK_SIZE: usize = 32;
/// The size in bytes of a Sapling anchor.
const ANCHOR_SIZE: usize = 32;
/// The size in bytes of a Sapling extracted note commitment.
const CMU_SIZE: usize = 32;
/// The size in bytes of a Sapling ephemeral key.
const EPHEMERAL_KEY_SIZE: usize = 32;
/// The size in bytes of a Sapling encrypted note ciphertext.
const ENC_CIPHERTEXT_SIZE: usize = 580;
/// The size in bytes of a Sapling encrypted outgoing ciphertext.
const OUT_CIPHERTEXT_SIZE: usize = 80;
/// The size in bytes of a Sapling spend authorization signature.
const SPEND_AUTH_SIG_SIZE: usize = 64;
/// The size in bytes of a Sapling binding signature.
const BINDING_SIG_SIZE: usize = 64;

/// A Sapling spend description's effecting data.
///
/// This is the `SaplingSpendEffecting` encoding used by version 5 and later
/// transactions: the value commitment, nullifier, and randomized validating
/// key. The anchor, proof, and spend authorization signature are authorizing
/// data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingSpendBytes {
    cv: [u8; VALUE_COMMITMENT_SIZE],
    nullifier: [u8; NULLIFIER_SIZE],
    rk: [u8; RK_SIZE],
}

impl SaplingSpendBytes {
    /// Constructs a spend's effecting data from its wire fields.
    pub fn from_parts(
        cv: [u8; VALUE_COMMITMENT_SIZE],
        nullifier: [u8; NULLIFIER_SIZE],
        rk: [u8; RK_SIZE],
    ) -> Self {
        Self { cv, nullifier, rk }
    }

    /// Returns the value commitment.
    pub fn cv(&self) -> &[u8; VALUE_COMMITMENT_SIZE] {
        &self.cv
    }

    /// Returns the nullifier.
    pub fn nullifier(&self) -> &[u8; NULLIFIER_SIZE] {
        &self.nullifier
    }

    /// Returns the randomized validating key.
    pub fn rk(&self) -> &[u8; RK_SIZE] {
        &self.rk
    }

    /// Reads a spend's effecting data.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self {
            cv: read_fixed::<VALUE_COMMITMENT_SIZE, _>(&mut reader)?,
            nullifier: read_fixed::<NULLIFIER_SIZE, _>(&mut reader)?,
            rk: read_fixed::<RK_SIZE, _>(&mut reader)?,
        })
    }

    /// Writes a spend's effecting data.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv)?;
        writer.write_all(&self.nullifier)?;
        writer.write_all(&self.rk)
    }

    /// Interprets this effecting data as a version 5 Sapling spend description.
    ///
    /// The value commitment, nullifier, and randomized validating key are
    /// validated by the same decoders used for the v5 wire format.
    #[cfg(feature = "sapling")]
    pub(crate) fn to_spend_v5(&self) -> io::Result<::sapling::bundle::SpendDescriptionV5> {
        let mut bytes = Vec::with_capacity(96);
        self.write(&mut bytes)?;
        crate::transaction::components::sapling::read_spend_v5(&mut &bytes[..])
    }
}

/// A Sapling output description.
///
/// This is the `SaplingOutput` encoding used by version 5 and later
/// transactions. The proof is authorizing data and is not part of this
/// structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingOutputBytes {
    cv: [u8; VALUE_COMMITMENT_SIZE],
    cmu: [u8; CMU_SIZE],
    ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
}

impl SaplingOutputBytes {
    /// Constructs an output description from its wire fields.
    pub fn from_parts(
        cv: [u8; VALUE_COMMITMENT_SIZE],
        cmu: [u8; CMU_SIZE],
        ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
        enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
        out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    ) -> Self {
        Self {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
        }
    }

    /// Returns the value commitment.
    pub fn cv(&self) -> &[u8; VALUE_COMMITMENT_SIZE] {
        &self.cv
    }

    /// Returns the extracted note commitment.
    pub fn cmu(&self) -> &[u8; CMU_SIZE] {
        &self.cmu
    }

    /// Returns the ephemeral key.
    pub fn ephemeral_key(&self) -> &[u8; EPHEMERAL_KEY_SIZE] {
        &self.ephemeral_key
    }

    /// Returns the encrypted note ciphertext.
    pub fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }

    /// Returns the encrypted outgoing ciphertext.
    pub fn out_ciphertext(&self) -> &[u8; OUT_CIPHERTEXT_SIZE] {
        &self.out_ciphertext
    }

    /// Reads an output description.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self {
            cv: read_fixed::<VALUE_COMMITMENT_SIZE, _>(&mut reader)?,
            cmu: read_fixed::<CMU_SIZE, _>(&mut reader)?,
            ephemeral_key: read_fixed::<EPHEMERAL_KEY_SIZE, _>(&mut reader)?,
            enc_ciphertext: read_fixed::<ENC_CIPHERTEXT_SIZE, _>(&mut reader)?,
            out_ciphertext: read_fixed::<OUT_CIPHERTEXT_SIZE, _>(&mut reader)?,
        })
    }

    /// Writes an output description.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv)?;
        writer.write_all(&self.cmu)?;
        writer.write_all(&self.ephemeral_key)?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)
    }

    /// Interprets this output description as a version 5 Sapling output.
    ///
    /// The value commitment, note commitment, and ciphertexts are validated by
    /// the same decoders used for the v5 wire format.
    #[cfg(feature = "sapling")]
    pub(crate) fn to_output_v5(&self) -> io::Result<::sapling::bundle::OutputDescriptionV5> {
        let mut bytes = Vec::with_capacity(756);
        self.write(&mut bytes)?;
        crate::transaction::components::sapling::read_output_v5(&mut &bytes[..])
    }
}

/// A version 4 Sapling spend description.
///
/// Version 4 carries the anchor, proof, and spend authorization signature
/// inline with each spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingSpendV4Bytes {
    cv: [u8; VALUE_COMMITMENT_SIZE],
    anchor: [u8; ANCHOR_SIZE],
    nullifier: [u8; NULLIFIER_SIZE],
    rk: [u8; RK_SIZE],
    zkproof: [u8; GROTH_PROOF_SIZE],
    spend_auth_sig: [u8; SPEND_AUTH_SIG_SIZE],
}

impl SaplingSpendV4Bytes {
    /// Constructs a version 4 spend description from its wire fields.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        cv: [u8; VALUE_COMMITMENT_SIZE],
        anchor: [u8; ANCHOR_SIZE],
        nullifier: [u8; NULLIFIER_SIZE],
        rk: [u8; RK_SIZE],
        zkproof: [u8; GROTH_PROOF_SIZE],
        spend_auth_sig: [u8; SPEND_AUTH_SIG_SIZE],
    ) -> Self {
        Self {
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        }
    }

    /// Returns the value commitment.
    pub fn cv(&self) -> &[u8; VALUE_COMMITMENT_SIZE] {
        &self.cv
    }

    /// Returns the anchor.
    pub fn anchor(&self) -> &[u8; ANCHOR_SIZE] {
        &self.anchor
    }

    /// Returns the nullifier.
    pub fn nullifier(&self) -> &[u8; NULLIFIER_SIZE] {
        &self.nullifier
    }

    /// Returns the randomized validating key.
    pub fn rk(&self) -> &[u8; RK_SIZE] {
        &self.rk
    }

    /// Returns the proof.
    pub fn zkproof(&self) -> &[u8; GROTH_PROOF_SIZE] {
        &self.zkproof
    }

    /// Returns the spend authorization signature.
    pub fn spend_auth_sig(&self) -> &[u8; SPEND_AUTH_SIG_SIZE] {
        &self.spend_auth_sig
    }

    /// Reads a version 4 spend description.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self {
            cv: read_fixed::<VALUE_COMMITMENT_SIZE, _>(&mut reader)?,
            anchor: read_fixed::<ANCHOR_SIZE, _>(&mut reader)?,
            nullifier: read_fixed::<NULLIFIER_SIZE, _>(&mut reader)?,
            rk: read_fixed::<RK_SIZE, _>(&mut reader)?,
            zkproof: read_fixed::<GROTH_PROOF_SIZE, _>(&mut reader)?,
            spend_auth_sig: read_fixed::<SPEND_AUTH_SIG_SIZE, _>(&mut reader)?,
        })
    }

    /// Writes a version 4 spend description.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv)?;
        writer.write_all(&self.anchor)?;
        writer.write_all(&self.nullifier)?;
        writer.write_all(&self.rk)?;
        writer.write_all(&self.zkproof)?;
        writer.write_all(&self.spend_auth_sig)
    }

    /// Interprets this description as a version 4 Sapling spend.
    ///
    /// The value commitment, anchor, nullifier, and randomized validating key
    /// are validated by the same decoder used for the v4 wire format.
    #[cfg(feature = "sapling")]
    pub(crate) fn to_spend_v4(
        &self,
    ) -> io::Result<::sapling::bundle::SpendDescription<::sapling::bundle::Authorized>> {
        let mut bytes = Vec::with_capacity(32 + 32 + 32 + 32 + GROTH_PROOF_SIZE + 64);
        self.write(&mut bytes)?;
        crate::transaction::components::sapling::read_spend_v4(&mut &bytes[..])
    }
}

/// A version 4 Sapling output description.
///
/// Version 4 carries the proof inline with each output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingOutputV4Bytes {
    cv: [u8; VALUE_COMMITMENT_SIZE],
    cmu: [u8; CMU_SIZE],
    ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    zkproof: [u8; GROTH_PROOF_SIZE],
}

impl SaplingOutputV4Bytes {
    /// Constructs a version 4 output description from its wire fields.
    pub fn from_parts(
        cv: [u8; VALUE_COMMITMENT_SIZE],
        cmu: [u8; CMU_SIZE],
        ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
        enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
        out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
        zkproof: [u8; GROTH_PROOF_SIZE],
    ) -> Self {
        Self {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        }
    }

    /// Returns the value commitment.
    pub fn cv(&self) -> &[u8; VALUE_COMMITMENT_SIZE] {
        &self.cv
    }

    /// Returns the extracted note commitment.
    pub fn cmu(&self) -> &[u8; CMU_SIZE] {
        &self.cmu
    }

    /// Returns the ephemeral key.
    pub fn ephemeral_key(&self) -> &[u8; EPHEMERAL_KEY_SIZE] {
        &self.ephemeral_key
    }

    /// Returns the encrypted note ciphertext.
    pub fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }

    /// Returns the encrypted outgoing ciphertext.
    pub fn out_ciphertext(&self) -> &[u8; OUT_CIPHERTEXT_SIZE] {
        &self.out_ciphertext
    }

    /// Returns the proof.
    pub fn zkproof(&self) -> &[u8; GROTH_PROOF_SIZE] {
        &self.zkproof
    }

    /// Reads a version 4 output description.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self {
            cv: read_fixed::<VALUE_COMMITMENT_SIZE, _>(&mut reader)?,
            cmu: read_fixed::<CMU_SIZE, _>(&mut reader)?,
            ephemeral_key: read_fixed::<EPHEMERAL_KEY_SIZE, _>(&mut reader)?,
            enc_ciphertext: read_fixed::<ENC_CIPHERTEXT_SIZE, _>(&mut reader)?,
            out_ciphertext: read_fixed::<OUT_CIPHERTEXT_SIZE, _>(&mut reader)?,
            zkproof: read_fixed::<GROTH_PROOF_SIZE, _>(&mut reader)?,
        })
    }

    /// Writes a version 4 output description.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv)?;
        writer.write_all(&self.cmu)?;
        writer.write_all(&self.ephemeral_key)?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)?;
        writer.write_all(&self.zkproof)
    }

    /// Interprets this description as a version 4 Sapling output.
    ///
    /// The value commitment and note commitment are validated by the same
    /// decoder used for the v4 wire format.
    #[cfg(feature = "sapling")]
    pub(crate) fn to_output_v4(
        &self,
    ) -> io::Result<::sapling::bundle::OutputDescription<::sapling::bundle::GrothProofBytes>> {
        let mut bytes = Vec::with_capacity(
            32 + 32 + 32 + ENC_CIPHERTEXT_SIZE + OUT_CIPHERTEXT_SIZE + GROTH_PROOF_SIZE,
        );
        self.write(&mut bytes)?;
        crate::transaction::components::sapling::read_output_v4(&mut &bytes[..])
    }
}

/// A version 4 Sapling bundle in its wire representation.
///
/// The wire layout is `value_balance || spends || outputs`. The binding
/// signature is a transaction-level field that follows the Sprout bundle, so
/// it is carried by [`LegacyTransactionBodyBytes`](super::LegacyTransactionBodyBytes)
/// rather than here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V4SaplingBundleBytes {
    value_balance: i64,
    spends: Vec<SaplingSpendV4Bytes>,
    outputs: Vec<SaplingOutputV4Bytes>,
}

impl V4SaplingBundleBytes {
    /// Constructs a version 4 Sapling bundle from its wire fields.
    pub fn from_parts(
        value_balance: i64,
        spends: Vec<SaplingSpendV4Bytes>,
        outputs: Vec<SaplingOutputV4Bytes>,
    ) -> Self {
        Self {
            value_balance,
            spends,
            outputs,
        }
    }

    /// Returns the value balance.
    pub fn value_balance(&self) -> i64 {
        self.value_balance
    }

    /// Returns the spend descriptions.
    pub fn spends(&self) -> &[SaplingSpendV4Bytes] {
        &self.spends
    }

    /// Returns the output descriptions.
    pub fn outputs(&self) -> &[SaplingOutputV4Bytes] {
        &self.outputs
    }

    /// Returns `true` if the bundle has neither spends nor outputs.
    pub fn is_empty(&self) -> bool {
        self.spends.is_empty() && self.outputs.is_empty()
    }

    /// Reads a version 4 Sapling bundle.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let value_balance = read_balance(&mut reader)?;
        let spends = read_vector(&mut reader, |r| SaplingSpendV4Bytes::read(r))?;
        let outputs = read_vector(&mut reader, |r| SaplingOutputV4Bytes::read(r))?;
        Ok(Self {
            value_balance,
            spends,
            outputs,
        })
    }

    /// Writes a version 4 Sapling bundle.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.value_balance.to_le_bytes())?;
        Vector::write(&mut writer, &self.spends, |w, spend| spend.write(w))?;
        Vector::write(&mut writer, &self.outputs, |w, output| output.write(w))
    }

    /// Interprets this bundle as an authorized Sapling bundle.
    ///
    /// The binding signature is a transaction-level field in the version 4
    /// format, so the caller supplies it. Returns `None` for an empty bundle,
    /// matching the representation used by `TransactionData`.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle is non-empty but no binding signature is
    /// supplied, or if a spend or output description is invalid.
    #[cfg(feature = "sapling")]
    pub fn to_authorized(
        &self,
        binding_sig: Option<[u8; BINDING_SIG_SIZE]>,
    ) -> io::Result<Option<::sapling::bundle::Bundle<::sapling::bundle::Authorized, ZatBalance>>>
    {
        if self.is_empty() {
            if binding_sig.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a Sapling binding signature is present for an empty bundle",
                ));
            }
            return Ok(None);
        }

        let binding_sig = binding_sig.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "a non-empty Sapling bundle requires a binding signature",
            )
        })?;

        let spends = self
            .spends
            .iter()
            .map(SaplingSpendV4Bytes::to_spend_v4)
            .collect::<io::Result<Vec<_>>>()?;
        let outputs = self
            .outputs
            .iter()
            .map(SaplingOutputV4Bytes::to_output_v4)
            .collect::<io::Result<Vec<_>>>()?;

        Ok(::sapling::bundle::Bundle::from_parts(
            spends,
            outputs,
            value_balance_from_raw(self.value_balance)?,
            ::sapling::bundle::Authorized {
                binding_sig: redjubjub::Signature::from(binding_sig),
            },
        ))
    }
}

/// A version 5 or 6 Sapling bundle in its wire representation.
///
/// The wire layout is `spends || outputs || value_balance? || anchor? ||
/// spend_proofs || spend_auth_sigs || output_proofs || binding_sig?`, where
/// the optional fields are present exactly when the bundle is non-empty (and
/// the anchor only when there is at least one spend).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingBundleBytes {
    spends: Vec<SaplingSpendBytes>,
    outputs: Vec<SaplingOutputBytes>,
    value_balance: i64,
    anchor: Option<[u8; ANCHOR_SIZE]>,
    spend_proofs: Vec<[u8; GROTH_PROOF_SIZE]>,
    spend_auth_sigs: Vec<[u8; SPEND_AUTH_SIG_SIZE]>,
    output_proofs: Vec<[u8; GROTH_PROOF_SIZE]>,
    binding_sig: Option<[u8; BINDING_SIG_SIZE]>,
}

impl SaplingBundleBytes {
    /// Constructs a version 5 or 6 Sapling bundle from its wire fields.
    ///
    /// Returns an error if the anchor, proofs, signatures, or binding
    /// signature do not correspond to the spend and output counts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        spends: Vec<SaplingSpendBytes>,
        outputs: Vec<SaplingOutputBytes>,
        value_balance: i64,
        anchor: Option<[u8; ANCHOR_SIZE]>,
        spend_proofs: Vec<[u8; GROTH_PROOF_SIZE]>,
        spend_auth_sigs: Vec<[u8; SPEND_AUTH_SIG_SIZE]>,
        output_proofs: Vec<[u8; GROTH_PROOF_SIZE]>,
        binding_sig: Option<[u8; BINDING_SIG_SIZE]>,
    ) -> io::Result<Self> {
        if spends.is_empty() && outputs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an empty Sapling bundle is encoded as two zero counts",
            ));
        }
        let nonempty = !spends.is_empty() || !outputs.is_empty();
        if nonempty != binding_sig.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a Sapling binding signature is present exactly when the bundle is non-empty",
            ));
        }
        if spends.is_empty() != anchor.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a Sapling anchor is present exactly when there is at least one spend",
            ));
        }
        if spend_proofs.len() != spends.len()
            || spend_auth_sigs.len() != spends.len()
            || output_proofs.len() != outputs.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sapling proofs and signatures must correspond one-to-one with spends and outputs",
            ));
        }
        Ok(Self {
            spends,
            outputs,
            value_balance,
            anchor,
            spend_proofs,
            spend_auth_sigs,
            output_proofs,
            binding_sig,
        })
    }

    /// Returns the spend descriptions.
    pub fn spends(&self) -> &[SaplingSpendBytes] {
        &self.spends
    }

    /// Returns the output descriptions.
    pub fn outputs(&self) -> &[SaplingOutputBytes] {
        &self.outputs
    }

    /// Returns the value balance.
    pub fn value_balance(&self) -> i64 {
        self.value_balance
    }

    /// Returns the anchor, if the bundle has spends.
    pub fn anchor(&self) -> Option<&[u8; ANCHOR_SIZE]> {
        self.anchor.as_ref()
    }

    /// Returns the spend proofs.
    pub fn spend_proofs(&self) -> &[[u8; GROTH_PROOF_SIZE]] {
        &self.spend_proofs
    }

    /// Returns the spend authorization signatures.
    pub fn spend_auth_sigs(&self) -> &[[u8; SPEND_AUTH_SIG_SIZE]] {
        &self.spend_auth_sigs
    }

    /// Returns the output proofs.
    pub fn output_proofs(&self) -> &[[u8; GROTH_PROOF_SIZE]] {
        &self.output_proofs
    }

    /// Returns the binding signature, if the bundle is non-empty.
    pub fn binding_sig(&self) -> Option<&[u8; BINDING_SIG_SIZE]> {
        self.binding_sig.as_ref()
    }

    /// Reads a version 5 or 6 Sapling bundle, returning `None` for an empty
    /// one.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Option<Self>> {
        let spends = read_vector(&mut reader, |r| SaplingSpendBytes::read(r))?;
        let outputs = read_vector(&mut reader, |r| SaplingOutputBytes::read(r))?;
        if spends.is_empty() && outputs.is_empty() {
            return Ok(None);
        }

        let value_balance = read_balance(&mut reader)?;
        let anchor = if spends.is_empty() {
            None
        } else {
            Some(read_fixed::<ANCHOR_SIZE, _>(&mut reader)?)
        };
        let spend_proofs = read_array(&mut reader, spends.len(), |r| {
            read_fixed::<GROTH_PROOF_SIZE, _>(r)
        })?;
        let spend_auth_sigs = read_array(&mut reader, spends.len(), |r| {
            read_fixed::<SPEND_AUTH_SIG_SIZE, _>(r)
        })?;
        let output_proofs = read_array(&mut reader, outputs.len(), |r| {
            read_fixed::<GROTH_PROOF_SIZE, _>(r)
        })?;
        let binding_sig = Some(read_fixed::<BINDING_SIG_SIZE, _>(&mut reader)?);

        Ok(Some(Self {
            spends,
            outputs,
            value_balance,
            anchor,
            spend_proofs,
            spend_auth_sigs,
            output_proofs,
            binding_sig,
        }))
    }

    /// Writes a version 5 or 6 Sapling bundle, or two zero counts if `bundle`
    /// is `None`.
    pub fn write_opt<W: Write>(mut writer: W, bundle: Option<&Self>) -> io::Result<()> {
        match bundle {
            Some(bundle) => {
                Vector::write(&mut writer, &bundle.spends, |w, spend| spend.write(w))?;
                Vector::write(&mut writer, &bundle.outputs, |w, output| output.write(w))?;
                writer.write_all(&bundle.value_balance.to_le_bytes())?;
                if let Some(anchor) = &bundle.anchor {
                    writer.write_all(anchor)?;
                }
                Array::write(&mut writer, &bundle.spend_proofs, |w, proof| {
                    w.write_all(&proof[..])
                })?;
                Array::write(&mut writer, &bundle.spend_auth_sigs, |w, sig| {
                    w.write_all(&sig[..])
                })?;
                Array::write(&mut writer, &bundle.output_proofs, |w, proof| {
                    w.write_all(&proof[..])
                })?;
                if let Some(binding_sig) = &bundle.binding_sig {
                    writer.write_all(binding_sig)?;
                }
                Ok(())
            }
            None => {
                CompactSize::write(&mut writer, 0)?;
                CompactSize::write(&mut writer, 0)
            }
        }
    }

    /// Interprets this bundle as an authorized Sapling bundle.
    ///
    /// The value balance, anchor, proofs, and signatures are validated by the
    /// same decoders used for the v5 wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle is empty, or if a field is invalid.
    #[cfg(feature = "sapling")]
    pub fn to_authorized(
        &self,
    ) -> io::Result<::sapling::bundle::Bundle<::sapling::bundle::Authorized, ZatBalance>> {
        use crate::transaction::components::sapling::{
            read_base, read_spend_auth_sig, read_zkproof,
        };

        if self.spends.is_empty() && self.outputs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "an empty Sapling bundle has no typed representation",
            ));
        }

        let anchor = self
            .anchor
            .as_ref()
            .map(|anchor| read_base(&mut &anchor[..], "anchor"))
            .transpose()?;

        let spends = self
            .spends
            .iter()
            .zip(self.spend_proofs.iter().zip(self.spend_auth_sigs.iter()))
            .map(|(spend, (proof, sig))| {
                let spend = spend.to_spend_v5()?;
                let zkproof = read_zkproof(&mut &proof[..])?;
                let spend_auth_sig = read_spend_auth_sig(&mut &sig[..])?;
                Ok(spend.into_spend_description(
                    anchor.expect("a non-empty spend list has an anchor"),
                    zkproof,
                    spend_auth_sig,
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;

        let outputs = self
            .outputs
            .iter()
            .zip(self.output_proofs.iter())
            .map(|(output, proof)| {
                let output = output.to_output_v5()?;
                let zkproof = read_zkproof(&mut &proof[..])?;
                Ok(output.into_output_description(zkproof))
            })
            .collect::<io::Result<Vec<_>>>()?;

        let binding_sig = self.binding_sig.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "a non-empty Sapling bundle requires a binding signature",
            )
        })?;

        Ok(::sapling::bundle::Bundle::from_parts(
            spends,
            outputs,
            value_balance_from_raw(self.value_balance)?,
            ::sapling::bundle::Authorized {
                binding_sig: redjubjub::Signature::from(binding_sig),
            },
        )
        .expect("a non-empty Sapling bundle has a typed representation"))
    }
}

/// A CompactSize-prefixed `sighashInfo` value.
///
/// The bytes are retained verbatim. Sighash version 0 is the only version
/// defined for the Sapling and Orchard bundles, and its `sighashInfo` is the
/// single byte `0x00`; [`Self::is_v0`] reports whether that is the case. The
/// byte layer does not reject other versions; typed conversion does.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SighashInfoBytes {
    bytes: Vec<u8>,
}

#[cfg(zcash_unstable = "nu8")]
impl SighashInfoBytes {
    /// Constructs a `sighashInfo` value from its raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the sighash version 0 encoding, `[0x00]`.
    pub fn v0() -> Self {
        Self {
            bytes: alloc::vec![0x00],
        }
    }

    /// Returns the raw `sighashInfo` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns `true` if this is the sighash version 0 encoding.
    pub fn is_v0(&self) -> bool {
        self.bytes == [0x00]
    }

    /// Reads a CompactSize-prefixed `sighashInfo` value.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self::from_bytes(Vector::read_bytes(&mut reader)?))
    }

    /// Writes this `sighashInfo` value with its CompactSize length prefix.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write_bytes(&mut writer, &self.bytes)
    }
}

/// A Sapling signature with its `sighashInfo` prefix.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingSignatureBytes {
    sighash_info: SighashInfoBytes,
    signature: [u8; SPEND_AUTH_SIG_SIZE],
}

#[cfg(zcash_unstable = "nu8")]
impl SaplingSignatureBytes {
    /// Constructs a Sapling signature from its wire fields.
    pub fn from_parts(
        sighash_info: SighashInfoBytes,
        signature: [u8; SPEND_AUTH_SIG_SIZE],
    ) -> Self {
        Self {
            sighash_info,
            signature,
        }
    }

    /// Returns the `sighashInfo` value.
    pub fn sighash_info(&self) -> &SighashInfoBytes {
        &self.sighash_info
    }

    /// Returns the signature bytes.
    pub fn signature(&self) -> &[u8; SPEND_AUTH_SIG_SIZE] {
        &self.signature
    }

    /// Reads a Sapling signature.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let sighash_info = SighashInfoBytes::read(&mut reader)?;
        let signature = read_fixed::<SPEND_AUTH_SIG_SIZE, _>(&mut reader)?;
        Ok(Self {
            sighash_info,
            signature,
        })
    }

    /// Writes a Sapling signature.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.sighash_info.write(&mut writer)?;
        writer.write_all(&self.signature)
    }
}

/// A version 7 Sapling bundle, retaining its effecting and authorizing data
/// separately.
///
/// [ZIP 248 §Sapling Bundle](https://zips.z.cash/zip-0248#sapling-bundle)
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V7SaplingBundleBytes {
    spends: Vec<SaplingSpendBytes>,
    outputs: Vec<SaplingOutputBytes>,
    anchor: Option<[u8; ANCHOR_SIZE]>,
    spend_proofs: Vec<[u8; GROTH_PROOF_SIZE]>,
    spend_auth_sigs: Vec<SaplingSignatureBytes>,
    output_proofs: Vec<[u8; GROTH_PROOF_SIZE]>,
    binding_sig: Option<SaplingSignatureBytes>,
    /// Whether an entry for this bundle is present in `mAuthBundles`.
    ///
    /// This is independent of whether the authorizing payload has contents: an
    /// empty bundle can have a present-but-empty authorizing entry, which the
    /// digests distinguish from an absent one.
    auth: bool,
}

#[cfg(zcash_unstable = "nu8")]
impl V7SaplingBundleBytes {
    /// Constructs a version 7 Sapling bundle from its wire fields.
    ///
    /// The authorizing entry is present exactly when `binding_sig` is present.
    /// Returns an error if the anchor is present without spends, if the proofs
    /// and signatures do not correspond one-to-one with the spends and
    /// outputs, or if authorizing fields are present without a binding
    /// signature. Authorizing data may be absent even when the effecting data
    /// has spends or outputs; requiring it is a consensus rule enforced by
    /// typed conversion rather than by the byte layer.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        spends: Vec<SaplingSpendBytes>,
        outputs: Vec<SaplingOutputBytes>,
        anchor: Option<[u8; ANCHOR_SIZE]>,
        spend_proofs: Vec<[u8; GROTH_PROOF_SIZE]>,
        spend_auth_sigs: Vec<SaplingSignatureBytes>,
        output_proofs: Vec<[u8; GROTH_PROOF_SIZE]>,
        binding_sig: Option<SaplingSignatureBytes>,
    ) -> io::Result<Self> {
        let auth = binding_sig.is_some();
        Self::from_parts_with_auth_presence(
            spends,
            outputs,
            anchor,
            spend_proofs,
            spend_auth_sigs,
            output_proofs,
            binding_sig,
            auth,
        )
    }

    /// Constructs a version 7 Sapling bundle, stating whether an authorizing
    /// entry is present independently of its contents.
    ///
    /// An empty bundle may have a present-but-empty authorizing entry, which
    /// is distinct from an absent entry because map presence is committed to
    /// by the digests.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_with_auth_presence(
        spends: Vec<SaplingSpendBytes>,
        outputs: Vec<SaplingOutputBytes>,
        anchor: Option<[u8; ANCHOR_SIZE]>,
        spend_proofs: Vec<[u8; GROTH_PROOF_SIZE]>,
        spend_auth_sigs: Vec<SaplingSignatureBytes>,
        output_proofs: Vec<[u8; GROTH_PROOF_SIZE]>,
        binding_sig: Option<SaplingSignatureBytes>,
        auth: bool,
    ) -> io::Result<Self> {
        let empty = spends.is_empty() && outputs.is_empty();
        if !auth {
            if binding_sig.is_some()
                || anchor.is_some()
                || !spend_proofs.is_empty()
                || !spend_auth_sigs.is_empty()
                || !output_proofs.is_empty()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Sapling authorizing data is present without an authorizing entry",
                ));
            }
        } else {
            if spends.is_empty() != anchor.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a Sapling anchor is present exactly when there is at least one spend",
                ));
            }
            if spend_proofs.len() != spends.len()
                || spend_auth_sigs.len() != spends.len()
                || output_proofs.len() != outputs.len()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Sapling proofs and signatures must correspond one-to-one with \
                     spends and outputs",
                ));
            }
            if !empty && binding_sig.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a non-empty Sapling bundle requires a binding signature",
                ));
            }
            if empty && binding_sig.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "an empty Sapling bundle has no binding signature",
                ));
            }
        }
        Ok(Self {
            spends,
            outputs,
            anchor,
            spend_proofs,
            spend_auth_sigs,
            output_proofs,
            binding_sig,
            auth,
        })
    }

    /// Returns the spend descriptions.
    pub fn spends(&self) -> &[SaplingSpendBytes] {
        &self.spends
    }

    /// Returns the output descriptions.
    pub fn outputs(&self) -> &[SaplingOutputBytes] {
        &self.outputs
    }

    /// Returns the anchor, if the bundle has spends and authorizing data.
    pub fn anchor(&self) -> Option<&[u8; ANCHOR_SIZE]> {
        self.anchor.as_ref()
    }

    /// Returns the spend proofs.
    pub fn spend_proofs(&self) -> &[[u8; GROTH_PROOF_SIZE]] {
        &self.spend_proofs
    }

    /// Returns the spend authorization signatures.
    pub fn spend_auth_sigs(&self) -> &[SaplingSignatureBytes] {
        &self.spend_auth_sigs
    }

    /// Returns the output proofs.
    pub fn output_proofs(&self) -> &[[u8; GROTH_PROOF_SIZE]] {
        &self.output_proofs
    }

    /// Returns the binding signature, if the bundle has authorizing data.
    pub fn binding_sig(&self) -> Option<&SaplingSignatureBytes> {
        self.binding_sig.as_ref()
    }

    /// Returns `true` if an authorizing entry is present for this bundle.
    pub fn has_auth(&self) -> bool {
        self.auth
    }

    /// Reads a version 7 Sapling bundle from its effecting and authorizing
    /// payloads.
    ///
    /// Both payloads must be consumed exactly; trailing bytes are rejected.
    /// An empty effecting payload is retained as a present bundle, and an
    /// authorizing payload may be absent or present-but-empty; the distinction
    /// is preserved because map presence is committed to by the digests.
    pub fn read(effects: &[u8], auth: Option<&[u8]>) -> io::Result<Self> {
        let mut effects_reader = effects;
        let spends = read_vector(&mut effects_reader, |r| SaplingSpendBytes::read(r))?;
        let outputs = read_vector(&mut effects_reader, |r| SaplingOutputBytes::read(r))?;
        if !effects_reader.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in v7 Sapling effecting data",
            ));
        }

        let empty = spends.is_empty() && outputs.is_empty();
        let Some(auth) = auth else {
            return Self::from_parts_with_auth_presence(
                spends,
                outputs,
                None,
                vec![],
                vec![],
                vec![],
                None,
                false,
            );
        };
        let auth_present = true;

        if empty {
            // ZIP 248: bindingSigSapling is present iff nSpendsSapling +
            // nOutputsSapling > 0, so an empty bundle's authorizing payload is
            // empty.
            if !auth.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "an empty Sapling bundle has non-empty authorizing data",
                ));
            }
            return Self::from_parts_with_auth_presence(
                spends,
                outputs,
                None,
                vec![],
                vec![],
                vec![],
                None,
                auth_present,
            );
        }

        let mut auth_reader = auth;
        let anchor = if spends.is_empty() {
            None
        } else {
            Some(read_fixed::<ANCHOR_SIZE, _>(&mut auth_reader)?)
        };
        let spend_proofs = read_array(&mut auth_reader, spends.len(), |r| {
            read_fixed::<GROTH_PROOF_SIZE, _>(r)
        })?;
        let spend_auth_sigs = read_array(&mut auth_reader, spends.len(), |r| {
            SaplingSignatureBytes::read(r)
        })?;
        let output_proofs = read_array(&mut auth_reader, outputs.len(), |r| {
            read_fixed::<GROTH_PROOF_SIZE, _>(r)
        })?;
        let binding_sig = SaplingSignatureBytes::read(&mut auth_reader)?;
        if !auth_reader.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in v7 Sapling authorizing data",
            ));
        }

        Self::from_parts_with_auth_presence(
            spends,
            outputs,
            anchor,
            spend_proofs,
            spend_auth_sigs,
            output_proofs,
            Some(binding_sig),
            auth_present,
        )
    }

    /// Writes the bundle's effecting data.
    pub fn write_effects<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write(&mut writer, &self.spends, |w, spend| spend.write(w))?;
        Vector::write(&mut writer, &self.outputs, |w, output| output.write(w))
    }

    /// Writes the bundle's authorizing data, if an authorizing entry is
    /// present.
    pub fn write_auth<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if !self.auth {
            return Ok(());
        }
        if let Some(anchor) = &self.anchor {
            writer.write_all(anchor)?;
        }
        Array::write(&mut writer, &self.spend_proofs, |w, proof| {
            w.write_all(&proof[..])
        })?;
        for sig in &self.spend_auth_sigs {
            sig.write(&mut writer)?;
        }
        Array::write(&mut writer, &self.output_proofs, |w, proof| {
            w.write_all(&proof[..])
        })?;
        match &self.binding_sig {
            Some(binding_sig) => binding_sig.write(&mut writer),
            None => Ok(()),
        }
    }

    /// Interprets this bundle as an authorized Sapling bundle.
    ///
    /// The value balance is not part of the v7 bundle encoding; it lives in
    /// `mValuePoolDeltas` and is supplied by the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle has no authorizing data, if a signature
    /// uses a sighash version other than 0, or if a field is invalid.
    #[cfg(feature = "sapling")]
    pub fn to_authorized(
        &self,
        value_balance: ZatBalance,
    ) -> io::Result<::sapling::bundle::Bundle<::sapling::bundle::Authorized, ZatBalance>> {
        use crate::transaction::components::sapling::{
            read_base, read_spend_auth_sig, read_zkproof,
        };

        if self.spends.is_empty() && self.outputs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "an empty Sapling bundle has no typed representation",
            ));
        }

        let binding_sig = self.binding_sig.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "v7 Sapling effecting data has no authorizing data",
            )
        })?;
        if !binding_sig.sighash_info().is_v0() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported Sapling binding signature sighash version",
            ));
        }

        let anchor = self
            .anchor
            .as_ref()
            .map(|anchor| read_base(&mut &anchor[..], "anchor"))
            .transpose()?;

        let spends = self
            .spends
            .iter()
            .zip(self.spend_proofs.iter().zip(self.spend_auth_sigs.iter()))
            .map(|(spend, (proof, sig))| {
                if !sig.sighash_info().is_v0() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported Sapling spend authorization sighash version",
                    ));
                }
                let spend = spend.to_spend_v5()?;
                let zkproof = read_zkproof(&mut &proof[..])?;
                let spend_auth_sig = read_spend_auth_sig(&mut &sig.signature()[..])?;
                Ok(spend.into_spend_description(
                    anchor.expect("a non-empty spend list has an anchor"),
                    zkproof,
                    spend_auth_sig,
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;

        let outputs = self
            .outputs
            .iter()
            .zip(self.output_proofs.iter())
            .map(|(output, proof)| {
                let output = output.to_output_v5()?;
                let zkproof = read_zkproof(&mut &proof[..])?;
                Ok(output.into_output_description(zkproof))
            })
            .collect::<io::Result<Vec<_>>>()?;

        Ok(::sapling::bundle::Bundle::from_parts(
            spends,
            outputs,
            value_balance,
            ::sapling::bundle::Authorized {
                binding_sig: redjubjub::Signature::from(*binding_sig.signature()),
            },
        )
        .expect("a non-empty Sapling bundle has a typed representation"))
    }
}

/// Reads a signed 64-bit value balance without narrowing it to the monetary
/// domain.
fn read_balance<R: Read>(mut reader: R) -> io::Result<i64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(i64::from_le_bytes(bytes))
}

#[cfg(feature = "sapling")]
fn value_balance_from_raw(value: i64) -> io::Result<ZatBalance> {
    ZatBalance::from_i64(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "valueBalance out of range"))
}
