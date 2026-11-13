use alloc::vec::Vec;
use core::mem::size_of;
#[cfg(any(
    all(feature = "sapling", feature = "orchard"),
    feature = "temporary-zcashd",
    test
))]
use corez::io::Write;
use corez::io::{self, Read};
use ff::PrimeField;

use ::sapling::{
    Nullifier,
    bundle::{
        Authorization, Authorized, Bundle, GrothProofBytes, OutputDescription, OutputDescriptionV5,
        SpendDescription, SpendDescriptionV5,
    },
    note::ExtractedNoteCommitment,
    note_encryption::{ENC_CIPHERTEXT_SIZE, Zip212Enforcement},
    value::ValueCommitment,
};
use redjubjub::SpendAuth;
use zcash_note_encryption::{EphemeralKeyBytes, OUT_CIPHERTEXT_SIZE};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters, ZIP212_GRACE_PERIOD};
use zcash_protocol::value::ZatBalance;

use super::GROTH_PROOF_SIZE;
#[cfg(zcash_unstable = "nu8")]
use crate::transaction::bytes::V7SaplingBundleBytes;
use crate::transaction::bytes::{
    SaplingBundleBytes, SaplingOutputBytes, SaplingOutputV4Bytes, SaplingSpendBytes,
    SaplingSpendV4Bytes, V4SaplingBundleBytes,
};

/// The size in bytes of a Sapling spend description in its v4 (pre-NU5) serialized form, as
/// written by [`SaplingSpendV4Bytes`].
///
/// This is the full per-spend cost on the wire in a version 4 transaction: the value
/// commitment, the anchor, the nullifier, the randomized spending key, the Groth16 proof,
/// and the spend authorization signature. Version 5 transactions move the proofs and
/// authorization signatures to bundle-level fields (the v5 spend encoder writes only
/// `cv` + `nullifier` + `rk`), so this v4 size is the conservative upper bound: dividing a
/// per-spend byte budget by this constant yields a lower bound on the number of spends
/// that fit within it.
pub const SPEND_DESCRIPTION_SIZE: usize = VALUE_COMMITMENT_BYTE_SIZE
    + ANCHOR_BYTE_SIZE
    + NULLIFIER_BYTE_SIZE
    + RK_BYTE_SIZE
    + GROTH_PROOF_SIZE
    + SPEND_AUTH_SIG_BYTE_SIZE;

/// The size in bytes of a Sapling output description in its v4 (pre-NU5) serialized form, as
/// written by the internal `write_output_v4` encoder.
///
/// This is the full per-output cost on the wire in a version 4 transaction: the value
/// commitment, the extracted note commitment, the ephemeral key, the encrypted note
/// ciphertext, the encrypted outgoing ciphertext, and the Groth16 proof. Version 5
/// transactions move the proofs to a bundle-level field (the v5 output encoder omits the
/// `zkproof`), so this v4 size is the conservative upper bound: dividing a per-output byte
/// budget by this constant yields a lower bound on the number of outputs that fit within it.
pub const OUTPUT_DESCRIPTION_SIZE: usize = VALUE_COMMITMENT_BYTE_SIZE
    + CMU_BYTE_SIZE
    + EPHEMERAL_KEY_BYTE_SIZE
    + ENC_CIPHERTEXT_SIZE
    + OUT_CIPHERTEXT_SIZE
    + GROTH_PROOF_SIZE;

/// The size in bytes of the encoding of a Sapling value commitment (a Jubjub group element).
const VALUE_COMMITMENT_BYTE_SIZE: usize = 32;
/// The size in bytes of the encoding of a Sapling nullifier.
const NULLIFIER_BYTE_SIZE: usize = 32;
/// The size in bytes of the encoding of a Sapling spend authorization key (a RedJubjub
/// verification key).
const RK_BYTE_SIZE: usize = 32;
/// The size in bytes of the encoding of a Sapling spend authorization signature.
const SPEND_AUTH_SIG_BYTE_SIZE: usize = 64;
/// The size in bytes of the encoding of a Sapling binding signature.
const BINDING_SIG_BYTE_SIZE: usize = 64;
/// The size in bytes of the encoding of a Sapling anchor (a Jubjub base field element).
const ANCHOR_BYTE_SIZE: usize = 32;
/// The size in bytes of the encoding of a Sapling extracted note commitment.
const CMU_BYTE_SIZE: usize = 32;
/// The size in bytes of the encoding of a Sapling ephemeral key.
const EPHEMERAL_KEY_BYTE_SIZE: usize = size_of::<EphemeralKeyBytes>();

/// The per-bundle overhead of a Sapling bundle, excluding the per-spend and per-output
/// data: CompactSize prefixes for the spends and outputs arrays (at most 9 + 9) +
/// value_balance (8) + anchor (32) + binding_sig (64).
pub const BUNDLE_OVERHEAD: usize = 9 + 9 + 8 + 32 + 64;

/// Returns the enforcement policy for ZIP 212 at the given height.
pub fn zip212_enforcement(params: &impl Parameters, height: BlockHeight) -> Zip212Enforcement {
    if params.is_nu_active(NetworkUpgrade::Canopy, height) {
        let grace_period_end_height =
            params.activation_height(NetworkUpgrade::Canopy).unwrap() + ZIP212_GRACE_PERIOD;

        if height < grace_period_end_height {
            Zip212Enforcement::GracePeriod
        } else {
            Zip212Enforcement::On
        }
    } else {
        Zip212Enforcement::Off
    }
}

/// A map from one bundle authorization to another.
///
/// For use with `TransactionData::map_authorization`.
pub trait MapAuth<A: Authorization, B: Authorization> {
    fn map_spend_proof(&mut self, p: A::SpendProof) -> B::SpendProof;
    fn map_output_proof(&mut self, p: A::OutputProof) -> B::OutputProof;
    fn map_auth_sig(&mut self, s: A::AuthSig) -> B::AuthSig;
    fn map_authorization(&mut self, a: A) -> B;
}

/// The identity map.
///
/// This can be used with `TransactionData::map_authorization` when you want to map the
/// authorization of a subset of a transaction's bundles.
impl MapAuth<Authorized, Authorized> for () {
    fn map_spend_proof(
        &mut self,
        p: <Authorized as Authorization>::SpendProof,
    ) -> <Authorized as Authorization>::SpendProof {
        p
    }

    fn map_output_proof(
        &mut self,
        p: <Authorized as Authorization>::OutputProof,
    ) -> <Authorized as Authorization>::OutputProof {
        p
    }

    fn map_auth_sig(
        &mut self,
        s: <Authorized as Authorization>::AuthSig,
    ) -> <Authorized as Authorization>::AuthSig {
        s
    }

    fn map_authorization(&mut self, a: Authorized) -> Authorized {
        a
    }
}

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
pub fn read_base<R: Read>(mut reader: R, _field: &str) -> io::Result<jubjub::Base> {
    let mut f = [0u8; 32];
    reader.read_exact(&mut f)?;
    Option::from(jubjub::Base::from_repr(f)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "base value not a valid field element",
        )
    })
}

/// Consensus rules (§4.4) & (§4.5):
/// - Canonical encoding is enforced by the API of SaplingVerificationContext::check_spend()
///   and SaplingVerificationContext::check_output() due to the need to parse this into a
///   groth16::Proof.
/// - Proof validity is enforced in SaplingVerificationContext::check_spend()
///   and SaplingVerificationContext::check_output()
pub fn read_zkproof<R: Read>(mut reader: R) -> io::Result<GrothProofBytes> {
    let mut zkproof = [0u8; GROTH_PROOF_SIZE];
    reader.read_exact(&mut zkproof)?;
    Ok(zkproof)
}

fn read_nullifier<R: Read>(mut reader: R) -> io::Result<Nullifier> {
    let mut nullifier = Nullifier([0u8; 32]);
    reader.read_exact(&mut nullifier.0)?;
    Ok(nullifier)
}

/// Consensus rules (§4.4):
/// - Canonical encoding is enforced here.
/// - "Not small order" is enforced in SaplingVerificationContext::check_spend()
fn read_rk<R: Read>(mut reader: R) -> io::Result<redjubjub::VerificationKey<SpendAuth>> {
    let mut bytes = [0; 32];
    reader.read_exact(&mut bytes)?;
    redjubjub::VerificationKey::try_from(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "verification key is invalid"))
}

/// Consensus rules (§4.4):
/// - Canonical encoding is enforced here.
/// - Signature validity is enforced in SaplingVerificationContext::check_spend()
pub(crate) fn read_spend_auth_sig<R: Read>(
    mut reader: R,
) -> io::Result<redjubjub::Signature<SpendAuth>> {
    let mut sig = [0; 64];
    reader.read_exact(&mut sig)?;
    Ok(redjubjub::Signature::from(sig))
}

#[cfg(feature = "temporary-zcashd")]
pub fn temporary_zcashd_read_spend_v4<R: Read>(
    reader: R,
) -> io::Result<SpendDescription<Authorized>> {
    read_spend_v4(reader)
}

pub(crate) fn read_spend_v4<R: Read>(mut reader: R) -> io::Result<SpendDescription<Authorized>> {
    // Consensus rules (§4.4) & (§4.5):
    // - Canonical encoding is enforced here.
    // - "Not small order" is enforced in SaplingVerificationContext::(check_spend()/check_output())
    //   (located in zcash_proofs::sapling::verifier).
    let cv = read_value_commitment(&mut reader)?;
    // Consensus rules (§7.3) & (§7.4):
    // - Canonical encoding is enforced here
    let anchor = read_base(&mut reader, "anchor")?;
    let nullifier = read_nullifier(&mut reader)?;
    let rk = read_rk(&mut reader)?;
    let zkproof = read_zkproof(&mut reader)?;
    let spend_auth_sig = read_spend_auth_sig(&mut reader)?;

    Ok(SpendDescription::from_parts(
        cv,
        anchor,
        nullifier,
        rk,
        zkproof,
        spend_auth_sig,
    ))
}

pub(crate) fn read_spend_v5<R: Read>(mut reader: &mut R) -> io::Result<SpendDescriptionV5> {
    let cv = read_value_commitment(&mut reader)?;
    let nullifier = read_nullifier(&mut reader)?;
    let rk = read_rk(&mut reader)?;

    Ok(SpendDescriptionV5::from_parts(cv, nullifier, rk))
}

#[cfg(feature = "temporary-zcashd")]
pub fn temporary_zcashd_read_output_v4<R: Read>(
    mut reader: R,
) -> io::Result<OutputDescription<GrothProofBytes>> {
    read_output_v4(&mut reader)
}

pub(crate) fn read_output_v4<R: Read>(
    mut reader: &mut R,
) -> io::Result<OutputDescription<GrothProofBytes>> {
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

    let mut enc_ciphertext = [0u8; ENC_CIPHERTEXT_SIZE];
    let mut out_ciphertext = [0u8; OUT_CIPHERTEXT_SIZE];
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

#[cfg(feature = "temporary-zcashd")]
pub fn temporary_zcashd_write_output_v4<W: Write>(
    writer: W,
    output: &OutputDescription<GrothProofBytes>,
) -> io::Result<()> {
    write_output_v4(writer, output)
}

#[cfg(any(
    all(feature = "sapling", feature = "orchard"),
    feature = "temporary-zcashd",
    test
))]
pub(crate) fn write_output_v4<W: Write>(
    writer: W,
    output: &OutputDescription<GrothProofBytes>,
) -> io::Result<()> {
    SaplingOutputV4Bytes::from_output_v4(output).write(writer)
}

pub(crate) fn read_output_v5<R: Read>(mut reader: &mut R) -> io::Result<OutputDescriptionV5> {
    let cv = read_value_commitment(&mut reader)?;
    let cmu = read_cmu(&mut reader)?;

    // Consensus rules (§4.5):
    // - Canonical encoding is enforced in librustzcash_sapling_check_output by zcashd
    // - "Not small order" is enforced in SaplingVerificationContext::check_output()
    let mut ephemeral_key = EphemeralKeyBytes([0u8; 32]);
    reader.read_exact(&mut ephemeral_key.0)?;

    let mut enc_ciphertext = [0u8; ENC_CIPHERTEXT_SIZE];
    let mut out_ciphertext = [0u8; OUT_CIPHERTEXT_SIZE];
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

impl SaplingSpendBytes {
    /// Interprets this effecting data as a version 5 Sapling spend description.
    ///
    /// The value commitment, nullifier, and randomized validating key are
    /// validated by the same decoders used for the v5 wire format.
    pub(crate) fn to_spend_v5(&self) -> io::Result<SpendDescriptionV5> {
        let mut bytes =
            Vec::with_capacity(VALUE_COMMITMENT_BYTE_SIZE + NULLIFIER_BYTE_SIZE + RK_BYTE_SIZE);
        self.write(&mut bytes)?;
        read_spend_v5(&mut &bytes[..])
    }
}

impl SaplingOutputBytes {
    /// Interprets this output description as a version 5 Sapling output.
    ///
    /// The value commitment, note commitment, and ciphertexts are validated by
    /// the same decoders used for the v5 wire format.
    pub(crate) fn to_output_v5(&self) -> io::Result<OutputDescriptionV5> {
        let mut bytes = Vec::with_capacity(
            VALUE_COMMITMENT_BYTE_SIZE
                + CMU_BYTE_SIZE
                + EPHEMERAL_KEY_BYTE_SIZE
                + ENC_CIPHERTEXT_SIZE
                + OUT_CIPHERTEXT_SIZE,
        );
        self.write(&mut bytes)?;
        read_output_v5(&mut &bytes[..])
    }
}

impl SaplingSpendV4Bytes {
    /// Interprets this description as a version 4 Sapling spend.
    ///
    /// The value commitment, anchor, nullifier, and randomized validating key
    /// are validated by the same decoder used for the v4 wire format.
    pub(crate) fn to_spend_v4(&self) -> io::Result<SpendDescription<Authorized>> {
        let mut bytes = Vec::with_capacity(SPEND_DESCRIPTION_SIZE);
        self.write(&mut bytes)?;
        read_spend_v4(&mut &bytes[..])
    }
}

impl SaplingOutputV4Bytes {
    /// Interprets this description as a version 4 Sapling output.
    ///
    /// The value commitment and note commitment are validated by the same
    /// decoder used for the v4 wire format.
    pub(crate) fn to_output_v4(&self) -> io::Result<OutputDescription<GrothProofBytes>> {
        let mut bytes = Vec::with_capacity(OUTPUT_DESCRIPTION_SIZE);
        self.write(&mut bytes)?;
        read_output_v4(&mut &bytes[..])
    }
}

impl V4SaplingBundleBytes {
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
    pub fn to_authorized(
        &self,
        binding_sig: Option<[u8; BINDING_SIG_BYTE_SIZE]>,
    ) -> io::Result<Option<Bundle<Authorized, ZatBalance>>> {
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
            .spends()
            .iter()
            .map(SaplingSpendV4Bytes::to_spend_v4)
            .collect::<io::Result<Vec<_>>>()?;
        let outputs = self
            .outputs()
            .iter()
            .map(SaplingOutputV4Bytes::to_output_v4)
            .collect::<io::Result<Vec<_>>>()?;

        Ok(Bundle::from_parts(
            spends,
            outputs,
            value_balance_from_raw(self.value_balance())?,
            Authorized {
                binding_sig: redjubjub::Signature::from(binding_sig),
            },
        ))
    }
}

impl SaplingBundleBytes {
    /// Interprets this bundle as an authorized Sapling bundle.
    ///
    /// The value balance, anchor, proofs, and signatures are validated by the
    /// same decoders used for the v5 wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle is empty, or if a field is invalid.
    pub fn to_authorized(&self) -> io::Result<Bundle<Authorized, ZatBalance>> {
        if self.spends().is_empty() && self.outputs().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "an empty Sapling bundle has no typed representation",
            ));
        }

        let anchor = self
            .anchor()
            .map(|anchor| read_base(&mut &anchor[..], "anchor"))
            .transpose()?;

        let spends = self
            .spends()
            .iter()
            .zip(
                self.spend_proofs()
                    .iter()
                    .zip(self.spend_auth_sigs().iter()),
            )
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
            .outputs()
            .iter()
            .zip(self.output_proofs().iter())
            .map(|(output, proof)| {
                let output = output.to_output_v5()?;
                let zkproof = read_zkproof(&mut &proof[..])?;
                Ok(output.into_output_description(zkproof))
            })
            .collect::<io::Result<Vec<_>>>()?;

        let binding_sig = self.binding_sig().copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "a non-empty Sapling bundle requires a binding signature",
            )
        })?;

        Ok(Bundle::from_parts(
            spends,
            outputs,
            value_balance_from_raw(self.value_balance())?,
            Authorized {
                binding_sig: redjubjub::Signature::from(binding_sig),
            },
        )
        .expect("a non-empty Sapling bundle has a typed representation"))
    }
}

#[cfg(zcash_unstable = "nu8")]
impl V7SaplingBundleBytes {
    /// Interprets this bundle as an authorized Sapling bundle.
    ///
    /// The value balance is not part of the v7 bundle encoding; it lives in
    /// `mValuePoolDeltas` and is supplied by the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle has no authorizing data, if a signature
    /// uses a sighash version other than 0, or if a field is invalid.
    pub fn to_authorized(
        &self,
        value_balance: ZatBalance,
    ) -> io::Result<Bundle<Authorized, ZatBalance>> {
        if self.spends().is_empty() && self.outputs().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "an empty Sapling bundle has no typed representation",
            ));
        }

        let binding_sig = self.binding_sig().ok_or_else(|| {
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
            .anchor()
            .map(|anchor| read_base(&mut &anchor[..], "anchor"))
            .transpose()?;

        let spends = self
            .spends()
            .iter()
            .zip(
                self.spend_proofs()
                    .iter()
                    .zip(self.spend_auth_sigs().iter()),
            )
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
            .outputs()
            .iter()
            .zip(self.output_proofs().iter())
            .map(|(output, proof)| {
                let output = output.to_output_v5()?;
                let zkproof = read_zkproof(&mut &proof[..])?;
                Ok(output.into_output_description(zkproof))
            })
            .collect::<io::Result<Vec<_>>>()?;

        Ok(Bundle::from_parts(
            spends,
            outputs,
            value_balance,
            Authorized {
                binding_sig: redjubjub::Signature::from(*binding_sig.signature()),
            },
        )
        .expect("a non-empty Sapling bundle has a typed representation"))
    }
}

/// Reads the Sapling components of a v4 transaction.
#[cfg(feature = "temporary-zcashd")]
#[allow(clippy::type_complexity)]
pub fn temporary_zcashd_read_v4_components<R: Read>(
    reader: R,
    tx_has_sapling: bool,
) -> io::Result<(
    ZatBalance,
    Vec<SpendDescription<Authorized>>,
    Vec<OutputDescription<GrothProofBytes>>,
)> {
    read_v4_components(reader, tx_has_sapling)
}

/// Reads the Sapling components of a v4 transaction.
#[cfg(feature = "temporary-zcashd")]
#[allow(clippy::type_complexity)]
pub(crate) fn read_v4_components<R: Read>(
    mut reader: R,
    tx_has_sapling: bool,
) -> io::Result<(
    ZatBalance,
    Vec<SpendDescription<Authorized>>,
    Vec<OutputDescription<GrothProofBytes>>,
)> {
    if tx_has_sapling {
        let bundle = V4SaplingBundleBytes::read(&mut reader)?;
        let value_balance = value_balance_from_raw(bundle.value_balance())?;
        let spends = bundle
            .spends()
            .iter()
            .map(SaplingSpendV4Bytes::to_spend_v4)
            .collect::<io::Result<Vec<_>>>()?;
        let outputs = bundle
            .outputs()
            .iter()
            .map(SaplingOutputV4Bytes::to_output_v4)
            .collect::<io::Result<Vec<_>>>()?;
        Ok((value_balance, spends, outputs))
    } else {
        Ok((ZatBalance::zero(), vec![], vec![]))
    }
}

/// Writes the Sapling components of a v4 transaction.
#[cfg(feature = "temporary-zcashd")]
pub fn temporary_zcashd_write_v4_components<W: Write>(
    writer: W,
    bundle: Option<&Bundle<Authorized, ZatBalance>>,
    tx_has_sapling: bool,
) -> io::Result<()> {
    write_v4_components(writer, bundle, tx_has_sapling)
}

/// Writes the Sapling components of a v4 transaction.
#[cfg(feature = "temporary-zcashd")]
pub(crate) fn write_v4_components<W: Write>(
    mut writer: W,
    bundle: Option<&Bundle<Authorized, ZatBalance>>,
    tx_has_sapling: bool,
) -> io::Result<()> {
    if tx_has_sapling {
        let bytes = match bundle {
            Some(bundle) => V4SaplingBundleBytes::from_bundle(bundle),
            None => V4SaplingBundleBytes::from_parts(
                i64::from_le_bytes(ZatBalance::zero().to_i64_le_bytes()),
                vec![],
                vec![],
            ),
        };
        bytes.write(&mut writer)
    } else if bundle.is_some() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Sapling components may not be present if Sapling is not active.",
        ))
    } else {
        Ok(())
    }
}

/// Reads a [`Bundle`] from a v5 transaction format.
#[cfg(all(feature = "sapling", feature = "orchard", feature = "temporary-zcashd"))]
#[allow(clippy::redundant_closure)]
pub(crate) fn read_v5_bundle<R: Read>(
    mut reader: R,
) -> io::Result<Option<Bundle<Authorized, ZatBalance>>> {
    SaplingBundleBytes::read(&mut reader)?
        .map(|bundle| bundle.to_authorized())
        .transpose()
}

/// Writes a [`Bundle`] in the v5 transaction format.
#[cfg(any(all(feature = "sapling", feature = "orchard"), test))]
pub(crate) fn write_v5_bundle<W: Write>(
    mut writer: W,
    sapling_bundle: Option<&Bundle<Authorized, ZatBalance>>,
) -> io::Result<()> {
    let bytes = sapling_bundle.map(SaplingBundleBytes::from_bundle);
    SaplingBundleBytes::write_opt(&mut writer, bytes.as_ref())
}

fn value_balance_from_raw(value: i64) -> io::Result<ZatBalance> {
    ZatBalance::from_i64(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "valueBalance out of range"))
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use crate::transaction::TxVersion;
    use ::sapling::bundle::{Authorized, Bundle, testing as t_sap};
    use zcash_protocol::value::{ZatBalance, testing::arb_zat_balance};

    prop_compose! {
        pub fn arb_bundle()(
            value_balance in arb_zat_balance()
        )(
            bundle in t_sap::arb_bundle(value_balance)
        ) -> Option<Bundle<Authorized, ZatBalance>> {
            bundle
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<Bundle<Authorized, ZatBalance>>> {
        if v.has_sapling() {
            Strategy::boxed(arb_bundle())
        } else {
            Strategy::boxed(Just(None))
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use corez::io::{self, Write};
    use proptest::prelude::*;

    use super::{
        ANCHOR_BYTE_SIZE, CMU_BYTE_SIZE, EPHEMERAL_KEY_BYTE_SIZE, GROTH_PROOF_SIZE,
        NULLIFIER_BYTE_SIZE, OUTPUT_DESCRIPTION_SIZE, RK_BYTE_SIZE, SPEND_AUTH_SIG_BYTE_SIZE,
        SPEND_DESCRIPTION_SIZE, SaplingSpendV4Bytes, VALUE_COMMITMENT_BYTE_SIZE,
        testing::arb_bundle, write_output_v4,
    };
    use ff::PrimeField;

    // Returns the number of bytes `write` emits.
    fn encoded_len(write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> usize {
        let mut buf = Vec::new();
        write(&mut buf).expect("writing to a Vec cannot fail");
        buf.len()
    }

    proptest! {
        /// `SPEND_DESCRIPTION_SIZE` is what callers divide a per-spend byte budget by to bound a
        /// spend count, so it must equal what the v4 encoder actually writes, not merely what the
        /// constant's own arithmetic says. Measure a real spend description rather than restating
        /// the composition, so that a change to any element's encoding fails here.
        ///
        /// This is also what keeps the per-element sizes honest while `sapling` exposes none of
        /// them itself: each is checked against the encoding of the field it describes. The v4
        /// form is used (rather than v5) because it carries every per-spend byte inline, making it
        /// the conservative upper bound for size budgeting.
        #[test]
        fn spend_description_size_matches_the_encoding(
            bundle in arb_bundle().prop_filter("bundle has spends", |b| {
                b.as_ref().is_some_and(|b| !b.shielded_spends().is_empty())
            }),
        ) {
            let bundle = bundle.unwrap();
            let spend = &bundle.shielded_spends()[0];
            prop_assert_eq!(
                encoded_len(|w| SaplingSpendV4Bytes::from_spend_v4(spend).write(w)),
                SPEND_DESCRIPTION_SIZE
            );

            // Each element, against the constant that names it.
            prop_assert_eq!(
                encoded_len(|w| w.write_all(&spend.cv().to_bytes())),
                VALUE_COMMITMENT_BYTE_SIZE
            );
            prop_assert_eq!(
                encoded_len(|w| w.write_all(spend.anchor().to_repr().as_ref())),
                ANCHOR_BYTE_SIZE
            );
            prop_assert_eq!(
                encoded_len(|w| w.write_all(&spend.nullifier().0)),
                NULLIFIER_BYTE_SIZE
            );
            prop_assert_eq!(
                encoded_len(|w| w.write_all(&<[u8; 32]>::from(*spend.rk()))),
                RK_BYTE_SIZE
            );
            prop_assert_eq!(
                encoded_len(|w| w.write_all(spend.zkproof())),
                GROTH_PROOF_SIZE
            );
            prop_assert_eq!(
                encoded_len(|w| w.write_all(&<[u8; 64]>::from(*spend.spend_auth_sig()))),
                SPEND_AUTH_SIG_BYTE_SIZE
            );
        }

        /// `OUTPUT_DESCRIPTION_SIZE` is what callers divide a per-output byte budget by to bound an
        /// output count, so it must equal what the v4 encoder actually writes. See
        /// `spend_description_size_matches_the_encoding` for the rationale.
        #[test]
        fn output_description_size_matches_the_encoding(
            bundle in arb_bundle().prop_filter("bundle has outputs", |b| {
                b.as_ref().is_some_and(|b| !b.shielded_outputs().is_empty())
            }),
        ) {
            let bundle = bundle.unwrap();
            let output = &bundle.shielded_outputs()[0];
            prop_assert_eq!(
                encoded_len(|w| write_output_v4(w, output)),
                OUTPUT_DESCRIPTION_SIZE
            );

            // Each element, against the constant that names it.
            prop_assert_eq!(
                encoded_len(|w| w.write_all(&output.cv().to_bytes())),
                VALUE_COMMITMENT_BYTE_SIZE
            );
            prop_assert_eq!(
                encoded_len(|w| w.write_all(output.cmu().to_bytes().as_ref())),
                CMU_BYTE_SIZE
            );
            prop_assert_eq!(
                encoded_len(|w| w.write_all(output.ephemeral_key().as_ref())),
                EPHEMERAL_KEY_BYTE_SIZE
            );
            prop_assert_eq!(
                encoded_len(|w| w.write_all(output.zkproof())),
                GROTH_PROOF_SIZE
            );
        }
    }
}
