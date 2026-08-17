use alloc::vec::Vec;
use core::mem::size_of;
use corez::io::{self, Read, Write};
use ff::PrimeField;

use ::sapling::{
    Nullifier,
    bundle::{
        Authorization, Authorized, Bundle, GrothProofBytes, OutputDescription, OutputDescriptionV5,
        SpendDescription, SpendDescriptionV5,
    },
    note::ExtractedNoteCommitment,
    note_encryption::Zip212Enforcement,
    value::ValueCommitment,
};
use redjubjub::SpendAuth;
use zcash_encoding::{Array, CompactSize, Vector};
use zcash_note_encryption::{ENC_CIPHERTEXT_SIZE, EphemeralKeyBytes, OUT_CIPHERTEXT_SIZE};
use zcash_protocol::{
    consensus::{BlockHeight, NetworkUpgrade, Parameters, ZIP212_GRACE_PERIOD},
    value::ZatBalance,
};

use super::GROTH_PROOF_SIZE;
use crate::transaction::Transaction;

/// The size in bytes of a Sapling spend description in its v4 (pre-NU5) serialized form, as
/// written by the internal `write_spend_v4` encoder.
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
/// The size in bytes of the encoding of a Sapling anchor (a Jubjub base field element).
const ANCHOR_BYTE_SIZE: usize = 32;
/// The size in bytes of the encoding of a Sapling extracted note commitment.
const CMU_BYTE_SIZE: usize = 32;
/// The size in bytes of the encoding of a Sapling ephemeral key.
const EPHEMERAL_KEY_BYTE_SIZE: usize = size_of::<EphemeralKeyBytes>();

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

/// The per-bundle overhead of a Sapling bundle, excluding the per-spend and per-output
/// data: CompactSize prefixes for the spends and outputs arrays (at most 9 + 9) +
/// value_balance (8) + anchor (32) + binding_sig (64).
pub const BUNDLE_OVERHEAD: usize = 9 + 9 + 8 + 32 + 64;

/// A map from one bundle authorization to another.
///
/// For use with [`TransactionData::map_authorization`].
///
/// [`TransactionData::map_authorization`]: crate::transaction::TransactionData::map_authorization
pub trait MapAuth<A: Authorization, B: Authorization> {
    fn map_spend_proof(&mut self, p: A::SpendProof) -> B::SpendProof;
    fn map_output_proof(&mut self, p: A::OutputProof) -> B::OutputProof;
    fn map_auth_sig(&mut self, s: A::AuthSig) -> B::AuthSig;
    fn map_authorization(&mut self, a: A) -> B;
}

/// The identity map.
///
/// This can be used with [`TransactionData::map_authorization`] when you want to map the
/// authorization of a subset of a transaction's bundles.
///
/// [`TransactionData::map_authorization`]: crate::transaction::TransactionData::map_authorization
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
///   bellman::groth16::Proof.
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
fn read_spend_auth_sig<R: Read>(mut reader: R) -> io::Result<redjubjub::Signature<SpendAuth>> {
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

fn read_spend_v4<R: Read>(mut reader: R) -> io::Result<SpendDescription<Authorized>> {
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

fn write_spend_v4<W: Write>(mut writer: W, spend: &SpendDescription<Authorized>) -> io::Result<()> {
    writer.write_all(&spend.cv().to_bytes())?;
    writer.write_all(spend.anchor().to_repr().as_ref())?;
    writer.write_all(&spend.nullifier().0)?;
    writer.write_all(&<[u8; 32]>::from(*spend.rk()))?;
    writer.write_all(spend.zkproof())?;
    writer.write_all(&<[u8; 64]>::from(*spend.spend_auth_sig()))
}

fn write_spend_v5_without_witness_data<W: Write>(
    mut writer: W,
    spend: &SpendDescription<Authorized>,
) -> io::Result<()> {
    writer.write_all(&spend.cv().to_bytes())?;
    writer.write_all(&spend.nullifier().0)?;
    writer.write_all(&<[u8; 32]>::from(*spend.rk()))
}

fn read_spend_v5<R: Read>(mut reader: &mut R) -> io::Result<SpendDescriptionV5> {
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

fn read_output_v4<R: Read>(mut reader: &mut R) -> io::Result<OutputDescription<GrothProofBytes>> {
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

pub(crate) fn write_output_v4<W: Write>(
    mut writer: W,
    output: &OutputDescription<GrothProofBytes>,
) -> io::Result<()> {
    writer.write_all(&output.cv().to_bytes())?;
    writer.write_all(output.cmu().to_bytes().as_ref())?;
    writer.write_all(output.ephemeral_key().as_ref())?;
    writer.write_all(output.enc_ciphertext())?;
    writer.write_all(output.out_ciphertext())?;
    writer.write_all(output.zkproof())
}

fn write_output_v5_without_proof<W: Write>(
    mut writer: W,
    output: &OutputDescription<GrothProofBytes>,
) -> io::Result<()> {
    writer.write_all(&output.cv().to_bytes())?;
    writer.write_all(output.cmu().to_bytes().as_ref())?;
    writer.write_all(output.ephemeral_key().as_ref())?;
    writer.write_all(output.enc_ciphertext())?;
    writer.write_all(output.out_ciphertext())
}

fn read_output_v5<R: Read>(mut reader: &mut R) -> io::Result<OutputDescriptionV5> {
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
        let vb = Transaction::read_amount(&mut reader)?;
        #[allow(clippy::redundant_closure)]
        let ss: Vec<SpendDescription<Authorized>> =
            Vector::read(&mut reader, |r| read_spend_v4(r))?;
        #[allow(clippy::redundant_closure)]
        let so: Vec<OutputDescription<GrothProofBytes>> =
            Vector::read(&mut reader, |r| read_output_v4(r))?;
        Ok((vb, ss, so))
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
pub(crate) fn write_v4_components<W: Write>(
    mut writer: W,
    bundle: Option<&Bundle<Authorized, ZatBalance>>,
    tx_has_sapling: bool,
) -> io::Result<()> {
    if tx_has_sapling {
        writer.write_all(
            &bundle
                .map_or(ZatBalance::zero(), |b| *b.value_balance())
                .to_i64_le_bytes(),
        )?;
        Vector::write(
            &mut writer,
            bundle.map_or(&[], |b| b.shielded_spends()),
            |w, e| write_spend_v4(w, e),
        )?;
        Vector::write(
            &mut writer,
            bundle.map_or(&[], |b| b.shielded_outputs()),
            |w, e| write_output_v4(w, e),
        )?;
    } else if bundle.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Sapling components may not be present if Sapling is not active.",
        ));
    }

    Ok(())
}

/// Reads a [`Bundle`] from a v5 transaction format.
#[allow(clippy::redundant_closure)]
pub(crate) fn read_v5_bundle<R: Read>(
    mut reader: R,
) -> io::Result<Option<Bundle<Authorized, ZatBalance>>> {
    let sd_v5s = Vector::read(&mut reader, read_spend_v5)?;
    let od_v5s = Vector::read(&mut reader, read_output_v5)?;
    let n_spends = sd_v5s.len();
    let n_outputs = od_v5s.len();
    let value_balance = if n_spends > 0 || n_outputs > 0 {
        Transaction::read_amount(&mut reader)?
    } else {
        ZatBalance::zero()
    };

    let anchor = if n_spends > 0 {
        Some(read_base(&mut reader, "anchor")?)
    } else {
        None
    };

    let v_spend_proofs = Array::read(&mut reader, n_spends, |r| read_zkproof(r))?;
    let v_spend_auth_sigs = Array::read(&mut reader, n_spends, |r| read_spend_auth_sig(r))?;
    let v_output_proofs = Array::read(&mut reader, n_outputs, |r| read_zkproof(r))?;

    let binding_sig = if n_spends > 0 || n_outputs > 0 {
        let mut sig = [0; 64];
        reader.read_exact(&mut sig)?;
        Some(redjubjub::Signature::from(sig))
    } else {
        None
    };

    let shielded_spends = sd_v5s
        .into_iter()
        .zip(v_spend_proofs.into_iter().zip(v_spend_auth_sigs))
        .map(|(sd_5, (zkproof, spend_auth_sig))| {
            // the following `unwrap` is safe because we know n_spends > 0.
            sd_5.into_spend_description(anchor.unwrap(), zkproof, spend_auth_sig)
        })
        .collect();

    let shielded_outputs = od_v5s
        .into_iter()
        .zip(v_output_proofs)
        .map(|(od_5, zkproof)| od_5.into_output_description(zkproof))
        .collect();

    Ok(binding_sig.and_then(|binding_sig| {
        Bundle::from_parts(
            shielded_spends,
            shielded_outputs,
            value_balance,
            Authorized { binding_sig },
        )
    }))
}

/// Writes a [`Bundle`] in the v5 transaction format.
pub(crate) fn write_v5_bundle<W: Write>(
    mut writer: W,
    sapling_bundle: Option<&Bundle<Authorized, ZatBalance>>,
) -> io::Result<()> {
    if let Some(bundle) = sapling_bundle {
        Vector::write(&mut writer, bundle.shielded_spends(), |w, e| {
            write_spend_v5_without_witness_data(w, e)
        })?;

        Vector::write(&mut writer, bundle.shielded_outputs(), |w, e| {
            write_output_v5_without_proof(w, e)
        })?;

        if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
            writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;
        }
        if !bundle.shielded_spends().is_empty() {
            writer.write_all(bundle.shielded_spends()[0].anchor().to_repr().as_ref())?;
        }

        Array::write(
            &mut writer,
            bundle.shielded_spends().iter().map(|s| &s.zkproof()[..]),
            |w, e| w.write_all(e),
        )?;
        Array::write(
            &mut writer,
            bundle.shielded_spends().iter().map(|s| s.spend_auth_sig()),
            |w, e| w.write_all(&<[u8; 64]>::from(**e)),
        )?;

        Array::write(
            &mut writer,
            bundle.shielded_outputs().iter().map(|s| &s.zkproof()[..]),
            |w, e| w.write_all(e),
        )?;

        if !(bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()) {
            writer.write_all(&<[u8; 64]>::from(bundle.authorization().binding_sig))?;
        }
    } else {
        CompactSize::write(&mut writer, 0)?;
        CompactSize::write(&mut writer, 0)?;
    }

    Ok(())
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
        SPEND_DESCRIPTION_SIZE, VALUE_COMMITMENT_BYTE_SIZE, testing::arb_bundle, write_output_v4,
        write_spend_v4,
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
                encoded_len(|w| write_spend_v4(w, spend)),
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
