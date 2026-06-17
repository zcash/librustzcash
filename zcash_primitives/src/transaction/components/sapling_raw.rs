//! Parsing and serialization of the Sapling components of a transaction when the `sapling`
//! feature is disabled.
//!
//! When the `sapling` feature is not enabled, the `sapling` crate is not compiled, so a
//! transaction's Sapling bundle cannot be converted into the typed [`sapling::Bundle`]
//! domain representation. These functions parse the exact same binary wire format as the
//! typed path, retaining the parsed bytes in [`RawSaplingBundle`] so that the transaction
//! can be re-serialized byte-identically and its consensus txid / authorizing-data digests
//! computed (see [`crate::transaction::txid`]).
//!
//! Canonical field-element (`cmu`, `anchor`), value-commitment (`cv`, "not small order"),
//! and verification-key (`rk`) encodings are validated here using `jubjub` and `redjubjub`,
//! which are always compiled, so parse-rejection of malformed Sapling encodings matches the
//! typed path exactly.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use ff::PrimeField;

use redjubjub::SpendAuth;
use zcash_encoding::{Array, CompactSize, Vector};
use zcash_protocol::value::ZatBalance;

use super::GROTH_PROOF_SIZE;
use crate::transaction::Transaction;

const ENC_CIPHERTEXT_SIZE: usize = 580;
const OUT_CIPHERTEXT_SIZE: usize = 80;

/// A parsed-but-unconverted Sapling spend description.
///
/// Holds the raw wire bytes of a v4 or v5 Sapling spend description. The `anchor` is stored
/// per-spend (as in the v4 format); for v5 transactions, which encode a single shared
/// anchor, that anchor is replicated into each spend.
#[derive(Clone, Debug)]
pub struct RawSaplingSpend {
    pub(crate) cv: [u8; 32],
    pub(crate) anchor: [u8; 32],
    pub(crate) nullifier: [u8; 32],
    pub(crate) rk: [u8; 32],
    pub(crate) zkproof: [u8; GROTH_PROOF_SIZE],
    pub(crate) spend_auth_sig: [u8; 64],
}

/// A parsed-but-unconverted Sapling output description.
#[derive(Clone, Debug)]
pub struct RawSaplingOutput {
    pub(crate) cv: [u8; 32],
    pub(crate) cmu: [u8; 32],
    pub(crate) ephemeral_key: [u8; 32],
    pub(crate) enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    pub(crate) out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    pub(crate) zkproof: [u8; GROTH_PROOF_SIZE],
}

/// A parsed-but-unconverted Sapling bundle.
///
/// This is the representation of a transaction's Sapling bundle used when the `sapling`
/// feature is disabled. It retains exactly the data required to re-serialize the bundle
/// byte-identically and to compute the ZIP 244 txid and authorizing-data digests.
#[derive(Clone, Debug)]
pub struct RawSaplingBundle {
    spends: Vec<RawSaplingSpend>,
    outputs: Vec<RawSaplingOutput>,
    value_balance: ZatBalance,
    binding_sig: [u8; 64],
}

impl RawSaplingBundle {
    /// Constructs a bundle from its constituent parts, returning `None` if it would contain
    /// neither spends nor outputs (matching `sapling::Bundle::from_parts`).
    fn from_parts(
        spends: Vec<RawSaplingSpend>,
        outputs: Vec<RawSaplingOutput>,
        value_balance: ZatBalance,
        binding_sig: [u8; 64],
    ) -> Option<Self> {
        if spends.is_empty() && outputs.is_empty() {
            None
        } else {
            Some(RawSaplingBundle {
                spends,
                outputs,
                value_balance,
                binding_sig,
            })
        }
    }

    pub(crate) fn shielded_spends(&self) -> &[RawSaplingSpend] {
        &self.spends
    }

    pub(crate) fn shielded_outputs(&self) -> &[RawSaplingOutput] {
        &self.outputs
    }

    pub(crate) fn value_balance(&self) -> &ZatBalance {
        &self.value_balance
    }

    pub(crate) fn binding_sig(&self) -> &[u8; 64] {
        &self.binding_sig
    }
}

/// Reads a value commitment, enforcing canonical encoding and rejecting small-order points
/// (matching `sapling::value::ValueCommitment::from_bytes_not_small_order`).
fn read_cv<R: Read>(mut reader: R) -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    // Matches `sapling::value::ValueCommitment::from_bytes_not_small_order`, which decodes the
    // canonical Jubjub point encoding and rejects small-order points.
    let affine = jubjub::AffinePoint::from_bytes(bytes);
    if affine.is_none().into() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid cv"));
    }
    let cv = jubjub::ExtendedPoint::from(affine.unwrap());
    if bool::from(cv.is_small_order()) {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid cv"))
    } else {
        Ok(bytes)
    }
}

/// Reads a base field element (`cmu` or `anchor`), enforcing canonical encoding (matching
/// `jubjub::Base::from_repr`, as used by `ExtractedNoteCommitment::from_bytes`).
fn read_base<R: Read>(mut reader: R) -> io::Result<[u8; 32]> {
    let mut f = [0u8; 32];
    reader.read_exact(&mut f)?;
    if Option::<jubjub::Base>::from(jubjub::Base::from_repr(f)).is_none() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "base value not a valid field element",
        ))
    } else {
        Ok(f)
    }
}

/// Reads a randomized verification key, enforcing canonical encoding (matching
/// `redjubjub::VerificationKey::<SpendAuth>::try_from`).
fn read_rk<R: Read>(mut reader: R) -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    redjubjub::VerificationKey::<SpendAuth>::try_from(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "verification key is invalid"))?;
    Ok(bytes)
}

fn read_zkproof<R: Read>(mut reader: R) -> io::Result<[u8; GROTH_PROOF_SIZE]> {
    let mut zkproof = [0u8; GROTH_PROOF_SIZE];
    reader.read_exact(&mut zkproof)?;
    Ok(zkproof)
}

fn read_array<const N: usize, R: Read>(mut reader: R) -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_spend_v4<R: Read>(mut reader: R) -> io::Result<RawSaplingSpend> {
    let cv = read_cv(&mut reader)?;
    let anchor = read_base(&mut reader)?;
    let nullifier = read_array(&mut reader)?;
    let rk = read_rk(&mut reader)?;
    let zkproof = read_zkproof(&mut reader)?;
    let spend_auth_sig = read_array(&mut reader)?;
    Ok(RawSaplingSpend {
        cv,
        anchor,
        nullifier,
        rk,
        zkproof,
        spend_auth_sig,
    })
}

fn write_spend_v4<W: Write>(mut writer: W, spend: &RawSaplingSpend) -> io::Result<()> {
    writer.write_all(&spend.cv)?;
    writer.write_all(&spend.anchor)?;
    writer.write_all(&spend.nullifier)?;
    writer.write_all(&spend.rk)?;
    writer.write_all(&spend.zkproof)?;
    writer.write_all(&spend.spend_auth_sig)
}

fn read_output_v4<R: Read>(mut reader: R) -> io::Result<RawSaplingOutput> {
    let cv = read_cv(&mut reader)?;
    let cmu = read_base(&mut reader)?;
    let ephemeral_key = read_array(&mut reader)?;
    let enc_ciphertext = read_array(&mut reader)?;
    let out_ciphertext = read_array(&mut reader)?;
    let zkproof = read_zkproof(&mut reader)?;
    Ok(RawSaplingOutput {
        cv,
        cmu,
        ephemeral_key,
        enc_ciphertext,
        out_ciphertext,
        zkproof,
    })
}

fn write_output_v4<W: Write>(mut writer: W, output: &RawSaplingOutput) -> io::Result<()> {
    writer.write_all(&output.cv)?;
    writer.write_all(&output.cmu)?;
    writer.write_all(&output.ephemeral_key)?;
    writer.write_all(&output.enc_ciphertext)?;
    writer.write_all(&output.out_ciphertext)?;
    writer.write_all(&output.zkproof)
}

/// Reads the Sapling components of a v4 transaction.
#[allow(clippy::type_complexity)]
pub(crate) fn read_v4_components<R: Read>(
    mut reader: R,
    tx_has_sapling: bool,
) -> io::Result<(ZatBalance, Vec<RawSaplingSpend>, Vec<RawSaplingOutput>)> {
    if tx_has_sapling {
        let vb = Transaction::read_amount(&mut reader)?;
        #[allow(clippy::redundant_closure)]
        let ss = Vector::read(&mut reader, |r| read_spend_v4(r))?;
        #[allow(clippy::redundant_closure)]
        let so = Vector::read(&mut reader, |r| read_output_v4(r))?;
        Ok((vb, ss, so))
    } else {
        Ok((ZatBalance::zero(), vec![], vec![]))
    }
}

/// Assembles a v4 Sapling bundle from its parsed components and (separately-read) binding
/// signature, returning `None` when there is no bundle.
pub(crate) fn build_v4_bundle(
    value_balance: ZatBalance,
    spends: Vec<RawSaplingSpend>,
    outputs: Vec<RawSaplingOutput>,
    binding_sig: Option<[u8; 64]>,
) -> Option<RawSaplingBundle> {
    binding_sig.and_then(|binding_sig| {
        RawSaplingBundle::from_parts(spends, outputs, value_balance, binding_sig)
    })
}

/// Writes the Sapling components of a v4 transaction.
pub(crate) fn write_v4_components<W: Write>(
    mut writer: W,
    bundle: Option<&RawSaplingBundle>,
    tx_has_sapling: bool,
) -> io::Result<()> {
    if tx_has_sapling {
        writer.write_all(
            &bundle
                .map_or(ZatBalance::zero(), |b| b.value_balance)
                .to_i64_le_bytes(),
        )?;
        Vector::write(
            &mut writer,
            bundle.map_or(&[][..], |b| &b.spends),
            |w, e| write_spend_v4(w, e),
        )?;
        Vector::write(
            &mut writer,
            bundle.map_or(&[][..], |b| &b.outputs),
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

/// Reads a Sapling bundle from a v5 transaction format.
pub(crate) fn read_v5_bundle<R: Read>(mut reader: R) -> io::Result<Option<RawSaplingBundle>> {
    let sd_v5s: Vec<([u8; 32], [u8; 32], [u8; 32])> = Vector::read(&mut reader, |r| {
        let cv = read_cv(&mut *r)?;
        let nullifier = read_array(&mut *r)?;
        let rk = read_rk(&mut *r)?;
        Ok((cv, nullifier, rk))
    })?;
    let od_v5s: Vec<RawSaplingOutput> = Vector::read(&mut reader, |r| {
        let cv = read_cv(&mut *r)?;
        let cmu = read_base(&mut *r)?;
        let ephemeral_key = read_array(&mut *r)?;
        let enc_ciphertext = read_array(&mut *r)?;
        let out_ciphertext = read_array(&mut *r)?;
        Ok(RawSaplingOutput {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            // Filled in from the separately-encoded output proofs below.
            zkproof: [0u8; GROTH_PROOF_SIZE],
        })
    })?;
    let n_spends = sd_v5s.len();
    let n_outputs = od_v5s.len();
    let value_balance = if n_spends > 0 || n_outputs > 0 {
        Transaction::read_amount(&mut reader)?
    } else {
        ZatBalance::zero()
    };

    let anchor = if n_spends > 0 {
        Some(read_base(&mut reader)?)
    } else {
        None
    };

    #[allow(clippy::redundant_closure)]
    let v_spend_proofs = Array::read(&mut reader, n_spends, |r| read_zkproof(r))?;
    let v_spend_auth_sigs = Array::read(&mut reader, n_spends, |r| read_array::<64, _>(r))?;
    #[allow(clippy::redundant_closure)]
    let v_output_proofs = Array::read(&mut reader, n_outputs, |r| read_zkproof(r))?;

    let binding_sig = if n_spends > 0 || n_outputs > 0 {
        let mut sig = [0u8; 64];
        reader.read_exact(&mut sig)?;
        Some(sig)
    } else {
        None
    };

    let spends = sd_v5s
        .into_iter()
        .zip(v_spend_proofs.into_iter().zip(v_spend_auth_sigs))
        .map(
            |((cv, nullifier, rk), (zkproof, spend_auth_sig))| RawSaplingSpend {
                cv,
                // the following `unwrap` is safe because we know n_spends > 0.
                anchor: anchor.unwrap(),
                nullifier,
                rk,
                zkproof,
                spend_auth_sig,
            },
        )
        .collect();

    let outputs = od_v5s
        .into_iter()
        .zip(v_output_proofs)
        .map(|(output, zkproof)| RawSaplingOutput { zkproof, ..output })
        .collect();

    Ok(binding_sig.and_then(|binding_sig| {
        RawSaplingBundle::from_parts(spends, outputs, value_balance, binding_sig)
    }))
}

/// Writes a Sapling bundle in the v5 transaction format.
pub(crate) fn write_v5_bundle<W: Write>(
    mut writer: W,
    bundle: Option<&RawSaplingBundle>,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        Vector::write(&mut writer, &bundle.spends, |w, s| {
            w.write_all(&s.cv)?;
            w.write_all(&s.nullifier)?;
            w.write_all(&s.rk)
        })?;

        Vector::write(&mut writer, &bundle.outputs, |w, o| {
            w.write_all(&o.cv)?;
            w.write_all(&o.cmu)?;
            w.write_all(&o.ephemeral_key)?;
            w.write_all(&o.enc_ciphertext)?;
            w.write_all(&o.out_ciphertext)
        })?;

        if !(bundle.spends.is_empty() && bundle.outputs.is_empty()) {
            writer.write_all(&bundle.value_balance.to_i64_le_bytes())?;
        }
        if !bundle.spends.is_empty() {
            writer.write_all(&bundle.spends[0].anchor)?;
        }

        Array::write(
            &mut writer,
            bundle.spends.iter().map(|s| &s.zkproof[..]),
            |w, e| w.write_all(e),
        )?;
        Array::write(
            &mut writer,
            bundle.spends.iter().map(|s| &s.spend_auth_sig[..]),
            |w, e| w.write_all(e),
        )?;
        Array::write(
            &mut writer,
            bundle.outputs.iter().map(|s| &s.zkproof[..]),
            |w, e| w.write_all(e),
        )?;

        if !(bundle.spends.is_empty() && bundle.outputs.is_empty()) {
            writer.write_all(&bundle.binding_sig)?;
        }
    } else {
        CompactSize::write(&mut writer, 0)?;
        CompactSize::write(&mut writer, 0)?;
    }

    Ok(())
}
