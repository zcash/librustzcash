//! Parsing and serialization of the Orchard components of a transaction when the `orchard`
//! feature is disabled.
//!
//! When the `orchard` feature is not enabled, the `orchard` crate (and its `pasta_curves`
//! dependency) is not compiled, so a transaction's Orchard bundle cannot be converted into
//! the typed [`orchard::Bundle`] domain representation. These functions parse the exact same
//! binary wire format as the typed path, retaining the parsed bytes in [`RawOrchardBundle`]
//! so that the transaction can be re-serialized byte-identically and its consensus txid /
//! authorizing-data digests computed (see [`crate::transaction::txid`]).
//!
//! Parsing here is *lenient*: it validates field lengths, the Orchard flags bits, and (under
//! [`ProofSizeEnforcement::Strict`]) the canonical proof size, but it does NOT validate
//! Pallas point membership of `cv_net`/`nullifier`/`rk`/`cmx`/`anchor` (that requires
//! `pasta_curves`, which is only compiled with the `orchard` feature). Point-membership
//! validation is therefore deferred to the point at which the bytes would be converted into
//! a typed bundle, which requires the `orchard` feature. This is sufficient to re-serialize
//! byte-identically and to compute the correct consensus txid.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};

use zcash_encoding::{Array, CompactSize, Vector};
use zcash_protocol::value::ZatBalance;

use crate::transaction::Transaction;

const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;
const FLAG_OUTPUTS_ENABLED: u8 = 0b0000_0010;
const FLAGS_EXPECTED_UNSET: u8 = !(FLAG_SPENDS_ENABLED | FLAG_OUTPUTS_ENABLED);

const ENC_CIPHERTEXT_SIZE: usize = 580;
const OUT_CIPHERTEXT_SIZE: usize = 80;

// The canonical byte length of an Orchard proof is a fixed base plus a fixed per-action
// contribution; these constants mirror `orchard::Proof::expected_proof_size`. A proof of any
// other length is non-canonical (e.g. padded; GHSA-2x4w-pxqw-58v9).
const PROOF_BASE_SIZE: usize = 2720;
const PROOF_PER_ACTION_SIZE: usize = 2272;

fn expected_proof_size(num_actions: usize) -> usize {
    PROOF_BASE_SIZE + PROOF_PER_ACTION_SIZE * num_actions
}

/// Whether to enforce the canonical Orchard proof size when parsing, mirroring
/// `orchard::bundle::ProofSizeEnforcement`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofSizeEnforcement {
    /// Do not enforce the canonical proof size (pre-NU6.2 consensus rules).
    Unenforced,
    /// Reject proofs that are not the canonical size for the number of actions.
    Strict,
}

/// A parsed-but-unconverted Orchard action.
#[derive(Clone, Debug)]
pub struct RawOrchardAction {
    pub(crate) cv_net: [u8; 32],
    pub(crate) nullifier: [u8; 32],
    pub(crate) rk: [u8; 32],
    pub(crate) cmx: [u8; 32],
    pub(crate) epk_bytes: [u8; 32],
    pub(crate) enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    pub(crate) out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    pub(crate) spend_auth_sig: [u8; 64],
}

/// A parsed-but-unconverted Orchard bundle.
///
/// This is the representation of a transaction's Orchard bundle used when the `orchard`
/// feature is disabled. It retains exactly the data required to re-serialize the bundle
/// byte-identically and to compute the ZIP 244 txid and authorizing-data digests.
#[derive(Clone, Debug)]
pub struct RawOrchardBundle {
    actions: Vec<RawOrchardAction>,
    flags: u8,
    value_balance: ZatBalance,
    anchor: [u8; 32],
    proof: Vec<u8>,
    binding_sig: [u8; 64],
}

impl RawOrchardBundle {
    pub(crate) fn actions(&self) -> &[RawOrchardAction] {
        &self.actions
    }

    pub(crate) fn flags(&self) -> u8 {
        self.flags
    }

    pub(crate) fn value_balance(&self) -> &ZatBalance {
        &self.value_balance
    }

    pub(crate) fn anchor(&self) -> &[u8; 32] {
        &self.anchor
    }

    pub(crate) fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub(crate) fn binding_sig(&self) -> &[u8; 64] {
        &self.binding_sig
    }
}

struct RawActionWithoutAuth {
    cv_net: [u8; 32],
    nullifier: [u8; 32],
    rk: [u8; 32],
    cmx: [u8; 32],
    epk_bytes: [u8; 32],
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
}

impl RawActionWithoutAuth {
    fn with_auth(self, spend_auth_sig: [u8; 64]) -> RawOrchardAction {
        RawOrchardAction {
            cv_net: self.cv_net,
            nullifier: self.nullifier,
            rk: self.rk,
            cmx: self.cmx,
            epk_bytes: self.epk_bytes,
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
            spend_auth_sig,
        }
    }
}

fn read_array<const N: usize, R: Read>(mut reader: R) -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_flags<R: Read>(mut reader: R) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    if byte[0] & FLAGS_EXPECTED_UNSET != 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Orchard flags",
        ))
    } else {
        Ok(byte[0])
    }
}

fn read_action_without_auth<R: Read>(mut reader: R) -> io::Result<RawActionWithoutAuth> {
    let cv_net = read_array(&mut reader)?;
    let nullifier = read_array(&mut reader)?;
    let rk = read_array(&mut reader)?;
    let cmx = read_array(&mut reader)?;
    let epk_bytes = read_array(&mut reader)?;
    let enc_ciphertext = read_array(&mut reader)?;
    let out_ciphertext = read_array(&mut reader)?;
    Ok(RawActionWithoutAuth {
        cv_net,
        nullifier,
        rk,
        cmx,
        epk_bytes,
        enc_ciphertext,
        out_ciphertext,
    })
}

fn write_action_without_auth<W: Write>(mut writer: W, act: &RawOrchardAction) -> io::Result<()> {
    writer.write_all(&act.cv_net)?;
    writer.write_all(&act.nullifier)?;
    writer.write_all(&act.rk)?;
    writer.write_all(&act.cmx)?;
    writer.write_all(&act.epk_bytes)?;
    writer.write_all(&act.enc_ciphertext)?;
    writer.write_all(&act.out_ciphertext)
}

/// Reads an Orchard bundle from a v5 transaction format.
pub(crate) fn read_v5_bundle<R: Read>(
    mut reader: R,
    proof_size_enforcement: ProofSizeEnforcement,
) -> io::Result<Option<RawOrchardBundle>> {
    #[allow(clippy::redundant_closure)]
    let actions_without_auth = Vector::read(&mut reader, |r| read_action_without_auth(r))?;
    if actions_without_auth.is_empty() {
        Ok(None)
    } else {
        let flags = read_flags(&mut reader)?;
        let value_balance = Transaction::read_amount(&mut reader)?;
        let anchor = read_array(&mut reader)?;
        let proof = Vector::read(&mut reader, |r| {
            let mut b = [0u8; 1];
            r.read_exact(&mut b)?;
            Ok(b[0])
        })?;
        let actions = actions_without_auth
            .into_iter()
            .map(|awa| Ok(awa.with_auth(read_array::<64, _>(&mut reader)?)))
            .collect::<io::Result<Vec<_>>>()?;
        let binding_sig = read_array(&mut reader)?;

        if proof_size_enforcement == ProofSizeEnforcement::Strict
            && proof.len() != expected_proof_size(actions.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-canonical Orchard proof size",
            ));
        }

        Ok(Some(RawOrchardBundle {
            actions,
            flags,
            value_balance,
            anchor,
            proof,
            binding_sig,
        }))
    }
}

#[cfg(zcash_unstable = "nu7")]
pub(crate) fn read_v6_bundle<R: Read>(reader: R) -> io::Result<Option<RawOrchardBundle>> {
    read_v5_bundle(reader, ProofSizeEnforcement::Strict)
}

/// Writes an Orchard bundle in the v5 transaction format.
pub(crate) fn write_v5_bundle<W: Write>(
    bundle: Option<&RawOrchardBundle>,
    mut writer: W,
) -> io::Result<()> {
    if let Some(bundle) = &bundle {
        Vector::write(&mut writer, &bundle.actions, |w, a| {
            write_action_without_auth(w, a)
        })?;
        writer.write_all(&[bundle.flags])?;
        writer.write_all(&bundle.value_balance.to_i64_le_bytes())?;
        writer.write_all(&bundle.anchor)?;
        Vector::write(&mut writer, &bundle.proof, |w, b| w.write_all(&[*b]))?;
        Array::write(
            &mut writer,
            bundle.actions.iter().map(|a| &a.spend_auth_sig[..]),
            |w, e| w.write_all(e),
        )?;
        writer.write_all(&bundle.binding_sig)?;
    } else {
        CompactSize::write(&mut writer, 0)?;
    }

    Ok(())
}

#[cfg(zcash_unstable = "nu7")]
pub(crate) fn write_v6_bundle<W: Write>(
    bundle: Option<&RawOrchardBundle>,
    writer: W,
) -> io::Result<()> {
    write_v5_bundle(bundle, writer)
}
