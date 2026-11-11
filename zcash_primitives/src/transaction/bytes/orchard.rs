//! Byte-level Orchard and Ironwood bundle representations.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::{Array, CompactSize, Vector};
use zcash_protocol::value::ZatBalance;

#[cfg(zcash_unstable = "nu8")]
use super::sapling::SighashInfoBytes;
use super::{read_array, read_fixed, read_vector};

/// The size in bytes of an Orchard value commitment.
const VALUE_COMMITMENT_SIZE: usize = 32;
/// The size in bytes of an Orchard nullifier.
const NULLIFIER_SIZE: usize = 32;
/// The size in bytes of an Orchard randomized validating key.
const RK_SIZE: usize = 32;
/// The size in bytes of an Orchard extracted note commitment.
const CMX_SIZE: usize = 32;
/// The size in bytes of an Orchard ephemeral key.
const EPHEMERAL_KEY_SIZE: usize = 32;
/// The size in bytes of an Orchard encrypted note ciphertext.
const ENC_CIPHERTEXT_SIZE: usize = 580;
/// The size in bytes of an Orchard encrypted outgoing ciphertext.
const OUT_CIPHERTEXT_SIZE: usize = 80;
/// The size in bytes of an Orchard spend authorization signature.
const SPEND_AUTH_SIG_SIZE: usize = 64;
/// The size in bytes of an Orchard binding signature.
const BINDING_SIG_SIZE: usize = 64;
/// The size in bytes of an Orchard anchor.
const ANCHOR_SIZE: usize = 32;
/// The fixed part of the length of an Orchard proof.
///
/// ZIP 248 requires a bundle's `proofsOrchard` to be `2720 + 2272 * nActionsOrchard`
/// bytes.
const PROOF_BASE_SIZE: usize = 2720;
/// The length that each action adds to an Orchard proof.
const PROOF_PER_ACTION_SIZE: usize = 2272;

/// Returns the required length of a bundle's proof for `n_actions` actions.
fn expected_proof_size(n_actions: usize) -> Option<usize> {
    PROOF_PER_ACTION_SIZE
        .checked_mul(n_actions)
        .and_then(|per_action| PROOF_BASE_SIZE.checked_add(per_action))
}

/// An Orchard action description's effecting data.
///
/// This is the `OrchardActionEffecting` encoding used by version 5 and later
/// transactions. The spend authorization signature is authorizing data and is
/// not part of this structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchardActionBytes {
    cv: [u8; VALUE_COMMITMENT_SIZE],
    nullifier: [u8; NULLIFIER_SIZE],
    rk: [u8; RK_SIZE],
    cmx: [u8; CMX_SIZE],
    ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
    enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
}

impl OrchardActionBytes {
    /// Constructs an action description from its wire fields.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        cv: [u8; VALUE_COMMITMENT_SIZE],
        nullifier: [u8; NULLIFIER_SIZE],
        rk: [u8; RK_SIZE],
        cmx: [u8; CMX_SIZE],
        ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
        enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
        out_ciphertext: [u8; OUT_CIPHERTEXT_SIZE],
    ) -> Self {
        Self {
            cv,
            nullifier,
            rk,
            cmx,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
        }
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

    /// Returns the extracted note commitment.
    pub fn cmx(&self) -> &[u8; CMX_SIZE] {
        &self.cmx
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

    /// Reads an action description.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self {
            cv: read_fixed::<VALUE_COMMITMENT_SIZE, _>(&mut reader)?,
            nullifier: read_fixed::<NULLIFIER_SIZE, _>(&mut reader)?,
            rk: read_fixed::<RK_SIZE, _>(&mut reader)?,
            cmx: read_fixed::<CMX_SIZE, _>(&mut reader)?,
            ephemeral_key: read_fixed::<EPHEMERAL_KEY_SIZE, _>(&mut reader)?,
            enc_ciphertext: read_fixed::<ENC_CIPHERTEXT_SIZE, _>(&mut reader)?,
            out_ciphertext: read_fixed::<OUT_CIPHERTEXT_SIZE, _>(&mut reader)?,
        })
    }

    /// Writes an action description.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv)?;
        writer.write_all(&self.nullifier)?;
        writer.write_all(&self.rk)?;
        writer.write_all(&self.cmx)?;
        writer.write_all(&self.ephemeral_key)?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)
    }
}

/// A version 5 or 6 Orchard-protocol bundle in its wire representation.
///
/// The wire layout is `actions || flags || value_balance || anchor || proof ||
/// spend_auth_sigs || binding_sig`, with the whole bundle encoded as a bare
/// zero count when there are no actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchardBundleBytes {
    actions: Vec<OrchardActionBytes>,
    flags: u8,
    value_balance: ZatBalance,
    anchor: [u8; ANCHOR_SIZE],
    proof: Vec<u8>,
    spend_auth_sigs: Vec<[u8; SPEND_AUTH_SIG_SIZE]>,
    binding_sig: [u8; BINDING_SIG_SIZE],
}

impl OrchardBundleBytes {
    /// Constructs an Orchard-protocol bundle from its wire fields.
    ///
    /// Returns an error if the bundle has no actions, or if the spend
    /// authorization signatures do not correspond one-to-one with the actions.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        actions: Vec<OrchardActionBytes>,
        flags: u8,
        value_balance: ZatBalance,
        anchor: [u8; ANCHOR_SIZE],
        proof: Vec<u8>,
        spend_auth_sigs: Vec<[u8; SPEND_AUTH_SIG_SIZE]>,
        binding_sig: [u8; BINDING_SIG_SIZE],
    ) -> io::Result<Self> {
        if actions.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an empty Orchard-protocol bundle is encoded as a bare zero count",
            ));
        }
        if spend_auth_sigs.len() != actions.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Orchard spend authorization signatures must correspond one-to-one with actions",
            ));
        }
        Ok(Self {
            actions,
            flags,
            value_balance,
            anchor,
            proof,
            spend_auth_sigs,
            binding_sig,
        })
    }

    /// Returns the action descriptions.
    pub fn actions(&self) -> &[OrchardActionBytes] {
        &self.actions
    }

    /// Returns the flags byte.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the value balance.
    pub fn value_balance(&self) -> ZatBalance {
        self.value_balance
    }

    /// Returns the anchor.
    pub fn anchor(&self) -> &[u8; ANCHOR_SIZE] {
        &self.anchor
    }

    /// Returns the proof bytes.
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Returns the spend authorization signatures.
    pub fn spend_auth_sigs(&self) -> &[[u8; SPEND_AUTH_SIG_SIZE]] {
        &self.spend_auth_sigs
    }

    /// Returns the binding signature.
    pub fn binding_sig(&self) -> &[u8; BINDING_SIG_SIZE] {
        &self.binding_sig
    }

    /// Reads a version 5 or 6 Orchard-protocol bundle, returning `None` for an
    /// empty one.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Option<Self>> {
        let actions = read_vector(&mut reader, |r| OrchardActionBytes::read(r))?;
        if actions.is_empty() {
            return Ok(None);
        }
        let mut flags = [0u8; 1];
        reader.read_exact(&mut flags)?;
        let value_balance = read_balance(&mut reader)?;
        let anchor = read_fixed::<ANCHOR_SIZE, _>(&mut reader)?;
        let proof = Vector::read_bytes(&mut reader)?;
        let spend_auth_sigs = read_array(&mut reader, actions.len(), |r| {
            read_fixed::<SPEND_AUTH_SIG_SIZE, _>(r)
        })?;
        let binding_sig = read_fixed::<BINDING_SIG_SIZE, _>(&mut reader)?;
        Ok(Some(Self {
            actions,
            flags: flags[0],
            value_balance,
            anchor,
            proof,
            spend_auth_sigs,
            binding_sig,
        }))
    }

    /// Writes a version 5 or 6 Orchard-protocol bundle, or a bare zero count if
    /// `bundle` is `None`.
    pub fn write_opt<W: Write>(mut writer: W, bundle: Option<&Self>) -> io::Result<()> {
        match bundle {
            Some(bundle) => {
                Vector::write(&mut writer, &bundle.actions, |w, action| action.write(w))?;
                writer.write_all(&[bundle.flags])?;
                writer.write_all(&bundle.value_balance.to_i64_le_bytes())?;
                writer.write_all(&bundle.anchor)?;
                Vector::write_bytes(&mut writer, &bundle.proof)?;
                Array::write(&mut writer, &bundle.spend_auth_sigs, |w, sig| {
                    w.write_all(&sig[..])
                })?;
                writer.write_all(&bundle.binding_sig)
            }
            None => CompactSize::write(&mut writer, 0),
        }
    }
}

/// A version 6 Ironwood bundle in its wire representation.
///
/// The Ironwood bundle uses the same encoding as [`OrchardBundleBytes`]; only
/// the value pool it acts on, and so its digest personalizations, differ.
pub type IronwoodBundleBytes = OrchardBundleBytes;

/// An Orchard-protocol signature with its `sighashInfo` prefix.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchardSignatureBytes {
    sighash_info: SighashInfoBytes,
    signature: [u8; SPEND_AUTH_SIG_SIZE],
}

#[cfg(zcash_unstable = "nu8")]
impl OrchardSignatureBytes {
    /// Constructs an Orchard-protocol signature from its wire fields.
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

    /// Reads an Orchard-protocol signature.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let sighash_info = SighashInfoBytes::read(&mut reader)?;
        let signature = read_fixed::<SPEND_AUTH_SIG_SIZE, _>(&mut reader)?;
        Ok(Self {
            sighash_info,
            signature,
        })
    }

    /// Writes an Orchard-protocol signature.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.sighash_info.write(&mut writer)?;
        writer.write_all(&self.signature)
    }
}

/// A version 7 Orchard-protocol bundle, retaining its effecting and
/// authorizing data separately.
///
/// [ZIP 248 §Orchard Protocol Bundles](https://zips.z.cash/zip-0248#orchard-protocol-bundles)
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V7OrchardBundleBytes {
    actions: Vec<OrchardActionBytes>,
    flags: u8,
    anchor: Option<[u8; ANCHOR_SIZE]>,
    proof: Vec<u8>,
    spend_auth_sigs: Vec<OrchardSignatureBytes>,
    binding_sig: Option<OrchardSignatureBytes>,
    /// Whether an entry for this bundle is present in `mAuthBundles`.
    ///
    /// This is independent of whether the authorizing payload has contents: an
    /// empty bundle can have a present-but-empty authorizing entry, which the
    /// digests distinguish from an absent one.
    auth: bool,
}

#[cfg(zcash_unstable = "nu8")]
impl V7OrchardBundleBytes {
    /// Constructs a version 7 Orchard-protocol bundle from its wire fields.
    ///
    /// The authorizing entry is present exactly when `binding_sig` is present.
    /// Returns an error if an anchor is present without actions, if the spend
    /// authorization signatures do not correspond one-to-one with the actions,
    /// if authorizing data is present and the proof length is not
    /// `2720 + 2272 * nActionsOrchard`, or if authorizing fields are present
    /// without a binding signature. Authorizing data may be absent even when
    /// the effecting data has actions; requiring it is a consensus rule
    /// enforced by typed conversion rather than by the byte layer.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        actions: Vec<OrchardActionBytes>,
        flags: u8,
        anchor: Option<[u8; ANCHOR_SIZE]>,
        proof: Vec<u8>,
        spend_auth_sigs: Vec<OrchardSignatureBytes>,
        binding_sig: Option<OrchardSignatureBytes>,
    ) -> io::Result<Self> {
        let auth = binding_sig.is_some();
        Self::from_parts_with_auth_presence(
            actions,
            flags,
            anchor,
            proof,
            spend_auth_sigs,
            binding_sig,
            auth,
        )
    }

    /// Constructs a version 7 Orchard-protocol bundle, stating whether an
    /// authorizing entry is present independently of its contents.
    ///
    /// An empty bundle may have a present-but-empty authorizing entry, which
    /// is distinct from an absent entry because map presence is committed to
    /// by the digests.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_with_auth_presence(
        actions: Vec<OrchardActionBytes>,
        flags: u8,
        anchor: Option<[u8; ANCHOR_SIZE]>,
        proof: Vec<u8>,
        spend_auth_sigs: Vec<OrchardSignatureBytes>,
        binding_sig: Option<OrchardSignatureBytes>,
        auth: bool,
    ) -> io::Result<Self> {
        let empty = actions.is_empty();
        if empty && flags != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an empty Orchard-protocol bundle has no flags byte",
            ));
        }
        if !auth {
            if binding_sig.is_some()
                || anchor.is_some()
                || !proof.is_empty()
                || !spend_auth_sigs.is_empty()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Orchard authorizing data is present without an authorizing entry",
                ));
            }
        } else if empty {
            if binding_sig.is_some()
                || anchor.is_some()
                || !proof.is_empty()
                || !spend_auth_sigs.is_empty()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "an empty Orchard-protocol bundle has only empty authorizing data",
                ));
            }
        } else {
            if anchor.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "an Orchard anchor is present exactly when the bundle has \
                     authorizing data",
                ));
            }
            if spend_auth_sigs.len() != actions.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Orchard spend authorization signatures must correspond one-to-one \
                     with actions",
                ));
            }
            let expected = expected_proof_size(actions.len()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Orchard proof size overflows the address space",
                )
            })?;
            if proof.len() != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Orchard proofs must aggregate exactly one 2272-byte proof per \
                     action, plus a 2720-byte base",
                ));
            }
            if binding_sig.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a non-empty Orchard-protocol bundle requires a binding signature",
                ));
            }
        }
        Ok(Self {
            actions,
            flags,
            anchor,
            proof,
            spend_auth_sigs,
            binding_sig,
            auth,
        })
    }

    /// Returns the action descriptions.
    pub fn actions(&self) -> &[OrchardActionBytes] {
        &self.actions
    }

    /// Returns the flags byte.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the anchor, if the bundle has authorizing data.
    pub fn anchor(&self) -> Option<&[u8; ANCHOR_SIZE]> {
        self.anchor.as_ref()
    }

    /// Returns the proof bytes.
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Returns the spend authorization signatures.
    pub fn spend_auth_sigs(&self) -> &[OrchardSignatureBytes] {
        &self.spend_auth_sigs
    }

    /// Returns the binding signature, if the bundle has authorizing data.
    pub fn binding_sig(&self) -> Option<&OrchardSignatureBytes> {
        self.binding_sig.as_ref()
    }

    /// Returns `true` if an authorizing entry is present for this bundle.
    pub fn has_auth(&self) -> bool {
        self.auth
    }

    /// Reads a version 7 Orchard-protocol bundle from its effecting and
    /// authorizing payloads.
    ///
    /// Both payloads must be consumed exactly; trailing bytes are rejected.
    /// An empty effecting payload is retained as a present bundle, and an
    /// authorizing payload may be absent or present-but-empty; the distinction
    /// is preserved because map presence is committed to by the digests.
    pub fn read(effects: &[u8], auth: Option<&[u8]>) -> io::Result<Self> {
        let mut effects_reader = effects;
        let actions = read_vector(&mut effects_reader, |r| OrchardActionBytes::read(r))?;
        // ZIP 248: flagsOrchard is present if and only if nActionsOrchard > 0.
        let flags = if actions.is_empty() {
            0
        } else {
            let mut flags = [0u8; 1];
            effects_reader.read_exact(&mut flags)?;
            flags[0]
        };
        if !effects_reader.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in v7 Orchard effecting data",
            ));
        }

        let Some(auth) = auth else {
            return Self::from_parts_with_auth_presence(
                actions,
                flags,
                None,
                vec![],
                vec![],
                None,
                false,
            );
        };

        if actions.is_empty() {
            // ZIP 248: anchorOrchard, proofsOrchard, and bindingSigOrchard are
            // present iff nActionsOrchard > 0, so an empty bundle's authorizing
            // payload is empty.
            if !auth.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "an empty Orchard-protocol bundle has non-empty authorizing data",
                ));
            }
            return Self::from_parts_with_auth_presence(
                actions,
                flags,
                None,
                vec![],
                vec![],
                None,
                true,
            );
        }

        let mut auth_reader = auth;
        let anchor = read_fixed::<ANCHOR_SIZE, _>(&mut auth_reader)?;
        let proof = Vector::read_bytes(&mut auth_reader)?;
        let spend_auth_sigs = read_array(&mut auth_reader, actions.len(), |r| {
            OrchardSignatureBytes::read(r)
        })?;
        let binding_sig = OrchardSignatureBytes::read(&mut auth_reader)?;
        if !auth_reader.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in v7 Orchard authorizing data",
            ));
        }

        Self::from_parts_with_auth_presence(
            actions,
            flags,
            Some(anchor),
            proof,
            spend_auth_sigs,
            Some(binding_sig),
            true,
        )
    }

    /// Writes the bundle's effecting data.
    pub fn write_effects<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write(&mut writer, &self.actions, |w, action| action.write(w))?;
        // ZIP 248: flagsOrchard is present if and only if nActionsOrchard > 0.
        if !self.actions.is_empty() {
            writer.write_all(&[self.flags])?;
        }
        Ok(())
    }

    /// Writes the bundle's authorizing data, if an authorizing entry is
    /// present.
    pub fn write_auth<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if !self.auth {
            return Ok(());
        }
        let Some(anchor) = self.anchor.as_ref() else {
            // An empty bundle's authorizing payload is empty.
            return Ok(());
        };
        writer.write_all(anchor)?;
        Vector::write_bytes(&mut writer, &self.proof)?;
        for sig in &self.spend_auth_sigs {
            sig.write(&mut writer)?;
        }
        match &self.binding_sig {
            Some(binding_sig) => binding_sig.write(&mut writer),
            None => Ok(()),
        }
    }
}

/// Reads a signed 64-bit value balance.
fn read_balance<R: Read>(mut reader: R) -> io::Result<ZatBalance> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    ZatBalance::from_i64_le_bytes(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "valueBalance out of range"))
}
