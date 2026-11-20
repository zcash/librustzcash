//! Byte-level Orchard and Ironwood bundle representations.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::{Array, CompactSize, Vector};
#[cfg(feature = "orchard")]
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
#[cfg(zcash_unstable = "nu8")]
const PROOF_BASE_SIZE: usize = 2720;
/// The length that each action adds to an Orchard proof.
#[cfg(zcash_unstable = "nu8")]
const PROOF_PER_ACTION_SIZE: usize = 2272;
/// The defined ZIP 248 flag bits: spends, outputs, and cross-address transfers.
#[cfg(zcash_unstable = "nu8")]
const V7_FLAGS_MASK: u8 = 0b0000_0111;

/// Returns the required length of a bundle's proof for `n_actions` actions.
#[cfg(zcash_unstable = "nu8")]
pub(super) fn expected_proof_size(n_actions: usize) -> Option<usize> {
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
    value_balance: i64,
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
        value_balance: i64,
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
    pub fn value_balance(&self) -> i64 {
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
                writer.write_all(&bundle.value_balance.to_le_bytes())?;
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

    /// Interprets this bundle as an authorized Orchard-protocol bundle.
    ///
    /// `bundle_version` fixes the flag-byte grammar and circuit generation for
    /// the consensus branch the transaction is in. It is `None` when the pool
    /// is not supported under that branch, in which case a non-empty bundle is
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle is empty, if the pool is not supported
    /// under the supplied bundle version, or if a field is invalid.
    #[cfg(feature = "orchard")]
    pub fn to_authorized(
        &self,
        bundle_version: Option<orchard::bundle::BundleVersion>,
    ) -> io::Result<orchard::Bundle<orchard::bundle::Authorized, ZatBalance>> {
        crate::transaction::components::orchard::bundle_from_bytes(self, bundle_version)
    }

    /// Interprets this bundle, moving its proof buffer into the domain type.
    #[cfg(feature = "orchard")]
    pub(crate) fn into_authorized(
        mut self,
        bundle_version: Option<orchard::bundle::BundleVersion>,
    ) -> io::Result<orchard::Bundle<orchard::bundle::Authorized, ZatBalance>> {
        let proof = core::mem::take(&mut self.proof);
        crate::transaction::components::orchard::bundle_from_bytes_with_proof(
            &self,
            bundle_version,
            || proof,
        )
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

/// The effecting data of a version 7 Orchard-protocol bundle.
///
/// [ZIP 248 §Orchard Protocol Effecting Data](https://zips.z.cash/zip-0248#orchard-protocol-effecting-data)
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V7OrchardBundleBytes {
    actions: Vec<OrchardActionBytes>,
    flags: u8,
}

#[cfg(zcash_unstable = "nu8")]
impl V7OrchardBundleBytes {
    /// Constructs Orchard-protocol effecting data from its wire fields.
    ///
    /// Empty actions or reserved flag bits prevent serialization and inclusion
    /// in a v7 transaction body.
    pub fn from_parts(actions: Vec<OrchardActionBytes>, flags: u8) -> Self {
        Self { actions, flags }
    }

    /// Returns the action descriptions.
    pub fn actions(&self) -> &[OrchardActionBytes] {
        &self.actions
    }

    /// Returns the flags byte.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub(super) fn validate(&self) -> io::Result<()> {
        if self.actions.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty Orchard-protocol effecting data must be omitted",
            ));
        }
        if self.flags & !V7_FLAGS_MASK != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reserved Orchard-protocol flag bits must be zero",
            ));
        }
        Ok(())
    }

    /// Reads nonempty Orchard-protocol effecting data.
    ///
    /// Rejects reserved flag bits and trailing bytes.
    pub fn read(effects: &[u8]) -> io::Result<Self> {
        let mut reader = effects;
        let actions = read_vector(&mut reader, |r| OrchardActionBytes::read(r))?;
        let flags = if actions.is_empty() {
            0
        } else {
            let mut flags = [0u8; 1];
            reader.read_exact(&mut flags)?;
            flags[0]
        };
        if !reader.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in v7 Orchard effecting data",
            ));
        }
        let effects = Self::from_parts(actions, flags);
        effects
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(effects)
    }

    /// Writes the effecting data.
    ///
    /// Returns an error if there are no actions or reserved flag bits are set.
    pub fn write_effects<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.validate()?;
        Vector::write(&mut writer, &self.actions, |w, action| action.write(w))?;
        if !self.actions.is_empty() {
            writer.write_all(&[self.flags])?;
        }
        Ok(())
    }
}

/// The authorizing data of a version 7 Orchard-protocol bundle.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V7OrchardAuthBytes {
    anchor: Option<[u8; ANCHOR_SIZE]>,
    proof: Vec<u8>,
    spend_auth_sigs: Vec<OrchardSignatureBytes>,
    binding_sig: Option<OrchardSignatureBytes>,
}

#[cfg(zcash_unstable = "nu8")]
impl V7OrchardAuthBytes {
    /// Constructs Orchard-protocol authorizing data from its wire fields.
    ///
    /// The enclosing transaction body checks that these fields correspond to
    /// the effecting data's actions.
    pub fn from_parts(
        anchor: Option<[u8; ANCHOR_SIZE]>,
        proof: Vec<u8>,
        spend_auth_sigs: Vec<OrchardSignatureBytes>,
        binding_sig: Option<OrchardSignatureBytes>,
    ) -> Self {
        Self {
            anchor,
            proof,
            spend_auth_sigs,
            binding_sig,
        }
    }

    /// Returns the anchor, if the bundle has actions.
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

    /// Returns the binding signature, if the bundle has actions.
    pub fn binding_sig(&self) -> Option<&OrchardSignatureBytes> {
        self.binding_sig.as_ref()
    }

    /// Reads Orchard-protocol authorizing data for `action_count` actions.
    ///
    /// Returns an error if `action_count` is zero.
    pub fn read(auth: &[u8], action_count: usize) -> io::Result<Self> {
        if action_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "authorizing data for an empty Orchard-protocol bundle must be omitted",
            ));
        }

        let mut reader = auth;
        let anchor = read_fixed::<ANCHOR_SIZE, _>(&mut reader)?;
        let proof = Vector::read_bytes(&mut reader)?;
        let expected = expected_proof_size(action_count).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Orchard proof size overflows the address space",
            )
        })?;
        if proof.len() != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Orchard proof length does not correspond to the action count",
            ));
        }
        let spend_auth_sigs = read_array(&mut reader, action_count, |r| {
            OrchardSignatureBytes::read(r)
        })?;
        let binding_sig = OrchardSignatureBytes::read(&mut reader)?;
        if !reader.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in v7 Orchard authorizing data",
            ));
        }

        Ok(Self::from_parts(
            Some(anchor),
            proof,
            spend_auth_sigs,
            Some(binding_sig),
        ))
    }

    /// Writes the authorizing data.
    ///
    /// Returns an error if there are no actions, anchor, or binding signature.
    pub fn write_auth<W: Write>(&self, mut writer: W) -> io::Result<()> {
        if self.spend_auth_sigs.is_empty() || self.binding_sig.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Orchard authorizing data requires actions and a binding signature",
            ));
        }
        let Some(anchor) = self.anchor.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Orchard authorizing data requires an anchor",
            ));
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

    /// Interprets effecting and authorizing data as an authorized typed bundle.
    #[cfg(feature = "orchard")]
    pub fn to_authorized(
        &self,
        effects: &V7OrchardBundleBytes,
        value_balance: ZatBalance,
        bundle_version: Option<orchard::bundle::BundleVersion>,
    ) -> io::Result<orchard::Bundle<orchard::bundle::Authorized, ZatBalance>> {
        crate::transaction::components::orchard::v7_bundle_from_bytes(
            effects,
            self,
            value_balance,
            bundle_version,
        )
    }

    /// Interprets the bundle, moving its proof buffer into the domain type.
    #[cfg(feature = "orchard")]
    pub(crate) fn into_authorized(
        mut self,
        effects: &V7OrchardBundleBytes,
        value_balance: ZatBalance,
        bundle_version: Option<orchard::bundle::BundleVersion>,
    ) -> io::Result<orchard::Bundle<orchard::bundle::Authorized, ZatBalance>> {
        let proof = core::mem::take(&mut self.proof);
        crate::transaction::components::orchard::v7_bundle_from_bytes_with_proof(
            effects,
            &self,
            value_balance,
            bundle_version,
            || proof,
        )
    }
}

/// Reads a signed 64-bit value balance without narrowing it to the monetary
/// domain.
fn read_balance<R: Read>(mut reader: R) -> io::Result<i64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(i64::from_le_bytes(bytes))
}
