//! The Orchard fields of a PCZT.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

#[cfg(feature = "orchard")]
use ff::PrimeField;
use getset::Getters;
#[cfg(feature = "orchard")]
use orchard::bundle::BundleVersion;
#[cfg(feature = "orchard")]
pub(crate) use orchard::note::NoteVersion;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
#[cfg(feature = "orchard")]
use zcash_note_encryption::{Domain, ENC_CIPHERTEXT_SIZE, EphemeralKeyBytes, ShieldedOutput};

use crate::{
    common::{Global, Zip32Derivation},
    roles::combiner::{merge_map, merge_optional},
};

#[cfg(not(feature = "orchard"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoteVersion {
    V2,
    V3,
}

/// PCZT fields that are specific to producing the transaction's Orchard bundle (if any).
#[derive(Clone, Debug, PartialEq, Getters)]
pub struct Bundle {
    /// The Orchard actions in this bundle.
    ///
    /// Entries are added by the Constructor, and modified by an Updater, IO Finalizer,
    /// Signer, Combiner, or Spend Finalizer.
    #[getset(get = "pub")]
    pub(crate) actions: Vec<Action>,

    /// The flags for the Orchard bundle.
    ///
    /// Contains:
    /// - `enableSpendsOrchard` flag (bit 0)
    /// - `enableOutputsOrchard` flag (bit 1)
    /// - Reserved, zeros (bits 2..=7)
    ///
    /// This is set by the Creator. The Constructor MUST only add spends and outputs that
    /// are consistent with these flags (i.e. are dummies as appropriate).
    #[getset(get = "pub")]
    pub(crate) flags: u8,

    /// The net value of Orchard spends minus outputs.
    ///
    /// This is initialized by the Creator, and updated by the Constructor as spends or
    /// outputs are added to the PCZT. It enables per-spend and per-output values to be
    /// redacted from the PCZT after they are no longer necessary.
    #[getset(get = "pub")]
    pub(crate) value_sum: (u64, bool),

    /// The Orchard anchor for this transaction.
    ///
    /// Set by the Creator.
    #[getset(get = "pub")]
    pub(crate) anchor: Option<[u8; 32]>,

    /// The note plaintext version for notes in this bundle.
    pub(crate) note_version: NoteVersion,

    /// The Orchard bundle proof.
    ///
    /// This is `None` until it is set by the Prover.
    pub(crate) zkproof: Option<Vec<u8>>,

    /// The Orchard binding signature signing key.
    ///
    /// - This is `None` until it is set by the IO Finalizer.
    /// - The Transaction Extractor uses this to produce the binding signature.
    pub(crate) bsk: Option<[u8; 32]>,
}

/// The default Orchard bundle flags: both spends and outputs enabled (bits 0 and
/// 1). This is the value the Creator sets on a new bundle, and the flag value of
/// an empty bundle for serialization purposes.
pub(crate) const ORCHARD_SPENDS_AND_OUTPUTS_ENABLED: u8 = 0b0000_0011;

/// The default Ironwood bundle flags: spends, outputs, and cross-address transfers
/// enabled (bits 0, 1, and 2). This is the value the Creator sets on a new bundle,
/// and the flag value of an empty bundle for serialization purposes.
pub(crate) const IRONWOOD_SPENDS_OUTPUTS_AND_CROSS_ADDRESS_ENABLED: u8 = 0b0000_0111;

/// The size in bytes of the memo portion of an Orchard note plaintext.
pub(crate) const MEMO_SIZE: usize = 512;

pub(crate) const DEFAULT_ANCHOR: [u8; 32] = [0; 32];

/// The canonical empty Orchard-pool bundle: the form the Orchard slot of a PCZT takes
/// when it carries no Orchard-protocol data. The Creator, the v1 decoder, and the v2
/// decoder all produce exactly this value for an absent bundle, so that copies of a
/// PCZT that take different serialization paths continue to merge successfully.
pub(crate) const EMPTY_ORCHARD: Bundle = Bundle {
    actions: Vec::new(),
    flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
    value_sum: (0, false),
    anchor: None,
    note_version: NoteVersion::V2,
    zkproof: None,
    bsk: None,
};

/// The canonical empty Ironwood bundle; see [`EMPTY_ORCHARD`].
pub(crate) const EMPTY_IRONWOOD: Bundle = Bundle {
    actions: Vec::new(),
    flags: IRONWOOD_SPENDS_OUTPUTS_AND_CROSS_ADDRESS_ENABLED,
    value_sum: (0, false),
    anchor: None,
    note_version: NoteVersion::V3,
    zkproof: None,
    bsk: None,
};

/// Errors that can occur while constructing a single note's [`MemoPlaintext`].
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
enum MemoPlaintextError {
    /// The stripped memo plaintext exceeds [`MEMO_SIZE`].
    TooLong,
    /// The memo plaintext was not encoded with all trailing zero bytes stripped.
    NotStripped,
}

impl fmt::Display for MemoPlaintextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoPlaintextError::TooLong => {
                write!(f, "memo plaintext exceeds {MEMO_SIZE} bytes")
            }
            MemoPlaintextError::NotStripped => {
                write!(f, "memo plaintext has trailing zero bytes")
            }
        }
    }
}

/// The result of parsing a logical Orchard-protocol bundle (Orchard or Ironwood) via
/// [`Bundle::into_parsed_with_version`] or one of its siblings.
///
/// Carries the bundle's original wire `anchor` alongside the parsed form, so that
/// [`Parsed::reserialize`] can restore it after an operation that does not itself
/// change the anchor, even though parsing may have substituted a placeholder for it
/// (see [ZIP 374: Anchors and pre-authorization](https://zips.z.cash/zip-0374#anchors-and-pre-authorization)).
#[cfg(feature = "orchard")]
pub(crate) struct Parsed {
    pub(crate) bundle: orchard::pczt::Bundle,
    pub(crate) wire_anchor: Option<[u8; 32]>,
}

#[cfg(feature = "orchard")]
impl Parsed {
    /// Serializes the parsed bundle back into its wire representation, using
    /// [`Self::wire_anchor`] as the result's `anchor` in place of any placeholder
    /// substituted while parsing.
    ///
    /// Must not be used after an operation that legitimately changes the anchor;
    /// such operations should set `wire_anchor` to the new value first.
    pub(crate) fn reserialize(self) -> Bundle {
        Bundle {
            anchor: self.wire_anchor,
            ..Bundle::serialize_from(self.bundle)
        }
    }
}

/// Shared fixtures for hand-crafting Orchard-protocol PCZT test data.
#[cfg(all(test, feature = "orchard"))]
pub(crate) mod testing {
    use alloc::collections::BTreeMap;

    use pasta_curves::pallas;

    use super::{Action, EncCiphertext, Output, Spend};

    /// Derives a valid Orchard value commitment encoding for the given value and
    /// trapdoor, so that hand-crafted `Action`s pass the structural validity check
    /// applied when parsing (regardless of anchor consistency, which is unrelated).
    pub(crate) fn value_commitment(value: u64, rcv: [u8; 32]) -> [u8; 32] {
        let rcv = orchard::value::ValueCommitTrapdoor::from_bytes(rcv)
            .into_option()
            .unwrap();
        let value_sum =
            orchard::value::NoteValue::from_raw(value) - orchard::value::NoteValue::from_raw(0);
        orchard::value::ValueCommitment::derive(value_sum, rcv).to_bytes()
    }

    /// Derives a valid, randomized `rk` encoding (a curve point, unlike an arbitrary
    /// byte string) so that hand-crafted `Spend`s pass the structural validity check
    /// applied when parsing.
    pub(crate) fn randomized_verification_key() -> [u8; 32] {
        use ff::Field;

        let sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
        let ask = orchard::keys::SpendAuthorizingKey::from(&sk);
        let randomized_signing_key = ask.randomize(&pallas::Scalar::ONE);
        let rk: orchard::primitives::redpallas::VerificationKey<
            orchard::primitives::redpallas::SpendAuth,
        > = (&randomized_signing_key).into();
        (&rk).into()
    }

    /// A structurally valid dummy Orchard action with no witness (so it is exempt
    /// from anchor-consistency checks), for use as a base in hand-crafted test PCZTs.
    pub(crate) fn dummy_action() -> Action {
        Action {
            cv_net: Some(value_commitment(0, [3; 32])),
            spend: Spend {
                nullifier: [2; 32],
                rk: randomized_verification_key(),
                spend_auth_sig: None,
                recipient: None,
                value: None,
                rho: None,
                rseed: None,
                fvk: None,
                witness: None,
                alpha: None,
                zip32_derivation: None,
                dummy_sk: None,
                proprietary: BTreeMap::new(),
            },
            output: Output {
                cmx: Some([4; 32]),
                ephemeral_key: [5; 32],
                enc_ciphertext: EncCiphertext::Encrypted(alloc::vec![6; 580]),
                out_ciphertext: alloc::vec![7; 80],
                recipient: None,
                value: None,
                rseed: None,
                ock: None,
                zip32_derivation: None,
                user_address: None,
                proprietary: BTreeMap::new(),
            },
            rcv: None,
        }
    }
}

/// A memo plaintext with all trailing zero bytes stripped.
///
/// This is the memo portion of an Orchard note plaintext, not the full note
/// plaintext. It is expanded back to the protocol memo size before recomputing
/// [`EncCiphertext::Encrypted`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoPlaintext(Vec<u8>);

impl MemoPlaintext {
    /// Constructs a stripped memo plaintext from a full memo.
    pub fn from_memo(memo: [u8; MEMO_SIZE]) -> Self {
        let len = memo.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
        Self(memo[..len].to_vec())
    }

    /// Constructs a stripped memo plaintext from its encoded bytes.
    ///
    /// Returns an error if `bytes` is longer than [`MEMO_SIZE`], or if it
    /// contains any trailing zero bytes.
    fn from_stripped_bytes(bytes: Vec<u8>) -> Result<Self, MemoPlaintextError> {
        if bytes.len() > MEMO_SIZE {
            Err(MemoPlaintextError::TooLong)
        } else if bytes.last() == Some(&0) {
            Err(MemoPlaintextError::NotStripped)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns the trailing-zero-stripped memo plaintext bytes.
    pub fn as_stripped_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Expands this memo plaintext to its full-size protocol encoding.
    pub fn to_memo(&self) -> [u8; MEMO_SIZE] {
        let mut memo = [0; MEMO_SIZE];
        memo[..self.0.len()].copy_from_slice(&self.0);
        memo
    }
}

impl Serialize for MemoPlaintext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MemoPlaintext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::from_stripped_bytes(bytes).map_err(de::Error::custom)
    }
}

/// The encrypted note plaintext for an output, or the memo plaintext needed to
/// recompute it.
///
/// [`EncCiphertext::MemoPlaintext`] can be resolved to
/// [`EncCiphertext::Encrypted`] from the output note fields and the action's
/// spend nullifier.
///
/// The variant order is part of the v2 wire encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncCiphertext {
    /// The encrypted note plaintext for the output.
    Encrypted(Vec<u8>),
    /// The note's memo plaintext, with trailing zero bytes stripped.
    MemoPlaintext(MemoPlaintext),
}

impl EncCiphertext {
    /// Consumes this value and returns the encrypted note plaintext, if present.
    pub fn into_encrypted(self) -> Option<Vec<u8>> {
        match self {
            EncCiphertext::Encrypted(ciphertext) => Some(ciphertext),
            EncCiphertext::MemoPlaintext(_) => None,
        }
    }
}

#[cfg(feature = "orchard")]
fn recover_memo_plaintext_from_ciphertext_and_action(
    action: &Action,
    note_version: NoteVersion,
) -> Option<MemoPlaintext> {
    use ::orchard::{
        Address, Note,
        note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho},
        note_encryption::{CompactAction, IronwoodDomain, OrchardDomain},
        value::NoteValue,
    };
    use zcash_note_encryption::{COMPACT_NOTE_SIZE, try_output_recovery_with_pkd_esk};

    struct OutputRecoveryData {
        cmx: [u8; 32],
        ephemeral_key: [u8; 32],
        enc_ciphertext: [u8; ENC_CIPHERTEXT_SIZE],
    }

    impl<D> ShieldedOutput<D, ENC_CIPHERTEXT_SIZE> for OutputRecoveryData
    where
        D: Domain<ExtractedCommitmentBytes = [u8; 32]>,
    {
        fn ephemeral_key(&self) -> EphemeralKeyBytes {
            EphemeralKeyBytes(self.ephemeral_key)
        }

        fn cmstar_bytes(&self) -> [u8; 32] {
            self.cmx
        }

        fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
            &self.enc_ciphertext
        }
    }

    fn recover_with_domain<D>(
        domain: &D,
        note: &Note,
        output: &OutputRecoveryData,
    ) -> Option<MemoPlaintext>
    where
        D: Domain<Note = Note, Memo = [u8; MEMO_SIZE], ExtractedCommitmentBytes = [u8; 32]>,
    {
        let pk_d = D::get_pk_d(note);
        let esk = D::derive_esk(note)?;

        try_output_recovery_with_pkd_esk(domain, pk_d, esk, output)
            .map(|(_, _, memo)| MemoPlaintext::from_memo(memo))
    }

    let enc_ciphertext = match &action.output.enc_ciphertext {
        EncCiphertext::Encrypted(ciphertext) => ciphertext.as_slice().try_into().ok()?,
        // we return None here to avoid excess sets or clone operations, as the caller need not do anything in this case.
        EncCiphertext::MemoPlaintext(_) => return None,
    };
    let recipient = Option::from(Address::from_raw_address_bytes(
        action.output.recipient.as_ref()?,
    ))?;
    let rho = Option::from(Rho::from_bytes(&action.spend.nullifier))?;
    let rseed = Option::from(RandomSeed::from_bytes(*action.output.rseed.as_ref()?, &rho))?;
    let note = Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(action.output.value?),
        rho,
        rseed,
        note_version,
    ))?;

    let nullifier = Option::from(Nullifier::from_bytes(&action.spend.nullifier))?;
    // Memo recovery is best-effort and should not resolve redacted fields.
    // Callers that want redacted `cmx` restored should use `resolve_fields`.
    let cmx_bytes = action.output.cmx?;
    let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&cmx_bytes))?;
    let output = OutputRecoveryData {
        cmx: cmx_bytes,
        ephemeral_key: action.output.ephemeral_key,
        enc_ciphertext,
    };
    let compact_action = CompactAction::from_parts(
        nullifier,
        cmx,
        EphemeralKeyBytes(action.output.ephemeral_key),
        output.enc_ciphertext[..COMPACT_NOTE_SIZE].try_into().ok()?,
    );

    match note_version {
        NoteVersion::V2 => recover_with_domain(
            &OrchardDomain::for_compact_action(&compact_action),
            &note,
            &output,
        ),
        NoteVersion::V3 => recover_with_domain(
            &IronwoodDomain::for_compact_action(&compact_action),
            &note,
            &output,
        ),
    }
}

#[cfg(feature = "orchard")]
impl Action {
    pub(crate) fn replace_enc_ciphertext_with_decrypted_memo_plaintext(
        &mut self,
        note_version: NoteVersion,
    ) {
        if let Some(memo) = recover_memo_plaintext_from_ciphertext_and_action(self, note_version) {
            self.output.enc_ciphertext = EncCiphertext::MemoPlaintext(memo);
        }
    }

    pub(crate) fn redact_recomputable_fields(&mut self, note_version: NoteVersion) {
        let original_enc_ciphertext = self.output.enc_ciphertext.clone();
        self.replace_enc_ciphertext_with_decrypted_memo_plaintext(note_version);
        if self.output.enc_ciphertext != original_enc_ciphertext {
            let mut resolved = self.output.clone();
            if resolved
                .encrypt_ciphertext_from_memo(note_version, self.spend.nullifier)
                .is_err()
                || resolved.enc_ciphertext != original_enc_ciphertext
            {
                self.output.enc_ciphertext = original_enc_ciphertext;
            }
        }

        if let Some(original_cv_net) = self.cv_net {
            let mut resolved = self.clone();
            resolved.cv_net = None;
            if resolved.resolve_cv_net().is_ok() && resolved.cv_net == Some(original_cv_net) {
                self.cv_net = None;
            }
        }

        if let Some(original_cmx) = self.output.cmx {
            let mut resolved = self.output.clone();
            resolved.cmx = None;
            if resolved
                .resolve_cmx(note_version, self.spend.nullifier)
                .is_ok()
                && resolved.cmx == Some(original_cmx)
            {
                self.output.cmx = None;
            }
        }
    }
}

/// Information about an Orchard action within a transaction.
#[derive(Clone, Debug, PartialEq, Getters)]
pub struct Action {
    //
    // Action effecting data.
    //
    // These fields describe the action as a whole. `cv_net` is part of the
    // final transaction, but may be redacted in v2 and recomputed from the note
    // values and `rcv`.
    //
    #[getset(get = "pub")]
    pub(crate) cv_net: Option<[u8; 32]>,
    #[getset(get = "pub")]
    pub(crate) spend: Spend,
    #[getset(get = "pub")]
    pub(crate) output: Output,

    /// The value commitment randomness.
    ///
    /// - This is set by the Constructor.
    /// - The IO Finalizer compresses it into the bsk.
    /// - This is required by the Prover.
    /// - This may be used by Signers to verify that the value correctly matches `cv`.
    ///
    /// This opens `cv` for all participants. For Signers who don't need this information,
    /// or after proofs / signatures have been applied, this can be redacted.
    pub(crate) rcv: Option<[u8; 32]>,
}

/// Information about the spend part of an Orchard action.
#[derive(Clone, Debug, PartialEq, Getters)]
pub struct Spend {
    //
    // Spend-specific Action effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding a spend.
    //
    #[getset(get = "pub")]
    pub(crate) nullifier: [u8; 32],
    #[getset(get = "pub")]
    pub(crate) rk: [u8; 32],

    /// The spend authorization signature.
    ///
    /// This is set by the Signer.
    #[getset(get = "pub")]
    pub(crate) spend_auth_sig: Option<[u8; 64]>,

    /// The [raw encoding] of the Orchard payment address that received the note being spent.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    ///
    /// [raw encoding]: https://zips.z.cash/protocol/protocol.pdf#orchardpaymentaddrencoding
    pub(crate) recipient: Option<[u8; 43]>,

    /// The value of the input being spent.
    ///
    /// - This is required by the Prover.
    /// - This may be used by Signers to verify that the value matches `cv`, and to
    ///   confirm the values and change involved in the transaction.
    ///
    /// This exposes the input value to all participants. For Signers who don't need this
    /// information, or after signatures have been applied, this can be redacted.
    pub(crate) value: Option<u64>,

    /// The rho value for the note being spent.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    pub(crate) rho: Option<[u8; 32]>,

    /// The seed randomness for the note being spent.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    pub(crate) rseed: Option<[u8; 32]>,

    /// The full viewing key that received the note being spent.
    ///
    /// - This is set by the Updater.
    /// - This is required by the Prover.
    pub(crate) fvk: Option<[u8; 96]>,

    /// A witness from the note to the bundle's anchor.
    ///
    /// - This is set by the Updater.
    /// - This is required by the Prover.
    pub(crate) witness: Option<(u32, [[u8; 32]; 32])>,

    /// The spend authorization randomizer.
    ///
    /// - This is chosen by the Constructor.
    /// - This is required by the Signer for creating `spend_auth_sig`, and may be used to
    ///   validate `rk`.
    /// - After `zkproof` / `spend_auth_sig` has been set, this can be redacted.
    pub(crate) alpha: Option<[u8; 32]>,

    /// The ZIP 32 derivation path at which the spending key can be found for the note
    /// being spent.
    pub(crate) zip32_derivation: Option<Zip32Derivation>,

    /// The spending key for this spent note, if it is a dummy note.
    ///
    /// - This is chosen by the Constructor.
    /// - This is required by the IO Finalizer, and is cleared by it once used.
    /// - Signers MUST reject PCZTs that contain `dummy_sk` values.
    pub(crate) dummy_sk: Option<[u8; 32]>,

    /// Proprietary fields related to the note being spent.
    #[getset(get = "pub")]
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

/// Information about the output part of an Orchard action.
#[derive(Clone, Debug, PartialEq, Getters)]
pub struct Output {
    //
    // Output-specific Action effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    #[getset(get = "pub")]
    pub(crate) cmx: Option<[u8; 32]>,
    #[getset(get = "pub")]
    pub(crate) ephemeral_key: [u8; 32],
    /// The encrypted note plaintext for the output, or the memo plaintext
    /// needed to recompute it.
    #[getset(get = "pub")]
    pub(crate) enc_ciphertext: EncCiphertext,
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    #[getset(get = "pub")]
    pub(crate) out_ciphertext: Vec<u8>,

    /// The [raw encoding] of the Orchard payment address that will receive the output.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    ///
    /// [raw encoding]: https://zips.z.cash/protocol/protocol.pdf#orchardpaymentaddrencoding
    #[getset(get = "pub")]
    pub(crate) recipient: Option<[u8; 43]>,

    /// The value of the output.
    ///
    /// This may be used by Signers to verify that the value matches `cv`, and to confirm
    /// the values and change involved in the transaction.
    ///
    /// This exposes the value to all participants. For Signers who don't need this
    /// information, we can drop the values and compress the rcvs into the bsk global.
    #[getset(get = "pub")]
    pub(crate) value: Option<u64>,

    /// The seed randomness for the output.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover, instead of disclosing `shared_secret` to them.
    #[getset(get = "pub")]
    pub(crate) rseed: Option<[u8; 32]>,

    /// The `ock` value used to encrypt `out_ciphertext`.
    ///
    /// This enables Signers to verify that `out_ciphertext` is correctly encrypted.
    ///
    /// This may be `None` if the Constructor added the output using an OVK policy of
    /// "None", to make the output unrecoverable from the chain by the sender.
    pub(crate) ock: Option<[u8; 32]>,

    /// The ZIP 32 derivation path at which the spending key can be found for the output.
    pub(crate) zip32_derivation: Option<Zip32Derivation>,

    /// The user-facing address to which this output is being sent, if any.
    ///
    /// - This is set by an Updater.
    /// - Signers must parse this address (if present) and confirm that it contains
    ///   `recipient` (either directly, or e.g. as a receiver within a Unified Address).
    #[getset(get = "pub")]
    pub(crate) user_address: Option<String>,

    /// Proprietary fields related to the note being created.
    #[getset(get = "pub")]
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

/// Types for the v1 Orchard PCZT encoding.
pub mod v1 {
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec::Vec;

    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    use crate::common::Zip32Derivation;

    use super::NoteVersion;

    /// PCZT fields that are specific to producing the transaction's Orchard bundle.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Bundle {
        actions: Vec<Action>,
        flags: u8,
        value_sum: (u64, bool),
        anchor: [u8; 32],
        zkproof: Option<Vec<u8>>,
        bsk: Option<[u8; 32]>,
    }

    /// Information about an Orchard action within a transaction.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct Action {
        cv_net: [u8; 32],
        spend: Spend,
        output: Output,
        rcv: Option<[u8; 32]>,
    }

    /// Information about the spend part of an Orchard action.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct Spend {
        nullifier: [u8; 32],
        rk: [u8; 32],
        #[serde_as(as = "Option<[_; 64]>")]
        spend_auth_sig: Option<[u8; 64]>,
        #[serde_as(as = "Option<[_; 43]>")]
        recipient: Option<[u8; 43]>,
        value: Option<u64>,
        rho: Option<[u8; 32]>,
        rseed: Option<[u8; 32]>,
        #[serde_as(as = "Option<[_; 96]>")]
        fvk: Option<[u8; 96]>,
        witness: Option<(u32, [[u8; 32]; 32])>,
        alpha: Option<[u8; 32]>,
        zip32_derivation: Option<Zip32Derivation>,
        dummy_sk: Option<[u8; 32]>,
        proprietary: BTreeMap<String, Vec<u8>>,
    }

    /// Information about the output part of an Orchard action.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct Output {
        cmx: [u8; 32],
        ephemeral_key: [u8; 32],
        enc_ciphertext: Vec<u8>,
        out_ciphertext: Vec<u8>,
        #[serde_as(as = "Option<[_; 43]>")]
        recipient: Option<[u8; 43]>,
        value: Option<u64>,
        rseed: Option<[u8; 32]>,
        ock: Option<[u8; 32]>,
        zip32_derivation: Option<Zip32Derivation>,
        user_address: Option<String>,
        proprietary: BTreeMap<String, Vec<u8>>,
    }

    impl TryFrom<super::Bundle> for Bundle {
        type Error = crate::EncodingError;

        fn try_from(bundle: super::Bundle) -> Result<Self, Self::Error> {
            if bundle.note_version != NoteVersion::V2 {
                return Err(crate::EncodingError::UnsupportedOrchardNoteVersion);
            }

            Ok(Self {
                actions: bundle
                    .actions
                    .into_iter()
                    .map(Action::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
                flags: bundle.flags,
                value_sum: bundle.value_sum,
                anchor: bundle.anchor.ok_or(crate::EncodingError::RequiresV2)?,
                zkproof: bundle.zkproof,
                bsk: bundle.bsk,
            })
        }
    }

    impl From<Bundle> for super::Bundle {
        fn from(bundle: Bundle) -> Self {
            Self {
                actions: bundle
                    .actions
                    .into_iter()
                    .map(super::Action::from)
                    .collect(),
                flags: bundle.flags,
                value_sum: bundle.value_sum,
                anchor: Some(bundle.anchor),
                note_version: NoteVersion::V2,
                zkproof: bundle.zkproof,
                bsk: bundle.bsk,
            }
        }
    }

    impl TryFrom<super::Action> for Action {
        type Error = crate::EncodingError;

        fn try_from(action: super::Action) -> Result<Self, Self::Error> {
            Ok(Self {
                cv_net: action.cv_net.ok_or(crate::EncodingError::RequiresV2)?,
                spend: Spend::from(action.spend),
                output: Output::try_from(action.output)?,
                rcv: action.rcv,
            })
        }
    }

    impl From<Action> for super::Action {
        fn from(action: Action) -> Self {
            Self {
                cv_net: Some(action.cv_net),
                spend: super::Spend::from(action.spend),
                output: super::Output::from(action.output),
                rcv: action.rcv,
            }
        }
    }

    impl From<super::Spend> for Spend {
        fn from(spend: super::Spend) -> Self {
            Self {
                nullifier: spend.nullifier,
                rk: spend.rk,
                spend_auth_sig: spend.spend_auth_sig,
                recipient: spend.recipient,
                value: spend.value,
                rho: spend.rho,
                rseed: spend.rseed,
                fvk: spend.fvk,
                witness: spend.witness,
                alpha: spend.alpha,
                zip32_derivation: spend.zip32_derivation,
                dummy_sk: spend.dummy_sk,
                proprietary: spend.proprietary,
            }
        }
    }

    impl From<Spend> for super::Spend {
        fn from(spend: Spend) -> Self {
            Self {
                nullifier: spend.nullifier,
                rk: spend.rk,
                spend_auth_sig: spend.spend_auth_sig,
                recipient: spend.recipient,
                value: spend.value,
                rho: spend.rho,
                rseed: spend.rseed,
                fvk: spend.fvk,
                witness: spend.witness,
                alpha: spend.alpha,
                zip32_derivation: spend.zip32_derivation,
                dummy_sk: spend.dummy_sk,
                proprietary: spend.proprietary,
            }
        }
    }

    impl TryFrom<super::Output> for Output {
        type Error = crate::EncodingError;

        fn try_from(output: super::Output) -> Result<Self, Self::Error> {
            let enc_ciphertext = output
                .enc_ciphertext
                .into_encrypted()
                .ok_or(crate::EncodingError::RequiresV2)?;

            Ok(Self {
                cmx: output.cmx.ok_or(crate::EncodingError::RequiresV2)?,
                ephemeral_key: output.ephemeral_key,
                enc_ciphertext,
                out_ciphertext: output.out_ciphertext,
                recipient: output.recipient,
                value: output.value,
                rseed: output.rseed,
                ock: output.ock,
                zip32_derivation: output.zip32_derivation,
                user_address: output.user_address,
                proprietary: output.proprietary,
            })
        }
    }

    impl From<Output> for super::Output {
        fn from(output: Output) -> Self {
            Self {
                cmx: Some(output.cmx),
                ephemeral_key: output.ephemeral_key,
                enc_ciphertext: super::EncCiphertext::Encrypted(output.enc_ciphertext),
                out_ciphertext: output.out_ciphertext,
                recipient: output.recipient,
                value: output.value,
                rseed: output.rseed,
                ock: output.ock,
                zip32_derivation: output.zip32_derivation,
                user_address: output.user_address,
                proprietary: output.proprietary,
            }
        }
    }
}

/// Types for the v2 Orchard PCZT encoding.
pub(crate) mod v2 {
    use alloc::{collections::BTreeMap, string::String, vec::Vec};

    use getset::Getters;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    use super::NoteVersion;

    /// A serializable representation of Orchard note plaintext versions.
    #[derive(Clone, Copy, Debug, Serialize, Deserialize)]
    enum SerializedNoteVersion {
        V2,
        V3,
    }

    impl From<NoteVersion> for SerializedNoteVersion {
        fn from(note_version: NoteVersion) -> Self {
            match note_version {
                NoteVersion::V2 => Self::V2,
                NoteVersion::V3 => Self::V3,
            }
        }
    }

    impl From<SerializedNoteVersion> for NoteVersion {
        fn from(note_version: SerializedNoteVersion) -> Self {
            match note_version {
                SerializedNoteVersion::V2 => Self::V2,
                SerializedNoteVersion::V3 => Self::V3,
            }
        }
    }

    /// PCZT fields that are specific to producing the transaction's Orchard bundle.
    #[derive(Clone, Debug, Serialize, Deserialize, Getters)]
    pub struct Bundle {
        actions: Vec<Action>,
        flags: u8,
        value_sum: (u64, bool),
        anchor: Option<[u8; 32]>,
        note_version: SerializedNoteVersion,
        zkproof: Option<Vec<u8>>,
        bsk: Option<[u8; 32]>,
    }

    /// Information about an Orchard action within a transaction.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct Action {
        cv_net: Option<[u8; 32]>,
        spend: Spend,
        output: Output,
        rcv: Option<[u8; 32]>,
    }

    /// Information about the spend part of an Orchard action.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct Spend {
        #[serde_as(as = "Option<[_; 32]>")]
        nullifier: Option<[u8; 32]>,
        #[serde_as(as = "Option<[_; 32]>")]
        rk: Option<[u8; 32]>,
        #[serde_as(as = "Option<[_; 64]>")]
        spend_auth_sig: Option<[u8; 64]>,
        #[serde_as(as = "Option<[_; 43]>")]
        recipient: Option<[u8; 43]>,
        value: Option<u64>,
        rho: Option<[u8; 32]>,
        rseed: Option<[u8; 32]>,
        #[serde_as(as = "Option<[_; 96]>")]
        fvk: Option<[u8; 96]>,
        witness: Option<(u32, [[u8; 32]; 32])>,
        alpha: Option<[u8; 32]>,
        zip32_derivation: Option<crate::common::Zip32Derivation>,
        dummy_sk: Option<[u8; 32]>,
        proprietary: BTreeMap<String, Vec<u8>>,
    }

    /// Information about the output part of an Orchard action.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct Output {
        cmx: Option<[u8; 32]>,
        ephemeral_key: [u8; 32],
        enc_ciphertext: super::EncCiphertext,
        out_ciphertext: Vec<u8>,
        #[serde_as(as = "Option<[_; 43]>")]
        recipient: Option<[u8; 43]>,
        value: Option<u64>,
        rseed: Option<[u8; 32]>,
        ock: Option<[u8; 32]>,
        zip32_derivation: Option<crate::common::Zip32Derivation>,
        user_address: Option<String>,
        proprietary: BTreeMap<String, Vec<u8>>,
    }

    impl TryFrom<super::Bundle> for Bundle {
        type Error = crate::EncodingError;

        fn try_from(bundle: super::Bundle) -> Result<Self, Self::Error> {
            Ok(Self {
                actions: bundle
                    .actions
                    .into_iter()
                    .map(Action::from)
                    .collect::<Vec<_>>(),
                flags: bundle.flags,
                value_sum: bundle.value_sum,
                anchor: bundle.anchor,
                note_version: bundle.note_version.into(),
                zkproof: bundle.zkproof,
                bsk: bundle.bsk,
            })
        }
    }

    impl Bundle {
        pub(crate) fn into_logical(self) -> Result<super::Bundle, crate::ParseError> {
            Ok(super::Bundle {
                actions: self
                    .actions
                    .into_iter()
                    .map(Action::into_logical)
                    .collect::<Result<Vec<_>, _>>()?,
                flags: self.flags,
                value_sum: self.value_sum,
                anchor: self.anchor,
                note_version: self.note_version.into(),
                zkproof: self.zkproof,
                bsk: self.bsk,
            })
        }
    }

    impl From<super::Action> for Action {
        fn from(action: super::Action) -> Self {
            Self {
                cv_net: action.cv_net,
                spend: Spend::from(action.spend),
                output: Output::from(action.output),
                rcv: action.rcv,
            }
        }
    }

    impl Action {
        fn into_logical(self) -> Result<super::Action, crate::ParseError> {
            Ok(super::Action {
                cv_net: self.cv_net,
                spend: self.spend.into_logical()?,
                output: super::Output::from(self.output),
                rcv: self.rcv,
            })
        }
    }

    impl From<super::Spend> for Spend {
        fn from(spend: super::Spend) -> Self {
            Self {
                nullifier: Some(spend.nullifier),
                rk: Some(spend.rk),
                spend_auth_sig: spend.spend_auth_sig,
                recipient: spend.recipient,
                value: spend.value,
                rho: spend.rho,
                rseed: spend.rseed,
                fvk: spend.fvk,
                witness: spend.witness,
                alpha: spend.alpha,
                zip32_derivation: spend.zip32_derivation,
                dummy_sk: spend.dummy_sk,
                proprietary: spend.proprietary,
            }
        }
    }

    impl Spend {
        fn into_logical(self) -> Result<super::Spend, crate::ParseError> {
            Ok(super::Spend {
                nullifier: self
                    .nullifier
                    .ok_or(crate::ParseError::MissingRequiredField(
                        "orchard.actions[].spend.nullifier",
                    ))?,
                rk: self.rk.ok_or(crate::ParseError::MissingRequiredField(
                    "orchard.actions[].spend.rk",
                ))?,
                spend_auth_sig: self.spend_auth_sig,
                recipient: self.recipient,
                value: self.value,
                rho: self.rho,
                rseed: self.rseed,
                fvk: self.fvk,
                witness: self.witness,
                alpha: self.alpha,
                zip32_derivation: self.zip32_derivation,
                dummy_sk: self.dummy_sk,
                proprietary: self.proprietary,
            })
        }
    }

    impl From<super::Output> for Output {
        fn from(output: super::Output) -> Self {
            Self {
                cmx: output.cmx,
                ephemeral_key: output.ephemeral_key,
                enc_ciphertext: output.enc_ciphertext,
                out_ciphertext: output.out_ciphertext,
                recipient: output.recipient,
                value: output.value,
                rseed: output.rseed,
                ock: output.ock,
                zip32_derivation: output.zip32_derivation,
                user_address: output.user_address,
                proprietary: output.proprietary,
            }
        }
    }

    impl From<Output> for super::Output {
        fn from(output: Output) -> Self {
            Self {
                cmx: output.cmx,
                ephemeral_key: output.ephemeral_key,
                enc_ciphertext: output.enc_ciphertext,
                out_ciphertext: output.out_ciphertext,
                recipient: output.recipient,
                value: output.value,
                rseed: output.rseed,
                ock: output.ock,
                zip32_derivation: output.zip32_derivation,
                user_address: output.user_address,
                proprietary: output.proprietary,
            }
        }
    }

    /// Encodes a logical Orchard-protocol bundle for the v2 PCZT format, owning the
    /// decision of whether the bundle can be omitted. A bundle that is exactly equal
    /// to `empty` (the canonical empty bundle for its slot, [`super::EMPTY_ORCHARD`]
    /// or [`super::EMPTY_IRONWOOD`]) serializes to `None` and is dropped from the
    /// encoding. An otherwise-empty bundle carrying [`super::DEFAULT_ANCHOR`] is
    /// treated as empty for this purpose; any other bundle is converted via the
    /// [`Bundle`]-producing [`TryFrom`] impl. The reverse direction is
    /// [`From<Bundle>`] plus the canonical empty bundle for the omitted case.
    pub(crate) fn encode(
        bundle: super::Bundle,
        empty: &super::Bundle,
    ) -> Result<Option<Bundle>, crate::EncodingError> {
        (!is_default_empty(&bundle, empty))
            .then(|| Bundle::try_from(bundle))
            .transpose()
    }

    fn is_default_empty(bundle: &super::Bundle, empty: &super::Bundle) -> bool {
        let mut bundle = bundle.clone();
        if bundle.anchor == Some(super::DEFAULT_ANCHOR) {
            bundle.anchor = None;
        }

        bundle == *empty
    }

    #[cfg(test)]
    mod tests {
        use alloc::{collections::BTreeMap, vec::Vec};

        use super::super::{
            Action as LogicalAction, Bundle as LogicalBundle, EncCiphertext, MEMO_SIZE,
            MemoPlaintext, NoteVersion, ORCHARD_SPENDS_AND_OUTPUTS_ENABLED, Output, Spend,
        };

        fn logical_action(cv_net: Option<[u8; 32]>, cmx: Option<[u8; 32]>) -> LogicalAction {
            LogicalAction {
                cv_net,
                spend: Spend {
                    nullifier: [1; 32],
                    rk: [2; 32],
                    spend_auth_sig: None,
                    recipient: None,
                    value: None,
                    rho: None,
                    rseed: None,
                    fvk: None,
                    witness: None,
                    alpha: None,
                    zip32_derivation: None,
                    dummy_sk: None,
                    proprietary: BTreeMap::new(),
                },
                output: Output {
                    cmx,
                    ephemeral_key: [4; 32],
                    enc_ciphertext: EncCiphertext::Encrypted(Vec::new()),
                    out_ciphertext: Vec::new(),
                    recipient: None,
                    value: None,
                    rseed: None,
                    ock: None,
                    zip32_derivation: None,
                    user_address: None,
                    proprietary: BTreeMap::new(),
                },
                rcv: None,
            }
        }

        fn logical_bundle(anchor: Option<[u8; 32]>, cv_net: Option<[u8; 32]>) -> LogicalBundle {
            logical_bundle_with_cmx(anchor, cv_net, Some([3; 32]))
        }

        fn logical_bundle_with_cmx(
            anchor: Option<[u8; 32]>,
            cv_net: Option<[u8; 32]>,
            cmx: Option<[u8; 32]>,
        ) -> LogicalBundle {
            LogicalBundle {
                actions: vec![logical_action(cv_net, cmx)],
                flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
                value_sum: (0, false),
                anchor,
                note_version: NoteVersion::V2,
                zkproof: None,
                bsk: None,
            }
        }

        #[test]
        fn anchor_cv_net_and_cmx_round_trip_optional_encoding() {
            for (anchor, cv_net, cmx) in [
                (None, None, None),
                (Some([5; 32]), Some([6; 32]), Some([7; 32])),
            ] {
                let bundle = logical_bundle_with_cmx(anchor, cv_net, cmx);

                let encoded = super::Bundle::try_from(bundle.clone()).unwrap();
                assert_eq!(encoded.anchor, anchor);
                assert_eq!(encoded.actions[0].cv_net, cv_net);
                assert_eq!(encoded.actions[0].output.cmx, cmx);

                let decoded = encoded.into_logical().unwrap();
                assert_eq!(decoded, bundle);
            }
        }

        #[test]
        fn missing_spend_nullifier_or_rk_is_rejected() {
            let bundle = logical_bundle(Some([5; 32]), Some([6; 32]));

            for (clear_field, missing_field) in [
                (
                    (|spend: &mut super::Spend| spend.nullifier = None) as fn(&mut super::Spend),
                    "orchard.actions[].spend.nullifier",
                ),
                (
                    |spend: &mut super::Spend| spend.rk = None,
                    "orchard.actions[].spend.rk",
                ),
            ] {
                let mut encoded = super::Bundle::try_from(bundle.clone()).unwrap();
                assert_eq!(encoded.actions[0].spend.nullifier, Some([1; 32]));
                assert_eq!(encoded.actions[0].spend.rk, Some([2; 32]));

                clear_field(&mut encoded.actions[0].spend);

                assert!(matches!(
                    encoded.into_logical(),
                    Err(crate::ParseError::MissingRequiredField(field)) if field == missing_field
                ));
            }
        }

        #[test]
        fn memo_plaintext_strips_and_expands_trailing_zeroes() {
            let mut memo = [0; MEMO_SIZE];
            memo[..5].copy_from_slice(b"hello");

            let plaintext = MemoPlaintext::from_memo(memo);

            assert_eq!(plaintext.as_stripped_bytes(), b"hello");
            assert_eq!(plaintext.to_memo(), memo);
        }

        #[cfg(feature = "orchard")]
        fn decryptable_action_with_memo(memo: [u8; MEMO_SIZE]) -> LogicalAction {
            use ::orchard::{
                Note,
                keys::{FullViewingKey, Scope, SpendingKey},
                note::{ExtractedNoteCommitment, RandomSeed, Rho},
                note_encryption::{OrchardDomain, OrchardNoteEncryption},
                value::NoteValue,
            };
            use zcash_note_encryption::Domain;

            let mut nullifier = [0; 32];
            nullifier[0] = 1;
            let rho = Option::from(Rho::from_bytes(&nullifier)).unwrap();
            let (_, rseed) = (0u8..)
                .find_map(|i| {
                    let mut rseed = [0; 32];
                    rseed[0] = i;
                    Option::from(RandomSeed::from_bytes(rseed, &rho)).map(|parsed| (rseed, parsed))
                })
                .unwrap();
            let recipient = FullViewingKey::from(&SpendingKey::from_bytes([0; 32]).unwrap())
                .address_at(0u32, Scope::External);
            let value = NoteValue::from_raw(100_000);
            let note = Option::from(Note::from_parts(
                recipient,
                value,
                rho,
                rseed,
                NoteVersion::V2,
            ))
            .unwrap();

            let encryptor = OrchardNoteEncryption::new(None, note, memo);

            LogicalAction {
                cv_net: Some([0; 32]),
                spend: Spend {
                    nullifier,
                    rk: [2; 32],
                    spend_auth_sig: None,
                    recipient: None,
                    value: None,
                    rho: None,
                    rseed: None,
                    fvk: None,
                    witness: None,
                    alpha: None,
                    zip32_derivation: None,
                    dummy_sk: None,
                    proprietary: BTreeMap::new(),
                },
                output: Output {
                    cmx: Some(ExtractedNoteCommitment::from(note.commitment()).to_bytes()),
                    ephemeral_key: OrchardDomain::epk_bytes(encryptor.epk()).0,
                    enc_ciphertext: EncCiphertext::Encrypted(
                        encryptor.encrypt_note_plaintext().to_vec(),
                    ),
                    out_ciphertext: Vec::new(),
                    recipient: Some(recipient.to_raw_address_bytes()),
                    value: Some(value.inner()),
                    rseed: Some(*note.rseed().as_bytes()),
                    ock: None,
                    zip32_derivation: None,
                    user_address: None,
                    proprietary: BTreeMap::new(),
                },
                rcv: None,
            }
        }

        #[cfg(feature = "orchard")]
        #[test]
        fn v2_round_trips_memo_plaintext_ciphertext_data() {
            use zcash_protocol::consensus::BranchId;

            use crate::{roles::creator::Creator, roles::redactor::Redactor};

            const HELLO_MEMO_PAYLOAD_SIZE_REDUCTION: usize = 575;
            // The serialized reduction is one byte larger because postcard uses
            // a shorter length prefix for the stripped memo plaintext.
            const HELLO_MEMO_SERIALIZED_SIZE_REDUCTION: usize =
                HELLO_MEMO_PAYLOAD_SIZE_REDUCTION + 1;

            let mut memo = [0; MEMO_SIZE];
            memo[..5].copy_from_slice(b"hello");

            let mut pczt = Creator::new(
                BranchId::Nu6.into(),
                10_000_000,
                133,
                Some([0; 32]),
                Some([0; 32]),
            )
            .unwrap()
            .build()
            .unwrap();
            pczt.orchard
                .actions
                .push(decryptable_action_with_memo(memo));

            let encrypted_size = pczt.clone().serialize().unwrap().len();
            let redacted = Redactor::new(pczt)
                .redact_orchard_with(|mut orchard| {
                    orchard.redact_actions(|mut action| {
                        action
                            .replace_enc_ciphertext_with_decrypted_memo_plaintext(NoteVersion::V2);
                    });
                })
                .finish();
            let redacted_size = redacted.clone().serialize().unwrap().len();

            assert_eq!(
                redacted.orchard.actions[0].output.enc_ciphertext,
                EncCiphertext::MemoPlaintext(MemoPlaintext::from_memo(memo))
            );
            assert_eq!(
                encrypted_size - redacted_size,
                HELLO_MEMO_SERIALIZED_SIZE_REDUCTION
            );

            let decoded = crate::parse(&redacted.serialize().unwrap()).unwrap();

            assert_eq!(
                decoded.orchard.actions[0].output.enc_ciphertext,
                EncCiphertext::MemoPlaintext(MemoPlaintext::from_memo(memo))
            );
        }

        #[cfg(feature = "orchard")]
        #[test]
        fn resolve_fields_recomputes_cmx() {
            let action = decryptable_action_with_memo([0; MEMO_SIZE]);
            let expected_cmx = action.output.cmx;
            let mut bundle = LogicalBundle {
                actions: vec![action],
                flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
                value_sum: (0, false),
                anchor: None,
                note_version: NoteVersion::V2,
                zkproof: None,
                bsk: None,
            };
            bundle.actions[0].output.cmx = None;

            bundle.resolve_fields().unwrap();

            assert_eq!(bundle.actions[0].output.cmx, expected_cmx);
        }

        #[cfg(feature = "orchard")]
        #[test]
        fn decrypted_memo_plaintext_redaction_skips_decryption_failure() {
            let mut action = decryptable_action_with_memo([0; MEMO_SIZE]);
            let original_enc_ciphertext = match &mut action.output.enc_ciphertext {
                EncCiphertext::Encrypted(enc_ciphertext) => {
                    enc_ciphertext[0] ^= 1;
                    enc_ciphertext.clone()
                }
                EncCiphertext::MemoPlaintext(_) => unreachable!("helper encrypts memo plaintext"),
            };

            action.replace_enc_ciphertext_with_decrypted_memo_plaintext(NoteVersion::V2);

            assert_eq!(
                action.output.enc_ciphertext,
                EncCiphertext::Encrypted(original_enc_ciphertext)
            );
        }

        #[cfg(feature = "orchard")]
        #[test]
        fn recomputable_field_redaction_checks_derived_values() {
            let mut action = decryptable_action_with_memo([0; MEMO_SIZE]);
            action.spend.value = Some(200_000);
            action.rcv = Some([3; 32]);
            action.cv_net = Some(super::super::testing::value_commitment(100_000, [3; 32]));

            action.redact_recomputable_fields(NoteVersion::V2);

            assert_eq!(action.cv_net, None);
            assert_eq!(action.output.cmx, None);
            assert!(matches!(
                action.output.enc_ciphertext,
                EncCiphertext::MemoPlaintext(_)
            ));
        }

        #[cfg(feature = "orchard")]
        #[test]
        fn recomputable_field_redaction_retains_unverifiable_values() {
            let mut action = decryptable_action_with_memo([0; MEMO_SIZE]);
            let original_cv_net = action.cv_net;
            let original_cmx = action.output.cmx;
            let original_enc_ciphertext = action.output.enc_ciphertext.clone();
            action.output.recipient = None;

            action.redact_recomputable_fields(NoteVersion::V2);

            assert_eq!(action.cv_net, original_cv_net);
            assert_eq!(action.output.cmx, original_cmx);
            assert_eq!(action.output.enc_ciphertext, original_enc_ciphertext);
        }

        #[cfg(feature = "orchard")]
        #[test]
        fn recomputable_field_redaction_retains_mismatched_values() {
            let mut action = decryptable_action_with_memo([0; MEMO_SIZE]);
            action.spend.value = Some(200_000);
            action.rcv = Some([3; 32]);
            let mut cv_net = super::super::testing::value_commitment(100_000, [3; 32]);
            cv_net[0] ^= 1;
            action.cv_net = Some(cv_net);
            let mut cmx = action.output.cmx.unwrap();
            cmx[0] ^= 1;
            action.output.cmx = Some(cmx);
            let original_enc_ciphertext = action.output.enc_ciphertext.clone();

            action.redact_recomputable_fields(NoteVersion::V2);

            assert_eq!(action.cv_net, Some(cv_net));
            assert_eq!(action.output.cmx, Some(cmx));
            assert_eq!(action.output.enc_ciphertext, original_enc_ciphertext);
        }

        #[test]
        fn v1_rejects_memo_plaintext_ciphertext_data() {
            let mut bundle = logical_bundle(Some([5; 32]), Some([6; 32]));
            bundle.actions[0].output.enc_ciphertext =
                EncCiphertext::MemoPlaintext(MemoPlaintext::from_memo([0; MEMO_SIZE]));

            assert!(matches!(
                crate::orchard::v1::Bundle::try_from(bundle),
                Err(crate::EncodingError::RequiresV2)
            ));
        }

        #[test]
        fn v1_rejects_missing_anchor_and_cv_net() {
            assert!(matches!(
                crate::orchard::v1::Bundle::try_from(logical_bundle(None, Some([6; 32]))),
                Err(crate::EncodingError::RequiresV2)
            ));

            assert!(matches!(
                crate::orchard::v1::Bundle::try_from(logical_bundle(Some([5; 32]), None)),
                Err(crate::EncodingError::RequiresV2)
            ));

            assert!(matches!(
                crate::orchard::v1::Bundle::try_from(logical_bundle_with_cmx(
                    Some([5; 32]),
                    Some([6; 32]),
                    None
                )),
                Err(crate::EncodingError::RequiresV2)
            ));
        }
    }
}

impl Bundle {
    /// Merges this bundle with another.
    ///
    /// Returns `None` if the bundles have conflicting data.
    pub(crate) fn merge(
        mut self,
        other: Self,
        self_global: &Global,
        other_global: &Global,
    ) -> Option<Self> {
        // Destructure `other` to ensure we handle everything.
        let Self {
            mut actions,
            flags,
            value_sum,
            anchor,
            note_version,
            zkproof,
            bsk,
        } = other;

        if self.flags != flags || self.note_version != note_version {
            return None;
        }

        // If `bsk` is set on either bundle, the IO Finalizer has run, which means we
        // cannot have differing numbers of actions, and the value sums must match.
        match (self.bsk.as_mut(), bsk) {
            (Some(lhs), Some(rhs)) if lhs != &rhs => return None,
            (Some(_), _) | (_, Some(_))
                if self.actions.len() != actions.len() || self.value_sum != value_sum =>
            {
                return None;
            }
            // IO Finalizer has run, and neither bundle has excess spends or outputs.
            (Some(_), _) | (_, Some(_)) => (),
            // IO Finalizer has not run on either bundle.
            (None, None) => match (
                self_global.shielded_modifiable(),
                other_global.shielded_modifiable(),
                self.actions.len().cmp(&actions.len()),
            ) {
                // Fail if the merge would add actions to a non-modifiable bundle.
                (false, _, Ordering::Less) | (_, false, Ordering::Greater) => return None,
                // If the other bundle has more actions than us, move them over; these
                // cannot conflict by construction.
                (true, _, Ordering::Less) => {
                    self.actions.extend(actions.drain(self.actions.len()..));

                    // We check below that the overlapping actions match. Assuming here
                    // that they will, we can take the other bundle's value sum.
                    self.value_sum = value_sum;
                }
                // Do nothing otherwise.
                (_, _, Ordering::Equal) | (_, true, Ordering::Greater) => (),
            },
        }

        if !merge_optional(&mut self.anchor, anchor) {
            return None;
        }

        if !merge_optional(&mut self.zkproof, zkproof) {
            return None;
        }

        // Leverage the early-exit behaviour of zip to confirm that the remaining data in
        // the other bundle matches this one.
        for (lhs, rhs) in self.actions.iter_mut().zip(actions) {
            // Destructure `rhs` to ensure we handle everything.
            let Action {
                cv_net,
                spend:
                    Spend {
                        nullifier,
                        rk,
                        spend_auth_sig,
                        recipient,
                        value,
                        rho,
                        rseed,
                        fvk,
                        witness,
                        alpha,
                        zip32_derivation: spend_zip32_derivation,
                        dummy_sk,
                        proprietary: spend_proprietary,
                    },
                output:
                    Output {
                        cmx,
                        ephemeral_key,
                        enc_ciphertext,
                        out_ciphertext,
                        recipient: output_recipient,
                        value: output_value,
                        rseed: output_rseed,
                        ock,
                        zip32_derivation: output_zip32_derivation,
                        user_address,
                        proprietary: output_proprietary,
                    },
                rcv,
            } = rhs;

            if lhs.spend.nullifier != nullifier
                || lhs.spend.rk != rk
                || lhs.output.ephemeral_key != ephemeral_key
                || lhs.output.enc_ciphertext != enc_ciphertext
                || lhs.output.out_ciphertext != out_ciphertext
            {
                return None;
            }

            if !(merge_optional(&mut lhs.cv_net, cv_net)
                && merge_optional(&mut lhs.spend.spend_auth_sig, spend_auth_sig)
                && merge_optional(&mut lhs.spend.recipient, recipient)
                && merge_optional(&mut lhs.spend.value, value)
                && merge_optional(&mut lhs.spend.rho, rho)
                && merge_optional(&mut lhs.spend.rseed, rseed)
                && merge_optional(&mut lhs.spend.fvk, fvk)
                && merge_optional(&mut lhs.spend.witness, witness)
                && merge_optional(&mut lhs.spend.alpha, alpha)
                && merge_optional(&mut lhs.spend.zip32_derivation, spend_zip32_derivation)
                && merge_optional(&mut lhs.spend.dummy_sk, dummy_sk)
                && merge_map(&mut lhs.spend.proprietary, spend_proprietary)
                && merge_optional(&mut lhs.output.cmx, cmx)
                && merge_optional(&mut lhs.output.recipient, output_recipient)
                && merge_optional(&mut lhs.output.value, output_value)
                && merge_optional(&mut lhs.output.rseed, output_rseed)
                && merge_optional(&mut lhs.output.ock, ock)
                && merge_optional(&mut lhs.output.zip32_derivation, output_zip32_derivation)
                && merge_optional(&mut lhs.output.user_address, user_address)
                && merge_map(&mut lhs.output.proprietary, output_proprietary)
                && merge_optional(&mut lhs.rcv, rcv))
            {
                return None;
            }
        }

        Some(self)
    }
}

/// Returns the [`BundleVersion`] in effect for the given Orchard-protocol value pool
/// under the given Orchard protocol revision, or `None` if the pool is not supported
/// under that revision (the Ironwood pool exists only from revision V3).
#[cfg(feature = "orchard")]
pub(crate) fn bundle_version_for_revision(
    revision: zcash_protocol::consensus::OrchardProtocolRevision,
    pool: orchard::ValuePool,
) -> Option<BundleVersion> {
    use orchard::ValuePool;
    use zcash_protocol::consensus::OrchardProtocolRevision;

    match pool {
        ValuePool::Orchard => Some(match revision {
            OrchardProtocolRevision::InsecureV1 => BundleVersion::orchard_insecure_v1(),
            OrchardProtocolRevision::V2 => BundleVersion::orchard_v2(),
            OrchardProtocolRevision::V3 => BundleVersion::orchard_v3(),
        }),
        ValuePool::Ironwood => match revision {
            OrchardProtocolRevision::InsecureV1 | OrchardProtocolRevision::V2 => None,
            OrchardProtocolRevision::V3 => Some(BundleVersion::ironwood_v3()),
        },
    }
}

/// Returns the Orchard-pool [`BundleVersion`] implied by the given PCZT global data,
/// or `None` if the PCZT's consensus branch ID is unrecognized or predates NU5 (under
/// which the Orchard protocol is not supported).
#[cfg(feature = "orchard")]
pub(crate) fn orchard_bundle_version(global: &crate::common::Global) -> Option<BundleVersion> {
    use zcash_protocol::consensus::BranchId;

    BranchId::try_from(global.consensus_branch_id)
        .ok()?
        .orchard_protocol_revision()
        .and_then(|revision| bundle_version_for_revision(revision, orchard::ValuePool::Orchard))
}

/// Errors that can occur while parsing a logical Orchard-protocol bundle (Orchard or
/// Ironwood) into the form used by the `orchard` crate.
#[cfg(feature = "orchard")]
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// The operation requires the bundle's `anchor` to be set, but it was absent.
    ///
    /// For a v6 transaction, an Updater can resolve this by setting the anchor; see
    /// [ZIP 374: Anchors and pre-authorization](https://zips.z.cash/zip-0374#anchors-and-pre-authorization).
    MissingAnchor,
    /// The bundle's remaining fields were structurally invalid.
    Bundle(orchard::pczt::ParseError),
}

#[cfg(feature = "orchard")]
impl From<orchard::pczt::ParseError> for ParseError {
    fn from(e: orchard::pczt::ParseError) -> Self {
        ParseError::Bundle(e)
    }
}

/// Errors that can occur while checking that an Orchard-protocol bundle's spend
/// witnesses are consistent with its anchor.
#[cfg(feature = "orchard")]
#[derive(Debug)]
#[non_exhaustive]
pub enum AnchorConsistencyError {
    /// A non-zero-valued spend has a `witness` but is missing other note data required
    /// to compute its Merkle path root.
    IncompleteSpendData,
    /// A non-zero-valued spend's `witness` does not root to the given anchor.
    WitnessDoesNotRootToAnchor,
}

/// Checks that every non-zero-valued spend in `bundle` whose `witness` is present has a
/// Merkle path that roots to `anchor` (\[ZIP 374\] "Anchors and pre-authorization").
///
/// Zero-valued spends are skipped, as their Merkle paths are not checked by the Orchard
/// circuit.
///
/// [ZIP 374]: https://zips.z.cash/zip-0374#anchors-and-pre-authorization
#[cfg(feature = "orchard")]
pub(crate) fn verify_witnesses_root_to_anchor(
    bundle: &orchard::pczt::Bundle,
    anchor: orchard::Anchor,
) -> Result<(), AnchorConsistencyError> {
    for action in bundle.actions() {
        let spend = action.spend();

        let Some(witness) = spend.witness() else {
            continue;
        };
        let Some(value) = spend.value() else {
            continue;
        };
        if value.inner() == 0 {
            continue;
        }

        let recipient = spend
            .recipient()
            .ok_or(AnchorConsistencyError::IncompleteSpendData)?;
        let rho = spend
            .rho()
            .ok_or(AnchorConsistencyError::IncompleteSpendData)?;
        let rseed = spend
            .rseed()
            .ok_or(AnchorConsistencyError::IncompleteSpendData)?;

        let note = orchard::Note::from_parts(recipient, *value, rho, rseed, *spend.note_version())
            .into_option()
            .ok_or(AnchorConsistencyError::IncompleteSpendData)?;
        let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment());
        let computed_anchor = witness.root(cmx);

        if computed_anchor != anchor {
            return Err(AnchorConsistencyError::WitnessDoesNotRootToAnchor);
        }
    }

    Ok(())
}

#[cfg(feature = "orchard")]
impl Output {
    /// Recomputes `cmx`, if this output carries it as an omitted field.
    fn resolve_cmx(
        &mut self,
        note_version: NoteVersion,
        spend_nullifier: [u8; 32],
    ) -> Result<(), ::orchard::pczt::ParseError> {
        use ::orchard::{
            Address, Note,
            note::{ExtractedNoteCommitment, RandomSeed, Rho},
            pczt::ParseError,
            value::NoteValue,
        };

        if self.cmx.is_some() {
            return Ok(());
        }

        let recipient = Address::from_raw_address_bytes(
            self.recipient
                .as_ref()
                .ok_or(ParseError::InvalidExtractedNoteCommitment)?,
        )
        .into_option()
        .ok_or(ParseError::InvalidExtractedNoteCommitment)?;
        let rho = Rho::from_bytes(&spend_nullifier)
            .into_option()
            .ok_or(ParseError::InvalidExtractedNoteCommitment)?;
        let rseed = RandomSeed::from_bytes(
            *self
                .rseed
                .as_ref()
                .ok_or(ParseError::InvalidExtractedNoteCommitment)?,
            &rho,
        )
        .into_option()
        .ok_or(ParseError::InvalidExtractedNoteCommitment)?;
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(
                self.value
                    .ok_or(ParseError::InvalidExtractedNoteCommitment)?,
            ),
            rho,
            rseed,
            note_version,
        )
        .into_option()
        .ok_or(ParseError::InvalidExtractedNoteCommitment)?;

        self.cmx = Some(ExtractedNoteCommitment::from(note.commitment()).to_bytes());
        Ok(())
    }

    /// Recomputes [`Self::enc_ciphertext`] from memo plaintext, if present.
    ///
    /// If [`Self::enc_ciphertext`] is [`EncCiphertext::MemoPlaintext`], this
    /// computes the encrypted note plaintext and replaces it with
    /// [`EncCiphertext::Encrypted`]. If it is already encrypted, this is a
    /// no-op.
    ///
    /// This requires the action's spend nullifier because the output note's
    /// [`rho`](::orchard::note::Rho) is derived from it.
    fn encrypt_ciphertext_from_memo(
        &mut self,
        note_version: NoteVersion,
        spend_nullifier: [u8; 32],
    ) -> Result<(), ::orchard::pczt::ParseError> {
        use ::orchard::{
            Address, Note,
            note::{RandomSeed, Rho},
            note_encryption::{OrchardDomain, OrchardNoteEncryption},
            pczt::ParseError,
            value::NoteValue,
        };
        use zcash_note_encryption::Domain;

        let memo: [u8; 512] = match &self.enc_ciphertext {
            EncCiphertext::Encrypted(_) => return Ok(()),
            EncCiphertext::MemoPlaintext(memo) => memo.to_memo(),
        };

        let recipient = Address::from_raw_address_bytes(
            self.recipient
                .as_ref()
                .ok_or(ParseError::InvalidRecipient)?,
        )
        .into_option()
        .ok_or(ParseError::InvalidRecipient)?;
        let rho = Rho::from_bytes(&spend_nullifier)
            .into_option()
            .ok_or(ParseError::InvalidNullifier)?;
        let rseed = RandomSeed::from_bytes(
            *self.rseed.as_ref().ok_or(ParseError::InvalidRandomSeed)?,
            &rho,
        )
        .into_option()
        .ok_or(ParseError::InvalidRandomSeed)?;
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(self.value.ok_or(ParseError::InvalidEncCiphertext)?),
            rho,
            rseed,
            note_version,
        )
        .into_option()
        .ok_or(ParseError::InvalidEncCiphertext)?;
        let encryptor = OrchardNoteEncryption::new(None, note, memo);
        let ephemeral_key = OrchardDomain::epk_bytes(encryptor.epk()).0;
        let enc_ciphertext = encryptor.encrypt_note_plaintext().to_vec();

        if ephemeral_key != self.ephemeral_key {
            return Err(ParseError::InvalidEncCiphertext);
        }

        self.enc_ciphertext = EncCiphertext::Encrypted(enc_ciphertext);
        Ok(())
    }
}

#[cfg(feature = "orchard")]
impl Action {
    /// Recomputes `cv_net`, if this action carries it as an omitted field.
    fn resolve_cv_net(&mut self) -> Result<(), ::orchard::pczt::ParseError> {
        use ::orchard::{
            pczt::ParseError,
            value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
        };

        if self.cv_net.is_some() {
            return Ok(());
        }

        let spend_value: NoteValue =
            NoteValue::from_raw(self.spend.value.ok_or(ParseError::InvalidValueCommitment)?);
        let output_value = NoteValue::from_raw(
            self.output
                .value
                .ok_or(ParseError::InvalidValueCommitment)?,
        );
        let rcv =
            ValueCommitTrapdoor::from_bytes(self.rcv.ok_or(ParseError::InvalidValueCommitment)?)
                .into_option()
                .ok_or(ParseError::InvalidValueCommitment)?;

        self.cv_net = Some(ValueCommitment::derive(spend_value - output_value, rcv).to_bytes());
        Ok(())
    }
}

#[cfg(feature = "orchard")]
impl Bundle {
    /// Resolves fields that are optionally redacted in the PCZT but implied by
    /// other known fields.
    ///
    /// This currently recomputes:
    /// - [`Action::cv_net`] if it is redacted.
    /// - [`Output::cmx`] if it is redacted.
    /// - [`Output::enc_ciphertext`] if it is represented by memo plaintext.
    ///
    /// For improved efficiency, callers that will pass the same bundle through
    /// multiple roles should call this once up front, not in each role. Parsing
    /// also resolves fields defensively.
    pub fn resolve_fields(&mut self) -> Result<(), ::orchard::pczt::ParseError> {
        for action in &mut self.actions {
            action.resolve_cv_net()?;
            action
                .output
                .resolve_cmx(self.note_version, action.spend.nullifier)?;
            action
                .output
                .encrypt_ciphertext_from_memo(self.note_version, action.spend.nullifier)?;
        }

        Ok(())
    }

    /// Parses this bundle as an Ironwood-pool bundle, deriving each spend's
    /// `FullViewingKey` from its wire `fvk` bytes.
    pub(crate) fn into_ironwood_parsed(
        self,
        anchor_requirement: crate::common::AnchorRequirement,
    ) -> Result<Parsed, ParseError> {
        self.into_parsed_with_version(BundleVersion::ironwood_v3(), anchor_requirement)
    }

    /// Parses this bundle as an Ironwood-pool bundle for a preverified signing
    /// pass, skipping each spend's `FullViewingKey` derivation. See
    /// [`Bundle::into_parsed_with_version_preverified_for_signing`] for the invariant
    /// callers must uphold.
    pub(crate) fn into_ironwood_parsed_preverified_for_signing(
        self,
        anchor_requirement: crate::common::AnchorRequirement,
    ) -> Result<Parsed, ParseError> {
        self.into_parsed_with_version_preverified_for_signing(
            BundleVersion::ironwood_v3(),
            anchor_requirement,
        )
    }

    /// Parses this bundle with the given bundle version, deriving each spend's
    /// `FullViewingKey` from its wire `fvk` bytes.
    ///
    /// Callers should prefer [`Bundle::resolve_fields`] before parsing, so
    /// derivations happen once for all uses. This method still resolves
    /// fields defensively for direct callers.
    #[allow(dead_code)]
    pub(crate) fn into_parsed_with_version(
        self,
        bundle_version: BundleVersion,
        anchor_requirement: crate::common::AnchorRequirement,
    ) -> Result<Parsed, ParseError> {
        self.into_parsed_inner(bundle_version, anchor_requirement, false)
    }

    /// Parses this bundle with the given bundle version for a preverified signing
    /// pass, skipping each spend's `FullViewingKey` derivation (an expensive step the
    /// spend authorization signature does not depend on).
    ///
    /// Callers should prefer [`Bundle::resolve_fields`] before parsing, so
    /// derivations happen once for all uses. This method still resolves
    /// fields defensively for direct callers.
    ///
    /// Callers MUST have already run the full Verifier checks over the identical PCZT
    /// bytes: the wire `fvk` bytes are neither validated nor retained here (each spend
    /// has `fvk: None`), so the result must not go to the Verifier check path or the
    /// Prover, and re-serializing it drops the wire `fvk`s (the low-level Signer
    /// restores them from a pre-parse snapshot).
    #[allow(dead_code)]
    pub(crate) fn into_parsed_with_version_preverified_for_signing(
        self,
        bundle_version: BundleVersion,
        anchor_requirement: crate::common::AnchorRequirement,
    ) -> Result<Parsed, ParseError> {
        self.into_parsed_inner(bundle_version, anchor_requirement, true)
    }

    /// The shared body of [`Bundle::into_parsed_with_version`] and
    /// [`Bundle::into_parsed_with_version_preverified_for_signing`]: `preverified`
    /// selects between the full parse and the preverified signing parse.
    fn into_parsed_inner(
        mut self,
        bundle_version: BundleVersion,
        anchor_requirement: crate::common::AnchorRequirement,
        preverified: bool,
    ) -> Result<Parsed, ParseError> {
        self.resolve_fields()?;
        let wire_anchor = self.anchor;
        let anchor = anchor_requirement
            .resolve(wire_anchor, self.actions.is_empty())
            .ok_or(ParseError::MissingAnchor)?;

        // We parse actions through a helper that is specifically `#[inline(never)]`.
        // This is because if this gets inlined in a loop (e.g. `.map(..).collect()`),
        // it could compile into a stack frame that is tens of KB deep.
        // This can overflow stacks of embedded signers for high action count
        // transactions.
        #[inline(never)]
        fn parse_action_inner(
            mut action: Action,
            note_version: NoteVersion,
            preverified: bool,
        ) -> Result<orchard::pczt::Action, orchard::pczt::ParseError> {
            let spend_zip32_derivation = action
                .spend
                .zip32_derivation
                .map(|z| {
                    orchard::pczt::Zip32Derivation::parse(z.seed_fingerprint, z.derivation_path)
                })
                .transpose()?;
            let spend_nullifier = action.spend.nullifier;

            let spend = if preverified {
                orchard::pczt::Spend::parse_preverified_for_signing(
                    action.spend.nullifier,
                    action.spend.rk,
                    action.spend.spend_auth_sig,
                    action.spend.recipient,
                    action.spend.value,
                    action.spend.rho,
                    action.spend.rseed,
                    action.spend.fvk,
                    action.spend.witness,
                    action.spend.alpha,
                    spend_zip32_derivation,
                    action.spend.dummy_sk,
                    note_version,
                    action.spend.proprietary,
                )
            } else {
                orchard::pczt::Spend::parse(
                    action.spend.nullifier,
                    action.spend.rk,
                    action.spend.spend_auth_sig,
                    action.spend.recipient,
                    action.spend.value,
                    action.spend.rho,
                    action.spend.rseed,
                    action.spend.fvk,
                    action.spend.witness,
                    action.spend.alpha,
                    spend_zip32_derivation,
                    action.spend.dummy_sk,
                    note_version,
                    action.spend.proprietary,
                )
            }?;

            action
                .output
                .encrypt_ciphertext_from_memo(note_version, spend_nullifier)?;

            let enc_ciphertext = action
                .output
                .enc_ciphertext
                .into_encrypted()
                .ok_or(orchard::pczt::ParseError::InvalidEncCiphertext)?;
            let cv_net = action
                .cv_net
                .ok_or(orchard::pczt::ParseError::InvalidValueCommitment)?;

            let output = orchard::pczt::Output::parse(
                *spend.nullifier(),
                action
                    .output
                    .cmx
                    .ok_or(orchard::pczt::ParseError::InvalidExtractedNoteCommitment)?,
                action.output.ephemeral_key,
                enc_ciphertext,
                action.output.out_ciphertext,
                action.output.recipient,
                action.output.value,
                action.output.rseed,
                action.output.ock,
                action
                    .output
                    .zip32_derivation
                    .map(|z| {
                        orchard::pczt::Zip32Derivation::parse(z.seed_fingerprint, z.derivation_path)
                    })
                    .transpose()?,
                action.output.user_address,
                note_version,
                action.output.proprietary,
            )?;

            orchard::pczt::Action::parse(cv_net, spend, output, action.rcv)
        }

        let note_version = self.note_version;
        let mut actions = Vec::with_capacity(self.actions.len());
        for action in self.actions {
            actions.push(parse_action_inner(action, note_version, preverified)?);
        }

        let bundle = orchard::pczt::Bundle::parse(
            actions,
            self.flags,
            bundle_version,
            self.value_sum,
            anchor,
            self.zkproof,
            self.bsk,
        )?;

        Ok(Parsed {
            bundle,
            wire_anchor,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn serialize_from(bundle: orchard::pczt::Bundle) -> Self {
        let note_version = bundle.bundle_version().note_version();

        assert!(
            bundle.actions().iter().all(|action| {
                action.spend().note_version() == &note_version
                    && action.output().note_version() == &note_version
            }),
            "Orchard PCZT bundle must have a single note version"
        );

        let actions = bundle
            .actions()
            .iter()
            .map(|action| {
                let spend = action.spend();
                let output = action.output();

                Action {
                    cv_net: Some(action.cv_net().to_bytes()),
                    spend: Spend {
                        nullifier: spend.nullifier().to_bytes(),
                        rk: spend.rk().into(),
                        spend_auth_sig: spend.spend_auth_sig().as_ref().map(|s| s.into()),
                        recipient: action
                            .spend()
                            .recipient()
                            .map(|recipient| recipient.to_raw_address_bytes()),
                        value: spend.value().map(|value| value.inner()),
                        rho: spend.rho().map(|rho| rho.to_bytes()),
                        rseed: spend.rseed().map(|rseed| *rseed.as_bytes()),
                        fvk: spend.fvk().as_ref().map(|fvk| fvk.to_bytes()),
                        witness: spend.witness().as_ref().map(|witness| {
                            (
                                u32::try_from(u64::from(witness.position()))
                                    .expect("Sapling positions fit in u32"),
                                witness
                                    .auth_path()
                                    .iter()
                                    .map(|node| node.to_bytes())
                                    .collect::<Vec<_>>()[..]
                                    .try_into()
                                    .expect("path is length 32"),
                            )
                        }),
                        alpha: spend.alpha().map(|alpha| alpha.to_repr()),
                        zip32_derivation: spend.zip32_derivation().as_ref().map(|z| {
                            Zip32Derivation {
                                seed_fingerprint: *z.seed_fingerprint(),
                                derivation_path: z
                                    .derivation_path()
                                    .iter()
                                    .map(|i| i.index())
                                    .collect(),
                            }
                        }),
                        dummy_sk: action
                            .spend()
                            .dummy_sk()
                            .map(|dummy_sk| *dummy_sk.to_bytes()),
                        proprietary: spend.proprietary().clone(),
                    },
                    output: Output {
                        cmx: Some(output.cmx().to_bytes()),
                        ephemeral_key: output.encrypted_note().epk_bytes,
                        enc_ciphertext: EncCiphertext::Encrypted(
                            output.encrypted_note().enc_ciphertext.to_vec(),
                        ),
                        out_ciphertext: output.encrypted_note().out_ciphertext.to_vec(),
                        recipient: action
                            .output()
                            .recipient()
                            .map(|recipient| recipient.to_raw_address_bytes()),
                        value: output.value().map(|value| value.inner()),
                        rseed: output.rseed().map(|rseed| *rseed.as_bytes()),
                        ock: output.ock().as_ref().map(|ock| ock.0),
                        zip32_derivation: output.zip32_derivation().as_ref().map(|z| {
                            Zip32Derivation {
                                seed_fingerprint: *z.seed_fingerprint(),
                                derivation_path: z
                                    .derivation_path()
                                    .iter()
                                    .map(|i| i.index())
                                    .collect(),
                            }
                        }),
                        user_address: output.user_address().clone(),
                        proprietary: output.proprietary().clone(),
                    },
                    rcv: action.rcv().as_ref().map(|rcv| rcv.to_bytes()),
                }
            })
            .collect();

        let value_sum = {
            let (magnitude, sign) = bundle.value_sum().magnitude_sign();
            (magnitude, matches!(sign, orchard::value::Sign::Negative))
        };
        let anchor = bundle.anchor().to_bytes();

        Self {
            actions,
            flags: bundle.flag_byte(),
            value_sum,
            anchor: Some(anchor),
            note_version,
            zkproof: bundle
                .zkproof()
                .as_ref()
                .map(|zkproof| zkproof.as_ref().to_vec()),
            bsk: bundle.bsk().as_ref().map(|bsk| bsk.into()),
        }
    }
}
