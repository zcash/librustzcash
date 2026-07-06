//! The Orchard fields of a PCZT.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

#[cfg(feature = "orchard")]
use ff::PrimeField;
use getset::Getters;
#[cfg(feature = "orchard")]
use orchard::bundle::BundleVersion;
#[cfg(feature = "orchard")]
pub(crate) use orchard::note::NoteVersion;
use serde::{Deserialize, Serialize};

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
    /// Set by the Creator. A producer may elide it on transports where the anchor is
    /// not part of the signed data (the v6 transaction format excludes it from the
    /// txid/sighash digest); the receiver refills it with a fixed placeholder (see
    /// `Bundle::fill_derived_fields`, which requires the `orchard` feature), and the
    /// extracting wallet must install the real anchor.
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

/// The byte encoding of `orchard::Anchor::empty_tree()` at `MERKLE_DEPTH_ORCHARD`.
const EMPTY_TREE_ANCHOR: [u8; 32] = [
    0xae, 0x29, 0x35, 0xf1, 0xdf, 0xd8, 0xa2, 0x4a, 0xed, 0x7c, 0x70, 0xdf, 0x7d, 0xe3, 0xa6, 0x68,
    0xeb, 0x7a, 0x49, 0xb1, 0x31, 0x98, 0x80, 0xdd, 0xe2, 0xbb, 0xd9, 0x03, 0x1a, 0xe5, 0xd8, 0x2f,
];

/// The canonical empty Orchard-pool bundle: the form the Orchard slot of a PCZT takes
/// when it carries no Orchard-protocol data. The Creator, the v1 decoder, and the v2
/// decoder all produce exactly this value for an absent bundle, so that copies of a
/// PCZT that take different serialization paths continue to merge successfully.
pub(crate) const EMPTY_ORCHARD: Bundle = Bundle {
    actions: Vec::new(),
    flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
    value_sum: (0, false),
    anchor: Some([0; 32]),
    note_version: NoteVersion::V2,
    zkproof: None,
    bsk: None,
};

/// The canonical empty Ironwood bundle; see [`EMPTY_ORCHARD`].
pub(crate) const EMPTY_IRONWOOD: Bundle = Bundle {
    actions: Vec::new(),
    flags: IRONWOOD_SPENDS_OUTPUTS_AND_CROSS_ADDRESS_ENABLED,
    value_sum: (0, false),
    anchor: Some([0; 32]),
    note_version: NoteVersion::V3,
    zkproof: None,
    bsk: None,
};

/// The memo carried by an output whose `enc_ciphertext` has been elided from the wire.
///
/// Reconstructing an elided `enc_ciphertext` (see `Bundle::fill_derived_fields`, which
/// requires the `orchard` feature) requires the note's 512-byte memo. Wallets that
/// elide it only ever attach one of two memo constants, so the wire carries this
/// one-byte tag in its place.
///
/// The variant order is part of the v2 wire encoding (postcard serializes the variant
/// index: `Zero` = 0, `Empty` = 1) and must not change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoKind {
    /// The all-zero memo, `[0u8; 512]`, as attached to dummy outputs.
    Zero,
    /// The [ZIP 302] empty memo: `0xF6` followed by 511 zero bytes.
    ///
    /// [ZIP 302]: https://zips.z.cash/zip-0302
    Empty,
}

impl MemoKind {
    /// Returns the 512-byte memo this tag denotes.
    #[cfg(feature = "orchard")]
    fn memo(self) -> [u8; 512] {
        let mut memo = [0u8; 512];
        if let MemoKind::Empty = self {
            memo[0] = 0xF6;
        }
        memo
    }
}

/// Information about an Orchard action within a transaction.
#[derive(Clone, Debug, PartialEq, Getters)]
pub struct Action {
    //
    // Action effecting data.
    //
    // These fields are part of the final transaction. The Constructor fills them in
    // when adding an output, but a producer may elide any of the derived ones (here,
    // `cv_net`) and let the receiver recompute it from the note component fields. See
    // [`Bundle::fill_derived_fields`].
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
    // These fields are part of the final transaction. The Constructor fills them in
    // when adding a spend, but a producer may elide the derived ones (`nullifier` and
    // `rk`) and let the receiver recompute them; the recomputation requires the wire
    // `fvk`, so a producer that redacts `fvk` must keep them. See
    // [`Bundle::fill_derived_fields`].
    //
    #[getset(get = "pub")]
    pub(crate) nullifier: Option<[u8; 32]>,
    #[getset(get = "pub")]
    pub(crate) rk: Option<[u8; 32]>,

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

impl Spend {
    /// Returns whether this spend can identify its spending key from a ZIP 32 derivation.
    pub fn has_zip32_derivation(&self) -> bool {
        self.zip32_derivation.is_some()
    }
}

/// Information about the output part of an Orchard action.
#[derive(Clone, Debug, PartialEq, Getters)]
pub struct Output {
    //
    // Output-specific Action effecting data.
    //
    // These fields are part of the final transaction. The Constructor fills them in
    // when adding an output, but a producer may elide the derived ones (`cmx`,
    // `ephemeral_key`, and `enc_ciphertext`) and let the receiver recompute them from
    // the note component fields. See [`Bundle::fill_derived_fields`].
    // `out_ciphertext` is NOT recomputable (it is derived using RNG), so it remains
    // required.
    //
    #[getset(get = "pub")]
    pub(crate) cmx: Option<[u8; 32]>,
    #[getset(get = "pub")]
    pub(crate) ephemeral_key: Option<[u8; 32]>,
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    ///
    /// Once we have memo bundles, we will be able to set memos independently of Outputs.
    /// For now, the Constructor sets both at the same time.
    ///
    /// A producer may elide it, recording the note's memo as [`Output::memo_kind`] so
    /// the receiver can re-encrypt the note deterministically.
    #[getset(get = "pub")]
    pub(crate) enc_ciphertext: Option<Vec<u8>>,
    /// The memo carried by an elided `enc_ciphertext`; see [`MemoKind`].
    ///
    /// Set by the Redactor when eliding `enc_ciphertext`, and consumed (cleared) by
    /// `Bundle::fill_derived_fields` when reconstructing it.
    #[getset(get = "pub")]
    pub(crate) memo_kind: Option<MemoKind>,
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
                    .collect::<Result<_, _>>()?,
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
                // This encoding has no representation for an elided derived field;
                // reject any action that has redacted one (see
                // [`crate::EncodingError::RequiresV2`]).
                cv_net: action.cv_net.ok_or(crate::EncodingError::RequiresV2)?,
                spend: Spend::try_from(action.spend)?,
                output: Output::try_from(action.output)?,
                rcv: action.rcv,
            })
        }
    }

    impl From<Action> for super::Action {
        fn from(action: Action) -> Self {
            Self {
                // This encoding always carries the derived fields; wrap them in `Some`
                // for the live (optional) representation.
                cv_net: Some(action.cv_net),
                spend: super::Spend::from(action.spend),
                output: super::Output::from(action.output),
                rcv: action.rcv,
            }
        }
    }

    impl TryFrom<super::Spend> for Spend {
        type Error = crate::EncodingError;

        fn try_from(spend: super::Spend) -> Result<Self, Self::Error> {
            Ok(Self {
                nullifier: spend.nullifier.ok_or(crate::EncodingError::RequiresV2)?,
                rk: spend.rk.ok_or(crate::EncodingError::RequiresV2)?,
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
            })
        }
    }

    impl From<Spend> for super::Spend {
        fn from(spend: Spend) -> Self {
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

    impl TryFrom<super::Output> for Output {
        type Error = crate::EncodingError;

        fn try_from(output: super::Output) -> Result<Self, Self::Error> {
            // A memo-kind tag has no representation in this encoding either; it only
            // accompanies an elided `enc_ciphertext`, which is rejected below.
            if output.memo_kind.is_some() {
                return Err(crate::EncodingError::RequiresV2);
            }
            Ok(Self {
                cmx: output.cmx.ok_or(crate::EncodingError::RequiresV2)?,
                ephemeral_key: output
                    .ephemeral_key
                    .ok_or(crate::EncodingError::RequiresV2)?,
                enc_ciphertext: output
                    .enc_ciphertext
                    .ok_or(crate::EncodingError::RequiresV2)?,
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
                ephemeral_key: Some(output.ephemeral_key),
                enc_ciphertext: Some(output.enc_ciphertext),
                memo_kind: None,
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
///
/// Unlike in [`v1`], the derived fields (`Action.cv_net`, `Spend.nullifier`,
/// `Spend.rk`, `Output.cmx`, `Output.ephemeral_key`, `Output.enc_ciphertext`) and the
/// bundle `anchor` are optional, and each output carries an optional [`MemoKind`] tag.
/// `out_ciphertext` stays required because it is RNG-derived and can never be
/// recomputed. The live representation is itself optional for the derived fields,
/// so the conversions here are 1:1 and infallible.
pub(crate) mod v2 {
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec::Vec;

    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    use crate::common::Zip32Derivation;

    use super::{MemoKind, NoteVersion};

    /// A serializable representation of Orchard note plaintext versions.
    #[derive(Clone, Copy, Debug, Serialize, Deserialize)]
    pub(crate) enum SerializedNoteVersion {
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
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct Bundle {
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
        nullifier: Option<[u8; 32]>,
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
        zip32_derivation: Option<Zip32Derivation>,
        dummy_sk: Option<[u8; 32]>,
        proprietary: BTreeMap<String, Vec<u8>>,
    }

    /// Information about the output part of an Orchard action.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub(crate) struct Output {
        cmx: Option<[u8; 32]>,
        ephemeral_key: Option<[u8; 32]>,
        enc_ciphertext: Option<Vec<u8>>,
        memo_kind: Option<MemoKind>,
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

    impl From<super::Bundle> for Bundle {
        fn from(bundle: super::Bundle) -> Self {
            Self {
                actions: bundle.actions.into_iter().map(Action::from).collect(),
                flags: bundle.flags,
                value_sum: bundle.value_sum,
                anchor: bundle.anchor,
                note_version: bundle.note_version.into(),
                zkproof: bundle.zkproof,
                bsk: bundle.bsk,
            }
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
                anchor: bundle.anchor,
                note_version: bundle.note_version.into(),
                zkproof: bundle.zkproof,
                bsk: bundle.bsk,
            }
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

    impl From<Action> for super::Action {
        fn from(action: Action) -> Self {
            Self {
                cv_net: action.cv_net,
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

    impl From<super::Output> for Output {
        fn from(output: super::Output) -> Self {
            Self {
                cmx: output.cmx,
                ephemeral_key: output.ephemeral_key,
                enc_ciphertext: output.enc_ciphertext,
                memo_kind: output.memo_kind,
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
                memo_kind: output.memo_kind,
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
    /// decision of whether the bundle can be omitted: a bundle that is exactly equal
    /// to `empty` (the canonical empty bundle for its slot, [`super::EMPTY_ORCHARD`]
    /// or [`super::EMPTY_IRONWOOD`]) serializes to `None` and is dropped from the
    /// encoding. The reverse direction is [`From<Bundle>`] plus the canonical empty
    /// bundle for the omitted case.
    pub(crate) fn encode(bundle: super::Bundle, empty: &super::Bundle) -> Option<Bundle> {
        (bundle != *empty).then(|| Bundle::from(bundle))
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

        let self_zkproof_present = self.zkproof.is_some();
        let other_zkproof_present = zkproof.is_some();
        if !merge_anchor(
            &mut self.anchor,
            anchor,
            self_global,
            other_global,
            self_zkproof_present,
            other_zkproof_present,
        ) {
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
                        memo_kind,
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

            // `out_ciphertext` is required and never recomputable, so any divergence is
            // a hard conflict. The derived fields (`cv_net`, `nullifier`, `rk`, `cmx`,
            // `ephemeral_key`, `enc_ciphertext`) are optional and merge via
            // `merge_optional`, so a participant that carries one (e.g. a receiver that
            // recomputed it from a leaner copy) can fill in a peer's omission.
            if lhs.output.out_ciphertext != out_ciphertext {
                return None;
            }

            if !(merge_optional(&mut lhs.cv_net, cv_net)
                && merge_optional(&mut lhs.spend.nullifier, nullifier)
                && merge_optional(&mut lhs.spend.rk, rk)
                && merge_optional(&mut lhs.output.cmx, cmx)
                && merge_optional(&mut lhs.output.ephemeral_key, ephemeral_key)
                && merge_optional(&mut lhs.output.enc_ciphertext, enc_ciphertext)
                && merge_optional(&mut lhs.output.memo_kind, memo_kind)
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

fn merge_anchor(
    lhs: &mut Option<[u8; 32]>,
    rhs: Option<[u8; 32]>,
    self_global: &Global,
    other_global: &Global,
    lhs_has_zkproof: bool,
    rhs_has_zkproof: bool,
) -> bool {
    let Some(rhs) = rhs else {
        return true;
    };

    let Some(lhs_anchor) = lhs.as_mut() else {
        *lhs = Some(rhs);
        return true;
    };

    if lhs_anchor == &rhs {
        return true;
    }

    let v6_anchor_placeholder_merge = self_global.tx_version
        == zcash_protocol::constants::V6_TX_VERSION
        && other_global.tx_version == zcash_protocol::constants::V6_TX_VERSION
        && ((*lhs_anchor == EMPTY_TREE_ANCHOR && !lhs_has_zkproof)
            || (rhs == EMPTY_TREE_ANCHOR && !rhs_has_zkproof));

    if v6_anchor_placeholder_merge {
        if *lhs_anchor == EMPTY_TREE_ANCHOR && !lhs_has_zkproof {
            *lhs_anchor = rhs;
        }
        true
    } else {
        false
    }
}

#[cfg(all(test, feature = "orchard"))]
mod tests {
    use alloc::{collections::BTreeMap, vec::Vec};

    use crate::common::Zip32Derivation;

    use super::{Action, Bundle, NoteVersion, Output, Spend};

    #[test]
    fn fill_missing_spend_fvks_for_zip32_path_only_fills_matching_missing_fvks() {
        let seed_fingerprint = [7u8; 32];
        let matching_path = vec![0x8000_0020, 0x8000_0085, 0x8000_0000];
        let other_path = vec![0x8000_0020, 0x8000_0085, 0x8000_0001];
        let fvk = [42u8; 96];
        let existing_fvk = [99u8; 96];

        let mut bundle = Bundle {
            actions: vec![
                action_with_fvk_and_path(None, seed_fingerprint, matching_path.clone()),
                action_with_fvk_and_path(
                    Some(existing_fvk),
                    seed_fingerprint,
                    matching_path.clone(),
                ),
                action_with_fvk_and_path(None, seed_fingerprint, other_path),
            ],
            flags: 0,
            value_sum: (0, false),
            anchor: Some([0; 32]),
            note_version: NoteVersion::V2,
            zkproof: None,
            bsk: None,
        };

        assert_eq!(
            bundle.fill_missing_spend_fvks_for_zip32_path(&seed_fingerprint, &matching_path, fvk,),
            1,
        );
        assert_eq!(bundle.actions[0].spend.fvk, Some(fvk));
        assert_eq!(bundle.actions[1].spend.fvk, Some(existing_fvk));
        assert_eq!(bundle.actions[2].spend.fvk, None);
    }

    fn action_with_fvk_and_path(
        fvk: Option<[u8; 96]>,
        seed_fingerprint: [u8; 32],
        derivation_path: Vec<u32>,
    ) -> Action {
        Action {
            cv_net: Some([0; 32]),
            spend: Spend {
                nullifier: Some([1; 32]),
                rk: Some([2; 32]),
                spend_auth_sig: None,
                recipient: None,
                value: None,
                rho: None,
                rseed: None,
                fvk,
                witness: None,
                alpha: None,
                zip32_derivation: Some(Zip32Derivation {
                    seed_fingerprint,
                    derivation_path,
                }),
                dummy_sk: None,
                proprietary: BTreeMap::new(),
            },
            output: Output {
                cmx: Some([3; 32]),
                ephemeral_key: Some([4; 32]),
                enc_ciphertext: Some(vec![]),
                memo_kind: None,
                out_ciphertext: vec![],
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

/// Errors that can occur while [`Bundle::fill_derived_fields`] recomputes elided
/// derived fields.
#[cfg(feature = "orchard")]
#[derive(Debug)]
pub enum FillError {
    /// A derived field could not be recomputed from the action's note component fields.
    /// Wraps the [`orchard::pczt::VerifyError`] identifying the component that was
    /// missing or invalid.
    Recompute(orchard::pczt::VerifyError),
    /// An output's `enc_ciphertext` was elided without the [`MemoKind`] tag needed to
    /// reconstruct it.
    MissingMemoKind,
}

#[cfg(feature = "orchard")]
impl From<orchard::pczt::VerifyError> for FillError {
    fn from(e: orchard::pczt::VerifyError) -> Self {
        FillError::Recompute(e)
    }
}

#[cfg(feature = "orchard")]
impl FillError {
    /// Maps this fill failure onto the orchard parse error a parsing consumer reports.
    fn into_parse_error(self) -> orchard::pczt::ParseError {
        match self {
            FillError::Recompute(e) => orchard::pczt::ParseError::Recompute(e),
            // An elided ciphertext without its memo-kind tag cannot be reconstructed,
            // so to a parsing consumer the action's `enc_ciphertext` data is unusable.
            FillError::MissingMemoKind => orchard::pczt::ParseError::InvalidEncCiphertext,
        }
    }
}

#[cfg(feature = "orchard")]
impl Bundle {
    /// Fills missing spend FVK bytes for actions whose ZIP 32 derivation matches
    /// the supplied seed fingerprint and account path.
    ///
    /// This is intended for constrained signers that can derive the selected
    /// account's Orchard FVK locally and therefore do not need it supplied on
    /// the PCZT wire. Existing `fvk` fields are left unchanged.
    pub fn fill_missing_spend_fvks_for_zip32_path(
        &mut self,
        seed_fingerprint: &[u8; 32],
        derivation_path: &[u32],
        fvk: [u8; 96],
    ) -> usize {
        let mut filled = 0;
        for action in &mut self.actions {
            if action.spend.fvk.is_none()
                && action.spend.zip32_derivation.as_ref().is_some_and(|z| {
                    &z.seed_fingerprint == seed_fingerprint
                        && z.derivation_path.as_slice() == derivation_path
                })
            {
                action.spend.fvk = Some(fvk);
                filled += 1;
            }
        }
        filled
    }

    /// Recomputes and fills, in place, every elided derived field across this bundle,
    /// so that afterwards each action's `cv_net`, `nullifier`, `rk`, `cmx`,
    /// `ephemeral_key`, and `enc_ciphertext`, and the bundle `anchor`, are all present.
    ///
    /// This is the inverse of the redactor's `clear_*` methods, and is a strict lazy
    /// fill: a field that is present is never recomputed or overwritten, and the
    /// expensive note encryption runs only when `ephemeral_key` or `enc_ciphertext` is
    /// actually missing, so a fully-populated bundle does zero cryptographic work here.
    /// Parsing this bundle (and therefore every parsing role) performs the fill
    /// implicitly; this method is for consumers that read the wire-format fields
    /// directly.
    ///
    /// Each recomputed derived field is byte-identical to the value the producer
    /// elided: the [`orchard::pczt::recompute`] primitives reproduce the builder's
    /// derivations exactly, `enc_ciphertext` under the memo named by the output's
    /// [`MemoKind`] tag (which a successful fill consumes). Two caveats bound that
    /// guarantee:
    ///
    /// - `enc_ciphertext` is byte-identical only if the note's memo really was the
    ///   tagged constant; a producer must verify this before eliding. A mismatch is
    ///   not detectable here, but produces a shielded sighash that fails signature
    ///   verification at extraction.
    /// - An elided `anchor` is refilled with the fixed placeholder
    ///   [`Anchor::empty_tree`](orchard::Anchor::empty_tree), not a recomputation, so
    ///   it only reproduces a producer anchor that was already that constant. Under
    ///   the v6 transaction format the anchor is excluded from the txid/sighash
    ///   digest, so a signer sees no difference; the extracting wallet must install
    ///   the real anchor.
    ///
    /// On error the bundle may be left partially filled.
    pub fn fill_derived_fields(&mut self) -> Result<(), FillError> {
        use orchard::pczt::{VerifyError, recompute};

        if self.anchor.is_none() {
            self.anchor = Some(EMPTY_TREE_ANCHOR);
        }

        let note_version = self.note_version;
        for action in &mut self.actions {
            // Resolve the spend nullifier lazily: the output note's `rho` derives from
            // it, so `cmx`, `ephemeral_key`, and `enc_ciphertext` all need it, but only
            // when one of those (or the nullifier itself) is elided. `None` here means
            // "not yet computed and not yet needed".
            let mut resolved_nullifier = action.spend.nullifier;
            let mut nullifier = |spend: &Spend| -> Result<[u8; 32], FillError> {
                if let Some(nf) = resolved_nullifier {
                    return Ok(nf);
                }
                let nf = recompute::nullifier(
                    spend
                        .recipient
                        .as_ref()
                        .ok_or(VerifyError::MissingRecipient)?,
                    spend.value.ok_or(VerifyError::MissingValue)?,
                    spend.rho.as_ref().ok_or(VerifyError::MissingRho)?,
                    spend.rseed.as_ref().ok_or(VerifyError::MissingRandomSeed)?,
                    spend
                        .fvk
                        .as_ref()
                        .ok_or(VerifyError::MissingFullViewingKey)?,
                    note_version,
                )?;
                resolved_nullifier = Some(nf);
                Ok(nf)
            };

            if action.cv_net.is_none() {
                action.cv_net = Some(recompute::cv_net(
                    action.spend.value.ok_or(VerifyError::MissingValue)?,
                    action.output.value.ok_or(VerifyError::MissingValue)?,
                    action
                        .rcv
                        .as_ref()
                        .ok_or(VerifyError::MissingValueCommitTrapdoor)?,
                )?);
            }

            if action.spend.rk.is_none() {
                action.spend.rk = Some(recompute::rk(
                    action
                        .spend
                        .fvk
                        .as_ref()
                        .ok_or(VerifyError::MissingFullViewingKey)?,
                    action
                        .spend
                        .alpha
                        .as_ref()
                        .ok_or(VerifyError::MissingSpendAuthRandomizer)?,
                )?);
            }

            if action.output.cmx.is_none() {
                let nf = nullifier(&action.spend)?;
                action.output.cmx = Some(recompute::cmx(
                    action
                        .output
                        .recipient
                        .as_ref()
                        .ok_or(VerifyError::MissingRecipient)?,
                    action.output.value.ok_or(VerifyError::MissingValue)?,
                    &nf,
                    action
                        .output
                        .rseed
                        .as_ref()
                        .ok_or(VerifyError::MissingRandomSeed)?,
                    note_version,
                )?);
            }

            // `ephemeral_key` and `enc_ciphertext` share the note encryptor, so if
            // either is missing both are recomputed and the wire value is kept for
            // whichever was present.
            if action.output.ephemeral_key.is_none() || action.output.enc_ciphertext.is_none() {
                let memo = match (&action.output.enc_ciphertext, action.output.memo_kind) {
                    // Reconstructing the ciphertext requires the note's memo, named
                    // by the tag.
                    (None, Some(kind)) => kind.memo(),
                    (None, None) => return Err(FillError::MissingMemoKind),
                    // Only `ephemeral_key` is missing; it is memo-independent, so any
                    // memo serves.
                    (Some(_), _) => MemoKind::Zero.memo(),
                };
                let nf = nullifier(&action.spend)?;
                let (recomputed_epk, recomputed_enc) = recompute::ephemeral_key_and_enc_ciphertext(
                    action
                        .output
                        .recipient
                        .as_ref()
                        .ok_or(VerifyError::MissingRecipient)?,
                    action.output.value.ok_or(VerifyError::MissingValue)?,
                    &nf,
                    action
                        .output
                        .rseed
                        .as_ref()
                        .ok_or(VerifyError::MissingRandomSeed)?,
                    &memo,
                    note_version,
                )?;
                if action.output.ephemeral_key.is_none() {
                    action.output.ephemeral_key = Some(recomputed_epk);
                }
                if action.output.enc_ciphertext.is_none() {
                    action.output.enc_ciphertext = Some(recomputed_enc);
                }
            }

            if action.spend.nullifier.is_none() {
                action.spend.nullifier = Some(nullifier(&action.spend)?);
            }

            // The tag exists only to reconstruct an elided ciphertext; with
            // `enc_ciphertext` now present it is spent, and clearing it restores the
            // never-redacted encoding.
            action.output.memo_kind = None;
        }
        Ok(())
    }

    /// Parses this bundle as an Ironwood-pool bundle, deriving each spend's
    /// `FullViewingKey` from its wire `fvk` bytes.
    pub(crate) fn into_ironwood_parsed(
        self,
    ) -> Result<orchard::pczt::Bundle, orchard::pczt::ParseError> {
        self.into_parsed_with_version(BundleVersion::ironwood_v3())
    }

    /// Parses this bundle as an Ironwood-pool bundle for a preverified signing pass,
    /// skipping each spend's `FullViewingKey` derivation. See
    /// [`Bundle::into_parsed_with_version_preverified_for_signing`] for the invariant
    /// callers must uphold.
    pub(crate) fn into_ironwood_parsed_preverified_for_signing(
        self,
    ) -> Result<orchard::pczt::Bundle, orchard::pczt::ParseError> {
        self.into_parsed_with_version_preverified_for_signing(BundleVersion::ironwood_v3())
    }

    /// Parses this bundle with the given bundle version, deriving each spend's
    /// `FullViewingKey` from its wire `fvk` bytes.
    pub(crate) fn into_parsed_with_version(
        self,
        bundle_version: BundleVersion,
    ) -> Result<orchard::pczt::Bundle, orchard::pczt::ParseError> {
        self.into_parsed_inner(bundle_version, false)
    }

    /// Parses this bundle with the given bundle version for a preverified signing
    /// pass, skipping each spend's `FullViewingKey` derivation (an expensive step the
    /// spend authorization signature does not depend on).
    ///
    /// Callers MUST have already run the full Verifier checks over the identical PCZT
    /// bytes: the wire `fvk` bytes are neither validated nor retained here (each spend
    /// has `fvk: None`), so the result must not go to the Verifier check path or the
    /// Prover, and re-serializing it drops the wire `fvk`s (the low-level Signer
    /// restores them from a pre-parse snapshot).
    pub(crate) fn into_parsed_with_version_preverified_for_signing(
        self,
        bundle_version: BundleVersion,
    ) -> Result<orchard::pczt::Bundle, orchard::pczt::ParseError> {
        self.into_parsed_inner(bundle_version, true)
    }

    /// The shared body of [`Bundle::into_parsed_with_version`] and
    /// [`Bundle::into_parsed_with_version_preverified_for_signing`]: `preverified`
    /// selects between the full parse and the preverified signing parse.
    fn into_parsed_inner(
        mut self,
        bundle_version: BundleVersion,
        preverified: bool,
    ) -> Result<orchard::pczt::Bundle, orchard::pczt::ParseError> {
        // Recompute-and-fill any elided derived field (and placeholder anchor) first,
        // so the parsed protocol structs are fully populated and every downstream
        // consumer sees complete actions; see `fill_derived_fields`. This is a no-op
        // for a fully-populated bundle, and justifies the `expect`s below.
        self.fill_derived_fields()
            .map_err(FillError::into_parse_error)?;

        // We parse actions through a helper that is specifically `#[inline(never)]`.
        // This is because if this gets inlined in a loop (e.g. `.map(..).collect()`),
        // it could compile into a stack frame that is tens of KB deep.
        // This can overflow stacks of embedded signers for high action count
        // transactions.
        #[inline(never)]
        fn parse_action_inner(
            action: Action,
            note_version: NoteVersion,
            preverified: bool,
        ) -> Result<orchard::pczt::Action, orchard::pczt::ParseError> {
            const FILLED: &str = "fill_derived_fields populated every derived field";

            let spend_zip32_derivation = action
                .spend
                .zip32_derivation
                .map(|z| {
                    orchard::pczt::Zip32Derivation::parse(z.seed_fingerprint, z.derivation_path)
                })
                .transpose()?;

            let spend = if preverified {
                orchard::pczt::Spend::parse_preverified_for_signing(
                    action.spend.nullifier.expect(FILLED),
                    action.spend.rk.expect(FILLED),
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
                    action.spend.nullifier.expect(FILLED),
                    action.spend.rk.expect(FILLED),
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

            let output = orchard::pczt::Output::parse(
                *spend.nullifier(),
                action.output.cmx.expect(FILLED),
                action.output.ephemeral_key.expect(FILLED),
                action.output.enc_ciphertext.expect(FILLED),
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

            orchard::pczt::Action::parse(action.cv_net.expect(FILLED), spend, output, action.rcv)
        }

        let note_version = self.note_version;
        let mut actions = Vec::with_capacity(self.actions.len());
        for action in self.actions {
            actions.push(parse_action_inner(action, note_version, preverified)?);
        }

        orchard::pczt::Bundle::parse(
            actions,
            self.flags,
            bundle_version,
            self.value_sum,
            self.anchor
                .expect("fill_derived_fields populated the anchor"),
            self.zkproof,
            self.bsk,
        )
    }

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
                    // A parsed bundle always carries the derived fields, so writing it
                    // back to the wire always populates them.
                    cv_net: Some(action.cv_net().to_bytes()),
                    spend: Spend {
                        nullifier: Some(spend.nullifier().to_bytes()),
                        rk: Some(spend.rk().into()),
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
                        ephemeral_key: Some(output.encrypted_note().epk_bytes),
                        enc_ciphertext: Some(output.encrypted_note().enc_ciphertext.to_vec()),
                        memo_kind: None,
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

        Self {
            actions,
            flags: bundle.flag_byte(),
            value_sum,
            anchor: Some(bundle.anchor().to_bytes()),
            note_version,
            zkproof: bundle
                .zkproof()
                .as_ref()
                .map(|zkproof| zkproof.as_ref().to_vec()),
            bsk: bundle.bsk().as_ref().map(|bsk| bsk.into()),
        }
    }
}
