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
    pub(crate) anchor: [u8; 32],

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

/// The canonical empty Orchard-pool bundle: the form the Orchard slot of a PCZT takes
/// when it carries no Orchard-protocol data. The Creator, the v1 decoder, and the v2
/// decoder all produce exactly this value for an absent bundle, so that copies of a
/// PCZT that take different serialization paths continue to merge successfully.
pub(crate) const EMPTY_ORCHARD: Bundle = Bundle {
    actions: Vec::new(),
    flags: ORCHARD_SPENDS_AND_OUTPUTS_ENABLED,
    value_sum: (0, false),
    anchor: [0; 32],
    note_version: NoteVersion::V2,
    zkproof: None,
    bsk: None,
};

/// The canonical empty Ironwood bundle; see [`EMPTY_ORCHARD`].
pub(crate) const EMPTY_IRONWOOD: Bundle = Bundle {
    actions: Vec::new(),
    flags: IRONWOOD_SPENDS_OUTPUTS_AND_CROSS_ADDRESS_ENABLED,
    value_sum: (0, false),
    anchor: [0; 32],
    note_version: NoteVersion::V3,
    zkproof: None,
    bsk: None,
};

/// Information about an Orchard action within a transaction.
#[derive(Clone, Debug, PartialEq, Getters)]
pub struct Action {
    //
    // Action effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    #[getset(get = "pub")]
    pub(crate) cv_net: [u8; 32],
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
    pub(crate) cmx: [u8; 32],
    #[getset(get = "pub")]
    pub(crate) ephemeral_key: [u8; 32],
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    ///
    /// Once we have memo bundles, we will be able to set memos independently of Outputs.
    /// For now, the Constructor sets both at the same time.
    #[getset(get = "pub")]
    pub(crate) enc_ciphertext: Vec<u8>,
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
                actions: bundle.actions.into_iter().map(Action::from).collect(),
                flags: bundle.flags,
                value_sum: bundle.value_sum,
                anchor: bundle.anchor,
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
                anchor: bundle.anchor,
                note_version: NoteVersion::V2,
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
}

/// Types for the v2 Orchard PCZT encoding.
pub(crate) mod v2 {
    use alloc::vec::Vec;

    use getset::Getters;
    use serde::{Deserialize, Serialize};

    use super::{NoteVersion, v1};

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
        actions: Vec<v1::Action>,
        flags: u8,
        value_sum: (u64, bool),
        anchor: [u8; 32],
        note_version: SerializedNoteVersion,
        zkproof: Option<Vec<u8>>,
        bsk: Option<[u8; 32]>,
    }

    impl TryFrom<super::Bundle> for Bundle {
        type Error = crate::EncodingError;

        fn try_from(bundle: super::Bundle) -> Result<Self, Self::Error> {
            Ok(Self {
                actions: bundle
                    .actions
                    .into_iter()
                    .map(v1::Action::from)
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

    /// Encodes a logical Orchard-protocol bundle for the v2 PCZT format, owning the
    /// decision of whether the bundle can be omitted. A bundle that is exactly equal
    /// to `empty` (the canonical empty bundle for its slot, [`super::EMPTY_ORCHARD`]
    /// or [`super::EMPTY_IRONWOOD`]) serializes to `None` and is dropped from the
    /// encoding; any other bundle is converted via the [`Bundle`]-producing
    /// [`TryFrom`] impl. The reverse direction is [`From<Bundle>`] plus the canonical
    /// empty bundle for the omitted case.
    pub(crate) fn encode(
        bundle: super::Bundle,
        empty: &super::Bundle,
    ) -> Result<Option<Bundle>, crate::EncodingError> {
        (bundle != *empty)
            .then(|| Bundle::try_from(bundle))
            .transpose()
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

        if self.anchor != anchor {
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

            if lhs.cv_net != cv_net
                || lhs.spend.nullifier != nullifier
                || lhs.spend.rk != rk
                || lhs.output.cmx != cmx
                || lhs.output.ephemeral_key != ephemeral_key
                || lhs.output.enc_ciphertext != enc_ciphertext
                || lhs.output.out_ciphertext != out_ciphertext
            {
                return None;
            }

            if !(merge_optional(&mut lhs.spend.spend_auth_sig, spend_auth_sig)
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

#[cfg(feature = "orchard")]
impl Bundle {
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
        self,
        bundle_version: BundleVersion,
        preverified: bool,
    ) -> Result<orchard::pczt::Bundle, orchard::pczt::ParseError> {
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
            let spend_zip32_derivation = action
                .spend
                .zip32_derivation
                .map(|z| {
                    orchard::pczt::Zip32Derivation::parse(z.seed_fingerprint, z.derivation_path)
                })
                .transpose()?;

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

            let output = orchard::pczt::Output::parse(
                *spend.nullifier(),
                action.output.cmx,
                action.output.ephemeral_key,
                action.output.enc_ciphertext,
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

            orchard::pczt::Action::parse(action.cv_net, spend, output, action.rcv)
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
            self.anchor,
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
                    cv_net: action.cv_net().to_bytes(),
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
                        cmx: output.cmx().to_bytes(),
                        ephemeral_key: output.encrypted_note().epk_bytes,
                        enc_ciphertext: output.encrypted_note().enc_ciphertext.to_vec(),
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
            anchor: bundle.anchor().to_bytes(),
            note_version,
            zkproof: bundle
                .zkproof()
                .as_ref()
                .map(|zkproof| zkproof.as_ref().to_vec()),
            bsk: bundle.bsk().as_ref().map(|bsk| bsk.into()),
        }
    }
}
