//! The Sapling fields of a PCZT.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use getset::Getters;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    common::{Global, Zip32Derivation},
    roles::combiner::{merge_map, merge_optional},
};

const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;

/// PCZT fields that are specific to producing the transaction's Sapling bundle (if any).
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Bundle {
    #[getset(get = "pub")]
    pub(crate) spends: Vec<Spend>,
    #[getset(get = "pub")]
    pub(crate) outputs: Vec<Output>,

    /// The net value of Sapling spends minus outputs.
    ///
    /// This is initialized by the Creator, and updated by the Constructor as spends or
    /// outputs are added to the PCZT. It enables per-spend and per-output values to be
    /// redacted from the PCZT after they are no longer necessary.
    #[getset(get = "pub")]
    pub(crate) value_sum: i128,

    /// The Sapling anchor for this transaction.
    ///
    /// Set by the Creator.
    #[getset(get = "pub")]
    pub(crate) anchor: [u8; 32],

    /// The Sapling binding signature signing key.
    ///
    /// - This is `None` until it is set by the IO Finalizer.
    /// - The Transaction Extractor uses this to produce the binding signature.
    pub(crate) bsk: Option<[u8; 32]>,
}

/// Information about a Sapling spend within a transaction.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Spend {
    //
    // SpendDescription effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    #[getset(get = "pub")]
    pub(crate) cv: [u8; 32],
    #[getset(get = "pub")]
    pub(crate) nullifier: [u8; 32],
    #[getset(get = "pub")]
    pub(crate) rk: [u8; 32],

    /// The Spend proof.
    ///
    /// This is set by the Prover.
    #[serde_as(as = "Option<[_; GROTH_PROOF_SIZE]>")]
    pub(crate) zkproof: Option<[u8; GROTH_PROOF_SIZE]>,

    /// The spend authorization signature.
    ///
    /// This is set by the Signer.
    #[serde_as(as = "Option<[_; 64]>")]
    pub(crate) spend_auth_sig: Option<[u8; 64]>,

    /// The [raw encoding] of the Sapling payment address that received the note being spent.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    ///
    /// [raw encoding]: https://zips.z.cash/protocol/protocol.pdf#saplingpaymentaddrencoding
    #[serde_as(as = "Option<[_; 43]>")]
    pub(crate) recipient: Option<[u8; 43]>,

    /// The value of the input being spent.
    ///
    /// This may be used by Signers to verify that the value matches `cv`, and to confirm
    /// the values and change involved in the transaction.
    ///
    /// This exposes the input value to all participants. For Signers who don't need this
    /// information, or after signatures have been applied, this can be redacted.
    pub(crate) value: Option<u64>,

    /// The note commitment randomness.
    ///
    /// - This is set by the Constructor. It MUST NOT be set if the note has an `rseed`
    ///   (i.e. was created after [ZIP 212] activation).
    /// - The Prover requires either this or `rseed`.
    ///
    /// [ZIP 212]: https://zips.z.cash/zip-0212
    pub(crate) rcm: Option<[u8; 32]>,

    /// The seed randomness for the note being spent.
    ///
    /// - This is set by the Constructor. It MUST NOT be set if the note has no `rseed`
    ///   (i.e. was created before [ZIP 212] activation).
    /// - The Prover requires either this or `rcm`.
    ///
    /// [ZIP 212]: https://zips.z.cash/zip-0212
    pub(crate) rseed: Option<[u8; 32]>,

    /// The value commitment randomness.
    ///
    /// - This is set by the Constructor.
    /// - The IO Finalizer compresses it into `bsk`.
    /// - This is required by the Prover.
    /// - This may be used by Signers to verify that the value correctly matches `cv`.
    ///
    /// This opens `cv` for all participants. For Signers who don't need this information,
    /// or after proofs / signatures have been applied, this can be redacted.
    pub(crate) rcv: Option<[u8; 32]>,

    /// The proof generation key `(ak, nsk)` corresponding to the recipient that received
    /// the note being spent.
    ///
    /// - This is set by the Updater.
    /// - This is required by the Prover.
    pub(crate) proof_generation_key: Option<([u8; 32], [u8; 32])>,

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

    /// The spend authorizing key for this spent note, if it is a dummy note.
    ///
    /// - This is chosen by the Constructor.
    /// - This is required by the IO Finalizer, and is cleared by it once used.
    /// - Signers MUST reject PCZTs that contain `dummy_ask` values.
    pub(crate) dummy_ask: Option<[u8; 32]>,

    /// Proprietary fields related to the note being spent.
    #[getset(get = "pub")]
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

/// Information about a Sapling output within a transaction.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Output {
    //
    // OutputDescription effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    #[getset(get = "pub")]
    pub(crate) cv: [u8; 32],
    #[getset(get = "pub")]
    pub(crate) cmu: [u8; 32],
    #[getset(get = "pub")]
    pub(crate) ephemeral_key: [u8; 32],
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    ///
    /// Once we have [memo bundles], we will be able to set memos independently of
    /// Outputs. For now, the Constructor sets both at the same time.
    ///
    /// [memo bundles]: https://zips.z.cash/zip-0231
    #[getset(get = "pub")]
    pub(crate) enc_ciphertext: Vec<u8>,
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    #[getset(get = "pub")]
    pub(crate) out_ciphertext: Vec<u8>,

    /// The Output proof.
    ///
    /// This is set by the Prover.
    #[serde_as(as = "Option<[_; GROTH_PROOF_SIZE]>")]
    pub(crate) zkproof: Option<[u8; GROTH_PROOF_SIZE]>,

    /// The [raw encoding] of the Sapling payment address that will receive the output.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    ///
    /// [raw encoding]: https://zips.z.cash/protocol/protocol.pdf#saplingpaymentaddrencoding
    #[serde_as(as = "Option<[_; 43]>")]
    #[getset(get = "pub")]
    pub(crate) recipient: Option<[u8; 43]>,

    /// The value of the output.
    ///
    /// This may be used by Signers to verify that the value matches `cv`, and to confirm
    /// the values and change involved in the transaction.
    ///
    /// This exposes the output value to all participants. For Signers who don't need this
    /// information, or after signatures have been applied, this can be redacted.
    #[getset(get = "pub")]
    pub(crate) value: Option<u64>,

    /// The seed randomness for the output.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover, instead of disclosing `shared_secret` to them.
    #[getset(get = "pub")]
    pub(crate) rseed: Option<[u8; 32]>,

    /// The value commitment randomness.
    ///
    /// - This is set by the Constructor.
    /// - The IO Finalizer compresses it into `bsk`.
    /// - This is required by the Prover.
    /// - This may be used by Signers to verify that the value correctly matches `cv`.
    ///
    /// This opens `cv` for all participants. For Signers who don't need this information,
    /// or after proofs / signatures have been applied, this can be redacted.
    pub(crate) rcv: Option<[u8; 32]>,

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

    /// Proprietary fields related to the note being spent.
    #[getset(get = "pub")]
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
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
            mut spends,
            mut outputs,
            value_sum,
            anchor,
            bsk,
        } = other;

        // If `bsk` is set on either bundle, the IO Finalizer has run, which means we
        // cannot have differing numbers of spends or outputs, and the value balances must
        // match.
        match (self.bsk.as_mut(), bsk) {
            (Some(lhs), Some(rhs)) if lhs != &rhs => return None,
            (Some(_), _) | (_, Some(_))
                if self.spends.len() != spends.len()
                    || self.outputs.len() != outputs.len()
                    || self.value_sum != value_sum =>
            {
                return None
            }
            // IO Finalizer has run, and neither bundle has excess spends or outputs.
            (Some(_), _) | (_, Some(_)) => (),
            // IO Finalizer has not run on either bundle.
            (None, None) => {
                let (spends_cmp_other, outputs_cmp_other) = match (
                    self.spends.len().cmp(&spends.len()),
                    self.outputs.len().cmp(&outputs.len()),
                ) {
                    // These cases require us to recalculate the value sum, which we can't
                    // do without a parsed bundle.
                    (Ordering::Less, Ordering::Greater) | (Ordering::Greater, Ordering::Less) => {
                        return None
                    }
                    // These cases mean that at least one of the two value sums is correct
                    // and we can use it directly.
                    (spends, outputs) => (spends, outputs),
                };

                match (
                    self_global.shielded_modifiable(),
                    other_global.shielded_modifiable(),
                    spends_cmp_other,
                ) {
                    // Fail if the merge would add spends to a non-modifiable bundle.
                    (false, _, Ordering::Less) | (_, false, Ordering::Greater) => return None,
                    // If the other bundle has more spends than us, move them over; these cannot
                    // conflict by construction.
                    (true, _, Ordering::Less) => {
                        self.spends.extend(spends.drain(self.spends.len()..))
                    }
                    // Do nothing otherwise.
                    (_, _, Ordering::Equal) | (_, true, Ordering::Greater) => (),
                }

                match (
                    self_global.shielded_modifiable(),
                    other_global.shielded_modifiable(),
                    outputs_cmp_other,
                ) {
                    // Fail if the merge would add outputs to a non-modifiable bundle.
                    (false, _, Ordering::Less) | (_, false, Ordering::Greater) => return None,
                    // If the other bundle has more outputs than us, move them over; these cannot
                    // conflict by construction.
                    (true, _, Ordering::Less) => {
                        self.outputs.extend(outputs.drain(self.outputs.len()..))
                    }
                    // Do nothing otherwise.
                    (_, _, Ordering::Equal) | (_, true, Ordering::Greater) => (),
                }

                if matches!(spends_cmp_other, Ordering::Less)
                    || matches!(outputs_cmp_other, Ordering::Less)
                {
                    // We check below that the overlapping spends and outputs match.
                    // Assuming here that they will, we take the other bundle's value sum.
                    self.value_sum = value_sum;
                }
            }
        }

        if self.anchor != anchor {
            return None;
        }

        // Leverage the early-exit behaviour of zip to confirm that the remaining data in
        // the other bundle matches this one.
        for (lhs, rhs) in self.spends.iter_mut().zip(spends.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Spend {
                cv,
                nullifier,
                rk,
                zkproof,
                spend_auth_sig,
                recipient,
                value,
                rcm,
                rseed,
                rcv,
                proof_generation_key,
                witness,
                alpha,
                zip32_derivation,
                dummy_ask,
                proprietary,
            } = rhs;

            if lhs.cv != cv || lhs.nullifier != nullifier || lhs.rk != rk {
                return None;
            }

            if !(merge_optional(&mut lhs.zkproof, zkproof)
                && merge_optional(&mut lhs.spend_auth_sig, spend_auth_sig)
                && merge_optional(&mut lhs.recipient, recipient)
                && merge_optional(&mut lhs.value, value)
                && merge_optional(&mut lhs.rcm, rcm)
                && merge_optional(&mut lhs.rseed, rseed)
                && merge_optional(&mut lhs.rcv, rcv)
                && merge_optional(&mut lhs.proof_generation_key, proof_generation_key)
                && merge_optional(&mut lhs.witness, witness)
                && merge_optional(&mut lhs.alpha, alpha)
                && merge_optional(&mut lhs.zip32_derivation, zip32_derivation)
                && merge_optional(&mut lhs.dummy_ask, dummy_ask)
                && merge_map(&mut lhs.proprietary, proprietary))
            {
                return None;
            }
        }

        for (lhs, rhs) in self.outputs.iter_mut().zip(outputs.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Output {
                cv,
                cmu,
                ephemeral_key,
                enc_ciphertext,
                out_ciphertext,
                zkproof,
                recipient,
                value,
                rseed,
                rcv,
                ock,
                zip32_derivation,
                user_address,
                proprietary,
            } = rhs;

            if lhs.cv != cv
                || lhs.cmu != cmu
                || lhs.ephemeral_key != ephemeral_key
                || lhs.enc_ciphertext != enc_ciphertext
                || lhs.out_ciphertext != out_ciphertext
            {
                return None;
            }

            if !(merge_optional(&mut lhs.zkproof, zkproof)
                && merge_optional(&mut lhs.recipient, recipient)
                && merge_optional(&mut lhs.value, value)
                && merge_optional(&mut lhs.rseed, rseed)
                && merge_optional(&mut lhs.rcv, rcv)
                && merge_optional(&mut lhs.ock, ock)
                && merge_optional(&mut lhs.zip32_derivation, zip32_derivation)
                && merge_optional(&mut lhs.user_address, user_address)
                && merge_map(&mut lhs.proprietary, proprietary))
            {
                return None;
            }
        }

        Some(self)
    }
}

#[cfg(feature = "sapling")]
impl Bundle {
    pub(crate) fn into_parsed(self) -> Result<sapling::pczt::Bundle, sapling::pczt::ParseError> {
        let spends = self
            .spends
            .into_iter()
            .map(|spend| {
                sapling::pczt::Spend::parse(
                    spend.cv,
                    spend.nullifier,
                    spend.rk,
                    spend.zkproof,
                    spend.spend_auth_sig,
                    spend.recipient,
                    spend.value,
                    spend.rcm,
                    spend.rseed,
                    spend.rcv,
                    spend.proof_generation_key,
                    spend.witness,
                    spend.alpha,
                    spend
                        .zip32_derivation
                        .map(|z| {
                            sapling::pczt::Zip32Derivation::parse(
                                z.seed_fingerprint,
                                z.derivation_path,
                            )
                        })
                        .transpose()?,
                    spend.dummy_ask,
                    spend.proprietary,
                )
            })
            .collect::<Result<_, _>>()?;

        let outputs = self
            .outputs
            .into_iter()
            .map(|output| {
                sapling::pczt::Output::parse(
                    output.cv,
                    output.cmu,
                    output.ephemeral_key,
                    output.enc_ciphertext,
                    output.out_ciphertext,
                    output.zkproof,
                    output.recipient,
                    output.value,
                    output.rseed,
                    output.rcv,
                    output.ock,
                    output
                        .zip32_derivation
                        .map(|z| {
                            sapling::pczt::Zip32Derivation::parse(
                                z.seed_fingerprint,
                                z.derivation_path,
                            )
                        })
                        .transpose()?,
                    output.user_address,
                    output.proprietary,
                )
            })
            .collect::<Result<_, _>>()?;

        sapling::pczt::Bundle::parse(spends, outputs, self.value_sum, self.anchor, self.bsk)
    }

    pub(crate) fn serialize_from(bundle: sapling::pczt::Bundle) -> Self {
        let spends = bundle
            .spends()
            .iter()
            .map(|spend| {
                let (rcm, rseed) = match spend.rseed() {
                    Some(sapling::Rseed::BeforeZip212(rcm)) => (Some(rcm.to_bytes()), None),
                    Some(sapling::Rseed::AfterZip212(rseed)) => (None, Some(*rseed)),
                    None => (None, None),
                };

                Spend {
                    cv: spend.cv().to_bytes(),
                    nullifier: spend.nullifier().0,
                    rk: (*spend.rk()).into(),
                    zkproof: *spend.zkproof(),
                    spend_auth_sig: spend.spend_auth_sig().map(|s| s.into()),
                    recipient: spend.recipient().map(|recipient| recipient.to_bytes()),
                    value: spend.value().map(|value| value.inner()),
                    rcm,
                    rseed,
                    rcv: spend.rcv().as_ref().map(|rcv| rcv.inner().to_bytes()),
                    proof_generation_key: spend
                        .proof_generation_key()
                        .as_ref()
                        .map(|key| (key.ak.to_bytes(), key.nsk.to_bytes())),
                    witness: spend.witness().as_ref().map(|witness| {
                        (
                            u32::try_from(u64::from(witness.position()))
                                .expect("Sapling positions fit in u32"),
                            witness
                                .path_elems()
                                .iter()
                                .map(|node| node.to_bytes())
                                .collect::<Vec<_>>()[..]
                                .try_into()
                                .expect("path is length 32"),
                        )
                    }),
                    alpha: spend.alpha().map(|alpha| alpha.to_bytes()),
                    zip32_derivation: spend.zip32_derivation().as_ref().map(|z| Zip32Derivation {
                        seed_fingerprint: *z.seed_fingerprint(),
                        derivation_path: z.derivation_path().iter().map(|i| i.index()).collect(),
                    }),
                    dummy_ask: spend
                        .dummy_ask()
                        .as_ref()
                        .map(|dummy_ask| dummy_ask.to_bytes()),
                    proprietary: spend.proprietary().clone(),
                }
            })
            .collect();

        let outputs = bundle
            .outputs()
            .iter()
            .map(|output| Output {
                cv: output.cv().to_bytes(),
                cmu: output.cmu().to_bytes(),
                ephemeral_key: output.ephemeral_key().0,
                enc_ciphertext: output.enc_ciphertext().to_vec(),
                out_ciphertext: output.out_ciphertext().to_vec(),
                zkproof: *output.zkproof(),
                recipient: output.recipient().map(|recipient| recipient.to_bytes()),
                value: output.value().map(|value| value.inner()),
                rseed: *output.rseed(),
                rcv: output.rcv().as_ref().map(|rcv| rcv.inner().to_bytes()),
                ock: output.ock().as_ref().map(|ock| ock.0),
                zip32_derivation: output.zip32_derivation().as_ref().map(|z| Zip32Derivation {
                    seed_fingerprint: *z.seed_fingerprint(),
                    derivation_path: z.derivation_path().iter().map(|i| i.index()).collect(),
                }),
                user_address: output.user_address().clone(),
                proprietary: output.proprietary().clone(),
            })
            .collect();

        Self {
            spends,
            outputs,
            value_sum: bundle.value_sum().to_raw(),
            anchor: bundle.anchor().to_bytes(),
            bsk: bundle.bsk().map(|bsk| bsk.into()),
        }
    }
}
