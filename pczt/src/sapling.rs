use std::cmp::Ordering;

use crate::roles::combiner::merge_optional;

#[cfg(feature = "sapling")]
use pasta_curves::group::ff::PrimeField;

const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;

/// PCZT fields that are specific to producing the transaction's Sapling bundle (if any).
#[derive(Clone, Debug)]
pub(crate) struct Bundle {
    pub(crate) spends: Vec<Spend>,
    pub(crate) outputs: Vec<Output>,

    /// The net value of Sapling spends minus outputs.
    ///
    /// This is initialized by the Creator, and updated by the Constructor as spends or
    /// outputs are added to the PCZT. It enables per-spend and per-output values to be
    /// redacted from the PCZT after they are no longer necessary.
    pub(crate) value_sum: i128,

    /// The Sapling anchor for this transaction.
    ///
    /// Set by the Creator.
    pub(crate) anchor: [u8; 32],

    /// The Sapling binding signature signing key.
    ///
    /// - This is `None` until it is set by the IO Finalizer.
    /// - The Transaction Extractor uses this to produce the binding signature.
    pub(crate) bsk: Option<[u8; 32]>,
}

/// Information about a Sapling spend within a transaction.
#[derive(Clone, Debug)]
pub(crate) struct Spend {
    //
    // SpendDescription effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) cv: [u8; 32],
    pub(crate) nullifier: [u8; 32],
    pub(crate) rk: [u8; 32],

    /// The Spend proof.
    ///
    /// This is set by the Prover.
    pub(crate) zkproof: Option<[u8; GROTH_PROOF_SIZE]>,

    /// The spend authorization signature.
    ///
    /// This is set by the Signer.
    pub(crate) spend_auth_sig: Option<[u8; 64]>,

    /// The spend authorization randomizer.
    ///
    /// - This is chosen by the Constructor.
    /// - This is required by the Signer for creating `spend_auth_sig`, and may be used to
    ///   validate `rk`.
    /// - After `zkproof` / `spend_auth_sig` has been set, this can be redacted.
    pub(crate) alpha: Option<[u8; 32]>,

    /// The spend authorizing key for this spent note, if it is a dummy note.
    ///
    /// - This is chosen by the Constructor.
    /// - This is required by the IO Finalizer, and is cleared by it once used.
    /// - Signers MUST reject PCZTs that contain `dummy_ask` values.
    pub(crate) dummy_ask: Option<[u8; 32]>,
}

/// Information about a Sapling output within a transaction.
#[derive(Clone, Debug)]
pub(crate) struct Output {
    //
    // OutputDescription effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) cv: [u8; 32],
    pub(crate) cmu: [u8; 32],
    pub(crate) ephemeral_key: [u8; 32],
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    ///
    /// Once we have [memo bundles], we will be able to set memos independently of
    /// Outputs. For now, the Constructor sets both at the same time.
    ///
    /// [memo bundles]: https://zips.z.cash/zip-0231
    pub(crate) enc_ciphertext: Vec<u8>,
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    pub(crate) out_ciphertext: Vec<u8>,

    /// The Output proof.
    ///
    /// This is set by the Prover.
    pub(crate) zkproof: Option<[u8; GROTH_PROOF_SIZE]>,
}

impl Bundle {
    /// Merges this bundle with another.
    ///
    /// Returns `None` if the bundles have conflicting data.
    pub(crate) fn merge(mut self, other: Self) -> Option<Self> {
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
            // IO Finalizer has not run on either bundle. If the other bundle has more
            // spends or outputs than us, move them over; these cannot conflict by
            // construction.
            (None, None) => {
                let (other_has_more_spends, other_has_more_outputs) = match (
                    spends.len().cmp(&self.spends.len()),
                    outputs.len().cmp(&self.outputs.len()),
                ) {
                    // These cases require us to recalculate the value sum, which we can't
                    // do without a parsed bundle.
                    (Ordering::Less, Ordering::Greater) | (Ordering::Greater, Ordering::Less) => {
                        return None
                    }
                    // These cases mean that at least one of the two value sums is correct
                    // and we can use it directly.
                    (spends, outputs) => (
                        matches!(spends, Ordering::Greater),
                        matches!(outputs, Ordering::Greater),
                    ),
                };

                if other_has_more_spends {
                    self.spends.extend(spends.drain(self.spends.len()..));
                }
                if other_has_more_outputs {
                    self.outputs.extend(outputs.drain(self.outputs.len()..));
                }
                if other_has_more_spends || other_has_more_outputs {
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
                alpha,
                dummy_ask,
            } = rhs;

            if lhs.cv != cv || lhs.nullifier != nullifier || lhs.rk != rk {
                return None;
            }

            if !(merge_optional(&mut lhs.zkproof, zkproof)
                && merge_optional(&mut lhs.spend_auth_sig, spend_auth_sig)
                && merge_optional(&mut lhs.alpha, alpha)
                && merge_optional(&mut lhs.dummy_ask, dummy_ask))
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
            } = rhs;

            if lhs.cv != cv
                || lhs.cmu != cmu
                || lhs.ephemeral_key != ephemeral_key
                || lhs.enc_ciphertext != enc_ciphertext
                || lhs.out_ciphertext != out_ciphertext
            {
                return None;
            }

            if !merge_optional(&mut lhs.zkproof, zkproof) {
                return None;
            }
        }

        Some(self)
    }
}

#[cfg(feature = "sapling")]
impl Bundle {
    pub(crate) fn to_tx_data<A, E, F, G, H, I>(
        &self,
        spend_proof: F,
        spend_auth: G,
        output_proof: H,
        bundle_auth: I,
    ) -> Result<Option<sapling::Bundle<A, zcash_protocol::value::ZatBalance>>, E>
    where
        A: sapling::bundle::Authorization,
        E: From<Error>,
        F: Fn(&Spend) -> Result<<A as sapling::bundle::Authorization>::SpendProof, E>,
        G: Fn(&Spend) -> Result<<A as sapling::bundle::Authorization>::AuthSig, E>,
        H: Fn(&Output) -> Result<<A as sapling::bundle::Authorization>::OutputProof, E>,
        I: FnOnce(&Self) -> Result<A, E>,
    {
        use sapling::{
            bundle::{OutputDescription, SpendDescription},
            note::ExtractedNoteCommitment,
            value::ValueCommitment,
            Bundle, Nullifier,
        };
        use zcash_note_encryption::EphemeralKeyBytes;
        use zcash_protocol::value::ZatBalance;

        let anchor = bls12_381::Scalar::from_bytes(&self.anchor)
            .into_option()
            .ok_or(Error::InvalidAnchor)?;

        let spends = self
            .spends
            .iter()
            .map(|spend| {
                let cv = ValueCommitment::from_bytes_not_small_order(&spend.cv)
                    .into_option()
                    .ok_or(Error::InvalidValueCommitment)?;

                let nullifier = Nullifier(spend.nullifier);

                let rk = redjubjub::VerificationKey::try_from(spend.rk)
                    .map_err(|_| Error::InvalidRandomizedKey)?;

                Ok(SpendDescription::from_parts(
                    cv,
                    anchor,
                    nullifier,
                    rk,
                    spend_proof(spend)?,
                    spend_auth(spend)?,
                ))
            })
            .collect::<Result<_, E>>()?;

        let outputs = self
            .outputs
            .iter()
            .map(|output| {
                let cv = ValueCommitment::from_bytes_not_small_order(&output.cv)
                    .into_option()
                    .ok_or(Error::InvalidValueCommitment)?;

                let cmu = ExtractedNoteCommitment::from_bytes(&output.cmu)
                    .into_option()
                    .ok_or(Error::InvalidExtractedNoteCommitment)?;

                let ephemeral_key = EphemeralKeyBytes(output.ephemeral_key);

                Ok(OutputDescription::from_parts(
                    cv,
                    cmu,
                    ephemeral_key,
                    output
                        .enc_ciphertext
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::InvalidEncCiphertext)?,
                    output
                        .out_ciphertext
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::InvalidOutCiphertext)?,
                    output_proof(output)?,
                ))
            })
            .collect::<Result<_, E>>()?;

        let value_balance =
            ZatBalance::from_u64(self.value_sum).map_err(|e| Error::InvalidValueBalance(e))?;

        let authorization = bundle_auth(&self)?;

        Ok(Bundle::from_parts(
            spends,
            outputs,
            value_balance,
            authorization,
        ))
    }
}

#[cfg(feature = "sapling")]
impl Spend {
    pub(crate) fn alpha_from_field(&self) -> Result<jubjub::Scalar, Error> {
        jubjub::Scalar::from_repr(self.alpha.ok_or(Error::MissingSpendAuthRandomizer)?)
            .into_option()
            .ok_or(Error::InvalidSpendAuthRandomizer)
    }
}

#[cfg(feature = "sapling")]
#[derive(Debug)]
pub enum Error {
    InvalidAnchor,
    InvalidEncCiphertext,
    InvalidExtractedNoteCommitment,
    InvalidOutCiphertext,
    InvalidRandomizedKey,
    InvalidSpendAuthRandomizer,
    InvalidValueBalance(zcash_protocol::value::BalanceError),
    InvalidValueCommitment,
    MissingSpendAuthRandomizer,
}
