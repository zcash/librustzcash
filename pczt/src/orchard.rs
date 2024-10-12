use crate::merge_optional;

/// PCZT fields that are specific to producing the transaction's Orchard bundle (if any).
#[derive(Clone)]
pub(crate) struct Bundle {
    /// The Orchard actions in this bundle.
    ///
    /// Entries are added by the Constructor, and modified by an Updater, IO Finalizer,
    /// Signer, Combiner, or Spend Finalizer.
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
    pub(crate) flags: u8,

    /// The net value of Orchard spends minus outputs.
    ///
    /// This is initialized by the Creator, and updated by the Constructor as spends or
    /// outputs are added to the PCZT. It enables per-spend and per-output values to be
    /// redacted from the PCZT after they are no longer necessary.
    pub(crate) value_balance: u64,

    /// The Orchard anchor for this transaction.
    ///
    /// TODO: Should this be non-optional and set by the Creator (which would be simpler)?
    /// Or do we need a separate role that picks the anchor, which runs before the
    /// Constructor adds spends?
    pub(crate) anchor: Option<[u8; 32]>,

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

#[derive(Clone)]
pub(crate) struct Action {
    //
    // Action effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) cv: [u8; 32],
    pub(crate) spend: Spend,
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

/// Information about a Sapling spend within a transaction.
#[derive(Clone)]
pub(crate) struct Spend {
    //
    // Spend-specific Action effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) nullifier: [u8; 32],
    pub(crate) rk: [u8; 32],

    /// The spend authorization signature.
    ///
    /// This is set by the Signer.
    pub(crate) spend_auth_sig: Option<[u8; 64]>,

    /// The address that received the note being spent.
    ///
    /// - This is set by the Constructor (or Updater?).
    /// - This is required by the Prover.
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
    ///
    /// TODO: This could be merged with `rseed` into a tuple. `recipient` and `value` are
    /// separate because they might need to be independently redacted. (For which role?)
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
    /// - After`zkproof` / `spend_auth_sig` has been set, this can be redacted.
    pub(crate) alpha: Option<[u8; 32]>,
}

/// Information about an Orchard output within a transaction.
#[derive(Clone)]
pub(crate) struct Output {
    //
    // Output-specific Action effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) cmx: [u8; 32],
    pub(crate) ephemeral_key: [u8; 32],
    /// TODO: Should it be possible to choose the memo _value_ after defining an Output?
    pub(crate) enc_ciphertext: [u8; 580],
    pub(crate) out_ciphertext: [u8; 80],

    /// The address that will receive the output.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    pub(crate) recipient: Option<[u8; 43]>,

    /// The value of the output.
    ///
    /// This may be used by Signers to verify that the value matches `cv`, and to confirm
    /// the values and change involved in the transaction.
    ///
    /// This exposes the value to all participants. For Signers who don't need this
    /// information, we can drop the values and compress the rcvs into the bsk global.
    pub(crate) value: Option<u64>,

    /// The seed randomness for the output.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    ///
    /// TODO: This could instead be decrypted from `enc_ciphertext` if `shared_secret`
    /// were required by the Prover. Likewise for `recipient` and `value`; is there ever a
    /// need for these to be independently redacted though?
    pub(crate) rseed: Option<[u8; 32]>,
}

impl Bundle {
    /// Merges this bundle with another.
    ///
    /// Returns `None` if the bundles have conflicting data.
    pub(crate) fn merge(mut self, other: Self) -> Option<Self> {
        // Destructure `other` to ensure we handle everything.
        let Self {
            mut actions,
            flags,
            value_balance,
            anchor,
            zkproof,
            bsk,
        } = other;

        if self.flags != flags {
            return None;
        }

        // If `bsk` is set on either bundle, the IO Finalizer has run, which means we
        // cannot have differing numbers of actions, and the value balances must match.
        match (self.bsk.as_mut(), bsk) {
            (Some(lhs), Some(rhs)) if lhs != &rhs => return None,
            (Some(_), _) | (_, Some(_))
                if self.actions.len() != actions.len() || self.value_balance != value_balance =>
            {
                return None
            }
            // IO Finalizer has run, and neither bundle has excess spends or outputs.
            (Some(_), _) | (_, Some(_)) => (),
            // IO Finalizer has not run on either bundle. If the other bundle has more
            // spends or outputs than us, move them over; these cannot conflict by
            // construction.
            (None, None) => {
                if actions.len() > self.actions.len() {
                    self.actions.extend(actions.drain(self.actions.len()..));

                    // We check below that the overlapping actions match. Assuming here
                    // that they will, we can take the other bundle's value balance.
                    self.value_balance = value_balance;
                }
            }
        }

        if !(merge_optional(&mut self.anchor, anchor) && merge_optional(&mut self.zkproof, zkproof))
        {
            return None;
        }

        // Leverage the early-exit behaviour of zip to confirm that the remaining data in
        // the other bundle matches this one.
        for (lhs, rhs) in self.actions.iter_mut().zip(actions.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Action {
                cv,
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
                    },
                rcv,
            } = rhs;

            if lhs.cv != cv
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
                && merge_optional(&mut lhs.output.recipient, output_recipient)
                && merge_optional(&mut lhs.output.value, output_value)
                && merge_optional(&mut lhs.output.rseed, output_rseed)
                && merge_optional(&mut lhs.rcv, rcv))
            {
                return None;
            }
        }

        Some(self)
    }
}

#[cfg(feature = "orchard")]
impl Bundle {
    pub(crate) fn to_tx_data<A, E, F, G>(
        &self,
        action_auth: F,
        bundle_auth: G,
    ) -> Result<Option<orchard::Bundle<A, zcash_protocol::value::ZatBalance>>, E>
    where
        A: orchard::bundle::Authorization,
        E: From<Error>,
        F: Fn(&Action) -> Result<<A as orchard::bundle::Authorization>::SpendAuth, E>,
        G: FnOnce(&Self) -> Result<A, E>,
    {
        use nonempty::NonEmpty;
        use orchard::{
            bundle::Flags,
            note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
            primitives::redpallas,
            value::ValueCommitment,
            Action, Anchor, Bundle,
        };
        use zcash_protocol::value::ZatBalance;

        let actions = self
            .actions
            .iter()
            .map(|action| {
                let nf = Nullifier::from_bytes(&action.spend.nullifier)
                    .into_option()
                    .ok_or(Error::InvalidNullifier)?;

                let rk = redpallas::VerificationKey::try_from(action.spend.rk)
                    .map_err(|_| Error::InvalidRandomizedKey)?;

                let cmx = ExtractedNoteCommitment::from_bytes(&action.output.cmx)
                    .into_option()
                    .ok_or(Error::InvalidExtractedNoteCommitment)?;

                let encrypted_note = TransmittedNoteCiphertext {
                    epk_bytes: action.output.ephemeral_key,
                    enc_ciphertext: action.output.enc_ciphertext,
                    out_ciphertext: action.output.out_ciphertext,
                };

                let cv_net = ValueCommitment::from_bytes(&action.cv)
                    .into_option()
                    .ok_or(Error::InvalidValueCommitment)?;

                let authorization = action_auth(action)?;

                Ok(Action::from_parts(
                    nf,
                    rk,
                    cmx,
                    encrypted_note,
                    cv_net,
                    authorization,
                ))
            })
            .collect::<Result<_, E>>()?;

        Ok(if let Some(actions) = NonEmpty::from_vec(actions) {
            let flags = Flags::from_byte(self.flags).ok_or(Error::UnexpectedFlagBitsSet)?;

            let value_balance = ZatBalance::from_u64(self.value_balance)
                .map_err(|e| Error::InvalidValueBalance(e))?;

            let anchor = Anchor::from_bytes(self.anchor.ok_or(Error::MissingAnchor)?)
                .into_option()
                .ok_or(Error::InvalidAnchor)?;

            let authorization = bundle_auth(&self)?;

            Some(Bundle::from_parts(
                actions,
                flags,
                value_balance,
                anchor,
                authorization,
            ))
        } else {
            None
        })
    }
}

#[cfg(feature = "orchard")]
#[derive(Debug)]
pub enum Error {
    InvalidAnchor,
    InvalidExtractedNoteCommitment,
    InvalidNullifier,
    InvalidRandomizedKey,
    InvalidValueBalance(zcash_protocol::value::BalanceError),
    InvalidValueCommitment,
    MissingAnchor,
    UnexpectedFlagBitsSet,
}
