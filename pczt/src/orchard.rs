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
                        alpha,
                    },
                output:
                    Output {
                        cmx,
                        ephemeral_key,
                        enc_ciphertext,
                        out_ciphertext,
                    },
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
                && merge_optional(&mut lhs.spend.alpha, alpha))
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
