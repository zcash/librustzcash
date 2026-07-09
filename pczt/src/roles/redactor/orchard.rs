use crate::orchard::{Action, Bundle, EncCiphertext, MEMO_SIZE, MemoPlaintext};

impl super::Redactor {
    /// Redacts the Orchard bundle with the given closure.
    pub fn redact_orchard_with<F>(mut self, f: F) -> Self
    where
        F: FnOnce(OrchardRedactor<'_>),
    {
        f(OrchardRedactor(&mut self.pczt.orchard));
        self
    }

    pub fn redact_ironwood_with<F>(mut self, f: F) -> Self
    where
        F: FnOnce(OrchardRedactor<'_>),
    {
        f(OrchardRedactor(&mut self.pczt.ironwood));
        self
    }
}

/// A Redactor for the Orchard bundle.
pub struct OrchardRedactor<'a>(&'a mut Bundle);

impl OrchardRedactor<'_> {
    /// Redacts all actions in the same way.
    pub fn redact_actions<F>(&mut self, f: F)
    where
        F: FnOnce(ActionRedactor<'_>),
    {
        f(ActionRedactor(Actions::All(&mut self.0.actions)));
    }

    /// Redacts the action at the given index.
    ///
    /// Does nothing if the index is out of range.
    pub fn redact_action<F>(&mut self, index: usize, f: F)
    where
        F: FnOnce(ActionRedactor<'_>),
    {
        if let Some(action) = self.0.actions.get_mut(index) {
            f(ActionRedactor(Actions::One(action)));
        }
    }

    /// Removes the proof.
    pub fn clear_zkproof(&mut self) {
        self.0.zkproof = None;
    }

    /// Removes the proof.
    pub fn clear_bsk(&mut self) {
        self.0.bsk = None;
    }

    /// Removes the bundle anchor.
    ///
    /// Parsed roles require the real anchor, so a receiver must restore it before
    /// parsing this bundle.
    pub fn clear_anchor(&mut self) {
        self.0.anchor = None;
    }
}

/// A Redactor for Orchard actions.
pub struct ActionRedactor<'a>(Actions<'a>);

enum Actions<'a> {
    All(&'a mut [Action]),
    One(&'a mut Action),
}

impl ActionRedactor<'_> {
    fn redact<F>(&mut self, f: F)
    where
        F: Fn(&mut Action),
    {
        match &mut self.0 {
            Actions::All(actions) => {
                for action in actions.iter_mut() {
                    f(action);
                }
            }
            Actions::One(action) => {
                f(action);
            }
        }
    }

    /// Removes the action's net value commitment.
    ///
    /// The receiver recomputes `cv_net` from the spend and output values and `rcv`.
    pub fn clear_cv_net(&mut self) {
        self.redact(|action| {
            action.cv_net = None;
        });
    }

    /// Removes the spend authorizing signature.
    pub fn clear_spend_auth_sig(&mut self) {
        self.redact(|action| {
            action.spend.spend_auth_sig = None;
        });
    }

    /// Removes the spend's recipient.
    pub fn clear_spend_recipient(&mut self) {
        self.redact(|action| {
            action.spend.recipient = None;
        });
    }

    /// Removes the spend's value.
    pub fn clear_spend_value(&mut self) {
        self.redact(|action| {
            action.spend.value = None;
        });
    }

    /// Removes the rho value for the note being spent.
    pub fn clear_spend_rho(&mut self) {
        self.redact(|action| {
            action.spend.rho = None;
        });
    }

    /// Removes the seed randomness for the note being spent.
    pub fn clear_spend_rseed(&mut self) {
        self.redact(|action| {
            action.spend.rseed = None;
        });
    }

    /// Removes the spend's full viewing key.
    pub fn clear_spend_fvk(&mut self) {
        self.redact(|action| {
            action.spend.fvk = None;
        });
    }

    /// Removes the witness from the spent note to the bundle's anchor.
    pub fn clear_spend_witness(&mut self) {
        self.redact(|action| {
            action.spend.witness = None;
        });
    }

    /// Removes the spend authorization randomizer.
    pub fn clear_spend_alpha(&mut self) {
        self.redact(|action| {
            action.spend.alpha = None;
        });
    }

    /// Removes the ZIP 32 derivation path at which the spending key can be found for the
    /// note being spent.
    pub fn clear_spend_zip32_derivation(&mut self) {
        self.redact(|action| {
            action.spend.zip32_derivation = None;
        });
    }

    /// Removes the spending key for this spent note, if it is a dummy note.
    pub fn clear_spend_dummy_sk(&mut self) {
        self.redact(|action| {
            action.spend.dummy_sk = None;
        });
    }

    /// Redacts the spend-specific proprietary value at the given key.
    pub fn redact_spend_proprietary(&mut self, key: &str) {
        self.redact(|action| {
            action.spend.proprietary.remove(key);
        });
    }

    /// Removes all spend-specific proprietary values.
    pub fn clear_spend_proprietary(&mut self) {
        self.redact(|action| {
            action.spend.proprietary.clear();
        });
    }

    /// Replaces the output's encrypted note plaintext with a stripped memo
    /// plaintext.
    ///
    /// The PCZT consumer can recompute
    /// [`Output::enc_ciphertext`](crate::orchard::Output::enc_ciphertext) from
    /// this memo, the output note fields, and the action's spend nullifier.
    pub fn replace_enc_ciphertext_with_memo_plaintext(&mut self, memo: [u8; MEMO_SIZE]) {
        self.redact(|action| {
            action.output.enc_ciphertext =
                EncCiphertext::MemoPlaintext(MemoPlaintext::from_memo(memo));
        });
    }

    /// Replaces the output's encrypted note plaintext with its decrypted,
    /// stripped memo plaintext, if decryption succeeds.
    ///
    /// Actions that already carry memo plaintext, lack required output note
    /// fields, or fail decryption are left unchanged.
    #[cfg(feature = "orchard")]
    pub fn replace_enc_ciphertext_with_decrypted_memo_plaintext(
        &mut self,
        note_version: ::orchard::note::NoteVersion,
    ) {
        self.redact(|action| {
            action.replace_enc_ciphertext_with_decrypted_memo_plaintext(note_version);
        });
    }

    /// Removes the output's recipient.
    pub fn clear_output_recipient(&mut self) {
        self.redact(|action| {
            action.output.recipient = None;
        });
    }

    /// Removes the output's value.
    pub fn clear_output_value(&mut self) {
        self.redact(|action| {
            action.output.value = None;
        });
    }

    /// Removes the seed randomness for the note being created.
    pub fn clear_output_rseed(&mut self) {
        self.redact(|action| {
            action.output.rseed = None;
        });
    }

    /// Removes the `ock` value used to encrypt `out_ciphertext`.
    pub fn clear_output_ock(&mut self) {
        self.redact(|action| {
            action.output.ock = None;
        });
    }

    /// Removes the ZIP 32 derivation path at which the spending key can be found for the
    /// note being created.
    pub fn clear_output_zip32_derivation(&mut self) {
        self.redact(|action| {
            action.output.zip32_derivation = None;
        });
    }

    /// Removes the user-facing address to which the output is being sent, if any.
    pub fn clear_output_user_address(&mut self) {
        self.redact(|spend| {
            spend.output.user_address = None;
        });
    }

    /// Redacts the output-specific proprietary value at the given key.
    pub fn redact_output_proprietary(&mut self, key: &str) {
        self.redact(|action| {
            action.output.proprietary.remove(key);
        });
    }

    /// Removes all output-specific proprietary values.
    pub fn clear_output_proprietary(&mut self) {
        self.redact(|action| {
            action.output.proprietary.clear();
        });
    }

    /// Removes the value commitment randomness.
    pub fn clear_rcv(&mut self) {
        self.redact(|action| {
            action.rcv = None;
        });
    }
}
