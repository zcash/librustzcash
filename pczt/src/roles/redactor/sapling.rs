use crate::sapling::{Bundle, Output, Spend};

impl super::Redactor {
    /// Redacts the Sapling bundle with the given closure.
    pub fn redact_sapling_with<F>(mut self, f: F) -> Self
    where
        F: FnOnce(SaplingRedactor<'_>),
    {
        f(SaplingRedactor(&mut self.pczt.sapling));
        self
    }
}

/// A Redactor for the Sapling bundle.
pub struct SaplingRedactor<'a>(&'a mut Bundle);

impl SaplingRedactor<'_> {
    /// Redacts all spends in the same way.
    pub fn redact_spends<F>(&mut self, f: F)
    where
        F: FnOnce(SpendRedactor<'_>),
    {
        f(SpendRedactor(Spends::All(&mut self.0.spends)));
    }

    /// Redacts the spend at the given index.
    ///
    /// Does nothing if the index is out of range.
    pub fn redact_spend<F>(&mut self, index: usize, f: F)
    where
        F: FnOnce(SpendRedactor<'_>),
    {
        if let Some(spend) = self.0.spends.get_mut(index) {
            f(SpendRedactor(Spends::One(spend)));
        }
    }

    /// Redacts all outputs in the same way.
    pub fn redact_outputs<F>(&mut self, f: F)
    where
        F: FnOnce(OutputRedactor<'_>),
    {
        f(OutputRedactor(Outputs::All(&mut self.0.outputs)));
    }

    /// Redacts the output at the given index.
    ///
    /// Does nothing if the index is out of range.
    pub fn redact_output<F>(&mut self, index: usize, f: F)
    where
        F: FnOnce(OutputRedactor<'_>),
    {
        if let Some(output) = self.0.outputs.get_mut(index) {
            f(OutputRedactor(Outputs::One(output)));
        }
    }

    /// Removes the proof.
    pub fn clear_bsk(&mut self) {
        self.0.bsk = None;
    }
}

/// A Redactor for Sapling spends.
pub struct SpendRedactor<'a>(Spends<'a>);

enum Spends<'a> {
    All(&'a mut [Spend]),
    One(&'a mut Spend),
}

impl SpendRedactor<'_> {
    fn redact<F>(&mut self, f: F)
    where
        F: Fn(&mut Spend),
    {
        match &mut self.0 {
            Spends::All(spends) => {
                for spend in spends.iter_mut() {
                    f(spend);
                }
            }
            Spends::One(spend) => {
                f(spend);
            }
        }
    }

    /// Removes the proof.
    pub fn clear_zkproof(&mut self) {
        self.redact(|spend| {
            spend.zkproof = None;
        });
    }

    /// Removes the spend authorizing signature.
    pub fn clear_spend_auth_sig(&mut self) {
        self.redact(|spend| {
            spend.spend_auth_sig = None;
        });
    }

    /// Removes the recipient.
    pub fn clear_recipient(&mut self) {
        self.redact(|spend| {
            spend.recipient = None;
        });
    }

    /// Removes the value.
    pub fn clear_value(&mut self) {
        self.redact(|spend| {
            spend.value = None;
        });
    }

    /// Removes the note commitment randomness.
    pub fn clear_rcm(&mut self) {
        self.redact(|spend| {
            spend.rcm = None;
        });
    }

    /// Removes the seed randomness for the note being spent.
    pub fn clear_rseed(&mut self) {
        self.redact(|spend| {
            spend.rseed = None;
        });
    }

    /// Removes the value commitment randomness.
    pub fn clear_rcv(&mut self) {
        self.redact(|spend| {
            spend.rcv = None;
        });
    }

    /// Removes the proof generation key.
    pub fn clear_proof_generation_key(&mut self) {
        self.redact(|spend| {
            spend.proof_generation_key = None;
        });
    }

    /// Removes the witness from the note to the bundle's anchor.
    pub fn clear_witness(&mut self) {
        self.redact(|spend| {
            spend.witness = None;
        });
    }

    /// Removes the spend authorization randomizer.
    pub fn clear_alpha(&mut self) {
        self.redact(|spend| {
            spend.alpha = None;
        });
    }

    /// Removes the ZIP 32 derivation path at which the spending key can be found for the
    /// note being spent.
    pub fn clear_zip32_derivation(&mut self) {
        self.redact(|spend| {
            spend.zip32_derivation = None;
        });
    }

    /// Removes the spend authorizing key for this spent note, if it is a dummy note.
    pub fn clear_dummy_ask(&mut self) {
        self.redact(|spend| {
            spend.dummy_ask = None;
        });
    }

    /// Redacts the proprietary value at the given key.
    pub fn redact_proprietary(&mut self, key: &str) {
        self.redact(|spend| {
            spend.proprietary.remove(key);
        });
    }

    /// Removes all proprietary values.
    pub fn clear_proprietary(&mut self) {
        self.redact(|spend| {
            spend.proprietary.clear();
        });
    }
}

/// A Redactor for Sapling outputs.
pub struct OutputRedactor<'a>(Outputs<'a>);

enum Outputs<'a> {
    All(&'a mut [Output]),
    One(&'a mut Output),
}

impl OutputRedactor<'_> {
    fn redact<F>(&mut self, f: F)
    where
        F: Fn(&mut Output),
    {
        match &mut self.0 {
            Outputs::All(outputs) => {
                for output in outputs.iter_mut() {
                    f(output);
                }
            }
            Outputs::One(output) => {
                f(output);
            }
        }
    }

    /// Removes the proof.
    pub fn clear_zkproof(&mut self) {
        self.redact(|output| {
            output.zkproof = None;
        });
    }

    /// Removes the recipient.
    pub fn clear_recipient(&mut self) {
        self.redact(|output| {
            output.recipient = None;
        });
    }

    /// Removes the value.
    pub fn clear_value(&mut self) {
        self.redact(|output| {
            output.value = None;
        });
    }

    /// Removes the seed randomness for the note being created.
    pub fn clear_rseed(&mut self) {
        self.redact(|output| {
            output.rseed = None;
        });
    }

    /// Removes the value commitment randomness.
    pub fn clear_rcv(&mut self) {
        self.redact(|output| {
            output.rcv = None;
        });
    }

    /// Removes the `ock` value used to encrypt `out_ciphertext`.
    pub fn clear_ock(&mut self) {
        self.redact(|output| {
            output.ock = None;
        });
    }

    /// Removes the ZIP 32 derivation path at which the spending key can be found for the
    /// note being created.
    pub fn clear_zip32_derivation(&mut self) {
        self.redact(|output| {
            output.zip32_derivation = None;
        });
    }

    /// Removes the user-facing address to which this output is being sent, if any.
    pub fn clear_user_address(&mut self) {
        self.redact(|output| {
            output.user_address = None;
        });
    }

    /// Redacts the proprietary value at the given key.
    pub fn redact_proprietary(&mut self, key: &str) {
        self.redact(|output| {
            output.proprietary.remove(key);
        });
    }

    /// Removes all proprietary values.
    pub fn clear_proprietary(&mut self) {
        self.redact(|output| {
            output.proprietary.clear();
        });
    }
}
