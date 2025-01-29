use crate::transparent::{Bundle, Input, Output};

impl super::Redactor {
    /// Redacts the transparent bundle with the given closure.
    pub fn redact_transparent_with<F>(mut self, f: F) -> Self
    where
        F: FnOnce(TransparentRedactor<'_>),
    {
        f(TransparentRedactor(&mut self.pczt.transparent));
        self
    }
}

/// A Redactor for the transparent bundle.
pub struct TransparentRedactor<'a>(&'a mut Bundle);

impl TransparentRedactor<'_> {
    /// Redacts all inputs in the same way.
    pub fn redact_inputs<F>(&mut self, f: F)
    where
        F: FnOnce(InputRedactor<'_>),
    {
        f(InputRedactor(Inputs::All(&mut self.0.inputs)));
    }

    /// Redacts the input at the given index.
    ///
    /// Does nothing if the index is out of range.
    pub fn redact_input<F>(&mut self, index: usize, f: F)
    where
        F: FnOnce(InputRedactor<'_>),
    {
        if let Some(input) = self.0.inputs.get_mut(index) {
            f(InputRedactor(Inputs::One(input)));
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
}

/// A Redactor for transparent inputs.
pub struct InputRedactor<'a>(Inputs<'a>);

enum Inputs<'a> {
    All(&'a mut [Input]),
    One(&'a mut Input),
}

impl InputRedactor<'_> {
    fn redact<F>(&mut self, f: F)
    where
        F: Fn(&mut Input),
    {
        match &mut self.0 {
            Inputs::All(inputs) => {
                for input in inputs.iter_mut() {
                    f(input);
                }
            }
            Inputs::One(input) => {
                f(input);
            }
        }
    }

    /// Removes the `script_sig`.
    pub fn clear_script_sig(&mut self) {
        self.redact(|input| {
            input.script_sig = None;
        });
    }

    /// Removes the `redeem_script`.
    pub fn clear_redeem_script(&mut self) {
        self.redact(|input| {
            input.redeem_script = None;
        });
    }

    /// Redacts the signature for the given pubkey.
    pub fn redact_partial_signature(&mut self, pubkey: [u8; 33]) {
        self.redact(|input| {
            input.partial_signatures.remove(&pubkey);
        });
    }

    /// Removes all signatures.
    pub fn clear_partial_signatures(&mut self) {
        self.redact(|input| {
            input.partial_signatures.clear();
        });
    }

    /// Redacts the BIP 32 derivation path for the given pubkey.
    pub fn redact_bip32_derivation(&mut self, pubkey: [u8; 33]) {
        self.redact(|input| {
            input.bip32_derivation.remove(&pubkey);
        });
    }

    /// Removes all BIP 32 derivation paths.
    pub fn clear_bip32_derivation(&mut self) {
        self.redact(|input| {
            input.bip32_derivation.clear();
        });
    }

    /// Redacts the RIPEMD160 preimage for the given hash.
    pub fn redact_ripemd160_preimage(&mut self, hash: [u8; 20]) {
        self.redact(|input| {
            input.ripemd160_preimages.remove(&hash);
        });
    }

    /// Removes all RIPEMD160 preimages.
    pub fn clear_ripemd160_preimages(&mut self) {
        self.redact(|input| {
            input.ripemd160_preimages.clear();
        });
    }

    /// Redacts the SHA256 preimage for the given hash.
    pub fn redact_sha256_preimage(&mut self, hash: [u8; 32]) {
        self.redact(|input| {
            input.sha256_preimages.remove(&hash);
        });
    }

    /// Removes all SHA256 preimages.
    pub fn clear_sha256_preimages(&mut self) {
        self.redact(|input| {
            input.sha256_preimages.clear();
        });
    }

    /// Redacts the HASH160 preimage for the given hash.
    pub fn redact_hash160_preimage(&mut self, hash: [u8; 20]) {
        self.redact(|input| {
            input.hash160_preimages.remove(&hash);
        });
    }

    /// Removes all HASH160 preimages.
    pub fn clear_hash160_preimages(&mut self) {
        self.redact(|input| {
            input.hash160_preimages.clear();
        });
    }

    /// Redacts the HASH256 preimage for the given hash.
    pub fn redact_hash256_preimage(&mut self, hash: [u8; 32]) {
        self.redact(|input| {
            input.hash256_preimages.remove(&hash);
        });
    }

    /// Removes all HASH256 preimages.
    pub fn clear_hash256_preimages(&mut self) {
        self.redact(|input| {
            input.hash256_preimages.clear();
        });
    }

    /// Redacts the proprietary value at the given key.
    pub fn redact_proprietary(&mut self, key: &str) {
        self.redact(|input| {
            input.proprietary.remove(key);
        });
    }

    /// Removes all proprietary values.
    pub fn clear_proprietary(&mut self) {
        self.redact(|input| {
            input.proprietary.clear();
        });
    }
}

/// A Redactor for transparent outputs.
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

    /// Removes the `redeem_script`.
    pub fn clear_redeem_script(&mut self) {
        self.redact(|output| {
            output.redeem_script = None;
        });
    }

    /// Redacts the BIP 32 derivation path for the given pubkey.
    pub fn redact_bip32_derivation(&mut self, pubkey: [u8; 33]) {
        self.redact(|output| {
            output.bip32_derivation.remove(&pubkey);
        });
    }

    /// Removes all BIP 32 derivation paths.
    pub fn clear_bip32_derivation(&mut self) {
        self.redact(|output| {
            output.bip32_derivation.clear();
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
