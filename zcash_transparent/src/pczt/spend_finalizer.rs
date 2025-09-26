use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use zcash_script::{pv::push_value, script};

use crate::address::TransparentAddress;

impl super::Bundle {
    /// Finalizes the spends for this bundle.
    pub fn finalize_spends(&mut self) -> Result<(), SpendFinalizerError> {
        // For each input, the Spend Finalizer determines if the input has enough data to
        // pass validation. If it does, it must construct the `script_sig` and place it
        // into the PCZT input. If `script_sig` is empty for an input, the field should
        // remain unset rather than assigned an empty array.
        for input in &mut self.inputs {
            TransparentAddress::from_script_from_chain(&input.script_pubkey)
                .ok_or(SpendFinalizerError::UnsupportedScriptPubkey)
                .and_then(|address| match address {
                    TransparentAddress::PublicKeyHash(hash) => {
                        let mut iter = input.partial_signatures.iter();
                        match (iter.next(), iter.next()) {
                            (Some(entry), None) => Ok(entry),
                            (None, _) => Err(SpendFinalizerError::MissingSignature),
                            (Some(_), Some(_)) => Err(SpendFinalizerError::UnexpectedSignatures),
                        }
                        .and_then(|(pubkey, sig_bytes)| {
                            // Check that the signature is for this input.
                            if hash[..] != Ripemd160::digest(Sha256::digest(pubkey))[..] {
                                Err(SpendFinalizerError::UnexpectedSignatures)
                            } else {
                                // P2PKH scriptSig
                                input.script_sig = Some(script::Component(vec![
                                    push_value(sig_bytes).expect("short enough"),
                                    push_value(pubkey).expect("short enough"),
                                ]));
                                Ok(())
                            }
                        })
                    }
                    TransparentAddress::ScriptHash(_) => {
                        Err(SpendFinalizerError::UnsupportedScriptPubkey)
                    }
                })?
        }

        // All other data except the UTXO and proprietary fields in the input should be
        // cleared from the PSBT. The UTXO should be kept to allow Transaction Extractors
        // to verify the final network serialized transaction.
        for input in &mut self.inputs {
            input.required_time_lock_time = None;
            input.required_height_lock_time = None;
            input.redeem_script = None;
            input.partial_signatures.clear();
            input.bip32_derivation.clear();
            input.ripemd160_preimages.clear();
            input.sha256_preimages.clear();
            input.hash160_preimages.clear();
            input.hash256_preimages.clear();
        }

        Ok(())
    }
}

/// Errors that can occur while finalizing the transparent inputs of a PCZT bundle.
#[derive(Debug)]
pub enum SpendFinalizerError {
    /// `partial_signatures` contained no signatures.
    MissingSignature,
    /// `partial_signatures` contained unexpected signatures.
    UnexpectedSignatures,
    /// The `script_pubkey` kind is unsupported.
    UnsupportedScriptPubkey,
}
