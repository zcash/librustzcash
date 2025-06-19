use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use zcash_script::{
    pattern::{push_script, push_vec},
    pv, script, standard,
};

use crate::address::TransparentAddress;

impl super::Bundle {
    /// Finalizes the spends for this bundle.
    pub fn finalize_spends(&mut self) -> Result<(), SpendFinalizerError> {
        // For each input, the Spend Finalizer determines if the input has enough data to
        // pass validation. If it does, it must construct the `script_sig` and place it
        // into the PCZT input. If `script_sig` is empty for an input, the field should
        // remain unset rather than assigned an empty array.
        for input in &mut self.inputs {
            TransparentAddress::from_script_pubkey(&input.script_pubkey)
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
                                input.script_sig = Some(script::Sig::new(vec![
                                    push_vec(sig_bytes),
                                    push_vec(pubkey),
                                ]));
                                Ok(())
                            }
                        })
                    }
                    TransparentAddress::ScriptHash(_) => {
                        let redeem_script = input
                            .redeem_script
                            .as_ref()
                            .ok_or(SpendFinalizerError::MissingRedeemScript)?;

                        match standard::solver(redeem_script) {
                            Some(standard::ScriptKind::MultiSig { required, pubkeys }) => {
                                // P2MS-in-P2SH `script_sig` format is:
                                // - Dummy OP_0 to bypass OP_CHECKMULTISIG bug.
                                let mut script_sig = vec![pv::_0];

                                // - PushData(signature) * required
                                //
                                // The OP_CHECKMULTISIG logic matches pubkeys and
                                // signatures together sequentially, so we look for
                                // signatures in the order that the pubkeys exist in
                                // `redeem_script`.
                                let mut signatures_found = 0;
                                for pubkey in pubkeys {
                                    // Once we reach the threshold of required signatures,
                                    // any additional signatures present in the PCZT are
                                    // discarded.
                                    if signatures_found == required {
                                        break;
                                    }

                                    // PCZT requires compressed pubkeys.
                                    let pubkey =
                                        <[u8; 33]>::try_from(pubkey.as_slice()).map_err(|_| {
                                            SpendFinalizerError::UncompressedPubkeyInScript
                                        })?;

                                    // If we have a signature from this pubkey, use it.
                                    if let Some(sig) = input.partial_signatures.get(&pubkey) {
                                        script_sig.push(push_vec(sig));
                                        signatures_found += 1;
                                    }
                                }
                                if signatures_found < required {
                                    return Err(SpendFinalizerError::MissingSignature);
                                }

                                // - PushData(redeem_script)
                                script_sig.push(push_script(&redeem_script));

                                // P2SH scriptSig
                                input.script_sig = Some(script::Sig::new(script_sig));

                                Ok(())
                            }
                            _ => Err(SpendFinalizerError::UnsupportedScriptPubkey),
                        }
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
    /// `script_pubkey` is a P2SH script, but `redeem_script` is not set.
    MissingRedeemScript,
    /// `partial_signatures` contained too few signatures.
    MissingSignature,
    /// `redeem_script` contained an uncompressed pubkey, which PCZT does not support.
    UncompressedPubkeyInScript,
    /// `partial_signatures` contained unexpected signatures.
    UnexpectedSignatures,
    /// The `script_pubkey` kind is unsupported.
    UnsupportedScriptPubkey,
}
