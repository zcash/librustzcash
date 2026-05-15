use zcash_script::{pattern::push_script, pv, script, solver};

use crate::address::TransparentAddress;

impl super::Bundle {
    /// Finalizes the spends for this bundle.
    ///
    /// Returns an error if any spend uses an unsupported script format. The supported
    /// script formats are:
    /// - P2PKH
    /// - P2SH with one of these redeem script formats:
    ///   - P2MS
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
                            if hash[..] != crate::util::hash160::hash(pubkey)[..] {
                                Err(SpendFinalizerError::UnexpectedSignatures)
                            } else {
                                // P2PKH scriptSig
                                input.script_sig = Some(script::Component(vec![
                                    pv::push_value(sig_bytes)
                                        .ok_or(SpendFinalizerError::InvalidSignature)?,
                                    pv::push_value(pubkey)
                                        .ok_or(SpendFinalizerError::InvalidSignature)?,
                                ]));
                                Ok(())
                            }
                        })
                    }
                    TransparentAddress::ScriptHash(_) => {
                        let redeem_script = input
                            .redeem_script
                            .as_ref()
                            .ok_or(SpendFinalizerError::MissingRedeemScript)?
                            .refine()
                            .map_err(|_| SpendFinalizerError::UnsupportedRedeemScript)?;

                        match solver::standard(&redeem_script) {
                            Some(solver::ScriptKind::MultiSig { required, pubkeys }) => {
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
                                        // Valid signatures always fit into `PushData`s.
                                        script_sig.push(
                                            pv::push_value(sig)
                                                .ok_or(SpendFinalizerError::InvalidSignature)?,
                                        );
                                        signatures_found += 1;
                                    }
                                }
                                if signatures_found < required {
                                    return Err(SpendFinalizerError::MissingSignature);
                                }

                                // - PushData(redeem_script)
                                script_sig.push(
                                    push_script(&redeem_script)
                                        .ok_or(SpendFinalizerError::RedeemScriptTooLong)?,
                                );

                                // P2SH scriptSig
                                input.script_sig = Some(script::Component(script_sig));

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
    /// `script_pubkey` is a P2SH script, but `redeem_script` is too long for a `PushData`.
    RedeemScriptTooLong,
    /// `partial_signatures` contained too few signatures.
    MissingSignature,
    /// `partial_signatures` contained an invalid signature.
    InvalidSignature,
    /// `redeem_script` contained an uncompressed pubkey, which PCZT does not support.
    UncompressedPubkeyInScript,
    /// `partial_signatures` contained unexpected signatures.
    UnexpectedSignatures,
    /// The `script_pubkey` kind is unsupported.
    UnsupportedScriptPubkey,
    /// The `redeem_script` kind is unsupported.
    UnsupportedRedeemScript,
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::vec;

    use zcash_script::{
        pattern::pay_to_pubkey_hash,
        script::{self, Evaluable},
    };

    use super::SpendFinalizerError;
    use crate::{
        pczt::{Bundle, Input, parse::MAX_SCRIPT_PUSH_VALUE_LEN},
        sighash::SIGHASH_ALL,
    };

    /// The P2PKH branch of `Bundle::finalize_spends` returns
    /// `Err(SpendFinalizerError::InvalidSignature)` for a `partial_signatures`
    /// entry too large to fit in a single script push, rather than panicking.
    ///
    /// `Input::parse` rejects such entries, so the test constructs a valid input
    /// and then replaces its `partial_signatures` directly.
    #[test]
    fn p2pkh_finalize_spends_rejects_oversize_signature() {
        // Any 33-byte value works as the key: the P2PKH branch only checks that
        // hash160(pubkey) matches the script_pubkey hash, and both sides of that
        // comparison are derived from this value.
        let pubkey = [0x02u8; 33];
        let script_pubkey_bytes = script::Component(pay_to_pubkey_hash(&pubkey)).to_bytes();

        let mut input = Input::parse(
            [0u8; 32],           // prevout_txid
            0,                   // prevout_index
            None,                // sequence
            None,                // required_time_lock_time
            None,                // required_height_lock_time
            None,                // script_sig
            1_000,               // value
            script_pubkey_bytes, // script_pubkey
            None,                // redeem_script
            BTreeMap::new(),     // partial_signatures
            SIGHASH_ALL,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("input parse should succeed");

        // One byte over the largest value a single script push can carry.
        input
            .partial_signatures
            .insert(pubkey, vec![0x42u8; MAX_SCRIPT_PUSH_VALUE_LEN + 1]);

        let mut bundle = Bundle {
            inputs: vec![input],
            outputs: vec![],
        };

        let result = bundle.finalize_spends();
        assert!(
            matches!(result, Err(SpendFinalizerError::InvalidSignature)),
            "expected Err(InvalidSignature), got {result:?}",
        );
    }
}
