use zcash_script::{pattern::push_script, pv, script, solver};

use crate::{
    address::TransparentAddress,
    sighash::{SighashPolicy, SighashType},
};

use super::Bundle;

impl Bundle {
    /// Finalizes the spends for this bundle.
    ///
    /// Every partial signature that is used commits to the transaction in full: a
    /// signature whose sighash type is not [`SighashType::ALL`] is refused, as is one
    /// whose sighash type does not match that of the input it is being applied to. Use
    /// [`Bundle::finalize_spends_with_sighash_policy`] to finalize with a wider policy.
    ///
    /// Returns an error if any spend uses an unsupported script format. The supported
    /// script formats are:
    /// - P2PKH
    /// - P2SH with one of these redeem script formats:
    ///   - P2MS
    pub fn finalize_spends(&mut self) -> Result<(), SpendFinalizerError> {
        self.finalize_spends_with_sighash_policy(SighashPolicy::ALL_ONLY)
    }

    /// Finalizes the spends for this bundle, accepting any partial signature whose
    /// sighash type is permitted by `sighash_policy`. See [`SighashPolicy`] for why that
    /// is a decision for the Spend Finalizer rather than for whoever supplied the
    /// signature.
    ///
    /// Otherwise behaves exactly as [`Bundle::finalize_spends`], which should be
    /// preferred.
    ///
    /// This policy governs which signatures are assembled into `script_sig`s; it does not
    /// protect whoever produced them. A partial signature that does not commit to the
    /// whole transaction can be lifted out of this bundle and used directly, without this
    /// role ever running, so the decision that protects a signer is the Signer's own
    /// [`Input::sign_with_sighash_policy`].
    ///
    /// [`Input::sign_with_sighash_policy`]: super::Input::sign_with_sighash_policy
    pub fn finalize_spends_with_sighash_policy(
        &mut self,
        sighash_policy: SighashPolicy,
    ) -> Result<(), SpendFinalizerError> {
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
                                check_sighash_type(sig_bytes, input.sighash_type, sighash_policy)?;

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
                                        check_sighash_type(
                                            sig,
                                            input.sighash_type,
                                            sighash_policy,
                                        )?;

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

/// Checks the trailing sighash-type byte of a partial signature that is about to be
/// placed into a `script_sig`.
fn check_sighash_type(
    sig_bytes: &[u8],
    expected: SighashType,
    sighash_policy: SighashPolicy,
) -> Result<(), SpendFinalizerError> {
    let (hash_type, _) = sig_bytes
        .split_last()
        .ok_or(SpendFinalizerError::InvalidSignature)?;
    let hash_type = SighashType::parse(*hash_type).ok_or(SpendFinalizerError::InvalidSignature)?;

    // The PCZT format requires a Spend Finalizer to fail to finalize an input whose
    // signatures do not match its `sighash_type`.
    if hash_type != expected {
        return Err(SpendFinalizerError::MismatchedSighashType);
    }

    if !sighash_policy.permits(hash_type) {
        return Err(SpendFinalizerError::DisallowedSighashType(hash_type));
    }

    Ok(())
}

/// Errors that can occur while finalizing the transparent inputs of a PCZT bundle.
#[derive(Debug)]
pub enum SpendFinalizerError {
    /// A partial signature's sighash type is not permitted by the Spend Finalizer's
    /// [`SighashPolicy`].
    DisallowedSighashType(SighashType),
    /// A partial signature's sighash type does not match that of the input it applies to.
    MismatchedSighashType,
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
    use alloc::vec::Vec;

    use zcash_script::{
        pattern::pay_to_pubkey_hash,
        script::{self, Evaluable},
    };

    use super::{SighashPolicy, SighashType, SpendFinalizerError};
    use crate::{
        pczt::{
            Bundle, Input,
            parse::MAX_SCRIPT_PUSH_VALUE_LEN,
            testing::{input, p2ms, p2pkh, p2sh},
        },
        sighash::{SIGHASH_ALL, SIGHASH_NONE},
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

    /// A pubkey-shaped byte string. The Spend Finalizer never checks that a pubkey is a
    /// point on the curve, so these do not need to be real.
    fn pubkey(i: u8) -> [u8; 33] {
        let mut pubkey = [i; 33];
        pubkey[0] = 0x02;
        pubkey
    }

    /// A signature-shaped byte string ending in `hash_type`. The Spend Finalizer never
    /// verifies a signature, so this does not need to be a real one.
    fn signature(hash_type: u8) -> Vec<u8> {
        vec![0xde, 0xad, 0xbe, 0xef, hash_type]
    }

    /// A P2PKH input signed by `pubkey(1)`.
    fn p2pkh_input(sighash_type: SighashType, signature: Vec<u8>) -> Input {
        let mut input = input(p2pkh(&pubkey(1)), None, sighash_type);
        input.partial_signatures.insert(pubkey(1), signature);
        input
    }

    /// A 2-of-3 P2SH-P2MS input, signed by the pubkeys named by the given indices.
    fn p2ms_input(sighash_type: SighashType, signatures: &[(u8, u8)]) -> Input {
        let pubkeys = [pubkey(1), pubkey(2), pubkey(3)];
        let redeem_script = p2ms(2, &[&pubkeys[0], &pubkeys[1], &pubkeys[2]]);
        let mut input = input(p2sh(&redeem_script), Some(redeem_script), sighash_type);
        for (i, hash_type) in signatures {
            input
                .partial_signatures
                .insert(pubkey(*i), signature(*hash_type));
        }
        input
    }

    fn finalize(input: Input, sighash_policy: SighashPolicy) -> Result<(), SpendFinalizerError> {
        Bundle {
            inputs: vec![input],
            outputs: vec![],
        }
        .finalize_spends_with_sighash_policy(sighash_policy)
    }

    #[test]
    fn finalize_accepts_p2pkh() {
        let input = p2pkh_input(SighashType::ALL, signature(SIGHASH_ALL));
        assert!(finalize(input, SighashPolicy::ALL_ONLY).is_ok());
    }

    #[test]
    fn finalize_accepts_multisig() {
        let input = p2ms_input(SighashType::ALL, &[(1, SIGHASH_ALL), (2, SIGHASH_ALL)]);
        assert!(finalize(input, SighashPolicy::ALL_ONLY).is_ok());
    }

    /// The PCZT format requires a Spend Finalizer to reject a signature that does not
    /// match the sighash type of the input it applies to.
    #[test]
    fn finalize_rejects_mismatched_sighash_type() {
        let input = p2pkh_input(SighashType::ALL, signature(SIGHASH_NONE));
        assert!(matches!(
            finalize(input, SighashPolicy::ALL_ONLY),
            Err(SpendFinalizerError::MismatchedSighashType),
        ));
    }

    #[test]
    fn finalize_rejects_mismatched_sighash_type_in_multisig() {
        let input = p2ms_input(SighashType::ALL, &[(1, SIGHASH_ALL), (2, SIGHASH_NONE)]);
        assert!(matches!(
            finalize(input, SighashPolicy::ALL_ONLY),
            Err(SpendFinalizerError::MismatchedSighashType),
        ));
    }

    #[test]
    fn finalize_rejects_non_all_sighash_type_by_default() {
        let input = p2pkh_input(SighashType::NONE, signature(SIGHASH_NONE));
        match finalize(input, SighashPolicy::ALL_ONLY) {
            Err(SpendFinalizerError::DisallowedSighashType(t)) => {
                assert_eq!(t, SighashType::NONE)
            }
            r => panic!("expected SIGHASH_NONE to be refused, got {r:?}"),
        }
    }

    #[test]
    fn finalize_accepts_non_all_sighash_type_under_explicit_policy() {
        let input = p2pkh_input(SighashType::NONE, signature(SIGHASH_NONE));
        assert!(finalize(input, SighashPolicy::ANY).is_ok());
    }

    #[test]
    fn finalize_rejects_empty_signature() {
        let input = p2pkh_input(SighashType::ALL, vec![]);
        assert!(matches!(
            finalize(input, SighashPolicy::ALL_ONLY),
            Err(SpendFinalizerError::InvalidSignature),
        ));
    }

    #[test]
    fn finalize_rejects_unparsable_sighash_type() {
        let input = p2pkh_input(SighashType::ALL, signature(0x05));
        assert!(matches!(
            finalize(input, SighashPolicy::ALL_ONLY),
            Err(SpendFinalizerError::InvalidSignature),
        ));
    }

    /// A signature that is discarded rather than placed into the `script_sig` is not
    /// checked, so that a Combiner cannot block finalization by contributing junk.
    #[test]
    fn finalize_ignores_discarded_multisig_signature() {
        let input = p2ms_input(
            SighashType::ALL,
            &[(1, SIGHASH_ALL), (2, SIGHASH_ALL), (3, 0x05)],
        );
        assert!(finalize(input, SighashPolicy::ALL_ONLY).is_ok());
    }
}
