use alloc::vec::Vec;

use zcash_protocol::value::Zatoshis;
use zcash_script::solver;

use crate::{
    address::{Script, TransparentAddress},
    sighash::SignableInput,
};

impl super::Input {
    /// Helper to prepare a [`SignableInput`] for this input.
    ///
    /// This can be used to calculate the sighash for this input within its transaction,
    /// to produce a signature externally suitable for passing to [`Self::append_signature`].
    pub fn with_signable_input<T, F>(&self, index: usize, f: F) -> T
    where
        F: FnOnce(SignableInput) -> T,
    {
        // For P2PKH, `script_code` is always the same as `script_pubkey`.
        let script_code = self.redeem_script.as_ref().unwrap_or(&self.script_pubkey);

        f(SignableInput {
            hash_type: self.sighash_type,
            index,
            script_code: &Script::from(script_code),
            script_pubkey: &Script::from(&self.script_pubkey),
            value: self.value,
        })
    }

    /// Signs the transparent spend with the given spend authorizing key.
    ///
    /// The `expected_amount` must be derived from a context trusted by the signer.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    ///
    /// Returns an error if the spend authorizing key does not match any pubkey involved
    /// with spend control of the input's spent coin. The supported script formats are:
    /// - P2PKH
    /// - P2MS
    /// - P2PK
    pub fn sign<C: secp256k1::Signing, F>(
        &mut self,
        index: usize,
        calculate_sighash: F,
        sk: &secp256k1::SecretKey,
        secp: &secp256k1::Secp256k1<C>,
        expected_amount: Zatoshis,
    ) -> Result<(), SignerError>
    where
        F: FnOnce(SignableInput) -> [u8; 32],
    {
        // ZIP-244 binds the input amount into the sighash. If the updater-provided
        // `self.value` differs from what the caller believes the amount to be, the
        // signature will be rejected at consensus. Convert that documented
        // caller-responsibility into a compiler-enforced precondition.
        if self.value != expected_amount {
            return Err(SignerError::ValueMismatch {
                expected: expected_amount,
                updater_provided: self.value,
            });
        }

        let pubkey = sk.public_key(secp).serialize();
        let p2pkh_addr = TransparentAddress::from_pubkey_bytes(&pubkey);

        // For P2PKH, `script_code` is always the same as `script_pubkey`.
        let script_code = self.redeem_script.as_ref().unwrap_or(&self.script_pubkey);

        // Check that the corresponding pubkey appears in either `script_pubkey` or
        // `redeem_script`.
        match script_code
            .refine()
            .ok()
            .as_ref()
            .and_then(solver::standard)
        {
            Some(solver::ScriptKind::PubKeyHash { hash })
                if TransparentAddress::PublicKeyHash(hash) == p2pkh_addr =>
            {
                Ok(())
            }
            Some(solver::ScriptKind::MultiSig { pubkeys, .. })
                if pubkeys
                    .iter()
                    .any(|data| data.as_slice() == pubkey.as_slice()) =>
            {
                Ok(())
            }
            Some(solver::ScriptKind::PubKey { data }) if data.as_slice() == pubkey.as_slice() => {
                Ok(())
            }
            // This spending key isn't involved with the input in any way we can detect.
            _ => Err(SignerError::WrongSpendingKey),
        }?;

        let sighash = calculate_sighash(SignableInput {
            hash_type: self.sighash_type,
            index,
            script_code: &Script::from(script_code),
            script_pubkey: &Script::from(&self.script_pubkey),
            value: self.value,
        });

        let msg = secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_ecdsa(&msg, sk);

        // Signature has to have the SighashType appended to it.
        let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
        sig_bytes.extend([self.sighash_type.encode()]);

        self.partial_signatures.insert(pubkey, sig_bytes);

        Ok(())
    }

    /// Appends the given signature to the transparent spend.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    ///
    /// Returns an error if the signature does not match any pubkey involved with spend
    /// control of the input's spent coin. The supported script formats are:
    /// - P2PKH
    ///   - The [`Input::hash160_preimages`] field must contan a mapping from the `pubkeyhash` to
    ///     the pubkey.
    /// - P2MS
    /// - P2PK
    ///
    /// [`Input::hash160_preimages`]: super::Input::hash160_preimages
    pub fn append_signature<C: secp256k1::Verification, F>(
        &mut self,
        index: usize,
        calculate_sighash: F,
        sig: secp256k1::ecdsa::Signature,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<(), SignerError>
    where
        F: FnOnce(SignableInput) -> [u8; 32],
    {
        // For P2PKH, `script_code` is always the same as `script_pubkey`.
        let script_code = self.redeem_script.as_ref().unwrap_or(&self.script_pubkey);
        let script_kind = script_code
            .refine()
            .ok()
            .as_ref()
            .and_then(solver::standard);

        fn to_pubkey(data: &[u8]) -> Result<[u8; 33], SignerError> {
            data.try_into().map_err(|_| SignerError::UnsupportedPubkey)
        }

        // Extract all candidate pubkeys.
        let pubkeys = match script_kind {
            Some(solver::ScriptKind::PubKeyHash { hash }) => {
                let data = self
                    .hash160_preimages()
                    .get(&hash)
                    .ok_or(SignerError::MissingPreimage)?;
                to_pubkey(data).map(|pubkey| vec![pubkey])
            }
            Some(solver::ScriptKind::MultiSig { pubkeys, .. }) => pubkeys
                .iter()
                .map(|data| to_pubkey(data.as_slice()))
                .collect::<Result<Vec<_>, _>>(),
            Some(solver::ScriptKind::PubKey { data }) => {
                to_pubkey(data.as_slice()).map(|pubkey| vec![pubkey])
            }
            // This spending key isn't involved with the input in any way we can detect.
            _ => Err(SignerError::WrongSpendingKey),
        }?;

        let sighash = calculate_sighash(SignableInput {
            hash_type: self.sighash_type,
            index,
            script_code: &Script::from(script_code),
            script_pubkey: &Script::from(&self.script_pubkey),
            value: self.value,
        });
        let msg = secp256k1::Message::from_digest(sighash);

        // Find the pubkey that the signature validates with.
        for pubkey in pubkeys {
            let pk = secp256k1::PublicKey::from_slice(&pubkey)
                .map_err(|_| SignerError::UnsupportedPubkey)?;

            if secp.verify_ecdsa(&msg, &sig, &pk).is_ok() {
                // Signature has to have the SighashType appended to it.
                let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
                sig_bytes.extend([self.sighash_type.encode()]);

                self.partial_signatures.insert(pubkey, sig_bytes);

                return Ok(());
            }
        }

        Err(SignerError::InvalidExternalSignature)
    }
}

/// Errors that can occur while signing a transparent input in a PCZT.
#[derive(Debug)]
pub enum SignerError {
    /// A provided external signature was not valid for any detected pubkey involved with
    /// spend control of the input's spent coin.
    InvalidExternalSignature,
    /// A required entry in one of the preimage maps is missing.
    MissingPreimage,
    /// A pubkey within the transparent input uses an unsupported format.
    UnsupportedPubkey,
    /// The provided `sk` does not match any pubkey involved with spend control of the
    /// input's spent coin.
    WrongSpendingKey,
    /// The updater-provided `Input::value` does not match the caller-supplied
    /// `expected_amount`. ZIP-244 binds the amount into the sighash, so signing
    /// with a mismatched value would produce a signature rejected at consensus.
    /// The caller is expected to derive `expected_amount` from already-trusted
    /// context (the spend record being signed) before invoking the signer.
    ValueMismatch {
        expected: Zatoshis,
        updater_provided: Zatoshis,
    },
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use zcash_protocol::{value::Zatoshis, TxId};
    use zcash_script::script;

    use super::SignerError;
    use crate::{pczt::Input, sighash::SighashType};

    fn input_with_value(value: Zatoshis) -> Input {
        Input {
            prevout_txid: TxId::from_bytes([0; 32]),
            prevout_index: 0,
            sequence: None,
            required_time_lock_time: None,
            required_height_lock_time: None,
            script_sig: None,
            value,
            script_pubkey: script::FromChain::parse(&script::Code(vec![])).unwrap(),
            redeem_script: None,
            partial_signatures: BTreeMap::new(),
            sighash_type: SighashType::ALL,
            bip32_derivation: BTreeMap::new(),
            ripemd160_preimages: BTreeMap::new(),
            sha256_preimages: BTreeMap::new(),
            hash160_preimages: BTreeMap::new(),
            hash256_preimages: BTreeMap::new(),
            proprietary: BTreeMap::new(),
        }
    }

    #[test]
    fn sign_rejects_value_mismatch() {
        let updater_provided = Zatoshis::from_u64(1000).unwrap();
        let expected = Zatoshis::from_u64(2000).unwrap();
        let mut input = input_with_value(updater_provided);

        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();

        let err = input
            .sign(
                0,
                |_| panic!("value mismatch must fail before sighash calculation"),
                &sk,
                &secp,
                expected,
            )
            .unwrap_err();

        match err {
            SignerError::ValueMismatch {
                expected: err_expected,
                updater_provided: err_updater_provided,
            } => {
                assert_eq!(err_expected, expected);
                assert_eq!(err_updater_provided, updater_provided);
            }
            err => panic!("unexpected signer error: {err:?}"),
        }
    }
}
