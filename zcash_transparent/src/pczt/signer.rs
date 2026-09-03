use alloc::vec::Vec;

use zcash_script::solver;

use crate::{
    address::{Script, TransparentAddress},
    sighash::{SighashPolicy, SighashType, SignableInput},
};

use super::{Input, VerifyError};

impl Input {
    /// Helper to prepare a [`SignableInput`] for this input.
    ///
    /// This can be used to calculate the sighash for this input within its transaction,
    /// to produce a signature externally suitable for passing to [`Self::append_signature`].
    ///
    /// The `script_code` that the sighash commits to is checked against the coin being
    /// spent, and only [`SighashType::ALL`] is prepared for; use
    /// [`Input::with_signable_input_with_sighash_policy`] for a wider policy. Whoever
    /// signs the resulting sighash is authorizing whatever it commits to, so these are
    /// the same checks that [`Input::sign`] makes.
    pub fn with_signable_input<T, F>(&self, index: usize, f: F) -> Result<T, SignerError>
    where
        F: FnOnce(SignableInput) -> T,
    {
        self.with_signable_input_with_sighash_policy(index, f, SighashPolicy::ALL_ONLY)
    }

    /// Helper to prepare a [`SignableInput`] for this input, if the input’s sighash type
    /// is permitted by `sighash_policy`.
    ///
    /// Otherwise behaves exactly as [`Input::with_signable_input`], which should be
    /// preferred.
    pub fn with_signable_input_with_sighash_policy<T, F>(
        &self,
        index: usize,
        f: F,
        sighash_policy: SighashPolicy,
    ) -> Result<T, SignerError>
    where
        F: FnOnce(SignableInput) -> T,
    {
        self.check_sighash_policy(sighash_policy)?;
        self.verify_for_signing()?;

        // For P2PKH, `script_code` is always the same as `script_pubkey`.
        let script_code = self.redeem_script.as_ref().unwrap_or(&self.script_pubkey);

        Ok(f(SignableInput {
            hash_type: self.sighash_type,
            index,
            script_code: &Script::from(script_code),
            script_pubkey: &Script::from(&self.script_pubkey),
            value: self.value,
        }))
    }

    /// The sighash type reaches us from whoever gave us this PCZT, so it is our policy,
    /// not theirs, that decides whether to authorize such a signature.
    fn check_sighash_policy(&self, sighash_policy: SighashPolicy) -> Result<(), SignerError> {
        if sighash_policy.permits(self.sighash_type) {
            Ok(())
        } else {
            Err(SignerError::DisallowedSighashType(self.sighash_type))
        }
    }

    /// The `redeem_script` reaches us from whoever gave us this PCZT, and the signing
    /// paths both search it for a pubkey and commit to it in the sighash. Check that it
    /// really is the script that the coin being spent commits to.
    fn verify_for_signing(&self) -> Result<(), SignerError> {
        match self.verify() {
            // `Input::verify` only recognises P2PKH and P2SH `script_pubkey`s, whereas
            // signing additionally supports bare P2PK and P2MS scripts. Those have no
            // `redeem_script` to check.
            Err(VerifyError::UnsupportedScriptPubkey) if self.redeem_script.is_none() => Ok(()),
            r => r,
        }
        .map_err(SignerError::InvalidInput)
    }

    /// Signs the transparent spend with the given spend authorizing key.
    ///
    /// This checks the consistency of the input being signed (in particular, that any
    /// `redeem_script` really is the script committed to by `script_pubkey`), but it is
    /// the caller's responsibility to perform any semantic validity checks on the rest of
    /// the PCZT (for example, confirming that the change amounts are correct) before
    /// calling this method.
    ///
    /// Only [`SighashType::ALL`] is signed for; use
    /// [`Input::sign_with_sighash_policy`] to sign with a wider policy.
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
    ) -> Result<(), SignerError>
    where
        F: FnOnce(SignableInput) -> [u8; 32],
    {
        self.sign_with_sighash_policy(index, calculate_sighash, sk, secp, SighashPolicy::ALL_ONLY)
    }

    /// Signs the transparent spend with the given spend authorizing key, if the input’s
    /// sighash type is permitted by `sighash_policy`. See [`SighashPolicy`] for why that
    /// is a decision for the Signer rather than for whoever supplied the PCZT.
    ///
    /// Otherwise behaves exactly as [`Input::sign`], which should be preferred.
    pub fn sign_with_sighash_policy<C: secp256k1::Signing, F>(
        &mut self,
        index: usize,
        calculate_sighash: F,
        sk: &secp256k1::SecretKey,
        secp: &secp256k1::Secp256k1<C>,
        sighash_policy: SighashPolicy,
    ) -> Result<(), SignerError>
    where
        F: FnOnce(SignableInput) -> [u8; 32],
    {
        self.check_sighash_policy(sighash_policy)?;
        self.verify_for_signing()?;

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
    /// This checks the consistency of the input being signed (in particular, that any
    /// `redeem_script` really is the script committed to by `script_pubkey`), but it is
    /// the caller's responsibility to perform any semantic validity checks on the rest of
    /// the PCZT (for example, confirming that the change amounts are correct) before
    /// calling this method.
    ///
    /// Only signatures over [`SighashType::ALL`] are accepted; use
    /// [`Input::append_signature_with_sighash_policy`] to accept a wider policy.
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
        self.append_signature_with_sighash_policy(
            index,
            calculate_sighash,
            sig,
            secp,
            SighashPolicy::ALL_ONLY,
        )
    }

    /// Appends the given signature to the transparent spend, if the input’s sighash type
    /// is permitted by `sighash_policy`. See [`SighashPolicy`] for why that is a decision
    /// for the Signer rather than for whoever supplied the PCZT.
    ///
    /// Otherwise behaves exactly as [`Input::append_signature`], which should be
    /// preferred.
    pub fn append_signature_with_sighash_policy<C: secp256k1::Verification, F>(
        &mut self,
        index: usize,
        calculate_sighash: F,
        sig: secp256k1::ecdsa::Signature,
        secp: &secp256k1::Secp256k1<C>,
        sighash_policy: SighashPolicy,
    ) -> Result<(), SignerError>
    where
        F: FnOnce(SignableInput) -> [u8; 32],
    {
        self.check_sighash_policy(sighash_policy)?;
        self.verify_for_signing()?;

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
    /// The input's `sighash_type` is not permitted by the Signer's [`SighashPolicy`].
    DisallowedSighashType(SighashType),
    /// A provided external signature was not valid for any detected pubkey involved with
    /// spend control of the input's spent coin.
    InvalidExternalSignature,
    /// The input being signed is not internally consistent.
    InvalidInput(VerifyError),
    /// A required entry in one of the preimage maps is missing.
    MissingPreimage,
    /// A pubkey within the transparent input uses an unsupported format.
    UnsupportedPubkey,
    /// The provided `sk` does not match any pubkey involved with spend control of the
    /// input's spent coin.
    WrongSpendingKey,
}

#[cfg(test)]
mod tests {
    use super::{SighashPolicy, SighashType, SignerError, VerifyError};
    use crate::{
        pczt::{
            Input,
            testing::{input, p2ms, p2pk, p2pkh, p2sh},
        },
        util::hash160,
    };

    /// Every sighash type other than `SighashType::ALL`.
    const NON_ALL_TYPES: [SighashType; 5] = [
        SighashType::NONE,
        SighashType::SINGLE,
        SighashType::ALL_ANYONECANPAY,
        SighashType::NONE_ANYONECANPAY,
        SighashType::SINGLE_ANYONECANPAY,
    ];

    /// The stub sighash that both signing paths are given.
    const SIGHASH: [u8; 32] = [0; 32];

    fn secret_key(i: u8) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[i; 32]).expect("valid")
    }

    fn pubkey(sk: &secp256k1::SecretKey) -> [u8; 33] {
        sk.public_key(&secp256k1::Secp256k1::signing_only())
            .serialize()
    }

    fn sign(
        input: &mut Input,
        sk: &secp256k1::SecretKey,
        sighash_policy: SighashPolicy,
    ) -> Result<(), SignerError> {
        input.sign_with_sighash_policy(
            0,
            |_| SIGHASH,
            sk,
            &secp256k1::Secp256k1::signing_only(),
            sighash_policy,
        )
    }

    /// Appends an externally-produced signature over [`SIGHASH`] by `sk`.
    fn append(
        input: &mut Input,
        sk: &secp256k1::SecretKey,
        sighash_policy: SighashPolicy,
    ) -> Result<(), SignerError> {
        let secp = secp256k1::Secp256k1::new();
        let sig = secp.sign_ecdsa(&secp256k1::Message::from_digest(SIGHASH), sk);
        input.append_signature_with_sighash_policy(0, |_| SIGHASH, sig, &secp, sighash_policy)
    }

    /// A P2PKH input, with the `hash160` preimage that `Input::append_signature` needs in
    /// order to recover the pubkey from the script.
    fn p2pkh_input(sk: &secp256k1::SecretKey, sighash_type: SighashType) -> Input {
        let mut input = input(p2pkh(&pubkey(sk)), None, sighash_type);
        input
            .hash160_preimages
            .insert(hash160::hash(&pubkey(sk)), pubkey(sk).to_vec());
        input
    }

    #[test]
    fn sign_rejects_unmatched_redeem_script() {
        let sk = secret_key(1);
        // A `redeem_script` that the signer does control, but that the coin being spent
        // does not commit to. Without a check, this is both searched for the signer's
        // pubkey and committed to by the sighash.
        let redeem_script = p2ms(1, &[&pubkey(&sk)]);
        let other_script = p2ms(1, &[&pubkey(&secret_key(2))]);

        let mut input = input(p2sh(&other_script), Some(redeem_script), SighashType::ALL);

        assert!(matches!(
            sign(&mut input, &sk, SighashPolicy::ALL_ONLY),
            Err(SignerError::InvalidInput(VerifyError::WrongRedeemScript)),
        ));
        assert!(input.partial_signatures.is_empty());
    }

    #[test]
    fn sign_rejects_redeem_script_on_p2pkh() {
        let sk = secret_key(1);
        let mut input = input(
            p2pkh(&pubkey(&sk)),
            Some(p2ms(1, &[&pubkey(&sk)])),
            SighashType::ALL,
        );

        assert!(matches!(
            sign(&mut input, &sk, SighashPolicy::ALL_ONLY),
            Err(SignerError::InvalidInput(VerifyError::NotP2sh)),
        ));
        assert!(input.partial_signatures.is_empty());
    }

    #[test]
    fn sign_accepts_matching_redeem_script() {
        let sk = secret_key(1);
        let redeem_script = p2ms(1, &[&pubkey(&sk)]);
        let mut input = input(p2sh(&redeem_script), Some(redeem_script), SighashType::ALL);

        assert!(sign(&mut input, &sk, SighashPolicy::ALL_ONLY).is_ok());
        assert!(input.partial_signatures.contains_key(&pubkey(&sk)));
    }

    #[test]
    fn sign_accepts_p2pkh() {
        let sk = secret_key(1);
        let mut input = input(p2pkh(&pubkey(&sk)), None, SighashType::ALL);

        assert!(sign(&mut input, &sk, SighashPolicy::ALL_ONLY).is_ok());
        assert!(input.partial_signatures.contains_key(&pubkey(&sk)));
    }

    /// `Input::verify` does not recognise bare P2PK `script_pubkey`s, but `Input::sign`
    /// supports them.
    #[test]
    fn sign_accepts_bare_p2pk() {
        let sk = secret_key(1);
        let mut input = input(p2pk(&pubkey(&sk)), None, SighashType::ALL);

        assert!(sign(&mut input, &sk, SighashPolicy::ALL_ONLY).is_ok());
        assert!(input.partial_signatures.contains_key(&pubkey(&sk)));
    }

    /// `Input::verify` does not recognise bare P2MS `script_pubkey`s, but `Input::sign`
    /// supports them.
    #[test]
    fn sign_accepts_bare_p2ms() {
        let sk = secret_key(1);
        let mut input = input(
            p2ms(1, &[&pubkey(&sk), &pubkey(&secret_key(2))]),
            None,
            SighashType::ALL,
        );

        assert!(sign(&mut input, &sk, SighashPolicy::ALL_ONLY).is_ok());
        assert!(input.partial_signatures.contains_key(&pubkey(&sk)));
    }

    #[test]
    fn sign_rejects_non_all_sighash_types_by_default() {
        let sk = secret_key(1);
        for sighash_type in NON_ALL_TYPES {
            let mut input = input(p2pkh(&pubkey(&sk)), None, sighash_type);

            match sign(&mut input, &sk, SighashPolicy::ALL_ONLY) {
                Err(SignerError::DisallowedSighashType(t)) => assert_eq!(t, sighash_type),
                r => panic!("expected {sighash_type:?} to be refused, got {r:?}"),
            }
            assert!(input.partial_signatures.is_empty());
        }
    }

    #[test]
    fn sign_accepts_non_all_sighash_types_under_explicit_policy() {
        let sk = secret_key(1);
        for sighash_type in NON_ALL_TYPES {
            let mut input = input(p2pkh(&pubkey(&sk)), None, sighash_type);

            assert!(sign(&mut input, &sk, SighashPolicy::ANY).is_ok());
            assert!(input.partial_signatures.contains_key(&pubkey(&sk)));
        }
    }

    /// Preparing the sighash for an external signer hands out a commitment to the same
    /// unverified `script_code`; whoever signs it authorizes whatever it commits to.
    fn signable_input(
        input: &Input,
        sighash_policy: SighashPolicy,
    ) -> Result<SighashType, SignerError> {
        input.with_signable_input_with_sighash_policy(
            0,
            |signable_input| *signable_input.hash_type(),
            sighash_policy,
        )
    }

    #[test]
    fn signable_input_rejects_unmatched_redeem_script() {
        let sk = secret_key(1);
        let redeem_script = p2ms(1, &[&pubkey(&sk)]);
        let other_script = p2ms(1, &[&pubkey(&secret_key(2))]);

        let input = input(p2sh(&other_script), Some(redeem_script), SighashType::ALL);

        assert!(matches!(
            signable_input(&input, SighashPolicy::ALL_ONLY),
            Err(SignerError::InvalidInput(VerifyError::WrongRedeemScript)),
        ));
    }

    #[test]
    fn signable_input_rejects_non_all_sighash_types_by_default() {
        let sk = secret_key(1);
        for sighash_type in NON_ALL_TYPES {
            let input = input(p2pkh(&pubkey(&sk)), None, sighash_type);

            match signable_input(&input, SighashPolicy::ALL_ONLY) {
                Err(SignerError::DisallowedSighashType(t)) => assert_eq!(t, sighash_type),
                r => panic!("expected {sighash_type:?} to be refused, got {r:?}"),
            }
        }
    }

    #[test]
    fn signable_input_accepts_non_all_sighash_types_under_explicit_policy() {
        let sk = secret_key(1);
        for sighash_type in NON_ALL_TYPES {
            let input = input(p2pkh(&pubkey(&sk)), None, sighash_type);

            assert_eq!(
                signable_input(&input, SighashPolicy::ANY).ok(),
                Some(sighash_type),
            );
        }
    }

    /// The external-signature path derives its `script_code` from the same unverified
    /// `redeem_script`, and uses it both to enumerate candidate pubkeys and as the script
    /// the signature commits to.
    #[test]
    fn append_rejects_unmatched_redeem_script() {
        let sk = secret_key(1);
        let redeem_script = p2ms(1, &[&pubkey(&sk)]);
        let other_script = p2ms(1, &[&pubkey(&secret_key(2))]);

        let mut input = input(p2sh(&other_script), Some(redeem_script), SighashType::ALL);

        assert!(matches!(
            append(&mut input, &sk, SighashPolicy::ALL_ONLY),
            Err(SignerError::InvalidInput(VerifyError::WrongRedeemScript)),
        ));
        assert!(input.partial_signatures.is_empty());
    }

    #[test]
    fn append_accepts_matching_redeem_script() {
        let sk = secret_key(1);
        let redeem_script = p2ms(1, &[&pubkey(&sk)]);
        let mut input = input(p2sh(&redeem_script), Some(redeem_script), SighashType::ALL);

        assert!(append(&mut input, &sk, SighashPolicy::ALL_ONLY).is_ok());
        assert!(input.partial_signatures.contains_key(&pubkey(&sk)));
    }

    #[test]
    fn append_rejects_non_all_sighash_types_by_default() {
        let sk = secret_key(1);
        for sighash_type in NON_ALL_TYPES {
            let mut input = p2pkh_input(&sk, sighash_type);

            match append(&mut input, &sk, SighashPolicy::ALL_ONLY) {
                Err(SignerError::DisallowedSighashType(t)) => assert_eq!(t, sighash_type),
                r => panic!("expected {sighash_type:?} to be refused, got {r:?}"),
            }
            assert!(input.partial_signatures.is_empty());
        }
    }

    #[test]
    fn append_accepts_non_all_sighash_types_under_explicit_policy() {
        let sk = secret_key(1);
        for sighash_type in NON_ALL_TYPES {
            let mut input = p2pkh_input(&sk, sighash_type);

            assert!(append(&mut input, &sk, SighashPolicy::ANY).is_ok());
            assert!(input.partial_signatures.contains_key(&pubkey(&sk)));
        }
    }
}
