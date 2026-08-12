use alloc::vec::Vec;

use zcash_script::solver;

use crate::{
    address::{Script, TransparentAddress},
    sighash::{SighashPolicy, SighashType, SignableInput},
};

use super::VerifyError;

impl super::Input {
    /// Signs the transparent spend with the given spend authorizing key.
    ///
    /// This checks the consistency of the input being signed (in particular, that any
    /// `redeem_script` really is the script committed to by `script_pubkey`), but it is
    /// the caller’s responsibility to perform any semantic validity checks on the rest of
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
        // TODO: Enforced in a subsequent commit.
        let _ = sighash_policy;

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
}

/// Errors that can occur while signing a transparent input in a PCZT.
#[derive(Debug)]
pub enum SignerError {
    /// The input's `sighash_type` is not permitted by the Signer's [`SighashPolicy`].
    DisallowedSighashType(SighashType),
    /// The input being signed is not internally consistent.
    InvalidInput(VerifyError),
    /// The provided `sk` does not match any pubkey involved with spend control of the
    /// input's spent coin.
    WrongSpendingKey,
}

#[cfg(test)]
mod tests {
    use super::{SighashPolicy, SighashType, SignerError, VerifyError};
    use crate::pczt::{
        testing::{input, p2ms, p2pk, p2pkh, p2sh},
        Input,
    };

    /// Every sighash type other than `SighashType::ALL`.
    const NON_ALL_TYPES: [SighashType; 5] = [
        SighashType::NONE,
        SighashType::SINGLE,
        SighashType::ALL_ANYONECANPAY,
        SighashType::NONE_ANYONECANPAY,
        SighashType::SINGLE_ANYONECANPAY,
    ];

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
            |_| [0; 32],
            sk,
            &secp256k1::Secp256k1::signing_only(),
            sighash_policy,
        )
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
}
