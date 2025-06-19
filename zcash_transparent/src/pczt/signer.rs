use alloc::vec::Vec;

use zcash_script::solver;

use crate::{
    address::{Script, TransparentAddress},
    sighash::SignableInput,
};

impl super::Input {
    /// Signs the transparent spend with the given spend authorizing key.
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
    ) -> Result<(), SignerError>
    where
        F: FnOnce(SignableInput) -> [u8; 32],
    {
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
    /// The provided `sk` does not match any pubkey involved with spend control of the
    /// input's spent coin.
    WrongSpendingKey,
}
