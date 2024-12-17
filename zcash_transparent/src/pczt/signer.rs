use crate::sighash::SignableInput;
use alloc::vec::Vec;

impl super::Input {
    /// Signs the transparent spend with the given spend authorizing key.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
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

        // Check that the corresponding pubkey appears in either `script_pubkey` or
        // `redeem_script`.
        // TODO

        let sighash = calculate_sighash(SignableInput {
            hash_type: self.sighash_type,
            index,
            // for p2pkh, always the same as script_pubkey
            script_code: self.redeem_script.as_ref().unwrap_or(&self.script_pubkey),
            script_pubkey: &self.script_pubkey,
            value: self.value,
        });

        let msg = secp256k1::Message::from_digest_slice(&sighash).expect("32 bytes");
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
