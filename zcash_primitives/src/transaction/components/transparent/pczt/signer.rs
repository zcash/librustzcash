use blake2b_simd::Hash as Blake2bHash;

use crate::transaction::{
    sighash::{SignableInput, TransparentAuthorizingContext},
    sighash_v5::v5_signature_hash,
    Authorization, TransactionData, TxDigests,
};

impl super::Input {
    /// Signs the transparent spend with the given spend authorizing key.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn sign<
        TA: TransparentAuthorizingContext,
        A: Authorization<TransparentAuth = TA>,
        C: secp256k1::Signing,
    >(
        &mut self,
        index: usize,
        mtx: &TransactionData<A>,
        txid_parts: &TxDigests<Blake2bHash>,
        sk: &secp256k1::SecretKey,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<(), SignerError> {
        let hash_type = self.sighash_type.encode();
        let pubkey = sk.public_key(secp).serialize();

        // Check that the corresponding pubkey appears in either `script_pubkey` or
        // `redeem_script`.
        // TODO

        let sighash = v5_signature_hash(
            mtx,
            &SignableInput::Transparent {
                hash_type,
                index,
                script_code: self.redeem_script.as_ref().unwrap_or(&self.script_pubkey), // for p2pkh, always the same as script_pubkey
                script_pubkey: &self.script_pubkey,
                value: self.value,
            },
            txid_parts,
        );

        let msg = secp256k1::Message::from_slice(sighash.as_ref()).expect("32 bytes");
        let sig = secp.sign_ecdsa(&msg, sk);

        // Signature has to have the SighashType appended to it.
        let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
        sig_bytes.extend([hash_type]);

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
