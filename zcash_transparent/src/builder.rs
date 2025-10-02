//! Types and functions for building transparent transaction components.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use zcash_protocol::value::{BalanceError, ZatBalance, Zatoshis};

use zcash_script::{op, script};

use crate::{
    address::{Script, TransparentAddress},
    bundle::{Authorization, Authorized, Bundle, TxIn, TxOut},
    pczt,
    sighash::{SignableInput, TransparentAuthorizingContext},
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        bundle::OutPoint,
        sighash::{SighashType, SIGHASH_ALL},
    },
    sha2::Digest,
    zcash_script::pv::push_value,
};

#[cfg(not(feature = "transparent-inputs"))]
use zcash_script::Opcode;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The provided script contains unsupported opcodes.
    UnsupportedScript,
    InvalidAddress,
    InvalidAmount,
    /// A bundle could not be built because a required signing keys was missing.
    MissingSigningKey,
    /// Provided null data is longer than the maximum supported length.
    NullDataTooLong {
        actual: usize,
        limit: usize,
    },
    /// The number of inputs does not match number of sighashes.
    InputCountMismatch, // Use this for prepare_transparent_signatures
    /// A provided external signature was not valid for any transparent input.
    InvalidExternalSignature {
        sig_index: usize,
    },
    /// An external signature is valid for more than one transparent input.
    /// This should not happen: it indicates either a duplicate signed input
    /// and key (and therefore a double-spend), or an attack on ECDSA such as
    /// key substitution.
    DuplicateSignature,
    /// A bundle could not be built because required signatures on transparent
    /// inputs were missing.
    MissingSignatures,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnsupportedScript => write!(f, "Script contains unsupported opcodes"),
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::MissingSigningKey => write!(f, "Missing signing key"),
            Error::NullDataTooLong { actual, limit } => write!(f, "Provided null data is longer than the maximum supported length (actual: {}, limit: {})", actual, limit),
            Error::InputCountMismatch => write!(f, "The number of inputs does not match the number of sighashes"),
            Error::InvalidExternalSignature { sig_index } => write!(f, "A provided external signature at index {} was not valid for any transparent input", sig_index),
            Error::DuplicateSignature => write!(f, "An external signature is valid for more than one transparent input."),
            Error::MissingSignatures => write!(f, "A bundle could not be built because required signatures on transparent inputs were missing."),
        }
    }
}

/// A set of transparent signing keys.
///
/// When the `transparent-inputs` feature flag is enabled, transparent signing keys can be
/// stored in this set and used to authorize transactions with transparent inputs.
pub struct TransparentSigningSet {
    #[cfg(feature = "transparent-inputs")]
    secp: secp256k1::Secp256k1<secp256k1::SignOnly>,
    #[cfg(feature = "transparent-inputs")]
    keys: Vec<(secp256k1::SecretKey, secp256k1::PublicKey)>,
}

impl Default for TransparentSigningSet {
    fn default() -> Self {
        Self::new()
    }
}

impl TransparentSigningSet {
    /// Constructs an empty set of signing keys.
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "transparent-inputs")]
            secp: secp256k1::Secp256k1::gen_new(),
            #[cfg(feature = "transparent-inputs")]
            keys: vec![],
        }
    }

    /// Adds a signing key to the set.
    ///
    /// Returns the corresponding pubkey.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_key(&mut self, sk: secp256k1::SecretKey) -> secp256k1::PublicKey {
        let pubkey = secp256k1::PublicKey::from_secret_key(&self.secp, &sk);
        // Cache the pubkey for ease of matching later.
        self.keys.push((sk, pubkey));
        pubkey
    }
}

// Helper function within the transparent-inputs feature gate
#[cfg(feature = "transparent-inputs")]
fn construct_script_sig(
    signature: &secp256k1::ecdsa::Signature,
    pubkey: &secp256k1::PublicKey,
) -> script::Sig {
    let mut sig_bytes: Vec<u8> = signature.serialize_der().to_vec();
    sig_bytes.push(SIGHASH_ALL);
    script::Component(vec![
        push_value(&sig_bytes).expect("short enough"),
        push_value(&pubkey.serialize()).expect("short enough"),
    ])
}

// TODO: This feature gate can be removed.
#[cfg(feature = "transparent-inputs")]
#[derive(Debug, Clone)]
pub struct TransparentInputInfo {
    pubkey: secp256k1::PublicKey,
    utxo: OutPoint,
    coin: TxOut,
}

#[cfg(feature = "transparent-inputs")]
impl TransparentInputInfo {
    pub fn outpoint(&self) -> &OutPoint {
        &self.utxo
    }

    pub fn coin(&self) -> &TxOut {
        &self.coin
    }
}

pub struct TransparentBuilder {
    #[cfg(feature = "transparent-inputs")]
    inputs: Vec<TransparentInputInfo>,
    vout: Vec<TxOut>,
}

#[derive(Debug, Clone)]
pub struct Unauthorized {
    #[cfg(feature = "transparent-inputs")]
    inputs: Vec<TransparentInputInfo>,
}

impl Authorization for Unauthorized {
    type ScriptSig = ();
}

#[cfg(feature = "transparent-inputs")]
pub struct TransparentSignatureContext<'a, V: secp256k1::Verification = secp256k1::VerifyOnly> {
    // Data from the original Bundle<Unauthorized>, needed to reconstruct Bundle<Authorized>
    original_vin_unauthorized: Vec<TxIn<Unauthorized>>,
    original_vout: Vec<TxOut>,
    authorization_inputs: Vec<TransparentInputInfo>,

    // External data references
    sighashes: Vec<[u8; 32]>,
    secp_ctx: &'a secp256k1::Secp256k1<V>,

    // Mutable state: accumulated script signatures for inputs
    final_script_sigs: Vec<Option<script::Sig>>,
}

impl TransparentBuilder {
    /// Constructs a new TransparentBuilder
    pub fn empty() -> Self {
        TransparentBuilder {
            #[cfg(feature = "transparent-inputs")]
            inputs: vec![],
            vout: vec![],
        }
    }

    /// Returns the list of transparent inputs that will be consumed by the transaction being
    /// constructed.
    #[cfg(feature = "transparent-inputs")]
    pub fn inputs(&self) -> &[TransparentInputInfo] {
        &self.inputs
    }

    /// Returns the transparent outputs that will be produced by the transaction being constructed.
    pub fn outputs(&self) -> &[TxOut] {
        &self.vout
    }

    /// Adds a coin (the output of a previous transaction) to be spent to the transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_input(
        &mut self,
        pubkey: secp256k1::PublicKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        let script_pubkey =
            script::PubKey::parse(&coin.script_pubkey().0).map_err(|_| Error::UnsupportedScript)?;

        // Ensure that the RIPEMD-160 digest of the public key associated with the
        // provided secret key matches that of the address to which the provided
        // output may be spent.
        match TransparentAddress::from_script_pubkey(&script_pubkey) {
            Some(TransparentAddress::PublicKeyHash(hash)) => {
                use ripemd::Ripemd160;
                use sha2::Sha256;

                if hash[..] != Ripemd160::digest(Sha256::digest(pubkey.serialize()))[..] {
                    return Err(Error::InvalidAddress);
                }
            }
            _ => return Err(Error::InvalidAddress),
        }

        self.inputs
            .push(TransparentInputInfo { pubkey, utxo, coin });

        Ok(())
    }

    pub fn add_output(&mut self, to: &TransparentAddress, value: Zatoshis) -> Result<(), Error> {
        self.vout.push(TxOut::new(value, to.script().into()));

        Ok(())
    }

    pub fn value_balance(&self) -> Result<ZatBalance, BalanceError> {
        #[cfg(feature = "transparent-inputs")]
        let input_sum = self
            .inputs
            .iter()
            .map(|input| input.coin.value())
            .sum::<Option<Zatoshis>>()
            .ok_or(BalanceError::Overflow)?;

        #[cfg(not(feature = "transparent-inputs"))]
        let input_sum = Zatoshis::ZERO;

        let output_sum = self
            .vout
            .iter()
            .map(|vo| vo.value())
            .sum::<Option<Zatoshis>>()
            .ok_or(BalanceError::Overflow)?;

        (ZatBalance::from(input_sum) - ZatBalance::from(output_sum)).ok_or(BalanceError::Underflow)
    }

    pub fn build(self) -> Option<Bundle<Unauthorized>> {
        #[cfg(feature = "transparent-inputs")]
        let vin: Vec<TxIn<Unauthorized>> = self
            .inputs
            .iter()
            .map(|i| TxIn::new(i.utxo.clone()))
            .collect();

        #[cfg(not(feature = "transparent-inputs"))]
        let vin: Vec<TxIn<Unauthorized>> = vec![];

        if vin.is_empty() && self.vout.is_empty() {
            None
        } else {
            Some(Bundle {
                vin,
                vout: self.vout,
                authorization: Unauthorized {
                    #[cfg(feature = "transparent-inputs")]
                    inputs: self.inputs,
                },
            })
        }
    }

    /// Builds a bundle containing the given inputs and outputs, for inclusion in a PCZT.
    pub fn build_for_pczt(self) -> Option<pczt::Bundle> {
        #[cfg(feature = "transparent-inputs")]
        let inputs = self
            .inputs
            .iter()
            .map(|i| pczt::Input {
                prevout_txid: i.utxo.hash,
                prevout_index: i.utxo.n,
                sequence: None,
                required_time_lock_time: None,
                required_height_lock_time: None,
                script_sig: None,
                value: i.coin.value(),
                script_pubkey: script::FromChain::parse(&i.coin.script_pubkey().0)
                    .expect("checked by builder when input was added"),
                // We don't currently support spending P2SH coins.
                redeem_script: None,
                partial_signatures: BTreeMap::new(),
                sighash_type: SighashType::ALL,
                bip32_derivation: BTreeMap::new(),
                ripemd160_preimages: BTreeMap::new(),
                sha256_preimages: BTreeMap::new(),
                hash160_preimages: BTreeMap::new(),
                hash256_preimages: BTreeMap::new(),
                proprietary: BTreeMap::new(),
            })
            .collect::<Vec<_>>();

        #[cfg(not(feature = "transparent-inputs"))]
        let inputs = vec![];

        if inputs.is_empty() && self.vout.is_empty() {
            None
        } else {
            let outputs = self
                .vout
                .iter()
                .map(|o| pczt::Output {
                    value: o.value(),
                    script_pubkey: script::PubKey::parse(&o.script_pubkey().0)
                        .expect("builder doesn't produce output scripts with unknown opcodes"),
                    // We don't currently support spending P2SH coins, so we only ever see
                    // external P2SH recipients here, for which we never know the redeem
                    // script.
                    redeem_script: None,
                    bip32_derivation: BTreeMap::new(),
                    user_address: None,
                    proprietary: BTreeMap::new(),
                })
                .collect();

            Some(pczt::Bundle { inputs, outputs })
        }
    }

    /// Adds a zero-value "null data" (OP_RETURN) output containing the given data.
    pub fn add_null_data_output(&mut self, data: &[u8]) -> Result<(), Error> {
        // Check 80 bytes limit.
        const MAX_OP_RETURN_RELAY_BYTES: usize = 80;
        if data.len() > MAX_OP_RETURN_RELAY_BYTES {
            return Err(Error::NullDataTooLong {
                actual: data.len(),
                limit: MAX_OP_RETURN_RELAY_BYTES,
            });
        }

        let script = script::Component(vec![
            op::RETURN,
            op::push_value(data).expect("length checked"),
        ]);

        self.vout.push(TxOut::new(Zatoshis::ZERO, script.into()));
        Ok(())
    }
}

impl TxIn<Unauthorized> {
    #[cfg(feature = "transparent-inputs")]
    pub fn new(prevout: OutPoint) -> Self {
        TxIn::from_parts(prevout, (), u32::MAX)
    }
}

#[cfg(not(feature = "transparent-inputs"))]
impl TransparentAuthorizingContext for Unauthorized {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        vec![]
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        vec![]
    }
}

#[cfg(feature = "transparent-inputs")]
impl TransparentAuthorizingContext for Unauthorized {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.inputs.iter().map(|txin| txin.coin.value()).collect()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.inputs
            .iter()
            .map(|txin| txin.coin.script_pubkey().clone())
            .collect()
    }
}

impl Bundle<Unauthorized> {
    #[cfg_attr(not(feature = "transparent-inputs"), allow(unused_variables))]
    pub fn apply_signatures<F>(
        self,
        calculate_sighash: F,
        signing_set: &TransparentSigningSet,
    ) -> Result<Bundle<Authorized>, Error>
    where
        F: Fn(SignableInput) -> [u8; 32],
    {
        #[cfg(feature = "transparent-inputs")]
        let script_sigs = self
            .authorization
            .inputs
            .iter()
            .enumerate()
            .map(|(index, info)| {
                // Find the matching signing key.
                let (sk, _) = signing_set
                    .keys
                    .iter()
                    .find(|(_, pubkey)| pubkey == &info.pubkey)
                    .ok_or(Error::MissingSigningKey)?;

                let sighash = calculate_sighash(SignableInput {
                    hash_type: SighashType::ALL,
                    index,
                    script_code: info.coin.script_pubkey(), // for p2pkh, always the same as script_pubkey
                    script_pubkey: info.coin.script_pubkey(),
                    value: info.coin.value(),
                });

                let msg = secp256k1::Message::from_digest(sighash);
                let sig = signing_set.secp.sign_ecdsa(&msg, sk);

                // Signature has to have "SIGHASH_ALL" appended to it
                let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
                sig_bytes.extend([SIGHASH_ALL]);

                // P2PKH scriptSig
                Ok(script::Component(vec![
                    op::push_value(&sig_bytes).expect("length checked"),
                    op::push_value(&info.pubkey.serialize()).expect("length checked"),
                ]))
            });

        #[cfg(not(feature = "transparent-inputs"))]
        let script_sigs = core::iter::empty::<Result<script::Component<Opcode>, Error>>();

        Ok(Bundle {
            vin: self
                .vin
                .iter()
                .zip(script_sigs)
                .map(|(txin, sig)| {
                    Ok(TxIn::from_parts(
                        txin.prevout().clone(),
                        sig?.into(),
                        txin.sequence(),
                    ))
                })
                .collect::<Result<_, _>>()?,
            vout: self.vout,
            authorization: Authorized,
        })
    }

    /// Prepares the bundle for staged application of external signatures.
    ///
    /// This method computes the sighash for each transparent input using the provided
    /// `calculate_sighash` closure.
    #[cfg(feature = "transparent-inputs")]
    pub fn prepare_transparent_signatures<F>(
        self,
        calculate_sighash: F,
        secp_ctx: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    ) -> Result<TransparentSignatureContext<'_, secp256k1::VerifyOnly>, Error>
    where
        F: Fn(SignableInput) -> [u8; 32], // The closure's signature
    {
        // Compute the sighashes for all inputs using the provided closure.
        let sighashes = self
            .authorization
            .inputs
            .iter()
            .enumerate()
            .map(|(index, info)| {
                calculate_sighash(SignableInput {
                    hash_type: SighashType::ALL,
                    index,
                    // for p2pkh, script_code is always the same as script_pubkey
                    script_code: info.coin.script_pubkey(),
                    script_pubkey: info.coin.script_pubkey(),
                    value: info.coin.value(),
                })
            })
            .collect::<Vec<_>>();

        let num_inputs = self.authorization.inputs.len();
        Ok(TransparentSignatureContext {
            original_vin_unauthorized: self.vin,
            original_vout: self.vout,
            authorization_inputs: self.authorization.inputs,
            sighashes,
            secp_ctx,
            final_script_sigs: vec![None; num_inputs],
        })
    }
}

#[cfg(feature = "transparent-inputs")]
impl<'a> TransparentSignatureContext<'a, secp256k1::VerifyOnly> {
    /// Appends a new batch of external signatures to the transparent inputs.
    ///
    /// This method iterates through the provided signatures, applying each one to the
    /// single input for which it is valid.
    ///
    /// An error will be returned if any of the signatures are not valid for any
    /// available unsigned inputs, or valid for more than one input.
    pub fn append_external_signatures(
        self,
        signatures: &[secp256k1::ecdsa::Signature],
    ) -> Result<Self, Error> {
        if self.authorization_inputs.is_empty() && !signatures.is_empty() {
            // No inputs to sign.
            return Err(Error::InvalidExternalSignature { sig_index: 0 });
        }

        // Iterate over signatures
        signatures
            .iter()
            .enumerate()
            .try_fold(self, |current_self, (sig_idx, sig)| {
                current_self.append_external_signature(sig_idx, sig)
            })
    }

    /// Applies a single external signature to the one input for which it is valid.
    ///
    /// An error will be returned if the signature is not valid for any available
    /// unsigned inputs, or if it is valid for more than one input.
    fn append_external_signature(
        mut self,
        sig_idx: usize,
        signature: &secp256k1::ecdsa::Signature,
    ) -> Result<Self, Error> {
        let mut matched_input_idx = None;

        // Find which single unsigned input this signature is valid for.
        for (input_idx, input_info) in self.authorization_inputs.iter().enumerate() {
            // Skip inputs that have already been signed.
            if self.final_script_sigs[input_idx].is_some() {
                continue;
            }

            let sighash_msg = secp256k1::Message::from_digest(self.sighashes[input_idx]);

            if self
                .secp_ctx
                .verify_ecdsa(&sighash_msg, signature, &input_info.pubkey)
                .is_ok()
            {
                if matched_input_idx.is_some() {
                    // This signature was already valid for a different input.
                    return Err(Error::DuplicateSignature);
                }
                matched_input_idx = Some(input_idx);
            }
        }

        if let Some(final_input_idx) = matched_input_idx {
            // Check if another signature has already been applied to this input.
            if self.final_script_sigs[final_input_idx].is_some() {
                return Err(Error::DuplicateSignature);
            }

            // Apply the signature.
            self.final_script_sigs[final_input_idx] = Some(construct_script_sig(
                signature,
                &self.authorization_inputs[final_input_idx].pubkey,
            ));

            Ok(self)
        } else {
            // This signature did not match any available unsigned inputs.
            Err(Error::InvalidExternalSignature { sig_index: sig_idx })
        }
    }

    /// Finalizes the signing process and attempts to build the `Bundle<Authorized>`.
    ///
    /// Returns an error if any signatures are missing.
    pub fn finalize_signatures(self) -> Result<Bundle<Authorized>, Error> {
        let mut fully_signed_scripts = Vec::with_capacity(self.final_script_sigs.len());
        for script_opt in self.final_script_sigs.iter() {
            match script_opt {
                Some(script) => fully_signed_scripts.push(script.clone()),
                None => {
                    if !self.authorization_inputs.is_empty() {
                        return Err(Error::MissingSignatures);
                    }
                }
            }
        }

        Ok(Bundle {
            vin: self
                .original_vin_unauthorized
                .iter()
                .zip(fully_signed_scripts)
                .map(|(txin_unauth, sig_script)| {
                    TxIn::from_parts(
                        txin_unauth.prevout().clone(),
                        sig_script.into(),
                        txin_unauth.sequence(),
                    )
                })
                .collect(),
            vout: self.original_vout,
            authorization: Authorized,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, OutPoint, SignableInput, TransparentBuilder, TxOut};
    use crate::address::TransparentAddress;
    use ripemd::Ripemd160;
    use secp256k1::{Message, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    use zcash_address::ZcashAddress;
    use zcash_protocol::value::Zatoshis;

    // Helper that takes a key to create distinct inputs.
    fn new_p2pkh_spend_with_key(
        key_bytes: [u8; 32],
    ) -> (SecretKey, secp256k1::PublicKey, TxOut, OutPoint) {
        let sk = SecretKey::from_slice(&key_bytes).expect("32 bytes is a valid secret key");
        let secp = Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        let pk_hash_generic_array = Ripemd160::digest(Sha256::digest(pk.serialize()));
        let pk_hash_bytes: [u8; 20] = pk_hash_generic_array.into();
        let taddr = TransparentAddress::PublicKeyHash(pk_hash_bytes);

        let txout = TxOut::new(Zatoshis::from_u64(10000).unwrap(), taddr.script().into());

        let txid = [0u8; 32]; // Dummy txid
        let outpoint = OutPoint::new(txid, 0);

        (sk, pk, txout, outpoint)
    }

    #[test]
    fn append_and_finalize_signatures() {
        let addr_str = "tmNUFAr71YAW3eXetm8fhx7k8zpUJYQiKZP";
        let generic_addr: ZcashAddress = addr_str
            .parse()
            .expect("Test address string should be valid");
        let taddr: TransparentAddress = generic_addr
            .convert()
            .expect("Conversion to TransparentAddress should succeed");

        // Create two inputs with corresponding secret keys for signing
        let (sk1, pk1, coin1, utxo1) = new_p2pkh_spend_with_key([1; 32]);
        let (sk2, pk2, coin2, utxo2) = new_p2pkh_spend_with_key([1; 32]);

        // Create a builder and add the inputs and a dummy output
        let mut builder = TransparentBuilder::empty();
        builder.add_input(pk1, utxo1, coin1).unwrap();
        builder.add_input(pk2, utxo2, coin2).unwrap();
        builder
            .add_output(&taddr, Zatoshis::from_u64(5000).unwrap())
            .unwrap();

        // Build the unauthorized bundle
        let bundle = builder.build().unwrap();

        // Create the secp256k1 context for verification
        let secp = Secp256k1::verification_only();

        // This closure will be called by `prepare_transparent_signatures` for each input.
        // For this test, we'll just return a fixed, unique hash for each input.
        let calculate_sighash = |input: SignableInput| {
            let mut sighash = [0u8; 32];
            // Create a distinct sighash for each input index
            sighash[0] = input.index as u8;
            sighash
        };

        // Prepare the signing context
        let sig_context = bundle
            .prepare_transparent_signatures(calculate_sighash, &secp)
            .unwrap();

        let sighash1 = sig_context.sighashes[0];
        let sighash2 = sig_context.sighashes[1];

        // Sign with the corresponding secret keys
        let signing_secp = Secp256k1::signing_only();
        let msg1 = Message::from_digest_slice(&sighash1).unwrap();
        let msg2 = Message::from_digest_slice(&sighash2).unwrap();
        let sig1 = signing_secp.sign_ecdsa(&msg1, &sk1);
        let sig2 = signing_secp.sign_ecdsa(&msg2, &sk2);

        // Create a batch with the correct signatures
        let signatures_batch = vec![sig1, sig2];

        // Append the external signatures. This should succeed.
        let result = sig_context.append_external_signatures(&signatures_batch);
        assert!(result.is_ok(), "Appending valid signatures failed");

        // Finalize the bundle. This should also succeed as all inputs are signed.
        let final_bundle_result = result.unwrap().finalize_signatures();
        assert!(final_bundle_result.is_ok(), "Finalizing bundle failed");
    }

    #[test]
    fn append_fails_for_unmatched_signature() {
        // Create one input with a known secret key
        let (_sk1, pk1, coin1, utxo1) = new_p2pkh_spend_with_key([1; 32]);
        let mut builder = TransparentBuilder::empty();
        builder.add_input(pk1, utxo1, coin1).unwrap();
        let bundle = builder.build().unwrap();

        // Prepare the signing context
        let secp = Secp256k1::verification_only();
        let calculate_sighash = |input: SignableInput| [input.index as u8; 32];
        let sig_context = bundle
            .prepare_transparent_signatures(calculate_sighash, &secp)
            .unwrap();

        // Create a signature from a different key
        let unrelated_sk_bytes = [2; 32];
        let unrelated_sk = SecretKey::from_slice(&unrelated_sk_bytes).unwrap();

        let sighash = sig_context.sighashes[0];
        let msg = Message::from_digest_slice(&sighash).unwrap();
        let bad_signature = Secp256k1::signing_only().sign_ecdsa(&msg, &unrelated_sk);

        // Assert that appending this "bad" signature fails with the correct error
        let result = sig_context.append_external_signatures(&[bad_signature]);
        assert!(matches!(
            result,
            Err(Error::InvalidExternalSignature { sig_index: 0 })
        ));
    }

    #[test]
    fn append_fails_for_ambiguous_signature() {
        // Create one keypair. We will use it to create two identical inputs.
        let (sk, pk, coin, _) = new_p2pkh_spend_with_key([1; 32]);

        // Create two different UTXOs, but they both belong to the same public key and have the same value.
        let utxo1 = OutPoint::new([10; 32], 0);
        let utxo2 = OutPoint::new([20; 32], 1);

        let mut builder = TransparentBuilder::empty();
        // Add the first input associated with pk.
        builder.add_input(pk, utxo1, coin.clone()).unwrap();
        // Add the second, distinct input that is also associated with pk.
        builder.add_input(pk, utxo2, coin).unwrap();

        let bundle = builder.build().unwrap();

        // Prepare the signing context
        let secp = Secp256k1::verification_only();
        // Make both sighashes the same for this test.
        let calculate_sighash = |_input: SignableInput| [42; 32];
        let sig_context = bundle
            .prepare_transparent_signatures(calculate_sighash, &secp)
            .unwrap();

        // Create one signature from the first key that will now appear valid for both inputs
        let sighash = sig_context.sighashes[0]; // Both sighashes are identical ([42; 32])
        let msg = Message::from_digest_slice(&sighash).unwrap();
        let ambiguous_sig = Secp256k1::signing_only().sign_ecdsa(&msg, &sk);

        // Assert that appending this one signature fails with DuplicateSignature
        let result = sig_context.append_external_signatures(&[ambiguous_sig]);
        assert!(matches!(result, Err(Error::DuplicateSignature)));
    }

    #[test]
    fn finalize_fails_if_not_all_inputs_are_signed() {
        // Create two distinct inputs that need to be signed.
        let (sk1, pk1, coin1, utxo1) = new_p2pkh_spend_with_key([1; 32]);
        let (_sk2, pk2, coin2, utxo2) = new_p2pkh_spend_with_key([2; 32]);

        let mut builder = TransparentBuilder::empty();
        builder.add_input(pk1, utxo1, coin1).unwrap();
        builder.add_input(pk2, utxo2, coin2).unwrap();
        let bundle = builder.build().unwrap();

        // Prepare the signing context
        let secp = Secp256k1::verification_only();
        let calculate_sighash = |input: SignableInput| {
            let mut sighash = [0u8; 32];
            sighash[0] = input.index as u8; // A simple, unique sighash for each input
            sighash
        };
        let sig_context = bundle
            .prepare_transparent_signatures(calculate_sighash, &secp)
            .unwrap();

        // Create and append a signature for only the first input
        let sighash1 = sig_context.sighashes[0];
        let msg1 = Message::from_digest_slice(&sighash1).unwrap();
        let sig1 = Secp256k1::signing_only().sign_ecdsa(&msg1, &sk1);

        // This append operation should succeed, as we are providing one valid signature.
        let result_after_append = sig_context.append_external_signatures(&[sig1]);
        assert!(
            result_after_append.is_ok(),
            "Appending a single valid signature should not fail."
        );
        let partially_signed_context = result_after_append.unwrap();

        // Assert that finalizing the bundle fails.
        // The context is missing a signature for the second input.
        let final_bundle_result = partially_signed_context.finalize_signatures();
        assert!(
            matches!(final_bundle_result, Err(Error::MissingSignatures)),
            "Should fail with MissingSignatures, but got: {:?}",
            final_bundle_result
        );
    }
}
