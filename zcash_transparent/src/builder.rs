//! Types and functions for building transparent transaction components.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use zcash_protocol::value::{BalanceError, ZatBalance, Zatoshis};

use crate::{
    address::{Script, TransparentAddress},
    bundle::{Authorization, Authorized, Bundle, TxIn, TxOut},
    pczt,
    sighash::{SignableInput, TransparentAuthorizingContext},
};

use crate::address::OpCode;

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        bundle::OutPoint,
        sighash::{SighashType, SIGHASH_ALL},
    },
    alloc::string::ToString,
    sha2::Digest,
};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAddress,
    InvalidAmount,
    /// A bundle could not be built because a required signing keys was missing.
    MissingSigningKey,
    /// Provided null data is longer than the maximum supported length
    NullDataTooLong {
        actual: usize,
        limit: usize,
    },
    /// The number of provided external signatures does not match the number of transparent inputs.
    SignatureCountMismatch,
    /// The number of inputs does not match number of sighashes.
    InputCountMismatch, // Use this for prepare_transparent_signatures
    /// A pre-calculated sighash could not be correctly formed or was invalid.
    SighashGeneration,
    /// An external signature failed cryptographic verification for a specific transparent input.
    SignatureVerificationFailed {
        input_index: usize,
    },
    /// A provided external signature did not cryptographically match any available unsigned transparent input.
    NoMatchingInputForSignature {
        input_index: usize,
    },
    /// An attempt was made to apply a signature to a transparent input that had already been signed.
    InputAlreadySigned {
        input_index: usize,
    },
    /// A single provided external signature was cryptographically valid for more than one distinct transparent input.
    AmbiguousSignature,
    /// Not all transparent inputs that require signing received a valid signature.
    NotAllInputsSigned,
    /// One or more provided external signatures were not used to sign any transparent input.
    UnusedExternalSignature {
        input_index: usize,
    },
    /// An error occurred within the secp256k1 cryptographic library.
    Secp256k1Error(String), // Stores String to satisfy PartialEq/Eq
    /// Generic internal error during transparent builder operations.
    InternalBuilderError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::MissingSigningKey => write!(f, "Missing signing key"),
            Error::NullDataTooLong { actual, limit } => write!(f, "Provided null data is longer than the maximum supported length (actual: {}, limit: {}", actual, limit),
            Error::SignatureCountMismatch => write!(f, "The number of provided external signatures does not match the number of transparent inputs"),
            Error::InputCountMismatch => write!(f, "The number of inputs does not match the number of sighashes"),
            Error::SighashGeneration => write!(f, "A pre-calculated sighash could not be correctly formed or was invalid"),
            Error::SignatureVerificationFailed { input_index } => write!(f, "External signature verification failed for transparent input at index {}", input_index),
            Error::NoMatchingInputForSignature { input_index } => write!(f, "A provided external signature at index {} did not cryptographically match any available unsigned transparent input", input_index),
            Error::InputAlreadySigned { input_index } => write!(f, "Transparent input at index {} has already been signed", input_index),
            Error::AmbiguousSignature => write!(f, "A single provided external signature was cryptographically valid for more than one distinct transparent input"),
            Error::NotAllInputsSigned => write!(f, "Not all transparent inputs that require signing received a valid signature"),
            Error::UnusedExternalSignature { input_index } => write!(f, "External signature at index {} was not used to sign any transparent input", input_index),
            Error::Secp256k1Error(msg) => write!(f, "Secp256k1 cryptographic library error: {}", msg),
            Error::InternalBuilderError(msg) => write!(f, "Internal transparent builder error: {}", msg),            
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
) -> Script {
    let mut sig_bytes: Vec<u8> = signature.serialize_der().to_vec();
    sig_bytes.push(SIGHASH_ALL);
    Script::default() << &sig_bytes[..] << &pubkey.serialize()[..]
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
    sighashes: &'a [[u8; 32]],
    secp_ctx: &'a secp256k1::Secp256k1<V>,

    // Mutable state: accumulated script signatures for inputs
    final_script_sigs: Vec<Option<Script>>,
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
        // Ensure that the RIPEMD-160 digest of the public key associated with the
        // provided secret key matches that of the address to which the provided
        // output may be spent.
        match coin.script_pubkey.address() {
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
        self.vout.push(TxOut {
            value,
            script_pubkey: to.script(),
        });

        Ok(())
    }

    pub fn value_balance(&self) -> Result<ZatBalance, BalanceError> {
        #[cfg(feature = "transparent-inputs")]
        let input_sum = self
            .inputs
            .iter()
            .map(|input| input.coin.value)
            .sum::<Option<Zatoshis>>()
            .ok_or(BalanceError::Overflow)?;

        #[cfg(not(feature = "transparent-inputs"))]
        let input_sum = Zatoshis::ZERO;

        let output_sum = self
            .vout
            .iter()
            .map(|vo| vo.value)
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
                value: i.coin.value,
                script_pubkey: i.coin.script_pubkey.clone(),
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
                .into_iter()
                .map(|o| pczt::Output {
                    value: o.value,
                    script_pubkey: o.script_pubkey,
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

        let script = Script::default() << OpCode::Return << data;

        self.vout.push(TxOut {
            value: Zatoshis::ZERO,
            script_pubkey: script,
        });
        Ok(())
    }
}

impl TxIn<Unauthorized> {
    #[cfg(feature = "transparent-inputs")]
    pub fn new(prevout: OutPoint) -> Self {
        TxIn {
            prevout,
            script_sig: (),
            sequence: u32::MAX,
        }
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
        self.inputs.iter().map(|txin| txin.coin.value).collect()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.inputs
            .iter()
            .map(|txin| txin.coin.script_pubkey.clone())
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
                    script_code: &info.coin.script_pubkey, // for p2pkh, always the same as script_pubkey
                    script_pubkey: &info.coin.script_pubkey,
                    value: info.coin.value,
                });

                let msg =
                    secp256k1::Message::from_digest_slice(sighash.as_ref()).expect("32 bytes");
                let sig = signing_set.secp.sign_ecdsa(&msg, sk);

                // Signature has to have "SIGHASH_ALL" appended to it
                let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
                sig_bytes.extend([SIGHASH_ALL]);

                // P2PKH scriptSig
                Ok(Script::default() << &sig_bytes[..] << &info.pubkey.serialize()[..])
            });

        #[cfg(not(feature = "transparent-inputs"))]
        let script_sigs = core::iter::empty::<Result<Script, Error>>();

        Ok(Bundle {
            vin: self
                .vin
                .iter()
                .zip(script_sigs)
                .map(|(txin, sig)| {
                    Ok(TxIn {
                        prevout: txin.prevout.clone(),
                        script_sig: sig?,
                        sequence: txin.sequence,
                    })
                })
                .collect::<Result<_, _>>()?,
            vout: self.vout,
            authorization: Authorized,
        })
    }

    /// Prepares the bundle for staged application of external signatures.
    #[cfg(feature = "transparent-inputs")]
    pub fn prepare_transparent_signatures<'a>(
        self,
        sighashes: &'a [[u8; 32]],
        secp_ctx: &'a secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    ) -> Result<TransparentSignatureContext<'a, secp256k1::VerifyOnly>, Error> {
        if self.authorization.inputs.len() != sighashes.len() {
            return Err(Error::InputCountMismatch);
        }

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
    /// Each signature will be applied to the one input for which it is valid. An error
    /// will be returned if the signature is not valid for any inputs, or if it is valid
    /// for more than one input.
    pub fn append_external_signatures(
        &mut self,
        signatures: &[secp256k1::ecdsa::Signature],
    ) -> Result<(), Error> {
        if signatures.is_empty() {
            return Ok(());
        }

        let num_inputs = self.authorization_inputs.len();
        if num_inputs == 0 {
            return Err(Error::NoMatchingInputForSignature { input_index: 0 });
        }

        let num_sigs = signatures.len();
        let mut sig_is_used = vec![false; num_sigs];

        // Iterate through each input that is not yet signed from previous calls
        for input_idx in 0..num_inputs {
            if self.final_script_sigs[input_idx].is_some() {
                continue;
            }

            let input_info = &self.authorization_inputs[input_idx];
            let sighash_msg = secp256k1::Message::from_digest_slice(&self.sighashes[input_idx][..])
                .map_err(|e| Error::Secp256k1Error(e.to_string()))?;

            let mut matching_sig_indices: Vec<usize> = Vec::new();
            for (sig_idx, sig) in signatures.iter().enumerate() {
                if self
                    .secp_ctx
                    .verify_ecdsa(&sighash_msg, sig, &input_info.pubkey)
                    .is_ok()
                {
                    if sig_is_used[sig_idx] {
                        // This signature was already used for a previous input_idx in this append call,
                        // and it also matches this current input_idx. This is "one signature, multiple inputs".
                        return Err(Error::AmbiguousSignature);
                    }
                    matching_sig_indices.push(sig_idx);
                }
            }

            if matching_sig_indices.is_empty() {
                // Remains unsigned for now.
                continue;
            } else if matching_sig_indices.len() == 1 {
                let an_assignable_sig_idx = matching_sig_indices[0];
                self.final_script_sigs[input_idx] = Some(construct_script_sig(
                    &signatures[an_assignable_sig_idx],
                    &input_info.pubkey,
                ));
                sig_is_used[an_assignable_sig_idx] = true;
            } else {
                // Multiple signatures for one input.
                return Err(Error::AmbiguousSignature);
            }
        }

        // Verify if all provided signatures were used.
        for (sig_idx, used) in sig_is_used.iter().enumerate() {
            if !*used {
                return Err(Error::NoMatchingInputForSignature {
                    input_index: sig_idx,
                });
            }
        }

        Ok(())
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
                        return Err(Error::NotAllInputsSigned);
                    }
                }
            }
        }

        Ok(Bundle {
            vin: self
                .original_vin_unauthorized
                .iter()
                .zip(fully_signed_scripts)
                .map(|(txin_unauth, sig_script)| TxIn {
                    prevout: txin_unauth.prevout.clone(),
                    script_sig: sig_script,
                    sequence: txin_unauth.sequence,
                })
                .collect(),
            vout: self.original_vout,
            authorization: Authorized,
        })
    }
}
