//! Types and functions for building transparent transaction components.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use zcash_protocol::value::{BalanceError, ZatBalance, Zatoshis};

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
};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAddress,
    InvalidAmount,
    /// A bundle could not be built because a required signing keys was missing.
    MissingSigningKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::MissingSigningKey => write!(f, "Missing signing key"),
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

#[derive(Debug, Clone)]
enum InputKind {
    P2pkh { pubkey: secp256k1::PublicKey },
    P2sh { redeem_script: Script },
}

// TODO: This feature gate can be removed.
#[cfg(feature = "transparent-inputs")]
#[derive(Debug, Clone)]
pub struct TransparentInputInfo {
    kind: InputKind,
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

    /// The size of this transparent input in a transaction, as used in [ZIP 317].
    ///
    /// Returns `None` if we cannot determine the size. (TODO: Remove this case)
    ///
    /// [ZIP 317]: https://zips.z.cash/zip-0317#rationale-for-the-chosen-parameters
    pub fn serialized_len(&self) -> Option<usize> {
        use zcash_encoding::CompactSize;
        let push_data = |data_len| {
            (if data_len < 0x4c {
                1
            } else if data_len <= 0xff {
                2
            } else if data_len <= 0xffff {
                3
            } else {
                5
            }) + data_len
        };

        let script_len = match &self.kind {
            InputKind::P2pkh { .. } => {
                // P2PKH `script_sig` format is:
                // - PushData(secp256k1::ecdsa::serialized_signature::MAX_LEN + 1)
                // - PushData(secp256k1::constants::PUBLIC_KEY_SIZE)
                Some(push_data(72 + 1) + push_data(secp256k1::constants::PUBLIC_KEY_SIZE))
            }
            InputKind::P2sh { redeem_script } => {
                // TODO: Replace this hacky P2MS detection logic with `zcash_script`.
                if redeem_script.0.len() >= 3
                    // OP_1..=OP_15
                    && (0x51..=0x5f).contains(&redeem_script.0[0])
                    && (0x51..=0x5f).contains(&redeem_script.0[redeem_script.0.len()-2])
                    // OP_CHECKMULTISIG
                    && redeem_script.0.last() == Some(&0xae)
                {
                    let num_sigs = usize::from(redeem_script.0[0] - 0x50);
                    // P2MS-in-P2SH `script_sig` format is:
                    // - Dummy OP_0 to bypass OP_CHECKMULTISIG bug.
                    // - PushData(secp256k1::ecdsa::serialized_signature::MAX_LEN + 1) * num_sigs
                    // - PushData(redeem_script)
                    Some(1 + num_sigs * push_data(72 + 1) + push_data(redeem_script.0.len()))
                } else {
                    // TODO: Use `zcash_script` to figure out the necessary shape of the
                    // inputs to `redeem_script`
                    None
                }
            }
        }?;

        let prevout_len = 32 + 4;
        let script_sig_len = CompactSize::serialized_size(script_len) + script_len;
        let sequence_len = 4;
        Some(prevout_len + script_sig_len + sequence_len)
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

    /// Adds a coin (the output of a previous transaction) to be spent in the transaction.
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

        self.inputs.push(TransparentInputInfo {
            kind: InputKind::P2pkh { pubkey },
            utxo,
            coin,
        });

        Ok(())
    }

    /// Adds a P2SH coin (the output of a previous transaction) to be spent in the
    /// transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_p2sh_input(
        &mut self,
        redeem_script: Script,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        // Ensure that the RIPEMD-160 digest of the public key associated with the
        // provided secret key matches that of the address to which the provided
        // output may be spent.
        match coin.script_pubkey.address() {
            Some(TransparentAddress::ScriptHash(hash)) => {
                use ripemd::Ripemd160;
                use sha2::Sha256;

                if hash[..] != Ripemd160::digest(Sha256::digest(&redeem_script.0))[..] {
                    return Err(Error::InvalidAddress);
                }
            }
            _ => return Err(Error::InvalidAddress),
        }

        self.inputs.push(TransparentInputInfo {
            kind: InputKind::P2sh { redeem_script },
            utxo,
            coin,
        });

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
            .into_iter()
            .map(|i| pczt::Input {
                prevout_txid: i.utxo.hash,
                prevout_index: i.utxo.n,
                sequence: None,
                required_time_lock_time: None,
                required_height_lock_time: None,
                script_sig: None,
                value: i.coin.value,
                script_pubkey: i.coin.script_pubkey,
                redeem_script: match i.kind {
                    InputKind::P2pkh { .. } => None,
                    InputKind::P2sh { redeem_script } => Some(redeem_script),
                },
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
                    // We don't currently support providing the redeem script for
                    // user-controlled P2SH addresses, so we only ever see external P2SH
                    // recipients here, for which we never know the redeem script.
                    redeem_script: None,
                    bip32_derivation: BTreeMap::new(),
                    user_address: None,
                    proprietary: BTreeMap::new(),
                })
                .collect();

            Some(pczt::Bundle { inputs, outputs })
        }
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
                match info.kind {
                    InputKind::P2pkh { pubkey } => {
                        // Find the matching signing key.
                        let (sk, _) = signing_set
                            .keys
                            .iter()
                            .find(|(_, pk)| pk == &pubkey)
                            .ok_or(Error::MissingSigningKey)?;

                        let sighash = calculate_sighash(SignableInput {
                            hash_type: SighashType::ALL,
                            index,
                            script_code: &info.coin.script_pubkey, // for p2pkh, always the same as script_pubkey
                            script_pubkey: &info.coin.script_pubkey,
                            value: info.coin.value,
                        });

                        let msg = secp256k1::Message::from_digest_slice(sighash.as_ref())
                            .expect("32 bytes");
                        let sig = signing_set.secp.sign_ecdsa(&msg, sk);

                        // Signature has to have "SIGHASH_ALL" appended to it
                        let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
                        sig_bytes.extend([SIGHASH_ALL]);

                        // P2PKH scriptSig
                        Ok(Script::default() << &sig_bytes[..] << &pubkey.serialize()[..])
                    }
                    // P2SH is unsupported here; use the PCZT workflow instead.
                    InputKind::P2sh { .. } => Err(Error::InvalidAddress),
                }
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
}
