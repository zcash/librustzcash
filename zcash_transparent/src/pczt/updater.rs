use alloc::string::String;
use alloc::vec::Vec;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::address::{Script, TransparentAddress};

use super::{Bip32Derivation, Bundle, Input, Output};

impl Bundle {
    /// Updates the bundle with information provided in the given closure.
    pub fn update_with<F>(&mut self, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(Updater<'_>) -> Result<(), UpdaterError>,
    {
        f(Updater(self))
    }
}

/// An updater for a transparent PCZT bundle.
pub struct Updater<'a>(&'a mut Bundle);

impl Updater<'_> {
    /// Provides read access to the bundle being updated.
    pub fn bundle(&self) -> &Bundle {
        self.0
    }

    /// Updates the input at the given index with information provided in the given
    /// closure.
    pub fn update_input_with<F>(&mut self, index: usize, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(InputUpdater<'_>) -> Result<(), UpdaterError>,
    {
        f(InputUpdater(
            self.0
                .inputs
                .get_mut(index)
                .ok_or(UpdaterError::InvalidIndex)?,
        ))
    }

    /// Updates the input at the given index with information provided in the given
    /// closure.
    pub fn update_output_with<F>(&mut self, index: usize, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(OutputUpdater<'_>) -> Result<(), UpdaterError>,
    {
        f(OutputUpdater(
            self.0
                .outputs
                .get_mut(index)
                .ok_or(UpdaterError::InvalidIndex)?,
        ))
    }
}

/// An updater for a transparent PCZT input.
pub struct InputUpdater<'a>(&'a mut Input);

impl InputUpdater<'_> {
    /// Sets the redeem script for this input.
    ///
    /// Returns an error if the input is not P2SH, or the given `redeem_script` does not
    /// match the input's `script_pubkey`.
    pub fn set_redeem_script(&mut self, redeem_script: Script) -> Result<(), UpdaterError> {
        if let Some(TransparentAddress::ScriptHash(hash)) = self.0.script_pubkey.address() {
            if hash[..] == Ripemd160::digest(Sha256::digest(&redeem_script.0))[..] {
                self.0.redeem_script = Some(redeem_script);
                Ok(())
            } else {
                Err(UpdaterError::WrongRedeemScript)
            }
        } else {
            Err(UpdaterError::NotP2sh)
        }
    }

    /// Sets the BIP 32 derivation path for the given pubkey.
    pub fn set_bip32_derivation(&mut self, pubkey: [u8; 33], derivation: Bip32Derivation) {
        self.0.bip32_derivation.insert(pubkey, derivation);
    }

    /// Stores the given value along with `key = RIPEMD160(value)`.
    pub fn set_ripemd160_preimage(&mut self, value: Vec<u8>) {
        let hash = Ripemd160::digest(&value);
        self.0.ripemd160_preimages.insert(hash.into(), value);
    }

    /// Stores the given value along with `key = SHA256(value)`.
    pub fn set_sha256_preimage(&mut self, value: Vec<u8>) {
        let hash = Sha256::digest(&value);
        self.0.sha256_preimages.insert(hash.into(), value);
    }

    /// Stores the given value along with `key = RIPEMD160(SHA256(value))`.
    pub fn set_hash160_preimage(&mut self, value: Vec<u8>) {
        let hash = Ripemd160::digest(Sha256::digest(&value));
        self.0.hash160_preimages.insert(hash.into(), value);
    }

    /// Stores the given value along with `key = SHA256(SHA256(value))`.
    pub fn set_hash256_preimage(&mut self, value: Vec<u8>) {
        let hash = Sha256::digest(Sha256::digest(&value));
        self.0.hash256_preimages.insert(hash.into(), value);
    }

    /// Stores the given proprietary value at the given key.
    pub fn set_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.proprietary.insert(key, value);
    }
}

/// An updater for a transparent PCZT output.
pub struct OutputUpdater<'a>(&'a mut Output);

impl OutputUpdater<'_> {
    /// Sets the redeem script for this output.
    ///
    /// Returns an error if the output is not P2SH, or the given `redeem_script` does not
    /// match the output's `script_pubkey`.
    pub fn set_redeem_script(&mut self, redeem_script: Script) -> Result<(), UpdaterError> {
        if let Some(TransparentAddress::ScriptHash(hash)) = self.0.script_pubkey.address() {
            if hash[..] == Ripemd160::digest(Sha256::digest(&redeem_script.0))[..] {
                self.0.redeem_script = Some(redeem_script);
                Ok(())
            } else {
                Err(UpdaterError::WrongRedeemScript)
            }
        } else {
            Err(UpdaterError::NotP2sh)
        }
    }

    /// Sets the BIP 32 derivation path for the given pubkey.
    pub fn set_bip32_derivation(&mut self, pubkey: [u8; 33], derivation: Bip32Derivation) {
        self.0.bip32_derivation.insert(pubkey, derivation);
    }

    /// Sets the user-facing address that the new note is being sent to.
    pub fn set_user_address(&mut self, user_address: String) {
        self.0.user_address = Some(user_address);
    }

    /// Stores the given proprietary value at the given key.
    pub fn set_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.proprietary.insert(key, value);
    }
}

/// Errors that can occur while signing a transparent input in a PCZT.
#[derive(Debug)]
pub enum UpdaterError {
    /// An out-of-bounds index was provided when looking up an input or output.
    InvalidIndex,
    /// A `redeem_script` can only be set on a P2SH coin.
    NotP2sh,
    /// The provided `redeem_script` does not match the input's `script_pubkey`.
    WrongRedeemScript,
}
