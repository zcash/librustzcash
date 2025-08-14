use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use bip32::ChildNumber;
use zcash_protocol::{value::Zatoshis, TxId};

use crate::{address::Script, sighash::SighashType};

use super::{Bip32Derivation, Bundle, Input, Output};

impl Bundle {
    /// Parses a PCZT bundle from its component parts.
    pub fn parse(inputs: Vec<Input>, outputs: Vec<Output>) -> Result<Self, ParseError> {
        Ok(Self { inputs, outputs })
    }
}

impl Input {
    /// Parses a PCZT input from its component parts.
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        prevout_txid: [u8; 32],
        prevout_index: u32,
        sequence: Option<u32>,
        required_time_lock_time: Option<u32>,
        required_height_lock_time: Option<u32>,
        script_sig: Option<Vec<u8>>,
        value: u64,
        script_pubkey: Vec<u8>,
        redeem_script: Option<Vec<u8>>,
        partial_signatures: BTreeMap<[u8; 33], Vec<u8>>,
        sighash_type: u8,
        bip32_derivation: BTreeMap<[u8; 33], Bip32Derivation>,
        ripemd160_preimages: BTreeMap<[u8; 20], Vec<u8>>,
        sha256_preimages: BTreeMap<[u8; 32], Vec<u8>>,
        hash160_preimages: BTreeMap<[u8; 20], Vec<u8>>,
        hash256_preimages: BTreeMap<[u8; 32], Vec<u8>>,
        proprietary: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, ParseError> {
        let prevout_txid = TxId::from_bytes(prevout_txid);

        match required_time_lock_time {
            None | Some(500000000..) => Ok(()),
            Some(_) => Err(ParseError::InvalidRequiredTimeLocktime),
        }?;

        match required_height_lock_time {
            None | Some(1..=499999999) => Ok(()),
            Some(_) => Err(ParseError::InvalidRequiredHeightLocktime),
        }?;

        // TODO: Verify that the script is not nonsense.
        let script_sig = script_sig.map(Script);

        let value = Zatoshis::from_u64(value).map_err(|_| ParseError::InvalidValue)?;

        // TODO: Verify that the script is not nonsense.
        let script_pubkey = Script(script_pubkey);

        // TODO: Verify that the script is not nonsense.
        let redeem_script = redeem_script.map(Script);

        let sighash_type =
            SighashType::parse(sighash_type).ok_or(ParseError::InvalidSighashType)?;

        Ok(Self {
            prevout_txid,
            prevout_index,
            sequence,
            required_time_lock_time,
            required_height_lock_time,
            script_sig,
            value,
            script_pubkey,
            redeem_script,
            partial_signatures,
            sighash_type,
            bip32_derivation,
            ripemd160_preimages,
            sha256_preimages,
            hash160_preimages,
            hash256_preimages,
            proprietary,
        })
    }
}

impl Output {
    /// Parses a PCZT output from its component parts.
    pub fn parse(
        value: u64,
        script_pubkey: Vec<u8>,
        redeem_script: Option<Vec<u8>>,
        bip32_derivation: BTreeMap<[u8; 33], Bip32Derivation>,
        user_address: Option<String>,
        proprietary: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, ParseError> {
        let value = Zatoshis::from_u64(value).map_err(|_| ParseError::InvalidValue)?;

        // TODO: Verify that the script is not nonsense.
        let script_pubkey = Script(script_pubkey);

        // TODO: Verify that the script is not nonsense.
        let redeem_script = redeem_script.map(Script);

        Ok(Self {
            value,
            script_pubkey,
            redeem_script,
            bip32_derivation,
            user_address,
            proprietary,
        })
    }
}

impl Bip32Derivation {
    /// Parses a BIP 32 derivation path from its component parts.
    pub fn parse(
        seed_fingerprint: [u8; 32],
        derivation_path: Vec<u32>,
    ) -> Result<Self, ParseError> {
        Ok(Self {
            seed_fingerprint,
            derivation_path: derivation_path.into_iter().map(ChildNumber).collect(),
        })
    }
}

/// Errors that can occur while parsing a PCZT bundle.
#[derive(Debug)]
pub enum ParseError {
    InvalidRequiredHeightLocktime,
    InvalidRequiredTimeLocktime,
    /// An invalid `sighash_type` was provided.
    InvalidSighashType,
    /// An invalid `value` was provided.
    InvalidValue,
}
