use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use bip32::ChildNumber;
use zcash_protocol::{TxId, value::Zatoshis};
use zcash_script::script;

use crate::sighash::SighashType;

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

        let script_sig = script_sig
            .map(|s| parse_script_sig(s).ok_or(ParseError::InvalidScriptSig))
            .transpose()?;

        let value = Zatoshis::from_u64(value).map_err(|_| ParseError::InvalidValue)?;

        let script_pubkey =
            parse_script_from_chain(script_pubkey).ok_or(ParseError::InvalidScriptPubkey)?;

        let redeem_script = redeem_script
            .map(|s| parse_script_from_chain(s).ok_or(ParseError::InvalidRedeemScript))
            .transpose()?;

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

        let script_pubkey =
            parse_script_pubkey(script_pubkey).ok_or(ParseError::InvalidScriptPubkey)?;

        let redeem_script = redeem_script
            .map(|s| parse_script_pubkey(s).ok_or(ParseError::InvalidRedeemScript))
            .transpose()?;

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

fn parse_script_from_chain(script_code: Vec<u8>) -> Option<script::FromChain> {
    script::FromChain::parse(&script::Code(script_code)).ok()
}

fn parse_script_pubkey(script_pubkey: Vec<u8>) -> Option<script::PubKey> {
    script::PubKey::parse(&script::Code(script_pubkey)).ok()
}

fn parse_script_sig(script_sig: Vec<u8>) -> Option<script::Sig> {
    script::Sig::parse(&script::Code(script_sig)).ok()
}

/// Errors that can occur while parsing a PCZT bundle.
#[derive(Debug)]
pub enum ParseError {
    /// An invalid `redeem_script` was provided.
    InvalidRedeemScript,
    InvalidRequiredHeightLocktime,
    InvalidRequiredTimeLocktime,
    /// An invalid `script_pubkey` was provided.
    InvalidScriptPubkey,
    /// An invalid `script_sig` was provided.
    InvalidScriptSig,
    /// An invalid `sighash_type` was provided.
    InvalidSighashType,
    /// An invalid `value` was provided.
    InvalidValue,
}
