//! Bitcoin and Litecoin on-chain payment requests.
//!
//! Bitcoin URIs implement the on-chain subset of [BIP 321], the modern replacement for the
//! original [BIP 21]. Litecoin URIs follow Litecoin Core's own BIP-21-compatible convention
//! (case-sensitive parameter keys, and its own base58 version bytes), rather than BIP 321.
//!
//! Only the on-chain payment fields (`amount`, `label`, `message`) are implemented. BIP 321
//! also defines a number of alternate-payment-method and privacy extensions this module does
//! not implement -- `lightning` (BOLT 11 invoices), `lno` (BOLT 12 offers), `pay` (BIP 351
//! private payments), `sp` (BIP 352 silent payments), `bc`/`tb` (segwit fallback addresses),
//! and `pop`/`req-pop` (proof-of-payment callbacks). None of those are supported, but per the
//! `req-` convention both BIPs define, an unsupported parameter is only fatal to the request
//! when it is marked required (`req-lno=...`); as a plain optional parameter (`lightning=...`)
//! it is safely ignored, the same as any other wallet that hasn't implemented that extension.
//!
//! [BIP 21]: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
//! [BIP 321]: https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki

use std::collections::HashSet;

use crate::{DecimalAmount, Error, decode};

const MAX_FRACTIONAL_DIGITS: usize = 8;

/// Length in bytes of the RIPEMD160(SHA256(...)) hash carried by a legacy P2PKH or P2SH address,
/// after the leading version byte.
const HASH160_LEN: usize = 20;

/// Base58Check version byte for a Bitcoin mainnet P2PKH address ("1..."). See [BIP 13].
///
/// [BIP 13]: https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
const BITCOIN_MAINNET_P2PKH: u8 = 0;
/// Base58Check version byte for a Bitcoin mainnet P2SH address ("3..."). See [BIP 13].
///
/// [BIP 13]: https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
const BITCOIN_MAINNET_P2SH: u8 = 5;
/// Base58Check version byte for a Bitcoin testnet/regtest P2PKH address ("m.../n...").
const BITCOIN_TESTNET_P2PKH: u8 = 111;
/// Base58Check version byte for a Bitcoin testnet/regtest P2SH address ("2...").
const BITCOIN_TESTNET_P2SH: u8 = 196;

/// Base58Check version byte for a Litecoin mainnet P2PKH address ("L...").
const LITECOIN_MAINNET_P2PKH: u8 = 48;
/// Base58Check version byte for a Litecoin mainnet P2SH address ("M..."), current form.
const LITECOIN_MAINNET_P2SH: u8 = 50;
/// Base58Check version byte for a Litecoin mainnet P2SH address, legacy form ("3...").
///
/// Litecoin Core still accepts this on decode for backward compatibility with addresses
/// generated before the switch to [`LITECOIN_MAINNET_P2SH`]; it collides with
/// [`BITCOIN_MAINNET_P2SH`], since Litecoin originally reused Bitcoin's P2SH prefix.
const LITECOIN_MAINNET_P2SH_LEGACY: u8 = 5;
/// Base58Check version byte for a Litecoin testnet P2PKH address ("Q...").
const LITECOIN_TESTNET_P2PKH: u8 = 58;

#[derive(Clone, Copy)]
pub(crate) enum Currency {
    Bitcoin,
    Litecoin,
}

/// The network encoded by a Bitcoin or Litecoin address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Network {
    /// The production network.
    Mainnet,
    /// A public test network.
    Testnet,
    /// A local regression-test network.
    Regtest,
}

impl Network {
    /// Returns the lowercase name used in this crate's versioned JSON representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }
}

/// A validated Bitcoin or Litecoin on-chain payment request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtxoPaymentRequest {
    address: String,
    network: Network,
    amount: Option<DecimalAmount>,
    label: Option<String>,
    message: Option<String>,
}

impl UtxoPaymentRequest {
    /// Returns the validated recipient address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns the network encoded by the recipient address.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the requested amount in BTC or LTC display units.
    pub fn amount(&self) -> Option<&DecimalAmount> {
        self.amount.as_ref()
    }

    /// Returns the decoded recipient label, if provided.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns the decoded payment message, if provided.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

/// Parses and validates a `bitcoin:` or `litecoin:` on-chain payment request.
///
/// Examples of accepted input:
/// - `bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo`
/// - `bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=20.3&label=Luke-Jr`
/// - `litecoin:LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA?amount=1.25&message=Coffee`
///
/// Examples of rejected input:
/// - `bitcoin:` (missing recipient)
/// - `bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?amount=42&amount=42` (duplicate parameter,
///   even when the values agree)
/// - `bitcoin:1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo?req-somethingunknown=1` (unimplemented
///   required extension)
pub(crate) fn parse(input: &str, currency: Currency) -> Result<UtxoPaymentRequest, Error> {
    let (_, payload) = input.split_once(':').ok_or(Error::MissingScheme)?;
    let (address, query) = payload
        .split_once('?')
        .map_or((payload, None), |(a, q)| (a, Some(q)));
    if address.is_empty() {
        return Err(Error::MissingRecipient);
    }
    let network = validate_address(address, currency)?;

    let mut amount = None;
    let mut label = None;
    let mut message = None;
    let mut seen = HashSet::new();

    for parameter in query.into_iter().flat_map(|query| query.split('&')) {
        let (raw_key, raw_value) = parameter.split_once('=').unwrap_or((parameter, ""));
        let normalized = match currency {
            Currency::Bitcoin => raw_key.to_ascii_lowercase(),
            Currency::Litecoin => raw_key.to_owned(),
        };
        let (required, key) = normalized
            .strip_prefix("req-")
            .map_or((false, normalized.as_str()), |key| (true, key));

        if matches!(key, "amount" | "label" | "message") && !seen.insert(key.to_owned()) {
            return Err(Error::DuplicateParameter(key.to_owned()));
        }

        match key {
            "amount" => {
                let parsed = DecimalAmount::parse(raw_value)?;
                if parsed.atomic_value(MAX_FRACTIONAL_DIGITS).is_none() {
                    return Err(Error::InvalidAmount(raw_value.to_owned()));
                }
                amount = Some(parsed);
            }
            "label" => label = Some(decode(raw_value)?),
            "message" => message = Some(decode(raw_value)?),
            _ if required => {
                return Err(Error::UnsupportedRequiredParameter(raw_key.to_owned()));
            }
            _ => {}
        }
    }

    Ok(UtxoPaymentRequest {
        address: address.to_owned(),
        network,
        amount,
        label,
        message,
    })
}

fn validate_address(address: &str, currency: Currency) -> Result<Network, Error> {
    if let Ok((hrp, _, _)) = bech32::segwit::decode(address) {
        let network = match (currency, hrp.as_str()) {
            (Currency::Bitcoin, "bc") | (Currency::Litecoin, "ltc") => Network::Mainnet,
            (Currency::Bitcoin, "tb") | (Currency::Litecoin, "tltc") => Network::Testnet,
            (Currency::Bitcoin, "bcrt") | (Currency::Litecoin, "rltc") => Network::Regtest,
            _ => return Err(Error::InvalidAddress(address.to_owned())),
        };
        return Ok(network);
    }

    let decoded = bs58::decode(address)
        .with_check(None)
        .into_vec()
        .map_err(|_| Error::InvalidAddress(address.to_owned()))?;
    let [version, payload @ ..] = decoded.as_slice() else {
        return Err(Error::InvalidAddress(address.to_owned()));
    };
    if payload.len() != HASH160_LEN {
        return Err(Error::InvalidAddress(address.to_owned()));
    }

    match (currency, *version) {
        (Currency::Bitcoin, BITCOIN_MAINNET_P2PKH | BITCOIN_MAINNET_P2SH)
        | (
            Currency::Litecoin,
            LITECOIN_MAINNET_P2SH_LEGACY | LITECOIN_MAINNET_P2PKH | LITECOIN_MAINNET_P2SH,
        ) => Ok(Network::Mainnet),
        (Currency::Bitcoin, BITCOIN_TESTNET_P2PKH | BITCOIN_TESTNET_P2SH)
        | (
            Currency::Litecoin,
            // Litecoin also accepts Bitcoin's testnet prefixes outright, in addition to its own.
            LITECOIN_TESTNET_P2PKH | BITCOIN_TESTNET_P2PKH | BITCOIN_TESTNET_P2SH,
        ) => Ok(Network::Testnet),
        _ => Err(Error::InvalidAddress(address.to_owned())),
    }
}
