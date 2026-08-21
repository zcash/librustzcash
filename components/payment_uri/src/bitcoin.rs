use std::collections::HashSet;

use crate::{DecimalAmount, Error, decode};

const MAX_FRACTIONAL_DIGITS: usize = 8;

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
    if payload.len() != 20 {
        return Err(Error::InvalidAddress(address.to_owned()));
    }

    match (currency, *version) {
        (Currency::Bitcoin, 0 | 5) | (Currency::Litecoin, 5 | 48 | 50) => Ok(Network::Mainnet),
        (Currency::Bitcoin, 111 | 196) | (Currency::Litecoin, 58 | 111 | 196) => {
            Ok(Network::Testnet)
        }
        _ => Err(Error::InvalidAddress(address.to_owned())),
    }
}
