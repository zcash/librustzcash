//! Typed parsing for payment request URIs used by supported cross-chain assets.
//!
//! The parser validates protocol syntax and address encodings. Applications
//! remain responsible for deciding which chains and token contracts they
//! support and for requiring user confirmation before payment.

mod bitcoin;
mod solana;

use core::fmt;

pub use bitcoin::{Network, UtxoPaymentRequest};
pub use solana::{SolanaRequest, SolanaTransactionRequest, SolanaTransferRequest};

/// A non-negative decimal amount represented without floating-point loss.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecimalAmount(String);

impl DecimalAmount {
    fn parse(value: &str) -> Result<Self, Error> {
        let (whole, fraction) = value
            .split_once('.')
            .map_or((value, None), |(w, f)| (w, Some(f)));
        if whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.is_some_and(|digits| {
                digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(Error::InvalidAmount(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact decimal text encoded by the URI.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the number of digits following the decimal point.
    pub fn fractional_digits(&self) -> usize {
        self.0.split_once('.').map_or(0, |(_, digits)| digits.len())
    }

    fn atomic_value(&self, decimal_places: usize) -> Option<u64> {
        if self.fractional_digits() > decimal_places {
            return None;
        }
        let (whole, fraction) = self.0.split_once('.').unwrap_or((&self.0, ""));
        let scale = 10_u64.checked_pow(decimal_places.try_into().ok()?)?;
        let whole = whole.parse::<u64>().ok()?.checked_mul(scale)?;
        let fractional_digits = fraction.len();
        let fraction = fraction.parse::<u64>().unwrap_or(0);
        let padding = 10_u64.checked_pow((decimal_places - fractional_digits).try_into().ok()?)?;
        whole.checked_add(fraction.checked_mul(padding)?)
    }
}

impl fmt::Display for DecimalAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A parsed payment request.
#[derive(Debug)]
#[non_exhaustive]
pub enum PaymentRequest {
    /// A Bitcoin on-chain payment request following the on-chain subset of BIP 321.
    Bitcoin(UtxoPaymentRequest),
    /// An EIP-681 transaction request.
    Ethereum(eip681::TransactionRequest),
    /// A Litecoin payment request using Litecoin Core's BIP-21-compatible format.
    Litecoin(UtxoPaymentRequest),
    /// A Solana Pay transfer or interactive transaction request.
    Solana(SolanaRequest),
}

impl PaymentRequest {
    /// Parses and validates a supported payment request URI.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let (scheme, payload) = input.split_once(':').ok_or(Error::MissingScheme)?;
        if scheme.eq_ignore_ascii_case("bitcoin") {
            bitcoin::parse(input, bitcoin::Currency::Bitcoin).map(Self::Bitcoin)
        } else if scheme.eq_ignore_ascii_case("litecoin") {
            bitcoin::parse(input, bitcoin::Currency::Litecoin).map(Self::Litecoin)
        } else if scheme.eq_ignore_ascii_case("ethereum") {
            eip681::TransactionRequest::parse(&format!("ethereum:{payload}"))
                .map(Self::Ethereum)
                .map_err(Error::Ethereum)
        } else if scheme.eq_ignore_ascii_case("solana") {
            solana::parse(input).map(Self::Solana)
        } else {
            Err(Error::UnsupportedScheme(scheme.to_owned()))
        }
    }
}

/// A payment request parsing or validation error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The input has no URI scheme delimiter.
    MissingScheme,
    /// The URI scheme is not supported.
    UnsupportedScheme(String),
    /// A payment recipient is required but missing.
    MissingRecipient,
    /// An address is malformed for the selected protocol.
    InvalidAddress(String),
    /// A decimal amount is malformed or exceeds protocol precision.
    InvalidAmount(String),
    /// A single-value parameter occurs more than once.
    DuplicateParameter(String),
    /// A required parameter is not implemented by this parser.
    UnsupportedRequiredParameter(String),
    /// A percent-encoded parameter is malformed or is not UTF-8.
    InvalidEncoding(String),
    /// An interactive transaction endpoint is not an absolute HTTPS URL in canonical form.
    InvalidTransactionLink(String),
    /// The delegated EIP-681 parser rejected the request.
    Ethereum(eip681::error::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingScheme => f.write_str("payment request is missing a URI scheme"),
            Self::UnsupportedScheme(scheme) => {
                write!(f, "unsupported payment URI scheme: {scheme}")
            }
            Self::MissingRecipient => f.write_str("payment request is missing a recipient"),
            Self::InvalidAddress(address) => write!(f, "invalid payment address: {address}"),
            Self::InvalidAmount(amount) => write!(f, "invalid payment amount: {amount}"),
            Self::DuplicateParameter(key) => write!(f, "duplicate payment parameter: {key}"),
            Self::UnsupportedRequiredParameter(key) => {
                write!(f, "unsupported required payment parameter: {key}")
            }
            Self::InvalidEncoding(value) => write!(f, "invalid URI encoding: {value}"),
            Self::InvalidTransactionLink(link) => {
                write!(f, "invalid interactive transaction link: {link}")
            }
            Self::Ethereum(error) => write!(f, "invalid EIP-681 request: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ethereum(error) => Some(error),
            _ => None,
        }
    }
}

fn decode(value: &str) -> Result<String, Error> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(Error::InvalidEncoding(value.to_owned()));
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|_| Error::InvalidEncoding(value.to_owned()))
}
