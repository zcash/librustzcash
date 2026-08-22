//! Typed parsing for payment request URIs used by supported cross-chain assets.
//!
//! The parser validates protocol syntax and address encodings. Applications
//! remain responsible for deciding which chains and token contracts they
//! support and for requiring user confirmation before payment.

mod bitcoin;
mod solana;

use core::fmt;

#[cfg(feature = "json")]
use serde_json::{Value, json};

pub use bitcoin::{Network, UtxoPaymentRequest};
pub use solana::{SolanaRequest, SolanaTransactionRequest, SolanaTransferRequest};

#[cfg(feature = "json")]
/// Version of the JSON representation returned by [`parse_to_json`].
pub const JSON_VERSION: u8 = 1;

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

    #[cfg(feature = "json")]
    fn to_json(&self) -> Value {
        match self {
            Self::Bitcoin(request) => utxo_json("bitcoin", request),
            Self::Ethereum(request) => ethereum_json(request),
            Self::Litecoin(request) => utxo_json("litecoin", request),
            Self::Solana(SolanaRequest::Transfer(request)) => json!({
                "version": JSON_VERSION,
                "type": "solana_transfer",
                "recipient": request.recipient(),
                "amount": request.amount().map(DecimalAmount::as_str),
                "spl_token": request.spl_token(),
                "references": request.references(),
                "label": request.label(),
                "message": request.message(),
                "memo": request.memo(),
            }),
            Self::Solana(SolanaRequest::Transaction(request)) => json!({
                "version": JSON_VERSION,
                "type": "solana_transaction",
                "link": request.link(),
            }),
        }
    }
}

/// Parses a payment request and returns its versioned JSON representation.
#[cfg(feature = "json")]
pub fn parse_to_json(input: &str) -> Result<String, Error> {
    PaymentRequest::parse(input).map(|request| request.to_json().to_string())
}

#[cfg(feature = "json")]
fn utxo_json(request_type: &str, request: &UtxoPaymentRequest) -> Value {
    json!({
        "version": JSON_VERSION,
        "type": request_type,
        "address": request.address(),
        "network": request.network().as_str(),
        "amount": request.amount().map(DecimalAmount::as_str),
        "label": request.label(),
        "message": request.message(),
    })
}

#[cfg(feature = "json")]
fn ethereum_json(request: &eip681::TransactionRequest) -> Value {
    match request {
        eip681::TransactionRequest::NativeRequest(request) => json!({
            "version": JSON_VERSION,
            "type": "ethereum_native",
            "schema_prefix": request.schema_prefix(),
            "has_pay": request.has_pay(),
            "chain_id": request.chain_id().map(|value| value.to_string()),
            "recipient_address": request.recipient_address(),
            "value_hex": request.value_atomic().map(|value| format!("{value:#x}")),
            "gas_limit_hex": request.gas_limit().map(|value| format!("{value:#x}")),
            "gas_price_hex": request.gas_price().map(|value| format!("{value:#x}")),
        }),
        eip681::TransactionRequest::Erc20Request(request) => json!({
            "version": JSON_VERSION,
            "type": "ethereum_erc20",
            "schema_prefix": request.schema_prefix(),
            "has_pay": request.has_pay(),
            "chain_id": request.chain_id().map(|value| value.to_string()),
            "token_contract_address": request.token_contract_address(),
            "recipient_address": request.recipient_address(),
            "value_hex": format!("{:#x}", request.value_atomic()),
        }),
        eip681::TransactionRequest::Unrecognised(_) => json!({
            "version": JSON_VERSION,
            "type": "ethereum_unrecognised",
        }),
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn decimal_amount_accepts_well_formed_values() {
        for valid in ["0", "1", "20.3", "0.00000001", "000123", "1.0", "10.00"] {
            let parsed = DecimalAmount::parse(valid).unwrap_or_else(|_| {
                panic!("expected {valid:?} to parse");
            });
            assert_eq!(parsed.as_str(), valid);
        }
    }

    #[test]
    fn decimal_amount_rejects_malformed_values() {
        for invalid in [
            "",       // empty
            ".",      // neither a whole nor fractional part
            ".5",     // missing whole part
            "1.",     // missing fractional part after the dot
            "-1",     // sign not permitted
            "+1",     // sign not permitted
            "1e5",    // scientific notation not permitted
            "1,5",    // comma is not a valid separator
            "1.5.5",  // more than one decimal point
            " 1",     // leading whitespace
            "1 ",     // trailing whitespace
            "1_000",  // digit-group separators not permitted
            "0x1",    // hex not permitted
            "\u{0}1", // embedded NUL
        ] {
            assert!(
                DecimalAmount::parse(invalid).is_err(),
                "expected {invalid:?} to be rejected"
            );
        }
    }

    #[test]
    fn decimal_amount_fractional_digits_counts_only_the_fraction() {
        assert_eq!(DecimalAmount::parse("5").unwrap().fractional_digits(), 0);
        assert_eq!(DecimalAmount::parse("5.1").unwrap().fractional_digits(), 1);
        assert_eq!(
            DecimalAmount::parse("5.12345678")
                .unwrap()
                .fractional_digits(),
            8
        );
    }

    #[test]
    fn decimal_amount_atomic_value_rejects_excess_precision() {
        let amount = DecimalAmount::parse("1.123").unwrap();
        assert_eq!(amount.atomic_value(3), Some(1_123));
        assert_eq!(amount.atomic_value(2), None);
    }

    #[test]
    fn decimal_amount_atomic_value_rejects_overflow() {
        // u64::MAX is 18446744073709551615 (20 digits); this whole part alone already exceeds it
        // before considering the *8 scale needed for 8 decimal places.
        let amount = DecimalAmount::parse("99999999999999999999").unwrap();
        assert_eq!(amount.atomic_value(8), None);
    }

    proptest! {
        /// Any digit string this crate's own grammar accepts round-trips through `parse` and
        /// `as_str` byte-for-byte -- parsing must not normalize, reformat, or lose precision.
        #[test]
        fn decimal_amount_round_trips_through_parse(
            whole in "[0-9]{1,10}",
            fraction in proptest::option::of("[0-9]{1,8}"),
        ) {
            let text = match &fraction {
                Some(f) => format!("{whole}.{f}"),
                None => whole.clone(),
            };
            let parsed = DecimalAmount::parse(&text).expect("well-formed by construction");
            prop_assert_eq!(parsed.as_str(), text.as_str());
        }

        /// Any value with no more fractional digits than `decimal_places`, and a whole part small
        /// enough not to overflow once scaled, must produce an atomic value satisfying the basic
        /// arithmetic identity `atomic == whole * 10^decimal_places + fraction_padded`.
        #[test]
        fn decimal_amount_atomic_value_matches_arithmetic_identity(
            whole in 0u64..1_000_000_000,
            fraction_digits in 0usize..=8,
        ) {
            let decimal_places = 8;
            let fraction: u64 = if fraction_digits == 0 { 0 } else { 12_345_678 % 10u64.pow(fraction_digits as u32) };
            let text = if fraction_digits == 0 {
                whole.to_string()
            } else {
                format!("{whole}.{fraction:0fraction_digits$}")
            };
            let parsed = DecimalAmount::parse(&text).expect("well-formed by construction");
            let expected = whole * 10u64.pow(decimal_places) + fraction * 10u64.pow((decimal_places as usize - fraction_digits) as u32);
            prop_assert_eq!(parsed.atomic_value(decimal_places as usize), Some(expected));
        }

        /// Must never panic on arbitrary input. This is deliberately the only property checked
        /// here: the round-trip test above already proves well-formed input is accepted
        /// correctly, and `decimal_amount_rejects_malformed_values` already proves specific
        /// malformed cases are rejected. Checking accept/reject correctness for fully arbitrary
        /// strings would need an oracle for "is this well-formed", and the only accurate oracle
        /// for this exact grammar is a reimplementation of parse's own logic -- which wouldn't
        /// catch a bug shared by both copies, so it isn't worth the duplication.
        #[test]
        fn decimal_amount_never_panics_on_arbitrary_strings(s in ".*") {
            let _ = DecimalAmount::parse(&s);
        }
    }
}
