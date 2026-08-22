//! Solana Pay transfer and interactive transaction requests.
//!
//! Implements the [Solana Pay specification]: non-interactive `solana:<recipient>?...` transfer
//! requests (native SOL or an SPL token, identified by its mint address), and interactive
//! `solana:<https-url>` transaction requests, which this crate parses and categorizes but does
//! not itself act on -- consumers decide whether to follow an interactive link.
//!
//! A transaction-request link only needs percent-encoding when it would otherwise contain
//! characters (like a literal `?` introducing its own query string) that would be ambiguous
//! against the outer `solana:` URI's own grammar; a bare link with no query component does not.
//! Both forms appear as valid examples in the spec itself.
//!
//! Unlike BIP-21/BIP-321, which explicitly define query parameter keys as case-insensitive
//! (Bitcoin) or case-sensitive (Litecoin), the Solana Pay spec says nothing about the case
//! sensitivity of its keys -- it only ever shows them in lowercase. This module treats them as
//! case-sensitive (no normalization is applied), matching the spec's own examples literally;
//! `Amount=1` is therefore an unrecognised key, not a match for `amount`.
//!
//! [Solana Pay specification]: https://github.com/solana-foundation/solana-pay/blob/master/SPEC.md

use std::collections::HashSet;

use crate::{DecimalAmount, Error, decode};

const SOL_DECIMAL_PLACES: usize = 9;
const PUBLIC_KEY_BYTES_LEN: usize = 32;

/// A parsed Solana Pay request.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SolanaRequest {
    /// A non-interactive SOL or SPL Token transfer request.
    Transfer(SolanaTransferRequest),
    /// An interactive HTTPS transaction request.
    Transaction(SolanaTransactionRequest),
}

/// A validated Solana Pay transfer request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolanaTransferRequest {
    recipient: String,
    amount: Option<DecimalAmount>,
    spl_token: Option<String>,
    references: Vec<String>,
    label: Option<String>,
    message: Option<String>,
    memo: Option<String>,
}

impl SolanaTransferRequest {
    /// Returns the recipient's base58-encoded public key.
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// Returns the amount in SOL or SPL Token display units.
    pub fn amount(&self) -> Option<&DecimalAmount> {
        self.amount.as_ref()
    }

    /// Returns the SPL Token mint, or `None` for native SOL.
    pub fn spl_token(&self) -> Option<&str> {
        self.spl_token.as_deref()
    }

    /// Returns the ordered reference keys attached to the request.
    pub fn references(&self) -> &[String] {
        &self.references
    }

    /// Returns the decoded request label.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns the decoded request message.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Returns the decoded public memo to include in the transaction.
    pub fn memo(&self) -> Option<&str> {
        self.memo.as_deref()
    }
}

/// A validated interactive Solana Pay transaction request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolanaTransactionRequest {
    link: String,
}

impl SolanaTransactionRequest {
    /// Returns the decoded absolute HTTPS endpoint.
    pub fn link(&self) -> &str {
        &self.link
    }
}

/// Parses and validates a `solana:` transfer or interactive transaction request.
///
/// Examples of accepted input:
/// - `solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=1&label=Michael` (native SOL)
/// - `solana:mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN?amount=0.01&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`
///   (SPL token transfer)
/// - `solana:https://example.com/solana-pay` (interactive request, no query string, no
///   escaping needed)
/// - `solana:https%3A%2F%2Fexample.com%2Fsolana-pay%3Forder%3D12345` (interactive request
///   whose own query string is percent-encoded so it doesn't collide with the outer URI)
///
/// Examples of rejected input:
/// - `solana:https://example.com/solana-pay?order=12345` (an interactive link with an
///   unescaped `?` is ambiguous with the outer URI's own query string, so it must be
///   percent-encoded as above instead)
/// - a `recipient`, `spl-token`, or `reference` value that isn't a well-formed base58 public key
pub(crate) fn parse(input: &str) -> Result<SolanaRequest, Error> {
    let (_, payload) = input.split_once(':').ok_or(Error::MissingScheme)?;
    let decoded_payload = decode(payload)?;
    if is_https_url(&decoded_payload) {
        if payload.contains('?') {
            return Err(Error::InvalidTransactionLink(payload.to_owned()));
        }
        return Ok(SolanaRequest::Transaction(SolanaTransactionRequest {
            link: decoded_payload,
        }));
    }

    let (recipient, query) = payload
        .split_once('?')
        .map_or((payload, None), |(r, q)| (r, Some(q)));
    validate_public_key(recipient)?;

    let mut amount = None;
    let mut spl_token = None;
    let mut references = vec![];
    let mut label = None;
    let mut message = None;
    let mut memo = None;
    let mut seen = HashSet::new();

    for parameter in query.into_iter().flat_map(|query| query.split('&')) {
        let (key, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        if matches!(key, "amount" | "spl-token" | "label" | "message" | "memo") && !seen.insert(key)
        {
            return Err(Error::DuplicateParameter(key.to_owned()));
        }
        match key {
            "amount" => amount = Some(DecimalAmount::parse(value)?),
            "spl-token" => {
                validate_public_key(value)?;
                spl_token = Some(value.to_owned());
            }
            "reference" => {
                validate_public_key(value)?;
                references.push(value.to_owned());
            }
            "label" => label = Some(decode(value)?),
            "message" => message = Some(decode(value)?),
            "memo" => memo = Some(decode(value)?),
            _ => {}
        }
    }

    if let Some(amount) = amount.as_ref()
        && spl_token.is_none()
        && amount.atomic_value(SOL_DECIMAL_PLACES).is_none()
    {
        return Err(Error::InvalidAmount(amount.to_string()));
    }

    Ok(SolanaRequest::Transfer(SolanaTransferRequest {
        recipient: recipient.to_owned(),
        amount,
        spl_token,
        references,
        label,
        message,
        memo,
    }))
}

fn validate_public_key(value: &str) -> Result<(), Error> {
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| Error::InvalidAddress(value.to_owned()))?;
    if decoded.len() == PUBLIC_KEY_BYTES_LEN {
        Ok(())
    } else {
        Err(Error::InvalidAddress(value.to_owned()))
    }
}

fn is_https_url(value: &str) -> bool {
    let Some((scheme, remainder)) = value.split_once("://") else {
        return false;
    };
    scheme.eq_ignore_ascii_case("https")
        && remainder
            .split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| {
                !authority.is_empty() && !authority.chars().any(char::is_whitespace)
            })
}
