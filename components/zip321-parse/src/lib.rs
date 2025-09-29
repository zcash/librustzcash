use core::fmt::Debug;
use std::collections::BTreeMap;

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use nom::{
    bytes::complete::{tag, take_till},
    character::complete::{alpha1, char, digit0, digit1, one_of},
    combinator::{all_consuming, map_opt, map_res, opt, recognize},
    multi::separated_list0,
    sequence::{preceded, separated_pair, tuple},
    AsChar, IResult, InputTakeAtPosition,
};
use percent_encoding::percent_decode;
use snafu::prelude::*;

/// Parsing errors.
#[derive(Debug, Snafu)]
pub enum Error {
    /// The ZIP 321 request included more payments than can be created within a single Zcash
    /// transaction. The wrapped value is the number of payments in the request.
    #[snafu(display("Cannot create a Zcash transation container {count} payments"))]
    TooManyPayments { count: usize },

    /// A memo field in the ZIP 321 URI was not properly base-64 encoded
    #[snafu(display("Memo value was not correctly base64-encoded: {source:?}"))]
    InvalidBase64 { source: base64::DecodeError },

    /// A memo byte array was too long.
    #[snafu(display("Memo length {count} is larger than maximum of 512"))]
    MemoBytesTooLong { count: usize },

    #[snafu(display("Error parsing lead address: {source}"))]
    LeadAddress {
        source: nom::Err<nom::error::Error<String>>,
    },

    #[snafu(display("Error parsing query parameters: {source}"))]
    QueryParams {
        source: nom::Err<nom::error::Error<String>>,
    },

    /// Parsing encountered a duplicate ZIP 321 URI parameter for the returned payment index.
    #[snafu(display("There is a duplicate {} parameter at index {idx}", param.name()))]
    DuplicateParameter { param: Param, idx: usize },

    /// The payment at the wrapped index did not include a recipient address.
    #[snafu(display("Payment {idx} is missing its recipient address"))]
    RecipientMissing { idx: usize },
}

type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Memo {
    pub bytes: Box<[u8; 512]>,
}

impl Memo {
    /// Converts a [`MemoBytes`] value to a ZIP 321 compatible base64-encoded string.
    ///
    /// [`MemoBytes`]: zcash_protocol::memo::MemoBytes
    pub fn to_base64(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.bytes.as_slice())
    }

    /// Parse a [`MemoBytes`] value from a ZIP 321 compatible base64-encoded string.
    ///
    /// [`MemoBytes`]: zcash_protocol::memo::MemoBytes
    pub fn try_from_base64(s: &str) -> Result<Self> {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(s)
            .context(InvalidBase64Snafu)?;

        if bytes.len() > 512 {
            return MemoBytesTooLongSnafu { count: bytes.len() }.fail();
        }

        let mut memo = [0u8; 512];
        memo[..bytes.len()].copy_from_slice(&bytes);
        Ok(Self {
            bytes: Box::new(memo),
        })
    }
}

/// A data type that defines the possible parameter types which may occur within a
/// ZIP 321 URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Addr(String),
    Amount { coins: u64, zatoshis: u64 },
    Memo(Memo),
    Label(String),
    Message(String),
    Other(String, String),
}

impl Param {
    /// Returns the name of the parameter from which this value was parsed.
    pub fn name(&self) -> String {
        match self {
            Param::Addr(_) => "address".to_owned(),
            Param::Amount { .. } => "amount".to_owned(),
            Param::Memo(_) => "memo".to_owned(),
            Param::Label(_) => "label".to_owned(),
            Param::Message(_) => "message".to_owned(),
            Param::Other(name, _) => name.clone(),
        }
    }
}

/// A [`Param`] value with its associated index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedParam {
    pub param: Param,
    pub payment_index: usize,
}

/// Utility function for determining parameter uniqueness.
///
/// Utility function for determining whether a newly parsed param is a duplicate
/// of a previous parameter.
pub fn has_duplicate_param(v: &[Param], p: &Param) -> bool {
    for p0 in v {
        match (p0, p) {
            (Param::Addr(_), Param::Addr(_)) => return true,
            (Param::Amount { .. }, Param::Amount { .. }) => return true,
            (Param::Memo(_), Param::Memo(_)) => return true,
            (Param::Label(_), Param::Label(_)) => return true,
            (Param::Message(_), Param::Message(_)) => return true,
            (Param::Other(n, _), Param::Other(n0, _)) if (n == n0) => return true,
            _otherwise => continue,
        }
    }

    false
}

/// Parses and consumes the leading "zcash:\[address\]" from a ZIP 321 URI.
pub fn lead_addr(input: &str) -> IResult<&str, Option<IndexedParam>> {
    let (i, addr_str) = preceded(tag("zcash:"), take_till(|c| c == '?'))(input)?;
    if addr_str.is_empty() {
        Ok((i, None)) // no address is ok
    } else {
        // TODO: add ZcashAddress parsing of the string later, in zip321

        // `try_from_encoded(..).ok()` returns `None` on error, which we want to then
        // cause `map_opt` to fail.
        // ZcashAddress::try_from_encoded(addr_str)
        //     .map(|a| {
        //         Some(IndexedParam {
        //             param: Param::Addr(Box::new(a)),
        //             payment_index: 0,
        //         })
        //     })
        //     .ok()
        Ok((
            i,
            Some(IndexedParam {
                param: Param::Addr(addr_str.to_owned()),
                payment_index: 0,
            }),
        ))
    }
}

/// The primary parser for `name=value` query-string parameter pairs.
pub fn zcashparam(input: &str) -> IResult<&str, IndexedParam> {
    map_res(
        separated_pair(indexed_name, char('='), recognize(qchars)),
        to_indexed_param,
    )(input)
}

/// Extension for the `alphanumeric0` parser which extends that parser
/// by also permitting the characters that are members of the `allowed`
/// string.
fn alphanum_or(allowed: &str) -> impl (Fn(&str) -> IResult<&str, &str>) + '_ {
    move |input| {
        input.split_at_position_complete(|item| {
            let c = item.as_char();
            !(c.is_alphanum() || allowed.contains(c))
        })
    }
}

/// Parses valid characters which may appear in parameter values.
pub fn qchars(input: &str) -> IResult<&str, &str> {
    alphanum_or("-._~!$'()*+,;:@%")(input)
}

/// Parses valid characters that may appear in parameter names.
pub fn namechars(input: &str) -> IResult<&str, &str> {
    alphanum_or("+-")(input)
}

/// Parses a parameter name and its associated index.
pub fn indexed_name(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    let paramname = recognize(tuple((alpha1, namechars)));

    tuple((
        paramname,
        opt(preceded(
            char('.'),
            recognize(tuple((
                one_of("123456789"),
                map_opt(digit0, |s: &str| if s.len() > 3 { None } else { Some(s) }),
            ))),
        )),
    ))(input)
}

/// Parses a value in decimal ZEC.
pub fn parse_amount(input: &str) -> IResult<&str, (u64, u64)> {
    map_res(
        all_consuming(tuple((
            digit1,
            opt(preceded(
                char('.'),
                map_opt(digit1, |s: &str| if s.len() > 8 { None } else { Some(s) }),
            )),
        ))),
        |(whole_s, decimal_s): (&str, Option<&str>)| {
            let coins: u64 = whole_s
                .to_string()
                .parse::<u64>()
                .map_err(|e| e.to_string())?;

            let zatoshis: u64 = match decimal_s {
                Some(d) => format!("{d:0<8}")
                    .parse::<u64>()
                    .map_err(|e| e.to_string())?,
                None => 0,
            };
            Ok::<_, String>((coins, zatoshis))

            // TODO:
            // coins
            //     .checked_mul(COIN)
            //     .and_then(|coin_zats| coin_zats.checked_add(zats))
            //     .ok_or(BalanceError::Overflow)
            //     .and_then(Zatoshis::from_u64)
            //     .map_err(|_| format!("Not a valid zat amount: {coins}.{zats}"))
        },
    )(input)
}

fn to_indexed_param(
    ((name, iopt), value): ((&str, Option<&str>), &str),
) -> Result<IndexedParam, String> {
    let param = match name {
        "address" => Ok(Param::Addr(value.to_owned())),
        // TODO(schell): add back in later
        // ZcashAddress::try_from_encoded(value)
        //     .map(Box::new)
        //     .map(Param::Addr)
        //     .map_err(|err| format!("Could not interpret {value} as a valid Zcash address: {err}")),
        "amount" => parse_amount(value)
            .map_err(|e| e.to_string())
            .map(|(_, (coins, zatoshis))| Param::Amount { coins, zatoshis }),

        "label" => percent_decode(value.as_bytes())
            .decode_utf8()
            .map(|s| Param::Label(s.into_owned()))
            .map_err(|e| e.to_string()),

        "message" => percent_decode(value.as_bytes())
            .decode_utf8()
            .map(|s| Param::Message(s.into_owned()))
            .map_err(|e| e.to_string()),

        "memo" => Memo::try_from_base64(value)
            .map(Param::Memo)
            .map_err(|e| format!("Decoded memo was invalid: {e:?}")),
        other if other.starts_with("req-") => {
            Err(format!("Required parameter {other} not recognized"))
        }

        other => percent_decode(value.as_bytes())
            .decode_utf8()
            .map(|s| Param::Other(other.to_string(), s.into_owned()))
            .map_err(|e| e.to_string()),
    }?;

    let payment_index = match iopt {
        Some(istr) => istr.parse::<usize>().map(Some).map_err(|e| e.to_string()),
        None => Ok(None),
    }?;

    Ok(IndexedParam {
        param,
        payment_index: payment_index.unwrap_or(0),
    })
}

/// Converts an vector of [`Param`] values to a [`Payment`].
///
/// This function performs checks to ensure that the resulting [`Payment`] is structurally
/// valid; for example, a request for memo contents may not be associated with a
/// transparent payment address.
pub fn to_payment(vs: Vec<Param>, i: usize) -> Result<Payment> {
    let recipient_address = vs
        .iter()
        .find_map(|v| match v {
            Param::Addr(a) => Some(a.clone()),
            _otherwise => None,
        })
        .context(RecipientMissingSnafu { idx: i })?;

    let mut payment = Payment {
        recipient_address,
        amount_coins: 0,
        amount_zatoshis: 0,
        memo: None,
        label: None,
        message: None,
        other_params: vec![],
    };

    for v in vs {
        match v {
            Param::Amount { coins, zatoshis } => {
                payment.amount_coins = coins;
                payment.amount_zatoshis = zatoshis;
            }
            Param::Memo(m) => {
                // TODO(schell): add this check to main crate
                // if payment.recipient_address.can_receive_memo() {
                //     payment.memo = Some(*m);
                // } else {
                //     return Err(Zip321Error::TransparentMemo(i));
                // }
                payment.memo = Some(m);
            }
            Param::Label(m) => payment.label = Some(m),
            Param::Message(m) => payment.message = Some(m),
            Param::Other(n, m) => payment.other_params.push((n, m)),
            _otherwise => {}
        }
    }

    Ok(payment)
}

/// A single payment being requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    // TODO(schell): changed
    /// The address to which the payment should be sent.
    recipient_address: String,
    // TODO(schell): changed, make separate types for whole and fractional
    /// The amount of the payment that is being requested.
    amount_coins: u64,
    amount_zatoshis: u64,
    // TODO(schell): changed
    /// A memo that, if included, must be provided with the payment.
    /// If a memo is present and [`recipient_address`] is not a shielded
    /// address, the wallet should report an error.
    ///
    /// [`recipient_address`]: #structfield.recipient_address
    memo: Option<Memo>,
    /// A human-readable label for this payment within the larger structure
    /// of the transaction request.
    label: Option<String>,
    /// A human-readable message to be displayed to the user describing the
    /// purpose of this payment.
    message: Option<String>,
    /// A list of other arbitrary key/value pairs associated with this payment.
    other_params: Vec<(String, String)>,
}

impl Payment {
    /// Constructs a new [`Payment`] from its constituent parts.
    ///
    /// Returns `None` if the payment requests that a memo be sent to a recipient that cannot
    /// receive a memo.
    pub fn new(
        recipient_address: String,
        amount: (u64, u64),
        memo: Option<Memo>,
        label: Option<String>,
        message: Option<String>,
        other_params: Vec<(String, String)>,
    ) -> Option<Self> {
        if memo.is_none() {
            Some(Self {
                recipient_address,
                amount_coins: amount.0,
                amount_zatoshis: amount.1,
                memo,
                label,
                message,
                other_params,
            })
        } else {
            None
        }
    }

    /// Constructs a new [`Payment`] paying the given address the specified amount.
    pub fn without_memo(recipient_address: String, amount: (u64, u64)) -> Self {
        Self {
            recipient_address,
            amount_coins: amount.0,
            amount_zatoshis: amount.0,
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        }
    }

    /// Returns the payment address to which the payment should be sent.
    pub fn recipient_address_str(&self) -> &str {
        &self.recipient_address
    }

    /// Returns the integer ZEC value of the payment that is being requested.
    pub fn amount_coins(&self) -> u64 {
        self.amount_coins
    }

    /// Returns the integer zatoshis value of the payment that is being requested, after
    /// subtracting the whole integer ZEC.
    pub fn amount_zatoshis_remainder(&self) -> u64 {
        self.amount_zatoshis
    }

    // TODO(schell): add pub fn amount(&self) -> Zatoshis in the main crate

    // TODO(schell): add in the main crate
    // /// Returns the memo that, if included, must be provided with the payment.
    // pub fn memo_string(&self) -> Option<&str> {
    //     self.memo.as_deref()
    // }

    /// Returns the memo that, if included, must be provided with the payment.
    pub fn memo_bytes(&self) -> Option<&[u8; 512]> {
        self.memo.as_ref().map(|m| m.bytes.as_ref())
    }

    /// A human-readable label for this payment within the larger structure
    /// of the transaction request.
    pub fn label(&self) -> Option<&String> {
        self.label.as_ref()
    }

    /// A human-readable message to be displayed to the user describing the
    /// purpose of this payment.
    pub fn message(&self) -> Option<&String> {
        self.message.as_ref()
    }

    /// A list of other arbitrary key/value pairs associated with this payment.
    pub fn other_params(&self) -> &[(String, String)] {
        self.other_params.as_ref()
    }

    /// A utility for use in tests to help check round-trip serialization properties.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub(crate) fn normalize(&mut self) {
        self.other_params.sort();
    }
}

/// A ZIP321 transaction request.
///
/// A ZIP 321 request may include one or more such requests for payment.
/// When constructing a transaction in response to such a request,
/// a separate output should be added to the transaction for each
/// payment value in the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRequest {
    payments: BTreeMap<usize, Payment>,
}

impl TransactionRequest {
    /// Constructs a new empty transaction request.
    pub fn empty() -> Self {
        Self {
            payments: BTreeMap::new(),
        }
    }

    /// Constructs a new transaction request that obeys the ZIP-321 invariants.
    pub fn new(payments: Vec<Payment>) -> Result<TransactionRequest> {
        // Payment indices are limited to 4 digits
        if payments.len() > 9999 {
            return TooManyPaymentsSnafu {
                count: payments.len(),
            }
            .fail();
        }

        let request = TransactionRequest {
            payments: payments.into_iter().enumerate().collect(),
        };

        // Enforce validity requirements.
        if !request.payments.is_empty() {
            TransactionRequest::from_uri(&request.to_uri())?;
        }

        Ok(request)
    }

    /// Constructs a new transaction request from the provided map from payment
    /// index to payment.
    ///
    /// Payment index 0 will be mapped to the empty payment index.
    pub fn from_indexed(payments: BTreeMap<usize, Payment>) -> Result<TransactionRequest> {
        if let Some(k) = payments.keys().find(|k| **k > 9999) {
            // This is not quite the correct error, but close enough.
            return TooManyPaymentsSnafu { count: *k }.fail();
        }

        Ok(TransactionRequest { payments })
    }

    /// Returns the map of payments that make up this request.
    ///
    /// This is a map from payment index to payment. Payment index `0` is used to denote
    /// the empty payment index in the returned values.
    pub fn payments(&self) -> &BTreeMap<usize, Payment> {
        &self.payments
    }

    /// A utility for use in tests to help check round-trip serialization properties.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub(crate) fn normalize(&mut self) {
        for p in &mut self.payments.values_mut() {
            p.normalize();
        }
    }

    /// A utility for use in tests to help check round-trip serialization properties.
    /// by comparing a two transaction requests for equality after normalization.
    #[cfg(test)]
    pub(crate) fn normalize_and_eq(a: &mut TransactionRequest, b: &mut TransactionRequest) -> bool {
        a.normalize();
        b.normalize();

        a == b
    }

    /// Convert this request to a URI string.
    ///
    /// Returns None if the payment request is empty.
    pub fn to_uri(&self) -> String {
        fn payment_params(
            payment: &Payment,
            payment_index: Option<usize>,
        ) -> impl IntoIterator<Item = String> + '_ {
            std::iter::empty()
                .chain(Some(render::amount_param(
                    (payment.amount_coins, payment.amount_zatoshis),
                    payment_index,
                )))
                .chain(
                    payment
                        .memo
                        .as_ref()
                        .map(|m| render::memo_param(m, payment_index)),
                )
                .chain(
                    payment
                        .label
                        .as_ref()
                        .map(|m| render::str_param("label", m, payment_index)),
                )
                .chain(
                    payment
                        .message
                        .as_ref()
                        .map(|m| render::str_param("message", m, payment_index)),
                )
                .chain(
                    payment
                        .other_params
                        .iter()
                        .map(move |(name, value)| render::str_param(name, value, payment_index)),
                )
        }

        match self.payments.len() {
            0 => "zcash:".to_string(),
            1 if *self.payments.iter().next().unwrap().0 == 0 => {
                let (_, payment) = self.payments.iter().next().unwrap();
                let query_params = payment_params(payment, None)
                    .into_iter()
                    .collect::<Vec<String>>();

                format!(
                    "zcash:{}{}{}",
                    // TODO(schell):
                    // payment.recipient_address.encode(),
                    payment.recipient_address,
                    if query_params.is_empty() { "" } else { "?" },
                    query_params.join("&")
                )
            }
            _ => {
                let query_params = self
                    .payments
                    .iter()
                    .flat_map(|(i, payment)| {
                        let idx = if *i == 0 { None } else { Some(*i) };
                        let primary_address = payment.recipient_address.clone();
                        std::iter::empty()
                            // TODO(schell): mention changed
                            .chain(Some(render::addr_param_encoded(&primary_address, idx)))
                            .chain(payment_params(payment, idx))
                    })
                    .collect::<Vec<String>>();

                format!("zcash:?{}", query_params.join("&"))
            }
        }
    }

    /// Parse the provided URI to a payment request value.
    pub fn from_uri(uri: &str) -> Result<Self> {
        // Parse the leading zcash:<address>
        let (rest, primary_addr_param) = lead_addr(uri)
            .map_err(|e| e.to_owned())
            .context(LeadAddressSnafu)?;

        // Parse the remaining parameters as an undifferentiated list
        let (_, xs) = if rest.is_empty() {
            ("", vec![])
        } else {
            all_consuming(preceded(char('?'), separated_list0(char('&'), zcashparam)))(rest)
                .map_err(|e| e.to_owned())
                .context(QueryParamsSnafu)?
        };

        // Construct sets of payment parameters, keyed by the payment index.
        let mut params_by_index: BTreeMap<usize, Vec<Param>> = BTreeMap::new();

        // Add the primary address, if any, to the index.
        if let Some(p) = primary_addr_param {
            params_by_index.insert(p.payment_index, vec![p.param]);
        }

        // Group the remaining parameters by payment index
        for p in xs {
            match params_by_index.get_mut(&p.payment_index) {
                None => {
                    params_by_index.insert(p.payment_index, vec![p.param]);
                }

                Some(current) => {
                    if has_duplicate_param(current, &p.param) {
                        return DuplicateParameterSnafu {
                            param: p.param.clone(),
                            idx: p.payment_index,
                        }
                        .fail();
                    } else {
                        current.push(p.param);
                    }
                }
            }
        }

        // Build the actual payment values from the index.
        params_by_index
            .into_iter()
            .map(|(i, params)| to_payment(params, i).map(|payment| (i, payment)))
            .collect::<Result<BTreeMap<usize, Payment>, _>>()
            .map(|payments| TransactionRequest { payments })
    }
}

mod render {
    use super::*;
    use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

    /// The set of ASCII characters that must be percent-encoded according
    /// to the definition of ZIP 321. This is the complement of the subset of
    /// ASCII characters defined by `qchar`
    ///
    //      unreserved      = ALPHA / DIGIT / "-" / "." / "_" / "~"
    //      allowed-delims  = "!" / "$" / "'" / "(" / ")" / "*" / "+" / "," / ";"
    //      qchar           = unreserved / pct-encoded / allowed-delims / ":" / "@"
    pub const QCHAR_ENCODE: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'%')
        .add(b'&')
        .add(b'/')
        .add(b'<')
        .add(b'=')
        .add(b'>')
        .add(b'?')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'^')
        .add(b'`')
        .add(b'{')
        .add(b'|')
        .add(b'}');

    /// Converts a parameter index value to the `String` representation
    /// that must be appended to a parameter name when constructing a ZIP 321 URI.
    pub fn param_index(idx: Option<usize>) -> String {
        match idx {
            Some(i) if i > 0 => format!(".{i}"),
            _otherwise => "".to_string(),
        }
    }

    // TODO(schell): add in the main crate
    // /// Constructs an "address" key/value pair containing the encoded recipient address
    // /// at the specified parameter index.
    // pub fn addr_param(addr: &ZcashAddress, idx: Option<usize>) -> String {
    //     format!("address{}={}", param_index(idx), addr.encode())
    // }

    /// Constructs an "address" key/value pair containing the encoded recipient address
    /// at the specified parameter index.
    pub fn addr_param_encoded(encoded_addr: &str, idx: Option<usize>) -> String {
        format!("address{}={}", param_index(idx), encoded_addr)
    }

    // TODO(schell):
    // /// Converts a [`Zatoshis`] value to a correctly formatted decimal ZEC
    // /// value for inclusion in a ZIP 321 URI.
    // pub fn amount_str(amount: Zatoshis) -> String {
    //     let coins = u64::from(amount) / COIN;
    //     let zats = u64::from(amount) % COIN;
    //     amount_coins_zats_str(coins, zats)
    // }

    /// Converts a `(coins, zatoshis_remainder)` value to a correctly formatted decimal ZEC
    /// value for inclusion in a ZIP 321 URI.
    pub fn amount_coins_zats_str(coins: u64, zats: u64) -> String {
        if zats == 0 {
            format!("{coins}")
        } else {
            format!("{coins}.{zats:0>8}")
                .trim_end_matches('0')
                .to_string()
        }
    }

    /// Constructs an "amount" key/value pair containing the encoded ZEC amount
    /// at the specified parameter index.
    pub fn amount_param(amount: (u64, u64), idx: Option<usize>) -> String {
        format!(
            "amount{}={}",
            param_index(idx),
            amount_coins_zats_str(amount.0, amount.1)
        )
    }

    /// Constructs a "memo" key/value pair containing the base64URI-encoded memo
    /// at the specified parameter index.
    pub fn memo_param(value: &Memo, idx: Option<usize>) -> String {
        format!("{}{}={}", "memo", param_index(idx), value.to_base64())
    }

    /// Utility function for an arbitrary string key/value pair for inclusion in
    /// a ZIP 321 URI at the specified parameter index.
    pub fn str_param(label: &str, value: &str, idx: Option<usize>) -> String {
        format!(
            "{}{}={}",
            label,
            param_index(idx),
            utf8_percent_encode(value, QCHAR_ENCODE)
        )
    }
}
