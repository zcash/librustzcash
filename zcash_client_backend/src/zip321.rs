//! Reference implementation of the ZIP-321 standard for payment requests.
//!
//! This module provides data structures, parsing, and rendering functions
//! for interpreting and producing valid ZIP 321 URIs.
//!
//! The specification for ZIP 321 URIs may be found at <https://zips.z.cash/zip-0321>
use core::fmt::Debug;
use std::{
    collections::BTreeMap,
    fmt::{self, Display},
};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use nom::{
    character::complete::char, combinator::all_consuming, multi::separated_list0,
    sequence::preceded,
};
use zcash_primitives::{
    consensus,
    memo::{self, MemoBytes},
    transaction::components::amount::NonNegativeAmount,
};

use crate::address::Address;

/// Errors that may be produced in decoding of payment requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Zip321Error {
    /// A memo field in the ZIP 321 URI was not properly base-64 encoded
    InvalidBase64(base64::DecodeError),
    /// A memo value exceeded 512 bytes in length or could not be interpreted as a UTF-8 string
    /// when using a valid UTF-8 lead byte.
    MemoBytesError(memo::Error),
    /// The ZIP 321 request included more payments than can be created within a single Zcash
    /// transaction. The wrapped value is the number of payments in the request.
    TooManyPayments(usize),
    /// Parsing encountered a duplicate ZIP 321 URI parameter for the returned payment index.
    DuplicateParameter(parse::Param, usize),
    /// The payment at the wrapped index attempted to include a memo when sending to a
    /// transparent recipient address, which is not supported by the protocol.
    TransparentMemo(usize),
    /// The payment at the wrapped index did not include a recipient address.
    RecipientMissing(usize),
    /// The ZIP 321 URI was malformed and failed to parse.
    ParseError(String),
}

impl Display for Zip321Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Zip321Error::InvalidBase64(err) => {
                write!(f, "Memo value was not correctly base64-encoded: {:?}", err)
            }
            Zip321Error::MemoBytesError(err) => write!(
                f,
                "Memo exceeded maximum length or violated UTF-8 encoding restrictions: {:?}",
                err
            ),
            Zip321Error::TooManyPayments(n) => write!(
                f,
                "Cannot create a Zcash transaction containing {} payments",
                n
            ),
            Zip321Error::DuplicateParameter(param, idx) => write!(
                f,
                "There is a duplicate {} parameter at index {}",
                param.name(),
                idx
            ),
            Zip321Error::TransparentMemo(idx) => write!(
                f,
                "Payment {} is invalid: cannot send a memo to a transparent recipient address",
                idx
            ),
            Zip321Error::RecipientMissing(idx) => {
                write!(f, "Payment {} is missing its recipient address", idx)
            }
            Zip321Error::ParseError(s) => write!(f, "Parse failure: {}", s),
        }
    }
}

impl std::error::Error for Zip321Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Zip321Error::InvalidBase64(err) => Some(err),
            Zip321Error::MemoBytesError(err) => Some(err),
            _ => None,
        }
    }
}

/// Converts a [`MemoBytes`] value to a ZIP 321 compatible base64-encoded string.
///
/// [`MemoBytes`]: zcash_primitives::memo::MemoBytes
pub fn memo_to_base64(memo: &MemoBytes) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(memo.as_slice())
}

/// Parse a [`MemoBytes`] value from a ZIP 321 compatible base64-encoded string.
///
/// [`MemoBytes`]: zcash_primitives::memo::MemoBytes
pub fn memo_from_base64(s: &str) -> Result<MemoBytes, Zip321Error> {
    BASE64_URL_SAFE_NO_PAD
        .decode(s)
        .map_err(Zip321Error::InvalidBase64)
        .and_then(|b| MemoBytes::from_bytes(&b).map_err(Zip321Error::MemoBytesError))
}

/// A single payment being requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    /// The payment address to which the payment should be sent.
    pub recipient_address: Address,
    /// The amount of the payment that is being requested.
    pub amount: NonNegativeAmount,
    /// A memo that, if included, must be provided with the payment.
    /// If a memo is present and [`recipient_address`] is not a shielded
    /// address, the wallet should report an error.
    ///
    /// [`recipient_address`]: #structfield.recipient_address
    pub memo: Option<MemoBytes>,
    /// A human-readable label for this payment within the larger structure
    /// of the transaction request.
    pub label: Option<String>,
    /// A human-readable message to be displayed to the user describing the
    /// purpose of this payment.
    pub message: Option<String>,
    /// A list of other arbitrary key/value pairs associated with this payment.
    pub other_params: Vec<(String, String)>,
}

impl Payment {
    /// A utility for use in tests to help check round-trip serialization properties.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub(in crate::zip321) fn normalize(&mut self) {
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
    pub fn new(payments: Vec<Payment>) -> Result<TransactionRequest, Zip321Error> {
        // Payment indices are limited to 4 digits
        if payments.len() > 9999 {
            return Err(Zip321Error::TooManyPayments(payments.len()));
        }

        let request = TransactionRequest {
            payments: payments.into_iter().enumerate().collect(),
        };

        // Enforce validity requirements.
        if !request.payments.is_empty() {
            // It doesn't matter what params we use here, as none of the validity
            // requirements depend on them.
            let params = consensus::MAIN_NETWORK;
            TransactionRequest::from_uri(&params, &request.to_uri(&params))?;
        }

        Ok(request)
    }

    /// Constructs a new transaction request from the provided map from payment
    /// index to payment.
    ///
    /// Payment index 0 will be mapped to the empty payment index.
    pub fn from_indexed(
        payments: BTreeMap<usize, Payment>,
    ) -> Result<TransactionRequest, Zip321Error> {
        if let Some(k) = payments.keys().find(|k| **k > 9999) {
            // This is not quite the correct error, but close enough.
            return Err(Zip321Error::TooManyPayments(*k));
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

    /// Returns the total value of payments to be made.
    ///
    /// Returns `Err` in the case of overflow, or if the value is
    /// outside the range `0..=MAX_MONEY` zatoshis.
    pub fn total(&self) -> Result<NonNegativeAmount, ()> {
        self.payments
            .values()
            .map(|p| p.amount)
            .fold(Ok(NonNegativeAmount::ZERO), |acc, a| (acc? + a).ok_or(()))
    }

    /// A utility for use in tests to help check round-trip serialization properties.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub(in crate::zip321) fn normalize(&mut self) {
        for p in self.payments.values_mut() {
            p.normalize();
        }
    }

    /// A utility for use in tests to help check round-trip serialization properties.
    /// by comparing a two transaction requests for equality after normalization.
    #[cfg(all(test, feature = "test-dependencies"))]
    pub(in crate::zip321) fn normalize_and_eq(
        a: &mut TransactionRequest,
        b: &mut TransactionRequest,
    ) -> bool {
        a.normalize();
        b.normalize();

        a == b
    }

    /// Convert this request to a URI string.
    ///
    /// Returns None if the payment request is empty.
    pub fn to_uri<P: consensus::Parameters>(&self, params: &P) -> String {
        fn payment_params(
            payment: &Payment,
            payment_index: Option<usize>,
        ) -> impl IntoIterator<Item = String> + '_ {
            std::iter::empty()
                .chain(render::amount_param(payment.amount, payment_index))
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
                    payment.recipient_address.encode(params),
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
                            .chain(Some(render::addr_param(params, &primary_address, idx)))
                            .chain(payment_params(payment, idx))
                    })
                    .collect::<Vec<String>>();

                format!("zcash:?{}", query_params.join("&"))
            }
        }
    }

    /// Parse the provided URI to a payment request value.
    pub fn from_uri<P: consensus::Parameters>(params: &P, uri: &str) -> Result<Self, Zip321Error> {
        // Parse the leading zcash:<address>
        let (rest, primary_addr_param) =
            parse::lead_addr(params)(uri).map_err(|e| Zip321Error::ParseError(e.to_string()))?;

        // Parse the remaining parameters as an undifferentiated list
        let (_, xs) = if rest.is_empty() {
            ("", vec![])
        } else {
            all_consuming(preceded(
                char('?'),
                separated_list0(char('&'), parse::zcashparam(params)),
            ))(rest)
            .map_err(|e| Zip321Error::ParseError(e.to_string()))?
        };

        // Construct sets of payment parameters, keyed by the payment index.
        let mut params_by_index: BTreeMap<usize, Vec<parse::Param>> = BTreeMap::new();

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
                    if parse::has_duplicate_param(current, &p.param) {
                        return Err(Zip321Error::DuplicateParameter(p.param, p.payment_index));
                    } else {
                        current.push(p.param);
                    }
                }
            }
        }

        // Build the actual payment values from the index.
        params_by_index
            .into_iter()
            .map(|(i, params)| parse::to_payment(params, i).map(|payment| (i, payment)))
            .collect::<Result<BTreeMap<usize, Payment>, _>>()
            .map(|payments| TransactionRequest { payments })
    }
}

mod render {
    use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

    use zcash_primitives::{
        consensus,
        transaction::components::amount::COIN,
        transaction::components::{amount::NonNegativeAmount, Amount},
    };

    use super::{memo_to_base64, Address, MemoBytes};

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
            Some(i) if i > 0 => format!(".{}", i),
            _otherwise => "".to_string(),
        }
    }

    /// Constructs an "address" key/value pair containing the encoded recipient address
    /// at the specified parameter index.
    pub fn addr_param<P: consensus::Parameters>(
        params: &P,
        addr: &Address,
        idx: Option<usize>,
    ) -> String {
        format!("address{}={}", param_index(idx), addr.encode(params))
    }

    /// Converts an [`Amount`] value to a correctly formatted decimal ZEC
    /// value for inclusion in a ZIP 321 URI.
    pub fn amount_str(amount: Amount) -> Option<String> {
        if amount.is_positive() {
            let coins = i64::from(amount) / COIN;
            let zats = i64::from(amount) % COIN;
            Some(if zats == 0 {
                format!("{}", coins)
            } else {
                format!("{}.{:0>8}", coins, zats)
                    .trim_end_matches('0')
                    .to_string()
            })
        } else {
            None
        }
    }

    /// Constructs an "amount" key/value pair containing the encoded ZEC amount
    /// at the specified parameter index.
    pub fn amount_param(amount: NonNegativeAmount, idx: Option<usize>) -> Option<String> {
        amount_str(amount.into()).map(|s| format!("amount{}={}", param_index(idx), s))
    }

    /// Constructs a "memo" key/value pair containing the base64URI-encoded memo
    /// at the specified parameter index.
    pub fn memo_param(value: &MemoBytes, idx: Option<usize>) -> String {
        format!("{}{}={}", "memo", param_index(idx), memo_to_base64(value))
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

mod parse {
    use core::fmt::Debug;

    use nom::{
        bytes::complete::{tag, take_till},
        character::complete::{alpha1, char, digit0, digit1, one_of},
        combinator::{map_opt, map_res, opt, recognize},
        sequence::{preceded, separated_pair, tuple},
        AsChar, IResult, InputTakeAtPosition,
    };
    use percent_encoding::percent_decode;
    use zcash_primitives::{
        consensus,
        transaction::components::amount::COIN,
        transaction::components::{amount::NonNegativeAmount, Amount},
    };

    use crate::address::Address;

    use super::{memo_from_base64, MemoBytes, Payment, Zip321Error};

    /// A data type that defines the possible parameter types which may occur within a
    /// ZIP 321 URI.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Param {
        Addr(Box<Address>),
        Amount(NonNegativeAmount),
        Memo(MemoBytes),
        Label(String),
        Message(String),
        Other(String, String),
    }

    impl Param {
        /// Returns the name of the parameter from which this value was parsed.
        pub fn name(&self) -> String {
            match self {
                Param::Addr(_) => "address".to_owned(),
                Param::Amount(_) => "amount".to_owned(),
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
                (Param::Amount(_), Param::Amount(_)) => return true,
                (Param::Memo(_), Param::Memo(_)) => return true,
                (Param::Label(_), Param::Label(_)) => return true,
                (Param::Message(_), Param::Message(_)) => return true,
                (Param::Other(n, _), Param::Other(n0, _)) if (n == n0) => return true,
                _otherwise => continue,
            }
        }

        false
    }

    /// Converts an vector of [`Param`] values to a [`Payment`].
    ///
    /// This function performs checks to ensure that the resulting [`Payment`] is structurally
    /// valid; for example, a request for memo contents may not be associated with a
    /// transparent payment address.
    pub fn to_payment(vs: Vec<Param>, i: usize) -> Result<Payment, Zip321Error> {
        let addr = vs.iter().find_map(|v| match v {
            Param::Addr(a) => Some(a.clone()),
            _otherwise => None,
        });

        let mut payment = Payment {
            recipient_address: *addr.ok_or(Zip321Error::RecipientMissing(i))?,
            amount: NonNegativeAmount::ZERO,
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        };

        for v in vs {
            match v {
                Param::Amount(a) => payment.amount = a,
                Param::Memo(m) => match payment.recipient_address {
                    Address::Sapling(_) | Address::Unified(_) => payment.memo = Some(m),
                    Address::Transparent(_) => return Err(Zip321Error::TransparentMemo(i)),
                },

                Param::Label(m) => payment.label = Some(m),
                Param::Message(m) => payment.message = Some(m),
                Param::Other(n, m) => payment.other_params.push((n, m)),
                _otherwise => {}
            }
        }

        Ok(payment)
    }

    /// Parses and consumes the leading "zcash:\[address\]" from a ZIP 321 URI.
    pub fn lead_addr<P: consensus::Parameters>(
        params: &P,
    ) -> impl Fn(&str) -> IResult<&str, Option<IndexedParam>> + '_ {
        move |input: &str| {
            map_opt(
                preceded(tag("zcash:"), take_till(|c| c == '?')),
                |addr_str: &str| {
                    if addr_str.is_empty() {
                        Some(None) // no address is ok, so wrap in `Some`
                    } else {
                        // `decode` returns `None` on error, which we want to
                        // then cause `map_opt` to fail.
                        Address::decode(params, addr_str).map(|a| {
                            Some(IndexedParam {
                                param: Param::Addr(Box::new(a)),
                                payment_index: 0,
                            })
                        })
                    }
                },
            )(input)
        }
    }

    /// The primary parser for <name>=<value> query-string parameter pair.
    pub fn zcashparam<P: consensus::Parameters>(
        params: &P,
    ) -> impl Fn(&str) -> IResult<&str, IndexedParam> + '_ {
        move |input| {
            map_res(
                separated_pair(indexed_name, char('='), recognize(qchars)),
                move |r| to_indexed_param(params, r),
            )(input)
        }
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
    pub fn parse_amount(input: &str) -> IResult<&str, Amount> {
        map_res(
            tuple((
                digit1,
                opt(preceded(
                    char('.'),
                    map_opt(digit0, |s: &str| if s.len() > 8 { None } else { Some(s) }),
                )),
            )),
            |(whole_s, decimal_s): (&str, Option<&str>)| {
                let coins: i64 = whole_s
                    .to_string()
                    .parse::<i64>()
                    .map_err(|e| e.to_string())?;

                let zats: i64 = match decimal_s {
                    Some(d) => format!("{:0<8}", d)
                        .parse::<i64>()
                        .map_err(|e| e.to_string())?,
                    None => 0,
                };

                if coins >= 21000000 && (coins > 21000000 || zats > 0) {
                    return Err(format!(
                        "{} coins exceeds the maximum possible Zcash value.",
                        coins
                    ));
                }

                let amt = coins * COIN + zats;

                Amount::from_nonnegative_i64(amt)
                    .map_err(|_| format!("Not a valid zat amount: {}", amt))
            },
        )(input)
    }

    fn to_indexed_param<'a, P: consensus::Parameters>(
        params: &'a P,
        ((name, iopt), value): ((&str, Option<&str>), &str),
    ) -> Result<IndexedParam, String> {
        let param = match name {
            "address" => Address::decode(params, value)
                .map(Box::new)
                .map(Param::Addr)
                .ok_or(format!(
                    "Could not interpret {} as a valid Zcash address.",
                    value
                )),

            "amount" => parse_amount(value)
                .map_err(|e| e.to_string())
                .and_then(|(_, a)| {
                    NonNegativeAmount::try_from(a)
                        .map_err(|_| "Payment amount must be nonnegative.".to_owned())
                })
                .map(Param::Amount),

            "label" => percent_decode(value.as_bytes())
                .decode_utf8()
                .map(|s| Param::Label(s.into_owned()))
                .map_err(|e| e.to_string()),

            "message" => percent_decode(value.as_bytes())
                .decode_utf8()
                .map(|s| Param::Message(s.into_owned()))
                .map_err(|e| e.to_string()),

            "memo" => memo_from_base64(value)
                .map(Param::Memo)
                .map_err(|e| format!("Decoded memo was invalid: {:?}", e)),

            other if other.starts_with("req-") => {
                Err(format!("Required parameter {} not recognized", other))
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
}

#[cfg(feature = "test-dependencies")]
pub mod testing {
    use proptest::collection::btree_map;
    use proptest::collection::vec;
    use proptest::option;
    use proptest::prelude::{any, prop_compose};
    use zcash_keys::address::testing::arb_addr;
    use zcash_keys::keys::UnifiedAddressRequest;
    use zcash_primitives::{
        consensus::TEST_NETWORK, transaction::components::amount::testing::arb_nonnegative_amount,
    };

    use crate::address::Address;

    use super::{MemoBytes, Payment, TransactionRequest};
    pub const VALID_PARAMNAME: &str = "[a-zA-Z][a-zA-Z0-9+-]*";

    #[cfg(feature = "transparent-inputs")]
    const TRANSPARENT_INPUTS_ENABLED: bool = true;
    #[cfg(not(feature = "transparent-inputs"))]
    const TRANSPARENT_INPUTS_ENABLED: bool = false;

    pub(crate) const UA_REQUEST: UnifiedAddressRequest =
        UnifiedAddressRequest::unsafe_new(false, true, TRANSPARENT_INPUTS_ENABLED);

    prop_compose! {
        pub fn arb_valid_memo()(bytes in vec(any::<u8>(), 0..512)) -> MemoBytes {
            MemoBytes::from_bytes(&bytes).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_zip321_payment()(
            recipient_address in arb_addr(UA_REQUEST),
            amount in arb_nonnegative_amount(),
            memo in option::of(arb_valid_memo()),
            message in option::of(any::<String>()),
            label in option::of(any::<String>()),
            // prevent duplicates by generating a set rather than a vec
            other_params in btree_map(VALID_PARAMNAME, any::<String>(), 0..3),
        ) -> Payment {
            let is_shielded = match recipient_address {
                Address::Transparent(_) => false,
                Address::Sapling(_) | Address::Unified(_) => true,
            };

            Payment {
                recipient_address,
                amount,
                memo: memo.filter(|_| is_shielded),
                label,
                message,
                other_params: other_params.into_iter().collect(),
            }
        }
    }

    prop_compose! {
        pub fn arb_zip321_request()(payments in btree_map(0usize..10000, arb_zip321_payment(), 1..10)) -> TransactionRequest {
            let mut req = TransactionRequest::from_indexed(payments).unwrap();
            req.normalize(); // just to make test comparisons easier
            req
        }
    }

    prop_compose! {
        pub fn arb_zip321_request_sequential()(payments in vec(arb_zip321_payment(), 1..10)) -> TransactionRequest {
            let mut req = TransactionRequest::new(payments).unwrap();
            req.normalize(); // just to make test comparisons easier
            req
        }
    }

    prop_compose! {
        pub fn arb_zip321_uri()(req in arb_zip321_request()) -> String {
            req.to_uri(&TEST_NETWORK)
        }
    }

    prop_compose! {
        pub fn arb_addr_str()(
            recipient_address in arb_addr(UA_REQUEST)
        ) -> String {
            recipient_address.encode(&TEST_NETWORK)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use zcash_keys::address::testing::arb_addr;
    use zcash_primitives::{
        consensus::{Parameters, TEST_NETWORK},
        memo::Memo,
        transaction::components::amount::{Amount, NonNegativeAmount},
    };

    #[cfg(feature = "local-consensus")]
    use zcash_primitives::{local_consensus::LocalNetwork, BlockHeight};

    use crate::{address::Address, encoding::decode_payment_address, zip321::testing::UA_REQUEST};

    use super::{
        memo_from_base64, memo_to_base64,
        parse::{parse_amount, zcashparam, Param},
        render::amount_str,
        MemoBytes, Payment, TransactionRequest,
    };

    #[cfg(all(test, feature = "test-dependencies"))]
    use proptest::prelude::{any, proptest};

    #[cfg(all(test, feature = "test-dependencies"))]
    use zcash_primitives::transaction::components::amount::testing::arb_nonnegative_amount;

    #[cfg(all(test, feature = "test-dependencies"))]
    use super::{
        render::{memo_param, str_param},
        testing::{arb_addr_str, arb_valid_memo, arb_zip321_request, arb_zip321_uri},
    };

    fn check_roundtrip(req: TransactionRequest) {
        let req_uri = req.to_uri(&TEST_NETWORK);
        let parsed = TransactionRequest::from_uri(&TEST_NETWORK, &req_uri).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn test_zip321_roundtrip_simple_amounts() {
        let amounts = vec![1u64, 1000u64, 100000u64, 100000000u64, 100000000000u64];

        for amt_u64 in amounts {
            let amt = Amount::from_u64(amt_u64).unwrap();
            let amt_str = amount_str(amt).unwrap();
            assert_eq!(amt, parse_amount(&amt_str).unwrap().1);
        }
    }

    #[test]
    fn test_zip321_parse_empty_message() {
        let fragment = "message=";

        let result = zcashparam(&TEST_NETWORK)(fragment).unwrap().1.param;
        assert_eq!(result, Param::Message("".to_string()));
    }

    #[test]
    fn test_zip321_parse_simple() {
        let uri = "zcash:ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k?amount=3768769.02796286&message=";
        let parse_result = TransactionRequest::from_uri(&TEST_NETWORK, uri).unwrap();

        let expected = TransactionRequest::new(
            vec![
                Payment {
                    recipient_address: Address::Sapling(decode_payment_address(TEST_NETWORK.hrp_sapling_payment_address(), "ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k").unwrap()),
                    amount: NonNegativeAmount::const_from_u64(376876902796286),
                    memo: None,
                    label: None,
                    message: Some("".to_string()),
                    other_params: vec![],
                }
            ]
        ).unwrap();

        assert_eq!(parse_result, expected);
    }

    #[test]
    fn test_zip321_parse_no_query_params() {
        let uri = "zcash:ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k";
        let parse_result = TransactionRequest::from_uri(&TEST_NETWORK, uri).unwrap();

        let expected = TransactionRequest::new(
            vec![
                Payment {
                    recipient_address: Address::Sapling(decode_payment_address(TEST_NETWORK.hrp_sapling_payment_address(), "ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k").unwrap()),
                    amount: NonNegativeAmount::ZERO,
                    memo: None,
                    label: None,
                    message: None,
                    other_params: vec![],
                }
            ]
        ).unwrap();

        assert_eq!(parse_result, expected);
    }

    #[test]
    fn test_zip321_roundtrip_empty_message() {
        let req = TransactionRequest::new(
            vec![
                Payment {
                    recipient_address: Address::Sapling(decode_payment_address(TEST_NETWORK.hrp_sapling_payment_address(), "ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k").unwrap()),
                    amount: NonNegativeAmount::ZERO,
                    memo: None,
                    label: None,
                    message: Some("".to_string()),
                    other_params: vec![]
                }
            ]
        ).unwrap();

        check_roundtrip(req);
    }

    #[test]
    fn test_zip321_memos() {
        let m_simple: MemoBytes = Memo::from_str("This is a simple memo.").unwrap().into();
        let m_simple_64 = memo_to_base64(&m_simple);
        assert_eq!(memo_from_base64(&m_simple_64).unwrap(), m_simple);

        let m_json: MemoBytes = Memo::from_str("{ \"key\": \"This is a JSON-structured memo.\" }")
            .unwrap()
            .into();
        let m_json_64 = memo_to_base64(&m_json);
        assert_eq!(memo_from_base64(&m_json_64).unwrap(), m_json);

        let m_unicode: MemoBytes = Memo::from_str("This is a unicode memo ✨🦄🏆🎉")
            .unwrap()
            .into();
        let m_unicode_64 = memo_to_base64(&m_unicode);
        assert_eq!(memo_from_base64(&m_unicode_64).unwrap(), m_unicode);
    }

    #[test]
    fn test_zip321_spec_valid_examples() {
        let valid_0 = "zcash:";
        let v0r = TransactionRequest::from_uri(&TEST_NETWORK, valid_0).unwrap();
        assert!(v0r.payments.is_empty());

        let valid_0 = "zcash:?";
        let v0r = TransactionRequest::from_uri(&TEST_NETWORK, valid_0).unwrap();
        assert!(v0r.payments.is_empty());

        let valid_1 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=1&memo=VGhpcyBpcyBhIHNpbXBsZSBtZW1vLg&message=Thank%20you%20for%20your%20purchase";
        let v1r = TransactionRequest::from_uri(&TEST_NETWORK, valid_1).unwrap();
        assert_eq!(
            v1r.payments.get(&0).map(|p| p.amount),
            Some(NonNegativeAmount::const_from_u64(100000000))
        );

        let valid_2 = "zcash:?address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&amount=123.456&address.1=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.1=0.789&memo.1=VGhpcyBpcyBhIHVuaWNvZGUgbWVtbyDinKjwn6aE8J-PhvCfjok";
        let mut v2r = TransactionRequest::from_uri(&TEST_NETWORK, valid_2).unwrap();
        v2r.normalize();
        assert_eq!(
            v2r.payments.get(&0).map(|p| p.amount),
            Some(NonNegativeAmount::const_from_u64(12345600000))
        );
        assert_eq!(
            v2r.payments.get(&1).map(|p| p.amount),
            Some(NonNegativeAmount::const_from_u64(78900000))
        );

        // valid; amount just less than MAX_MONEY
        // 20999999.99999999
        let valid_3 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=20999999.99999999";
        let v3r = TransactionRequest::from_uri(&TEST_NETWORK, valid_3).unwrap();
        assert_eq!(
            v3r.payments.get(&0).map(|p| p.amount),
            Some(NonNegativeAmount::const_from_u64(2099999999999999u64))
        );

        // valid; MAX_MONEY
        // 21000000
        let valid_4 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=21000000";
        let v4r = TransactionRequest::from_uri(&TEST_NETWORK, valid_4).unwrap();
        assert_eq!(
            v4r.payments.get(&0).map(|p| p.amount),
            Some(NonNegativeAmount::const_from_u64(2100000000000000u64))
        );
    }

    #[cfg(feature = "local-consensus")]
    #[test]
    fn test_zip321_spec_regtest_valid_examples() {
        let params = LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(1)),
            blossom: Some(BlockHeight::from_u32(1)),
            heartwood: Some(BlockHeight::from_u32(1)),
            canopy: Some(BlockHeight::from_u32(1)),
            nu5: Some(BlockHeight::from_u32(1)),
            nu6: Some(BlockHeight::from_u32(1)),
            z_future: Some(BlockHeight::from_u32(1)),
        };
        let valid_1 = "zcash:zregtestsapling1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle7505hlz3?amount=1&memo=VGhpcyBpcyBhIHNpbXBsZSBtZW1vLg&message=Thank%20you%20for%20your%20purchase";
        let v1r = TransactionRequest::from_uri(&params, valid_1).unwrap();
        assert_eq!(
            v1r.payments.get(&0).map(|p| p.amount),
            Some(NonNegativeAmount::const_from_u64(100000000))
        );
    }

    #[test]
    fn test_zip321_spec_invalid_examples() {
        // invalid; empty string
        let invalid_0 = "";
        let i0r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_0);
        assert!(i0r.is_err());

        // invalid; missing `address=`
        let invalid_1 = "zcash:?amount=3491405.05201255&address.1=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.1=5740296.87793245";
        let i1r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_1);
        assert!(i1r.is_err());

        // invalid; missing `address.1=`
        let invalid_2 = "zcash:?address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&amount=1&amount.1=2&address.2=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez";
        let i2r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_2);
        assert!(i2r.is_err());

        // invalid; `address.0=` and `amount.0=` are not permitted (leading 0s).
        let invalid_3 = "zcash:?address.0=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.0=2";
        let i3r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_3);
        assert!(i3r.is_err());

        // invalid; duplicate `amount=` field
        let invalid_4 =
            "zcash:?amount=1.234&amount=2.345&address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";
        let i4r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_4);
        assert!(i4r.is_err());

        // invalid; duplicate `amount.1=` field
        let invalid_5 =
            "zcash:?amount.1=1.234&amount.1=2.345&address.1=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";
        let i5r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_5);
        assert!(i5r.is_err());

        //invalid; memo associated with t-addr
        let invalid_6 = "zcash:?address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&amount=123.456&memo=eyAia2V5IjogIlRoaXMgaXMgYSBKU09OLXN0cnVjdHVyZWQgbWVtby4iIH0&address.1=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.1=0.789&memo.1=VGhpcyBpcyBhIHVuaWNvZGUgbWVtbyDinKjwn6aE8J-PhvCfjok";
        let i6r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_6);
        assert!(i6r.is_err());

        // invalid; amount component exceeds an i64
        // 9223372036854775808 = i64::MAX + 1
        let invalid_7 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=9223372036854775808";
        let i7r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_7);
        assert!(i7r.is_err());

        // invalid; amount component wraps into a valid small positive i64
        // 18446744073709551624
        let invalid_7a = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=18446744073709551624";
        let i7ar = TransactionRequest::from_uri(&TEST_NETWORK, invalid_7a);
        assert!(i7ar.is_err());

        // invalid; amount component is MAX_MONEY
        // 21000000.00000001
        let invalid_8 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=21000000.00000001";
        let i8r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_8);
        assert!(i8r.is_err());

        // invalid; negative amount
        let invalid_9 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=-1";
        let i9r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_9);
        assert!(i9r.is_err());

        // invalid; parameter index too large
        let invalid_10 =
            "zcash:?amount.10000=1.23&address.10000=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";
        let i10r = TransactionRequest::from_uri(&TEST_NETWORK, invalid_10);
        assert!(i10r.is_err());
    }

    #[cfg(all(test, feature = "test-dependencies"))]
    proptest! {
        #[test]
        fn prop_zip321_roundtrip_address(addr in arb_addr(UA_REQUEST)) {
            let a = addr.encode(&TEST_NETWORK);
            assert_eq!(Address::decode(&TEST_NETWORK, &a), Some(addr));
        }

        #[test]
        fn prop_zip321_roundtrip_address_str(a in arb_addr_str()) {
            let addr = Address::decode(&TEST_NETWORK, &a).unwrap();
            assert_eq!(addr.encode(&TEST_NETWORK), a);
        }

        #[test]
        fn prop_zip321_roundtrip_amount(nn_amt in arb_nonnegative_amount()) {
            let amt = Amount::from(nn_amt);
            let amt_str = amount_str(amt).unwrap();
            assert_eq!(amt, parse_amount(&amt_str).unwrap().1);
        }

        #[test]
        fn prop_zip321_roundtrip_str_param(
            message in any::<String>(), i in proptest::option::of(0usize..2000)) {
            let fragment = str_param("message", &message, i);
            let (rest, iparam) = zcashparam(&TEST_NETWORK)(&fragment).unwrap();
            assert_eq!(rest, "");
            assert_eq!(iparam.param, Param::Message(message));
            assert_eq!(iparam.payment_index, i.unwrap_or(0));
        }

        #[test]
        fn prop_zip321_roundtrip_memo_param(
            memo in arb_valid_memo(), i in proptest::option::of(0usize..2000)) {
            let fragment = memo_param(&memo, i);
            let (rest, iparam) = zcashparam(&TEST_NETWORK)(&fragment).unwrap();
            assert_eq!(rest, "");
            assert_eq!(iparam.param, Param::Memo(memo));
            assert_eq!(iparam.payment_index, i.unwrap_or(0));
        }

        #[test]
        fn prop_zip321_roundtrip_request(mut req in arb_zip321_request()) {
            let req_uri = req.to_uri(&TEST_NETWORK);
            let mut parsed = TransactionRequest::from_uri(&TEST_NETWORK, &req_uri).unwrap();
            assert!(TransactionRequest::normalize_and_eq(&mut parsed, &mut req));
        }

        #[test]
        fn prop_zip321_roundtrip_uri(uri in arb_zip321_uri()) {
            let mut parsed = TransactionRequest::from_uri(&TEST_NETWORK, &uri).unwrap();
            parsed.normalize();
            let serialized = parsed.to_uri(&TEST_NETWORK);
            assert_eq!(serialized, uri)
        }
    }
}
