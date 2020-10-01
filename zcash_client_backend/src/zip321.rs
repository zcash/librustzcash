use core::fmt::Debug;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use base64;
use nom::{
    character::complete::char, combinator::all_consuming, multi::separated_list, sequence::preceded,
};
use zcash_primitives::{consensus, legacy, primitives, transaction::components::Amount};

use crate::encoding::{
    decode_payment_address, decode_transparent_address, encode_payment_address,
    encode_transparent_address,
};

#[derive(Debug, PartialEq, Clone)]
pub enum Address {
    Transparent(legacy::TransparentAddress),
    Sapling(primitives::PaymentAddress),
}

#[derive(Debug)]
pub enum AddrParseError {
    TAddrError(bs58::decode::Error),
    SAddrError(bech32::Error),
}

impl Address {
    pub fn render<P: consensus::Parameters>(&self, params: &P) -> String {
        match self {
            Address::Transparent(t) => encode_transparent_address(
                &params.b58_pubkey_address_prefix(),
                &params.b58_script_address_prefix(),
                &t,
            ),
            Address::Sapling(s) => {
                encode_payment_address(&params.hrp_sapling_payment_address(), &s)
            }
        }
    }

    /// Parser for shielded (Sapling) and transparent ZCash addresses.
    pub fn parse<P: consensus::Parameters>(
        params: &P,
        addr_str: &str,
    ) -> Result<Option<Address>, AddrParseError> {
        if addr_str == "" {
            Ok(None)
        } else {
            let t_res = decode_transparent_address(
                &params.b58_pubkey_address_prefix(),
                &params.b58_script_address_prefix(),
                addr_str,
            )
            .map(|t| t.map(Address::Transparent))
            .map_err(AddrParseError::TAddrError);

            let s_res = decode_payment_address(&params.hrp_sapling_payment_address(), addr_str)
                .map(|s| s.map(Address::Sapling))
                .map_err(AddrParseError::SAddrError);

            match t_res {
                Err(_) | Ok(None) => s_res,
                t_addr => t_addr,
            }
        }
    }
}

pub struct RawMemo([u8; 512]);

#[derive(Debug)]
pub enum MemoError {
    InvalidBase64(base64::DecodeError),
    LengthExceeded(usize),
}

impl RawMemo {
    // Construct a memo from a vector of bytes.
    pub fn from_str(s: &str) -> Result<Self, MemoError> {
        RawMemo::from_bytes(s.as_bytes())
    }

    pub fn from_bytes(v: &[u8]) -> Result<Self, MemoError> {
        if v.len() > 512 {
            Err(MemoError::LengthExceeded(v.len()))
        } else {
            let mut memo: [u8; 512] = [0; 512];
            memo[..v.len()].copy_from_slice(&v);
            Ok(RawMemo(memo))
        }
    }

    pub fn to_base64(&self) -> String {
        // strip trailing zero bytes.
        let mut last_nonzero = -1;
        for i in (0..(self.0.len())).rev() {
            if self.0[i] != 0x0 {
                last_nonzero = i as i64;
                break;
            }
        }

        base64::encode_config(
            &self.0[..((last_nonzero + 1) as usize)],
            base64::URL_SAFE_NO_PAD,
        )
    }

    pub fn from_base64(s: &str) -> Result<Self, MemoError> {
        base64::decode_config(s, base64::URL_SAFE_NO_PAD)
            .map_err(MemoError::InvalidBase64)
            .and_then(|b| RawMemo::from_bytes(&b))
    }
}

impl Debug for RawMemo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("RawMemo")
            .field("memo", &format!("{:?}...", &self.0[0..17]))
            .finish()
    }
}

impl PartialEq for RawMemo {
    fn eq(&self, other: &Self) -> bool {
        self.to_base64() == other.to_base64()
    }
}

impl FromStr for RawMemo {
    type Err = MemoError;

    fn from_str(memo: &str) -> Result<Self, Self::Err> {
        RawMemo::from_str(memo)
    }
}

impl Eq for RawMemo {}

impl PartialOrd for RawMemo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.to_base64().cmp(&other.to_base64()))
    }
}

impl Ord for RawMemo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

// RawMemo is somewhat duplicative of the `Memo` type
// in crate::note_encryption but as that's actively being
// updated at time of this writing, these functions provide
// shims to ease future use of those
pub fn memo_from_vec(v: &[u8]) -> Result<RawMemo, MemoError> {
    RawMemo::from_bytes(v)
}

pub fn memo_to_base64(memo: &RawMemo) -> String {
    memo.to_base64()
}

pub fn memo_from_base64(s: &str) -> Result<RawMemo, MemoError> {
    RawMemo::from_base64(s)
}

#[derive(Debug, PartialEq)]
pub struct Zip321Payment {
    recipient_address: Address,
    amount: Amount,
    memo: Option<RawMemo>,
    label: Option<String>,
    message: Option<String>,
    other_params: Vec<(String, String)>,
}

impl Zip321Payment {
    pub fn normalize(&mut self) {
        self.other_params.sort();
    }

    /// Returns a function which compares two normalized payments, with addresses sorted by their
    /// string representation given the specified network. This does not perform normalization
    /// internally, so payments must be normalized prior to being passed to the comparison function
    /// returned from this method.
    pub fn compare_normalized<'a, P: consensus::Parameters>(
        params: &'a P,
    ) -> impl Fn(&Zip321Payment, &Zip321Payment) -> Ordering + 'a {
        move |a: &Zip321Payment, b: &Zip321Payment| {
            let a_addr = a.recipient_address.render(params);
            let b_addr = b.recipient_address.render(params);

            a_addr
                .cmp(&b_addr)
                .then(a.amount.cmp(&b.amount))
                .then(a.memo.cmp(&b.memo))
                .then(a.label.cmp(&b.label))
                .then(a.message.cmp(&b.message))
                .then(a.other_params.cmp(&b.other_params))
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Zip321Request {
    payments: Vec<Zip321Payment>,
}

impl Zip321Request {
    pub fn normalize<P: consensus::Parameters>(&mut self, params: &P) {
        for p in &mut self.payments {
            p.normalize();
        }

        self.payments
            .sort_by(Zip321Payment::compare_normalized(params));
    }

    pub fn normalize_and_eq<P: consensus::Parameters>(
        params: &P,
        a: &mut Zip321Request,
        b: &mut Zip321Request,
    ) -> bool {
        a.normalize(params);
        b.normalize(params);

        a == b
    }

    /// Convert this request to a URI string.
    ///
    /// Returns None if the payment request is empty.
    pub fn to_uri<P: consensus::Parameters>(&self, params: &P) -> Option<String> {
        fn push_params(
            payment: &Zip321Payment,
            payment_index: Option<usize>,
            query_params: &mut Vec<String>,
        ) {
            if let Some(amount_p) = render::amount_param(payment.amount, payment_index) {
                query_params.push(amount_p);
            }

            if let Some(memo_p) = payment
                .memo
                .as_ref()
                .map(|m| render::memo_param(&m, payment_index))
            {
                query_params.push(memo_p);
            }

            if let Some(label_p) = payment
                .label
                .as_ref()
                .map(|m| render::str_param("label", &m, payment_index))
            {
                query_params.push(label_p);
            }

            if let Some(message_p) = payment
                .message
                .as_ref()
                .map(|m| render::str_param("message", &m, payment_index))
            {
                query_params.push(message_p);
            }

            for (name, value) in &payment.other_params {
                query_params.push(render::str_param(&name, &value, payment_index))
            }
        }

        let mut query_params = vec![];
        if self.payments.len() == 1 {
            self.payments.get(0).map(|payment| {
                push_params(payment, None, &mut query_params);
                format!(
                    "zcash:{}?{}",
                    payment.recipient_address.render(params),
                    query_params.join("&")
                )
            })
        } else {
            for (i, payment) in (&self.payments).into_iter().enumerate() {
                query_params.push(render::addr_param(
                    params,
                    &payment.recipient_address,
                    Some(i),
                ));
                push_params(payment, Some(i), &mut query_params);
            }

            Some(format!("zcash:?{}", query_params.join("&")))
        }
    }

    /// Parse the provided URI to a payment request value.
    pub fn from_uri<P: consensus::Parameters>(params: &P, uri: &str) -> Result<Self, String> {
        // Parse the leading zcash:<address>
        let (rest, primary_addr_param) =
            parse::lead_addr(&params.clone())(uri).map_err(|e| e.to_string())?;

        // Parse the remaining parameters as an undifferentiated list
        let (_, xs) = all_consuming(preceded(
            char('?'),
            separated_list(char('&'), parse::zcashparam(params)),
        ))(rest)
        .map_err(|e| e.to_string())?;

        // Construct sets of payment parameters, keyed by the payment index.
        let mut params_by_index: HashMap<usize, Vec<parse::Param>> = HashMap::new();

        // Add the primary address, if any, to the index.
        for p in primary_addr_param {
            params_by_index.insert(p.payment_index, vec![p.param]);
        }

        // Group the remaining parameters by payment index
        for p in xs {
            match params_by_index.get_mut(&p.payment_index) {
                None => {
                    params_by_index.insert(p.payment_index, vec![p.param]);
                }

                Some(current) => {
                    if parse::has_duplicate_param(&current, &p.param) {
                        return Err(format!(
                            "Found duplicate parameter {:?} at index {}",
                            p.param, p.payment_index
                        ));
                    } else {
                        current.push(p.param);
                    }
                }
            }
        }

        // Build the actual payment values from the index.
        let mut payments = vec![];
        for (i, params) in params_by_index {
            let payment = parse::to_payment(params, i)?;
            payments.push(payment);
        }

        Ok(Zip321Request { payments })
    }
}

pub mod render {
    use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

    use zcash_primitives::{
        consensus, transaction::components::amount::COIN, transaction::components::Amount,
    };

    use super::{memo_to_base64, Address, RawMemo};

    // The set of ASCII characters which must be percent-encoded according
    // to the definition of ZIP-0321. This is the complement of the subset of
    // ASCII characters defined by `qchar`
    //
    //       unreserved      = ALPHA / DIGIT / "-" / "." / "_" / "~"
    //       allowed-delims  = "!" / "$" / "'" / "(" / ")" / "*" / "+" / "," / ";"
    //       qchar           = unreserved / pct-encoded / allowed-delims / ":" / "@"
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

    pub fn param_index(idx: Option<usize>) -> String {
        match idx {
            Some(i) if i > 0 => format!(".{}", i),
            _otherwise => "".to_string(),
        }
    }

    pub fn addr_param<P: consensus::Parameters>(
        params: &P,
        addr: &Address,
        idx: Option<usize>,
    ) -> String {
        format!("address{}={}", param_index(idx), addr.render(params),)
    }

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

    pub fn amount_param(amount: Amount, idx: Option<usize>) -> Option<String> {
        amount_str(amount).map(|s| format!("amount{}={}", param_index(idx), s))
    }

    pub fn memo_param(value: &RawMemo, idx: Option<usize>) -> String {
        format!("{}{}={}", "memo", param_index(idx), memo_to_base64(value),)
    }

    pub fn str_param(label: &str, value: &str, idx: Option<usize>) -> String {
        format!(
            "{}{}={}",
            label,
            param_index(idx),
            utf8_percent_encode(value, QCHAR_ENCODE)
        )
    }
}

pub mod parse {
    use core::fmt::Debug;
    use std::convert::TryInto;

    use nom::{
        bytes::complete::{tag, take_until},
        character::complete::{alpha1, char, digit0, digit1, one_of},
        combinator::{map_res, opt, recognize},
        sequence::{preceded, separated_pair, tuple},
        AsChar, IResult, InputTakeAtPosition,
    };
    use percent_encoding::percent_decode;
    use zcash_primitives::{
        consensus, transaction::components::amount::COIN, transaction::components::Amount,
    };

    use super::{memo_from_base64, AddrParseError, Address, RawMemo, Zip321Payment};

    // For purposes of parsing
    #[derive(Debug, PartialEq)]
    pub enum Param {
        Addr(Address),
        Amount(Amount),
        Memo(RawMemo),
        Label(String),
        Message(String),
        Other(String, String),
    }

    #[derive(Debug)]
    pub struct IndexedParam {
        pub param: Param,
        pub payment_index: usize,
    }

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

        return false;
    }

    pub fn to_payment(vs: Vec<Param>, i: usize) -> Result<Zip321Payment, String> {
        let mut addr: Option<Address> = None;
        for v in &vs {
            match v {
                Param::Addr(a) => addr = Some(a.clone()),
                _otherwise => {}
            }
        }

        let mut payment = Zip321Payment {
            recipient_address: addr.ok_or(format!("Payment {} had no recipient address.", i))?,
            amount: Amount::zero(),
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        };

        for v in vs {
            match v {
                Param::Amount(a) => payment.amount = a.clone(),
                Param::Memo(m) => {
                    match payment.recipient_address {
                        Address::Sapling(_) => payment.memo = Some(m),
                        Address::Transparent(_) => return Err(format!("Payment {} attempted to associate a memo with a transparent recipient address", i)),
                    }
                },

                Param::Label(m) => payment.label = Some(m),
                Param::Message(m) => payment.message = Some(m),
                Param::Other(n, m) => payment.other_params.push((n, m)),
                _otherwise => {}
            }
        }

        return Ok(payment);
    }

    /// Parser that consumes the leading "zcash:[address]" from
    /// a zip-0321 URI.
    pub fn lead_addr<'a, P: consensus::Parameters>(
        params: &'a P,
    ) -> impl Fn(&str) -> IResult<&str, Option<IndexedParam>> + 'a {
        move |input: &str| {
            let (input, _) = tag("zcash:")(input)?;
            let (input, addr) = map_res(take_until("?"), |i| Address::parse(params, i))(input)?;
            let primary_addr_param = addr.map(|a| IndexedParam {
                param: Param::Addr(a),
                payment_index: 0,
            });

            Ok((input, primary_addr_param))
        }
    }

    /// The primary parser for <name>=<value> query-string
    /// parameter pair.
    pub fn zcashparam<'a, P: consensus::Parameters>(
        params: &'a P,
    ) -> impl Fn(&str) -> IResult<&str, IndexedParam> + 'a {
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
    fn alphanum_or(allowed: String) -> impl (Fn(&str) -> IResult<&str, &str>) {
        move |input| {
            input.split_at_position_complete(|item| {
                let c = item.as_char();
                !(c.is_alphanum() || allowed.contains(c))
            })
        }
    }

    pub fn qchars(input: &str) -> IResult<&str, &str> {
        alphanum_or("-._~!$'()*+,;:@%".to_string())(input)
    }

    pub fn namechars(input: &str) -> IResult<&str, &str> {
        alphanum_or("+-".to_string())(input)
    }

    pub fn indexed_name<'a>(input: &'a str) -> IResult<&'a str, (&'a str, Option<&'a str>)> {
        let paramname = recognize(tuple((alpha1, namechars)));

        tuple((
            paramname,
            opt(preceded(
                char('.'),
                recognize(tuple((one_of("123456789"), digit0))),
            )),
        ))(input)
    }

    pub fn parse_amount<'a>(input: &'a str) -> IResult<&'a str, Amount> {
        map_res(
            tuple((digit1, opt(preceded(char('.'), digit1)))),
            |(whole_s, decimal_s): (&str, Option<&str>)| {
                let coins: i64 = whole_s
                    .to_string()
                    .parse::<i64>()
                    .map_err(|e| e.to_string())?;

                let zats: i64 = match decimal_s {
                    Some(d) => d
                        .char_indices()
                        .map(|(i, c)| {
                            let digit: i64 = c.to_digit(10).unwrap().into();
                            digit * 10i64.pow((7 - i).try_into().unwrap())
                        })
                        .sum::<i64>()
                        .into(),
                    None => 0,
                };

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
            "address" => Address::parse(params, value)
                .map_err(|e| match e {
                    AddrParseError::TAddrError(_) => format!(
                        "Could not interpret {} as a valid transparent address.",
                        value
                    ),
                    AddrParseError::SAddrError(_) => {
                        format!("Could not interpret {} as a valid Sapling address.", value)
                    }
                })
                .and_then(|addr_opt| {
                    addr_opt.map(Param::Addr).ok_or(format!(
                        "Could not interpret {} as a valid Zcash address.",
                        value
                    ))
                }),

            "amount" => parse_amount(value)
                .map(|(_, a)| Param::Amount(a))
                .map_err(|e| e.to_string()),

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
            Some(istr) => istr
                .to_string()
                .parse::<usize>()
                .map(Some)
                .map_err(|e| e.to_string()),
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
    use proptest::collection::vec;
    use proptest::option;
    use proptest::prelude::*;
    use proptest::strategy::Strategy;
    use zcash_primitives::{
        consensus::TEST_NETWORK, keys::testing::arb_shielded_addr,
        legacy::testing::arb_transparent_addr,
        transaction::components::amount::testing::arb_amount,
    };

    use super::{memo_from_vec, Address, RawMemo, Zip321Payment, Zip321Request};

    pub fn arb_addr() -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_shielded_addr().prop_map(Address::Sapling),
            arb_transparent_addr().prop_map(Address::Transparent),
        ]
    }

    pub const VALID_PARAMNAME: &str = "[a-zA-Z][a-zA-Z0-9+-]*";

    prop_compose! {
        pub fn arb_valid_memo()(bytes in vec(any::<u8>(), 0..512)) -> RawMemo {
            memo_from_vec(&bytes).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_zip321_payment()(
            recipient_address in arb_addr(),
            amount in arb_amount(),
            memo in option::of(arb_valid_memo()),
            message in option::of(any::<String>()),
            label in option::of(any::<String>()),
            other_params in vec((VALID_PARAMNAME, any::<String>()), 0..3),
            ) -> Zip321Payment {

            let is_sapling = match recipient_address {
                Address::Transparent(_) => false,
                Address::Sapling(_) => true,
            };

            Zip321Payment {
                recipient_address,
                amount,
                memo: memo.filter(|_| is_sapling),
                label,
                message,
                other_params,
            }
        }
    }

    prop_compose! {
        pub fn arb_zip321_request()(payments in vec(arb_zip321_payment(), 1..10)) -> Zip321Request {
            let mut req = Zip321Request { payments };
            req.normalize(&TEST_NETWORK); // just to make test comparisons easier
            req
        }
    }

    prop_compose! {
        pub fn arb_zip321_uri()(req in arb_zip321_request()) -> String {
            req.to_uri(&TEST_NETWORK).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_addr_str()(addr in arb_addr()) -> String {
            addr.render(&TEST_NETWORK)
        }
    }
}

#[cfg(test)]
mod tests {
    use zcash_primitives::{
        consensus::{Parameters, TEST_NETWORK},
        transaction::components::Amount,
    };

    use super::{
        memo_from_base64, memo_to_base64,
        parse::{parse_amount, zcashparam, Param},
        render::amount_str,
        Address, RawMemo, Zip321Payment, Zip321Request,
    };
    use crate::encoding::decode_payment_address;

    #[cfg(all(test, feature = "test-dependencies"))]
    use proptest::prelude::*;

    #[cfg(all(test, feature = "test-dependencies"))]
    use zcash_primitives::transaction::components::amount::testing::arb_amount;

    #[cfg(all(test, feature = "test-dependencies"))]
    use super::{
        render::{memo_param, str_param},
        testing::{arb_addr, arb_addr_str, arb_valid_memo, arb_zip321_request, arb_zip321_uri},
    };

    fn check_roundtrip(req: Zip321Request) {
        if let Some(req_uri) = req.to_uri(&TEST_NETWORK) {
            let parsed = Zip321Request::from_uri(&TEST_NETWORK, &req_uri).unwrap();
            assert_eq!(parsed, req);
        } else {
            panic!("Generated invalid payment request: {:?}", req);
        }
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
        let parse_result = Zip321Request::from_uri(&TEST_NETWORK, &uri).unwrap();

        let expected = Zip321Request {
            payments: vec![
                Zip321Payment {
                    recipient_address: Address::Sapling(decode_payment_address(&TEST_NETWORK.hrp_sapling_payment_address(), "ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k").unwrap().unwrap()),
                    amount: Amount::from_u64(376876902796286).unwrap(),
                    memo: None,
                    label: None,
                    message: Some("".to_string()),
                    other_params: vec![],
                }
            ]
        };

        assert_eq!(parse_result, expected);
    }

    #[test]
    fn test_zip321_roundtrip_empty_message() {
        let req = Zip321Request {
            payments: vec![
                Zip321Payment {
                    recipient_address: Address::Sapling(decode_payment_address(TEST_NETWORK.hrp_sapling_payment_address(), "ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k").unwrap().unwrap()),
                    amount: Amount::from_u64(0).unwrap(),
                    memo: None,
                    label: None,
                    message: Some("".to_string()),
                    other_params: vec![]
                }
            ]
        };

        check_roundtrip(req);
    }

    #[test]
    fn test_zip321_memos() {
        let m_simple: RawMemo = "This is a simple memo.".parse().unwrap();
        let m_simple_64 = memo_to_base64(&m_simple);
        assert_eq!(memo_from_base64(&m_simple_64).unwrap(), m_simple);

        let m_json: RawMemo = "{ \"key\": \"This is a JSON-structured memo.\" }"
            .parse()
            .unwrap();
        let m_json_64 = memo_to_base64(&m_json);
        assert_eq!(memo_from_base64(&m_json_64).unwrap(), m_json);

        let m_unicode: RawMemo = "This is a unicode memo ✨🦄🏆🎉".parse().unwrap();
        let m_unicode_64 = memo_to_base64(&m_unicode);
        assert_eq!(memo_from_base64(&m_unicode_64).unwrap(), m_unicode);
    }

    #[test]
    fn test_zip321_spec_valid_examples() {
        let valid_1 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=1&memo=VGhpcyBpcyBhIHNpbXBsZSBtZW1vLg&message=Thank%20you%20for%20your%20purchase";
        let v1r = Zip321Request::from_uri(&TEST_NETWORK, &valid_1).unwrap();
        assert_eq!(
            v1r.payments.get(0).map(|p| p.amount),
            Some(Amount::from_u64(100000000).unwrap())
        );

        let valid_2 = "zcash:?address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&amount=123.456&address.1=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.1=0.789&memo.1=VGhpcyBpcyBhIHVuaWNvZGUgbWVtbyDinKjwn6aE8J-PhvCfjok";
        let mut v2r = Zip321Request::from_uri(&TEST_NETWORK, &valid_2).unwrap();
        v2r.normalize(&TEST_NETWORK);
        assert_eq!(
            v2r.payments.get(0).map(|p| p.amount),
            Some(Amount::from_u64(12345600000).unwrap())
        );
        assert_eq!(
            v2r.payments.get(1).map(|p| p.amount),
            Some(Amount::from_u64(78900000).unwrap())
        );

        // valid; amount just less than MAX_MONEY
        // 20999999.99999999
        let valid_3 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=20999999.99999999";
        let v3r = Zip321Request::from_uri(&TEST_NETWORK, &valid_3).unwrap();
        assert_eq!(
            v3r.payments.get(0).map(|p| p.amount),
            Some(Amount::from_u64(2099999999999999u64).unwrap())
        );

        // valid; MAX_MONEY
        // 21000000
        let valid_4 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=21000000";
        let v4r = Zip321Request::from_uri(&TEST_NETWORK, &valid_4).unwrap();
        assert_eq!(
            v4r.payments.get(0).map(|p| p.amount),
            Some(Amount::from_u64(2100000000000000u64).unwrap())
        );
    }

    #[test]
    fn test_zip321_spec_invalid_examples() {
        // invalid; missing `address=` or `address.0=`
        let invalid_1 = "zcash:?amount=3491405.05201255&address.1=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.1=5740296.87793245";
        let i1r = Zip321Request::from_uri(&TEST_NETWORK, &invalid_1);
        assert!(i1r.is_err());

        // invalid; missing `address.1=`
        let invalid_2 = "zcash:?address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&amount=1&amount.1=2&address.2=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez";
        let i2r = Zip321Request::from_uri(&TEST_NETWORK, &invalid_2);
        assert!(i2r.is_err());

        // invalid; `address.0=` and `amount.0=` are not permitted (leading 0s).
        let invalid_3 = "zcash:?address.0=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.0=2";
        let i3r = Zip321Request::from_uri(&TEST_NETWORK, &invalid_3);
        assert!(i3r.is_err());

        // invalid; duplicate `amount=` field
        let invalid_4 =
            "zcash:?amount=1.234&amount=2.345&address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";
        let i4r = Zip321Request::from_uri(&TEST_NETWORK, &invalid_4);
        assert!(i4r.is_err());

        // invalid; duplicate `amount.1=` field
        let invalid_5 =
            "zcash:?amount.1=1.234&amount.1=2.345&address.1=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";
        let i5r = Zip321Request::from_uri(&TEST_NETWORK, &invalid_5);
        assert!(i5r.is_err());

        //invalid; memo associated with t-addr
        let invalid_6 = "zcash:?address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&amount=123.456&memo=eyAia2V5IjogIlRoaXMgaXMgYSBKU09OLXN0cnVjdHVyZWQgbWVtby4iIH0&address.1=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.1=0.789&memo.1=VGhpcyBpcyBhIHVuaWNvZGUgbWVtbyDinKjwn6aE8J-PhvCfjok";
        let i6r = Zip321Request::from_uri(&TEST_NETWORK, &invalid_6);
        assert!(i6r.is_err());

        // invalid; amount component exceeds an i64
        // 9223372036854775808 = i64::MAX + 1
        let invalid_7 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=9223372036854775808";
        let i7r = Zip321Request::from_uri(&TEST_NETWORK, &invalid_7);
        assert!(i7r.is_err());

        // invalid; amount component is MAX_MONEY
        // 21000000.00000001 = 
        let invalid_8 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=21000000.00000001";
        let i8r = Zip321Request::from_uri(&TEST_NETWORK, &invalid_8);
        assert!(i8r.is_err());

        // invalid; negative amount
        let invalid_9 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=-1";
        let i9r = Zip321Request::from_uri(&TEST_NETWORK, &invalid_9);
        assert!(i9r.is_err());
    }

    #[cfg(all(test, feature = "test-dependencies"))]
    proptest! {
        #[test]
        fn prop_zip321_roundtrip_address(addr in arb_addr()) {
            let a = addr.render(&TEST_NETWORK);
            assert_eq!(Address::parse(&TEST_NETWORK, &a).unwrap(), Some(addr));
        }

        #[test]
        fn prop_zip321_roundtrip_address_str(a in arb_addr_str()) {
            let addr = Address::parse(&TEST_NETWORK, &a).unwrap().unwrap();
            assert_eq!(addr.render(&TEST_NETWORK), a);
        }

        #[test]
        fn prop_zip321_roundtrip_amount(amt in arb_amount()) {
            let amt_str = amount_str(amt).unwrap();
            assert_eq!(amt, parse_amount(&amt_str).unwrap().1);
        }

        #[test]
        fn prop_zip321_roundtrip_str_param(
            message in any::<String>(), i in proptest::option::of(any::<usize>())) {
            let fragment = str_param("message", &message, i);
            let (rest, iparam) = zcashparam(&TEST_NETWORK)(&fragment).unwrap();
            assert_eq!(rest, "");
            assert_eq!(iparam.param, Param::Message(message));
            assert_eq!(iparam.payment_index, i.unwrap_or(0));
        }

        #[test]
        fn prop_zip321_roundtrip_memo_param(
            memo in arb_valid_memo(), i in proptest::option::of(any::<usize>())) {
            let fragment = memo_param(&memo, i);
            let (rest, iparam) = zcashparam(&TEST_NETWORK)(&fragment).unwrap();
            assert_eq!(rest, "");
            assert_eq!(iparam.param, Param::Memo(memo));
            assert_eq!(iparam.payment_index, i.unwrap_or(0));
        }

        #[test]
        fn prop_zip321_roundtrip_request(mut req in arb_zip321_request()) {
            if let Some(req_uri) = req.to_uri(&TEST_NETWORK) {
                let mut parsed = Zip321Request::from_uri(&TEST_NETWORK, &req_uri).unwrap();
                assert!(Zip321Request::normalize_and_eq(&TEST_NETWORK, &mut parsed, &mut req));
            } else {
                panic!("Generated invalid payment request: {:?}", req);
            }
        }

        #[test]
        fn prop_zip321_roundtrip_uri(uri in arb_zip321_uri()) {
            let mut parsed = Zip321Request::from_uri(&TEST_NETWORK, &uri).unwrap();
            parsed.normalize(&TEST_NETWORK);
            let serialized = parsed.to_uri(&TEST_NETWORK);
            assert_eq!(serialized, Some(uri))
        }
    }
}
