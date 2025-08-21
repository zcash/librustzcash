//! Types and functions used for parsing.

use std::borrow::Cow;

use nom::{AsChar, Parser};
use snafu::prelude::*;

#[derive(Debug, Snafu)]
pub enum ParseError<'a> {
    #[snafu(display("{}", nom::error::Error::to_string(&nom::error::Error {
        input: *input, code: *code
    })))]
    Nom {
        input: &'a str,
        code: nom::error::ErrorKind,
        other: Option<String>,
    },

    #[snafu(display(
        "Expected at least {min} digits, saw {} before {}",
        digits.len(),
        input.split_at(10).0
    ))]
    DigitsMinimum {
        min: usize,
        digits: Vec<u8>,
        input: &'a str,
    },

    #[snafu(display("Missing ENS name"))]
    EnsMissing,

    #[snafu(display("Not a domain"))]
    EnsDomain,

    #[snafu(display("{source}"))]
    EnsNormalization {
        source: ens_normalize_rs::ProcessError,
    },

    #[snafu(display(
        "Invalid bit size. Expected {}..={} but saw {seen}",
        range.start(),
        range.end()
    ))]
    InvalidBitRange {
        range: std::ops::RangeInclusive<u32>,
        seen: u64,
    },

    #[snafu(display("Bit size must be a multiple of 8, saw {seen}"))]
    InvalidBitSize { seen: u64 },

    #[snafu(display("Invalid parameter value. Expected a number."))]
    InvalidParameterValue,
}

impl<'a> nom::error::ParseError<&'a str> for ParseError<'a> {
    fn from_error_kind(input: &'a str, code: nom::error::ErrorKind) -> Self {
        NomSnafu {
            input,
            code,
            other: None,
        }
        .build()
    }

    fn append(input: &'a str, code: nom::error::ErrorKind, other: Self) -> Self {
        NomSnafu {
            input,
            code,
            other: Some(other.to_string()),
        }
        .build()
    }
}

impl<'a> From<ParseError<'a>> for nom::Err<ParseError<'a>> {
    fn from(value: ParseError<'a>) -> Self {
        if value.is_recoverable() {
            nom::Err::Error(value)
        } else {
            nom::Err::Failure(value)
        }
    }
}

impl ParseError<'_> {
    pub fn is_recoverable(&self) -> bool {
        true
    }
}

#[derive(Debug, Snafu, PartialEq)]
pub enum ValidationError {
    #[snafu(display("Exponent is too small, expected at least {expected}, saw {seen}"))]
    SmallExponent { expected: usize, seen: u64 },

    #[snafu(display("Exponent {seen} is too big and has saturated"))]
    BigExponent { seen: u64 },

    #[snafu(display("Could not decode url-encoded string: {source}"))]
    UrlEncoding { source: std::str::Utf8Error },
}

/// Zero or more consecutive digits.
///
/// ```abnf
/// *DIGIT
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Digits {
    places: Vec<u8>,
}

impl core::fmt::Display for Digits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for n in self.places.iter() {
            f.write_fmt(format_args!("{n}"))?;
        }
        Ok(())
    }
}

impl Digits {
    pub const MAX_PLACES: usize = u64::MAX.ilog10() as usize;

    pub fn as_u64(&self) -> u64 {
        let mut total = 0;
        for (mag, digit) in self.places.iter().rev().enumerate() {
            total += *digit as u64 * 10u64.pow(mag as u32);
        }
        total
    }

    /// Returns the digits as a ratio, where prefixed zeros
    /// are treated as a denominator.
    pub fn as_decimal_ratio(&self) -> (u64, u64) {
        let mut numerator = 0;
        let denominator = 10u64.pow(self.places.len() as u32);
        // Skip the prefixed zeros to build an integer numerator
        let rest = self
            .places
            .iter()
            .skip_while(|n| **n == 0)
            .collect::<Vec<_>>();
        for (mag, digit) in rest.into_iter().rev().enumerate() {
            numerator += *digit as u64 * 10u64.pow(mag as u32);
        }

        (numerator, denominator)
    }

    pub fn from_u64(mut v: u64) -> Self {
        if v == 0 {
            return Digits { places: vec![0] };
        }

        let mut digits = Digits { places: vec![] };
        for log in (0..=v.ilog10()).rev() {
            let top = 10u64.pow(log);
            let digit = v / top;
            digits.places.push(digit as u8);
            v -= digit * top;
        }
        digits
    }

    /// Parse at least `min` digits.
    pub fn parse_min(i: &str, min: usize) -> nom::IResult<&str, Self, ParseError<'_>> {
        let (i, places) = parse_min(i, min, false)?;
        Ok((i, Digits { places }))
    }
}

/// Parse at least `min` digits.
pub fn parse_min(i: &str, min: usize, is_hex: bool) -> nom::IResult<&str, Vec<u8>, ParseError<'_>> {
    let radix = if is_hex { 16 } else { 10 };
    let (i, chars) = nom::bytes::complete::take_while(|c: char| c.is_digit(radix))(i)?;
    let data = chars
        .chars()
        .map(|c| {
            c.to_digit(radix)
                .unwrap_or_else(|| unreachable!("we already checked that this char was a digit"))
                as u8
        })
        .collect::<Vec<_>>();
    snafu::ensure!(
        data.len() >= min,
        DigitsMinimumSnafu {
            min,
            digits: data,
            input: i
        }
    );
    Ok((i, data))
}

/// Zero or more consecutive hexidecimal digits.
///
/// ```abnf
/// *HEXDIG
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct HexDigits {
    places: Vec<u8>,
}

impl core::fmt::Display for HexDigits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for n in self.places.iter() {
            f.write_fmt(format_args!("{n:x}"))?;
        }
        Ok(())
    }
}

impl HexDigits {
    /// Parse at least `min` digits.
    pub fn parse_min(i: &str, min: usize) -> nom::IResult<&str, Self, ParseError<'_>> {
        let (i, places) = parse_min(i, min, true)?;
        Ok((i, HexDigits { places }))
    }
}

/// A parsed number.
///
/// ```abnf
/// number = [ "-" / "+" ] *DIGIT [ "." 1*DIGIT ] [ ( "e" / "E" ) [ 1*DIGIT ] ]
/// ```
///
/// A number can be expressed in scientific notation, with a
/// multiplier of a power of 10. Only integer numbers are allowed, so the
/// exponent MUST be greater or equal to the number of decimals after the point.
///
/// ## Note
/// This ABNF notation is doesn't seem correct, as it allows for quite a few
/// cases that don't make sense - for example:
///
/// 1. `*DIGIT` is missing and `[ "." 1*DIGIT ]` is present while `[ ( "e" / "E" ) [ 1*DIGIT] ]`
///    is not
/// 2. `[ ( "e" / "E" ) [ 1*DIGIT] ]` is missing the `[ 1*DIGIT ]` (eg, just "e")
/// 3. The decimal is present while the exponent is missing
/// 4. only `"-" / "+"` is present
/// 5. ...others
///
/// For this reason, in this library, parsing is separate from validation.
///
/// Other implementations use regular expressions instead of parsing, and only
/// support very specific values.  
///
// TODO(schell):
//   - tell someone about the bugs in the ABNF syntax
#[derive(Debug, PartialEq)]
pub struct Number {
    /// true for "+", false for "-"
    signum: Option<bool>,
    integer: Digits,
    decimal: Option<Digits>,
    exponent: Option<(
        // true for "e", false for "E"
        bool,
        Option<Digits>,
    )>,
}

impl core::fmt::Display for Number {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let this = &self;
        let Number {
            signum,
            integer,
            decimal,
            exponent,
        } = this;
        if let Some(signum) = signum {
            f.write_str(if *signum { "+" } else { "-" })?;
        }
        integer.fmt(f)?;
        if let Some(dec) = decimal {
            f.write_fmt(format_args!(".{dec}"))?;
        };
        if let Some((little_e, maybe_exp)) = exponent {
            f.write_str(if *little_e { "e" } else { "E" })?;
            if let Some(exp) = maybe_exp {
                exp.fmt(f)?;
            }
        }
        Ok(())
    }
}

impl Number {
    /// Parse a `Number`.
    ///
    /// /// ```abnf
    /// number = [ "-" / "+" ] *DIGIT [ "." 1*DIGIT ] [ ( "e" / "E" ) [ 1*DIGIT ] ]
    /// ```
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        // Parse [ "-" / "+" ]
        let parse_signum_pos = nom::character::complete::char('+').map(|_| true);
        let parse_signum_neg = nom::character::complete::char('-').map(|_| false);
        let parse_signum = parse_signum_pos.or(parse_signum_neg);
        let (i, signum) = nom::combinator::opt(parse_signum)(i)?;

        // Parse *DIGIT
        let (i, integer) = Digits::parse_min(i, 0)?;

        // Parse [ "." 1*DIGIT ]
        fn parse_decimal(i: &str) -> nom::IResult<&str, Digits, ParseError<'_>> {
            let (i, _dot) = nom::character::complete::char('.')(i)?;
            let (i, digits) = Digits::parse_min(i, 1)?;
            Ok((i, digits))
        }
        let (i, decimal) = nom::combinator::opt(parse_decimal)(i)?;

        // Parse [ ( "e" / "E" ) [ 1*DIGIT ] ]
        fn parse_exponent(i: &str) -> nom::IResult<&str, (bool, Option<Digits>), ParseError<'_>> {
            // Parse ( "e" / "E" )
            let parse_little_e = nom::character::complete::char('e').map(|_| true);
            let parse_big_e = nom::character::complete::char('E').map(|_| false);
            let mut parse_e = parse_little_e.or(parse_big_e);
            let (i, little_e) = parse_e.parse(i)?;

            // Parse [ 1*DIGIT ]
            let (i, maybe_exp) = nom::combinator::opt(|i| Digits::parse_min(i, 1))(i)?;

            Ok((i, (little_e, maybe_exp)))
        }
        let (i, exponent) = nom::combinator::opt(parse_exponent)(i)?;

        Ok((
            i,
            Self {
                signum,
                integer,
                decimal,
                exponent,
            },
        ))
    }

    /// Returns the value of the integer portion of the number.
    pub fn integer(&self) -> u64 {
        self.integer.as_u64()
    }

    /// Returns the value of the decimal portion of the number as a ratio
    /// of `u64`s.
    pub fn decimal(&self) -> (u64, u64) {
        self.decimal
            .as_ref()
            .map(|d| d.as_decimal_ratio())
            .unwrap_or((0, 1))
    }

    /// Convert this [`Number`] into an i128, if possible.
    pub fn as_i128(&self) -> Result<i128, ValidationError> {
        let signum = self
            .signum
            .map(|is_positive| if is_positive { 1 } else { -1 })
            .unwrap_or(1i128);
        dbg!(signum);
        let integer = self.integer();
        dbg!(integer);
        let (decimal_numerator, decimal_denominator) = self.decimal();
        dbg!(decimal_numerator);
        dbg!(decimal_denominator);
        let exp = self
            .exponent
            .as_ref()
            .and_then(|(_, maybe_exp)| maybe_exp.as_ref().map(|digits| digits.as_u64() as u32))
            .unwrap_or_default();
        dbg!(exp);
        let multiplier = 10u64.saturating_pow(exp);
        snafu::ensure!(multiplier < u64::MAX, BigExponentSnafu { seen: exp });
        dbg!(multiplier);
        let modulo = multiplier % decimal_denominator;
        dbg!(modulo);
        snafu::ensure!(
            modulo == 0 || decimal_numerator == 0,
            SmallExponentSnafu {
                expected: decimal_denominator.ilog10() as usize,
                seen: exp
            }
        );
        let multiplied_integer = integer * multiplier;
        let decimal_multiplier = multiplier / decimal_denominator;
        let multiplied_decimal = decimal_numerator * decimal_multiplier;
        Ok(signum * (multiplied_integer as i128 + multiplied_decimal as i128))
    }
}

/// Ethereum Name Service name.
///
/// See [EIP-137](https://eips.ethereum.org/EIPS/eip-137).
///
/// Examples:
/// * dao.eth
/// * linea.eth
///
/// Uses:
/// * https://crates.io/crates/ens-normalize-rs
///
/// ENS names must conform to the following syntax:
///
/// ## Name Syntax
///
/// ```not_abnf
/// <domain> ::= <label> | <domain> "." <label>
/// <label> ::= any valid string label per [UTS46](https://unicode.org/reports/tr46/)
/// ```
///
/// In short, names consist of a series of dot-separated labels.
///
/// ## Note
/// There's nothing in the spec that says an ENS name _must_ contain a '.', but for the
/// purposes of this library it is required.
#[derive(Clone, Debug, PartialEq)]
pub struct EnsName(String);

impl core::fmt::Display for EnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl EnsName {
    const DELIMITERS: &[char] = &['@', '/', '?', '&'];

    /// Parse an `EnsName`.
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        fn continue_parsing(c: char) -> bool {
            !c.is_whitespace() && !EnsName::DELIMITERS.contains(&c)
        }

        let (i, name) = nom::bytes::complete::take_till(|c| !continue_parsing(c))(i)?;
        snafu::ensure!(!name.is_empty(), EnsMissingSnafu);
        snafu::ensure!(name.contains('.'), EnsMissingSnafu);

        // Now we have our name, normalize
        let normalized_name = ens_normalize_rs::normalize(name).context(EnsNormalizationSnafu)?;

        Ok((i, EnsName(normalized_name)))
    }
}

/// An Ethereum address.
///
/// ```abnf
/// ethereum_address = ( "0x" 40*HEXDIG ) / ENS_NAME
/// ```
///
/// Where `ENS_NAME` is [`EnsName`].
#[derive(Clone, Debug, PartialEq)]
pub enum EthereumAddress {
    Hex(HexDigits),
    Name(EnsName),
}

impl core::fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EthereumAddress::Hex(digits) => f.write_fmt(format_args!("0x{digits}")),
            EthereumAddress::Name(name) => name.fmt(f),
        }
    }
}

impl EthereumAddress {
    /// Parse an `EthereumAddress`.
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        // Parse "0x" and then 40+ hex digits
        fn parse_40plus_hex(i: &str) -> nom::IResult<&str, EthereumAddress, ParseError<'_>> {
            let (i, _) = nom::bytes::complete::tag("0x")(i)?;
            let (i, digits) = HexDigits::parse_min(i, 40)?;
            Ok((i, EthereumAddress::Hex(digits)))
        }
        let parse_ens = EnsName::parse.map(EthereumAddress::Name);
        let mut parse_address = parse_40plus_hex.or(parse_ens);
        let (i, address) = parse_address.parse(i)?;
        Ok((i, address))
    }
}

/// A URL-encoded unicode string of arbitrary length, where delimiters and the
/// percentage symbol are mandatorily hex-encoded with a `%` prefix.
#[derive(Debug, PartialEq)]
pub struct UrlEncodedUnicodeString(String);

impl core::fmt::Display for UrlEncodedUnicodeString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl UrlEncodedUnicodeString {
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        fn should_continue_parsing(c: char) -> bool {
            c.is_alphanumeric() || c == '%'
        }
        let (i, s) = nom::bytes::complete::take_while(should_continue_parsing)(i)?;
        Ok((i, UrlEncodedUnicodeString(s.to_string())))
    }

    pub fn encode(input: impl AsRef<str>) -> Self {
        let s = percent_encoding::utf8_percent_encode(
            input.as_ref(),
            percent_encoding::NON_ALPHANUMERIC,
        );
        UrlEncodedUnicodeString(s.to_string())
    }

    pub fn decode(&self) -> Result<Cow<'_, str>, ValidationError> {
        let decoder = percent_encoding::percent_decode(self.0.as_bytes());
        let cow = decoder.decode_utf8().context(UrlEncodingSnafu)?;
        Ok(cow)
    }
}

/// A parameter value.
///
/// ```abnf
/// value = number / ethereum_address / STRING
/// ```
#[derive(Debug, PartialEq)]
pub enum Value {
    Number(Number),
    Address(EthereumAddress),
    String(UrlEncodedUnicodeString),
}

impl core::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Number(n) => n.fmt(f),
            Value::Address(a) => a.fmt(f),
            Value::String(s) => s.fmt(f),
        }
    }
}

impl Value {
    /// Parse a `Value`.
    ///
    /// ```abnf
    /// value = number / ethereum_address / STRING
    /// ```
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        let mut number = Number::parse.map(Value::Number);
        let mut ethereum_address = EthereumAddress::parse.map(Value::Address);
        let mut string = UrlEncodedUnicodeString::parse.map(Value::String);

        // Here there are some interesting corner cases:
        //
        // 1. In `number`'s spec, absolutely everything is optional, so it _never_ fails.
        // 2. `ethereum_address` may be prefixed with `0` in the hex-address case, so both number
        //   and address could be parsed. Because of 1, `number` always wins if it comes first, but
        //   even if the minimum was 1 digit `number` would still win by parsing "0", so
        //   we can't simply apply them with `number`.or(`address`).
        // 3. `string` will always match a valid `number`.
        //
        // To solve all of these cases we run all three parsers and then return whichever one
        // consumed the most input.
        //
        // In practice this should be fine because values either end with `&` (in the case of
        // more parameters after it) or with the end of the input.

        let mut results = [number.parse(i), ethereum_address.parse(i), string.parse(i)];
        results.sort_by_key(|a| {
            // Sort by the amount of input left over, smallest first
            a.as_ref().ok().map(|(i, _)| i.len()).unwrap_or(usize::MAX)
        });
        // UNWRAP: safe because this was an array of 3
        results.into_iter().next().unwrap()
    }

    /// Return the value as a [`Number`], if possible.
    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Value::Number(n) => Some(n),
            _ => None,
        }
    }
}

/// An Ethereum ABI type name.
///
/// See [Solidity ABI types](https://docs.soliditylang.org/en/develop/abi-spec.html#types)
/// for more info.
///
/// ## Note
/// Instead of parsing [`Type`] as a nested syntax tree, we instead only parse the _name_.
// TODO(schell): If we do end up wanting a syntax tree, I have the start of one on the branch
// `feat/eip-681-tx-req-parser-solidity-types`
#[derive(Clone, Debug, PartialEq)]
pub struct EthereumAbiTypeName {
    name: String,
}

impl core::fmt::Display for EthereumAbiTypeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.name.fmt(f)
    }
}

impl EthereumAbiTypeName {
    /// Parse a `Type`.
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        fn is_type_char(c: char) -> bool {
            let chars = &[
                '[', ']', // Arrays
                '<', '>', // Type constructors
                '(', ')', ',', // Tuples
            ];
            c.is_alphanum() || chars.contains(&c)
        }
        let (i, s) = nom::bytes::complete::take_while1(is_type_char)(i)?;
        Ok((i, EthereumAbiTypeName { name: s.to_owned() }))
    }
}

/// A parameter key.
///
/// ```abnf
/// key = "value" / "gas" / "gasLimit" / "gasPrice" / TYPE
/// ```
#[derive(Clone, Debug, PartialEq)]
pub enum Key {
    Value,
    Gas,
    GasLimit,
    GasPrice,
    Type(EthereumAbiTypeName),
}

impl core::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Value => f.write_str("value"),
            Key::Gas => f.write_str("gas"),
            Key::GasLimit => f.write_str("gasLimit"),
            Key::GasPrice => f.write_str("gasPrice"),
            Key::Type(ty) => ty.fmt(f),
        }
    }
}

impl Key {
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        let parse_value = nom::bytes::complete::tag("value").map(|_| Key::Value);
        let parse_gas = nom::bytes::complete::tag("gas").map(|_| Key::Gas);
        let parse_gas_limit = nom::bytes::complete::tag("gasLimit").map(|_| Key::GasLimit);
        let parse_gas_price = nom::bytes::complete::tag("gasPrice").map(|_| Key::GasPrice);

        nom::branch::alt((
            parse_value,
            parse_gas_limit,
            parse_gas_price,
            parse_gas,
            EthereumAbiTypeName::parse.map(Key::Type),
        ))(i)
    }
}

/// A key-value pair.
#[derive(Debug, PartialEq)]
pub struct Parameter {
    key: Key,
    value: Value,
}

impl core::fmt::Display for Parameter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}={}", self.key, self.value))
    }
}

impl Parameter {
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        let (i, key) = Key::parse(i)?;
        let (i, _eq) = nom::character::complete::char('=')(i)?;
        let (i, value) = Value::parse(i)?;
        // If key in the parameter list is value, gasLimit, gasPrice or gas then
        // value MUST be a number. Otherwise, it must correspond to the TYPE
        // string used as key.
        match &key {
            Key::Value | Key::Gas | Key::GasLimit | Key::GasPrice => {
                snafu::ensure!(
                    matches!(value, Value::Number(_)),
                    InvalidParameterValueSnafu
                );
            }
            Key::Type(_ty) => {
                // For the moment, we're not going to check the type here.
            }
        }

        Ok((i, Parameter { key, value }))
    }
}

/// A collection of [`Parameter`].
#[derive(Debug, PartialEq)]
pub struct Parameters(Vec<Parameter>);

impl core::fmt::Display for Parameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut iter = self.0.iter();
        if let Some(first) = iter.next() {
            first.fmt(f)?;
            for other in iter {
                f.write_str("&")?;
                other.fmt(f)?;
            }
        }
        Ok(())
    }
}

impl Parameters {
    /// Parses zero or more parameters, separated by '&'.
    ///
    /// ## Note
    /// This parser never fails.
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        let (i, maybe_head) = nom::combinator::opt(Parameter::parse).parse(i)?;
        if let Some(head) = maybe_head {
            let parse_next_param =
                nom::sequence::preceded(nom::bytes::complete::tag("&"), Parameter::parse);
            let (i, tail) = nom::multi::many0(parse_next_param)(i)?;
            let mut parameters = vec![head];
            parameters.extend(tail);
            Ok((i, Parameters(parameters)))
        } else {
            Ok((i, Parameters(vec![])))
        }
    }

    /// Return the value of the parameter with the given `key`, if any.
    pub fn get_value(&self, key: &Key) -> Option<&Value> {
        for param in self.0.iter() {
            if &param.key == key {
                return Some(&param.value);
            }
        }
        None
    }
}

/// Schema prefix.
///
/// ```absnf
/// schema_prefix = "ethereum" ":" [ "pay-" ]
/// ```
#[derive(Debug, PartialEq)]
pub struct SchemaPrefix {
    has_pay: bool,
}

impl core::fmt::Display for SchemaPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ethereum:")?;
        if self.has_pay {
            f.write_str("pay-")?;
        }
        Ok(())
    }
}

impl SchemaPrefix {
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        let (i, _) = nom::bytes::complete::tag("ethereum:")(i)?;
        let (i, maybe_pay) = nom::combinator::opt(nom::bytes::complete::tag("pay-"))(i)?;
        let has_pay = maybe_pay.is_some();
        Ok((i, SchemaPrefix { has_pay }))
    }
}

/// Ethereum transaction request.
///
/// ```abnf
/// request = schema_prefix target_address [ "@" chain_id ] [ "/" function_name ] [ "?" parameters ]
/// ```
#[derive(Debug, PartialEq)]
pub struct EthereumTransactionRequest {
    pub schema_prefix: SchemaPrefix,
    pub target_address: EthereumAddress,
    pub chain_id: Option<Digits>,
    pub function_name: Option<UrlEncodedUnicodeString>,
    pub parameters: Parameters,
}

impl core::fmt::Display for EthereumTransactionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            schema_prefix,
            target_address,
            chain_id,
            function_name,
            parameters,
        } = self;
        schema_prefix.fmt(f)?;
        target_address.fmt(f)?;
        if let Some(chain_id) = chain_id {
            f.write_str("@")?;
            chain_id.fmt(f)?;
        }
        if let Some(fn_name) = function_name {
            f.write_str("/")?;
            fn_name.fmt(f)?;
        }
        if !parameters.0.is_empty() {
            f.write_str("?")?;
            parameters.fmt(f)?;
        }

        Ok(())
    }
}

impl EthereumTransactionRequest {
    /// Parse a transaction request.
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        let (i, schema_prefix) = SchemaPrefix::parse(i)?;
        let (i, target_address) = EthereumAddress::parse(i)?;

        let parse_chain_id =
            nom::sequence::preceded(nom::bytes::complete::tag("@"), |i| Digits::parse_min(i, 1));
        let (i, chain_id) = nom::combinator::opt(parse_chain_id)(i)?;

        let parse_function_name = nom::sequence::preceded(
            nom::bytes::complete::tag("/"),
            UrlEncodedUnicodeString::parse,
        );
        let (i, function_name) = nom::combinator::opt(parse_function_name)(i)?;

        let (i, _) = nom::combinator::opt(nom::bytes::complete::tag("?"))(i)?;
        let (i, parameters) = Parameters::parse(i)?;
        Ok((
            i,
            Self {
                schema_prefix,
                target_address,
                chain_id,
                function_name,
                parameters,
            },
        ))
    }
}

#[cfg(test)]
mod test {
    use std::ops::RangeInclusive;

    use super::*;

    use prop::strategy::Union;
    use proptest::prelude::*;

    #[test]
    fn digits_sanity() {
        assert_eq!(
            123,
            Digits {
                places: vec![1, 2, 3]
            }
            .as_u64()
        );
        assert_eq!(vec![1, 2, 3], Digits::from_u64(123).places);
    }

    #[test]
    fn digits_as_decimal_ratio() {
        // 0.0123
        let digits = Digits {
            places: vec![0, 1, 2, 3],
        };
        assert_eq!((123, 10_000), digits.as_decimal_ratio());

        // 0.666
        let digits = Digits {
            places: vec![6, 6, 6],
        };
        assert_eq!((666, 1000), digits.as_decimal_ratio());
    }

    fn arb_digits_in(size_range: RangeInclusive<usize>) -> impl Strategy<Value = Digits> {
        prop::collection::vec(0..10u8, size_range).prop_map(|places| Digits { places })
    }

    fn arb_digits(min_digits: usize) -> impl Strategy<Value = Digits> {
        arb_digits_in(min_digits..=Digits::MAX_PLACES)
    }

    fn arb_hex_digits(min_digits: usize, max_digits: usize) -> impl Strategy<Value = HexDigits> {
        let size_range = min_digits..=max_digits;
        prop::collection::vec(0..16u8, size_range).prop_map(|places| HexDigits { places })
    }

    proptest! {
        #[test]
        fn arb_digits_sanity(digits in arb_digits_in(2..=Digits::MAX_PLACES)) {
            assert!(digits.places.len() >= 2, "digits: {digits:#?}");
            assert!(digits.places.len() <= Digits::MAX_PLACES, "digits: {digits:#?}");
        }
    }

    fn arb_digits_gte(min_value: u64, max_value: u64) -> impl Strategy<Value = Digits> {
        (min_value..=max_value).prop_map(Digits::from_u64)
    }

    proptest! {
        #[test]
        fn arb_digits_gte_sanity(digits in arb_digits_gte(20, u64::MAX)) {
            assert!(digits.as_u64() >= 20);
        }
    }

    #[test]
    fn parse_digits_sanity() {
        let (i, seen_digits) = Digits::parse_min("256", 0).unwrap();
        assert!(i.is_empty());
        assert_eq!(256, seen_digits.as_u64())
    }

    proptest! {
        #[test]
        fn parse_digits(digits in arb_digits(1)) {
            let s = digits.to_string();
            let (i, seen_digits) = Digits::parse_min(&s, 1).unwrap();
            assert_eq!("", i);
            assert_eq!(digits, seen_digits);
        }
    }

    #[test]
    fn number_as_i128_sanity() {
        let (_, n) = Number::parse("666.0").unwrap();
        assert_eq!(666, n.as_i128().unwrap());
    }

    fn arb_valid_number() -> impl Strategy<Value = Number> {
        (
            prop::option::of(any::<bool>()),
            arb_digits(0),
            any::<bool>(),
            prop::option::of(arb_digits_in(1..=10)),
        )
            .prop_flat_map(|(signum, integer, little_e, decimal)| {
                if let Some(dec) = decimal.as_ref() {
                    // If there is a decimal, ensure that the exponent "covers" it
                    arb_digits_gte(dec.places.len() as u64, u64::MAX.ilog10() as u64 / 2)
                        .prop_map(Some)
                        .boxed()
                } else {
                    prop::option::of(arb_digits(1)).boxed()
                }
                .prop_map(move |exponent| Number {
                    signum,
                    integer: integer.clone(),
                    decimal: decimal.clone(),
                    exponent: exponent.map(|exp| (little_e, Some(exp))),
                })
            })
    }

    /// Produce an arbitrary `Number` that may or may not be valid.
    fn arb_any_number() -> impl Strategy<Value = Number> {
        (
            prop::option::of(any::<bool>()),
            arb_digits(0),
            prop::option::of(any::<bool>()),
            prop::option::of(arb_digits(1)),
            prop::option::of(arb_digits(1)),
        )
            .prop_map(|(signum, integer, little_e, decimal, exponent)| Number {
                signum,
                integer,
                decimal,
                exponent: little_e.map(|e| (e, exponent)),
            })
    }

    proptest! {
        #[test]
        fn arb_valid_number_sanity(number in arb_valid_number()) {
            assert!(number.as_i128().is_ok());
        }
    }

    proptest! {
        #[test]
        fn parse_valid_number(ns in arb_valid_number()) {
            let s = ns.to_string();
            let (i, seen_ns) = Number::parse(&s).unwrap();
            assert!(i.is_empty());
            assert_eq!(ns, seen_ns);
            let result = seen_ns.as_i128();
            assert!(result.is_ok(), "{}", result.unwrap_err());
        }
    }

    proptest! {
        #[test]
        fn parse_any_number(ns in arb_any_number()) {
            let s = ns.to_string();
            let (i, seen_ns) = Number::parse(&s).unwrap();
            assert!(i.is_empty());
            assert_eq!(ns, seen_ns);
        }
    }

    #[test]
    fn parse_ens_name_sanity() {
        let valid_ens_names = [
            "luckyrabbits.meter",
            "web3.web2.web1",
            "kitty.cat",
            "renderling.xyz",
            "efnx.com",
            "takt.com",
        ];
        for input in valid_ens_names {
            let (i, name) = EnsName::parse(input).unwrap();
            assert_eq!("", i);
            assert_eq!(EnsName(input.to_string()), name);
        }
    }

    /// Produces rather exhaustive `EnsName`s that may not be parseable because:
    ///
    /// * includes unicode that doesn't pass normalization
    /// * is zero length
    ///
    /// This produces a lot of cases, as a result `parse_arb_ens_name` takes about
    /// 7 seconds on a mac M4Max machine.
    fn arb_any_ens_name() -> impl Strategy<Value = EnsName> {
        proptest::string::string_regex("[^\\s\\t@/?]{0,255}")
            .unwrap()
            .prop_map(EnsName)
    }

    /// Produces "happy path" `EnsName`s that are guaranteed to be parseable,
    /// but are not exhaustive.
    fn arb_happy_ens_name() -> impl Strategy<Value = EnsName> {
        /// Creates a "happy path" label according to
        /// [EIP-137](https://eips.ethereum.org/EIPS/eip-137):
        ///
        /// > Labels and domains may be of any length, but for compatibility with
        /// > legacy DNS, it is recommended that labels be restricted to no more than
        /// > 64 characters each, and complete ENS names to no more than 255
        /// > characters. For the same reason, it is recommended that labels do not
        /// > start or end with hyphens, or start with digits.
        ///
        fn arb_happy_label() -> impl Strategy<Value = String> {
            proptest::string::string_regex("[a-z][a-z0-9]{1,62}[a-z0-9]?").unwrap()
        }

        fn arb_happy_label_maybe() -> impl Strategy<Value = Option<String>> {
            (any::<bool>(), arb_happy_label()).prop_map(|(is_some, label)| is_some.then_some(label))
        }

        fn arb_happy_label_list() -> impl Strategy<Value = [Option<String>; 4]> {
            [
                // We require the ENS name to have at least two labels
                arb_happy_label().prop_map(Some).boxed(),
                arb_happy_label().prop_map(Some).boxed(),
                arb_happy_label_maybe().boxed(),
                arb_happy_label_maybe().boxed(),
            ]
        }

        arb_happy_label_list()
            .prop_map(|list| EnsName(list.into_iter().flatten().collect::<Vec<_>>().join(".")))
    }

    #[test]
    fn parsing_ens_name_without_dot_fails() {
        let name = "hellogarbagestuff";
        let result = EnsName::parse(name);
        assert!(result.is_err(), "Parsed bad ENS name: {result:#?}");
    }

    proptest! {
        #[test]
        fn parse_arb_ens_name(expected in arb_any_ens_name()) {
            let input = expected.to_string();
            match EnsName::parse(&input) {
                Ok((i, seen)) => {
                    assert_eq!("", i);
                    assert_eq!(expected, seen);
                }
                // The input was empty, fine
                Err(nom::Err::Error(ParseError::EnsMissing)) => {}
                // The input didn't normalize, fine since we don't know how to
                // construct a strategy via regex that is exhaustive of normalized input
                Err(nom::Err::Error(ParseError::EnsNormalization { .. })) => {}
                // Anything else panic because it's unexpected and should be fixed
                Err(e) => panic!("{e}"),

            }
        }
    }

    #[test]
    fn hex_address_zero_sanity() {
        let input = "0x0000000000000000000000000000000000000000";
        let (output, addy) = EthereumAddress::parse(input).unwrap();
        assert_eq!("", output, "output was not fully consumed");
        assert_eq!(
            EthereumAddress::Hex(HexDigits {
                places: [0; 40].to_vec()
            }),
            addy
        );
        assert_eq!(input, &format!("{addy}"));
    }

    fn arb_eth_addy() -> impl Strategy<Value = EthereumAddress> {
        let hexes: BoxedStrategy<EthereumAddress> = arb_hex_digits(40, 40)
            .prop_map(EthereumAddress::Hex)
            .boxed();
        let names: BoxedStrategy<EthereumAddress> =
            arb_happy_ens_name().prop_map(EthereumAddress::Name).boxed();
        hexes.prop_union(names)
    }

    proptest! {
        #[test]
        fn parse_arb_eth_address(expected in arb_eth_addy()) {
            let input = expected.to_string();
            let (rest, seen) = EthereumAddress::parse(&input).unwrap();
            assert_eq!("", rest);
            assert_eq!(expected, seen);
        }
    }

    #[test]
    fn url_encoding_sanity() {
        let s = "hello@blah/blah?blah blah🫠blah";
        let encoded = UrlEncodedUnicodeString::encode(s);
        assert_eq!(
            "hello%40blah%2Fblah%3Fblah%20blah%F0%9F%AB%A0blah",
            &encoded.0.to_string()
        );
    }

    fn arb_unicode(min: usize, max: usize) -> impl Strategy<Value = String> {
        proptest::string::string_regex(&format!(".{{{min}, {max}}}")).unwrap()
    }

    fn arb_url_encoded_string() -> impl Strategy<Value = UrlEncodedUnicodeString> {
        arb_unicode(1, 1024).prop_map(UrlEncodedUnicodeString::encode)
    }

    proptest! {
        #[test]
        fn parse_arb_url_encoded_unicode_string(expected in arb_url_encoded_string()) {
            let input = &expected.0;
            let (output, seen) = UrlEncodedUnicodeString::parse(input).unwrap();
            assert_eq!("", output);
            assert_eq!(expected, seen);
        }
    }

    fn arb_eth_type_name(recursions_max: usize) -> impl Strategy<Value = EthereumAbiTypeName> {
        fn arb_eth_base_type_name() -> impl Strategy<Value = EthereumAbiTypeName> {
            fn one_offs() -> impl Strategy<Value = EthereumAbiTypeName> {
                proptest::strategy::Union::new(
                    [
                        "uint", "int", "address", "bool", "fixed", "ufixed", "function", "bytes",
                        "string",
                    ]
                    .map(|s| proptest::strategy::Just(EthereumAbiTypeName { name: s.to_owned() })),
                )
            }
            fn arb_uint_or_int() -> impl Strategy<Value = EthereumAbiTypeName> {
                // 0 < M <= 256, M % 8 == 0
                ((0u32..=256 / 8), any::<bool>()).prop_map(|(n, is_uint)| EthereumAbiTypeName {
                    name: format!("{}{}", if is_uint { "uint" } else { "int" }, n * 8),
                })
            }
            fn arb_fixed_or_ufixed() -> impl Strategy<Value = EthereumAbiTypeName> {
                // 8 <= M <= 256, M % 8 == 0
                let m = 1u32..=256 / 8;
                // 0 < N <= 80
                let n = 1..=80;
                (m, n, any::<bool>()).prop_map(|(m, n, is_fixed)| EthereumAbiTypeName {
                    name: format!("{}{m}{n}", if is_fixed { "fixed" } else { "ufixed" }),
                })
            }
            fn arb_bytes() -> impl Strategy<Value = EthereumAbiTypeName> {
                // 0 < M <= 32
                (1..=32).prop_map(|m| EthereumAbiTypeName {
                    name: format!("bytes{m}"),
                })
            }

            proptest::strategy::Union::new([
                one_offs().boxed(),
                arb_uint_or_int().boxed(),
                arb_fixed_or_ufixed().boxed(),
                arb_bytes().boxed(),
            ])
        }

        // Don't allow infinite recursion, but ensure that we return _something_
        if recursions_max == 0 {
            return arb_eth_base_type_name().boxed();
        }

        fn arb_eth_array_type_name(
            recursions_max: usize,
        ) -> impl Strategy<Value = EthereumAbiTypeName> {
            // M >= 0 but we also have to cover variable-length arrays
            (
                (0u32..),
                arb_eth_type_name(recursions_max.saturating_sub(1)),
            )
                .prop_map(|(m, ty)| EthereumAbiTypeName {
                    name: format!(
                        "<{ty}>[{}]",
                        if m > 0 { m.to_string() } else { String::new() }
                    ),
                })
        }

        fn arb_eth_n_tuple(
            recursions_max: usize,
            n_tuple: usize,
        ) -> impl Strategy<Value = EthereumAbiTypeName> {
            proptest::collection::vec(arb_eth_type_name(recursions_max.saturating_sub(1)), n_tuple)
                .prop_map(|types| EthereumAbiTypeName {
                    name: format!(
                        "({})",
                        types
                            .into_iter()
                            .map(|ty| ty.name)
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                })
        }

        fn arb_eth_tuple(recursions_max: usize) -> impl Strategy<Value = EthereumAbiTypeName> {
            (0usize..10)
                .prop_flat_map(move |n| arb_eth_n_tuple(recursions_max.saturating_sub(1), n))
        }

        proptest::strategy::Union::new([
            arb_eth_base_type_name().boxed(),
            arb_eth_array_type_name(recursions_max - 1).boxed(),
            arb_eth_tuple(recursions_max - 1).boxed(),
        ])
        .boxed()
    }

    const TYPE_RECURSIONS: usize = 4;
    proptest! {
        #[test]
        fn parse_arb_eth_type_name(expected in arb_eth_type_name(TYPE_RECURSIONS)) {
            let input = &expected.name;
            let (output, seen) = EthereumAbiTypeName::parse(input).unwrap();
            assert_eq!("", output);
            assert_eq!(expected, seen);
        }
    }

    fn arb_key() -> impl Strategy<Value = Key> {
        fn type_keys() -> impl Strategy<Value = Key> {
            arb_eth_type_name(TYPE_RECURSIONS).prop_map(Key::Type)
        }
        fn one_offs() -> impl Strategy<Value = Key> {
            Union::new([Key::Value, Key::Gas, Key::GasLimit, Key::GasPrice].map(Just))
        }
        Union::new([one_offs().boxed(), type_keys().boxed()])
    }

    proptest! {
        #[test]
        fn parse_arb_key(expected in arb_key()) {
            let input = expected.to_string();
            let (output, seen) = Key::parse(&input).unwrap();
            assert_eq!("", output);
            assert_eq!(expected, seen);
        }
    }

    fn arb_value() -> impl Strategy<Value = Value> {
        Union::new([
            arb_valid_number().prop_map(Value::Number).boxed(),
            arb_eth_addy().prop_map(Value::Address).boxed(),
            arb_url_encoded_string().prop_map(Value::String).boxed(),
        ])
    }

    #[test]
    fn parse_value_url_encoded_space() {
        let expected = Value::String(UrlEncodedUnicodeString("%20".to_owned()));
        let input = expected.to_string();
        assert_eq!("%20", &input);
        let (output, seen) = Value::parse(&input).unwrap();
        assert_eq!(
            "", output,
            "`input` was not fully consumed. Parsed '{seen:?}' from '{input}'"
        );
        assert_eq!(expected, seen);
    }

    #[test]
    /// Parsing a value as an ENS name consumes more input than as a string, so ENS name should
    /// win.
    fn parse_value_ens_name_over_string() {
        let expected = Value::Address(EthereumAddress::Name(EnsName("aa.a0".to_string())));
        let input = expected.to_string();
        let (_output, seen) = Value::parse(&input).unwrap();
        pretty_assertions::assert_eq!(expected, seen);
    }

    proptest! {
        #[test]
        fn parse_arb_value(expected in arb_value()) {
            let input = expected.to_string();
            let (output, seen) = Value::parse(&input).unwrap();
            assert_eq!(
                "",
                output,
                "`input` was not fully consumed. Parsed '{seen:?}' from input '{input}'"
            );
            assert_eq!(expected, seen);
        }
    }

    fn arb_parameter() -> impl Strategy<Value = Parameter> {
        arb_key().prop_flat_map(|key| {
            if matches!(key, Key::Value | Key::Gas | Key::GasLimit | Key::GasPrice) {
                arb_valid_number()
                    .prop_map(move |n| Parameter {
                        key: key.clone(),
                        value: Value::Number(n),
                    })
                    .boxed()
            } else {
                arb_value()
                    .prop_map(move |v| Parameter {
                        key: key.clone(),
                        value: v,
                    })
                    .boxed()
            }
        })
    }

    proptest! {
        #[test]
        fn parse_arb_parameter(expected in arb_parameter()) {
            let input = expected.to_string();
            let (output, seen) = Parameter::parse(&input).unwrap();
            assert_eq!("", output, "`input` was not fully consumed. Parsed '{seen}'");
            assert_eq!(expected, seen);
        }
    }

    #[test]
    fn parse_parameter_sanity() {
        let expected = Parameter {
            key: Key::Value,
            value: Value::Address(EthereumAddress::Name(EnsName("aa.a0".to_owned()))),
        };
        let input = "value=aa.a0&value=31554253.75819936219e60504434428";
        println!("{input}");
        let (_output, seen) = Parameter::parse(input).unwrap();
        pretty_assertions::assert_eq!(expected, seen);
    }

    #[test]
    fn parse_parameters_sanity() {
        let expected = Parameters(vec![
            Parameter {
                key: Key::Value,
                value: Value::Address(EthereumAddress::Name(EnsName("aa.a0".to_owned()))),
            },
            Parameter {
                key: Key::Value,
                value: Value::Number(Number {
                    signum: None,
                    integer: Digits {
                        places: vec![3, 1, 5, 5, 4, 2, 5, 3],
                    },
                    decimal: Some(Digits {
                        places: vec![7, 5, 8, 1, 9, 9, 3, 6, 2, 1, 9],
                    }),
                    exponent: Some((
                        true,
                        Some(Digits {
                            places: vec![6, 0, 5, 0, 4, 4, 3, 4, 4, 2, 8],
                        }),
                    )),
                }),
            },
        ]);
        let input = expected.to_string();
        let (_output, seen) = Parameters::parse(&input).unwrap();
        println!("parsed: {input}");
        pretty_assertions::assert_eq!(expected, seen);
    }

    fn arb_parameters() -> impl Strategy<Value = Parameters> {
        proptest::collection::vec(arb_parameter(), 0..10).prop_map(Parameters)
    }

    proptest! {
        #[test]
        fn parse_arb_parameters(expected in arb_parameters()) {
            let input = expected.to_string();
            let (output, seen) = Parameters::parse(&input).unwrap();
            assert_eq!("", output, "`input` was not fully consumed. Parsed '{seen}' from '{input}'");
            assert_eq!(expected, seen);
        }
    }

    fn arb_schema_prefix() -> impl Strategy<Value = SchemaPrefix> {
        any::<bool>().prop_map(|has_pay| SchemaPrefix { has_pay })
    }

    proptest! {
    #[test]
    fn parse_arb_schema_prefix(expected in arb_schema_prefix()) {
            let input = expected.to_string();
            let (output, seen) = SchemaPrefix::parse(&input).unwrap();
            assert_eq!("", output);
            assert_eq!(expected, seen);
        }
    }

    fn arb_request() -> impl Strategy<Value = EthereumTransactionRequest> {
        (
            arb_schema_prefix(),
            arb_eth_addy(),
            prop::option::of(arb_digits(1)),
            prop::option::of(arb_url_encoded_string()),
            prop::option::of(arb_parameters()),
        )
            .prop_map(
                |(schema_prefix, target_address, chain_id, function_name, paramaters)| {
                    EthereumTransactionRequest {
                        schema_prefix,
                        target_address,
                        chain_id,
                        function_name,
                        parameters: paramaters.unwrap_or(Parameters(vec![])),
                    }
                },
            )
    }

    proptest! {
        #[test]
        fn parse_arb_request(expected in arb_request()) {
            let input = expected.to_string();
            let (output, seen) = EthereumTransactionRequest::parse(&input).unwrap();
            assert_eq!("", output);
            pretty_assertions::assert_eq!(expected, seen);
        }
    }

    #[test]
    fn test_vectors_eip_681() {
        let input = "ethereum:0xfb6916095ca1df60bb79Ce92ce3ea74c37c5d359?value=2.014e18";
        let (_, seen) = EthereumTransactionRequest::parse(input).unwrap();
        pretty_assertions::assert_eq!(
            "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
            seen.target_address.to_string()
        );
        let value = seen
            .parameters
            .get_value(&Key::Value)
            .unwrap()
            .as_number()
            .unwrap();
        assert_eq!(2, value.integer());
        assert_eq!(2.014e18 as i128, value.as_i128().unwrap());
    }
}
