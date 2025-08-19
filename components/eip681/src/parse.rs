//! Types and functions used for parsing.

use std::borrow::Cow;

use nom::Parser;
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
    MissingEns,

    #[snafu(display("{source}"))]
    EnsNormalization {
        source: ens_normalize_rs::ProcessError,
    },

    #[snafu(display("Invalid bit size. Expected {range:?} but saw {seen}"))]
    InvalidBitRange {
        range: std::ops::RangeInclusive<u32>,
        seen: u64,
    },

    #[snafu(display("Bit size must be a multiple of 8, saw {seen}"))]
    InvalidBitSize { seen: u64 },
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
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let Some(dec) = self.decimal.as_ref() {
            let exp_value = self
                .exponent
                .as_ref()
                .and_then(|(_e, maybe_exp)| maybe_exp.as_ref().map(Digits::as_u64))
                .unwrap_or_default();
            snafu::ensure!(
                exp_value >= dec.places.len() as u64,
                SmallExponentSnafu {
                    expected: dec.places.len(),
                    seen: exp_value,
                }
            );
        }
        Ok(())
    }

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
#[derive(Clone, Debug, PartialEq)]
pub struct EnsName(String);

impl core::fmt::Display for EnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl EnsName {
    const DELIMITERS: &[char] = &['@', '/', '?'];

    /// Parse an `EnsName`.
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        fn continue_parsing(c: char) -> bool {
            !c.is_whitespace() && !EnsName::DELIMITERS.contains(&c)
        }

        let (i, name) = nom::bytes::complete::take_till(|c| !continue_parsing(c))(i)?;
        snafu::ensure!(!name.is_empty(), MissingEnsSnafu);

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

impl Value {
    /// Parse a `Value`.
    ///
    /// ```abnf
    /// value = number / ethereum_address / STRING
    /// ```
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        let number = Number::parse.map(Value::Number);
        let ethereum_address = EthereumAddress::parse.map(Value::Address);
        let string = UrlEncodedUnicodeString::parse.map(Value::String);
        nom::branch::alt((number, ethereum_address, string)).parse(i)
    }
}

/// An Ethereum ABI type.
///
/// See [Solidity ABI types](https://docs.soliditylang.org/en/develop/abi-spec.html#types)
/// for more info.
#[derive(Debug, PartialEq)]
pub enum Type {
    /// Unsigned int type (uint<M>).
    Uint(u32),
    /// Signed int type (int<M>).
    Int(u32),
    /// Address type (address).
    Address,
    /// Bool type (bool).
    Bool,
    /// Fixed size bytes type (bytes<M>).
    FixedBytes(usize),
    /// Fixed size array type (T\[k\])
    FixedArray(Box<Type>, usize),
    /// UTF-8 string type (string).
    String,
    /// Dynamic size bytes type (bytes).
    Bytes,
    /// Dynamic size array type (T[])
    Array(Box<Type>),
    /// Tuple type (tuple(T1, T2, ..., Tn))
    Tuple(Vec<(String, Type)>),
}

impl core::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::Uint(size) => write!(f, "uint{}", size),
            Type::Int(size) => write!(f, "int{}", size),
            Type::Address => write!(f, "address"),
            Type::Bool => write!(f, "bool"),
            Type::FixedBytes(size) => write!(f, "bytes{}", size),
            Type::Bytes => write!(f, "bytes"),
            Type::FixedArray(ty, size) => write!(f, "{}[{}]", ty, size),
            Type::Array(ty) => write!(f, "{}[]", ty),
            Type::String => write!(f, "string"),
            Type::Tuple(tys) => write!(
                f,
                "({})",
                tys.iter()
                    .map(|(_, ty)| format!("{}", ty))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
}

impl Type {
    /// Parse a `Type`.
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        fn parse_uint(i: &str) -> nom::IResult<&str, Type, ParseError<'_>> {
            let (i, _uint) = nom::bytes::complete::tag("uint")(i)?;
            let (i, digits) = Digits::parse_min(i, 0)?;
            if digits.places.is_empty() {
                // `uint` is a synonym for `uint256`
                return Ok((i, Type::Uint(256)));
            }

            let bits = digits.as_u64();

            snafu::ensure!(
                bits > 0 && bits <= 256,
                InvalidBitRangeSnafu {
                    range: 1..=256,
                    seen: bits
                }
            );
            snafu::ensure!(bits % 8 == 0, InvalidBitSizeSnafu { seen: bits });

            Ok((i, Type::Uint(bits as u32)))
        }
        fn parse_int(i: &str) -> nom::IResult<&str, Type, ParseError<'_>> {
            let (i, _int) = nom::bytes::complete::tag("int")(i)?;
            let (i, digits) = Digits::parse_min(i, 0)?;
            if digits.places.is_empty() {
                // `int` is a synonym for `int256`
                return Ok((i, Type::Uint(256)));
            }
            let bits = digits.as_u64();

            snafu::ensure!(
                bits > 0 && bits <= 256,
                InvalidBitRangeSnafu {
                    range: 1..=256,
                    seen: bits
                }
            );
            snafu::ensure!(bits % 8 == 0, InvalidBitSizeSnafu { seen: bits });

            Ok((i, Type::Int(bits as u32)))
        }

        let parse_address = nom::bytes::complete::tag("address").map(|_| Type::Address);
        let parse_bool = nom::bytes::complete::tag("bool").map(|_| Type::Bool);

        let mut parse_type = nom::branch::alt((parse_uint, parse_int, parse_address, parse_bool));
        let (i, type_) = parse_type.parse(i)?;
        Ok((i, type_))
    }
}

#[cfg(test)]
mod test {
    use super::*;

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

    fn arb_digits_with(min_digits: usize) -> impl Strategy<Value = Digits> {
        let size_range = min_digits..=Digits::MAX_PLACES;

        prop::collection::vec(0..10u8, size_range).prop_map(|places| Digits { places })
    }

    fn arb_digits(min_digits: usize) -> impl Strategy<Value = Digits> {
        arb_digits_with(min_digits)
    }

    fn arb_hex_digits(min_digits: usize, max_digits: usize) -> impl Strategy<Value = HexDigits> {
        let size_range = min_digits..=max_digits;
        prop::collection::vec(0..16u8, size_range).prop_map(|places| HexDigits { places })
    }

    proptest! {
        #[test]
        fn arb_digits_sanity(digits in arb_digits_with(2)) {
            assert!(digits.places.len() >= 2, "digits: {digits:#?}");
            assert!(digits.places.len() <= Digits::MAX_PLACES, "digits: {digits:#?}");
        }
    }

    fn arb_digits_gte(min_value: u64) -> impl Strategy<Value = Digits> {
        (min_value..).prop_map(Digits::from_u64)
    }

    proptest! {
        #[test]
        fn arb_digits_gte_sanity(digits in arb_digits_gte(20)) {
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

    fn arb_valid_number() -> impl Strategy<Value = Number> {
        (
            prop::option::of(any::<bool>()),
            arb_digits(0),
            any::<bool>(),
            prop::option::of(arb_digits(1)),
        )
            .prop_flat_map(|(signum, integer, little_e, decimal)| {
                if let Some(dec) = decimal.as_ref() {
                    // If there is a decimal, ensure that the exponent "covers" it
                    arb_digits_gte(dec.places.len() as u64)
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
            assert_eq!(Ok(()), number.validate());
        }
    }

    proptest! {
        #[test]
        fn parse_valid_number(ns in arb_valid_number()) {
            let s = ns.to_string();
            let (i, seen_ns) = Number::parse(&s).unwrap();
            assert!(i.is_empty());
            assert_eq!(ns, seen_ns);
            assert_eq!(Ok(()), seen_ns.validate());
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
                arb_happy_label().prop_map(Some).boxed(),
                arb_happy_label_maybe().boxed(),
                arb_happy_label_maybe().boxed(),
                arb_happy_label_maybe().boxed(),
            ]
        }

        arb_happy_label_list()
            .prop_map(|list| EnsName(list.into_iter().flatten().collect::<Vec<_>>().join(".")))
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
                Err(nom::Err::Error(ParseError::MissingEns)) => {}
                // The input didn't normalize, fine since we don't know how to
                // construct a strategy via regex that is exhaustive of normalized input
                Err(nom::Err::Error(ParseError::EnsNormalization { .. })) => {}
                // Anything else panic because it's unexpected and should be fixed
                Err(e) => panic!("{e}"),

            }
        }
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
}
