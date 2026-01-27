//! Types and functions used for parsing.

use std::{borrow::Cow, collections::BTreeMap};

use nom::{
    AsChar, Parser,
    bytes::complete::{is_not, tag, take_till, take_till1, take_while, take_while1},
    character::complete::char,
    combinator::opt,
    multi::separated_list0,
    sequence::preceded,
};
use snafu::{OptionExt, ResultExt};

use crate::error::*;

/// Zero or more consecutive digits.
///
/// ```abnf
/// *DIGIT
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    #[cfg(any(test, feature = "test-dependencies"))]
    pub const MAX_PLACES: usize = u64::MAX.ilog10() as usize;

    /// Construct a new `Digits` from a `u64`.
    pub fn from_u64(mut v: u64) -> Self {
        if v == 0 {
            return Digits { places: vec![0] };
        }

        let mut places: Vec<u8> = vec![];
        while v > 0 {
            places.push((v % 10) as u8);
            v /= 10;
        }
        places.reverse();
        Digits { places }
    }

    /// Returns the `u64` representation.
    ///
    /// ## Errors
    /// Errors if internal arithmetic operations overflow.
    pub fn as_u64(&self) -> Result<u64, ValidationError> {
        let mut total = 0u64;
        for digit in &self.places {
            total = total
                .checked_mul(10)
                .context(OverflowSnafu)?
                .checked_add(*digit as u64)
                .context(OverflowSnafu)?;
        }
        Ok(total)
    }

    #[cfg(test)]
    /// Returns the ratio corresponding to the decimal number `0.<digits>`,
    /// i.e. the denominator will be `10^len(digits)`.
    fn as_decimal_ratio(&self) -> Result<(u64, u64), ValidationError> {
        let denominator = 10u64
            .checked_pow(u32::try_from(self.places.len()).context(IntegerSnafu)?)
            .context(OverflowSnafu)?;
        Ok((self.as_u64()?, denominator))
    }

    /// Parse at least `min` digits.
    pub fn parse_min(min: usize) -> impl Fn(&str) -> nom::IResult<&str, Self, ParseError<'_>> {
        move |i| {
            parse_min(min, false)
                .map(|places| Digits { places })
                .parse(i)
        }
    }
}

/// Parse at least `min` digits.
pub fn parse_min(
    min: usize,
    is_hex: bool,
) -> impl Fn(&str) -> nom::IResult<&str, Vec<u8>, ParseError<'_>> {
    move |i| {
        let radix = if is_hex { 16 } else { 10 };
        let (i, chars) = take_while(|c: char| c.is_digit(radix))(i)?;
        let data = chars
            .chars()
            .map(|c| {
                c.to_digit(radix)
                    .expect("we already checked that this char was a digit") as u8
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
}

/// Zero or more consecutive hexadecimal digits.
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
    pub fn parse_min(min: usize) -> impl Fn(&str) -> nom::IResult<&str, Self, ParseError<'_>> {
        move |i| {
            parse_min(min, true)
                .map(|places| HexDigits { places })
                .parse(i)
        }
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
/// This ABNF notation doesn't seem correct, as it allows for quite a few
/// cases that don't make sense - for example:
///
/// 1. `*DIGIT` is missing and `[ "." 1*DIGIT ]` is present while `[ ( "e" / "E" ) [ 1*DIGIT] ]`
///    is not
/// 2. `[ ( "e" / "E" ) [ 1*DIGIT] ]` is missing the `[ 1*DIGIT ]` (eg, just "e")
/// 3. only `"-" / "+"` is present
///
/// For this reason, in this library, parsing is separate from validation.
///
/// Other implementations use regular expressions instead of parsing, and only
/// support very specific values.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
        let parse_signum_pos = char('+').map(|_| true);
        let parse_signum_neg = char('-').map(|_| false);
        let parse_signum = parse_signum_pos.or(parse_signum_neg);
        let (i, signum) = opt(parse_signum)(i)?;

        // Parse *DIGIT
        let (i, integer) = Digits::parse_min(0)(i)?;

        // Parse [ "." 1*DIGIT ]
        fn parse_decimal(i: &str) -> nom::IResult<&str, Digits, ParseError<'_>> {
            let (i, _dot) = char('.')(i)?;
            let (i, digits) = Digits::parse_min(1)(i)?;
            Ok((i, digits))
        }
        let (i, decimal) = opt(parse_decimal)(i)?;

        // Parse [ ( "e" / "E" ) [ 1*DIGIT ] ]
        fn parse_exponent(i: &str) -> nom::IResult<&str, (bool, Option<Digits>), ParseError<'_>> {
            // Parse ( "e" / "E" )
            let parse_little_e = char('e').map(|_| true);
            let parse_big_e = char('E').map(|_| false);
            let mut parse_e = parse_little_e.or(parse_big_e);
            let (i, little_e) = parse_e.parse(i)?;

            // Parse [ 1*DIGIT ]
            let (i, maybe_exp) = opt(Digits::parse_min(1))(i)?;

            Ok((i, (little_e, maybe_exp)))
        }
        let (i, exponent) = opt(parse_exponent)(i)?;

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
    ///
    /// ## Errors
    /// Errors if internal arithmetic operations overflow.
    fn integer(&self) -> Result<u64, ValidationError> {
        self.integer.as_u64()
    }

    /// Convert this [`Number`] into an i128, if possible.
    ///
    /// ## Errors
    /// Errors if internal arithmetic operations overflow.
    pub fn as_i128(&self) -> Result<i128, ValidationError> {
        let signum = self
            .signum
            .map_or(1i128, |is_positive| if is_positive { 1 } else { -1 });
        let integer = self.integer()?;
        let decimal_numerator = self
            .decimal
            .as_ref()
            .map(|d| d.as_u64())
            .transpose()?
            .unwrap_or(0);
        let decimal_places: u32 = self
            .decimal
            .as_ref()
            .map(|d| d.places.len())
            .unwrap_or(0)
            .try_into()
            .context(IntegerSnafu)?;
        let exp: u32 = self
            .exponent
            .as_ref()
            .and_then(|(_, maybe_exp)| maybe_exp.as_ref().map(|digits| digits.as_u64()))
            .transpose()?
            .unwrap_or(0)
            .try_into()
            .context(IntegerSnafu)?;
        let multiplier = 10i128.checked_pow(exp).context(LargeExponentSnafu {
            expected: u128::MAX.ilog10() as usize,
            seen: exp as u64,
        })?;
        // The exponent must be >= the number of decimal places to yield an integer result.
        let decimal_exp = exp
            .checked_sub(decimal_places)
            .with_context(|| SmallExponentSnafu {
                expected: decimal_places as usize,
                seen: exp,
            });
        // Since it's hard to see through all the function chaining, this is
        // what's going on here:
        // ```
        // signum * (
        //     (integer * 10^exp) +
        //     (decimal_numerator * 10^(exp - decimal_places))
        // )
        // ```
        let multiplied_integer = (integer as i128)
            .checked_mul(multiplier)
            .with_context(|| OverflowSnafu)?;
        let decimal_multiplier = match decimal_exp {
            Ok(d) => 10i128.checked_pow(d).context(OverflowSnafu)?,
            Err(_) if decimal_numerator == 0 => 0,
            Err(e) => return Err(e),
        };
        let multiplied_decimal = (decimal_numerator as i128)
            .checked_mul(decimal_multiplier)
            .with_context(|| OverflowSnafu)?;
        let value = multiplied_integer
            .checked_add(multiplied_decimal)
            .context(OverflowSnafu)?;
        signum.checked_mul(value).context(OverflowSnafu)
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
    /// These delimiters are implicit in the ABNF syntax because they mark the
    /// start of optional sections after the possible ENS name. There's nothing
    /// in the spec that says these characters _cannot_ occur within an ENS name,
    /// as the EIP-137 spec defers to the Unicode Technical Standard #46 to define
    /// what valid labels are, and that pulls from
    /// [this table](https://unicode.org/reports/tr46/#Table_Base_Valid_Set), which
    /// specifically says "Add all ASCII except for '.'".
    ///
    /// But it's clear at a quick look that these delimiters _must_ end parsing of
    /// an ENS name because if they did not, the parser would eat all optional sections.
    ///
    /// Also we must add '&' because an address could be used as the value of a parameter.
    const DELIMITERS: &[char] = &['@', '/', '?', '&'];

    /// Parse an `EnsName`.
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        fn continue_parsing(c: char) -> bool {
            !c.is_whitespace() && !EnsName::DELIMITERS.contains(&c)
        }

        let (i, name) = take_till(|c| !continue_parsing(c))(i)?;
        snafu::ensure!(!name.is_empty(), EnsMissingSnafu);
        snafu::ensure!(name.contains('.'), EnsDomainSnafu);

        // Now we have our name, normalize
        let normalized_name = ens_normalize_rs::normalize(name).context(EnsNormalizationSnafu)?;
        // According to <https://eips.ethereum.org/EIPS/eip-137#name-syntax> each label in a name
        // must be a valid, normalized label, so the input `name` should match `normalized_name`.
        snafu::ensure!(
            normalized_name == name,
            NotNormalizedSnafu {
                expected: normalized_name,
                seen: name.to_string(),
            }
        );

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
            let (i, _) = tag("0x")(i)?;
            let (i, digits) = HexDigits::parse_min(40)(i)?;
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
#[derive(Clone, Debug, PartialEq)]
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
        let (i, s) = take_while(should_continue_parsing)(i)?;
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
#[derive(Clone, Debug, PartialEq)]
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
        // 2. `ethereum_address` may be prefixed with `0` (in the hex-address case), so both number
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
        results
            .into_iter()
            .next()
            .expect("safe because this was an array of 3")
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
/// Instead of parsing [`EthereumAbiTypeName`] as a nested syntax tree, we
/// instead only parse the _name_.
// TODO(schell): If we do end up wanting a syntax tree representing the type, I
// have the start of one on the branch `feat/eip-681-tx-req-parser-solidity-types`
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
        let (i, s) = take_while1(is_type_char)(i)?;
        Ok((i, EthereumAbiTypeName { name: s.to_owned() }))
    }
}

/// A key-value pair, where the the type of the value depends upon the key.
///
/// ```abnf
/// key = "value" / "gas" / "gasLimit" / "gasPrice" / TYPE
/// ```
///
/// > If _key_ in the parameter list is "value", "gasLimit", "gasPrice" or "gas" then
/// > _value_ MUST be a number. Otherwise, it must correspond to the TYPE string
/// > used as key.
///
/// > ... gasLimit and gasPrice are suggested user-editable values for gas
/// > limit and gas price, respectively, for the requested transaction. It is
/// > acceptable to abbreviate gasLimit as gas, the two are treated synonymously.
#[derive(Debug, PartialEq)]
pub enum Parameter {
    /// The amount to be paid, in the atomic unit of the native token of the blockchain.
    ///
    /// In most cases this will denote wei on the ether blockchain, but it depends on
    /// context outside the scope of this library.
    Value(Number),
    /// Synonym for [`Self::GasLimit`].
    Gas(Number),
    /// Suggested user-editable value for the gas limit of the transaction.
    GasLimit(Number),
    /// Suggested user-editable value for the gas price of the transaction.
    GasPrice(Number),
    /// A "type" parameter denotes a positional parameter provided to the function
    /// named by `function_name`. For information about `function_name` see the ABNF
    /// spec in the module-level docs.
    AbiType(EthereumAbiTypeName, Value),
}

impl core::fmt::Display for Parameter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}={}", self.key(), self.value()))
    }
}

impl Parameter {
    fn key(&self) -> String {
        match self {
            Parameter::Value(_) => "value".to_string(),
            Parameter::Gas(_) => "gas".to_string(),
            Parameter::GasLimit(_) => "gasLimit".to_string(),
            Parameter::GasPrice(_) => "gasPrice".to_string(),
            Parameter::AbiType(ethereum_abi_type_name, _) => format!("{ethereum_abi_type_name}"),
        }
    }

    /// Returns just the value of this parameter.
    pub fn value(&self) -> Value {
        match self {
            Parameter::Value(number) => Value::Number(number.clone()),
            Parameter::Gas(number) => Value::Number(number.clone()),
            Parameter::GasLimit(number) => Value::Number(number.clone()),
            Parameter::GasPrice(number) => Value::Number(number.clone()),
            Parameter::AbiType(_, value) => value.clone(),
        }
    }

    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        // Parse the key blob
        let (i, key_blob) = take_till1(|c| c == '=')(i)?;
        let (i, _) = tag("=")(i)?;

        fn parse_number(
            i: &str,
            f: fn(Number) -> Parameter,
        ) -> nom::IResult<&str, Parameter, ParseError<'_>> {
            let (i, number) =
                Number::parse
                    .parse(i)
                    .map_err(|_| ParseError::InvalidParameterValue {
                        ty: "Number".to_string(),
                    })?;
            Ok((i, f(number)))
        }
        // If key in the parameter list is value, gasLimit, gasPrice or gas then
        // value MUST be a number. Otherwise, it must correspond to the TYPE
        // string used as key.
        Ok(match key_blob {
            "value" => parse_number(i, Parameter::Value)?,
            "gas" => parse_number(i, Parameter::Gas)?,
            "gasLimit" => parse_number(i, Parameter::GasLimit)?,
            "gasPrice" => parse_number(i, Parameter::GasPrice)?,
            other_key_blob => {
                let (remaining_name_input, type_name) = EthereumAbiTypeName::parse(other_key_blob)?;
                snafu::ensure!(
                    remaining_name_input.is_empty(),
                    InvalidParameterKeySnafu {
                        key: other_key_blob.to_string()
                    }
                );
                let (i, value) =
                    Value::parse(i).map_err(|_| ParseError::InvalidParameterValue {
                        ty: type_name.to_string(),
                    })?;
                (i, Parameter::AbiType(type_name, value))
            }
        })
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

impl IntoIterator for Parameters {
    type Item = Parameter;

    type IntoIter = <Vec<Parameter> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Parameters {
    /// Parses zero or more parameters, separated by '&'.
    ///
    /// ## Note
    /// This parser never fails.
    pub fn parse(i: &str) -> nom::IResult<&str, Self, ParseError<'_>> {
        // First parse into parameter "blobs", separated by '&'
        let (i, blobs) = separated_list0(tag("&"), take_till1(|c| c == '&'))(i)?;
        let mut params = vec![];
        for blob in blobs.into_iter() {
            let (j, param) = Parameter::parse(blob)?;
            snafu::ensure!(j.is_empty(), UnexpectedLeftoverInputSnafu { input: j });
            params.push(param);
        }
        Ok((i, Parameters(params)))
    }

    /// Return an iterator over all parameters.
    pub fn iter(&self) -> impl Iterator<Item = &Parameter> {
        self.0.iter()
    }

    /// Returns the number value of the parameter with the "value" key, if any.
    ///
    /// ## Errors
    /// Errors if there are more than one parameter with the key "value", and the
    /// values of those parameters are not semantically equal.
    pub fn value(&self) -> Result<Option<Number>, ValidationError> {
        let mut values = BTreeMap::default();
        for p in self.iter() {
            let (number, n) = match p {
                Parameter::Value(n) => (n.as_i128()?, n),
                _ => continue,
            };
            values.insert(("value", number), n.clone());
        }
        snafu::ensure!(
            values.len() <= 1,
            MultipleParameterValuesSnafu {
                key: "value",
                values: values
                    .into_iter()
                    .map(|((k, _), n)| (k, Value::Number(n)))
                    .collect::<Vec<_>>(),
            }
        );
        Ok(values.into_iter().next().map(|(_, n)| n))
    }

    /// Returns the number value of the parameter with the "gas" or "gasLimit" key, if any.
    ///
    /// ## Errors
    /// Errors if there are more than one parameter with the key "gas" or "gasLimit", and those
    /// values are not semantically equal.
    pub fn gas_limit(&self) -> Result<Option<Number>, ValidationError> {
        let mut values = BTreeMap::default();
        for p in self.iter() {
            let (k, number, n) = match p {
                Parameter::Gas(n) => ("gas", n.as_i128()?, n),
                Parameter::GasLimit(n) => ("gasLimit", n.as_i128()?, n),
                _ => continue,
            };
            // Also return the actual key for error reporting
            values.insert(("gasLimit", number), (k, n.clone()));
        }
        snafu::ensure!(
            values.len() <= 1,
            MultipleParameterValuesSnafu {
                key: "gasLimit",
                values: values
                    .into_iter()
                    .map(|(_, (k, n))| (k, Value::Number(n)))
                    .collect::<Vec<_>>(),
            }
        );
        Ok(values.into_iter().next().map(|(_, (_, n))| n))
    }

    /// Returns the number value of the parameter with the "gasPrice",
    /// if any.
    ///
    /// ## Errors
    /// Errors if there are more than one parameter with the key "gasPrice"
    /// and the values of those parameters are not semantically equal.
    pub fn gas_price(&self) -> Result<Option<Number>, ValidationError> {
        let mut values = BTreeMap::default();
        for p in self.iter() {
            let (number, n) = match p {
                Parameter::GasPrice(n) => (n.as_i128()?, n),
                _ => continue,
            };
            values.insert(("gasPrice", number), n.clone());
        }
        snafu::ensure!(
            values.len() <= 1,
            MultipleParameterValuesSnafu {
                key: "gasPrice",
                values: values
                    .into_iter()
                    .map(|((k, _), n)| (k, Value::Number(n)))
                    .collect::<Vec<_>>(),
            }
        );
        Ok(values.into_iter().next().map(|(_, n)| n))
    }

    /// Returns an iterator over all ABI type parameters.
    pub fn abi_parameters(&self) -> impl Iterator<Item = (&EthereumAbiTypeName, &Value)> {
        self.iter().filter_map(|p| match p {
            Parameter::AbiType(name, value) => Some((name, value)),
            _ => None,
        })
    }
}

/// Schema prefix.
///
/// ```abnf
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
        let (i, _) = tag("ethereum:")(i)?;
        let (i, maybe_pay) = opt(tag("pay-"))(i)?;
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
        let (i, address_blob) = is_not("@/?")(i)?;
        let (remaining_address_input, target_address) = EthereumAddress::parse(address_blob)?;
        snafu::ensure!(
            remaining_address_input.is_empty(),
            UnexpectedLeftoverInputSnafu {
                input: remaining_address_input
            }
        );

        let parse_chain_id = preceded(tag("@"), Digits::parse_min(1));
        let (i, chain_id) = opt(parse_chain_id)(i)?;

        let parse_function_name = preceded(tag("/"), UrlEncodedUnicodeString::parse);
        let (i, function_name) = opt(parse_function_name)(i)?;

        let (i, _) = opt(tag("?"))(i)?;
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
            .unwrap()
        );
        assert_eq!(vec![1, 2, 3], Digits::from_u64(123).places);
    }

    #[test]
    fn digits_as_decimal_ratio() {
        // 0.0123
        let digits = Digits {
            places: vec![0, 1, 2, 3],
        };
        assert_eq!((123, 10_000), digits.as_decimal_ratio().unwrap());

        // 0.666
        let digits = Digits {
            places: vec![6, 6, 6],
        };
        assert_eq!((666, 1000), digits.as_decimal_ratio().unwrap());
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
            assert!(digits.as_u64().unwrap() >= 20);
        }
    }

    #[test]
    fn parse_digits_sanity() {
        let (i, seen_digits) = Digits::parse_min(0)("256").unwrap();
        assert!(i.is_empty());
        assert_eq!(256, seen_digits.as_u64().unwrap())
    }

    proptest! {
        #[test]
        fn parse_digits(digits in arb_digits(1)) {
            let s = digits.to_string();
            let (i, seen_digits) = Digits::parse_min(1)(&s).unwrap();
            assert_eq!("", i);
            assert_eq!(digits, seen_digits);
        }
    }

    #[test]
    fn number_as_i128_sanity() {
        let (_, n) = Number::parse("666.0").unwrap();
        assert_eq!(666, n.as_i128().unwrap());
    }

    #[test]
    fn number_as_signum_only_parses_to_zero() {
        let (_, n) = Number::parse("-").unwrap();
        assert_eq!(0, n.as_i128().unwrap());
    }

    fn arb_valid_number() -> impl Strategy<Value = Number> {
        (
            prop::option::of(any::<bool>()),
            arb_digits(1),
            any::<bool>(),
            prop::option::of(arb_digits_in(1..=4)),
        )
            .prop_flat_map(|(signum, integer, little_e, decimal)| {
                if let Some(dec) = decimal.as_ref() {
                    // If there is a decimal, ensure that the exponent "covers" it
                    let places_len = dec.places.len();
                    (places_len..=places_len + 14)
                        .prop_map(|n| Some(Digits::from_u64(n as u64)))
                        .boxed()
                } else {
                    prop::option::of((0..=18).prop_map(|n| Digits::from_u64(n as u64))).boxed()
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
        fn parse_arb_valid_number(ns in arb_valid_number()) {
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
    /// * only has one label, ie doesn't contain any '.' - eg "notadomain"
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
    ///
    /// Being exhaustive _and_ happy is hard here, because labels are almost
    /// arbitrary Unicode, but there are "recommendations" about what makes a
    /// good name. For added security we also validate the name after parsing
    /// to ensure it is properly normalized, but synthesizing Unicode that
    /// is guaranteed normalizable is outside the scope of this testsuite, for
    /// now.
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
        /// Meant to test not-necessarily-happy path ENS names, to ensure
        /// that they either fail to parse predictably, or parse to an equivalent name
        fn parse_arb_ens_name(expected in arb_any_ens_name()) {
            let input = expected.to_string();
            match EnsName::parse(&input) {
                Ok((i, seen)) => {
                    if i.is_empty() {
                        // The entirety was parsed, ensure they match
                        assert_eq!(expected, seen);
                    } else {
                        // Only a portion was matched, meaning it ran into a terminator,
                        // an encounter which few humans survive.
                    }
                }
                // The input was empty, fine
                Err(nom::Err::Error(ParseError::EnsMissing)) => {}
                // The input was not a valid domain
                Err(nom::Err::Error(ParseError::EnsDomain)) => {}
                // The input didn't normalize, fine since we don't know how to
                // construct a strategy via regex that is exhaustive of normalized input
                Err(nom::Err::Error(ParseError::EnsNormalization { .. })) => {}
                // The input was not normalized to begin with, which is also fine because
                // of the aformentioned scenario
                Err(nom::Err::Error(ParseError::NotNormalized {..})) => {}
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
        proptest::string::string_regex(&format!(".{{{min},{max}}}")).unwrap()
    }

    /// Used to produce url encoded unicode strings that are **not** numbers.
    ///
    /// This is used for arbitrary unicode values that should not roundtrip to a number.
    ///
    /// Imagine this scenario:
    ///
    /// 1. arb_url_encoded_string produces `input = UrlEncodedString(0)`.
    /// 2. serialize to "0"
    /// 3. parse from "0" produces `output = Number(0)`
    /// 4. input != output
    fn arb_non_numeric_url_encoded_string() -> impl Strategy<Value = UrlEncodedUnicodeString> {
        {
            let min = 1;
            let max = 1024;
            proptest::string::string_regex(&format!("[^\\d]{{{min},{max}}}")).unwrap()
        }
        .prop_map(UrlEncodedUnicodeString::encode)
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

    fn arb_value() -> impl Strategy<Value = Value> {
        Union::new([
            arb_valid_number().prop_map(Value::Number).boxed(),
            arb_eth_addy().prop_map(Value::Address).boxed(),
            arb_non_numeric_url_encoded_string()
                .prop_map(Value::String)
                .boxed(),
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

    fn arb_eth_abi_parameter() -> impl Strategy<Value = Parameter> {
        (arb_eth_type_name(TYPE_RECURSIONS), arb_value())
            .prop_map(|(name, value)| Parameter::AbiType(name, value))
    }

    fn arb_non_eth_abi_parameter() -> impl Strategy<Value = Parameter> {
        arb_valid_number()
            .prop_map(Parameter::Value)
            .boxed()
            .prop_union(arb_valid_number().prop_map(Parameter::Gas).boxed())
            .boxed()
            .prop_union(arb_valid_number().prop_map(Parameter::GasLimit).boxed())
            .boxed()
            .prop_union(arb_valid_number().prop_map(Parameter::GasPrice).boxed())
            .boxed()
    }

    fn arb_parameter() -> impl Strategy<Value = Parameter> {
        arb_eth_abi_parameter()
            .boxed()
            .prop_union(arb_non_eth_abi_parameter().boxed())
    }

    #[test]
    fn sanity_uint_eq_zero_parameter() {
        let expected = Parameter::AbiType(
            EthereumAbiTypeName {
                name: "uint".to_string(),
            },
            Value::Number(Number {
                signum: None,
                integer: Digits { places: vec![0] },
                decimal: None,
                exponent: None,
            }),
        );
        let expected_string = expected.to_string();
        assert_eq!("uint=0", expected_string);

        let (_i, parsed) = Parameter::parse(&expected_string).unwrap();
        pretty_assertions::assert_eq!(expected, parsed);
    }

    proptest! {
        #[test]
        fn parse_arb_parameter(expected in arb_parameter()) {
            let input = expected.to_string();
            let (output, seen) = Parameter::parse(&input).unwrap();
            assert_eq!("", output, "`input` was not fully consumed. Parsed '{seen}'");
            pretty_assertions::assert_eq!(expected, seen);
        }
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
            let (i, seen) = EthereumTransactionRequest::parse(&input).unwrap_or_else(|e| panic!("could not parse '{input}': {e}"));
            pretty_assertions::assert_str_eq!(input, seen.to_string().as_str(), "input: {input}\ni: {i}");
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
        let number = seen.parameters.value().unwrap().unwrap();
        assert_eq!(2, number.integer().unwrap());
        assert_eq!(2.014e18 as i128, number.as_i128().unwrap());
    }

    #[test]
    fn digits_as_decimal_ratio_sanity() {
        let input = "0001234";
        let (_, digits) = Digits::parse_min(1)(input).unwrap();
        let ratio = digits.as_decimal_ratio().unwrap();
        assert_eq!((1234, 10_000_000), ratio);
        assert_eq!(0.0001234, ratio.0 as f32 / ratio.1 as f32);
    }
}
