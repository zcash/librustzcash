//! Types and functions used for parsing.

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
        "Expected at least {min} digits, saw only '{digits}' before {}",
        input.split_at(10).0
    ))]
    DigitsMinimum {
        min: usize,
        digits: Digits,
        input: &'a str,
    },

    #[snafu(display("Missing ENS name"))]
    MissingEns,

    #[snafu(display("{source}"))]
    EnsNormalization {
        source: ens_normalize_rs::ProcessError,
    },
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
        nom::Err::Error(value)
    }
}

#[derive(Debug, Snafu, PartialEq)]
pub enum ValidationError {
    #[snafu(display("Exponent is too small, expected at least {expected}, saw {seen}"))]
    SmallExponent { expected: usize, seen: u64 },
}

/// Zero or more consecutive digits.
///
/// ```abnf
/// *DIGIT
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Digits(Vec<u8>);

impl core::fmt::Display for Digits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for n in self.0.iter() {
            f.write_fmt(format_args!("{n}"))?;
        }
        Ok(())
    }
}

impl Digits {
    pub const MAX_PLACES: usize = u64::MAX.ilog10() as usize;

    pub fn as_u64(&self) -> u64 {
        let mut total = 0;
        for (mag, digit) in self.0.iter().rev().enumerate() {
            total += *digit as u64 * 10u64.pow(mag as u32);
        }
        total
    }

    pub fn from_u64(mut v: u64) -> Self {
        if v == 0 {
            return Digits(vec![0]);
        }

        let mut digits = Digits(vec![]);
        for log in (0..=v.ilog10()).rev() {
            let top = 10u64.pow(log);
            let digit = v / top;
            digits.0.push(digit as u8);
            v -= digit * top;
        }
        digits
    }

    /// Parse at least `min` digits.
    pub fn parse_min(i: &str, min: usize) -> nom::IResult<&str, Self, ParseError<'_>> {
        let (i, chars) = nom::bytes::complete::take_while(|c: char| c.is_ascii_digit())(i)?;
        let data = chars
            .chars()
            .map(|c| {
                c.to_digit(10).unwrap_or_else(|| {
                    unreachable!("we already checked that this char was a digit")
                }) as u8
            })
            .collect::<Vec<_>>();
        let digits = Digits(data);
        snafu::ensure!(
            digits.0.len() >= min,
            DigitsMinimumSnafu {
                min,
                digits,
                input: i
            }
        );
        Ok((i, digits))
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
                exp_value >= dec.0.len() as u64,
                SmallExponentSnafu {
                    expected: dec.0.len(),
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
#[derive(Debug, PartialEq)]
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

#[cfg(test)]
mod test {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn digits_sanity() {
        assert_eq!(123, Digits(vec![1, 2, 3]).as_u64());
        assert_eq!(vec![1, 2, 3], Digits::from_u64(123).0);
    }

    fn arb_digits(min_digits: usize) -> impl Strategy<Value = Digits> {
        let size_range = min_digits..=Digits::MAX_PLACES;
        let strategy = prop::collection::vec(0..=9u8, size_range);
        strategy.prop_map(Digits)
    }

    proptest! {
        #[test]
        fn arb_digits_sanity(digits in arb_digits(2)) {
            // all digits should be >= 10
            assert!(digits.0.len() >= 2, "digits: {digits:#?}");
            assert!(digits.0.len() <= Digits::MAX_PLACES, "digits: {digits:#?}");
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
            let (i, seen_digits) = Digits::parse_min(&s, 0).unwrap();
            assert!(i.is_empty());
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
                    arb_digits_gte(dec.0.len() as u64).prop_map(Some).boxed()
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
            println!("parsing '{input}'");
            let (i, name) = EnsName::parse(input).unwrap();
            println!("  got '{name}'");
            assert_eq!("", i);
            assert_eq!(EnsName(input.to_string()), name);
        }
    }

    fn arb_any_ens_name() -> impl Strategy<Value = EnsName> {
        proptest::string::string_regex("[^\\s\\t@/?]{0,255}")
            .unwrap()
            .prop_map(EnsName)
    }

    proptest! {
        #[test]
        fn arb_ens_name(expected in arb_any_ens_name()) {
            let input = expected.to_string();
            match EnsName::parse(&input) {
                Err(nom::Err::Error(ParseError::EnsNormalization{..})) => {}
                Err(nom::Err::Error(ParseError::MissingEns)) => {}
                Err(e) => panic!("{e}"),
                Ok((i, seen)) => {
                    assert_eq!("", i);
                    assert_eq!(expected, seen);
                }

            }
        }
    }
}
