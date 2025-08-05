//! Parser for [EIP-681](https://eips.ethereum.org/EIPS/eip-681) transaction requests.
//!
//! ## Syntax
//!
//! ```abnf
//! request          = schema_prefix target_address [ "@" chain_id ] [ "/" function_name ] [ "?" parameters ]
//! schema_prefix    = "ethereum" ":" [ "pay-" ]
//! target_address   = ethereum_address
//! chain_id         = 1*DIGIT
//! function_name    = STRING
//! ethereum_address = ( "0x" 40*HEXDIG ) / ENS_NAME
//! parameters       = parameter *( "&" parameter )
//! parameter        = key "=" value
//! key              = "value" / "gas" / "gasLimit" / "gasPrice" / TYPE
//! value            = number / ethereum_address / STRING
//! number           = [ "-" / "+" ] *DIGIT [ "." 1*DIGIT ] [ ( "e" / "E" ) [ 1*DIGIT ] ]
//! ```

/// Errors produced in decoding of EIP-681 transaction requests.
// TODO(schell): discuss snafu here again?
#[derive(Debug, Clone)]
pub enum Eip681Error {}

mod parse {
    use super::*;

    /// Parse a number.
    ///
    /// ```abnf
    /// number = [ "-" / "+" ] *DIGIT [ "." 1*DIGIT ] [ ( "e" / "E" ) [ 1*DIGIT ] ]
    /// ```
    ///
    /// Note that a number can be expressed in scientific notation, with a
    /// multiplier of a power of 10. Only integer numbers are allowed, so the
    /// exponent MUST be greater or equal to the number of decimals after the point.
    ///
    /// Note(schell):
    /// I suspect that this ABNF notation is incorrect, as it allows for a few cases
    /// that wouldn't make sense.
    /// 1. `*DIGIT` is missing and `[ "." 1*DIGIT ]` is present while `[ ( "e" / "E" ) [ 1*DIGIT] ]`
    ///    is not
    /// 2. `[ ( "e" / "E" ) [ 1*DIGIT] ]` is missing the `[ 1*DIGIT ]` (eg, just "e")
    /// 3. The decimal is present while the exponent is missing
    /// 4. others
    ///
    /// TODO(schell):
    ///   - look at an EIP-681 _implementation_ to see what they've done
    ///     - <https://github.com/crypto-com/defi-wallet-core-rs/blob/52e6c5be2ce44085d7c0d94aabc901b13b8629b6/common/src/qr_code.rs#L171>
    ///   - tell someone about the bugs
    ///
    /// This suggests that validation is separate from parsing.
    pub fn number(i: &str) -> nom::IResult<&str, i64, Eip681Error> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use prop::{strategy::ValueTree, test_runner::TestRunner};
    use proptest::prelude::*;

    #[derive(Debug, Clone, PartialEq)]
    struct Digits(Vec<u8>);

    impl core::fmt::Display for Digits {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for n in self.0.iter() {
                f.write_fmt(format_args!("{n}"))?;
            }
            Ok(())
        }
    }

    impl Digits {
        const MAX_PLACES: usize = u64::MAX.ilog10() as usize;

        fn value(&self) -> u64 {
            let mut total = 0;
            for (mag, digit) in self.0.iter().rev().enumerate() {
                total += *digit as u64 * 10u64.pow(mag as u32);
            }
            total
        }

        fn from_u64(mut v: u64) -> Self {
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
    }

    #[test]
    fn digits_sanity() {
        assert_eq!(123, Digits(vec![1, 2, 3]).value());
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
            assert!(digits.value() >= 20);
        }
    }

    #[derive(Debug)]
    struct Number {
        /// true for "+", false for "-"
        signum: Option<bool>,
        integer: Digits,
        /// true for "e", false for "E"
        little_e: bool,
        decimal: Option<Digits>,
        exponent: Option<Digits>,
    }

    impl Number {
        fn render(&self) -> String {
            let Number {
                signum,
                integer,
                little_e,
                decimal,
                exponent,
            } = self;
            let sig = if let Some(signum) = signum {
                if *signum {
                    "+"
                } else {
                    "-"
                }
            } else {
                ""
            };
            let dec = if let Some(dec) = decimal {
                format!(".{dec}")
            } else {
                String::new()
            };
            let exp = if let Some(exp) = exponent {
                let e = if *little_e { "e" } else { "E" };
                format!("{e}{exp}")
            } else {
                String::new()
            };
            format!("{sig}{integer}{dec}{exp}")
        }

        fn is_valid(&self) -> bool {
            if let Some(dec) = self.decimal.as_ref() {
                let exp_value = self
                    .exponent
                    .as_ref()
                    .map(Digits::value)
                    .unwrap_or_default();
                exp_value >= dec.0.len() as u64
            } else {
                true
            }
        }
    }

    // #[test]
    // fn number_render_sanity() {
    //     Number { signum: Some(true), integer: Digits(vec!["12345"]),  }
    // }

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
                    little_e,
                    decimal: decimal.clone(),
                    exponent,
                })
            })
    }

    /// Produce an arbitrary `Number` that may or may not be valid.
    fn arb_any_number() -> impl Strategy<Value = Number> {
        (
            prop::option::of(any::<bool>()),
            arb_digits(0),
            any::<bool>(),
            prop::option::of(arb_digits(1)),
            prop::option::of(arb_digits(1)),
        )
            .prop_map(|(signum, integer, little_e, decimal, exponent)| Number {
                signum,
                integer,
                little_e,
                decimal,
                exponent,
            })
    }

    proptest! {
        #[test]
        fn arb_valid_number_sanity(number in arb_valid_number()) {
            assert!(number.is_valid());
        }
    }

    // prop_compose! {
    //     fn arb_number(max_len: usize)
    //     (
    //         n_decimals in prop::option::of(1..=max_len)
    //     )
    //     (
    //         decimal in n_decimals.prop_map(|n| arb_digits(1..=n))
    //     )
    //     (
    //         signum in any::<bool>(),
    //         integer in arb_digits(0..=max_len),
    //         decimal_and_exponent in decimal.prop_map(|ds| {
    //             let exponent = arb_digits()
    //             (
    //                 ds,
    //                 arb_digits()
    //             )
    //         })
    //     ) -> ArbNumber {
    //         ArbNumber {
    //             signum,
    //             integer,
    //             decimal_and_exponent: None
    //         }
    //     }
    // }

    // // prop_compose! {
    // //     fn arb_number_str()
    // //     (decimals in prop::option::of(any::<u64>()))
    // //     (
    // //         integer in prop::option::of(any::<i64>()),
    // //         digit2 in decimals.prop_map(|exp| )
    // //     ) -> String {

    // //     }
    // // }

    // proptest! {
    //     #[test]
    //     fn prop_number(ns in arb_number(10)) {
    //         assert!(ns.integer.len() <= 10);
    //     }
    // }
}
