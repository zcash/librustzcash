use std::{convert::TryInto, error::Error, fmt, str::FromStr};

use bech32::{self, FromBase32, ToBase32, Variant};

use crate::{kind::*, AddressKind, Network, ZcashAddress};

/// An error while attempting to parse a string as a Zcash address.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    /// The string is an invalid encoding.
    InvalidEncoding,
    /// The string is not a Zcash address.
    NotZcash,
    /// Errors specific to unified addresses.
    Unified(unified::ParseError),
}

impl From<unified::ParseError> for ParseError {
    fn from(e: unified::ParseError) -> Self {
        match e {
            unified::ParseError::InvalidEncoding(_) => Self::InvalidEncoding,
            _ => Self::Unified(e),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidEncoding => write!(f, "Invalid encoding"),
            ParseError::NotZcash => write!(f, "Not a Zcash address"),
            ParseError::Unified(e) => e.fmt(f),
        }
    }
}

impl Error for ParseError {}

impl FromStr for ZcashAddress {
    type Err = ParseError;

    /// Attempts to parse the given string as a Zcash address.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Remove leading and trailing whitespace, to handle copy-paste errors.
        let s = s.trim();

        // Most Zcash addresses use Bech32 or Bech32m, so try those first.
        match bech32::decode(s) {
            Ok((hrp, data, Variant::Bech32m)) => {
                // If we reached this point, the encoding is supposed to be valid Bech32m.
                let data =
                    Vec::<u8>::from_base32(&data).map_err(|_| ParseError::InvalidEncoding)?;

                let net = match hrp.as_str() {
                    unified::MAINNET => Network::Main,
                    unified::TESTNET => Network::Test,
                    unified::REGTEST => Network::Regtest,
                    // We will not define new Bech32m address encodings.
                    _ => {
                        return Err(ParseError::NotZcash);
                    }
                };

                return (hrp.as_str(), &data[..])
                    .try_into()
                    .map(AddressKind::Unified)
                    .map_err(|_| ParseError::InvalidEncoding)
                    .map(|kind| ZcashAddress { net, kind });
            }
            Ok((hrp, data, Variant::Bech32)) => {
                // If we reached this point, the encoding is supposed to be valid Bech32.
                let data =
                    Vec::<u8>::from_base32(&data).map_err(|_| ParseError::InvalidEncoding)?;

                let net = match hrp.as_str() {
                    sapling::MAINNET => Network::Main,
                    sapling::TESTNET => Network::Test,
                    sapling::REGTEST => Network::Regtest,
                    // We will not define new Bech32 address encodings.
                    _ => {
                        return Err(ParseError::NotZcash);
                    }
                };

                return data[..]
                    .try_into()
                    .map(AddressKind::Sapling)
                    .map_err(|_| ParseError::InvalidEncoding)
                    .map(|kind| ZcashAddress { net, kind });
            }
            Err(_) => (),
        }

        // The rest use Base58Check.
        if let Ok(decoded) = bs58::decode(s).with_check(None).into_vec() {
            let net = match decoded[..2].try_into().unwrap() {
                sprout::MAINNET | p2pkh::MAINNET | p2sh::MAINNET => Network::Main,
                sprout::TESTNET | p2pkh::TESTNET | p2sh::TESTNET => Network::Test,
                // We will not define new Base58Check address encodings.
                _ => return Err(ParseError::NotZcash),
            };

            return match decoded[..2].try_into().unwrap() {
                sprout::MAINNET | sprout::TESTNET => {
                    decoded[2..].try_into().map(AddressKind::Sprout)
                }
                p2pkh::MAINNET | p2pkh::TESTNET => decoded[2..].try_into().map(AddressKind::P2pkh),
                p2sh::MAINNET | p2sh::TESTNET => decoded[2..].try_into().map(AddressKind::P2sh),
                _ => unreachable!(),
            }
            .map_err(|_| ParseError::InvalidEncoding)
            .map(|kind| ZcashAddress { kind, net });
        };

        // If it's not valid Bech32 or Base58Check, it's not a Zcash address.
        Err(ParseError::NotZcash)
    }
}

fn encode_bech32m(hrp: &str, data: &[u8]) -> String {
    bech32::encode(hrp, data.to_base32(), Variant::Bech32m).expect("hrp is invalid")
}

fn encode_bech32(hrp: &str, data: &[u8]) -> String {
    bech32::encode(hrp, data.to_base32(), Variant::Bech32).expect("hrp is invalid")
}

fn encode_b58(prefix: [u8; 2], data: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(2 + data.len());
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(data);
    bs58::encode(bytes).with_check().into_string()
}

impl fmt::Display for ZcashAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = match &self.kind {
            AddressKind::Sprout(data) => encode_b58(
                match self.net {
                    Network::Main => sprout::MAINNET,
                    Network::Test | Network::Regtest => sprout::TESTNET,
                },
                data,
            ),
            AddressKind::Sapling(data) => encode_bech32(
                match self.net {
                    Network::Main => sapling::MAINNET,
                    Network::Test => sapling::TESTNET,
                    Network::Regtest => sapling::REGTEST,
                },
                data,
            ),
            AddressKind::Unified(data) => {
                let hrp = match self.net {
                    Network::Main => unified::MAINNET,
                    Network::Test => unified::TESTNET,
                    Network::Regtest => unified::REGTEST,
                };
                encode_bech32m(hrp, &data.to_bytes(hrp))
            }
            AddressKind::P2pkh(data) => encode_b58(
                match self.net {
                    Network::Main => p2pkh::MAINNET,
                    Network::Test | Network::Regtest => p2pkh::TESTNET,
                },
                data,
            ),
            AddressKind::P2sh(data) => encode_b58(
                match self.net {
                    Network::Main => p2sh::MAINNET,
                    Network::Test | Network::Regtest => p2sh::TESTNET,
                },
                data,
            ),
        };
        write!(f, "{}", encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kind::unified;

    fn encoding(encoded: &str, decoded: ZcashAddress) {
        assert_eq!(decoded.to_string(), encoded);
        assert_eq!(encoded.parse(), Ok(decoded));
    }

    #[test]
    fn sprout() {
        encoding(
            "zc8E5gYid86n4bo2Usdq1cpr7PpfoJGzttwBHEEgGhGkLUg7SPPVFNB2AkRFXZ7usfphup5426dt1buMmY3fkYeRrQGLa8y",
            ZcashAddress { net: Network::Main, kind: AddressKind::Sprout([0; 64]) },
        );
        encoding(
            "ztJ1EWLKcGwF2S4NA17pAJVdco8Sdkz4AQPxt1cLTEfNuyNswJJc2BbBqYrsRZsp31xbVZwhF7c7a2L9jsF3p3ZwRWpqqyS",
            ZcashAddress { net: Network::Test, kind: AddressKind::Sprout([0; 64]) },
        );
    }

    #[test]
    fn sapling() {
        encoding(
            "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpq6d8g",
            ZcashAddress {
                net: Network::Main,
                kind: AddressKind::Sapling([0; 43]),
            },
        );
        encoding(
            "ztestsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfhgwqu",
            ZcashAddress {
                net: Network::Test,
                kind: AddressKind::Sapling([0; 43]),
            },
        );
        encoding(
            "zregtestsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqknpr3m",
            ZcashAddress {
                net: Network::Regtest,
                kind: AddressKind::Sapling([0; 43]),
            },
        );
    }

    #[test]
    fn unified() {
        encoding(
            "u175h4qsgd8gujkevz283ka89ul6r2kr25xvachlt5w5srewdwcjacdtm3ku06jazzwk2klezj3kfy2jc9p65l5fgvjhekmnd4myk2m7xn",
            ZcashAddress {
                net: Network::Main,
                kind: AddressKind::Unified(unified::Address(vec![unified::Receiver::Sapling([0; 43])])),
            },
        );
        encoding(
            "utest193cmy6pcjrw6cg8rqcxgq6z2095a2mc0hqu0g0gvnlf83em0szx23qtv9722s6qkssz80try4tynp73u9gee3zskye0ztzdz0snrxw7n",
            ZcashAddress {
                net: Network::Test,
                kind: AddressKind::Unified(unified::Address(vec![unified::Receiver::Sapling([0; 43])])),
            },
        );
        encoding(
            "uregtest1dl4mka5saz8xwnf0pttr637jx6su0nejfhzcz3metcmqyzdgktsmm09ese6ew794xqcyp6476nuspvdvx2xk6gn2euvu7fdmrvwl87zx",
            ZcashAddress {
                net: Network::Regtest,
                kind: AddressKind::Unified(unified::Address(vec![unified::Receiver::Sapling([0; 43])])),
            },
        );
    }

    #[test]
    fn transparent() {
        encoding(
            "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs",
            ZcashAddress {
                net: Network::Main,
                kind: AddressKind::P2pkh([0; 20]),
            },
        );
        encoding(
            "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma",
            ZcashAddress {
                net: Network::Test,
                kind: AddressKind::P2pkh([0; 20]),
            },
        );
        encoding(
            "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ",
            ZcashAddress {
                net: Network::Main,
                kind: AddressKind::P2sh([0; 20]),
            },
        );
        encoding(
            "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2",
            ZcashAddress {
                net: Network::Test,
                kind: AddressKind::P2sh([0; 20]),
            },
        );
    }

    #[test]
    fn whitespace() {
        assert_eq!(
            " t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs".parse(),
            Ok(ZcashAddress {
                net: Network::Main,
                kind: AddressKind::P2pkh([0; 20])
            }),
        );
        assert_eq!(
            "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs ".parse(),
            Ok(ZcashAddress {
                net: Network::Main,
                kind: AddressKind::P2pkh([0; 20])
            }),
        );
        assert_eq!(
            "something t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs".parse::<ZcashAddress>(),
            Err(ParseError::NotZcash),
        );
    }
}
