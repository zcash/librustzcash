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
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidEncoding => write!(f, "Invalid encoding"),
            ParseError::NotZcash => write!(f, "Not a Zcash address"),
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

        // Most Zcash addresses use Bech32, so try that first.
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

                return data[..]
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
    let mut decoded = Vec::with_capacity(2 + data.len());
    decoded.extend_from_slice(&prefix);
    decoded.extend_from_slice(data);
    bs58::encode(decoded).with_check().into_string()
}

impl fmt::Display for ZcashAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = match self.kind {
            AddressKind::Sprout(data) => encode_b58(
                if let Network::Main = self.net {
                    sprout::MAINNET
                } else {
                    sprout::TESTNET
                },
                &data,
            ),
            AddressKind::Sapling(data) => encode_bech32(
                match self.net {
                    Network::Main => sapling::MAINNET,
                    Network::Test => sapling::TESTNET,
                    Network::Regtest => sapling::REGTEST,
                },
                &data,
            ),
            AddressKind::Unified(data) => encode_bech32m(
                match self.net {
                    Network::Main => unified::MAINNET,
                    Network::Test => unified::TESTNET,
                    Network::Regtest => unified::REGTEST,
                },
                &data,
            ),
            AddressKind::P2pkh(data) => encode_b58(
                if let Network::Main = self.net {
                    p2pkh::MAINNET
                } else {
                    p2pkh::TESTNET
                },
                &data,
            ),
            AddressKind::P2sh(data) => encode_b58(
                if let Network::Main = self.net {
                    p2sh::MAINNET
                } else {
                    p2sh::TESTNET
                },
                &data,
            ),
        };
        write!(f, "{}", encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "zo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq58lk79",
            ZcashAddress {
                net: Network::Main,
                kind: AddressKind::Unified([0; 43]),
            },
        );
        encoding(
            "ztestorchard1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcrmt3p",
            ZcashAddress {
                net: Network::Test,
                kind: AddressKind::Unified([0; 43]),
            },
        );
        encoding(
            "zregtestorchard1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq88jxqx",
            ZcashAddress {
                net: Network::Regtest,
                kind: AddressKind::Unified([0; 43]),
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
