use std::{convert::TryInto, error::Error, fmt, str::FromStr};

use bech32::{self, FromBase32, ToBase32, Variant};
use zcash_protocol::consensus::{NetworkConstants, NetworkType};
use zcash_protocol::constants::{mainnet, regtest, testnet};

use crate::kind::unified::Encoding;
use crate::{kind::*, AddressKind, ZcashAddress};

/// An error while attempting to parse a string as a Zcash address.
#[derive(Debug, PartialEq, Eq)]
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
            unified::ParseError::UnknownPrefix(_) => Self::NotZcash,
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

        // Try decoding as a unified address
        match unified::Address::decode(s) {
            Ok((net, data)) => {
                return Ok(ZcashAddress {
                    net,
                    kind: AddressKind::Unified(data),
                });
            }
            Err(unified::ParseError::NotUnified | unified::ParseError::UnknownPrefix(_)) => {
                // allow decoding to fall through to Sapling/TEX/Transparent
            }
            Err(e) => {
                return Err(ParseError::from(e));
            }
        }

        // Try decoding as a Sapling or TEX address (Bech32/Bech32m)
        if let Ok((hrp, data, variant)) = bech32::decode(s) {
            // If we reached this point, the encoding is found to be valid Bech32 or Bech32m.
            let data = Vec::<u8>::from_base32(&data).map_err(|_| ParseError::InvalidEncoding)?;

            match variant {
                Variant::Bech32 => {
                    let net = match hrp.as_str() {
                        mainnet::HRP_SAPLING_PAYMENT_ADDRESS => NetworkType::Main,
                        testnet::HRP_SAPLING_PAYMENT_ADDRESS => NetworkType::Test,
                        regtest::HRP_SAPLING_PAYMENT_ADDRESS => NetworkType::Regtest,
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
                Variant::Bech32m => {
                    // Try decoding as a TEX address (Bech32m)
                    let net = match hrp.as_str() {
                        mainnet::HRP_TEX_ADDRESS => NetworkType::Main,
                        testnet::HRP_TEX_ADDRESS => NetworkType::Test,
                        regtest::HRP_TEX_ADDRESS => NetworkType::Regtest,
                        // Not recognized as a Zcash address type
                        _ => {
                            return Err(ParseError::NotZcash);
                        }
                    };

                    return data[..]
                        .try_into()
                        .map(AddressKind::Tex)
                        .map_err(|_| ParseError::InvalidEncoding)
                        .map(|kind| ZcashAddress { net, kind });
                }
            }
        }

        // The rest use Base58Check.
        if let Ok(decoded) = bs58::decode(s).with_check(None).into_vec() {
            if decoded.len() >= 2 {
                let (prefix, net) = match decoded[..2].try_into().unwrap() {
                    prefix @ (mainnet::B58_PUBKEY_ADDRESS_PREFIX
                    | mainnet::B58_SCRIPT_ADDRESS_PREFIX
                    | mainnet::B58_SPROUT_ADDRESS_PREFIX) => (prefix, NetworkType::Main),
                    prefix @ (testnet::B58_PUBKEY_ADDRESS_PREFIX
                    | testnet::B58_SCRIPT_ADDRESS_PREFIX
                    | testnet::B58_SPROUT_ADDRESS_PREFIX) => (prefix, NetworkType::Test),
                    // We will not define new Base58Check address encodings.
                    _ => return Err(ParseError::NotZcash),
                };

                return match prefix {
                    mainnet::B58_SPROUT_ADDRESS_PREFIX | testnet::B58_SPROUT_ADDRESS_PREFIX => {
                        decoded[2..].try_into().map(AddressKind::Sprout)
                    }
                    mainnet::B58_PUBKEY_ADDRESS_PREFIX | testnet::B58_PUBKEY_ADDRESS_PREFIX => {
                        decoded[2..].try_into().map(AddressKind::P2pkh)
                    }
                    mainnet::B58_SCRIPT_ADDRESS_PREFIX | testnet::B58_SCRIPT_ADDRESS_PREFIX => {
                        decoded[2..].try_into().map(AddressKind::P2sh)
                    }
                    _ => unreachable!(),
                }
                .map_err(|_| ParseError::InvalidEncoding)
                .map(|kind| ZcashAddress { kind, net });
            }
        };

        // If it's not valid Bech32, Bech32m, or Base58Check, it's not a Zcash address.
        Err(ParseError::NotZcash)
    }
}

fn encode_bech32(hrp: &str, data: &[u8], variant: Variant) -> String {
    bech32::encode(hrp, data.to_base32(), variant).expect("hrp is invalid")
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
            AddressKind::Sprout(data) => encode_b58(self.net.b58_sprout_address_prefix(), data),
            AddressKind::Sapling(data) => encode_bech32(
                self.net.hrp_sapling_payment_address(),
                data,
                Variant::Bech32,
            ),
            AddressKind::Unified(addr) => addr.encode(&self.net),
            AddressKind::P2pkh(data) => encode_b58(self.net.b58_pubkey_address_prefix(), data),
            AddressKind::P2sh(data) => encode_b58(self.net.b58_script_address_prefix(), data),
            AddressKind::Tex(data) => {
                encode_bech32(self.net.hrp_tex_address(), data, Variant::Bech32m)
            }
        };
        write!(f, "{}", encoded)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::{kind::unified, Network};

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
            "u1qpatys4zruk99pg59gcscrt7y6akvl9vrhcfyhm9yxvxz7h87q6n8cgrzzpe9zru68uq39uhmlpp5uefxu0su5uqyqfe5zp3tycn0ecl",
            ZcashAddress {
                net: Network::Main,
                kind: AddressKind::Unified(unified::Address(vec![unified::address::Receiver::Sapling([0; 43])])),
            },
        );
        encoding(
            "utest10c5kutapazdnf8ztl3pu43nkfsjx89fy3uuff8tsmxm6s86j37pe7uz94z5jhkl49pqe8yz75rlsaygexk6jpaxwx0esjr8wm5ut7d5s",
            ZcashAddress {
                net: Network::Test,
                kind: AddressKind::Unified(unified::Address(vec![unified::address::Receiver::Sapling([0; 43])])),
            },
        );
        encoding(
            "uregtest15xk7vj4grjkay6mnfl93dhsflc2yeunhxwdh38rul0rq3dfhzzxgm5szjuvtqdha4t4p2q02ks0jgzrhjkrav70z9xlvq0plpcjkd5z3",
            ZcashAddress {
                net: Network::Regtest,
                kind: AddressKind::Unified(unified::Address(vec![unified::address::Receiver::Sapling([0; 43])])),
            },
        );

        let badencoded = "uinvalid1ck5navqwcng43gvsxwrxsplc22p7uzlcag6qfa0zh09e87efq6rq8wsnv25umqjjravw70rl994n5ueuhza2fghge5gl7zrl2qp6cwmp";
        assert_eq!(
            badencoded.parse::<ZcashAddress>(),
            Err(ParseError::NotZcash)
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
    fn tex() {
        let p2pkh_str = "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC";
        let tex_str = "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte";

        // Transcode P2PKH to TEX
        let p2pkh_zaddr: ZcashAddress = p2pkh_str.parse().unwrap();
        assert_matches!(p2pkh_zaddr.net, Network::Main);
        if let AddressKind::P2pkh(zaddr_data) = p2pkh_zaddr.kind {
            let tex_zaddr = ZcashAddress {
                net: p2pkh_zaddr.net,
                kind: AddressKind::Tex(zaddr_data),
            };

            assert_eq!(tex_zaddr.to_string(), tex_str);
        } else {
            panic!("Decoded address should have been a P2PKH address.");
        }

        // Transcode TEX to P2PKH
        let tex_zaddr: ZcashAddress = tex_str.parse().unwrap();
        assert_matches!(tex_zaddr.net, Network::Main);
        if let AddressKind::Tex(zaddr_data) = tex_zaddr.kind {
            let p2pkh_zaddr = ZcashAddress {
                net: tex_zaddr.net,
                kind: AddressKind::P2pkh(zaddr_data),
            };

            assert_eq!(p2pkh_zaddr.to_string(), p2pkh_str);
        } else {
            panic!("Decoded address should have been a TEX address.");
        }
    }

    #[test]
    fn tex_testnet() {
        let p2pkh_str = "tm9ofD7kHR7AF8MsJomEzLqGcrLCBkD9gDj";
        let tex_str = "textest1qyqszqgpqyqszqgpqyqszqgpqyqszqgpfcjgfy";

        // Transcode P2PKH to TEX
        let p2pkh_zaddr: ZcashAddress = p2pkh_str.parse().unwrap();
        assert_matches!(p2pkh_zaddr.net, Network::Test);
        if let AddressKind::P2pkh(zaddr_data) = p2pkh_zaddr.kind {
            let tex_zaddr = ZcashAddress {
                net: p2pkh_zaddr.net,
                kind: AddressKind::Tex(zaddr_data),
            };

            assert_eq!(tex_zaddr.to_string(), tex_str);
        } else {
            panic!("Decoded address should have been a P2PKH address.");
        }

        // Transcode TEX to P2PKH
        let tex_zaddr: ZcashAddress = tex_str.parse().unwrap();
        assert_matches!(tex_zaddr.net, Network::Test);
        if let AddressKind::Tex(zaddr_data) = tex_zaddr.kind {
            let p2pkh_zaddr = ZcashAddress {
                net: tex_zaddr.net,
                kind: AddressKind::P2pkh(zaddr_data),
            };

            assert_eq!(p2pkh_zaddr.to_string(), p2pkh_str);
        } else {
            panic!("Decoded address should have been a TEX address.");
        }
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
