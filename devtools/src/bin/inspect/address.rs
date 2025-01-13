use zcash_address::{
    unified::{self, Container, Encoding},
    ConversionError, ToAddress, ZcashAddress,
};
use zcash_protocol::consensus::NetworkType;

#[allow(dead_code)]
enum AddressKind {
    Sprout([u8; 64]),
    Sapling([u8; 43]),
    Unified(unified::Address),
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
    Tex([u8; 20]),
}

struct Address {
    net: NetworkType,
    kind: AddressKind,
}

impl zcash_address::TryFromAddress for Address {
    type Error = ();

    fn try_from_sprout(
        net: NetworkType,
        data: [u8; 64],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::Sprout(data),
        })
    }

    fn try_from_sapling(
        net: NetworkType,
        data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::Sapling(data),
        })
    }

    fn try_from_unified(
        net: NetworkType,
        data: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::Unified(data),
        })
    }

    fn try_from_transparent_p2pkh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::P2pkh(data),
        })
    }

    fn try_from_transparent_p2sh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::P2sh(data),
        })
    }

    fn try_from_tex(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::Tex(data),
        })
    }
}

pub(crate) fn inspect(addr: ZcashAddress) {
    eprintln!("Zcash address");

    match addr.convert::<Address>() {
        // TODO: Check for valid internals once we have migrated to a newer zcash_address
        // version with custom errors.
        Err(_) => unreachable!(),
        Ok(addr) => {
            eprintln!(
                " - Network: {}",
                match addr.net {
                    NetworkType::Main => "main",
                    NetworkType::Test => "testnet",
                    NetworkType::Regtest => "regtest",
                }
            );
            eprintln!(
                " - Kind: {}",
                match addr.kind {
                    AddressKind::Sprout(_) => "Sprout",
                    AddressKind::Sapling(_) => "Sapling",
                    AddressKind::Unified(_) => "Unified Address",
                    AddressKind::P2pkh(_) => "Transparent P2PKH",
                    AddressKind::P2sh(_) => "Transparent P2SH",
                    AddressKind::Tex(_) => "TEX (ZIP 320)",
                }
            );

            match addr.kind {
                AddressKind::Unified(ua) => {
                    eprintln!(" - Receivers:");
                    for receiver in ua.items() {
                        match receiver {
                            unified::Receiver::Orchard(data) => {
                                eprintln!(
                                    "   - Orchard ({})",
                                    unified::Address::try_from_items(vec![
                                        unified::Receiver::Orchard(data)
                                    ])
                                    .unwrap()
                                    .encode(&addr.net)
                                );
                            }
                            unified::Receiver::Sapling(data) => {
                                eprintln!(
                                    "   - Sapling ({})",
                                    ZcashAddress::from_sapling(addr.net, data)
                                );
                            }
                            unified::Receiver::P2pkh(data) => {
                                eprintln!(
                                    "   - Transparent P2PKH ({})",
                                    ZcashAddress::from_transparent_p2pkh(addr.net, data)
                                );
                            }
                            unified::Receiver::P2sh(data) => {
                                eprintln!(
                                    "   - Transparent P2SH ({})",
                                    ZcashAddress::from_transparent_p2sh(addr.net, data)
                                );
                            }
                            unified::Receiver::Unknown { typecode, data } => {
                                eprintln!("   - Unknown");
                                eprintln!("     - Typecode: {}", typecode);
                                eprintln!("     - Payload: {}", hex::encode(data));
                            }
                        }
                    }
                }
                AddressKind::P2pkh(data) => {
                    eprintln!(
                        " - Corresponding TEX: {}",
                        ZcashAddress::from_tex(addr.net, data),
                    );
                }
                AddressKind::Tex(data) => {
                    eprintln!(
                        " - Corresponding P2PKH: {}",
                        ZcashAddress::from_transparent_p2pkh(addr.net, data),
                    );
                }
                _ => (),
            }
        }
    }
}
