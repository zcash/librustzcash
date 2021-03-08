mod convert;
mod encoding;
mod kind;

pub use convert::{FromAddress, UnsupportedAddress};
pub use encoding::ParseError;

/// A Zcash address.
#[derive(Debug, PartialEq)]
pub struct ZcashAddress {
    net: Network,
    kind: AddressKind,
}

/// The Zcash network for which an address is encoded.
#[derive(Debug, PartialEq)]
pub enum Network {
    /// Zcash Mainnet.
    Main,
    /// Zcash Testnet.
    Test,
    /// Private integration / regression testing, used in `zcashd`.
    ///
    /// For some address types there is no distinction between test and regtest encodings;
    /// those will always be parsed as `Network::Test`.
    Regtest,
}

/// Known kinds of Zcash addresses.
#[derive(Debug, PartialEq)]
enum AddressKind {
    Sprout(kind::sprout::Data),
    Sapling(kind::sapling::Data),
    Orchard(kind::orchard::Data),
    P2pkh(kind::p2pkh::Data),
    P2sh(kind::p2sh::Data),
}
