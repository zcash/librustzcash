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

impl ZcashAddress {
    /// Attempts to parse the given string as a Zcash address.
    ///
    /// This simply calls [`s.parse()`], leveraging the [`FromStr` implementation].
    ///
    /// [`s.parse()`]: std::primitive::str::parse
    /// [`FromStr` implementation]: ZcashAddress#impl-FromStr
    ///
    /// # Errors
    ///
    /// In most cases, [`ParseError::NotZcash`] will be returned on failure. The two
    /// exceptions are:
    ///
    /// - If the parser can detect that the string _must_ contain an address encoding used
    ///   by Zcash, [`ParseError::InvalidEncoding`] will be returned if any subsequent
    ///   part of that encoding is invalid.
    ///
    /// - [`ParseError::MaybeZcash`] will be returned if the string is Bech32-encoded data
    ///   that satisfies some heuristics for probable future Zcash address formats (such
    ///   as beginning with a `z`). This can either be treated as an indication that this
    ///   library dependency should be updated, or mapped to [`ParseError::NotZcash`].
    ///
    /// # Examples
    ///
    /// ```
    /// use zcash_address::ZcashAddress;
    ///
    /// let encoded = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly";
    /// let addr = ZcashAddress::try_from_encoded(&encoded);
    /// assert_eq!(encoded.parse(), addr);
    /// ```
    pub fn try_from_encoded(s: &str) -> Result<Self, ParseError> {
        s.parse()
    }

    pub fn convert<T: FromAddress>(self) -> Result<T, UnsupportedAddress> {
        match self.kind {
            AddressKind::Sprout(data) => T::from_sprout(self.net, data),
            AddressKind::Sapling(data) => T::from_sapling(self.net, data),
            AddressKind::Orchard(data) => T::from_orchard(self.net, data),
            AddressKind::P2pkh(data) => T::from_transparent_p2pkh(self.net, data),
            AddressKind::P2sh(data) => T::from_transparent_p2sh(self.net, data),
        }
    }
}
