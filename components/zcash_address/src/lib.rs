mod convert;
mod encoding;
mod kind;

#[cfg(test)]
mod test_vectors;

pub use convert::{FromAddress, ToAddress, UnsupportedAddress};
pub use encoding::ParseError;
pub use kind::unified;

/// A Zcash address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ZcashAddress {
    net: Network,
    kind: AddressKind,
}

/// The Zcash network for which an address is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum AddressKind {
    Sprout(kind::sprout::Data),
    Sapling(kind::sapling::Data),
    Unified(unified::Address),
    P2pkh(kind::p2pkh::Data),
    P2sh(kind::p2sh::Data),
}

impl ZcashAddress {
    /// Encodes this Zcash address in its canonical string representation.
    ///
    /// This provides the encoded string representation of the address as defined by the
    /// [Zcash protocol specification](https://zips.z.cash/protocol.pdf) and/or
    /// [ZIP 316](https://zips.z.cash/zip-0316). The [`Display` implementation] can also
    /// be used to produce this encoding using [`address.to_string()`].
    ///
    /// [`Display` implementation]: std::fmt::Display
    /// [`address.to_string()`]: std::string::ToString
    pub fn encode(&self) -> String {
        format!("{}", self)
    }

    /// Attempts to parse the given string as a Zcash address.
    ///
    /// This simply calls [`s.parse()`], leveraging the [`FromStr` implementation].
    ///
    /// [`s.parse()`]: std::primitive::str::parse
    /// [`FromStr` implementation]: ZcashAddress#impl-FromStr
    ///
    /// # Errors
    ///
    /// - If the parser can detect that the string _must_ contain an address encoding used
    ///   by Zcash, [`ParseError::InvalidEncoding`] will be returned if any subsequent
    ///   part of that encoding is invalid.
    ///
    /// - In all other cases, [`ParseError::NotZcash`] will be returned on failure.
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

    /// Converts this address into another type.
    ///
    /// `convert` can convert into any type that implements the [`FromAddress`] trait.
    /// This enables `ZcashAddress` to be used as a common parsing and serialization
    /// interface for Zcash addresses, while delegating operations on those addresses
    /// (such as constructing transactions) to downstream crates.
    ///
    /// If you want to get the encoded string for this address, use the [`encode`]
    /// method or the [`Display` implementation] via [`address.to_string()`] instead.
    ///
    /// [`encode`]: Self::encode
    /// [`Display` implementation]: std::fmt::Display
    /// [`address.to_string()`]: std::string::ToString
    pub fn convert<T: FromAddress>(self) -> Result<T, UnsupportedAddress> {
        match self.kind {
            AddressKind::Sprout(data) => T::from_sprout(self.net, data),
            AddressKind::Sapling(data) => T::from_sapling(self.net, data),
            AddressKind::Unified(data) => T::from_unified(self.net, data),
            AddressKind::P2pkh(data) => T::from_transparent_p2pkh(self.net, data),
            AddressKind::P2sh(data) => T::from_transparent_p2sh(self.net, data),
        }
    }
}
