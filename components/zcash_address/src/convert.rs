use std::{error::Error, fmt};

use crate::{kind::*, AddressKind, Network, ZcashAddress};

/// An address type is not supported for conversion.
#[derive(Debug)]
pub struct UnsupportedAddress(&'static str);

impl fmt::Display for UnsupportedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Zcash {} addresses are not supported", self.0)
    }
}

impl Error for UnsupportedAddress {}

impl ZcashAddress {
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

/// A helper trait for converting a [`ZcashAddress`] into another type.
///
/// # Examples
///
/// ```
/// use zcash_address::{FromAddress, Network, UnsupportedAddress, ZcashAddress};
///
/// #[derive(Debug)]
/// struct MySapling([u8; 43]);
///
/// // Implement the FromAddress trait, overriding whichever conversion methods match your
/// // requirements for the resulting type.
/// impl FromAddress for MySapling {
///     fn from_sapling(net: Network, data: [u8; 43]) -> Result<Self, UnsupportedAddress> {
///         Ok(MySapling(data))
///     }
/// }
///
/// // For a supported address type, the conversion works.
/// let addr: ZcashAddress =
///     "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpq6d8g"
///         .parse()
///         .unwrap();
/// assert!(addr.convert::<MySapling>().is_ok());
///
/// // For an unsupported address type, we get an error.
/// let addr: ZcashAddress = "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs".parse().unwrap();
/// assert_eq!(
///     addr.convert::<MySapling>().unwrap_err().to_string(),
///     "Zcash transparent P2PKH addresses are not supported",
/// );
/// ```
pub trait FromAddress: Sized {
    fn from_sprout(net: Network, data: sprout::Data) -> Result<Self, UnsupportedAddress> {
        let _ = (net, data);
        Err(UnsupportedAddress("Sprout"))
    }

    fn from_sapling(net: Network, data: sapling::Data) -> Result<Self, UnsupportedAddress> {
        let _ = (net, data);
        Err(UnsupportedAddress("Sapling"))
    }

    fn from_orchard(net: Network, data: orchard::Data) -> Result<Self, UnsupportedAddress> {
        let _ = (net, data);
        Err(UnsupportedAddress("Orchard"))
    }

    fn from_transparent_p2pkh(net: Network, data: p2pkh::Data) -> Result<Self, UnsupportedAddress> {
        let _ = (net, data);
        Err(UnsupportedAddress("transparent P2PKH"))
    }

    fn from_transparent_p2sh(net: Network, data: p2sh::Data) -> Result<Self, UnsupportedAddress> {
        let _ = (net, data);
        Err(UnsupportedAddress("transparent P2SH"))
    }
}
