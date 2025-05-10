use core::fmt;

#[cfg(feature = "std")]
use std::error::Error;

use zcash_protocol::consensus::NetworkType;

use crate::{kind::*, AddressKind, ZcashAddress};

/// An error indicating that an address type is not supported for conversion.
#[derive(Debug)]
pub struct UnsupportedAddress(&'static str);

impl fmt::Display for UnsupportedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Zcash {} addresses are not supported", self.0)
    }
}

/// An error encountered while converting a parsed [`ZcashAddress`] into another type.
#[derive(Debug)]
pub enum ConversionError<E> {
    /// The address is for the wrong network.
    IncorrectNetwork {
        expected: NetworkType,
        actual: NetworkType,
    },
    /// The address type is not supported by the target type.
    Unsupported(UnsupportedAddress),
    /// A conversion error returned by the target type.
    User(E),
}

impl<E> From<E> for ConversionError<E> {
    fn from(e: E) -> Self {
        ConversionError::User(e)
    }
}

impl<E: fmt::Display> fmt::Display for ConversionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncorrectNetwork { expected, actual } => write!(
                f,
                "Address is for {:?} but we expected {:?}",
                actual, expected,
            ),
            Self::Unsupported(e) => e.fmt(f),
            Self::User(e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl Error for UnsupportedAddress {}
#[cfg(feature = "std")]
impl<E: Error + 'static> Error for ConversionError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConversionError::IncorrectNetwork { .. } | ConversionError::Unsupported(_) => None,
            ConversionError::User(e) => Some(e),
        }
    }
}

/// A helper trait for converting a [`ZcashAddress`] into another type.
///
/// [`ZcashAddress`]: crate::ZcashAddress
///
/// # Examples
///
/// ```
/// use zcash_address::{ConversionError, TryFromAddress, UnsupportedAddress, ZcashAddress};
/// use zcash_protocol::consensus::NetworkType;
///
/// #[derive(Debug)]
/// struct MySapling([u8; 43]);
///
/// // Implement the TryFromAddress trait, overriding whichever conversion methods match your
/// // requirements for the resulting type.
/// impl TryFromAddress for MySapling {
///     // In this example we aren't checking the validity of the inner Sapling address,
///     // but your code should do so!
///     type Error = &'static str;
///
///     fn try_from_sapling(
///         net: NetworkType,
///         data: [u8; 43],
///     ) -> Result<Self, ConversionError<Self::Error>> {
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
pub trait TryFromAddress: Sized {
    /// Conversion errors for the user type (e.g. failing to parse the data passed to
    /// [`Self::try_from_sapling`] as a valid Sapling address).
    type Error;

    fn try_from_sprout(
        net: NetworkType,
        data: [u8; 64],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress("Sprout")))
    }

    fn try_from_sapling(
        net: NetworkType,
        data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress("Sapling")))
    }

    fn try_from_unified(
        net: NetworkType,
        data: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress("Unified")))
    }

    fn try_from_transparent_p2pkh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent P2PKH",
        )))
    }

    fn try_from_transparent_p2sh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent P2SH",
        )))
    }

    fn try_from_tex(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent-source restricted P2PKH",
        )))
    }
}

impl<T: TryFromAddress> TryFromAddress for (NetworkType, T) {
    type Error = T::Error;

    fn try_from_sprout(
        net: NetworkType,
        data: [u8; 64],
    ) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_sprout(net, data).map(|addr| (net, addr))
    }

    fn try_from_sapling(
        net: NetworkType,
        data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_sapling(net, data).map(|addr| (net, addr))
    }

    fn try_from_unified(
        net: NetworkType,
        data: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_unified(net, data).map(|addr| (net, addr))
    }

    fn try_from_transparent_p2pkh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_transparent_p2pkh(net, data).map(|addr| (net, addr))
    }

    fn try_from_transparent_p2sh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_transparent_p2sh(net, data).map(|addr| (net, addr))
    }

    fn try_from_tex(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_tex(net, data).map(|addr| (net, addr))
    }
}

/// A trait for converter types that can project from a [`ZcashAddress`] into another type.
///
/// [`ZcashAddress`]: crate::ZcashAddress
///
/// # Examples
///
/// ```
/// use zcash_address::{ConversionError, Converter, UnsupportedAddress, ZcashAddress};
/// use zcash_protocol::consensus::NetworkType;
///
/// struct KeyFinder { }
///
/// impl KeyFinder {
///     fn find_sapling_extfvk(&self, data: [u8; 43]) -> Option<[u8; 73]> {
///         todo!()
///     }
/// }
///
/// // Makes it possible to use a KeyFinder to find the Sapling extfvk that corresponds
/// // to a given ZcashAddress.
/// impl Converter<Option<[u8; 73]>> for KeyFinder {
///     type Error = &'static str;
///
///     fn convert_sapling(
///         &self,
///         net: NetworkType,
///         data: [u8; 43],
///     ) -> Result<Option<[u8; 73]>, ConversionError<Self::Error>> {
///         Ok(self.find_sapling_extfvk(data))
///     }
/// }
/// ```
pub trait Converter<T> {
    /// Conversion errors for the user type (e.g. failing to parse the data passed to
    /// [`Self::convert_sapling`] as a valid Sapling address).
    type Error;

    fn convert_sprout(
        &self,
        net: NetworkType,
        data: [u8; 64],
    ) -> Result<T, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress("Sprout")))
    }

    fn convert_sapling(
        &self,
        net: NetworkType,
        data: [u8; 43],
    ) -> Result<T, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress("Sapling")))
    }

    fn convert_unified(
        &self,
        net: NetworkType,
        data: unified::Address,
    ) -> Result<T, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress("Unified")))
    }

    fn convert_transparent_p2pkh(
        &self,
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<T, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent P2PKH",
        )))
    }

    fn convert_transparent_p2sh(
        &self,
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<T, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent P2SH",
        )))
    }

    fn convert_tex(
        &self,
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<T, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent-source restricted P2PKH",
        )))
    }
}

/// A helper trait for converting another type into a [`ZcashAddress`].
///
/// This trait is sealed and cannot be implemented for types outside this crate. Its
/// purpose is to move these conversion functions out of the main `ZcashAddress` API
/// documentation, as they are only required when creating addresses (rather than when
/// parsing addresses, which is a more common occurrence).
///
/// [`ZcashAddress`]: crate::ZcashAddress
///
/// # Examples
///
/// ```
/// use zcash_address::{ToAddress, ZcashAddress};
/// use zcash_protocol::consensus::NetworkType;
///
/// #[derive(Debug)]
/// struct MySapling([u8; 43]);
///
/// impl MySapling {
///     /// Encodes this Sapling address for the given network.
///     fn encode(&self, net: NetworkType) -> ZcashAddress {
///         ZcashAddress::from_sapling(net, self.0)
///     }
/// }
///
/// let addr = MySapling([0; 43]);
/// let encoded = addr.encode(NetworkType::Main);
/// assert_eq!(
///     encoded.to_string(),
///     "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpq6d8g",
/// );
/// ```
pub trait ToAddress: private::Sealed {
    fn from_sprout(net: NetworkType, data: [u8; 64]) -> Self;

    fn from_sapling(net: NetworkType, data: [u8; 43]) -> Self;

    fn from_unified(net: NetworkType, data: unified::Address) -> Self;

    fn from_transparent_p2pkh(net: NetworkType, data: [u8; 20]) -> Self;

    fn from_transparent_p2sh(net: NetworkType, data: [u8; 20]) -> Self;

    fn from_tex(net: NetworkType, data: [u8; 20]) -> Self;
}

impl ToAddress for ZcashAddress {
    fn from_sprout(net: NetworkType, data: [u8; 64]) -> Self {
        ZcashAddress {
            net: if let NetworkType::Regtest = net {
                NetworkType::Test
            } else {
                net
            },
            kind: AddressKind::Sprout(data),
        }
    }

    fn from_sapling(net: NetworkType, data: [u8; 43]) -> Self {
        ZcashAddress {
            net,
            kind: AddressKind::Sapling(data),
        }
    }

    fn from_unified(net: NetworkType, data: unified::Address) -> Self {
        ZcashAddress {
            net,
            kind: AddressKind::Unified(data),
        }
    }

    fn from_transparent_p2pkh(net: NetworkType, data: [u8; 20]) -> Self {
        ZcashAddress {
            net: if let NetworkType::Regtest = net {
                NetworkType::Test
            } else {
                net
            },
            kind: AddressKind::P2pkh(data),
        }
    }

    fn from_transparent_p2sh(net: NetworkType, data: [u8; 20]) -> Self {
        ZcashAddress {
            net: if let NetworkType::Regtest = net {
                NetworkType::Test
            } else {
                net
            },
            kind: AddressKind::P2sh(data),
        }
    }

    fn from_tex(net: NetworkType, data: [u8; 20]) -> Self {
        ZcashAddress {
            net,
            kind: AddressKind::Tex(data),
        }
    }
}

mod private {
    use crate::ZcashAddress;

    pub trait Sealed {}
    impl Sealed for ZcashAddress {}
}
