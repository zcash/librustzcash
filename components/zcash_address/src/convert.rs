use std::{error::Error, fmt};

use crate::{kind::*, AddressKind, Network, ZcashAddress};

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
    IncorrectNetwork { expected: Network, actual: Network },
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

impl Error for UnsupportedAddress {}
impl<E: Error + 'static> Error for ConversionError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConversionError::IncorrectNetwork { .. } | ConversionError::Unsupported(_) => None,
            ConversionError::User(e) => Some(e),
        }
    }
}

/// A helper trait for converting a [`ZcashAddress`] into a network-agnostic type.
///
/// A blanket implementation of [`TryFromAddress`] is provided for `(Network, T)` where
/// `T: TryFromRawAddress`.
///
/// [`ZcashAddress`]: crate::ZcashAddress
///
/// # Examples
///
/// ```
/// use zcash_address::{ConversionError, Network, TryFromRawAddress, UnsupportedAddress, ZcashAddress};
///
/// #[derive(Debug, PartialEq)]
/// struct MySapling([u8; 43]);
///
/// // Implement the TryFromRawAddress trait, overriding whichever conversion methods match
/// // your requirements for the resulting type.
/// impl TryFromRawAddress for MySapling {
///     // In this example we aren't checking the validity of the inner Sapling address,
///     // but your code should do so!
///     type Error = &'static str;
///
///     fn try_from_raw_sapling(data: [u8; 43]) -> Result<Self, ConversionError<Self::Error>> {
///         Ok(MySapling(data))
///     }
/// }
///
/// // For a supported address type, the conversion works.
/// let addr_string = "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpq6d8g";
///
/// // You can use `ZcashAddress::convert_if_network` to get your type directly.
/// let addr: ZcashAddress = addr_string.parse().unwrap();
/// let converted = addr.convert_if_network::<MySapling>(Network::Main);
/// assert!(converted.is_ok());
/// assert_eq!(converted.unwrap(), MySapling([0; 43]));
///
/// // Using `ZcashAddress::convert` gives us the tuple `(network, converted_addr)`.
/// let addr: ZcashAddress = addr_string.parse().unwrap();
/// let converted = addr.convert::<(_, MySapling)>();
/// assert!(converted.is_ok());
/// assert_eq!(converted.unwrap(), (Network::Main, MySapling([0; 43])));
///
/// // For an unsupported address type, we get an error.
/// let addr: ZcashAddress = "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs".parse().unwrap();
/// assert_eq!(
///     addr.convert::<(_, MySapling)>().unwrap_err().to_string(),
///     "Zcash transparent P2PKH addresses are not supported",
/// );
/// ```
pub trait TryFromRawAddress: Sized {
    /// Conversion errors for the user type (e.g. failing to parse the data passed to
    /// [`Self::try_from_raw_sapling`] as a valid Sapling address).
    type Error;

    fn try_from_raw_sprout(data: [u8; 64]) -> Result<Self, ConversionError<Self::Error>> {
        let _ = data;
        Err(ConversionError::Unsupported(UnsupportedAddress("Sprout")))
    }

    fn try_from_raw_sapling(data: [u8; 43]) -> Result<Self, ConversionError<Self::Error>> {
        let _ = data;
        Err(ConversionError::Unsupported(UnsupportedAddress("Sapling")))
    }

    fn try_from_raw_unified(data: unified::Address) -> Result<Self, ConversionError<Self::Error>> {
        let _ = data;
        Err(ConversionError::Unsupported(UnsupportedAddress("Unified")))
    }

    fn try_from_raw_transparent_p2pkh(
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = data;
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent P2PKH",
        )))
    }

    fn try_from_raw_transparent_p2sh(data: [u8; 20]) -> Result<Self, ConversionError<Self::Error>> {
        let _ = data;
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent P2SH",
        )))
    }

    fn try_from_raw_tex(data: [u8; 20]) -> Result<Self, ConversionError<Self::Error>> {
        let _ = data;
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent-source restricted P2PKH",
        )))
    }
}

/// A helper trait for converting a [`ZcashAddress`] into another type.
///
/// [`ZcashAddress`]: crate::ZcashAddress
///
/// # Examples
///
/// ```
/// use zcash_address::{ConversionError, Network, TryFromAddress, UnsupportedAddress, ZcashAddress};
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
///         net: Network,
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

    fn try_from_sprout(net: Network, data: [u8; 64]) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress("Sprout")))
    }

    fn try_from_sapling(
        net: Network,
        data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress("Sapling")))
    }

    fn try_from_unified(
        net: Network,
        data: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress("Unified")))
    }

    fn try_from_transparent_p2pkh(
        net: Network,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent P2PKH",
        )))
    }

    fn try_from_transparent_p2sh(
        net: Network,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent P2SH",
        )))
    }

    fn try_from_tex(net: Network, data: [u8; 20]) -> Result<Self, ConversionError<Self::Error>> {
        let _ = (net, data);
        Err(ConversionError::Unsupported(UnsupportedAddress(
            "transparent-source restricted P2PKH",
        )))
    }
}

impl<T: TryFromRawAddress> TryFromAddress for (Network, T) {
    type Error = T::Error;

    fn try_from_sprout(net: Network, data: [u8; 64]) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_raw_sprout(data).map(|addr| (net, addr))
    }

    fn try_from_sapling(
        net: Network,
        data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_raw_sapling(data).map(|addr| (net, addr))
    }

    fn try_from_unified(
        net: Network,
        data: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_raw_unified(data).map(|addr| (net, addr))
    }

    fn try_from_transparent_p2pkh(
        net: Network,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_raw_transparent_p2pkh(data).map(|addr| (net, addr))
    }

    fn try_from_transparent_p2sh(
        net: Network,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_raw_transparent_p2sh(data).map(|addr| (net, addr))
    }

    fn try_from_tex(net: Network, data: [u8; 20]) -> Result<Self, ConversionError<Self::Error>> {
        T::try_from_raw_tex(data).map(|addr| (net, addr))
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
/// use zcash_address::{ToAddress, Network, ZcashAddress};
///
/// #[derive(Debug)]
/// struct MySapling([u8; 43]);
///
/// impl MySapling {
///     /// Encodes this Sapling address for the given network.
///     fn encode(&self, net: Network) -> ZcashAddress {
///         ZcashAddress::from_sapling(net, self.0)
///     }
/// }
///
/// let addr = MySapling([0; 43]);
/// let encoded = addr.encode(Network::Main);
/// assert_eq!(
///     encoded.to_string(),
///     "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpq6d8g",
/// );
/// ```
pub trait ToAddress: private::Sealed {
    fn from_sprout(net: Network, data: [u8; 64]) -> Self;

    fn from_sapling(net: Network, data: [u8; 43]) -> Self;

    fn from_unified(net: Network, data: unified::Address) -> Self;

    fn from_transparent_p2pkh(net: Network, data: [u8; 20]) -> Self;

    fn from_transparent_p2sh(net: Network, data: [u8; 20]) -> Self;

    fn from_tex(net: Network, data: [u8; 20]) -> Self;
}

impl ToAddress for ZcashAddress {
    fn from_sprout(net: Network, data: [u8; 64]) -> Self {
        ZcashAddress {
            net: if let Network::Regtest = net {
                Network::Test
            } else {
                net
            },
            kind: AddressKind::Sprout(data),
        }
    }

    fn from_sapling(net: Network, data: [u8; 43]) -> Self {
        ZcashAddress {
            net,
            kind: AddressKind::Sapling(data),
        }
    }

    fn from_unified(net: Network, data: unified::Address) -> Self {
        ZcashAddress {
            net,
            kind: AddressKind::Unified(data),
        }
    }

    fn from_transparent_p2pkh(net: Network, data: [u8; 20]) -> Self {
        ZcashAddress {
            net: if let Network::Regtest = net {
                Network::Test
            } else {
                net
            },
            kind: AddressKind::P2pkh(data),
        }
    }

    fn from_transparent_p2sh(net: Network, data: [u8; 20]) -> Self {
        ZcashAddress {
            net: if let Network::Regtest = net {
                Network::Test
            } else {
                net
            },
            kind: AddressKind::P2sh(data),
        }
    }

    fn from_tex(net: Network, data: [u8; 20]) -> Self {
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
