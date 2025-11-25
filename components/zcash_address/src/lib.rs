//! *Parser for all defined Zcash address types.*
//!
//! This crate implements address parsing as a two-phase process, built around the opaque
//! [`ZcashAddress`] type.
//!
//! - [`ZcashAddress`] can be parsed from, and encoded to, strings.
//! - [`ZcashAddress::convert`] or [`ZcashAddress::convert_if_network`] can be used to
//!   convert a parsed address into custom types that implement the [`TryFromAddress`] trait.
//! - Custom types can be converted into a [`ZcashAddress`] via its implementation of the
//!   [`ToAddress`] trait.
//!
//! ```text
//!         s.parse()              .convert()
//!         -------->              --------->
//! Strings           ZcashAddress            Custom types
//!         <--------              <---------
//!         .encode()              ToAddress
//! ```
//!
//! It is important to note that this crate does not depend on any of the Zcash protocol
//! crates (e.g. `sapling-crypto` or `orchard`). This crate has minimal dependencies by
//! design; it focuses solely on parsing, handling those concerns for you, while exposing
//! APIs that enable you to convert the parsed data into the Rust types you want to use.
//!
//! # Using this crate
//!
//! ## I just need to validate Zcash addresses
//!
//! ```
//! # use zcash_address::ZcashAddress;
//! fn is_valid_zcash_address(addr_string: &str) -> bool {
//!     addr_string.parse::<ZcashAddress>().is_ok()
//! }
//! ```
//!
//! ## I want to parse Zcash addresses in a Rust wallet app that uses the `zcash_primitives` transaction builder
//!
//! Use `zcash_client_backend::address::RecipientAddress`, which implements the traits in
//! this crate to parse address strings into protocol types that work with the transaction
//! builder in the `zcash_primitives` crate (as well as the wallet functionality in the
//! `zcash_client_backend` crate itself).
//!
//! > We intend to refactor the key and address types from the `zcash_client_backend` and
//! > `zcash_primitives` crates into a separate crate focused on dealing with Zcash key
//! > material. That crate will then be what you should use.
//!
//! ## I want to parse Unified Addresses
//!
//! See the [`unified::Address`] documentation for examples.
//!
//! While the [`unified::Address`] type does have parsing methods, you should still parse
//! your address strings with [`ZcashAddress`] and then convert; this will ensure that for
//! other Zcash address types you get a [`ConversionError::Unsupported`], which is a
//! better error for your users.
//!
//! ## I want to parse mainnet Zcash addresses in a language that supports C FFI
//!
//! As an example, you could use static functions to create the address types in the
//! target language from the parsed data.
//!
//! ```
//! use std::ffi::{CStr, c_char, c_void};
//! use std::ptr;
//!
//! use zcash_address::{ConversionError, TryFromAddress, ZcashAddress};
//! use zcash_protocol::consensus::NetworkType;
//!
//! // Functions that return a pointer to a heap-allocated address of the given kind in
//! // the target language. These should be augmented to return any relevant errors.
//! extern {
//!     fn addr_from_sapling(data: *const u8) -> *mut c_void;
//!     fn addr_from_transparent_p2pkh(data: *const u8) -> *mut c_void;
//! }
//!
//! struct ParsedAddress(*mut c_void);
//!
//! impl TryFromAddress for ParsedAddress {
//!     type Error = &'static str;
//!
//!     fn try_from_sapling(
//!         _net: NetworkType,
//!         data: [u8; 43],
//!     ) -> Result<Self, ConversionError<Self::Error>> {
//!         let parsed = unsafe { addr_from_sapling(data[..].as_ptr()) };
//!         if parsed.is_null() {
//!             Err("Reason for the failure".into())
//!         } else {
//!             Ok(Self(parsed))
//!         }
//!     }
//!
//!     fn try_from_transparent_p2pkh(
//!         _net: NetworkType,
//!         data: [u8; 20],
//!     ) -> Result<Self, ConversionError<Self::Error>> {
//!         let parsed = unsafe { addr_from_transparent_p2pkh(data[..].as_ptr()) };
//!         if parsed.is_null() {
//!             Err("Reason for the failure".into())
//!         } else {
//!             Ok(Self(parsed))
//!         }
//!     }
//! }
//!
//! pub extern "C" fn parse_zcash_address(encoded: *const c_char) -> *mut c_void {
//!     let encoded = unsafe { CStr::from_ptr(encoded) }.to_str().expect("valid");
//!
//!     let addr = match ZcashAddress::try_from_encoded(encoded) {
//!         Ok(addr) => addr,
//!         Err(e) => {
//!             // This was either an invalid address encoding, or not a Zcash address.
//!             // You should pass this error back across the FFI.
//!             return ptr::null_mut();
//!         }
//!     };
//!
//!     match addr.convert_if_network::<ParsedAddress>(NetworkType::Main) {
//!         Ok(parsed) => parsed.0,
//!         Err(e) => {
//!             // We didn't implement all of the methods of `TryFromAddress`, so if an
//!             // address with one of those kinds is parsed, it will result in an error
//!             // here that should be passed back across the FFI.
//!             ptr::null_mut()
//!         }
//!     }
//! }
//! ```

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::string::String;

mod convert;
mod encoding;
mod kind;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod test_vectors;

pub use convert::{ConversionError, Converter, ToAddress, TryFromAddress, UnsupportedAddress};
pub use encoding::ParseError;
pub use kind::unified;
use kind::unified::Receiver;

use zcash_protocol::{consensus::NetworkType, PoolType};

/// A Zcash address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ZcashAddress {
    net: NetworkType,
    kind: AddressKind,
}

/// Known kinds of Zcash addresses.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum AddressKind {
    Sprout([u8; 64]),
    Sapling([u8; 43]),
    Unified(unified::Address),
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
    Tex([u8; 20]),
}

impl ZcashAddress {
    /// Encodes this Zcash address in its canonical string representation.
    ///
    /// This provides the encoded string representation of the address as defined by the
    /// [Zcash protocol specification](https://zips.z.cash/protocol/protocol.pdf) and/or
    /// [ZIP 316](https://zips.z.cash/zip-0316). The [`Display` implementation] can also
    /// be used to produce this encoding using [`address.to_string()`].
    ///
    /// [`Display` implementation]: core::fmt::Display
    /// [`address.to_string()`]: alloc::string::ToString
    pub fn encode(&self) -> String {
        format!("{}", self)
    }

    /// Attempts to parse the given string as a Zcash address.
    ///
    /// This simply calls [`s.parse()`], leveraging the [`FromStr` implementation].
    ///
    /// [`s.parse()`]: str::parse
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
    /// let encoded = "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya";
    /// let addr = ZcashAddress::try_from_encoded(&encoded);
    /// assert_eq!(encoded.parse(), addr);
    /// ```
    pub fn try_from_encoded(s: &str) -> Result<Self, ParseError> {
        s.parse()
    }

    /// Converts this address into another type.
    ///
    /// `convert` can convert into any type that implements the [`TryFromAddress`] trait.
    /// This enables `ZcashAddress` to be used as a common parsing and serialization
    /// interface for Zcash addresses, while delegating operations on those addresses
    /// (such as constructing transactions) to downstream crates.
    ///
    /// If you want to get the encoded string for this address, use the [`encode`]
    /// method or the [`Display` implementation] via [`address.to_string()`] instead.
    ///
    /// [`encode`]: Self::encode
    /// [`Display` implementation]: core::fmt::Display
    /// [`address.to_string()`]: alloc::string::ToString
    pub fn convert<T: TryFromAddress>(self) -> Result<T, ConversionError<T::Error>> {
        match self.kind {
            AddressKind::Sprout(data) => T::try_from_sprout(self.net, data),
            AddressKind::Sapling(data) => T::try_from_sapling(self.net, data),
            AddressKind::Unified(data) => T::try_from_unified(self.net, data),
            AddressKind::P2pkh(data) => T::try_from_transparent_p2pkh(self.net, data),
            AddressKind::P2sh(data) => T::try_from_transparent_p2sh(self.net, data),
            AddressKind::Tex(data) => T::try_from_tex(self.net, data),
        }
    }

    /// Converts this address into another type, if it matches the expected network.
    ///
    /// `convert_if_network` can convert into any type that implements the [`TryFromAddress`]
    /// trait. This enables `ZcashAddress` to be used as a common parsing and serialization
    /// interface for Zcash addresses, while delegating operations on those addresses (such as
    /// constructing transactions) to downstream crates.
    ///
    /// If you want to get the encoded string for this address, use the [`encode`]
    /// method or the [`Display` implementation] via [`address.to_string()`] instead.
    ///
    /// [`encode`]: Self::encode
    /// [`Display` implementation]: core::fmt::Display
    /// [`address.to_string()`]: alloc::string::ToString
    pub fn convert_if_network<T: TryFromAddress>(
        self,
        net: NetworkType,
    ) -> Result<T, ConversionError<T::Error>> {
        let network_matches = self.net == net;
        // The Sprout and transparent address encodings use the same prefix for testnet
        // and regtest, so we need to allow parsing testnet addresses as regtest.
        let regtest_exception =
            network_matches || (self.net == NetworkType::Test && net == NetworkType::Regtest);

        match self.kind {
            AddressKind::Sprout(data) if regtest_exception => T::try_from_sprout(net, data),
            AddressKind::Sapling(data) if network_matches => T::try_from_sapling(net, data),
            AddressKind::Unified(data) if network_matches => T::try_from_unified(net, data),
            AddressKind::P2pkh(data) if regtest_exception => {
                T::try_from_transparent_p2pkh(net, data)
            }
            AddressKind::P2sh(data) if regtest_exception => T::try_from_transparent_p2sh(net, data),
            AddressKind::Tex(data) if network_matches => T::try_from_tex(net, data),
            _ => Err(ConversionError::IncorrectNetwork {
                expected: net,
                actual: self.net,
            }),
        }
    }

    /// Converts this address into another type using the specified converter.
    ///
    /// `convert` can convert into any type `T` for which an implementation of the [`Converter<T>`]
    /// trait exists. This enables conversion of [`ZcashAddress`] values into other types to rely
    /// on additional context.
    pub fn convert_with<T, C: Converter<T>>(
        self,
        converter: C,
    ) -> Result<T, ConversionError<C::Error>> {
        match self.kind {
            AddressKind::Sprout(data) => converter.convert_sprout(self.net, data),
            AddressKind::Sapling(data) => converter.convert_sapling(self.net, data),
            AddressKind::Unified(data) => converter.convert_unified(self.net, data),
            AddressKind::P2pkh(data) => converter.convert_transparent_p2pkh(self.net, data),
            AddressKind::P2sh(data) => converter.convert_transparent_p2sh(self.net, data),
            AddressKind::Tex(data) => converter.convert_tex(self.net, data),
        }
    }

    /// Returns whether this address has the ability to receive transfers of the given pool type.
    pub fn can_receive_as(&self, pool_type: PoolType) -> bool {
        use AddressKind::*;
        match &self.kind {
            Sprout(_) => false,
            Sapling(_) => pool_type == PoolType::SAPLING,
            Unified(addr) => addr.has_receiver_of_type(pool_type),
            P2pkh(_) | P2sh(_) | Tex(_) => pool_type == PoolType::TRANSPARENT,
        }
    }

    /// Returns whether this address can receive a memo.
    pub fn can_receive_memo(&self) -> bool {
        use AddressKind::*;
        match &self.kind {
            Sprout(_) | Sapling(_) => true,
            Unified(addr) => addr.can_receive_memo(),
            P2pkh(_) | P2sh(_) | Tex(_) => false,
        }
    }

    /// Returns whether or not this address contains or corresponds to the given unified address
    /// receiver.
    pub fn matches_receiver(&self, receiver: &Receiver) -> bool {
        match (&self.kind, receiver) {
            (AddressKind::Unified(ua), r) => ua.contains_receiver(r),
            (AddressKind::Sapling(d), Receiver::Sapling(r)) => r == d,
            (AddressKind::P2pkh(d), Receiver::P2pkh(r)) => r == d,
            (AddressKind::Tex(d), Receiver::P2pkh(r)) => r == d,
            (AddressKind::P2sh(d), Receiver::P2sh(r)) => r == d,
            _ => false,
        }
    }
}

#[cfg(feature = "test-dependencies")]
pub mod testing {
    use core::convert::TryInto;

    use proptest::{array::uniform20, collection::vec, prelude::any, prop_compose, prop_oneof};

    use crate::{unified::address::testing::arb_unified_address, AddressKind, ZcashAddress};
    use zcash_protocol::consensus::NetworkType;

    prop_compose! {
        fn arb_sprout_addr_kind()(
            r_bytes in vec(any::<u8>(), 64)
        ) -> AddressKind {
            AddressKind::Sprout(r_bytes.try_into().unwrap())
        }
    }

    prop_compose! {
        fn arb_sapling_addr_kind()(
            r_bytes in vec(any::<u8>(), 43)
        ) -> AddressKind {
            AddressKind::Sapling(r_bytes.try_into().unwrap())
        }
    }

    prop_compose! {
        fn arb_p2pkh_addr_kind()(
            r_bytes in uniform20(any::<u8>())
        ) -> AddressKind {
            AddressKind::P2pkh(r_bytes)
        }
    }

    prop_compose! {
        fn arb_p2sh_addr_kind()(
            r_bytes in uniform20(any::<u8>())
        ) -> AddressKind {
            AddressKind::P2sh(r_bytes)
        }
    }

    prop_compose! {
        fn arb_unified_addr_kind()(
            uaddr in arb_unified_address()
        ) -> AddressKind {
            AddressKind::Unified(uaddr)
        }
    }

    prop_compose! {
        fn arb_tex_addr_kind()(
            r_bytes in uniform20(any::<u8>())
        ) -> AddressKind {
            AddressKind::Tex(r_bytes)
        }
    }

    prop_compose! {
        /// Create an arbitrary, structurally-valid `ZcashAddress` value.
        ///
        /// Note that the data contained in the generated address does _not_ necessarily correspond
        /// to a valid address according to the Zcash protocol; binary data in the resulting value
        /// is entirely random.
        pub fn arb_address(net: NetworkType)(
            kind in prop_oneof!(
                arb_sprout_addr_kind(),
                arb_sapling_addr_kind(),
                arb_p2pkh_addr_kind(),
                arb_p2sh_addr_kind(),
                arb_unified_addr_kind(),
                arb_tex_addr_kind()
            )
        ) -> ZcashAddress {
            ZcashAddress { net, kind }
        }
    }
}
