//! Functions and types related to encoding and decoding wallet data for storage in the wallet
//! database.

use bitflags::bitflags;
use transparent::address::TransparentAddress::*;
use zcash_address::{
    unified::{Container, Receiver},
    ConversionError, TryFromAddress,
};
use zcash_keys::{
    address::{Address, UnifiedAddress},
    keys::{ReceiverRequirement, UnifiedAddressRequest},
};
use zcash_protocol::consensus::NetworkType;

bitflags! {
    /// A set of flags describing the type(s) of outputs that a Zcash address can receive.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct ReceiverFlags: i64 {
        /// The address did not contain any recognized receiver types.
        const UNKNOWN = 0b00000000;
        /// The associated address can receive transparent p2pkh outputs.
        const P2PKH = 0b00000001;
        /// The associated address can receive transparent p2sh outputs.
        const P2SH = 0b00000010;
        /// The associated address can receive Sapling outputs.
        const SAPLING = 0b00000100;
        /// The associated address can receive Orchard outputs.
        const ORCHARD = 0b00001000;
    }
}

impl ReceiverFlags {
    pub(crate) fn required(request: UnifiedAddressRequest) -> Self {
        let mut flags = ReceiverFlags::UNKNOWN;
        if matches!(request.orchard(), ReceiverRequirement::Require) {
            flags |= ReceiverFlags::ORCHARD;
        }
        if matches!(request.sapling(), ReceiverRequirement::Require) {
            flags |= ReceiverFlags::SAPLING;
        }
        if matches!(request.p2pkh(), ReceiverRequirement::Require) {
            flags |= ReceiverFlags::P2PKH;
        }
        flags
    }

    pub(crate) fn omitted(request: UnifiedAddressRequest) -> Self {
        let mut flags = ReceiverFlags::UNKNOWN;
        if matches!(request.orchard(), ReceiverRequirement::Omit) {
            flags |= ReceiverFlags::ORCHARD;
        }
        if matches!(request.sapling(), ReceiverRequirement::Omit) {
            flags |= ReceiverFlags::SAPLING;
        }
        if matches!(request.p2pkh(), ReceiverRequirement::Omit) {
            flags |= ReceiverFlags::P2PKH;
        }
        flags
    }
}

/// Computes the [`ReceiverFlags`] describing the types of outputs that the provided
/// [`UnifiedAddress`] can receive.
impl From<&UnifiedAddress> for ReceiverFlags {
    fn from(value: &UnifiedAddress) -> Self {
        let mut flags = ReceiverFlags::UNKNOWN;
        match value.transparent() {
            Some(PublicKeyHash(_)) => {
                flags |= ReceiverFlags::P2PKH;
            }
            Some(ScriptHash(_)) => {
                flags |= ReceiverFlags::P2SH;
            }
            _ => {}
        }
        if value.has_sapling() {
            flags |= ReceiverFlags::SAPLING;
        }
        if value.has_orchard() {
            flags |= ReceiverFlags::ORCHARD;
        }
        flags
    }
}

/// Computes the [`ReceiverFlags`] describing the types of outputs that the provided
/// [`Address`] can receive.
impl From<&Address> for ReceiverFlags {
    fn from(address: &Address) -> Self {
        match address {
            Address::Sapling(_) => ReceiverFlags::SAPLING,
            Address::Transparent(addr) => match addr {
                PublicKeyHash(_) => ReceiverFlags::P2PKH,
                ScriptHash(_) => ReceiverFlags::P2SH,
            },
            Address::Unified(ua) => ReceiverFlags::from(ua),
            Address::Tex(_) => ReceiverFlags::P2PKH,
        }
    }
}

impl TryFromAddress for ReceiverFlags {
    type Error = ();

    fn try_from_sapling(
        _net: NetworkType,
        _data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(ReceiverFlags::SAPLING)
    }

    fn try_from_unified(
        _net: NetworkType,
        data: zcash_address::unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        let mut result = ReceiverFlags::UNKNOWN;
        for i in data.items() {
            match i {
                Receiver::Orchard(_) => result |= ReceiverFlags::ORCHARD,
                Receiver::Sapling(_) => result |= ReceiverFlags::SAPLING,
                Receiver::P2pkh(_) => result |= ReceiverFlags::P2PKH,
                Receiver::P2sh(_) => result |= ReceiverFlags::P2SH,
                Receiver::Unknown { .. } => {}
            }
        }

        Ok(result)
    }

    fn try_from_transparent_p2pkh(
        _net: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(ReceiverFlags::P2PKH)
    }

    fn try_from_transparent_p2sh(
        _net: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(ReceiverFlags::P2SH)
    }

    fn try_from_tex(
        _net: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(ReceiverFlags::P2PKH)
    }
}
