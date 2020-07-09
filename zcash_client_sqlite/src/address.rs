//! Structs for handling supported address types.

use pairing::bls12_381::Bls12;
use zcash_client_backend::encoding::{
    decode_payment_address, decode_transparent_address, encode_payment_address,
    encode_transparent_address,
};
use zcash_primitives::{legacy::TransparentAddress, primitives::PaymentAddress};

#[cfg(feature = "mainnet")]
use zcash_client_backend::constants::mainnet::{
    B58_PUBKEY_ADDRESS_PREFIX, B58_SCRIPT_ADDRESS_PREFIX, HRP_SAPLING_PAYMENT_ADDRESS,
};

#[cfg(not(feature = "mainnet"))]
use zcash_client_backend::constants::testnet::{
    B58_PUBKEY_ADDRESS_PREFIX, B58_SCRIPT_ADDRESS_PREFIX, HRP_SAPLING_PAYMENT_ADDRESS,
};

/// An address that funds can be sent to.
pub enum RecipientAddress {
    Shielded(PaymentAddress<Bls12>),
    Transparent(TransparentAddress),
}

impl From<PaymentAddress<Bls12>> for RecipientAddress {
    fn from(addr: PaymentAddress<Bls12>) -> Self {
        RecipientAddress::Shielded(addr)
    }
}

impl From<TransparentAddress> for RecipientAddress {
    fn from(addr: TransparentAddress) -> Self {
        RecipientAddress::Transparent(addr)
    }
}

impl RecipientAddress {
    pub fn from_str(s: &str) -> Option<Self> {
        if let Ok(Some(pa)) = decode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, s) {
            Some(pa.into())
        } else if let Ok(Some(addr)) =
            decode_transparent_address(&B58_PUBKEY_ADDRESS_PREFIX, &B58_SCRIPT_ADDRESS_PREFIX, s)
        {
            Some(addr.into())
        } else {
            None
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            RecipientAddress::Shielded(pa) => {
                encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, pa)
            }
            RecipientAddress::Transparent(addr) => encode_transparent_address(
                &B58_PUBKEY_ADDRESS_PREFIX,
                &B58_SCRIPT_ADDRESS_PREFIX,
                addr,
            ),
        }
    }
}
