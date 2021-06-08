//! Structs for handling supported address types.

use zcash_primitives::{consensus, legacy::TransparentAddress, sapling::PaymentAddress};

use crate::encoding::{
    decode_payment_address, decode_transparent_address, encode_payment_address,
    encode_transparent_address,
};

/// An address that funds can be sent to.
// TODO: rename to ParsedAddress
#[derive(Debug, PartialEq, Clone)]
pub enum RecipientAddress {
    Shielded(PaymentAddress),
    Transparent(TransparentAddress),
}

impl From<PaymentAddress> for RecipientAddress {
    fn from(addr: PaymentAddress) -> Self {
        RecipientAddress::Shielded(addr)
    }
}

impl From<TransparentAddress> for RecipientAddress {
    fn from(addr: TransparentAddress) -> Self {
        RecipientAddress::Transparent(addr)
    }
}

impl RecipientAddress {
    pub fn decode<P: consensus::Parameters>(params: &P, s: &str) -> Option<Self> {
        if let Ok(Some(pa)) = decode_payment_address(params.hrp_sapling_payment_address(), s) {
            Some(pa.into())
        } else if let Ok(Some(addr)) = decode_transparent_address(
            &params.b58_pubkey_address_prefix(),
            &params.b58_script_address_prefix(),
            s,
        ) {
            Some(addr.into())
        } else {
            None
        }
    }

    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        match self {
            RecipientAddress::Shielded(pa) => {
                encode_payment_address(params.hrp_sapling_payment_address(), pa)
            }
            RecipientAddress::Transparent(addr) => encode_transparent_address(
                &params.b58_pubkey_address_prefix(),
                &params.b58_script_address_prefix(),
                addr,
            ),
        }
    }
}
