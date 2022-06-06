//! Structs for handling supported address types.

use zcash_address::{ConversionError, Network, ToAddress, TryFromRawAddress, ZcashAddress};
use zcash_primitives::{consensus, constants, legacy::TransparentAddress, sapling::PaymentAddress};

fn params_to_network<P: consensus::Parameters>(params: &P) -> Network {
    // Use the Sapling HRP as an indicator of network.
    match params.hrp_sapling_payment_address() {
        constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS => Network::Main,
        constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS => Network::Test,
        constants::regtest::HRP_SAPLING_PAYMENT_ADDRESS => Network::Regtest,
        _ => panic!("Unsupported network kind"),
    }
}

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

impl TryFromRawAddress for RecipientAddress {
    type Error = &'static str;

    fn try_from_raw_sapling(data: [u8; 43]) -> Result<Self, ConversionError<Self::Error>> {
        let pa = PaymentAddress::from_bytes(&data).ok_or("Invalid Sapling payment address")?;
        Ok(pa.into())
    }

    fn try_from_raw_transparent_p2pkh(
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(TransparentAddress::PublicKey(data).into())
    }

    fn try_from_raw_transparent_p2sh(data: [u8; 20]) -> Result<Self, ConversionError<Self::Error>> {
        Ok(TransparentAddress::Script(data).into())
    }
}

impl RecipientAddress {
    pub fn decode<P: consensus::Parameters>(params: &P, s: &str) -> Option<Self> {
        let addr = ZcashAddress::try_from_encoded(s).ok()?;
        addr.convert_if_network(params_to_network(params)).ok()
    }

    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        let net = params_to_network(params);

        match self {
            RecipientAddress::Shielded(pa) => ZcashAddress::from_sapling(net, pa.to_bytes()),
            RecipientAddress::Transparent(addr) => match addr {
                TransparentAddress::PublicKey(data) => {
                    ZcashAddress::from_transparent_p2pkh(net, *data)
                }
                TransparentAddress::Script(data) => ZcashAddress::from_transparent_p2sh(net, *data),
            },
        }
        .to_string()
    }
}
