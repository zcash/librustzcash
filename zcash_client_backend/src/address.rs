//! Structs for handling supported address types.

use std::convert::TryFrom;

use zcash_address::{
    unified::{self, Container, Encoding},
    ConversionError, Network, ToAddress, TryFromRawAddress, ZcashAddress,
};
use zcash_primitives::{
    consensus,
    legacy::TransparentAddress,
    sapling::PaymentAddress,
    zip32::{AccountId, DiversifierIndex},
};

pub struct AddressMetadata {
    account: AccountId,
    diversifier_index: DiversifierIndex,
}

impl AddressMetadata {
    pub fn new(account: AccountId, diversifier_index: DiversifierIndex) -> Self {
        Self {
            account,
            diversifier_index,
        }
    }

    pub fn account(&self) -> AccountId {
        self.account
    }

    pub fn diversifier_index(&self) -> &DiversifierIndex {
        &self.diversifier_index
    }
}

/// A Unified Address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiedAddress {
    orchard: Option<orchard::Address>,
    sapling: Option<PaymentAddress>,
    transparent: Option<TransparentAddress>,
    unknown: Vec<(u32, Vec<u8>)>,
}

impl TryFrom<unified::Address> for UnifiedAddress {
    type Error = &'static str;

    fn try_from(ua: unified::Address) -> Result<Self, Self::Error> {
        let mut orchard = None;
        let mut sapling = None;
        let mut transparent = None;

        // We can use as-parsed order here for efficiency, because we're breaking out the
        // receivers we support from the unknown receivers.
        let unknown = ua
            .items_as_parsed()
            .iter()
            .filter_map(|receiver| match receiver {
                unified::Receiver::Orchard(data) => {
                    Option::from(orchard::Address::from_raw_address_bytes(data))
                        .ok_or("Invalid Orchard receiver in Unified Address")
                        .map(|addr| {
                            orchard = Some(addr);
                            None
                        })
                        .transpose()
                }
                unified::Receiver::Sapling(data) => PaymentAddress::from_bytes(data)
                    .ok_or("Invalid Sapling receiver in Unified Address")
                    .map(|pa| {
                        sapling = Some(pa);
                        None
                    })
                    .transpose(),
                unified::Receiver::P2pkh(data) => {
                    transparent = Some(TransparentAddress::PublicKey(*data));
                    None
                }
                unified::Receiver::P2sh(data) => {
                    transparent = Some(TransparentAddress::Script(*data));
                    None
                }
                unified::Receiver::Unknown { typecode, data } => {
                    Some(Ok((*typecode, data.clone())))
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            orchard,
            sapling,
            transparent,
            unknown,
        })
    }
}

impl UnifiedAddress {
    /// Constructs a Unified Address from a given set of receivers.
    ///
    /// Returns `None` if the receivers would produce an invalid Unified Address (namely,
    /// if no shielded receiver is provided).
    pub fn from_receivers(
        orchard: Option<orchard::Address>,
        sapling: Option<PaymentAddress>,
        transparent: Option<TransparentAddress>,
    ) -> Option<Self> {
        if orchard.is_some() || sapling.is_some() {
            Some(Self {
                orchard,
                sapling,
                transparent,
                unknown: vec![],
            })
        } else {
            // UAs require at least one shielded receiver.
            None
        }
    }

    /// Returns the Orchard receiver within this Unified Address, if any.
    pub fn orchard(&self) -> Option<&orchard::Address> {
        self.orchard.as_ref()
    }

    /// Returns the Sapling receiver within this Unified Address, if any.
    pub fn sapling(&self) -> Option<&PaymentAddress> {
        self.sapling.as_ref()
    }

    /// Returns the transparent receiver within this Unified Address, if any.
    pub fn transparent(&self) -> Option<&TransparentAddress> {
        self.transparent.as_ref()
    }

    fn to_address(&self, net: Network) -> ZcashAddress {
        let ua = unified::Address::try_from_items(
            self.unknown
                .iter()
                .map(|(typecode, data)| unified::Receiver::Unknown {
                    typecode: *typecode,
                    data: data.clone(),
                })
                .chain(self.transparent.as_ref().map(|taddr| match taddr {
                    TransparentAddress::PublicKey(data) => unified::Receiver::P2pkh(*data),
                    TransparentAddress::Script(data) => unified::Receiver::P2sh(*data),
                }))
                .chain(
                    self.sapling
                        .as_ref()
                        .map(|pa| pa.to_bytes())
                        .map(unified::Receiver::Sapling),
                )
                .chain(
                    self.orchard
                        .as_ref()
                        .map(|addr| addr.to_raw_address_bytes())
                        .map(unified::Receiver::Orchard),
                )
                .collect(),
        )
        .expect("UnifiedAddress should only be constructed safely");
        ZcashAddress::from_unified(net, ua)
    }

    /// Returns the string encoding of this `UnifiedAddress` for the given network.
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        self.to_address(params.address_network().expect("Unrecognized network"))
            .to_string()
    }
}

/// An address that funds can be sent to.
// TODO: rename to ParsedAddress
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RecipientAddress {
    Shielded(PaymentAddress),
    Transparent(TransparentAddress),
    Unified(UnifiedAddress),
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

impl From<UnifiedAddress> for RecipientAddress {
    fn from(addr: UnifiedAddress) -> Self {
        RecipientAddress::Unified(addr)
    }
}

impl TryFromRawAddress for RecipientAddress {
    type Error = &'static str;

    fn try_from_raw_sapling(data: [u8; 43]) -> Result<Self, ConversionError<Self::Error>> {
        let pa = PaymentAddress::from_bytes(&data).ok_or("Invalid Sapling payment address")?;
        Ok(pa.into())
    }

    fn try_from_raw_unified(
        ua: zcash_address::unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        UnifiedAddress::try_from(ua)
            .map_err(ConversionError::User)
            .map(RecipientAddress::from)
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
        addr.convert_if_network(params.address_network().expect("Unrecognized network"))
            .ok()
    }

    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        let net = params.address_network().expect("Unrecognized network");

        match self {
            RecipientAddress::Shielded(pa) => ZcashAddress::from_sapling(net, pa.to_bytes()),
            RecipientAddress::Transparent(addr) => match addr {
                TransparentAddress::PublicKey(data) => {
                    ZcashAddress::from_transparent_p2pkh(net, *data)
                }
                TransparentAddress::Script(data) => ZcashAddress::from_transparent_p2sh(net, *data),
            },
            RecipientAddress::Unified(ua) => ua.to_address(net),
        }
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use zcash_address::test_vectors;
    use zcash_primitives::consensus::MAIN_NETWORK;

    use super::{RecipientAddress, UnifiedAddress};
    use crate::keys::sapling;

    #[test]
    fn ua_round_trip() {
        let orchard = {
            let sk = orchard::keys::SpendingKey::from_zip32_seed(&[0; 32], 0, 0).unwrap();
            let fvk = orchard::keys::FullViewingKey::from(&sk);
            Some(fvk.address_at(0u32, orchard::keys::Scope::External))
        };

        let sapling = {
            let extsk = sapling::spending_key(&[0; 32], 0, 0.into());
            let dfvk = extsk.to_diversifiable_full_viewing_key();
            Some(dfvk.default_address().1)
        };

        let transparent = { None };

        let ua = UnifiedAddress::from_receivers(orchard, sapling, transparent).unwrap();

        let addr = RecipientAddress::Unified(ua);
        let addr_str = addr.encode(&MAIN_NETWORK);
        assert_eq!(
            RecipientAddress::decode(&MAIN_NETWORK, &addr_str),
            Some(addr)
        );
    }

    #[test]
    fn ua_parsing() {
        for tv in test_vectors::UNIFIED {
            match RecipientAddress::decode(&MAIN_NETWORK, tv.unified_addr) {
                Some(RecipientAddress::Unified(ua)) => {
                    assert_eq!(
                        ua.transparent().is_some(),
                        tv.p2pkh_bytes.is_some() || tv.p2sh_bytes.is_some()
                    );
                    assert_eq!(ua.sapling().is_some(), tv.sapling_raw_addr.is_some());
                    assert_eq!(ua.orchard().is_some(), tv.orchard_raw_addr.is_some());
                }
                Some(_) => {
                    panic!(
                        "{} did not decode to a unified address value.",
                        tv.unified_addr
                    );
                }
                None => {
                    panic!(
                        "Failed to decode unified address from test vector: {}",
                        tv.unified_addr
                    );
                }
            }
        }
    }
}
