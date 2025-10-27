//! Structs for handling supported address types.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use transparent::address::TransparentAddress;
use zcash_address::{
    ConversionError, ToAddress, TryFromAddress, ZcashAddress,
    unified::{self, Container, Encoding, Typecode},
};
use zcash_protocol::consensus::{self, NetworkType};

#[cfg(feature = "sapling")]
use sapling::PaymentAddress;
use zcash_protocol::{PoolType, ShieldedProtocol};

/// A Unified Address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiedAddress {
    #[cfg(feature = "orchard")]
    orchard: Option<orchard::Address>,
    #[cfg(feature = "sapling")]
    sapling: Option<PaymentAddress>,
    transparent: Option<TransparentAddress>,
    unknown: Vec<(u32, Vec<u8>)>,
}

impl TryFrom<unified::Address> for UnifiedAddress {
    type Error = &'static str;

    fn try_from(ua: unified::Address) -> Result<Self, Self::Error> {
        #[cfg(feature = "orchard")]
        let mut orchard = None;
        #[cfg(feature = "sapling")]
        let mut sapling = None;
        let mut transparent = None;

        let mut unknown: Vec<(u32, Vec<u8>)> = vec![];

        // We can use as-parsed order here for efficiency, because we're breaking out the
        // receivers we support from the unknown receivers.
        for item in ua.items_as_parsed() {
            match item {
                unified::Receiver::Orchard(data) => {
                    #[cfg(feature = "orchard")]
                    {
                        orchard = Some(
                            Option::from(orchard::Address::from_raw_address_bytes(data))
                                .ok_or("Invalid Orchard receiver in Unified Address")?,
                        );
                    }
                    #[cfg(not(feature = "orchard"))]
                    {
                        unknown.push((unified::Typecode::Orchard.into(), data.to_vec()));
                    }
                }

                unified::Receiver::Sapling(data) => {
                    #[cfg(feature = "sapling")]
                    {
                        sapling = Some(
                            PaymentAddress::from_bytes(data)
                                .ok_or("Invalid Sapling receiver in Unified Address")?,
                        );
                    }
                    #[cfg(not(feature = "sapling"))]
                    {
                        unknown.push((unified::Typecode::Sapling.into(), data.to_vec()));
                    }
                }

                unified::Receiver::P2pkh(data) => {
                    transparent = Some(TransparentAddress::PublicKeyHash(*data));
                }

                unified::Receiver::P2sh(data) => {
                    transparent = Some(TransparentAddress::ScriptHash(*data));
                }

                unified::Receiver::Unknown { typecode, data } => {
                    unknown.push((*typecode, data.clone()));
                }
            }
        }

        Ok(Self {
            #[cfg(feature = "orchard")]
            orchard,
            #[cfg(feature = "sapling")]
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
        #[cfg(feature = "orchard")] orchard: Option<orchard::Address>,
        #[cfg(feature = "sapling")] sapling: Option<PaymentAddress>,
        transparent: Option<TransparentAddress>,
        // TODO: Add handling for address metadata items.
    ) -> Option<Self> {
        #[cfg(feature = "orchard")]
        let has_orchard = orchard.is_some();
        #[cfg(not(feature = "orchard"))]
        let has_orchard = false;

        #[cfg(feature = "sapling")]
        let has_sapling = sapling.is_some();
        #[cfg(not(feature = "sapling"))]
        let has_sapling = false;

        if has_orchard || has_sapling {
            Some(Self {
                #[cfg(feature = "orchard")]
                orchard,
                #[cfg(feature = "sapling")]
                sapling,
                transparent,
                unknown: vec![],
            })
        } else {
            // UAs require at least one shielded receiver.
            None
        }
    }

    /// Returns whether this address has an Orchard receiver.
    ///
    /// This method is available irrespective of whether the `orchard` feature flag is enabled.
    pub fn has_orchard(&self) -> bool {
        #[cfg(not(feature = "orchard"))]
        return false;
        #[cfg(feature = "orchard")]
        return self.orchard.is_some();
    }

    /// Returns the Orchard receiver within this Unified Address, if any.
    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> Option<&orchard::Address> {
        self.orchard.as_ref()
    }

    /// Returns whether this address has a Sapling receiver.
    pub fn has_sapling(&self) -> bool {
        #[cfg(not(feature = "sapling"))]
        return false;

        #[cfg(feature = "sapling")]
        return self.sapling.is_some();
    }

    /// Returns the Sapling receiver within this Unified Address, if any.
    #[cfg(feature = "sapling")]
    pub fn sapling(&self) -> Option<&PaymentAddress> {
        self.sapling.as_ref()
    }

    /// Returns whether this address has a Transparent receiver.
    pub fn has_transparent(&self) -> bool {
        self.transparent.is_some()
    }

    /// Returns the transparent receiver within this Unified Address, if any.
    pub fn transparent(&self) -> Option<&TransparentAddress> {
        self.transparent.as_ref()
    }

    /// Returns the set of unknown receivers of the unified address.
    pub fn unknown(&self) -> &[(u32, Vec<u8>)] {
        &self.unknown
    }

    /// Serializes this [`UnifiedAddress`] as a [`ZcashAddress`] for the given network.
    pub fn to_zcash_address(&self, net: NetworkType) -> ZcashAddress {
        let items = self
            .unknown
            .iter()
            .map(|(typecode, data)| unified::Receiver::Unknown {
                typecode: *typecode,
                data: data.clone(),
            });

        #[cfg(feature = "orchard")]
        let items = items.chain(
            self.orchard
                .as_ref()
                .map(|addr| addr.to_raw_address_bytes())
                .map(unified::Receiver::Orchard),
        );

        #[cfg(feature = "sapling")]
        let items = items.chain(
            self.sapling
                .as_ref()
                .map(|pa| pa.to_bytes())
                .map(unified::Receiver::Sapling),
        );

        let items = items.chain(self.transparent.as_ref().map(|taddr| match taddr {
            TransparentAddress::PublicKeyHash(data) => unified::Receiver::P2pkh(*data),
            TransparentAddress::ScriptHash(data) => unified::Receiver::P2sh(*data),
        }));

        let ua = unified::Address::try_from_items(items.collect())
            .expect("UnifiedAddress should only be constructed safely");
        ZcashAddress::from_unified(net, ua)
    }

    /// Returns the string encoding of this `UnifiedAddress` for the given network.
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        self.to_zcash_address(params.network_type()).to_string()
    }

    /// Returns the set of receiver typecodes.
    pub fn receiver_types(&self) -> Vec<Typecode> {
        let result = core::iter::empty();
        #[cfg(feature = "orchard")]
        let result = result.chain(self.orchard.map(|_| Typecode::Orchard));
        #[cfg(feature = "sapling")]
        let result = result.chain(self.sapling.map(|_| Typecode::Sapling));
        let result = result.chain(self.transparent.map(|taddr| match taddr {
            TransparentAddress::PublicKeyHash(_) => Typecode::P2pkh,
            TransparentAddress::ScriptHash(_) => Typecode::P2sh,
        }));
        let result = result.chain(
            self.unknown()
                .iter()
                .map(|(typecode, _)| Typecode::Unknown(*typecode)),
        );
        result.collect()
    }

    /// Returns the set of receivers in the unified address, excluding unknown receiver types.
    pub fn as_understood_receivers(&self) -> Vec<Receiver> {
        let result = core::iter::empty();
        #[cfg(feature = "orchard")]
        let result = result.chain(self.orchard.map(Receiver::Orchard));
        #[cfg(feature = "sapling")]
        let result = result.chain(self.sapling.map(Receiver::Sapling));
        let result = result.chain(self.transparent.map(Receiver::Transparent));
        result.collect()
    }
}

/// An enumeration of protocol-level receiver types.
///
/// While these correspond to unified address receiver types, this is a distinct type because it is
/// used to represent the protocol-level recipient of a transfer, instead of a part of an encoded
/// address.
pub enum Receiver {
    #[cfg(feature = "orchard")]
    Orchard(orchard::Address),
    #[cfg(feature = "sapling")]
    Sapling(PaymentAddress),
    Transparent(TransparentAddress),
}

impl Receiver {
    /// Converts this receiver to a [`ZcashAddress`] for the given network.
    ///
    /// This conversion function selects the least-capable address format possible; this means that
    /// Orchard receivers will be rendered as Unified addresses, Sapling receivers will be rendered
    /// as bare Sapling addresses, and Transparent receivers will be rendered as taddrs.
    pub fn to_zcash_address(&self, net: NetworkType) -> ZcashAddress {
        match self {
            #[cfg(feature = "orchard")]
            Receiver::Orchard(addr) => {
                let receiver = unified::Receiver::Orchard(addr.to_raw_address_bytes());
                let ua = unified::Address::try_from_items(vec![receiver])
                    .expect("A unified address may contain a single Orchard receiver.");
                ZcashAddress::from_unified(net, ua)
            }
            #[cfg(feature = "sapling")]
            Receiver::Sapling(addr) => ZcashAddress::from_sapling(net, addr.to_bytes()),
            Receiver::Transparent(TransparentAddress::PublicKeyHash(data)) => {
                ZcashAddress::from_transparent_p2pkh(net, *data)
            }
            Receiver::Transparent(TransparentAddress::ScriptHash(data)) => {
                ZcashAddress::from_transparent_p2sh(net, *data)
            }
        }
    }

    /// Returns whether or not this receiver corresponds to `addr`, or is contained
    /// in `addr` when the latter is a Unified Address.
    pub fn corresponds(&self, addr: &ZcashAddress) -> bool {
        addr.matches_receiver(&match self {
            #[cfg(feature = "orchard")]
            Receiver::Orchard(addr) => unified::Receiver::Orchard(addr.to_raw_address_bytes()),
            #[cfg(feature = "sapling")]
            Receiver::Sapling(addr) => unified::Receiver::Sapling(addr.to_bytes()),
            Receiver::Transparent(TransparentAddress::PublicKeyHash(data)) => {
                unified::Receiver::P2pkh(*data)
            }
            Receiver::Transparent(TransparentAddress::ScriptHash(data)) => {
                unified::Receiver::P2sh(*data)
            }
        })
    }
}

/// An address that funds can be sent to.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Address {
    /// A Sapling payment address.
    #[cfg(feature = "sapling")]
    Sapling(PaymentAddress),

    /// A transparent address corresponding to either a public key hash or a script hash.
    Transparent(TransparentAddress),

    /// A [ZIP 316] Unified Address.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    Unified(UnifiedAddress),

    /// A [ZIP 320] transparent-source-only P2PKH address, or "TEX address".
    ///
    /// [ZIP 320]: https://zips.z.cash/zip-0320
    Tex([u8; 20]),
}

#[cfg(feature = "sapling")]
impl From<PaymentAddress> for Address {
    fn from(addr: PaymentAddress) -> Self {
        Address::Sapling(addr)
    }
}

impl From<TransparentAddress> for Address {
    fn from(addr: TransparentAddress) -> Self {
        Address::Transparent(addr)
    }
}

impl From<UnifiedAddress> for Address {
    fn from(addr: UnifiedAddress) -> Self {
        Address::Unified(addr)
    }
}

impl TryFromAddress for Address {
    type Error = &'static str;

    #[cfg(feature = "sapling")]
    fn try_from_sapling(
        _net: NetworkType,
        data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        let pa = PaymentAddress::from_bytes(&data).ok_or("Invalid Sapling payment address")?;
        Ok(pa.into())
    }

    fn try_from_unified(
        _net: NetworkType,
        ua: zcash_address::unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        UnifiedAddress::try_from(ua)
            .map_err(ConversionError::User)
            .map(Address::from)
    }

    fn try_from_transparent_p2pkh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(TransparentAddress::PublicKeyHash(data).into())
    }

    fn try_from_transparent_p2sh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(TransparentAddress::ScriptHash(data).into())
    }

    fn try_from_tex(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address::Tex(data))
    }
}

impl Address {
    /// Attempts to decode an [`Address`] value from its [`ZcashAddress`] encoded representation.
    ///
    /// Returns `None` if any error is encountered in decoding. Use
    /// [`Self::try_from_zcash_address`] passing in `s.parse()?` if you need detailed
    /// error information.
    pub fn decode<P: consensus::Parameters>(params: &P, s: &str) -> Option<Self> {
        Self::try_from_zcash_address(params, s.parse::<ZcashAddress>().ok()?).ok()
    }

    /// Attempts to decode an [`Address`] value from its [`ZcashAddress`] encoded representation.
    pub fn try_from_zcash_address<P: consensus::Parameters>(
        params: &P,
        zaddr: ZcashAddress,
    ) -> Result<Self, ConversionError<&'static str>> {
        zaddr.convert_if_network(params.network_type())
    }

    /// Converts this [`Address`] to its encoded [`ZcashAddress`] representation.
    pub fn to_zcash_address<P: consensus::Parameters>(&self, params: &P) -> ZcashAddress {
        let net = params.network_type();

        match self {
            #[cfg(feature = "sapling")]
            Address::Sapling(pa) => ZcashAddress::from_sapling(net, pa.to_bytes()),
            Address::Transparent(addr) => match addr {
                TransparentAddress::PublicKeyHash(data) => {
                    ZcashAddress::from_transparent_p2pkh(net, *data)
                }
                TransparentAddress::ScriptHash(data) => {
                    ZcashAddress::from_transparent_p2sh(net, *data)
                }
            },
            Address::Unified(ua) => ua.to_zcash_address(net),
            Address::Tex(data) => ZcashAddress::from_tex(net, *data),
        }
    }

    /// Converts this [`Address`] to its encoded string representation.
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        self.to_zcash_address(params).to_string()
    }

    /// Returns whether or not this [`Address`] can receive funds in the specified pool.
    pub fn can_receive_as(&self, pool_type: PoolType) -> bool {
        match self {
            #[cfg(feature = "sapling")]
            Address::Sapling(_) => {
                matches!(pool_type, PoolType::Shielded(ShieldedProtocol::Sapling))
            }
            Address::Transparent(_) | Address::Tex(_) => {
                matches!(pool_type, PoolType::Transparent)
            }
            Address::Unified(ua) => match pool_type {
                PoolType::Transparent => ua.has_transparent(),
                PoolType::Shielded(ShieldedProtocol::Sapling) => ua.has_sapling(),
                PoolType::Shielded(ShieldedProtocol::Orchard) => ua.has_orchard(),
            },
        }
    }

    /// Returns the transparent address corresponding to this address, if it is a transparent
    /// address, a Unified address with a transparent receiver, or ZIP 320 (TEX) address.
    pub fn to_transparent_address(&self) -> Option<TransparentAddress> {
        match self {
            #[cfg(feature = "sapling")]
            Address::Sapling(_) => None,
            Address::Transparent(addr) => Some(*addr),
            Address::Unified(ua) => ua.transparent().copied(),
            Address::Tex(addr_bytes) => Some(TransparentAddress::PublicKeyHash(*addr_bytes)),
        }
    }

    /// Returns the Sapling address corresponding to this address, if it is a ZIP 32-encoded
    /// Sapling address, or a Unified address with a Sapling receiver.
    #[cfg(feature = "sapling")]
    pub fn to_sapling_address(&self) -> Option<PaymentAddress> {
        match self {
            Address::Sapling(addr) => Some(*addr),
            Address::Transparent(_) => None,
            Address::Unified(ua) => ua.sapling().copied(),
            Address::Tex(_) => None,
        }
    }

    /// Returns the protocol-typed unified [`Receiver`]s of this address as a vector, ignoring the
    /// original encoding of the address.
    ///
    /// In the case that the underlying address is the [`Address::Unified`] variant, this is
    /// equivalent to [`UnifiedAddress::as_understood_receivers`] in that it does not return
    /// unknown receiver data.
    ///
    /// Note that this method eliminates the distinction between transparent addresses and the
    /// transparent receiving address for a TEX address; as such, it should only be used in cases
    /// where address uses are being detected in inspection of chain data, and NOT in any situation
    /// where a transaction sending to this address is being constructed.
    pub fn as_understood_unified_receivers(&self) -> Vec<Receiver> {
        match self {
            #[cfg(feature = "sapling")]
            Address::Sapling(addr) => vec![Receiver::Sapling(*addr)],
            Address::Transparent(addr) => vec![Receiver::Transparent(*addr)],
            Address::Unified(ua) => ua.as_understood_receivers(),
            Address::Tex(addr) => vec![Receiver::Transparent(TransparentAddress::PublicKeyHash(
                *addr,
            ))],
        }
    }
}

#[cfg(all(
    any(
        feature = "orchard",
        feature = "sapling",
        feature = "transparent-inputs"
    ),
    any(test, feature = "test-dependencies")
))]
pub mod testing {
    use proptest::prelude::*;
    use zcash_protocol::consensus::Network;

    use crate::keys::{UnifiedAddressRequest, testing::arb_unified_spending_key};

    use super::{Address, UnifiedAddress};

    #[cfg(feature = "sapling")]
    use sapling::testing::arb_payment_address;
    use transparent::address::testing::arb_transparent_addr;

    pub fn arb_unified_addr(
        params: Network,
        request: UnifiedAddressRequest,
    ) -> impl Strategy<Value = UnifiedAddress> {
        arb_unified_spending_key(params).prop_map(move |k| k.default_address(request).0)
    }

    #[cfg(feature = "sapling")]
    pub fn arb_addr(request: UnifiedAddressRequest) -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_payment_address().prop_map(Address::Sapling),
            arb_transparent_addr().prop_map(Address::Transparent),
            arb_unified_addr(Network::TestNetwork, request).prop_map(Address::Unified),
            proptest::array::uniform20(any::<u8>()).prop_map(Address::Tex),
        ]
    }

    #[cfg(not(feature = "sapling"))]
    pub fn arb_addr(request: UnifiedAddressRequest) -> impl Strategy<Value = Address> {
        return prop_oneof![
            arb_transparent_addr().prop_map(Address::Transparent),
            arb_unified_addr(Network::TestNetwork, request).prop_map(Address::Unified),
            proptest::array::uniform20(any::<u8>()).prop_map(Address::Tex),
        ];
    }
}

#[cfg(test)]
mod tests {
    use zcash_address::test_vectors;
    use zcash_protocol::consensus::MAIN_NETWORK;

    use super::{Address, UnifiedAddress};

    #[cfg(feature = "sapling")]
    use crate::keys::sapling;

    #[cfg(any(feature = "orchard", feature = "sapling"))]
    use zip32::AccountId;

    #[test]
    #[cfg(any(feature = "orchard", feature = "sapling"))]
    fn ua_round_trip() {
        #[cfg(feature = "orchard")]
        let orchard = {
            let sk =
                orchard::keys::SpendingKey::from_zip32_seed(&[0; 32], 0, AccountId::ZERO).unwrap();
            let fvk = orchard::keys::FullViewingKey::from(&sk);
            Some(fvk.address_at(0u32, orchard::keys::Scope::External))
        };

        #[cfg(feature = "sapling")]
        let sapling = {
            let extsk = sapling::spending_key(&[0; 32], 0, AccountId::ZERO);
            let dfvk = extsk.to_diversifiable_full_viewing_key();
            Some(dfvk.default_address().1)
        };

        let transparent = None;

        #[cfg(all(feature = "orchard", feature = "sapling"))]
        let ua = UnifiedAddress::from_receivers(orchard, sapling, transparent).unwrap();

        #[cfg(all(not(feature = "orchard"), feature = "sapling"))]
        let ua = UnifiedAddress::from_receivers(sapling, transparent).unwrap();

        #[cfg(all(feature = "orchard", not(feature = "sapling")))]
        let ua = UnifiedAddress::from_receivers(orchard, transparent).unwrap();

        let addr = Address::Unified(ua);
        let addr_str = addr.encode(&MAIN_NETWORK);
        assert_eq!(Address::decode(&MAIN_NETWORK, &addr_str), Some(addr));
    }

    #[test]
    #[cfg(not(any(feature = "orchard", feature = "sapling")))]
    fn ua_round_trip() {
        let transparent = None;
        assert_eq!(UnifiedAddress::from_receivers(transparent), None)
    }

    #[test]
    fn ua_parsing() {
        for tv in test_vectors::UNIFIED {
            match Address::decode(&MAIN_NETWORK, tv.unified_addr) {
                Some(Address::Unified(ua)) => {
                    assert_eq!(
                        ua.has_transparent(),
                        tv.p2pkh_bytes.is_some() || tv.p2sh_bytes.is_some()
                    );
                    #[cfg(feature = "sapling")]
                    assert_eq!(ua.has_sapling(), tv.sapling_raw_addr.is_some());
                    #[cfg(feature = "orchard")]
                    assert_eq!(ua.has_orchard(), tv.orchard_raw_addr.is_some());
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
