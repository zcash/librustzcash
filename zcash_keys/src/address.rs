//! Structs for handling supported address types.

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::{convert::Infallible, fmt};

use transparent::address::TransparentAddress;
use zcash_address::{
    ConversionError, ToAddress, TryFromAddress, ZcashAddress,
    unified::{
        self, Container, Encoding, MetadataItem, MetadataTypecode, Revision, Typecode, Uitem,
    },
};
use zcash_protocol::{
    PoolType, ShieldedPool,
    consensus::{self, NetworkType},
};

use crate::encoding::{UnifiedDecodingError, UnifiedEncodingError};

#[cfg(feature = "sapling")]
use sapling::PaymentAddress;

/// An error that prevents pruning a [`UnifiedAddress`] to a set of item types.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PruneError {
    /// The address holds a MUST-understand metadata item of this type, and the
    /// requested item types do not include it.
    MustUnderstandMetadata(MetadataTypecode),
    /// The pruned address has no encoding at any revision. For example, an address whose
    /// only receiver is a short unknown item is below the minimum encoded length.
    NotRepresentable(unified::ParseError),
}

impl fmt::Display for PruneError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PruneError::MustUnderstandMetadata(typecode) => write!(
                f,
                "Cannot remove MUST-understand metadata item with typecode {:#04X}",
                u32::from(*typecode)
            ),
            PruneError::NotRepresentable(cause) => {
                write!(f, "The pruned unified address has no encoding: {cause}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PruneError {}

/// A Unified Address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiedAddress {
    #[cfg(feature = "orchard")]
    orchard: Option<orchard::Address>,
    #[cfg(feature = "sapling")]
    sapling: Option<PaymentAddress>,
    transparent: Option<TransparentAddress>,
    unknown: Vec<(u32, Vec<u8>)>,
    expiry_height: Option<consensus::BlockHeight>,
    expiry_time: Option<u64>,
    unknown_metadata: Vec<(u32, Vec<u8>)>,
}

impl TryFrom<unified::Address> for UnifiedAddress {
    type Error = &'static str;

    fn try_from(ua: unified::Address) -> Result<Self, Self::Error> {
        Self::from_container(ua).map_err(|typecode| match typecode {
            Typecode::ORCHARD => "Invalid Orchard receiver in Unified Address",
            _ => "Invalid Sapling receiver in Unified Address",
        })
    }
}

impl UnifiedAddress {
    /// Constructs a [`UnifiedAddress`] from a parsed unified container.
    ///
    /// On error, returns the typecode of the first receiver whose data is not a valid
    /// receiver of its type.
    fn from_container(ua: unified::Address) -> Result<Self, Typecode> {
        #[cfg(feature = "orchard")]
        let mut orchard = None;
        #[cfg(feature = "sapling")]
        let mut sapling = None;
        let mut transparent = None;

        let mut unknown: Vec<(u32, Vec<u8>)> = vec![];
        let mut expiry_height = None;
        let mut expiry_time = None;
        let mut unknown_metadata: Vec<(u32, Vec<u8>)> = vec![];

        // We can use as-parsed order here for efficiency, because we're breaking out the
        // receivers we support from the unknown receivers.
        for item in ua.items_as_parsed() {
            match item {
                Uitem::Data(unified::Receiver::Orchard(data)) => {
                    #[cfg(feature = "orchard")]
                    {
                        orchard = Some(
                            Option::from(orchard::Address::from_raw_address_bytes(data))
                                .ok_or(Typecode::ORCHARD)?,
                        );
                    }
                    #[cfg(not(feature = "orchard"))]
                    {
                        unknown.push((Typecode::ORCHARD.into(), data.to_vec()));
                    }
                }

                Uitem::Data(unified::Receiver::Sapling(data)) => {
                    #[cfg(feature = "sapling")]
                    {
                        sapling = Some(PaymentAddress::from_bytes(data).ok_or(Typecode::SAPLING)?);
                    }
                    #[cfg(not(feature = "sapling"))]
                    {
                        unknown.push((Typecode::SAPLING.into(), data.to_vec()));
                    }
                }

                Uitem::Data(unified::Receiver::P2pkh(data)) => {
                    transparent = Some(TransparentAddress::PublicKeyHash(*data));
                }

                Uitem::Data(unified::Receiver::P2sh(data)) => {
                    transparent = Some(TransparentAddress::ScriptHash(*data));
                }

                Uitem::Data(unified::Receiver::Unknown { typecode, data }) => {
                    unknown.push((*typecode, data.clone()));
                }

                Uitem::Metadata(MetadataItem::ExpiryHeight(h)) => {
                    expiry_height = Some(consensus::BlockHeight::from_u32(*h));
                }

                Uitem::Metadata(MetadataItem::ExpiryTime(t)) => {
                    expiry_time = Some(*t);
                }

                Uitem::Metadata(MetadataItem::Unknown { typecode, data }) => {
                    unknown_metadata.push((*typecode, data.clone()));
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
            expiry_height,
            expiry_time,
            unknown_metadata,
        })
    }

    /// Constructs a Unified Address from a given set of receivers.
    ///
    /// Returns `None` if the receivers would produce an invalid Unified Address (namely,
    /// if no receiver at all is provided). At least one receiver (transparent or shielded)
    /// must be present.
    ///
    /// An address whose only receiver is transparent has an encoding only at [ZIP 316]
    /// Revision 2, as a transparent-including (`tu`) address.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn from_receivers(
        #[cfg(feature = "orchard")] orchard: Option<orchard::Address>,
        #[cfg(feature = "sapling")] sapling: Option<PaymentAddress>,
        transparent: Option<TransparentAddress>,
        expiry_height: Option<consensus::BlockHeight>,
        expiry_time: Option<u64>,
    ) -> Option<Self> {
        #[cfg(feature = "orchard")]
        let has_orchard = orchard.is_some();
        #[cfg(not(feature = "orchard"))]
        let has_orchard = false;

        #[cfg(feature = "sapling")]
        let has_sapling = sapling.is_some();
        #[cfg(not(feature = "sapling"))]
        let has_sapling = false;

        if has_orchard || has_sapling || transparent.is_some() {
            Some(Self {
                #[cfg(feature = "orchard")]
                orchard,
                #[cfg(feature = "sapling")]
                sapling,
                transparent,
                unknown: vec![],
                expiry_height,
                expiry_time,
                unknown_metadata: vec![],
            })
        } else {
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

    /// Returns the expiry height metadata for this address, if present.
    pub fn expiry_height(&self) -> Option<consensus::BlockHeight> {
        self.expiry_height
    }

    /// Returns the expiry time metadata for this address, if present.
    pub fn expiry_time(&self) -> Option<u64> {
        self.expiry_time
    }

    /// Returns a copy of this address that holds only the items whose types are in
    /// `item_types`.
    ///
    /// The result omits each receiver and each SHOULD-understand metadata item whose type
    /// is not in `item_types`. Use this to share an address with fewer receivers, for
    /// example one without its transparent receiver.
    ///
    /// Returns `Ok(None)` if no receiver of this address has a type in `item_types`,
    /// because a unified address must hold at least one receiver.
    ///
    /// Returns [`PruneError::MustUnderstandMetadata`] if this address holds a [ZIP 316]
    /// MUST-understand metadata item, such as an expiry height or an expiry time, whose
    /// type is not in `item_types`. Removal of such an item changes the meaning of the
    /// address.
    ///
    /// Returns [`PruneError::NotRepresentable`] if the pruned address has no encoding at
    /// any revision.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn prune_retaining(&self, item_types: &[Typecode]) -> Result<Option<Self>, PruneError> {
        let is_requested = |typecode: u32| {
            item_types
                .iter()
                .any(|requested| requested.typecode_value() == typecode)
        };

        let must_understand_omitted = self
            .expiry_height
            .map(|_| MetadataTypecode::ExpiryHeight)
            .into_iter()
            .chain(self.expiry_time.map(|_| MetadataTypecode::ExpiryTime))
            .chain(
                self.unknown_metadata
                    .iter()
                    .map(|(typecode, _)| MetadataTypecode::Unknown(*typecode)),
            )
            .find(|typecode| typecode.is_must_understand() && !is_requested(u32::from(*typecode)));
        if let Some(typecode) = must_understand_omitted {
            return Err(PruneError::MustUnderstandMetadata(typecode));
        }

        let pruned = Self {
            #[cfg(feature = "orchard")]
            orchard: self
                .orchard
                .filter(|_| is_requested(Typecode::ORCHARD.into())),
            #[cfg(feature = "sapling")]
            sapling: self
                .sapling
                .filter(|_| is_requested(Typecode::SAPLING.into())),
            transparent: self.transparent.filter(|taddr| {
                is_requested(
                    match taddr {
                        TransparentAddress::PublicKeyHash(_) => Typecode::P2PKH,
                        TransparentAddress::ScriptHash(_) => Typecode::P2SH,
                    }
                    .into(),
                )
            }),
            unknown: self
                .unknown
                .iter()
                .filter(|(typecode, _)| is_requested(*typecode))
                .cloned()
                .collect(),
            expiry_height: self
                .expiry_height
                .filter(|_| is_requested(MetadataTypecode::ExpiryHeight.into())),
            expiry_time: self
                .expiry_time
                .filter(|_| is_requested(MetadataTypecode::ExpiryTime.into())),
            unknown_metadata: self
                .unknown_metadata
                .iter()
                .filter(|(typecode, _)| is_requested(*typecode))
                .cloned()
                .collect(),
        };

        let has_receiver = pruned.has_orchard()
            || pruned.has_sapling()
            || pruned.has_transparent()
            || !pruned.unknown.is_empty();
        if !has_receiver {
            return Ok(None);
        }

        // Revision 2 can encode every address that any revision can encode.
        pruned
            .to_container(Revision::R2)
            .map_err(PruneError::NotRepresentable)?;
        Ok(Some(pruned))
    }

    /// Parses a [`UnifiedAddress`] from its [ZIP 316] string encoding at any revision.
    ///
    /// # Errors
    ///
    /// - [`UnifiedDecodingError::Parse`] if the string is not a valid unified
    ///   address.
    /// - [`UnifiedDecodingError::NetworkMismatch`] if the address is for a network
    ///   other than that of `params`.
    /// - [`UnifiedDecodingError::InvalidItem`] if a receiver's data is not a valid
    ///   receiver of its type.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn decode<P: consensus::Parameters>(
        params: &P,
        address: &str,
    ) -> Result<Self, UnifiedDecodingError> {
        let (actual, _revision, ua) =
            unified::Address::decode(address).map_err(UnifiedDecodingError::Parse)?;
        let expected = params.network_type();
        if actual != expected {
            return Err(UnifiedDecodingError::NetworkMismatch { expected, actual });
        }
        Self::from_container(ua).map_err(UnifiedDecodingError::InvalidItem)
    }

    /// Serializes this [`UnifiedAddress`] as a [`ZcashAddress`] for the given network.
    ///
    /// The encoding contains every receiver and metadata item of this address. It uses
    /// [ZIP 316] [`Revision::R0`] if that revision can represent the address, and
    /// [`Revision::R2`] otherwise. At [`Revision::R2`], an address with a transparent
    /// receiver uses the transparent-including (`tu`) form, and an address without one
    /// uses the shielded-only (`zu`) form. To encode only some of the receivers, first
    /// call [`UnifiedAddress::prune_retaining`].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn to_zcash_address(&self, net: NetworkType) -> ZcashAddress {
        self.to_zcash_address_revision(net, Revision::R0)
            .or_else(|_| self.to_zcash_address_revision(net, Revision::R2))
            // Every `UnifiedAddress` has at least one data item, and every unknown item
            // or metadata item it holds was accepted by a decoder. `prune_retaining`
            // returns an address only if Revision 2 can encode it. So Revision 2 can
            // always encode it.
            .expect("Revision 2 can encode every UnifiedAddress")
    }

    /// Serializes this [`UnifiedAddress`] as a [`ZcashAddress`] for the given network at
    /// the given [ZIP 316] revision.
    ///
    /// The encoding contains every receiver and metadata item of this address. At
    /// [`Revision::R2`], an address with a transparent receiver uses the
    /// transparent-including (`tu`) form, and an address without one uses the
    /// shielded-only (`zu`) form.
    ///
    /// Returns [`UnifiedEncodingError::NotRepresentable`] if `revision` cannot encode
    /// every receiver and metadata item of this address. [`Revision::R0`] cannot encode
    /// expiry metadata or an address whose only receiver is transparent; every address
    /// has a [`Revision::R2`] encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn to_zcash_address_revision(
        &self,
        net: NetworkType,
        revision: Revision,
    ) -> Result<ZcashAddress, UnifiedEncodingError> {
        self.to_container(revision)
            .map(|ua| ZcashAddress::from_unified(net, ua))
            .map_err(|cause| UnifiedEncodingError::NotRepresentable { revision, cause })
    }

    /// Builds the unified container that holds every item of this address at `revision`.
    fn to_container(&self, revision: Revision) -> Result<unified::Address, unified::ParseError> {
        let items: Vec<Uitem<unified::Receiver>> = core::iter::empty()
            .chain(self.unknown.iter().map(|(typecode, data)| {
                Uitem::Data(unified::Receiver::Unknown {
                    typecode: *typecode,
                    data: data.clone(),
                })
            }))
            .chain({
                #[cfg(feature = "orchard")]
                {
                    self.orchard
                        .as_ref()
                        .map(|addr| {
                            Uitem::Data(unified::Receiver::Orchard(addr.to_raw_address_bytes()))
                        })
                        .into_iter()
                }
                #[cfg(not(feature = "orchard"))]
                {
                    core::iter::empty()
                }
            })
            .chain({
                #[cfg(feature = "sapling")]
                {
                    self.sapling
                        .as_ref()
                        .map(|pa| Uitem::Data(unified::Receiver::Sapling(pa.to_bytes())))
                        .into_iter()
                }
                #[cfg(not(feature = "sapling"))]
                {
                    core::iter::empty()
                }
            })
            .chain(self.transparent.as_ref().map(|taddr| match taddr {
                TransparentAddress::PublicKeyHash(data) => {
                    Uitem::Data(unified::Receiver::P2pkh(*data))
                }
                TransparentAddress::ScriptHash(data) => Uitem::Data(unified::Receiver::P2sh(*data)),
            }))
            .chain(
                self.expiry_height
                    .map(|h| Uitem::Metadata(MetadataItem::ExpiryHeight(h.into()))),
            )
            .chain(
                self.expiry_time
                    .map(|t| Uitem::Metadata(MetadataItem::ExpiryTime(t))),
            )
            .chain(self.unknown_metadata.iter().map(|(typecode, data)| {
                Uitem::Metadata(MetadataItem::Unknown {
                    typecode: *typecode,
                    data: data.clone(),
                })
            }))
            .collect();

        unified::Address::try_from_items(revision, items)
    }

    /// Returns the string encoding of this [`UnifiedAddress`] for the given network.
    ///
    /// The encoding contains every receiver and metadata item of this address. It uses
    /// [ZIP 316] [`Revision::R0`] if that revision can represent the address, and
    /// [`Revision::R2`] otherwise. At [`Revision::R2`], an address with a transparent
    /// receiver uses the transparent-including (`tu`) form, and an address without one
    /// uses the shielded-only (`zu`) form.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        self.to_zcash_address(params.network_type()).to_string()
    }

    /// Returns the string encoding of this [`UnifiedAddress`] for the given network at the
    /// given [ZIP 316] revision.
    ///
    /// The encoding contains every receiver and metadata item of this address. At
    /// [`Revision::R2`], an address with a transparent receiver uses the
    /// transparent-including (`tu`) form, and an address without one uses the
    /// shielded-only (`zu`) form.
    ///
    /// Returns [`UnifiedEncodingError::NotRepresentable`] if `revision` cannot encode
    /// every receiver and metadata item of this address. [`Revision::R0`] cannot encode
    /// expiry metadata or an address whose only receiver is transparent; every address
    /// has a [`Revision::R2`] encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn encode_revision<P: consensus::Parameters>(
        &self,
        params: &P,
        revision: Revision,
    ) -> Result<String, UnifiedEncodingError> {
        self.to_zcash_address_revision(params.network_type(), revision)
            .map(|addr| addr.to_string())
    }

    /// Returns the set of receiver typecodes.
    pub fn receiver_types(&self) -> Vec<Typecode> {
        let result = core::iter::empty();
        #[cfg(feature = "orchard")]
        let result = result.chain(self.orchard.map(|_| Typecode::ORCHARD));
        #[cfg(feature = "sapling")]
        let result = result.chain(self.sapling.map(|_| Typecode::SAPLING));
        let result = result.chain(self.transparent.map(|taddr| match taddr {
            TransparentAddress::PublicKeyHash(_) => Typecode::P2PKH,
            TransparentAddress::ScriptHash(_) => Typecode::P2SH,
        }));
        let result = result.chain(
            self.unknown()
                .iter()
                .filter_map(|(typecode, _)| Typecode::try_from(*typecode).ok()),
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
    /// Converts this receiver to a [`ZcashAddress`] for the given network, using the
    /// least-capable address format that can carry it.
    ///
    /// An Orchard receiver becomes a Unified Address encoded at the given [ZIP 316]
    /// revision, a Sapling receiver becomes a Sapling address, and a transparent receiver
    /// becomes a transparent address. Every revision can encode a Unified Address with a
    /// single Orchard receiver.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    #[cfg_attr(not(feature = "orchard"), allow(unused_variables))]
    pub fn to_zcash_address_revision(
        &self,
        net: NetworkType,
        ua_revision: Revision,
    ) -> ZcashAddress {
        match self {
            #[cfg(feature = "orchard")]
            Receiver::Orchard(addr) => {
                let receiver = Uitem::Data(unified::Receiver::Orchard(addr.to_raw_address_bytes()));
                let ua = unified::Address::try_from_items(ua_revision, vec![receiver]).expect(
                    "Every revision permits a unified address with a single Orchard receiver.",
                );
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

    /// Converts this receiver to a [`ZcashAddress`] for the given network, using the
    /// least-capable address format that can carry it.
    ///
    /// An Orchard receiver becomes a Unified Address encoded at [ZIP 316]
    /// [`Revision::R0`], a Sapling receiver becomes a Sapling address, and a transparent
    /// receiver becomes a transparent address.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn to_zcash_address(&self, net: NetworkType) -> ZcashAddress {
        self.to_zcash_address_revision(net, Revision::R0)
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
    Sapling(Box<PaymentAddress>),

    /// A transparent address corresponding to either a public key hash or a script hash.
    Transparent(TransparentAddress),

    /// A [ZIP 316] Unified Address.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    Unified(Box<UnifiedAddress>),

    /// A [ZIP 320] transparent-source-only P2PKH address, or "TEX address".
    ///
    /// [ZIP 320]: https://zips.z.cash/zip-0320
    Tex([u8; 20]),
}

#[cfg(feature = "sapling")]
impl From<PaymentAddress> for Address {
    fn from(addr: PaymentAddress) -> Self {
        Address::Sapling(Box::new(addr))
    }
}

impl From<TransparentAddress> for Address {
    fn from(addr: TransparentAddress) -> Self {
        Address::Transparent(addr)
    }
}

impl From<UnifiedAddress> for Address {
    fn from(addr: UnifiedAddress) -> Self {
        Address::Unified(Box::new(addr))
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

    /// Converts this [`Address`] to a [`ZcashAddress`].
    ///
    /// A unified address is encoded with every receiver and metadata item, at the given
    /// [ZIP 316] revision. Sapling, transparent, and TEX addresses have a single encoding
    /// and ignore `ua_revision`.
    ///
    /// Returns [`UnifiedEncodingError::NotRepresentable`] if this is a unified address
    /// that `ua_revision` cannot encode in full. [`Revision::R0`] cannot encode expiry
    /// metadata or an address whose only receiver is transparent; every address has a
    /// [`Revision::R2`] encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn to_zcash_address_revision<P: consensus::Parameters>(
        &self,
        params: &P,
        ua_revision: Revision,
    ) -> Result<ZcashAddress, UnifiedEncodingError> {
        self.to_zcash_address_with(params.network_type(), |ua, net| {
            ua.to_zcash_address_revision(net, ua_revision)
        })
    }

    /// Converts this [`Address`] to its encoded [`ZcashAddress`] representation, using
    /// `encode_unified` to encode a unified address.
    fn to_zcash_address_with<E>(
        &self,
        net: NetworkType,
        encode_unified: impl FnOnce(&UnifiedAddress, NetworkType) -> Result<ZcashAddress, E>,
    ) -> Result<ZcashAddress, E> {
        Ok(match self {
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
            Address::Unified(ua) => encode_unified(ua, net)?,
            Address::Tex(data) => ZcashAddress::from_tex(net, *data),
        })
    }

    /// Converts this [`Address`] to a [`ZcashAddress`].
    ///
    /// A unified address is encoded with every receiver and metadata item, at [ZIP 316]
    /// [`Revision::R0`] if that revision can represent it, and at [`Revision::R2`]
    /// otherwise. Sapling, transparent, and TEX addresses have a single encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn to_zcash_address<P: consensus::Parameters>(&self, params: &P) -> ZcashAddress {
        let result: Result<_, Infallible> =
            self.to_zcash_address_with(params.network_type(), |ua, net| {
                Ok(ua.to_zcash_address(net))
            });
        match result {
            Ok(addr) => addr,
            Err(e) => match e {},
        }
    }

    /// Returns the string encoding of this [`Address`].
    ///
    /// A unified address is encoded with every receiver and metadata item, at [ZIP 316]
    /// [`Revision::R0`] if that revision can represent it, and at [`Revision::R2`]
    /// otherwise. Sapling, transparent, and TEX addresses have a single encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        self.to_zcash_address(params).to_string()
    }

    /// Returns the string encoding of this [`Address`].
    ///
    /// A unified address is encoded with every receiver and metadata item, at the given
    /// [ZIP 316] revision. Sapling, transparent, and TEX addresses have a single encoding
    /// and ignore `ua_revision`.
    ///
    /// Returns [`UnifiedEncodingError::NotRepresentable`] if this is a unified address
    /// that `ua_revision` cannot encode in full. [`Revision::R0`] cannot encode expiry
    /// metadata or an address whose only receiver is transparent; every address has a
    /// [`Revision::R2`] encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn encode_revision<P: consensus::Parameters>(
        &self,
        params: &P,
        ua_revision: Revision,
    ) -> Result<String, UnifiedEncodingError> {
        self.to_zcash_address_revision(params, ua_revision)
            .map(|addr| addr.to_string())
    }

    /// Returns whether or not this [`Address`] can receive funds in the specified pool.
    pub fn can_receive_as(&self, pool_type: PoolType) -> bool {
        match self {
            #[cfg(feature = "sapling")]
            Address::Sapling(_) => {
                matches!(pool_type, PoolType::Shielded(ShieldedPool::Sapling))
            }
            Address::Transparent(_) | Address::Tex(_) => {
                matches!(pool_type, PoolType::Transparent)
            }
            Address::Unified(ua) => match pool_type {
                PoolType::Transparent => ua.has_transparent(),
                PoolType::Shielded(ShieldedPool::Sapling) => ua.has_sapling(),
                // Ironwood shares the Orchard receiver.
                PoolType::Shielded(ShieldedPool::Orchard | ShieldedPool::Ironwood) => {
                    ua.has_orchard()
                }
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
            Address::Sapling(addr) => Some(**addr),
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
            Address::Sapling(addr) => vec![Receiver::Sapling(**addr)],
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
            arb_payment_address().prop_map(Address::from),
            arb_transparent_addr().prop_map(Address::Transparent),
            arb_unified_addr(Network::TestNetwork, request).prop_map(Address::from),
            proptest::array::uniform20(any::<u8>()).prop_map(Address::Tex),
        ]
    }

    #[cfg(not(feature = "sapling"))]
    pub fn arb_addr(request: UnifiedAddressRequest) -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_transparent_addr().prop_map(Address::Transparent),
            arb_unified_addr(Network::TestNetwork, request).prop_map(Address::from),
            proptest::array::uniform20(any::<u8>()).prop_map(Address::Tex),
        ]
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use transparent::address::TransparentAddress;
    use zcash_address::{
        test_vectors,
        unified::{self, Encoding, MetadataItem, MetadataTypecode, ParseError, Revision, Uitem},
    };
    use zcash_protocol::consensus::{BlockHeight, MAIN_NETWORK, NetworkType, TEST_NETWORK};

    use super::{Address, PruneError, UnifiedAddress};
    use crate::encoding::{UnifiedDecodingError, UnifiedEncodingError};

    #[cfg(feature = "sapling")]
    use crate::keys::sapling;

    use zcash_address::unified::Typecode;

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
            let extsk = sapling::spending_key(&[0; 32], 0, AccountId::ZERO)
                .expect("the derivation path yields a valid key");
            let dfvk = extsk.to_diversifiable_full_viewing_key();
            Some(dfvk.default_address().1)
        };

        // Every encoding must retain the transparent receiver alongside the shielded ones.
        for transparent in [None, Some(TransparentAddress::PublicKeyHash([0; 20]))] {
            #[cfg(all(feature = "orchard", feature = "sapling"))]
            let ua =
                UnifiedAddress::from_receivers(orchard, sapling, transparent, None, None).unwrap();

            #[cfg(all(not(feature = "orchard"), feature = "sapling"))]
            let ua = UnifiedAddress::from_receivers(sapling, transparent, None, None).unwrap();

            #[cfg(all(feature = "orchard", not(feature = "sapling")))]
            let ua = UnifiedAddress::from_receivers(orchard, transparent, None, None).unwrap();

            let addr = Address::from(ua);
            assert_eq!(
                Address::decode(&MAIN_NETWORK, &addr.encode(&MAIN_NETWORK)),
                Some(addr.clone())
            );
            for revision in [Revision::R0, Revision::R2] {
                let addr_str = addr.encode_revision(&MAIN_NETWORK, revision).expect(
                    "a shielded address without metadata has an encoding at every revision",
                );
                assert_eq!(
                    Address::decode(&MAIN_NETWORK, &addr_str),
                    Some(addr.clone())
                );
            }
        }
    }

    #[test]
    #[cfg(not(any(feature = "orchard", feature = "sapling")))]
    fn ua_round_trip() {
        let transparent = None;
        assert_eq!(
            UnifiedAddress::from_receivers(transparent, None, None),
            None
        )
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

    #[test]
    fn r0_test_vectors_reencode_identically() {
        for tv in test_vectors::UNIFIED {
            let ua = UnifiedAddress::decode(&MAIN_NETWORK, tv.unified_addr)
                .expect("test vector is a valid unified address");
            assert_eq!(
                ua.encode_revision(&MAIN_NETWORK, Revision::R0).as_deref(),
                Ok(tv.unified_addr),
            );
            // Revision 0 can represent every test vector, so it is the compatible choice.
            assert_eq!(ua.encode(&MAIN_NETWORK), tv.unified_addr,);
        }
    }

    /// The lowest data typecode that ZIP 316 does not assign to a receiver type.
    const UNASSIGNED_DATA_TYPECODE: u32 = 0x04;
    /// The lowest metadata typecode in the ZIP 316 SHOULD-understand range.
    const SHOULD_UNDERSTAND_METADATA_TYPECODE: u32 = 0xC0;
    /// Payload bytes for the unknown items in the pruning tests.
    const UNKNOWN_ITEM_DATA: [u8; 4] = [0xAB; 4];
    /// Payload bytes for an unknown receiver that, alone in an address, meets the minimum
    /// encoded length.
    const UNKNOWN_RECEIVER_DATA: [u8; 32] = [0xCD; 32];
    /// Hash bytes for the P2PKH receiver in the pruning tests.
    const P2PKH_HASH: [u8; 20] = [0x11; 20];
    /// Expiry height for the pruning tests.
    const EXPIRY_HEIGHT: u32 = 3_000_000;

    /// A Revision 2 address with a P2PKH receiver, an unknown receiver that holds
    /// `receiver_data`, and an unknown SHOULD-understand metadata item.
    fn address_with_unknown_items(receiver_data: &[u8]) -> UnifiedAddress {
        let container = unified::Address::try_from_items(
            Revision::R2,
            vec![
                Uitem::Data(unified::Receiver::P2pkh(P2PKH_HASH)),
                Uitem::Data(unified::Receiver::Unknown {
                    typecode: UNASSIGNED_DATA_TYPECODE,
                    data: receiver_data.to_vec(),
                }),
                Uitem::Metadata(MetadataItem::Unknown {
                    typecode: SHOULD_UNDERSTAND_METADATA_TYPECODE,
                    data: UNKNOWN_ITEM_DATA.to_vec(),
                }),
            ],
        )
        .expect("the items form a valid Revision 2 address");
        UnifiedAddress::try_from(container).expect("the receivers are valid")
    }

    fn unassigned_data_typecode() -> Typecode {
        Typecode::try_from(UNASSIGNED_DATA_TYPECODE).unwrap()
    }

    fn should_understand_metadata_typecode() -> Typecode {
        Typecode::try_from(SHOULD_UNDERSTAND_METADATA_TYPECODE).unwrap()
    }

    #[test]
    fn prune_retaining_removes_unrequested_items() {
        let ua = address_with_unknown_items(&UNKNOWN_RECEIVER_DATA);

        let pruned = ua
            .prune_retaining(&[unassigned_data_typecode()])
            .unwrap()
            .expect("the unknown receiver remains");
        assert!(!pruned.has_transparent());
        assert_eq!(
            pruned.unknown(),
            &[(UNASSIGNED_DATA_TYPECODE, UNKNOWN_RECEIVER_DATA.to_vec())]
        );
        // The SHOULD-understand metadata item is removed, and the result round-trips.
        assert_eq!(
            UnifiedAddress::decode(&MAIN_NETWORK, &pruned.encode(&MAIN_NETWORK)),
            Ok(pruned.clone())
        );

        let pruned = ua
            .prune_retaining(&[Typecode::P2PKH])
            .unwrap()
            .expect("the transparent receiver remains");
        assert_eq!(
            pruned.transparent(),
            Some(&TransparentAddress::PublicKeyHash(P2PKH_HASH))
        );
        assert!(pruned.unknown().is_empty());
    }

    #[test]
    fn prune_retaining_to_unencodable_address_is_error() {
        let ua = address_with_unknown_items(&UNKNOWN_ITEM_DATA);
        assert_matches!(
            ua.prune_retaining(&[unassigned_data_typecode()]),
            Err(PruneError::NotRepresentable(
                ParseError::InvalidEncodedLength(_)
            ))
        );
    }

    #[test]
    fn prune_retaining_to_every_item_type_is_identity() {
        let ua = address_with_unknown_items(&UNKNOWN_RECEIVER_DATA);
        assert_eq!(
            ua.prune_retaining(&[
                Typecode::P2PKH,
                unassigned_data_typecode(),
                should_understand_metadata_typecode(),
            ]),
            Ok(Some(ua))
        );
    }

    #[test]
    fn prune_retaining_without_receivers_is_none() {
        let ua = address_with_unknown_items(&UNKNOWN_RECEIVER_DATA);
        assert_eq!(ua.prune_retaining(&[]), Ok(None));
        assert_eq!(
            ua.prune_retaining(&[should_understand_metadata_typecode()]),
            Ok(None)
        );
    }

    #[test]
    fn prune_retaining_retains_must_understand_metadata() {
        let ua = UnifiedAddress::from_receivers(
            #[cfg(feature = "orchard")]
            None,
            #[cfg(feature = "sapling")]
            None,
            Some(TransparentAddress::PublicKeyHash(P2PKH_HASH)),
            Some(BlockHeight::from_u32(EXPIRY_HEIGHT)),
            None,
        )
        .expect("a transparent-only unified address is valid");

        assert_eq!(
            ua.prune_retaining(&[Typecode::P2PKH]),
            Err(PruneError::MustUnderstandMetadata(
                MetadataTypecode::ExpiryHeight
            ))
        );
        // An address without receivers still may not drop MUST-understand metadata.
        assert_eq!(
            ua.prune_retaining(&[]),
            Err(PruneError::MustUnderstandMetadata(
                MetadataTypecode::ExpiryHeight
            ))
        );
        assert_eq!(
            ua.prune_retaining(&[Typecode::P2PKH, MetadataTypecode::ExpiryHeight.into()]),
            Ok(Some(ua))
        );
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn prune_retaining_removes_transparent_receiver() {
        let sk = orchard::keys::SpendingKey::from_zip32_seed(&[0; 32], 0, AccountId::ZERO).unwrap();
        let orchard = orchard::keys::FullViewingKey::from(&sk)
            .address_at(0u32, orchard::keys::Scope::External);
        let ua = UnifiedAddress::from_receivers(
            Some(orchard),
            #[cfg(feature = "sapling")]
            None,
            Some(TransparentAddress::PublicKeyHash(P2PKH_HASH)),
            None,
            None,
        )
        .unwrap();

        let pruned = ua
            .prune_retaining(&[Typecode::ORCHARD])
            .unwrap()
            .expect("the Orchard receiver remains");
        assert_eq!(pruned.orchard(), Some(&orchard));
        assert!(!pruned.has_transparent());
        assert_eq!(
            UnifiedAddress::decode(&MAIN_NETWORK, &pruned.encode(&MAIN_NETWORK)),
            Ok(pruned)
        );
    }

    #[test]
    fn decode_reports_structured_errors() {
        let tv = &test_vectors::UNIFIED[0];
        assert_eq!(
            UnifiedAddress::decode(&TEST_NETWORK, tv.unified_addr),
            Err(UnifiedDecodingError::NetworkMismatch {
                expected: NetworkType::Test,
                actual: NetworkType::Main,
            })
        );

        assert_matches!(
            UnifiedAddress::decode(&MAIN_NETWORK, "not an address"),
            Err(UnifiedDecodingError::Parse(_))
        );

        // An Orchard receiver whose bytes do not encode a valid Orchard address.
        const INVALID_ORCHARD_RECEIVER: [u8; 43] = [0xff; 43];
        let invalid = unified::Address::try_from_items(
            Revision::R0,
            vec![Uitem::Data(unified::Receiver::Orchard(
                INVALID_ORCHARD_RECEIVER,
            ))],
        )
        .unwrap()
        .encode(&NetworkType::Main);
        #[cfg(feature = "orchard")]
        assert_eq!(
            UnifiedAddress::decode(&MAIN_NETWORK, &invalid),
            Err(UnifiedDecodingError::InvalidItem(Typecode::ORCHARD))
        );
        #[cfg(not(feature = "orchard"))]
        assert!(UnifiedAddress::decode(&MAIN_NETWORK, &invalid).is_ok());
    }

    #[test]
    fn transparent_only_address_has_no_r0_encoding() {
        let ua = UnifiedAddress::from_receivers(
            #[cfg(feature = "orchard")]
            None,
            #[cfg(feature = "sapling")]
            None,
            Some(TransparentAddress::PublicKeyHash([0; 20])),
            None,
            None,
        )
        .expect("a transparent-only unified address is valid");

        assert_eq!(
            ua.encode_revision(&MAIN_NETWORK, Revision::R0),
            Err(UnifiedEncodingError::NotRepresentable {
                revision: Revision::R0,
                cause: ParseError::OnlyTransparent,
            })
        );
        let encoded = ua
            .encode_revision(&MAIN_NETWORK, Revision::R2)
            .expect("every address has a Revision 2 encoding");
        // Revision 2 is the only revision that can represent this address.
        assert_eq!(ua.encode(&MAIN_NETWORK), encoded);
        assert_eq!(UnifiedAddress::decode(&MAIN_NETWORK, &encoded), Ok(ua));
    }
}
