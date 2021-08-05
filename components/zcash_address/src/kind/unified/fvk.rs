use std::cmp;
use std::convert::{TryFrom, TryInto};

use crate::kind;

use super::{
    private::{SealedContainer, SealedItem},
    Encoding, ParseError, Container, Typecode,
};

/// The set of known FVKs for Unified FVKs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Fvk {
    /// The raw encoding of an Orchard Full Viewing Key.
    ///
    /// `(ak, nk, rivk)` each 32 bytes.
    Orchard([u8; 96]),

    /// Data contained within the Sapling component of a Unified Full Viewing Key
    ///
    /// `(ak, nk, ovk)` each 32 bytes.
    Sapling([u8; 96]),

    /// The extended public key for the BIP 44 account corresponding to the transparent
    /// address subtree from which transparent addresses are derived.
    ///
    /// Transparent addresses don't have "viewing keys" - the addresses themselves serve
    /// that purpose. However, we want the ability to derive diversified Unified Addresses
    /// from Unified Viewing Keys, and to not break the unlinkability property when they
    /// include transparent receivers. To achieve this, we treat the last hardened node in
    /// the BIP 44 derivation path as the "transparent viewing key"; all addresses derived
    /// from this node use non-hardened derivation, and can thus be derived just from this
    /// extended public key.
    P2pkh([u8; 78]),

    /// The raw data of a P2SH address.
    ///
    /// # Security
    ///
    /// P2SH addresses are hashes of scripts, and as such have no generic HD mechanism for
    /// us to derive independent-but-linked P2SH addresses. As such, if someone constructs
    /// a UFVK containing a P2SH address, and then derives diversified UAs from it, those
    /// UAs will be trivially linkable as they will share the same P2SH address.
    P2sh(kind::p2sh::Data),

    Unknown {
        typecode: u32,
        data: Vec<u8>,
    },
}

impl cmp::Ord for Fvk {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.typecode().cmp(&other.typecode()) {
            cmp::Ordering::Equal => self.data().cmp(other.data()),
            res => res,
        }
    }
}

impl cmp::PartialOrd for Fvk {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<(u32, &[u8])> for Fvk {
    type Error = ParseError;

    fn try_from((typecode, data): (u32, &[u8])) -> Result<Self, Self::Error> {
        match typecode.try_into()? {
            Typecode::P2pkh => data.try_into().map(Fvk::P2pkh),
            Typecode::P2sh => data.try_into().map(Fvk::P2sh),
            Typecode::Sapling => data.try_into().map(Fvk::Sapling),
            Typecode::Orchard => data.try_into().map(Fvk::Orchard),
            Typecode::Unknown(_) => Ok(Fvk::Unknown {
                typecode,
                data: data.to_vec(),
            }),
        }
        .map_err(|e| {
            ParseError::InvalidEncoding(format!("Invalid fvk for typecode {}: {:?}", typecode, e))
        })
    }
}

impl SealedItem for Fvk {
    fn typecode(&self) -> Typecode {
        match self {
            Fvk::P2pkh(_) => Typecode::P2pkh,
            Fvk::P2sh(_) => Typecode::P2sh,
            Fvk::Sapling(_) => Typecode::Sapling,
            Fvk::Orchard(_) => Typecode::Orchard,
            Fvk::Unknown { typecode, .. } => Typecode::Unknown(*typecode),
        }
    }

    fn data(&self) -> &[u8] {
        match self {
            Fvk::P2pkh(data) => data,
            Fvk::P2sh(data) => data,
            Fvk::Sapling(data) => data,
            Fvk::Orchard(data) => data,
            Fvk::Unknown { data, .. } => data,
        }
    }
}

/// A Unified Full Viewing Key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ufvk(pub(crate) Vec<Fvk>);

impl Container for Ufvk {
    type Item = Fvk;

    /// Returns the FVKs contained within this UFVK, in the order they were
    /// parsed from the string encoding.
    ///
    /// This API is for advanced usage; in most cases you should use `Ufvk::receivers`.
    fn items_as_parsed(&self) -> &[Fvk] {
        &self.0
    }
}
impl Encoding for Ufvk {}

impl SealedContainer for Ufvk {
    /// The HRP for a Bech32m-encoded mainnet Unified FVK.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const MAINNET: &'static str = "uview";

    /// The HRP for a Bech32m-encoded testnet Unified FVK.
    ///
    /// Defined in [ZIP 316][zip-0316].
    ///
    /// [zip-0316]: https://zips.z.cash/zip-0316
    const TESTNET: &'static str = "uviewtest";

    /// The HRP for a Bech32m-encoded regtest Unified FVK.
    const REGTEST: &'static str = "uviewregtest";

    fn from_inner(fvks: Vec<Self::Item>) -> Self {
        Self(fvks)
    }
}
