//! Types and serialization for the extensible V6 transaction format.
//!
//! This module implements the extensible transaction format specified in the
//! draft extensible transaction format ZIP. The format uses a type-length-value
//! encoding for protocol bundles and a value pool delta map for describing
//! balance changes.

use alloc::vec::Vec;
use core::convert::TryInto;
use core2::io::{self, Read, Write};

use crate::encoding::{ReadBytesExt, WriteBytesExt};
use zcash_encoding::CompactSize;
use zcash_protocol::value::ZatBalance;

/// Helper to convert u64 to usize safely.
fn u64_to_usize(value: u64) -> io::Result<usize> {
    value.try_into().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "value too large for usize")
    })
}

/// Bundle type identifiers as defined in the extensible transaction format.
///
/// Bundle types are identified by compactSize integers. Known bundle types
/// have specific semantics; unknown types can be parsed opaquely.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
pub enum BundleType {
    /// Transparent bundle (inputs/outputs).
    Transparent = 0,
    /// Reserved (not used).
    Reserved = 1,
    /// Sapling bundle (shielded spends/outputs).
    Sapling = 2,
    /// Orchard bundle (actions).
    Orchard = 3,
    /// Transaction fee (value deltas only, no effect/auth data).
    Fee = 4,
    /// ZIP 233 NSM field (value deltas only, no effect/auth data).
    Zip233Nsm = 5,
    /// Key rotation (effects & auth only, no value deltas).
    KeyRotation = 6,
    /// Lockbox disbursement.
    LockboxDisbursement = 7,
}

impl BundleType {
    /// Creates a BundleType from a u64 value.
    ///
    /// Returns `Some(BundleType)` for known bundle types, `None` for unknown types.
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0 => Some(BundleType::Transparent),
            1 => Some(BundleType::Reserved),
            2 => Some(BundleType::Sapling),
            3 => Some(BundleType::Orchard),
            4 => Some(BundleType::Fee),
            5 => Some(BundleType::Zip233Nsm),
            6 => Some(BundleType::KeyRotation),
            7 => Some(BundleType::LockboxDisbursement),
            _ => None,
        }
    }

    /// Returns true if this bundle type may have entries in mValuePoolDeltas.
    pub fn has_value_pool_deltas(&self) -> bool {
        match self {
            BundleType::Transparent => true,
            BundleType::Reserved => false,
            BundleType::Sapling => true,
            BundleType::Orchard => true,
            BundleType::Fee => true,
            BundleType::Zip233Nsm => true,
            BundleType::KeyRotation => false,
            BundleType::LockboxDisbursement => true,
        }
    }

    /// Returns true if this bundle type may have entries in mEffectBundles.
    pub fn has_effect_bundles(&self) -> bool {
        match self {
            BundleType::Transparent => true,
            BundleType::Reserved => false,
            BundleType::Sapling => true,
            BundleType::Orchard => true,
            BundleType::Fee => false,
            BundleType::Zip233Nsm => false,
            BundleType::KeyRotation => true,
            BundleType::LockboxDisbursement => true,
        }
    }

    /// Returns true if this bundle type may have entries in mAuthBundles.
    pub fn has_auth_bundles(&self) -> bool {
        match self {
            BundleType::Transparent => true,
            BundleType::Reserved => false,
            BundleType::Sapling => true,
            BundleType::Orchard => true,
            BundleType::Fee => false,
            BundleType::Zip233Nsm => false,
            BundleType::KeyRotation => true,
            BundleType::LockboxDisbursement => true,
        }
    }
}

/// Asset class identifiers for value pool deltas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetClass {
    /// ZEC (native asset), no UUID required.
    Zec = 0,
    /// Other asset (e.g., ZSA), requires a 64-byte UUID.
    Other = 1,
}

impl AssetClass {
    /// Creates an AssetClass from a byte value.
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(AssetClass::Zec),
            1 => Some(AssetClass::Other),
            _ => None,
        }
    }
}

/// A universally unique identifier for an asset (64 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetUuid(pub [u8; 64]);

impl AssetUuid {
    /// Reads an AssetUuid from a reader.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut uuid = [0u8; 64];
        reader.read_exact(&mut uuid)?;
        Ok(AssetUuid(uuid))
    }

    /// Writes the AssetUuid to a writer.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }
}

/// Represents a single entry in the mValuePoolDeltas map.
///
/// Each entry describes the change to the transparent transaction value pool
/// produced by a specific bundle for a specific asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValuePoolDelta {
    /// The bundle type identifier.
    pub bundle_type: u64,
    /// The asset class (ZEC or other).
    pub asset_class: AssetClass,
    /// The asset UUID (present only for non-ZEC assets).
    pub asset_uuid: Option<AssetUuid>,
    /// The net change to the value pool (must be non-zero).
    pub value: i64,
}

impl ValuePoolDelta {
    /// Creates a new ValuePoolDelta for ZEC.
    pub fn zec(bundle_type: u64, value: i64) -> Self {
        ValuePoolDelta {
            bundle_type,
            asset_class: AssetClass::Zec,
            asset_uuid: None,
            value,
        }
    }

    /// Creates a new ValuePoolDelta for a non-ZEC asset.
    pub fn other(bundle_type: u64, asset_uuid: AssetUuid, value: i64) -> Self {
        ValuePoolDelta {
            bundle_type,
            asset_class: AssetClass::Other,
            asset_uuid: Some(asset_uuid),
            value,
        }
    }

    /// Reads a ValuePoolDelta from a reader.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let bundle_type = CompactSize::read(&mut reader)?;
        let asset_class_byte = reader.read_u8()?;
        let asset_class = AssetClass::from_byte(asset_class_byte).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid asset class: {}", asset_class_byte),
            )
        })?;

        let asset_uuid = match asset_class {
            AssetClass::Zec => None,
            AssetClass::Other => Some(AssetUuid::read(&mut reader)?),
        };

        let value = reader.read_i64_le()?;

        // Consensus rule: value must be non-zero
        if value == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "value pool delta value must be non-zero",
            ));
        }

        Ok(ValuePoolDelta {
            bundle_type,
            asset_class,
            asset_uuid,
            value,
        })
    }

    /// Writes the ValuePoolDelta to a writer.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.bundle_type as usize)?;
        writer.write_u8(self.asset_class as u8)?;
        if let Some(ref uuid) = self.asset_uuid {
            uuid.write(&mut writer)?;
        }
        writer.write_i64_le(self.value)?;
        Ok(())
    }
}

/// Raw bundle data for an unknown or partially-parsed bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawBundleData {
    /// The bundle type identifier.
    pub bundle_type: u64,
    /// The raw bundle data bytes.
    pub data: Vec<u8>,
}

impl RawBundleData {
    /// Reads a RawBundleData entry from a reader.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let bundle_type = CompactSize::read(&mut reader)?;
        let data_len = CompactSize::read(&mut reader)?;
        let mut data = vec![0u8; u64_to_usize(data_len)?];
        reader.read_exact(&mut data)?;
        Ok(RawBundleData { bundle_type, data })
    }

    /// Writes the RawBundleData to a writer.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.bundle_type as usize)?;
        CompactSize::write(&mut writer, self.data.len())?;
        writer.write_all(&self.data)?;
        Ok(())
    }
}

/// Container for the V6Ext transaction maps.
///
/// This holds the raw data from the three main components of the extensible
/// transaction format: value pool deltas, effect bundles, and auth bundles.
#[derive(Clone, Debug, Default)]
pub struct V6ExtMaps {
    /// The value pool deltas map.
    pub value_pool_deltas: Vec<ValuePoolDelta>,
    /// The effect bundles map (raw data for each bundle type).
    pub effect_bundles: Vec<RawBundleData>,
    /// The auth bundles map (raw data for each bundle type).
    pub auth_bundles: Vec<RawBundleData>,
}

impl V6ExtMaps {
    /// Creates a new empty V6ExtMaps.
    pub fn new() -> Self {
        V6ExtMaps::default()
    }

    /// Reads the V6ExtMaps from a reader.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        // Read value pool deltas
        let n_value_pool_deltas = CompactSize::read(&mut reader)?;
        let mut value_pool_deltas = Vec::with_capacity(u64_to_usize(n_value_pool_deltas)?);
        for _ in 0..n_value_pool_deltas {
            value_pool_deltas.push(ValuePoolDelta::read(&mut reader)?);
        }

        // Read effect bundles
        let n_effect_bundles = CompactSize::read(&mut reader)?;
        let mut effect_bundles = Vec::with_capacity(u64_to_usize(n_effect_bundles)?);
        for _ in 0..n_effect_bundles {
            effect_bundles.push(RawBundleData::read(&mut reader)?);
        }

        // Read auth bundles
        let n_auth_bundles = CompactSize::read(&mut reader)?;
        let mut auth_bundles = Vec::with_capacity(u64_to_usize(n_auth_bundles)?);
        for _ in 0..n_auth_bundles {
            auth_bundles.push(RawBundleData::read(&mut reader)?);
        }

        Ok(V6ExtMaps {
            value_pool_deltas,
            effect_bundles,
            auth_bundles,
        })
    }

    /// Writes the V6ExtMaps to a writer.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write value pool deltas
        CompactSize::write(&mut writer, self.value_pool_deltas.len())?;
        for delta in &self.value_pool_deltas {
            delta.write(&mut writer)?;
        }

        // Write effect bundles
        CompactSize::write(&mut writer, self.effect_bundles.len())?;
        for bundle in &self.effect_bundles {
            bundle.write(&mut writer)?;
        }

        // Write auth bundles
        CompactSize::write(&mut writer, self.auth_bundles.len())?;
        for bundle in &self.auth_bundles {
            bundle.write(&mut writer)?;
        }

        Ok(())
    }

    /// Gets the value pool delta for a specific bundle type and asset (ZEC).
    pub fn get_zec_delta(&self, bundle_type: u64) -> Option<i64> {
        self.value_pool_deltas
            .iter()
            .find(|d| d.bundle_type == bundle_type && d.asset_class == AssetClass::Zec)
            .map(|d| d.value)
    }

    /// Gets the effect bundle data for a specific bundle type.
    pub fn get_effect_bundle(&self, bundle_type: u64) -> Option<&[u8]> {
        self.effect_bundles
            .iter()
            .find(|b| b.bundle_type == bundle_type)
            .map(|b| b.data.as_slice())
    }

    /// Gets the auth bundle data for a specific bundle type.
    pub fn get_auth_bundle(&self, bundle_type: u64) -> Option<&[u8]> {
        self.auth_bundles
            .iter()
            .find(|b| b.bundle_type == bundle_type)
            .map(|b| b.data.as_slice())
    }

    /// Converts a ZatBalance to a value pool delta value.
    ///
    /// Returns `None` if the balance is zero (zero values should not be stored).
    pub fn balance_to_delta(balance: ZatBalance) -> Option<i64> {
        let value = balance.into();
        if value == 0 { None } else { Some(value) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_pool_delta_roundtrip_zec() {
        let delta = ValuePoolDelta::zec(BundleType::Transparent as u64, 1000);

        let mut buf = Vec::new();
        delta.write(&mut buf).unwrap();

        let parsed = ValuePoolDelta::read(&buf[..]).unwrap();
        assert_eq!(delta, parsed);
    }

    #[test]
    fn test_value_pool_delta_roundtrip_other() {
        let uuid = AssetUuid([42u8; 64]);
        let delta = ValuePoolDelta::other(BundleType::Orchard as u64, uuid, -500);

        let mut buf = Vec::new();
        delta.write(&mut buf).unwrap();

        let parsed = ValuePoolDelta::read(&buf[..]).unwrap();
        assert_eq!(delta, parsed);
    }

    #[test]
    fn test_value_pool_delta_rejects_zero() {
        let delta = ValuePoolDelta::zec(BundleType::Fee as u64, 0);

        let mut buf = Vec::new();
        delta.write(&mut buf).unwrap();

        let result = ValuePoolDelta::read(&buf[..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_raw_bundle_data_roundtrip() {
        let bundle = RawBundleData {
            bundle_type: BundleType::Sapling as u64,
            data: vec![1, 2, 3, 4, 5],
        };

        let mut buf = Vec::new();
        bundle.write(&mut buf).unwrap();

        let parsed = RawBundleData::read(&buf[..]).unwrap();
        assert_eq!(bundle, parsed);
    }

    #[test]
    fn test_v6ext_maps_roundtrip() {
        let maps = V6ExtMaps {
            value_pool_deltas: vec![
                ValuePoolDelta::zec(BundleType::Transparent as u64, 1000),
                ValuePoolDelta::zec(BundleType::Sapling as u64, -500),
                ValuePoolDelta::zec(BundleType::Fee as u64, -500),
            ],
            effect_bundles: vec![
                RawBundleData {
                    bundle_type: BundleType::Transparent as u64,
                    data: vec![1, 2, 3],
                },
                RawBundleData {
                    bundle_type: BundleType::Sapling as u64,
                    data: vec![4, 5, 6, 7],
                },
            ],
            auth_bundles: vec![RawBundleData {
                bundle_type: BundleType::Transparent as u64,
                data: vec![8, 9],
            }],
        };

        let mut buf = Vec::new();
        maps.write(&mut buf).unwrap();

        let parsed = V6ExtMaps::read(&buf[..]).unwrap();
        assert_eq!(maps.value_pool_deltas.len(), parsed.value_pool_deltas.len());
        assert_eq!(maps.effect_bundles.len(), parsed.effect_bundles.len());
        assert_eq!(maps.auth_bundles.len(), parsed.auth_bundles.len());
    }

    #[test]
    fn test_bundle_type_properties() {
        // Fee bundle has value deltas but no effects/auth
        assert!(BundleType::Fee.has_value_pool_deltas());
        assert!(!BundleType::Fee.has_effect_bundles());
        assert!(!BundleType::Fee.has_auth_bundles());

        // KeyRotation has effects/auth but no value deltas
        assert!(!BundleType::KeyRotation.has_value_pool_deltas());
        assert!(BundleType::KeyRotation.has_effect_bundles());
        assert!(BundleType::KeyRotation.has_auth_bundles());

        // Standard bundles have all three
        assert!(BundleType::Transparent.has_value_pool_deltas());
        assert!(BundleType::Transparent.has_effect_bundles());
        assert!(BundleType::Transparent.has_auth_bundles());
    }
}
