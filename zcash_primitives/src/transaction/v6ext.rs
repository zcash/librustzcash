//! Types and serialization for the extensible V6 transaction format.
//!
//! This module implements the extensible transaction format specified in the
//! draft extensible transaction format ZIP. The format uses a type-length-value
//! encoding for protocol bundles and a value pool delta map for describing
//! balance changes.

use alloc::collections::BTreeMap;
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Key for the mValuePoolDeltas map.
///
/// Entries are keyed by (bundleType, assetClass, assetUuid) and must be
/// stored in increasing order of this tuple.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValuePoolDeltaKey {
    /// The bundle type identifier.
    pub bundle_type: u64,
    /// The asset class (ZEC or other).
    pub asset_class: AssetClass,
    /// The asset UUID (present only for non-ZEC assets).
    pub asset_uuid: Option<AssetUuid>,
}

impl ValuePoolDeltaKey {
    /// Creates a key for a ZEC value pool delta.
    pub fn zec(bundle_type: u64) -> Self {
        ValuePoolDeltaKey {
            bundle_type,
            asset_class: AssetClass::Zec,
            asset_uuid: None,
        }
    }

    /// Creates a key for a non-ZEC asset value pool delta.
    pub fn other(bundle_type: u64, asset_uuid: AssetUuid) -> Self {
        ValuePoolDeltaKey {
            bundle_type,
            asset_class: AssetClass::Other,
            asset_uuid: Some(asset_uuid),
        }
    }

    /// Reads a ValuePoolDeltaKey from a reader.
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

        Ok(ValuePoolDeltaKey {
            bundle_type,
            asset_class,
            asset_uuid,
        })
    }

    /// Writes the ValuePoolDeltaKey to a writer.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CompactSize::write(&mut writer, self.bundle_type as usize)?;
        writer.write_u8(self.asset_class as u8)?;
        if let Some(ref uuid) = self.asset_uuid {
            uuid.write(&mut writer)?;
        }
        Ok(())
    }
}

/// Represents a single entry in the mValuePoolDeltas map.
///
/// Each entry describes the change to the transparent transaction value pool
/// produced by a specific bundle for a specific asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValuePoolDelta {
    /// The key (bundle_type, asset_class, asset_uuid).
    pub key: ValuePoolDeltaKey,
    /// The net change to the value pool (must be non-zero).
    pub value: i64,
}

impl ValuePoolDelta {
    /// Creates a new ValuePoolDelta for ZEC.
    pub fn zec(bundle_type: u64, value: i64) -> Self {
        ValuePoolDelta {
            key: ValuePoolDeltaKey::zec(bundle_type),
            value,
        }
    }

    /// Creates a new ValuePoolDelta for a non-ZEC asset.
    pub fn other(bundle_type: u64, asset_uuid: AssetUuid, value: i64) -> Self {
        ValuePoolDelta {
            key: ValuePoolDeltaKey::other(bundle_type, asset_uuid),
            value,
        }
    }

    /// Returns the bundle type.
    pub fn bundle_type(&self) -> u64 {
        self.key.bundle_type
    }

    /// Returns the asset class.
    pub fn asset_class(&self) -> AssetClass {
        self.key.asset_class
    }

    /// Returns the asset UUID, if present.
    pub fn asset_uuid(&self) -> Option<&AssetUuid> {
        self.key.asset_uuid.as_ref()
    }

    /// Reads a ValuePoolDelta from a reader.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let key = ValuePoolDeltaKey::read(&mut reader)?;
        let value = reader.read_i64_le()?;

        // Consensus rule: value must be non-zero
        if value == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "value pool delta value must be non-zero",
            ));
        }

        Ok(ValuePoolDelta { key, value })
    }

    /// Writes the ValuePoolDelta to a writer.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.key.write(&mut writer)?;
        writer.write_i64_le(self.value)?;
        Ok(())
    }
}

/// Reads a bundle entry (bundle_type, length, data) and returns (bundle_type, data).
fn read_bundle_entry<R: Read>(mut reader: R) -> io::Result<(u64, Vec<u8>)> {
    let bundle_type = CompactSize::read(&mut reader)?;
    let data_len = CompactSize::read(&mut reader)?;
    let mut data = vec![0u8; u64_to_usize(data_len)?];
    reader.read_exact(&mut data)?;
    Ok((bundle_type, data))
}

/// Writes a bundle entry (bundle_type, length, data).
fn write_bundle_entry<W: Write>(mut writer: W, bundle_type: u64, data: &[u8]) -> io::Result<()> {
    CompactSize::write(&mut writer, bundle_type as usize)?;
    CompactSize::write(&mut writer, data.len())?;
    writer.write_all(data)?;
    Ok(())
}

/// Container for the V6Ext transaction maps.
///
/// This holds the raw data from the three main components of the extensible
/// transaction format: value pool deltas, effect bundles, and auth bundles.
///
/// All maps are stored as BTreeMaps which maintain entries in sorted order
/// by key, as required by the specification.
#[derive(Clone, Debug, Default)]
pub struct V6ExtMaps {
    /// The value pool deltas map, keyed by (bundleType, assetClass, assetUuid).
    pub value_pool_deltas: BTreeMap<ValuePoolDeltaKey, i64>,
    /// The effect bundles map, keyed by bundle type.
    pub effect_bundles: BTreeMap<u64, Vec<u8>>,
    /// The auth bundles map, keyed by bundle type.
    pub auth_bundles: BTreeMap<u64, Vec<u8>>,
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
        let mut value_pool_deltas = BTreeMap::new();
        for _ in 0..n_value_pool_deltas {
            let delta = ValuePoolDelta::read(&mut reader)?;
            value_pool_deltas.insert(delta.key, delta.value);
        }

        // Read effect bundles
        let n_effect_bundles = CompactSize::read(&mut reader)?;
        let mut effect_bundles = BTreeMap::new();
        for _ in 0..n_effect_bundles {
            let (bundle_type, data) = read_bundle_entry(&mut reader)?;
            effect_bundles.insert(bundle_type, data);
        }

        // Read auth bundles
        let n_auth_bundles = CompactSize::read(&mut reader)?;
        let mut auth_bundles = BTreeMap::new();
        for _ in 0..n_auth_bundles {
            let (bundle_type, data) = read_bundle_entry(&mut reader)?;
            auth_bundles.insert(bundle_type, data);
        }

        Ok(V6ExtMaps {
            value_pool_deltas,
            effect_bundles,
            auth_bundles,
        })
    }

    /// Writes the V6ExtMaps to a writer.
    ///
    /// Entries are written in sorted order by key (guaranteed by BTreeMap iteration).
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        // Write value pool deltas (already sorted by BTreeMap)
        CompactSize::write(&mut writer, self.value_pool_deltas.len())?;
        for (key, value) in &self.value_pool_deltas {
            key.write(&mut writer)?;
            writer.write_i64_le(*value)?;
        }

        // Write effect bundles (already sorted by BTreeMap)
        CompactSize::write(&mut writer, self.effect_bundles.len())?;
        for (bundle_type, data) in &self.effect_bundles {
            write_bundle_entry(&mut writer, *bundle_type, data)?;
        }

        // Write auth bundles (already sorted by BTreeMap)
        CompactSize::write(&mut writer, self.auth_bundles.len())?;
        for (bundle_type, data) in &self.auth_bundles {
            write_bundle_entry(&mut writer, *bundle_type, data)?;
        }

        Ok(())
    }

    /// Gets the value pool delta for a specific bundle type and asset (ZEC).
    pub fn get_zec_delta(&self, bundle_type: u64) -> Option<i64> {
        self.value_pool_deltas
            .get(&ValuePoolDeltaKey::zec(bundle_type))
            .copied()
    }

    /// Gets the effect bundle data for a specific bundle type.
    pub fn get_effect_bundle(&self, bundle_type: u64) -> Option<&[u8]> {
        self.effect_bundles.get(&bundle_type).map(|v| v.as_slice())
    }

    /// Gets the auth bundle data for a specific bundle type.
    pub fn get_auth_bundle(&self, bundle_type: u64) -> Option<&[u8]> {
        self.auth_bundles.get(&bundle_type).map(|v| v.as_slice())
    }

    /// Inserts a ZEC value pool delta.
    ///
    /// Returns the previous value if one existed for this key.
    pub fn insert_zec_delta(&mut self, bundle_type: u64, value: i64) -> Option<i64> {
        self.value_pool_deltas
            .insert(ValuePoolDeltaKey::zec(bundle_type), value)
    }

    /// Inserts an effect bundle.
    ///
    /// Returns the previous data if one existed for this bundle type.
    pub fn insert_effect_bundle(&mut self, bundle_type: u64, data: Vec<u8>) -> Option<Vec<u8>> {
        self.effect_bundles.insert(bundle_type, data)
    }

    /// Inserts an auth bundle.
    ///
    /// Returns the previous data if one existed for this bundle type.
    pub fn insert_auth_bundle(&mut self, bundle_type: u64, data: Vec<u8>) -> Option<Vec<u8>> {
        self.auth_bundles.insert(bundle_type, data)
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
    fn test_bundle_entry_roundtrip() {
        let bundle_type = BundleType::Sapling as u64;
        let data = vec![1, 2, 3, 4, 5];

        let mut buf = Vec::new();
        write_bundle_entry(&mut buf, bundle_type, &data).unwrap();

        let (parsed_type, parsed_data) = read_bundle_entry(&buf[..]).unwrap();
        assert_eq!(bundle_type, parsed_type);
        assert_eq!(data, parsed_data);
    }

    #[test]
    fn test_v6ext_maps_roundtrip() {
        let mut maps = V6ExtMaps::new();

        // Insert value pool deltas
        maps.insert_zec_delta(BundleType::Transparent as u64, 1000);
        maps.insert_zec_delta(BundleType::Sapling as u64, -500);
        maps.insert_zec_delta(BundleType::Fee as u64, -500);

        // Insert effect bundles
        maps.insert_effect_bundle(BundleType::Transparent as u64, vec![1, 2, 3]);
        maps.insert_effect_bundle(BundleType::Sapling as u64, vec![4, 5, 6, 7]);

        // Insert auth bundles
        maps.insert_auth_bundle(BundleType::Transparent as u64, vec![8, 9]);

        let mut buf = Vec::new();
        maps.write(&mut buf).unwrap();

        let parsed = V6ExtMaps::read(&buf[..]).unwrap();
        assert_eq!(maps.value_pool_deltas, parsed.value_pool_deltas);
        assert_eq!(maps.effect_bundles, parsed.effect_bundles);
        assert_eq!(maps.auth_bundles, parsed.auth_bundles);
    }

    #[test]
    fn test_v6ext_maps_ordering() {
        let mut maps = V6ExtMaps::new();

        // Insert in non-sorted order
        maps.insert_zec_delta(BundleType::Fee as u64, -500);
        maps.insert_zec_delta(BundleType::Transparent as u64, 1000);
        maps.insert_zec_delta(BundleType::Sapling as u64, -500);

        // BTreeMap should maintain sorted order
        let keys: Vec<_> = maps.value_pool_deltas.keys().collect();
        assert_eq!(keys[0].bundle_type, BundleType::Transparent as u64);
        assert_eq!(keys[1].bundle_type, BundleType::Sapling as u64);
        assert_eq!(keys[2].bundle_type, BundleType::Fee as u64);
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
