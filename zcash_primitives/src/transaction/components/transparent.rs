//! Functions for parsing & serialization of transparent transaction components.
//!
//! The types in this module are a byte-level codec for the transparent bundle's
//! wire structures. They deliberately do not construct
//! [`transparent::bundle`] domain values while parsing: a transparent bundle can
//! be read, retained, and re-serialized without interpreting its scripts or
//! checking any consensus rule. Explicit conversions to and from the domain
//! types are provided at the end of the module.
//!
//! Two wire layouts are covered:
//!
//! - The legacy layout used by transaction versions before v7, in which each
//!   input carries its `scriptSig` inline ([`LegacyTransparentBundleBytes`]).
//! - The [ZIP 248] v7 layout, which splits the bundle into effecting data
//!   (`TransparentEffectsBytes`) and authorizing data (`TransparentAuthBytes`)
//!   that are carried in separate bundle maps (`TransparentBundleBytes`). The
//!   v7 types require `zcash_unstable="nu8"`.
//!
//! [ZIP 248]: https://zips.z.cash/zip-0248#transparent-bundle

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::{CompactSize, Vector};
use zcash_protocol::TxId;

/// The size in bytes of a transparent prevout index.
const PREVOUT_INDEX_BYTE_SIZE: usize = 4;
/// The size in bytes of a transparent sequence number.
const SEQUENCE_BYTE_SIZE: usize = 4;
/// The size in bytes of a transparent output value.
const VALUE_BYTE_SIZE: usize = 8;

/// Reads `count` elements, growing the result as elements are decoded.
///
/// The count comes from the wire, so it must not be used to reserve capacity up
/// front: a claimed count that the remaining bytes cannot satisfy fails on the
/// first missing element without allocating for the whole claim.
fn read_array<R: Read, E, F>(mut reader: R, count: usize, mut func: F) -> io::Result<Vec<E>>
where
    F: FnMut(&mut R) -> io::Result<E>,
{
    let mut items = Vec::new();
    for _ in 0..count {
        items.push(func(&mut reader)?);
    }
    Ok(items)
}

/// Reads a CompactSize-prefixed vector, growing the result as elements are
/// decoded.
fn read_vector<R: Read, E, F>(mut reader: R, func: F) -> io::Result<Vec<E>>
where
    F: FnMut(&mut R) -> io::Result<E>,
{
    let count = CompactSize::read_t::<_, usize>(&mut reader)?;
    read_array(reader, count, func)
}

/// Opaque script bytes from a transparent input or output.
///
/// The bytes are retained verbatim. Interpreting them as a script, or checking
/// that they are well-formed, is a domain concern handled by the conversion
/// methods rather than by the wire codec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransparentScriptBytes {
    bytes: Vec<u8>,
}

impl TransparentScriptBytes {
    /// Constructs script bytes from their raw encoding.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the raw script bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes this value, returning the raw script bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Reads a CompactSize-prefixed script.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self::from_bytes(Vector::read_bytes(&mut reader)?))
    }

    /// Writes this script with its CompactSize length prefix.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write_bytes(&mut writer, &self.bytes)
    }
}

/// A transparent output's value as it appears on the wire.
///
/// The value is a signed 64-bit integer. The monetary range check is a
/// consensus rule, so it is applied when converting to
/// [`transparent::bundle::TxOut`] rather than while parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransparentOutputValueBytes {
    value: i64,
}

impl TransparentOutputValueBytes {
    /// Constructs a wire value from its signed 64-bit encoding.
    pub const fn from_i64(value: i64) -> Self {
        Self { value }
    }

    /// Returns the signed 64-bit encoding of this value.
    pub const fn to_i64(self) -> i64 {
        self.value
    }

    /// Reads a wire value from its little-endian 8-byte encoding.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut value = [0u8; VALUE_BYTE_SIZE];
        reader.read_exact(&mut value)?;
        Ok(Self::from_i64(i64::from_le_bytes(value)))
    }

    /// Writes this wire value in its little-endian 8-byte encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.value.to_le_bytes())
    }
}

/// A transparent outpoint in its wire representation.
///
/// The hash is the transaction ID of the output being spent, and the index is
/// its position within that transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransparentOutPointBytes {
    hash: TxId,
    index: u32,
}

impl TransparentOutPointBytes {
    /// Constructs an outpoint from its wire fields.
    pub const fn from_parts(hash: TxId, index: u32) -> Self {
        Self { hash, index }
    }

    /// Returns the transaction ID of the output being spent.
    pub const fn hash(&self) -> &TxId {
        &self.hash
    }

    /// Returns the index of the output being spent within its transaction.
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Reads an outpoint from its canonical binary encoding: a 32-byte txid
    /// followed by the output index as a little-endian `u32`.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let hash = TxId::read(&mut reader)?;
        let mut index = [0u8; PREVOUT_INDEX_BYTE_SIZE];
        reader.read_exact(&mut index)?;
        Ok(Self::from_parts(hash, u32::from_le_bytes(index)))
    }

    /// Writes this outpoint in its canonical binary encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.hash.write(&mut writer)?;
        writer.write_all(&self.index.to_le_bytes())
    }
}

/// A transparent output in its wire representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentOutputBytes {
    value: TransparentOutputValueBytes,
    script_pubkey: TransparentScriptBytes,
}

impl TransparentOutputBytes {
    /// Constructs an output from its wire fields.
    pub fn from_parts(
        value: TransparentOutputValueBytes,
        script_pubkey: TransparentScriptBytes,
    ) -> Self {
        Self {
            value,
            script_pubkey,
        }
    }

    /// Returns the output value as encoded on the wire.
    pub const fn value(&self) -> TransparentOutputValueBytes {
        self.value
    }

    /// Returns the raw `scriptPubKey` bytes.
    pub const fn script_pubkey(&self) -> &TransparentScriptBytes {
        &self.script_pubkey
    }

    /// Reads an output from its canonical binary encoding: an 8-byte
    /// little-endian value followed by a CompactSize-prefixed script.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let value = TransparentOutputValueBytes::read(&mut reader)?;
        let script_pubkey = TransparentScriptBytes::read(&mut reader)?;
        Ok(Self::from_parts(value, script_pubkey))
    }

    /// Writes this output in its canonical binary encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.value.write(&mut writer)?;
        self.script_pubkey.write(&mut writer)
    }
}

/// A transparent input in the legacy (pre-v7) wire representation.
///
/// The `scriptSig` is carried inline with the outpoint and sequence number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyTransparentInputBytes {
    prevout: TransparentOutPointBytes,
    script_sig: TransparentScriptBytes,
    sequence: u32,
}

impl LegacyTransparentInputBytes {
    /// Constructs an input from its wire fields.
    pub fn from_parts(
        prevout: TransparentOutPointBytes,
        script_sig: TransparentScriptBytes,
        sequence: u32,
    ) -> Self {
        Self {
            prevout,
            script_sig,
            sequence,
        }
    }

    /// Returns the outpoint being spent.
    pub const fn prevout(&self) -> &TransparentOutPointBytes {
        &self.prevout
    }

    /// Returns the raw `scriptSig` bytes.
    pub const fn script_sig(&self) -> &TransparentScriptBytes {
        &self.script_sig
    }

    /// Returns the input's sequence number.
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Reads an input from its canonical binary encoding: an outpoint, a
    /// CompactSize-prefixed `scriptSig`, and a little-endian `u32` sequence.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let prevout = TransparentOutPointBytes::read(&mut reader)?;
        let script_sig = TransparentScriptBytes::read(&mut reader)?;
        let mut sequence = [0u8; SEQUENCE_BYTE_SIZE];
        reader.read_exact(&mut sequence)?;
        Ok(Self::from_parts(
            prevout,
            script_sig,
            u32::from_le_bytes(sequence),
        ))
    }

    /// Writes this input in its canonical binary encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.prevout.write(&mut writer)?;
        self.script_sig.write(&mut writer)?;
        writer.write_all(&self.sequence.to_le_bytes())
    }
}

/// A transparent bundle in the legacy (pre-v7) wire representation.
///
/// The legacy layout is `vin` followed by `vout`, each a CompactSize-prefixed
/// vector. An empty bundle is encoded as two zero counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacyTransparentBundleBytes {
    inputs: Vec<LegacyTransparentInputBytes>,
    outputs: Vec<TransparentOutputBytes>,
}

impl LegacyTransparentBundleBytes {
    /// Constructs a legacy bundle from its wire fields.
    pub fn from_parts(
        inputs: Vec<LegacyTransparentInputBytes>,
        outputs: Vec<TransparentOutputBytes>,
    ) -> Self {
        Self { inputs, outputs }
    }

    /// Returns the bundle's inputs.
    pub fn inputs(&self) -> &[LegacyTransparentInputBytes] {
        &self.inputs
    }

    /// Returns the bundle's outputs.
    pub fn outputs(&self) -> &[TransparentOutputBytes] {
        &self.outputs
    }

    /// Returns `true` if the bundle has neither inputs nor outputs.
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty() && self.outputs.is_empty()
    }

    /// Reads a legacy transparent bundle from its canonical binary encoding.
    ///
    /// This reads exactly the bundle's bytes; any following bytes belong to the
    /// enclosing transaction and are left unread.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let inputs = read_vector(&mut reader, |r| LegacyTransparentInputBytes::read(r))?;
        let outputs = read_vector(&mut reader, |r| TransparentOutputBytes::read(r))?;
        Ok(Self::from_parts(inputs, outputs))
    }

    /// Writes this legacy bundle in its canonical binary encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write(&mut writer, &self.inputs, |w, input| input.write(w))?;
        Vector::write(&mut writer, &self.outputs, |w, output| output.write(w))
    }
}

/// A transparent input's effecting data in a v7 transaction.
///
/// [ZIP 248 §TransparentInputEffecting](https://zips.z.cash/zip-0248#transparentinputeffecting)
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentInputEffectingBytes {
    prevout: TransparentOutPointBytes,
    sequence: u32,
}

#[cfg(zcash_unstable = "nu8")]
impl TransparentInputEffectingBytes {
    /// Constructs an input's effecting data from its wire fields.
    pub const fn from_parts(prevout: TransparentOutPointBytes, sequence: u32) -> Self {
        Self { prevout, sequence }
    }

    /// Returns the outpoint being spent.
    pub const fn prevout(&self) -> &TransparentOutPointBytes {
        &self.prevout
    }

    /// Returns the input's sequence number.
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Reads an input's effecting data: an outpoint followed by a
    /// little-endian `u32` sequence.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let prevout = TransparentOutPointBytes::read(&mut reader)?;
        let mut sequence = [0u8; SEQUENCE_BYTE_SIZE];
        reader.read_exact(&mut sequence)?;
        Ok(Self::from_parts(prevout, u32::from_le_bytes(sequence)))
    }

    /// Writes this input's effecting data.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.prevout.write(&mut writer)?;
        writer.write_all(&self.sequence.to_le_bytes())
    }
}

/// A `TransparentSighashInfo` value in its wire representation.
///
/// [ZIP 248 §Transparent Sighash Information](https://zips.z.cash/zip-0248#transparent-sighash-information-transparentsighashinfo)
///
/// The bytes are retained verbatim. Sighash version 0 is the only version
/// defined for the transparent bundle, and its `sighashInfo` is the single byte
/// `0x00`; [`Self::is_v0`] reports whether that is the case.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentSighashInfoBytes {
    bytes: Vec<u8>,
}

#[cfg(zcash_unstable = "nu8")]
impl TransparentSighashInfoBytes {
    /// Constructs a sighash info value from its raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the sighash version 0 encoding, `[0x00]`.
    pub fn v0() -> Self {
        Self { bytes: vec![0x00] }
    }

    /// Returns the raw `sighashInfo` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns `true` if this is the sighash version 0 encoding.
    pub fn is_v0(&self) -> bool {
        self.bytes == [0x00]
    }

    /// Reads a CompactSize-prefixed `sighashInfo` value.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Self::from_bytes(Vector::read_bytes(&mut reader)?))
    }

    /// Writes this `sighashInfo` value with its CompactSize length prefix.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write_bytes(&mut writer, &self.bytes)
    }
}

/// A transparent input's authorizing data in a v7 transaction.
///
/// [ZIP 248 §TransparentInputAuth](https://zips.z.cash/zip-0248#transparentinputauth)
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentInputAuthBytes {
    sighash_info: TransparentSighashInfoBytes,
    script_sig: TransparentScriptBytes,
}

#[cfg(zcash_unstable = "nu8")]
impl TransparentInputAuthBytes {
    /// Constructs an input's authorizing data from its wire fields.
    pub fn from_parts(
        sighash_info: TransparentSighashInfoBytes,
        script_sig: TransparentScriptBytes,
    ) -> Self {
        Self {
            sighash_info,
            script_sig,
        }
    }

    /// Returns the input's sighash information.
    pub const fn sighash_info(&self) -> &TransparentSighashInfoBytes {
        &self.sighash_info
    }

    /// Returns the raw `scriptSig` bytes.
    pub const fn script_sig(&self) -> &TransparentScriptBytes {
        &self.script_sig
    }

    /// Reads an input's authorizing data: a `sighashInfo` value followed by a
    /// CompactSize-prefixed `scriptSig`.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let sighash_info = TransparentSighashInfoBytes::read(&mut reader)?;
        let script_sig = TransparentScriptBytes::read(&mut reader)?;
        Ok(Self::from_parts(sighash_info, script_sig))
    }

    /// Writes this input's authorizing data.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.sighash_info.write(&mut writer)?;
        self.script_sig.write(&mut writer)
    }
}

/// The effecting data of a v7 transparent bundle.
///
/// [ZIP 248 §Transparent Effecting Data](https://zips.z.cash/zip-0248#transparent-effecting-data)
///
/// The layout is `tx_in_count`, the effecting data for each input, then
/// `tx_out_count` and the outputs.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransparentEffectsBytes {
    inputs: Vec<TransparentInputEffectingBytes>,
    outputs: Vec<TransparentOutputBytes>,
}

#[cfg(zcash_unstable = "nu8")]
impl TransparentEffectsBytes {
    /// Constructs effecting data from its wire fields.
    pub fn from_parts(
        inputs: Vec<TransparentInputEffectingBytes>,
        outputs: Vec<TransparentOutputBytes>,
    ) -> Self {
        Self { inputs, outputs }
    }

    /// Returns the effecting data for each input.
    pub fn inputs(&self) -> &[TransparentInputEffectingBytes] {
        &self.inputs
    }

    /// Returns the bundle's outputs.
    pub fn outputs(&self) -> &[TransparentOutputBytes] {
        &self.outputs
    }

    /// Returns `true` if the effecting data has neither inputs nor outputs.
    ///
    /// ZIP 248 requires such a bundle to be omitted from `mEffectBundles`
    /// rather than encoded as an empty entry.
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty() && self.outputs.is_empty()
    }

    /// Reads effecting data from its canonical binary encoding.
    ///
    /// This reads exactly the effecting data's bytes; any following bytes
    /// belong to the enclosing bundle map and are left unread.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let inputs = read_vector(&mut reader, |r| TransparentInputEffectingBytes::read(r))?;
        let outputs = read_vector(&mut reader, |r| TransparentOutputBytes::read(r))?;
        Ok(Self::from_parts(inputs, outputs))
    }

    /// Writes this effecting data in its canonical binary encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write(&mut writer, &self.inputs, |w, input| input.write(w))?;
        Vector::write(&mut writer, &self.outputs, |w, output| output.write(w))
    }
}

/// The authorizing data of a v7 transparent bundle.
///
/// [ZIP 248 §Transparent Authorizing Data](https://zips.z.cash/zip-0248#transparent-authorizing-data)
///
/// The layout is one [`TransparentInputAuthBytes`] per input. The number of
/// entries is not encoded; it is the `tx_in_count` from the effecting data.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransparentAuthBytes {
    inputs: Vec<TransparentInputAuthBytes>,
}

#[cfg(zcash_unstable = "nu8")]
impl TransparentAuthBytes {
    /// Constructs authorizing data from its wire fields.
    pub fn from_parts(inputs: Vec<TransparentInputAuthBytes>) -> Self {
        Self { inputs }
    }

    /// Returns the authorizing data for each input.
    pub fn inputs(&self) -> &[TransparentInputAuthBytes] {
        &self.inputs
    }

    /// Returns the number of inputs with authorizing data.
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Returns `true` if there is no authorizing data.
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Reads authorizing data for `input_count` inputs.
    ///
    /// The count comes from the effecting data, so this reads exactly that many
    /// entries and leaves any following bytes unread.
    pub fn read<R: Read>(mut reader: R, input_count: usize) -> io::Result<Self> {
        let inputs = read_array(&mut reader, input_count, |r| {
            TransparentInputAuthBytes::read(r)
        })?;
        Ok(Self::from_parts(inputs))
    }

    /// Writes this authorizing data in its canonical binary encoding.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        for input in &self.inputs {
            input.write(&mut writer)?;
        }
        Ok(())
    }
}

/// A v7 transparent bundle, retaining its effecting and authorizing data
/// separately.
///
/// [ZIP 248 §Transparent Bundle](https://zips.z.cash/zip-0248#transparent-bundle)
///
/// The two halves travel in different bundle maps: effecting data in
/// `mEffectBundles` and authorizing data in `mAuthBundles`. ZIP 248 requires
/// the authorizing entry to be omitted when there are no inputs, and requires
/// one authorizing entry per input otherwise.
#[cfg(zcash_unstable = "nu8")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentBundleBytes {
    effects: TransparentEffectsBytes,
    auth: Option<TransparentAuthBytes>,
}

#[cfg(zcash_unstable = "nu8")]
impl TransparentBundleBytes {
    /// Constructs a bundle from its effecting and authorizing data.
    ///
    /// Returns an error if authorizing data is present for a bundle with no
    /// inputs, or if the authorizing data does not contain exactly one entry
    /// per input. Authorizing data may be absent even when the effecting data
    /// has inputs; requiring it is a consensus rule enforced by typed
    /// conversion rather than by the byte layer.
    pub fn from_parts(
        effects: TransparentEffectsBytes,
        auth: Option<TransparentAuthBytes>,
    ) -> io::Result<Self> {
        match (effects.inputs.is_empty(), &auth) {
            (true, Some(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "transparent authorizing data present for a bundle with no inputs; \
                     it must be omitted",
                ));
            }
            (false, Some(auth)) if auth.inputs.len() != effects.inputs.len() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "transparent authorizing data does not have one entry per input",
                ));
            }
            _ => {}
        }
        Ok(Self { effects, auth })
    }

    /// Returns the bundle's effecting data.
    pub const fn effects(&self) -> &TransparentEffectsBytes {
        &self.effects
    }

    /// Returns the bundle's authorizing data, if it has any.
    pub const fn auth(&self) -> Option<&TransparentAuthBytes> {
        self.auth.as_ref()
    }

    /// Returns `true` if the effecting data has neither inputs nor outputs.
    ///
    /// ZIP 248 requires such a bundle to be omitted from `mEffectBundles`
    /// rather than encoded as an empty entry.
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }

    /// Reads a bundle from its `mEffectBundles` and `mAuthBundles` payloads.
    ///
    /// Both payloads must be consumed exactly; trailing bytes are rejected.
    /// The authorizing payload's input count is taken from the effecting data.
    pub fn read(effects: &[u8], auth: Option<&[u8]>) -> io::Result<Self> {
        let mut effects_reader = effects;
        let effects = TransparentEffectsBytes::read(&mut effects_reader)?;
        if !effects_reader.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in v7 transparent effecting data",
            ));
        }

        let auth = match auth {
            Some(auth_bytes) => {
                let mut auth_reader = auth_bytes;
                let auth = TransparentAuthBytes::read(&mut auth_reader, effects.inputs.len())?;
                if !auth_reader.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in v7 transparent authorizing data",
                    ));
                }
                Some(auth)
            }
            None => None,
        };

        Self::from_parts(effects, auth)
    }

    /// Writes the bundle's effecting data.
    pub fn write_effects<W: Write>(&self, writer: W) -> io::Result<()> {
        self.effects.write(writer)
    }

    /// Writes the bundle's authorizing data, if it has any.
    pub fn write_auth<W: Write>(&self, writer: W) -> io::Result<()> {
        match &self.auth {
            Some(auth) => auth.write(writer),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(zcash_unstable = "nu8")]
    use zcash_encoding::CompactSize;

    fn outpoint(byte: u8, index: u32) -> TransparentOutPointBytes {
        TransparentOutPointBytes::from_parts(TxId::from_bytes([byte; 32]), index)
    }

    fn output(value: i64, script: &[u8]) -> TransparentOutputBytes {
        TransparentOutputBytes::from_parts(
            TransparentOutputValueBytes::from_i64(value),
            TransparentScriptBytes::from_bytes(script.to_vec()),
        )
    }

    fn legacy_input(
        byte: u8,
        index: u32,
        script: &[u8],
        sequence: u32,
    ) -> LegacyTransparentInputBytes {
        LegacyTransparentInputBytes::from_parts(
            outpoint(byte, index),
            TransparentScriptBytes::from_bytes(script.to_vec()),
            sequence,
        )
    }

    #[test]
    fn legacy_round_trip_empty() {
        let bundle = LegacyTransparentBundleBytes::default();
        assert!(bundle.is_empty());

        let mut encoded = Vec::new();
        bundle.write(&mut encoded).unwrap();
        assert_eq!(encoded, [0x00, 0x00]);

        let decoded = LegacyTransparentBundleBytes::read(&encoded[..]).unwrap();
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn legacy_round_trip_populated() {
        let bundle = LegacyTransparentBundleBytes::from_parts(
            vec![
                legacy_input(1, 2, &[0x51], 3),
                legacy_input(4, 5, &[], u32::MAX),
            ],
            vec![output(1000, &[0x51, 0x52]), output(0, &[])],
        );

        let mut encoded = Vec::new();
        bundle.write(&mut encoded).unwrap();
        let decoded = LegacyTransparentBundleBytes::read(&encoded[..]).unwrap();
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn legacy_truncation_is_rejected() {
        let bundle = LegacyTransparentBundleBytes::from_parts(
            vec![legacy_input(1, 2, &[0x51], 3)],
            vec![output(1000, &[0x51])],
        );
        let mut encoded = Vec::new();
        bundle.write(&mut encoded).unwrap();

        for len in 0..encoded.len() {
            assert!(
                LegacyTransparentBundleBytes::read(&encoded[..len]).is_err(),
                "truncation at {len} bytes was accepted"
            );
        }
    }

    #[cfg(zcash_unstable = "nu8")]
    fn v7_bundle(
        inputs: Vec<(u8, u32, u32, &[u8])>,
        outputs: Vec<(i64, &[u8])>,
    ) -> TransparentBundleBytes {
        let effects = TransparentEffectsBytes::from_parts(
            inputs
                .iter()
                .map(|&(byte, index, sequence, _)| {
                    TransparentInputEffectingBytes::from_parts(outpoint(byte, index), sequence)
                })
                .collect(),
            outputs
                .iter()
                .map(|&(value, script)| output(value, script))
                .collect(),
        );
        let auth = if inputs.is_empty() {
            None
        } else {
            Some(TransparentAuthBytes::from_parts(
                inputs
                    .iter()
                    .map(|&(_, _, _, script)| {
                        TransparentInputAuthBytes::from_parts(
                            TransparentSighashInfoBytes::v0(),
                            TransparentScriptBytes::from_bytes(script.to_vec()),
                        )
                    })
                    .collect(),
            ))
        };
        TransparentBundleBytes::from_parts(effects, auth).unwrap()
    }

    #[cfg(zcash_unstable = "nu8")]
    fn encode_v7(bundle: &TransparentBundleBytes) -> (Vec<u8>, Option<Vec<u8>>) {
        let mut effects = Vec::new();
        bundle.write_effects(&mut effects).unwrap();
        let auth = bundle.auth().map(|_| {
            let mut auth = Vec::new();
            bundle.write_auth(&mut auth).unwrap();
            auth
        });
        (effects, auth)
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_round_trip_empty() {
        let bundle = v7_bundle(vec![], vec![]);
        assert!(bundle.is_empty());
        assert!(bundle.auth().is_none());

        let (effects, auth) = encode_v7(&bundle);
        assert_eq!(effects, [0x00, 0x00]);
        assert!(auth.is_none());

        let decoded = TransparentBundleBytes::read(&effects, auth.as_deref()).unwrap();
        assert_eq!(decoded, bundle);
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_round_trip_outputs_only() {
        let bundle = v7_bundle(vec![], vec![(1000, &[0x51]), (0, &[])]);
        assert!(!bundle.is_empty());
        assert!(bundle.auth().is_none());

        let (effects, auth) = encode_v7(&bundle);
        let decoded = TransparentBundleBytes::read(&effects, auth.as_deref()).unwrap();
        assert_eq!(decoded, bundle);
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_round_trip_inputs_only() {
        let bundle = v7_bundle(vec![(1, 2, 3, &[0x51])], vec![]);
        assert!(!bundle.is_empty());
        assert!(bundle.auth().is_some());

        let (effects, auth) = encode_v7(&bundle);
        let decoded = TransparentBundleBytes::read(&effects, auth.as_deref()).unwrap();
        assert_eq!(decoded, bundle);
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_round_trip_inputs_and_outputs() {
        let bundle = v7_bundle(
            vec![(1, 2, 3, &[0x51]), (4, 5, u32::MAX, &[])],
            vec![(1000, &[0x51, 0x52]), (0, &[])],
        );

        let (effects, auth) = encode_v7(&bundle);
        let decoded = TransparentBundleBytes::read(&effects, auth.as_deref()).unwrap();
        assert_eq!(decoded, bundle);
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_effects_trailing_data_is_rejected() {
        let bundle = v7_bundle(vec![], vec![(1000, &[0x51])]);
        let (mut effects, auth) = encode_v7(&bundle);
        effects.push(0x00);

        assert!(TransparentBundleBytes::read(&effects, auth.as_deref()).is_err());
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_auth_trailing_data_is_rejected() {
        let bundle = v7_bundle(vec![(1, 2, 3, &[0x51])], vec![]);
        let (effects, mut auth) = encode_v7(&bundle);
        auth.as_mut().unwrap().push(0x00);

        assert!(TransparentBundleBytes::read(&effects, auth.as_deref()).is_err());
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_auth_count_mismatch_is_rejected() {
        let bundle = v7_bundle(vec![(1, 2, 3, &[0x51]), (4, 5, 6, &[0x52])], vec![]);
        let (effects, auth) = encode_v7(&bundle);
        let auth = auth.unwrap();

        // One entry too few.
        let mut short = auth.clone();
        let mut reader = &short[..];
        let first = TransparentInputAuthBytes::read(&mut reader).unwrap();
        let mut short_encoded = Vec::new();
        first.write(&mut short_encoded).unwrap();
        assert!(TransparentBundleBytes::read(&effects, Some(&short_encoded)).is_err());

        // One entry too many.
        let mut long = auth.clone();
        long.extend_from_slice(&short_encoded);
        assert!(TransparentBundleBytes::read(&effects, Some(&long)).is_err());

        // The original is accepted.
        assert!(TransparentBundleBytes::read(&effects, Some(&auth)).is_ok());
        short.clear();
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_auth_without_inputs_is_rejected() {
        let bundle = v7_bundle(vec![], vec![(1000, &[0x51])]);
        let (effects, _) = encode_v7(&bundle);

        // A present-but-empty authorizing payload is a second encoding of the
        // same bundle, so it is rejected.
        assert!(TransparentBundleBytes::read(&effects, Some(&[])).is_err());

        // A non-empty one is rejected too.
        let mut auth = Vec::new();
        TransparentInputAuthBytes::from_parts(
            TransparentSighashInfoBytes::v0(),
            TransparentScriptBytes::from_bytes(vec![0x51]),
        )
        .write(&mut auth)
        .unwrap();
        assert!(TransparentBundleBytes::read(&effects, Some(&auth)).is_err());
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_inputs_without_auth_round_trip() {
        let bundle = v7_bundle(vec![(1, 2, 3, &[0x51])], vec![]);
        let (effects, _) = encode_v7(&bundle);

        // The byte layer accepts effecting data without authorizing data.
        let decoded = TransparentBundleBytes::read(&effects, None).unwrap();
        assert_eq!(decoded.effects(), bundle.effects());
        assert!(decoded.auth().is_none());
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_truncation_is_rejected() {
        let bundle = v7_bundle(vec![(1, 2, 3, &[0x51])], vec![(1000, &[0x51, 0x52])]);
        let (effects, auth) = encode_v7(&bundle);
        let auth = auth.unwrap();

        for len in 0..effects.len() {
            assert!(
                TransparentBundleBytes::read(&effects[..len], Some(&auth)).is_err(),
                "effect truncation at {len} bytes was accepted"
            );
        }
        for len in 0..auth.len() {
            assert!(
                TransparentBundleBytes::read(&effects, Some(&auth[..len])).is_err(),
                "auth truncation at {len} bytes was accepted"
            );
        }
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn compact_size_boundaries_round_trip() {
        // Script lengths that straddle each CompactSize width boundary.
        for len in [0usize, 1, 252, 253, 65_535, 65_536] {
            let script = vec![0x51; len];
            let bundle = v7_bundle(vec![], vec![(1000, &script)]);
            let (effects, auth) = encode_v7(&bundle);
            let decoded = TransparentBundleBytes::read(&effects, auth.as_deref()).unwrap();
            assert_eq!(decoded, bundle, "script length {len}");
        }

        // Input and output counts that straddle the one-byte boundary.
        for count in [0usize, 1, 252, 253] {
            let inputs: Vec<_> = (0..count)
                .map(|i| (i as u8, i as u32, i as u32, &[][..]))
                .collect();
            let outputs: Vec<_> = (0..count).map(|i| (i as i64, &[][..])).collect();
            let bundle = v7_bundle(inputs, outputs);
            let (effects, auth) = encode_v7(&bundle);
            let decoded = TransparentBundleBytes::read(&effects, auth.as_deref()).unwrap();
            assert_eq!(decoded, bundle, "count {count}");
        }
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn excessive_counts_do_not_allocate() {
        // A count at the CompactSize limit with no elements behind it must fail
        // on the first element read, not by reserving for the claimed count.
        let mut effects = Vec::new();
        CompactSize::write(&mut effects, 0x0200_0000).unwrap();
        assert!(TransparentEffectsBytes::read(&effects[..]).is_err());

        // The same for a script length.
        let mut output = Vec::new();
        output.extend_from_slice(&0i64.to_le_bytes());
        CompactSize::write(&mut output, 0x0200_0000).unwrap();
        assert!(TransparentOutputBytes::read(&output[..]).is_err());

        // And for the legacy input vector.
        let mut legacy = Vec::new();
        CompactSize::write(&mut legacy, 0x0200_0000).unwrap();
        assert!(LegacyTransparentBundleBytes::read(&legacy[..]).is_err());
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn oversized_and_non_canonical_compact_sizes_are_rejected() {
        // 0x02000001 exceeds MAX_COMPACT_SIZE.
        let mut effects = Vec::new();
        effects.push(0xfe);
        effects.extend_from_slice(&0x0200_0001u32.to_le_bytes());
        assert!(TransparentEffectsBytes::read(&effects[..]).is_err());

        // 0xfd 0x01 0x00 is a non-canonical encoding of 1.
        let mut effects = Vec::new();
        effects.push(0xfd);
        effects.extend_from_slice(&1u16.to_le_bytes());
        assert!(TransparentEffectsBytes::read(&effects[..]).is_err());
    }
}
