use alloc::string::{String, ToString};
use core::fmt;
use corez::io::{self, Read, Write};

use zcash_encoding::ReverseHex;

#[cfg(feature = "std")]
use memuse::DynamicUsage;

/// The identifier for a Zcash transaction.
///
/// - For v1-4 transactions, this is a double-SHA-256 hash of the encoded transaction.
///   This means that it is malleable, and only a reliable identifier for transactions
///   that have been mined.
/// - For v5 transactions onwards, this identifier is derived only from "effecting" data,
///   and is non-malleable in all contexts.
#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct TxId([u8; 32]);

#[cfg(feature = "std")]
memuse::impl_no_dynamic_usage!(TxId);

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The (byte-flipped) hex string is more useful than the raw bytes, because we can
        // look that up in RPC methods and block explorers.
        let txid_str = self.to_string();
        f.debug_tuple("TxId").field(&txid_str).finish()
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_hex())
    }
}

impl AsRef<[u8; 32]> for TxId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<TxId> for [u8; 32] {
    fn from(value: TxId) -> Self {
        value.0
    }
}

impl TxId {
    /// The all-zeros txid. This is reserved as the txid of the transparent input to a coinbase
    /// transaction.
    pub const NULL: TxId = TxId([0u8; 32]);

    /// Wraps the given byte array as a TxId value
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        TxId(bytes)
    }

    /// Encodes this transaction ID in its canonical hexadecimal representation.
    pub fn as_hex(&self) -> String {
        ReverseHex::encode(&self.0)
    }

    /// Parses a transaction id from its canonical hexadecimal representation — the byte-reversed
    /// form produced by this type's [`Display`](fmt::Display) impl, as shown by block explorers
    /// and node RPCs. Returns `None` if the input is not exactly 64 hexadecimal digits.
    pub fn from_hex(s: &str) -> Option<Self> {
        ReverseHex::decode(s).map(TxId::from_bytes)
    }

    /// Reads a 32-byte txid directly from the provided reader.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;
        Ok(TxId::from_bytes(hash))
    }

    /// Writes the 32-byte payload directly to the provided writer.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    /// Returns true when the txid consists of all zeros, indicating the input
    /// to a coinbase transaction.
    pub fn is_null(&self) -> bool {
        *self == Self::NULL
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use super::TxId;
    use proptest::prelude::*;

    /// An arbitrary transaction id (32 random bytes)
    pub fn arb_txid() -> impl Strategy<Value = TxId> {
        any::<[u8; 32]>().prop_map(TxId::from_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::TxId;
    use alloc::string::ToString;

    /// `from_hex` inverts `Display` exactly, and is NOT the inverse of hex-encoding the internal
    /// bytes: the two encodings are mutually byte-reversed, checked with an asymmetric pattern.
    #[test]
    fn from_hex_inverts_display() {
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let txid = TxId::from_bytes(bytes);
        assert_eq!(TxId::from_hex(&txid.to_string()), Some(txid));
        assert_eq!(
            TxId::from_hex(&hex::encode(bytes)),
            Some(TxId::from_bytes({
                let mut r = bytes;
                r.reverse();
                r
            })),
            "internal-order hex parses as the REVERSED id"
        );
        assert_eq!(TxId::from_hex("beef"), None);
        assert_eq!(TxId::from_hex("zz"), None);
    }
}
