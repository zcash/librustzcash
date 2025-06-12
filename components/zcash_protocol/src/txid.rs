use alloc::string::ToString;
use core::fmt;
use core2::io::{self, Read, Write};

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
        let mut data = self.0;
        data.reverse();
        formatter.write_str(&hex::encode(data))
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
    /// Wraps the given byte array as a TxId value
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        TxId(bytes)
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

    /// Returns true when the txid consists of all zeros; this only occurs for coinbase
    /// transactions.
    pub fn is_null(&self) -> bool {
        self.0 == [0u8; 32]
    }
}
