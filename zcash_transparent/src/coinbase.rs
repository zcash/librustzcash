//! Types, constants, and functions related to coinbase transactions.

use alloc::{fmt, vec::Vec};

/// The maximum length of the coinbase script sig field.
///
/// # Consensus
///
/// > A coinbase transaction script MUST have length in {2 .. 100} bytes.
///
/// <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
pub const MAX_COINBASE_SCRIPT_LEN: usize = 100;

/// The minimum length of the coinbase script sig field.
///
/// # Consensus
///
/// > A coinbase transaction script MUST have length in {2 .. 100} bytes.
///
/// <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
pub const MIN_COINBASE_SCRIPT_LEN: usize = 2;

/// The maximum length of the encoded height in the coinbase script sig field.
///
/// # Consensus
///
/// > The length of `heightBytes` MUST be in the range {1 .. 5}. Then the encoding is the length of
/// > `heightBytes` encoded as one byte, followed by heightBytes itself.
///
/// <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
pub const MAX_COINBASE_HEIGHT_LEN: usize = 6;

/// The maximum length of the miner data in the coinbase script sig field.
pub const MAX_MINER_DATA_LEN: usize = MAX_COINBASE_SCRIPT_LEN - MAX_COINBASE_HEIGHT_LEN;

/// Arbitrary data inserted by miners into a coinbase transaction.
///
/// # Invariants
///
/// - The data cannot be empty.
/// - The data must be less than [`MAX_MINER_DATA_LEN`] bytes.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MinerData(Vec<u8>);

impl Default for MinerData {
    fn default() -> Self {
        // `zcashd` includes an empty byte after the coinbase height [1]. We do that only if
        // `miner_data` would be empty to comply with the following consensus rule:
        //
        // > A coinbase transaction script MUST have length in {2 .. 100} bytes.
        //
        // ## Rationale
        //
        // Coinbase heights < 17 are serialized as a single byte, and if there is no miner data,
        // the script of a coinbase tx with such a height would consist only of this single
        // byte, violating the consensus rule.
        //
        // [1]: <https://github.com/zcash/zcash/blob/18238d90cd0b810f5b07d5aaa1338126aa128c06/src/miner.cpp#L296>
        Self(vec![0])
    }
}

impl TryFrom<&[u8]> for MinerData {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        match data.len() {
            0 => Err(Error::EmptyMinerData),
            n if n > MAX_MINER_DATA_LEN => Err(Error::OversizedMinerData(n)),
            _ => Ok(Self(data.to_vec())),
        }
    }
}

impl AsRef<[u8]> for MinerData {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Errors related to coinbase transactions.
#[derive(Clone, Debug)]
pub enum Error {
    /// The miner data exceeds [`MAX_MINER_DATA_LEN`].
    OversizedMinerData(usize),
    /// The miner data is empty.
    EmptyMinerData,
    /// Creating a coinbase input for the genesis block is not supported.
    GenesisInputNotSupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::OversizedMinerData(len) => write!(
                f,
                "miner data is {len} bytes, exceeding the limit of {MAX_MINER_DATA_LEN}",
            ),
            Error::EmptyMinerData => write!(f, "miner data cannot be empty",),
            Error::GenesisInputNotSupported => write!(
                f,
                "creating a coinbase input for the genesis block is not supported",
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
