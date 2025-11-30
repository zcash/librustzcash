//! Types, constants, and functions related to coinbase transactions.

use alloc::{fmt, vec::Vec};
use zcash_script::{opcode::Evaluable, pv::push_value};

/// The maximum length of the coinbase transaction script.
pub const MAX_COINBASE_SCRIPT_LEN: usize = 100;

/// The minimum length of the coinbase transaction script.
pub const MIN_COINBASE_SCRIPT_LEN: usize = 2;

/// The maximum length of the encoded height in the coinbase transaction script.
pub const MAX_COINBASE_HEIGHT_LEN: usize = 6;

/// Optional, arbitrary data that miners can put in the coinbase transaction script.
///
/// # Invariants
///
/// - The data is internally encoded as a transparent script push value.
/// - The encoded form is limited to [`MAX_MINER_DATA_LEN`] bytes.
#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MinerData(Vec<u8>);

impl MinerData {
    /// The maximum length of encoded [`MinerData`].
    pub const MAX_LEN: usize = MAX_COINBASE_SCRIPT_LEN - MAX_COINBASE_HEIGHT_LEN;
}

impl Default for MinerData {
    fn default() -> Self {
        MinerData::try_from(&[][..]).expect("empty miner data is encoded as OP_0")
    }
}

impl TryFrom<&[u8]> for MinerData {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        push_value(data)
            .map(|pv| pv.to_bytes())
            .filter(|encoded| encoded.len() <= Self::MAX_LEN)
            .map(MinerData)
            .ok_or(Error::OversizedMinerData)
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
    /// Encoded coinbase script exceeds [`MAX_COINBASE_SCRIPT_LEN`].
    OversizedScript,
    /// Encoded coinbase script is shorter than [`MIN_COINBASE_SCRIPT_LEN`].
    UndersizedScript,
    /// Encoded block height exceeds [`MAX_COINBASE_HEIGHT_LEN`].
    OversizedHeight,
    /// Encoded miner data exceeds [`MinerData::MAX_LEN`].
    OversizedMinerData,
    /// Creating a coinbase input for the genesis block is not supported.
    GenesisInputNotSupported,
    /// Coinbase transactions can contain only predefined inputs.
    ExcessiveInputs,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::OversizedScript => write!(
                f,
                "encoded coinbase script exceeds the limit of {MAX_COINBASE_SCRIPT_LEN} bytes",
            ),
            Error::UndersizedScript => write!(
                f,
                "encoded coinbase script is shorter than the minimum of {} bytes",
                MIN_COINBASE_SCRIPT_LEN,
            ),
            Error::OversizedHeight => write!(
                f,
                "encoded block height exceeds the limit of {MAX_COINBASE_HEIGHT_LEN}",
            ),
            Error::OversizedMinerData => write!(
                f,
                "encoded miner data exceeds the limit of {}",
                MinerData::MAX_LEN,
            ),
            Error::GenesisInputNotSupported => write!(
                f,
                "creating a coinbase input for the genesis block is not supported",
            ),
            Error::ExcessiveInputs => write!(
                f,
                "coinbase transactions can contain only predefined inputs",
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
