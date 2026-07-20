//! Types, constants, and functions related to coinbase transactions.

use alloc::fmt;

/// The minimum length of the coinbase transaction script.
///
/// [§ 7.1.2](https://zips.z.cash/protocol/protocol.pdf#txnconsensus) specifies:
///
/// > A coinbase transaction script MUST have length in {2 .. 100} bytes.
pub const MIN_COINBASE_SCRIPT_LEN: usize = 2;

/// The maximum length of the coinbase transaction script.
///
/// [§ 7.1.2](https://zips.z.cash/protocol/protocol.pdf#txnconsensus) specifies:
///
/// > A coinbase transaction script MUST have length in {2 .. 100} bytes.
pub const MAX_COINBASE_SCRIPT_LEN: usize = 100;

/// The maximum length of the encoded height in the coinbase transaction script.
///
/// [§ 7.1.2](https://zips.z.cash/protocol/protocol.pdf#txnconsensus) specifies:
///
/// > The length of `heightBytes` MUST be in the range {1 .. 5}. Then the encoding is the length of
/// > `heightBytes` encoded as one byte, followed by `heightBytes` itself.
pub const MAX_COINBASE_HEIGHT_LEN: usize = 6;

/// Errors related to coinbase transactions.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Encoded coinbase script exceeds [`MAX_COINBASE_SCRIPT_LEN`].
    OversizedScript,
    /// Encoded block height exceeds [`MAX_COINBASE_HEIGHT_LEN`].
    OversizedHeight,
    /// Creating a coinbase input for the genesis block is not supported.
    GenesisInputNotSupported,
    /// Coinbase transactions must contain only a dummy input.
    UnexpectedInputs,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::OversizedScript => write!(
                f,
                "encoded coinbase script exceeds the limit of {MAX_COINBASE_SCRIPT_LEN} bytes",
            ),
            Error::OversizedHeight => write!(
                f,
                "encoded block height exceeds the limit of {MAX_COINBASE_HEIGHT_LEN} bytes",
            ),
            Error::GenesisInputNotSupported => write!(
                f,
                "creating a coinbase input for the genesis block is not supported",
            ),
            Error::UnexpectedInputs => {
                write!(f, "coinbase transactions must contain only a dummy input",)
            }
        }
    }
}

impl core::error::Error for Error {}
