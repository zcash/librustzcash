/// The prefix for a Base58Check-encoded mainnet transparent P2SH address.
pub(crate) const MAINNET: [u8; 2] = [0x1c, 0xbd];

/// The prefix for a Base58Check-encoded testnet transparent P2SH address.
pub(crate) const TESTNET: [u8; 2] = [0x1c, 0xba];

pub(crate) type Data = [u8; 20];
