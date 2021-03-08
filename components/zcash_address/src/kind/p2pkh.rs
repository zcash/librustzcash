/// The prefix for a Base58Check-encoded mainnet transparent P2PKH address.
pub(crate) const MAINNET: [u8; 2] = [0x1c, 0xb8];

/// The prefix for a Base58Check-encoded testnet transparent P2PKH address.
pub(crate) const TESTNET: [u8; 2] = [0x1d, 0x25];

pub(crate) type Data = [u8; 20];
