/// The prefix for a Base58Check-encoded mainnet Sprout address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.3][sproutpaymentaddrencoding].
///
/// [sproutpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#sproutpaymentaddrencoding
pub(crate) const MAINNET: [u8; 2] = [0x16, 0x9a];

/// The prefix for a Base58Check-encoded testnet Sprout address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.3][sproutpaymentaddrencoding].
///
/// [sproutpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#sproutpaymentaddrencoding
pub(crate) const TESTNET: [u8; 2] = [0x16, 0xb6];

pub(crate) type Data = [u8; 64];
