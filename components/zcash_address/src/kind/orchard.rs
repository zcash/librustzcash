/// The HRP for a Bech32-encoded mainnet Orchard address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.4.1][orchardpaymentaddrencoding].
///
/// [orchardpaymentaddrencoding]: https://zips.z.cash/protocol/nu5.pdf#orchardpaymentaddrencoding
pub(crate) const MAINNET: &str = "zo";

/// The HRP for a Bech32-encoded testnet Orchard address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.4.1][orchardpaymentaddrencoding].
///
/// [orchardpaymentaddrencoding]: https://zips.z.cash/protocol/nu5.pdf#orchardpaymentaddrencoding
pub(crate) const TESTNET: &str = "ztestorchard";

/// The HRP for a Bech32-encoded regtest Orchard address.
pub(crate) const REGTEST: &str = "zregtestorchard";

pub(crate) type Data = [u8; 43];
