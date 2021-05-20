mod f4jumble;

/// The HRP for a Bech32m-encoded mainnet Unified Address.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
pub(crate) const MAINNET: &str = "u";

/// The HRP for a Bech32m-encoded testnet Unified Address.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
pub(crate) const TESTNET: &str = "utest";

/// The HRP for a Bech32m-encoded regtest Unified Address.
pub(crate) const REGTEST: &str = "uregtest";

/// TODO
pub(crate) type Data = [u8; 43];
