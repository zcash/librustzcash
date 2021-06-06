/// The HRP for a Bech32-encoded mainnet Sapling address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.4][saplingpaymentaddrencoding].
///
/// [saplingpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#saplingpaymentaddrencoding
pub(crate) const MAINNET: &str = "zs";

/// The HRP for a Bech32-encoded testnet Sapling address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.4][saplingpaymentaddrencoding].
///
/// [saplingpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#saplingpaymentaddrencoding
pub(crate) const TESTNET: &str = "ztestsapling";

/// The HRP for a Bech32-encoded regtest Sapling address.
///
/// It is defined in [the `zcashd` codebase].
///
/// [the `zcashd` codebase]: https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L493
pub(crate) const REGTEST: &str = "zregtestsapling";

pub(crate) type Data = [u8; 43];
