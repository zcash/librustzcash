/// The mainnet coin type for ZEC, as defined by [SLIP 44].
///
/// [SLIP 44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub const COIN_TYPE: u32 = 133;

/// The HRP for a Bech32-encoded mainnet [`PaymentAddress`].
///
/// Defined in section 5.6.4 of the [Zcash Protocol Specification].
///
/// [`PaymentAddress`]: sapling_crypto::primitives::PaymentAddress
/// [Zcash Protocol Specification]: https://github.com/zcash/zips/blob/master/protocol/protocol.pdf
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "zs";
