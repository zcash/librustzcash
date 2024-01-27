//! Constants for the Zcash test network.

/// The testnet coin type for ZEC, as defined by [SLIP 44].
///
/// [SLIP 44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub const COIN_TYPE: u32 = 1;

/// The HRP for a Bech32-encoded testnet Sapling [`ExtendedSpendingKey`].
///
/// Defined in [ZIP 32].
///
/// [`ExtendedSpendingKey`]: crate::sapling::zip32::ExtendedSpendingKey
/// [ZIP 32]: https://github.com/zcash/zips/blob/master/zip-0032.rst
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-test";

/// The HRP for a Bech32-encoded testnet Sapling [`ExtendedFullViewingKey`].
///
/// Defined in [ZIP 32].
///
/// [`ExtendedFullViewingKey`]: crate::sapling::zip32::ExtendedFullViewingKey
/// [ZIP 32]: https://github.com/zcash/zips/blob/master/zip-0032.rst
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviewtestsapling";

/// The HRP for a Bech32-encoded testnet Sapling [`PaymentAddress`].
///
/// Defined in section 5.6.4 of the [Zcash Protocol Specification].
///
/// [`PaymentAddress`]: crate::sapling::PaymentAddress
/// [Zcash Protocol Specification]: https://github.com/zcash/zips/blob/master/protocol/protocol.pdf
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "ztestsapling";

/// The prefix for a Base58Check-encoded testnet transparent [`PublicKeyHash`].
///
/// [`PublicKeyHash`]: crate::legacy::TransparentAddress::PublicKeyHash
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x1d, 0x25];

/// The prefix for a Base58Check-encoded testnet transparent [`ScriptHash`].
///
/// [`ScriptHash`]: crate::legacy::TransparentAddress::ScriptHash
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0xba];
