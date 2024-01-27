//! # Regtest constants
//!
//! `regtest` is a `zcashd`-specific environment used for local testing. They mostly reuse
//! the testnet constants.
//! These constants are defined in [the `zcashd` codebase].
//!
//! [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L482-L496>

/// The regtest cointype reuses the testnet cointype
pub const COIN_TYPE: u32 = 1;

/// The HRP for a Bech32-encoded regtest Sapling [`ExtendedSpendingKey`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`ExtendedSpendingKey`]: crate::sapling::zip32::ExtendedSpendingKey
/// [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L496>
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-regtest";

/// The HRP for a Bech32-encoded regtest Sapling [`ExtendedFullViewingKey`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`ExtendedFullViewingKey`]: crate::sapling::zip32::ExtendedFullViewingKey
/// [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L494>
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviewregtestsapling";

/// The HRP for a Bech32-encoded regtest Sapling [`PaymentAddress`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`PaymentAddress`]: crate::sapling::PaymentAddress
/// [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L493>
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "zregtestsapling";

/// The prefix for a Base58Check-encoded regtest transparent [`PublicKeyHash`].
/// Same as the testnet prefix.
///
/// [`PublicKeyHash`]: crate::legacy::TransparentAddress::PublicKeyHash
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x1d, 0x25];

/// The prefix for a Base58Check-encoded regtest transparent [`ScriptHash`].
/// Same as the testnet prefix.
///
/// [`ScriptHash`]: crate::legacy::TransparentAddress::ScriptHash
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0xba];
