//! Network-specific Zcash constants.

pub mod mainnet;
pub mod regtest;
pub mod testnet;

/// The transaction version introduced by the Overwinter network upgrade.
pub const OVERWINTER_TX_VERSION: u32 = 3;
/// The version group id for Zcash Overwinter transactions.
pub const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C48270;

/// The transaction version introduced by the Sapling network upgrade.
pub const SAPLING_TX_VERSION: u32 = 4;
/// The version group id for Zcash Sapling transactions.
pub const SAPLING_VERSION_GROUP_ID: u32 = 0x892F2085;

/// The transaction version introduced by the NU5 network upgrade.
pub const V5_TX_VERSION: u32 = 5;
/// The version group id for Zcash Nu5 transactions.
pub const V5_VERSION_GROUP_ID: u32 = 0x26A7270A;

/// The transaction version introduced by ZIP 230.
#[cfg(zcash_unstable = "nu7")]
pub const V6_TX_VERSION: u32 = 6;
/// The version group id for Zcash ZIP 230 transactions.
#[cfg(zcash_unstable = "nu7")]
pub const V6_VERSION_GROUP_ID: u32 = 0xFFFFFFFF;

/// These versions are used exclusively for in-development transaction
/// serialization, and will never be active under the consensus rules.
/// When new consensus transaction versions are added, all call sites
/// using these constants should be inspected, and use of these constants
/// should be removed as appropriate in favor of the new consensus
/// transaction version and group.
#[cfg(zcash_unstable = "zfuture")]
pub const ZFUTURE_VERSION_GROUP_ID: u32 = 0xFFFFFFFF;
#[cfg(zcash_unstable = "zfuture")]
pub const ZFUTURE_TX_VERSION: u32 = 0x0000FFFF;
