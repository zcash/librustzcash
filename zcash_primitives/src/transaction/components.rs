//! Structs representing the components within Zcash transactions.
pub mod orchard;
pub mod sapling;
pub mod sprout;
#[cfg(zcash_unstable = "nu7")]
pub mod tachyon;

pub use self::sprout::JsDescription;

// π_A + π_B + π_C
pub const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;
