//! Structs representing the components within Zcash transactions.
pub mod orchard;
pub mod sapling;
pub mod sprout;
#[cfg(zcash_unstable = "zfuture")]
pub mod tze;

pub use self::sprout::JsDescription;

#[cfg(zcash_unstable = "zfuture")]
pub use self::tze::{TzeIn, TzeOut};

// π_A + π_B + π_C
pub const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;
