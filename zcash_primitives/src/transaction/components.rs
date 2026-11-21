//! Structs representing the components within Zcash transactions.
#[cfg(feature = "orchard")]
pub mod orchard;
#[cfg(feature = "sapling")]
pub mod sapling;
pub mod sprout;
pub mod transparent;

pub use self::sprout::JsDescription;

// π_A + π_B + π_C
pub const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;
