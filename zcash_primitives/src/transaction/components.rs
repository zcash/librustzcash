//! Structs representing the components within Zcash transactions.
#[cfg(feature = "orchard")]
pub mod orchard;
/// Parsing and serialization of Orchard components when the `orchard` feature is disabled.
#[cfg(not(feature = "orchard"))]
pub mod orchard_raw;
#[cfg(feature = "sapling")]
pub mod sapling;
/// Parsing and serialization of Sapling components when the `sapling` feature is disabled.
#[cfg(not(feature = "sapling"))]
pub mod sapling_raw;
pub mod sprout;

pub use self::sprout::JsDescription;

// π_A + π_B + π_C
pub const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;
