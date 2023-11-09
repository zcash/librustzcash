//! Structs representing the components within Zcash transactions.

pub mod amount;
pub mod orchard;
pub mod sapling;
pub mod sprout;
pub mod transparent;
pub mod tze;

pub use self::{
    amount::Amount,
    sprout::JsDescription,
    transparent::{OutPoint, TxIn, TxOut},
};
pub use crate::sapling::bundle::{OutputDescription, SpendDescription};

#[cfg(feature = "zfuture")]
pub use self::tze::{TzeIn, TzeOut};

// π_A + π_B + π_C
pub const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;
