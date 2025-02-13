//! Structs representing the components within Zcash transactions.
pub mod orchard;
pub mod sapling;
pub mod sprout;
#[cfg(zcash_unstable = "zfuture")]
pub mod tze;

pub use self::sprout::JsDescription;

#[deprecated(note = "This module is deprecated; use `::zcash_protocol::value` instead.")]
pub mod amount {
    #[deprecated(note = "Use `::zcash_protocol::value::BalanceError` instead.")]
    pub type BalanceError = zcash_protocol::value::BalanceError;
    #[deprecated(note = "Use `::zcash_protocol::value::ZatBalance` instead.")]
    pub type Amount = zcash_protocol::value::ZatBalance;
    #[deprecated(note = "Use `::zcash_protocol::value::Zatoshis` instead.")]
    pub type NonNegativeAmount = zcash_protocol::value::Zatoshis;
    #[deprecated(note = "Use `::zcash_protocol::value::COIN` instead.")]
    pub const COIN: u64 = zcash_protocol::value::COIN;

    #[cfg(any(test, feature = "test-dependencies"))]
    #[deprecated(note = "Use `::zcash_protocol::value::testing` instead.")]
    pub mod testing {
        pub use zcash_protocol::value::testing::arb_positive_zat_balance as arb_positive_amount;
        pub use zcash_protocol::value::testing::arb_zat_balance as arb_amount;
        pub use zcash_protocol::value::testing::arb_zatoshis as arb_nonnegative_amount;
    }
}

#[deprecated(note = "This module is deprecated; use the `zcash_transparent` crate instead.")]
pub mod transparent {
    #[deprecated(note = "This module is deprecated; use `::zcash_transparent::builder` instead.")]
    pub mod builder {
        pub use ::transparent::builder::*;
    }
    pub use ::transparent::bundle::*;
    #[deprecated(note = "This module is deprecated; use `::zcash_transparent::pczt` instead.")]
    pub mod pczt {
        pub use ::transparent::pczt::*;
    }
}

#[deprecated(note = "use `::zcash_transparent::bundle::OutPoint` instead.")]
pub type OutPoint = ::transparent::bundle::OutPoint;
#[deprecated(note = "use `::zcash_transparent::bundle::TxIn` instead.")]
pub type TxIn<A> = ::transparent::bundle::TxIn<A>;
#[deprecated(note = "use `::zcash_transparent::bundle::TxIn` instead.")]
pub type TxOut = ::transparent::bundle::TxOut;
#[deprecated(note = "use `::zcash_protocol::value::ZatBalance` instead.")]
pub type Amount = zcash_protocol::value::ZatBalance;

#[deprecated(note = "Use `::sapling_crypto::bundle::OutputDescription` instead.")]
pub type OutputDescription<A> = ::sapling::bundle::OutputDescription<A>;
#[deprecated(note = "Use `::sapling_crypto::bundle::SpendDescription` instead.")]
pub type SpendDescription<A> = ::sapling::bundle::SpendDescription<A>;

#[cfg(zcash_unstable = "zfuture")]
pub use self::tze::{TzeIn, TzeOut};

// π_A + π_B + π_C
pub const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;
