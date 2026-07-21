//! A backend-agnostic engine for migrating Zcash wallet funds between value pools. Zcash's first use
//! is the Orchard -> Ironwood migration enabled by NU6.3.
//!
//! The engine plans a note split into self-funding denominations, builds and signs migration
//! transactions as PCZTs, schedules them by block height, and persists its state through a wallet
//! backend; the consuming application broadcasts the transactions and reports results back. See
//! [`note_splitting`] for the note-split denomination planning.
//!
//! Inspired by an original implementation by Adam Tucker from ValarGroup, originally made
//! available in [Vizor Wallet](https://github.com/chainapsis/vizor-wallet).

#![no_std]
#![deny(rustdoc::broken_intra_doc_links)]

// The crate itself is `no_std` and needs only `alloc`; `macro_use` brings the `vec!` and `format!`
// macros into scope (the `build` module uses `format!`), and the tests link `std` for `proptest`.
#[macro_use]
extern crate alloc;
// The `wallet` adapter integrates with `zcash_client_backend`, which is a `std` crate; link `std`
// whenever that feature (or the test harness) is active.
#[cfg(any(test, feature = "wallet"))]
extern crate std;

#[cfg(feature = "orchard")]
pub mod build;
pub mod engine;
pub mod note_splitting;
pub mod preparation;
pub mod scheduling;
pub mod state;
#[cfg(feature = "wallet")]
pub mod wallet;
