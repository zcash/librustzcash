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

// The crate itself is `no_std` and needs only `alloc` (for `Vec`); `macro_use` under test brings the
// `vec!` macro into scope, and the tests link `std` for `proptest`.
#[cfg_attr(test, macro_use)]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod note_splitting;
