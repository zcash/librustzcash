//! An engine for migrating Zcash wallet funds from the Orchard value pool to the Ironwood value
//! pool.
//!
//! The engine plans a note split into self-funding denominations, builds and signs migration
//! transactions as PCZTs, schedules them by block height, and persists its state through a wallet
//! backend; the consuming application broadcasts the transactions and reports results back. See
//! [`note_splitting`] for the note-split denomination planning.
//!
//! Inspired by an original implementation by Adam Tucker from ValarGroup, originally made
//! available in [Vizor Wallet](https://github.com/chainapsis/vizor-wallet).

#![deny(rustdoc::broken_intra_doc_links)]

pub mod note_splitting;
