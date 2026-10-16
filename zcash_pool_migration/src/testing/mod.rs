//! Reusable test utilities for the pool-migration engine.
//!
//! Two things live here, so every store implementation is exercised the same way instead of
//! hand-rolling its own fixtures:
//!
//! - `proptest` strategies (`arb_*`) that generate the engine's persisted types, from a single
//!   `Zatoshis` up to a whole [`MigrationState`](crate::engine::MigrationState). The crate's
//!   own codec proptests consume these, and so does any downstream store crate.
//! - a backend-agnostic conformance suite (`assert_*`) over the
//!   [`PoolMigrationRead`](crate::engine::PoolMigrationRead) /
//!   [`PoolMigrationWrite`](crate::engine::PoolMigrationWrite) store traits: an empty store reads
//!   back nothing, a replace/get round-trips,
//!   a second replace overwrites the first, and a transaction state update persists. Point any store
//!   (the SQLite store, a future in-memory backend) at these and it inherits the same coverage.
//!
//! Enabled by the `test-dependencies` feature (and by the crate's own `test` build), so a
//! downstream crate reuses these directly rather than duplicating them.
//!
//! The groups are split into submodules and re-exported here, so every path resolves at
//! `testing::`: `generators` builds values, `conformance` says what correctness means, and
//! `scenarios` and `preparation_vectors` hold the fixed data the suites speak about. The
//! generators are NOT called `strategies`, which in this crate names a solution to one of the
//! planning problems ([`PreparationStrategy`](crate::preparation::PreparationStrategy) and
//! friends) rather than a `proptest` value source.

mod conformance;
mod generators;
mod preparation_vectors;
mod scenarios;
mod wallets;

pub use conformance::*;
pub use generators::*;
pub use preparation_vectors::*;
pub use scenarios::*;
pub use wallets::*;
