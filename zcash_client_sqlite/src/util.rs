//! Capability traits for side effects required by wallet operations.
//!
//! The types in this module are re-exported from [`zcash_client_backend::util`].

pub use zcash_client_backend::util::{Clock, SystemClock};

/// Test utilities for clock simulation.
#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    pub use zcash_client_backend::util::testing::FixedClock;
}
