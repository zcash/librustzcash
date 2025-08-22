//! The Updater role (anyone can contribute).
//!
//! - Adds information necessary for subsequent entities to proceed, such as key paths
//!   for signing spends.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{common::Global, Pczt};

#[cfg(feature = "orchard")]
mod orchard;
#[cfg(feature = "orchard")]
pub use orchard::OrchardError;

#[cfg(feature = "sapling")]
mod sapling;
#[cfg(feature = "sapling")]
pub use sapling::SaplingError;

#[cfg(feature = "transparent")]
mod transparent;
#[cfg(feature = "transparent")]
pub use transparent::TransparentError;

pub struct Updater {
    pczt: Pczt,
}

impl Updater {
    /// Instantiates the Updater role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Updates the global transaction details with information in the given closure.
    pub fn update_global_with<F>(self, f: F) -> Self
    where
        F: FnOnce(GlobalUpdater<'_>),
    {
        let Pczt {
            mut global,
            transparent,
            sapling,
            orchard,
        } = self.pczt;

        f(GlobalUpdater(&mut global));

        Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
            },
        }
    }

    /// Finishes the Updater role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}

/// An updater for a transparent PCZT output.
pub struct GlobalUpdater<'a>(&'a mut Global);

impl GlobalUpdater<'_> {
    /// Stores the given proprietary value at the given key.
    pub fn set_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.proprietary.insert(key, value);
    }
}
