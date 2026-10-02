//! Owned, zero-initialized storage for the solver tables.

use core::ops::{Deref, DerefMut};

use alloc::vec::Vec;

pub(super) struct Table(Vec<u32>);

impl Table {
    pub(super) fn new_zeroed(length: usize) -> Self {
        Self(vec![0; length])
    }
}

impl Deref for Table {
    type Target = [u32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Table {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
