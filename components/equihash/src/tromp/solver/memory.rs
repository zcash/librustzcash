//! Owned, zero-initialized storage for the solver tables.

use core::ops::{Deref, DerefMut};

#[cfg(not(all(feature = "unsafe-solver", target_os = "linux")))]
use alloc::vec::Vec;

#[cfg(all(feature = "unsafe-solver", target_os = "linux"))]
use core::{mem::size_of, ptr::NonNull, slice};

/// A table with an optional huge-page hint on Linux.
#[cfg(all(feature = "unsafe-solver", target_os = "linux"))]
pub(super) struct Table {
    pointer: NonNull<u32>,
    length: usize,
}

#[cfg(not(all(feature = "unsafe-solver", target_os = "linux")))]
pub(super) struct Table(Vec<u32>);

impl Table {
    pub(super) fn new_zeroed(length: usize) -> Self {
        #[cfg(all(feature = "unsafe-solver", target_os = "linux"))]
        {
            let layout = alloc::alloc::Layout::array::<u32>(length)
                .expect("solver table length exceeds the allocation limit");
            assert_ne!(length, 0);
            // SAFETY: the anonymous mapping has no backing file or requested
            // address. Its nonzero length is checked by `Layout::array`.
            // Successful mappings are page-aligned and contain zeroed bytes.
            let pointer = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    layout.size(),
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if pointer == libc::MAP_FAILED {
                alloc::alloc::handle_alloc_error(layout);
            }
            let pointer = NonNull::new(pointer.cast::<u32>())
                .expect("anonymous mapping returned a null address");
            // SAFETY: this hint applies to the complete, live mapping. Failure
            // is harmless; the table also works with ordinary pages.
            unsafe {
                libc::madvise(pointer.as_ptr().cast(), layout.size(), libc::MADV_HUGEPAGE);
            }
            Self { pointer, length }
        }
        #[cfg(not(all(feature = "unsafe-solver", target_os = "linux")))]
        {
            Self(vec![0; length])
        }
    }
}

impl Deref for Table {
    type Target = [u32];

    fn deref(&self) -> &Self::Target {
        #[cfg(all(feature = "unsafe-solver", target_os = "linux"))]
        {
            // SAFETY: the mapping is aligned, initialized and lives until
            // this owner is dropped. The shared borrow prevents mutation.
            unsafe { slice::from_raw_parts(self.pointer.as_ptr(), self.length) }
        }
        #[cfg(not(all(feature = "unsafe-solver", target_os = "linux")))]
        {
            &self.0
        }
    }
}

impl DerefMut for Table {
    fn deref_mut(&mut self) -> &mut Self::Target {
        #[cfg(all(feature = "unsafe-solver", target_os = "linux"))]
        {
            // SAFETY: this exclusive borrow owns the complete live mapping;
            // no other reference can access it during the returned borrow.
            unsafe { slice::from_raw_parts_mut(self.pointer.as_ptr(), self.length) }
        }
        #[cfg(not(all(feature = "unsafe-solver", target_os = "linux")))]
        {
            &mut self.0
        }
    }
}

#[cfg(all(feature = "unsafe-solver", target_os = "linux"))]
impl Drop for Table {
    fn drop(&mut self) {
        // SAFETY: this is the original mapping address and length. The owner
        // is being dropped, so no references into the mapping remain live.
        unsafe {
            libc::munmap(self.pointer.as_ptr().cast(), self.length * size_of::<u32>());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Table;

    #[test]
    fn table_is_zeroed_and_mutably_borrowed() {
        let mut table = Table::new_zeroed(4097);
        assert_eq!(table.len(), 4097);
        assert!(table.iter().all(|word| *word == 0));
        table[0] = 7;
        table[4096] = 11;
        assert_eq!((table[0], table[4096]), (7, 11));
        assert!(table[1..4096].iter().all(|word| *word == 0));
    }
}
