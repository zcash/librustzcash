//! Compile-time assertions pinning the in-memory size of every structure a PCZT
//! allocates.
//!
//! A PCZT is parsed in full before anything is signed, so its in-memory footprint, not
//! its serialized size, is what bounds how large a transaction a memory-constrained
//! signer can handle. On a hardware wallet that budget is measured in hundreds of
//! kilobytes, and a bundle holds one [`orchard::Action`] per action, so a field added to
//! `Action` costs its size times the action count, times however many copies of the
//! parsed PCZT are live at once. These assertions make that cost visible in the commit
//! that introduces it rather than in a signing failure on a device.
//!
//! The numbers are not a target. They are a record of what the layout is today, so that
//! a change to it has to be deliberate.
//!
//! # Why two numbers per type
//!
//! `size_of` is target-dependent: pointers, and therefore the `Vec` and `BTreeMap`
//! headers these structures are full of, are half the width on a 32-bit target. A signer
//! runs on 32-bit hardware while CI runs on 64-bit, so pinning only the host size would
//! leave the interesting target unpinned. Both are recorded, selected by
//! `target_pointer_width`.
//!
//! # How each is checked
//!
//! The 64-bit assertions are compiled by any ordinary test build:
//!
//! ```text
//! cargo test -p pczt --all-features
//! ```
//!
//! The 32-bit assertions need a 32-bit target. A `const` assertion is evaluated during
//! type checking, so `cargo check` proves them without a test runner, an emulator, or a
//! device, which is what makes covering an embedded target practical at all:
//!
//! ```text
//! cargo check -p pczt --target thumbv7em-none-eabihf \
//!     --no-default-features --features orchard,sapling,transparent,size-assertions
//! ```
//!
//! The `size-assertions` feature exists only to compile this module outside a test
//! build, since a `no_std` target cannot build the test harness.
//!
//! # Updating a number
//!
//! Measure it; do not compute it by hand and do not guess. A failing assertion reports
//! that a size changed but not what it changed to, so to read the new value, temporarily
//! add
//!
//! ```text
//! const _: [(); 0] = [(); size_of::<Type>()];
//! ```
//!
//! and build for the target in question: the mismatch names the actual size. Then update
//! both numbers, because a change almost never moves only one of them.
//!
//! # A note on what dominates
//!
//! Of [`orchard::Spend`]'s bytes, 1032 are the `witness` field, an
//! `Option<(u32, [[u8; 32]; 32])>` that occupies its full size whether or not a witness
//! is present, because it has no niche to store the discriminant in. Under ZIP 374 a
//! witness is authorizing data that a signer never sees, so on a signing path those
//! bytes are reserved for a field that is structurally empty. Boxing it would cost a
//! pointer instead, and would not change the serialized encoding, since `postcard`
//! encodes `Box<T>` exactly as `T`. That change is deliberately NOT made here: this
//! module's job is to pin the current layout so such a change can be measured.

/// Pins a type's size on both pointer widths this crate is built for.
///
/// Takes both numbers together so they cannot drift apart, and so a reader sees the
/// 32-bit cost next to the 64-bit one rather than having to build for a device to
/// discover it.
macro_rules! assert_size_of {
    ($t:ty, w64 = $w64:expr, w32 = $w32:expr $(,)?) => {
        #[cfg(target_pointer_width = "64")]
        const _: () = assert!(
            size_of::<$t>() == $w64,
            concat!(stringify!($t), " changed size on a 64-bit target"),
        );
        #[cfg(target_pointer_width = "32")]
        const _: () = assert!(
            size_of::<$t>() == $w32,
            concat!(stringify!($t), " changed size on a 32-bit target"),
        );
    };
}

assert_size_of!(crate::Pczt, w64 = 528, w32 = 408);
assert_size_of!(crate::common::Global, w64 = 56, w32 = 44);
assert_size_of!(crate::common::Zip32Derivation, w64 = 56, w32 = 44);

// One `Action` per Orchard action, so every byte here is multiplied by the action count
// of the bundle. `Spend` is the bulk of it, and the `witness` field is the bulk of that.
#[cfg(feature = "orchard")]
mod orchard {
    assert_size_of!(crate::orchard::Bundle, w64 = 136, w32 = 112);
    assert_size_of!(crate::orchard::Action, w64 = 1960, w32 = 1872);
    assert_size_of!(crate::orchard::Spend, w64 = 1536, w32 = 1512);
    assert_size_of!(crate::orchard::Output, w64 = 352, w32 = 288);
}

#[cfg(feature = "sapling")]
mod sapling {
    assert_size_of!(crate::sapling::Bundle, w64 = 144, w32 = 112);
    assert_size_of!(crate::sapling::Spend, w64 = 1760, w32 = 1736);
    assert_size_of!(crate::sapling::Output, w64 = 600, w32 = 544);
}

#[cfg(feature = "transparent")]
mod transparent {
    assert_size_of!(crate::transparent::Bundle, w64 = 48, w32 = 24);
    assert_size_of!(crate::transparent::Input, w64 = 312, w32 = 192);
    assert_size_of!(crate::transparent::Output, w64 = 128, w32 = 72);
}
