//! Functions for parsing & serialization of Tachyon transaction components.
//!
//! Delegates to `zcash_tachyon::TachyonBundle::{read,write}`. The wire-format
//! `tachyonBundleState` byte (`0x00` absent, `0x01` proof-stamped, `0x02`
//! pointer-stamped) is handled inside `TachyonBundle::{read,write}`, which own
//! the `NoBundle` (`0x00`) state directly. Here we translate that state to and
//! from `Option<TachyonBundle>` so the rest of the transaction code keeps its
//! `Option`-based representation.

use corez::io::{self, Read, Write};

use zcash_tachyon::TachyonBundle;

/// Reads a tachyon bundle from a v7 (tachyon) transaction.
pub fn read_v7_bundle<R: Read>(reader: R) -> io::Result<Option<TachyonBundle>> {
    Ok(match TachyonBundle::read(reader)? {
        TachyonBundle::NoBundle => None,
        bundle => Some(bundle),
    })
}

/// Writes a tachyon bundle in a v7 (tachyon) transaction.
pub fn write_v7_bundle<W: Write>(bundle: Option<&TachyonBundle>, mut writer: W) -> io::Result<()> {
    match bundle {
        None => TachyonBundle::NoBundle.write(&mut writer),
        Some(bundle) => bundle.write(&mut writer),
    }
}
