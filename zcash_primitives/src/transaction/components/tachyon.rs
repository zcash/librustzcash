//! Functions for parsing & serialization of Tachyon transaction components.
//!
//! Delegates to `zcash_tachyon::TachyonBundle::{read,write}`. The wire-format
//! `tachyonBundleState` byte (`0x00` absent, `0x01` stamped, `0x02` stripped)
//! is part of `TachyonBundle::read`; the `None` case must explicitly write the
//! `0x00` byte since `TachyonBundle::write` only emits `0x01`/`0x02`.

use core2::io::{self, Read, Write};

use zcash_tachyon::TachyonBundle;

/// Reads a tachyon bundle from v6 transaction format.
pub fn read_v6_bundle<R: Read>(reader: R) -> io::Result<Option<TachyonBundle>> {
    TachyonBundle::read(reader)
}

/// Writes a tachyon bundle in v6 transaction format.
pub fn write_v6_bundle<W: Write>(bundle: Option<&TachyonBundle>, mut writer: W) -> io::Result<()> {
    match bundle {
        None => writer.write_all(&[0u8]),
        Some(bundle) => bundle.write(&mut writer),
    }
}
