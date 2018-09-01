#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

extern crate byteorder;
extern crate subtle;

mod fq;
pub use fq::*;
