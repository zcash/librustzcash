#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

// For workspace compilation reasons, we have this crate in the workspace and just leave
// it empty if `zfuture` is not enabled.

#[cfg(zcash_unstable = "zfuture")]
pub mod consensus;
#[cfg(zcash_unstable = "zfuture")]
pub mod transparent;
