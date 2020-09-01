//! *A crate for implementing Zcash light clients.*
//!
//! `zcash_client_backend` contains Rust structs and traits for creating shielded Zcash
//! light clients.

// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]

pub mod constants;
mod decrypt;
pub mod encoding;
pub mod keys;
pub mod proto;
pub mod wallet;
pub mod welding_rig;

pub use decrypt::{decrypt_transaction, DecryptedOutput};
