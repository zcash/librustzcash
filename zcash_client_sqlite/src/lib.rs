//! *An SQLite-based Zcash light client.*
//!
//! `zcash_client_backend` contains a set of APIs that collectively implement an
//! SQLite-based light client for the Zcash network.
//!
//! # Design
//!
//! The light client is built around two SQLite databases:
//!
//! - A cache database, used to inform the light client about new [`CompactBlock`]s. It is
//!   read-only within all light client APIs *except* for [`init_cache_database`] which
//!   can be used to initialize the database.
//!
//! - A data database, where the light client's state is stored. It is read-write within
//!   the light client APIs, and **assumed to be read-only outside these APIs**. Callers
//!   **MUST NOT** write to the database without using these APIs. Callers **MAY** read
//!   the database directly in order to extract information for display to users.
//!
//! [`CompactBlock`]: zcash_client_backend::proto::compact_formats::CompactBlock
//! [`init_cache_database`]: crate::init::init_cache_database

use zcash_client_backend::{
    constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS, encoding::encode_payment_address,
};
use zcash_primitives::zip32::ExtendedFullViewingKey;

pub mod error;
pub mod init;

fn address_from_extfvk(extfvk: &ExtendedFullViewingKey) -> String {
    let addr = extfvk.default_address().unwrap().1;
    encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &addr)
}
