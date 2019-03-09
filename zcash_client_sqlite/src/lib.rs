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

use rusqlite::{Connection, NO_PARAMS};
use std::cmp;
use zcash_client_backend::{
    constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS, encoding::encode_payment_address,
};
use zcash_primitives::zip32::ExtendedFullViewingKey;

pub mod error;
pub mod init;
pub mod query;

const ANCHOR_OFFSET: u32 = 10;

fn address_from_extfvk(extfvk: &ExtendedFullViewingKey) -> String {
    let addr = extfvk.default_address().unwrap().1;
    encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &addr)
}

/// Determines the target height for a transaction, and the height from which to
/// select anchors, based on the current synchronised block chain.
fn get_target_and_anchor_heights(data: &Connection) -> Result<(u32, u32), error::Error> {
    data.query_row_and_then(
        "SELECT MIN(height), MAX(height) FROM blocks",
        NO_PARAMS,
        |row| match (row.get::<_, u32>(0), row.get::<_, u32>(1)) {
            // If there are no blocks, the query returns NULL.
            (Err(rusqlite::Error::InvalidColumnType(_, _, _)), _)
            | (_, Err(rusqlite::Error::InvalidColumnType(_, _, _))) => {
                Err(error::Error(error::ErrorKind::ScanRequired))
            }
            (Err(e), _) | (_, Err(e)) => Err(e.into()),
            (Ok(min_height), Ok(max_height)) => {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height =
                    cmp::max(target_height.saturating_sub(ANCHOR_OFFSET), min_height);

                Ok((target_height, anchor_height))
            }
        },
    )
}
