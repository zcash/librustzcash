//! Functions for scanning the chain and extracting relevant information.

use protobuf::parse_from_bytes;

use rusqlite::types::ToSql;

use zcash_primitives::consensus::BlockHeight;

use zcash_client_backend::proto::compact_formats::CompactBlock;

use crate::{error::SqliteClientError, CacheConnection};

struct CompactBlockRow {
    height: BlockHeight,
    data: Vec<u8>,
}

pub fn with_cached_blocks<F>(
    cache: &CacheConnection,
    from_height: BlockHeight,
    limit: Option<u32>,
    mut with_row: F,
) -> Result<(), SqliteClientError>
where
    F: FnMut(BlockHeight, CompactBlock) -> Result<(), SqliteClientError>,
{
    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = cache.0.prepare(
        "SELECT height, data FROM compactblocks WHERE height > ? ORDER BY height ASC LIMIT ?",
    )?;
    let rows = stmt_blocks.query_map(
        &[
            u32::from(from_height).to_sql()?,
            limit.unwrap_or(u32::max_value()).to_sql()?,
        ],
        |row| {
            Ok(CompactBlockRow {
                height: BlockHeight::from_u32(row.get(0)?),
                data: row.get(1)?,
            })
        },
    )?;

    for row_result in rows {
        let row = row_result?;
        with_row(row.height, parse_from_bytes(&row.data)?)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use tempfile::NamedTempFile;

    use zcash_primitives::{
        block::BlockHash,
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use zcash_client_backend::data_api::{chain::scan_cached_blocks, error::ChainInvalid};

    use crate::{
        init::{init_accounts_table, init_cache_database, init_data_database},
        query::get_balance,
        tests::{
            self, fake_compact_block, fake_compact_block_spending, insert_into_cache,
            sapling_activation_height,
        },
        AccountId, CacheConnection, DataConnection, NoteId,
    };

    #[test]
    fn scan_cached_blocks_requires_sequential_blocks() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = CacheConnection(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Create a block with height SAPLING_ACTIVATION_HEIGHT
        let value = Amount::from_u64(50000).unwrap();
        let (cb1, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb1);
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);

        // We cannot scan a block of height SAPLING_ACTIVATION_HEIGHT + 2 next
        let (cb2, _) = fake_compact_block(
            sapling_activation_height() + 1,
            cb1.hash(),
            extfvk.clone(),
            value,
        );
        let (cb3, _) = fake_compact_block(
            sapling_activation_height() + 2,
            cb2.hash(),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb3);
        match scan_cached_blocks(&tests::network(), &db_cache, &db_data, None) {
            Ok(_) => panic!("Should have failed"),
            Err(e) => {
                assert_eq!(
                    e.to_string(),
                    ChainInvalid::block_height_mismatch::<rusqlite::Error, NoteId>(
                        sapling_activation_height() + 1,
                        sapling_activation_height() + 2
                    )
                    .to_string()
                );
            }
        }

        // If we add a block of height SAPLING_ACTIVATION_HEIGHT + 1, we can now scan both
        insert_into_cache(&db_cache, &cb2);
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();
        assert_eq!(
            get_balance(&db_data, AccountId(0)).unwrap(),
            Amount::from_u64(150_000).unwrap()
        );
    }

    #[test]
    fn scan_cached_blocks_finds_received_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = CacheConnection(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Account balance should be zero
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), Amount::zero());

        // Create a fake CompactBlock sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let (cb, _) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Account balance should reflect the received note
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);

        // Create a second fake CompactBlock sending more value to the address
        let value2 = Amount::from_u64(7).unwrap();
        let (cb2, _) =
            fake_compact_block(sapling_activation_height() + 1, cb.hash(), extfvk, value2);
        insert_into_cache(&db_cache, &cb2);

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Account balance should reflect both received notes
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value + value2);
    }

    #[test]
    fn scan_cached_blocks_finds_change_notes() {
        let cache_file = NamedTempFile::new().unwrap();
        let db_cache = CacheConnection(Connection::open(cache_file.path()).unwrap());
        init_cache_database(&db_cache).unwrap();

        let data_file = NamedTempFile::new().unwrap();
        let db_data = DataConnection(Connection::open(data_file.path()).unwrap());
        init_data_database(&db_data).unwrap();

        // Add an account to the wallet
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        init_accounts_table(&db_data, &tests::network(), &[extfvk.clone()]).unwrap();

        // Account balance should be zero
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), Amount::zero());

        // Create a fake CompactBlock sending value to the address
        let value = Amount::from_u64(5).unwrap();
        let (cb, nf) = fake_compact_block(
            sapling_activation_height(),
            BlockHash([0; 32]),
            extfvk.clone(),
            value,
        );
        insert_into_cache(&db_cache, &cb);

        // Scan the cache
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Account balance should reflect the received note
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value);

        // Create a second fake CompactBlock spending value from the address
        let extsk2 = ExtendedSpendingKey::master(&[0]);
        let to2 = extsk2.default_address().unwrap().1;
        let value2 = Amount::from_u64(2).unwrap();
        insert_into_cache(
            &db_cache,
            &fake_compact_block_spending(
                sapling_activation_height() + 1,
                cb.hash(),
                (nf, value),
                extfvk,
                to2,
                value2,
            ),
        );

        // Scan the cache again
        scan_cached_blocks(&tests::network(), &db_cache, &db_data, None).unwrap();

        // Account balance should equal the change
        assert_eq!(get_balance(&db_data, AccountId(0)).unwrap(), value - value2);
    }
}
