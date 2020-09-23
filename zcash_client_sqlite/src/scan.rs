//! Functions for scanning the chain and extracting relevant information.

use ff::PrimeField;
use protobuf::parse_from_bytes;

use rusqlite::{types::ToSql, OptionalExtension, NO_PARAMS};

use zcash_primitives::{
    consensus::{self, BlockHeight, NetworkUpgrade},
    transaction::Transaction,
};

use zcash_client_backend::{
    address::RecipientAddress, data_api::error::Error, decrypt_transaction,
    encoding::decode_extended_full_viewing_key, proto::compact_formats::CompactBlock,
};

use crate::{error::SqliteClientError, CacheConnection, DataConnection};

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

/// Scans a [`Transaction`] for any information that can be decrypted by the accounts in
/// the wallet, and saves it to the wallet.
pub fn decrypt_and_store_transaction<P: consensus::Parameters>(
    data: &DataConnection,
    params: &P,
    tx: &Transaction,
) -> Result<(), SqliteClientError> {
    // Fetch the ExtendedFullViewingKeys we are tracking
    let mut stmt_fetch_accounts = data
        .0
        .prepare("SELECT extfvk FROM accounts ORDER BY account ASC")?;

    let extfvks = stmt_fetch_accounts.query_map(NO_PARAMS, |row| {
        row.get(0).map(|extfvk: String| {
            decode_extended_full_viewing_key(
                params.hrp_sapling_extended_full_viewing_key(),
                &extfvk,
            )
        })
    })?;

    // Raise SQL errors from the query, IO errors from parsing, and incorrect HRP errors.
    let extfvks: Vec<_> = extfvks
        .collect::<Result<Result<Option<_>, _>, _>>()??
        .ok_or(SqliteClientError(Error::IncorrectHRPExtFVK))?;

    // Height is block height for mined transactions, and the "mempool height" (chain height + 1) for mempool transactions.
    let mut stmt_select_block = data
        .0
        .prepare("SELECT block FROM transactions WHERE txid = ?")?;
    let height = match stmt_select_block
        .query_row(&[tx.txid().0.to_vec()], |row| {
            row.get::<_, u32>(0).map(BlockHeight::from)
        })
        .optional()?
    {
        Some(height) => height,
        None => data
            .0
            .query_row("SELECT MAX(height) FROM blocks", NO_PARAMS, |row| {
                row.get(0)
            })
            .optional()?
            .map(|last_height: u32| BlockHeight::from(last_height + 1))
            .or_else(|| params.activation_height(NetworkUpgrade::Sapling))
            .ok_or(SqliteClientError(Error::SaplingNotActive))?,
    };

    let outputs = decrypt_transaction(params, height, tx, &extfvks);

    if outputs.is_empty() {
        // Nothing to see here
        return Ok(());
    }

    let mut stmt_update_tx = data.0.prepare(
        "UPDATE transactions
        SET expiry_height = ?, raw = ? WHERE txid = ?",
    )?;
    let mut stmt_insert_tx = data.0.prepare(
        "INSERT INTO transactions (txid, expiry_height, raw)
        VALUES (?, ?, ?)",
    )?;
    let mut stmt_select_tx = data
        .0
        .prepare("SELECT id_tx FROM transactions WHERE txid = ?")?;
    let mut stmt_update_sent_note = data.0.prepare(
        "UPDATE sent_notes
        SET from_account = ?, address = ?, value = ?, memo = ?
        WHERE tx = ? AND output_index = ?",
    )?;
    let mut stmt_insert_sent_note = data.0.prepare(
        "INSERT INTO sent_notes (tx, output_index, from_account, address, value, memo)
        VALUES (?, ?, ?, ?, ?, ?)",
    )?;
    let mut stmt_update_received_note = data.0.prepare(
        "UPDATE received_notes
        SET account = ?, diversifier = ?, value = ?, rcm = ?, memo = ?
        WHERE tx = ? AND output_index = ?",
    )?;
    let mut stmt_insert_received_note = data.0.prepare(
        "INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, memo)
        VALUES (?, ?, ?, ?, ?, ?, ?)",
    )?;

    // Update the database atomically, to ensure the result is internally consistent.
    data.0.execute("BEGIN IMMEDIATE", NO_PARAMS)?;

    // First try update an existing transaction in the database.
    let txid = tx.txid().0.to_vec();
    let mut raw_tx = vec![];
    tx.write(&mut raw_tx)?;
    let tx_row = if stmt_update_tx.execute(&[
        u32::from(tx.expiry_height).to_sql()?,
        raw_tx.to_sql()?,
        txid.to_sql()?,
    ])? == 0
    {
        // It isn't there, so insert our transaction into the database.
        stmt_insert_tx.execute(&[
            txid.to_sql()?,
            u32::from(tx.expiry_height).to_sql()?,
            raw_tx.to_sql()?,
        ])?;
        data.0.last_insert_rowid()
    } else {
        // It was there, so grab its row number.
        stmt_select_tx.query_row(&[txid], |row| row.get(0))?
    };

    for output in outputs {
        let output_index = output.index as i64;
        let account = output.account as i64;
        let value = output.note.value as i64;

        if output.outgoing {
            let to_str = RecipientAddress::from(output.to).encode(params);

            // Try updating an existing sent note.
            if stmt_update_sent_note.execute(&[
                account.to_sql()?,
                to_str.to_sql()?,
                value.to_sql()?,
                output.memo.as_bytes().to_sql()?,
                tx_row.to_sql()?,
                output_index.to_sql()?,
            ])? == 0
            {
                // It isn't there, so insert.
                stmt_insert_sent_note.execute(&[
                    tx_row.to_sql()?,
                    output_index.to_sql()?,
                    account.to_sql()?,
                    to_str.to_sql()?,
                    value.to_sql()?,
                    output.memo.as_bytes().to_sql()?,
                ])?;
            }
        } else {
            let rcm = output.note.rcm().to_repr();

            // Try updating an existing received note.
            if stmt_update_received_note.execute(&[
                account.to_sql()?,
                output.to.diversifier().0.to_sql()?,
                value.to_sql()?,
                rcm.as_ref().to_sql()?,
                output.memo.as_bytes().to_sql()?,
                tx_row.to_sql()?,
                output_index.to_sql()?,
            ])? == 0
            {
                // It isn't there, so insert.
                stmt_insert_received_note.execute(&[
                    tx_row.to_sql()?,
                    output_index.to_sql()?,
                    account.to_sql()?,
                    output.to.diversifier().0.to_sql()?,
                    value.to_sql()?,
                    rcm.as_ref().to_sql()?,
                    output.memo.as_bytes().to_sql()?,
                ])?;
            }
        }
    }

    data.0.execute("COMMIT", NO_PARAMS)?;

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
