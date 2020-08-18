//! Functions for scanning the chain and extracting relevant information.

use ff::PrimeField;
use protobuf::parse_from_bytes;

use rusqlite::{types::ToSql, OptionalExtension, NO_PARAMS};

use zcash_client_backend::{
    address::RecipientAddress,
    data_api::{
        error::{ChainInvalid, Error},
        DBOps,
    },
    decrypt_transaction,
    encoding::decode_extended_full_viewing_key,
    proto::compact_formats::CompactBlock,
    welding_rig::scan_block,
};

use zcash_primitives::{
    consensus::{self, BlockHeight, NetworkUpgrade},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::Node,
    transaction::Transaction,
};

use crate::{error::SqliteClientError, CacheConnection, DataConnection, NoteId};

struct CompactBlockRow {
    height: BlockHeight,
    data: Vec<u8>,
}

#[derive(Clone)]
struct WitnessRow {
    id_note: i64,
    witness: IncrementalWitness<Node>,
}

/// Scans at most `limit` new blocks added to the cache for any transactions received by
/// the tracked accounts.
///
/// This function will return without error after scanning at most `limit` new blocks, to
/// enable the caller to update their UI with scanning progress. Repeatedly calling this
/// function will process sequential ranges of blocks, and is equivalent to calling
/// `scan_cached_blocks` and passing `None` for the optional `limit` value.
///
/// This function pays attention only to cached blocks with heights greater than the
/// highest scanned block in `db_data`. Cached blocks with lower heights are not verified
/// against previously-scanned blocks. In particular, this function **assumes** that the
/// caller is handling rollbacks.
///
/// For brand-new light client databases, this function starts scanning from the Sapling
/// activation height. This height can be fast-forwarded to a more recent block by calling
/// [`init_blocks_table`] before this function.
///
/// Scanned blocks are required to be height-sequential. If a block is missing from the
/// cache, an error will be returned with kind [`ChainInvalid::HeightMismatch`].
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::{
///     Network,
///     Parameters,
/// };
/// use zcash_client_sqlite::{
///     CacheConnection,
///     DataConnection,
///     scan::scan_cached_blocks,
/// };
///
/// let cache_file = NamedTempFile::new().unwrap();
/// let cache = CacheConnection::for_path(cache_file).unwrap();
/// let data_file = NamedTempFile::new().unwrap();
/// let data = DataConnection::for_path(data_file).unwrap();
/// scan_cached_blocks(&Network::TestNetwork, &cache, &data, None);
/// ```
///
/// [`init_blocks_table`]: crate::init::init_blocks_table
pub fn scan_cached_blocks<P: consensus::Parameters>(
    params: &P,
    cache: &CacheConnection,
    data: &DataConnection,
    limit: Option<u32>,
) -> Result<(), SqliteClientError> {
    let sapling_activation_height = params
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(Error::SaplingNotActive)?;

    // Recall where we synced up to previously.
    // If we have never synced, use sapling activation height to select all cached CompactBlocks.
    let mut last_height = data.block_height_extrema().map(|opt| {
        opt.map(|(_, max)| max)
            .unwrap_or(sapling_activation_height - 1)
    })?;

    // Raise SQL errors from the query, IO errors from parsing, and incorrect HRP errors.
    let extfvks = data.get_extended_full_viewing_keys(params)?;

    // Get the most recent CommitmentTree
    let mut tree = data
        .get_commitment_tree(last_height)
        .map(|t| t.unwrap_or(CommitmentTree::new()))?;

    // Get most recent incremental witnesses for the notes we are tracking
    let mut witnesses = data.get_witnesses(last_height)?;

    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers = data
        .0
        .prepare("SELECT id_note, nf, account FROM received_notes WHERE spent IS NULL")?;
    let nullifiers = stmt_fetch_nullifiers.query_map(NO_PARAMS, |row| {
        let nf: Vec<_> = row.get(1)?;
        let account: i64 = row.get(2)?;
        Ok((nf, account as usize))
    })?;
    let mut nullifiers: Vec<_> = nullifiers.collect::<Result<_, _>>()?;

    // Prepare per-block SQL statements
    let mut stmt_insert_block = data.0.prepare(
        "INSERT INTO blocks (height, hash, time, sapling_tree)
        VALUES (?, ?, ?, ?)",
    )?;
    let mut stmt_update_tx = data.0.prepare(
        "UPDATE transactions
        SET block = ?, tx_index = ? WHERE txid = ?",
    )?;
    let mut stmt_insert_tx = data.0.prepare(
        "INSERT INTO transactions (txid, block, tx_index)
        VALUES (?, ?, ?)",
    )?;
    let mut stmt_select_tx = data
        .0
        .prepare("SELECT id_tx FROM transactions WHERE txid = ?")?;
    let mut stmt_mark_spent_note = data
        .0
        .prepare("UPDATE received_notes SET spent = ? WHERE nf = ?")?;
    let mut stmt_update_note = data.0.prepare(
        "UPDATE received_notes
        SET account = ?, diversifier = ?, value = ?, rcm = ?, nf = ?, is_change = ?
        WHERE tx = ? AND output_index = ?",
    )?;
    let mut stmt_insert_note = data.0.prepare(
        "INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, nf, is_change)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )?;
    let mut stmt_select_note = data
        .0
        .prepare("SELECT id_note FROM received_notes WHERE tx = ? AND output_index = ?")?;
    let mut stmt_insert_witness = data.0.prepare(
        "INSERT INTO sapling_witnesses (note, block, witness)
        VALUES (?, ?, ?)",
    )?;
    let mut stmt_prune_witnesses = data
        .0
        .prepare("DELETE FROM sapling_witnesses WHERE block < ?")?;
    let mut stmt_update_expired = data.0.prepare(
        "UPDATE received_notes SET spent = NULL WHERE EXISTS (
            SELECT id_tx FROM transactions
            WHERE id_tx = received_notes.spent AND block IS NULL AND expiry_height < ?
        )",
    )?;

    // Fetch the CompactBlocks we need to scan
    let mut stmt_blocks = cache.0.prepare(
        "SELECT height, data FROM compactblocks WHERE height > ? ORDER BY height ASC LIMIT ?",
    )?;
    let rows = stmt_blocks.query_map(
        &[
            u32::from(last_height).to_sql()?,
            limit.unwrap_or(u32::max_value()).to_sql()?,
        ],
        |row| {
            Ok(CompactBlockRow {
                height: BlockHeight::from_u32(row.get(0)?),
                data: row.get(1)?,
            })
        },
    )?;

    for row in rows {
        let row = row?;

        // Start an SQL transaction for this block.
        data.0.execute("BEGIN IMMEDIATE", NO_PARAMS)?;

        // Scanned blocks MUST be height-sequential.
        if row.height != (last_height + 1) {
            return Err(SqliteClientError(ChainInvalid::block_height_mismatch(
                last_height + 1,
                row.height,
            )));
        }
        last_height = row.height;

        let block: CompactBlock = parse_from_bytes(&row.data)?;
        let block_hash = block.hash.clone();
        let block_time = block.time;

        let txs = {
            let nf_refs: Vec<_> = nullifiers.iter().map(|(nf, acc)| (&nf[..], *acc)).collect();
            let mut witness_refs: Vec<_> = witnesses.iter_mut().map(|w| &mut w.1).collect();
            scan_block(
                params,
                block,
                &extfvks[..],
                &nf_refs,
                &mut tree,
                &mut witness_refs[..],
            )
        };

        // Enforce that all roots match. This is slow, so only include in debug builds.
        #[cfg(debug_assertions)]
        {
            let cur_root = tree.root();
            for row in &witnesses {
                if row.1.root() != cur_root {
                    return Err(SqliteClientError(Error::InvalidWitnessAnchor(
                        row.0,
                        last_height,
                    )));
                }
            }
            for tx in &txs {
                for output in tx.shielded_outputs.iter() {
                    if output.witness.root() != cur_root {
                        return Err(Error::InvalidNewWitnessAnchor(
                            output.index,
                            tx.txid,
                            last_height,
                            output.witness.root(),
                        )
                        .into());
                    }
                }
            }
        }

        // Insert the block into the database.
        let mut encoded_tree = Vec::new();
        tree.write(&mut encoded_tree)
            .expect("Should be able to write to a Vec");
        stmt_insert_block.execute(&[
            u32::from(row.height).to_sql()?,
            block_hash.to_sql()?,
            block_time.to_sql()?,
            encoded_tree.to_sql()?,
        ])?;

        for tx in txs {
            // First try update an existing transaction in the database.
            let txid = tx.txid.0.to_vec();
            let tx_row = if stmt_update_tx.execute(&[
                u32::from(row.height).to_sql()?,
                (tx.index as i64).to_sql()?,
                txid.to_sql()?,
            ])? == 0
            {
                // It isn't there, so insert our transaction into the database.
                stmt_insert_tx.execute(&[
                    txid.to_sql()?,
                    u32::from(row.height).to_sql()?,
                    (tx.index as i64).to_sql()?,
                ])?;
                data.0.last_insert_rowid()
            } else {
                // It was there, so grab its row number.
                stmt_select_tx.query_row(&[txid], |row| row.get(0))?
            };

            // Mark notes as spent and remove them from the scanning cache
            for spend in &tx.shielded_spends {
                stmt_mark_spent_note.execute(&[tx_row.to_sql()?, spend.nf.to_sql()?])?;
            }
            nullifiers = nullifiers
                .into_iter()
                .filter(|(nf, _acc)| {
                    tx.shielded_spends
                        .iter()
                        .find(|spend| &spend.nf == nf)
                        .is_none()
                })
                .collect();

            for output in tx.shielded_outputs {
                let rcm = output.note.rcm().to_repr();
                let nf = output.note.nf(
                    &extfvks[output.account].fvk.vk,
                    output.witness.position() as u64,
                );

                // Assumptions:
                // - A transaction will not contain more than 2^63 shielded outputs.
                // - A note value will never exceed 2^63 zatoshis.

                // First try updating an existing received note into the database.
                let note_id = if stmt_update_note.execute(&[
                    (output.account as i64).to_sql()?,
                    output.to.diversifier().0.to_sql()?,
                    (output.note.value as i64).to_sql()?,
                    rcm.as_ref().to_sql()?,
                    nf.to_sql()?,
                    output.is_change.to_sql()?,
                    tx_row.to_sql()?,
                    (output.index as i64).to_sql()?,
                ])? == 0
                {
                    // It isn't there, so insert our note into the database.
                    stmt_insert_note.execute(&[
                        tx_row.to_sql()?,
                        (output.index as i64).to_sql()?,
                        (output.account as i64).to_sql()?,
                        output.to.diversifier().0.to_sql()?,
                        (output.note.value as i64).to_sql()?,
                        rcm.as_ref().to_sql()?,
                        nf.to_sql()?,
                        output.is_change.to_sql()?,
                    ])?;
                    NoteId(data.0.last_insert_rowid())
                } else {
                    // It was there, so grab its row number.
                    stmt_select_note.query_row(
                        &[tx_row.to_sql()?, (output.index as i64).to_sql()?],
                        |row| row.get(0).map(NoteId),
                    )?
                };

                // Save witness for note.
                witnesses.push((note_id, output.witness));

                // Cache nullifier for note (to detect subsequent spends in this scan).
                nullifiers.push((nf, output.account));
            }
        }

        // Insert current witnesses into the database.
        let mut encoded = Vec::new();
        for witness_row in witnesses.iter() {
            encoded.clear();
            witness_row
                .1
                .write(&mut encoded)
                .expect("Should be able to write to a Vec");
            stmt_insert_witness.execute(&[
                (witness_row.0).0.to_sql()?,
                u32::from(last_height).to_sql()?,
                encoded.to_sql()?,
            ])?;
        }

        // Prune the stored witnesses (we only expect rollbacks of at most 100 blocks).
        stmt_prune_witnesses.execute(&[u32::from(last_height - 100)])?;

        // Update now-expired transactions that didn't get mined.
        stmt_update_expired.execute(&[u32::from(last_height)])?;

        // Commit the SQL transaction, writing this block's data atomically.
        data.0.execute("COMMIT", NO_PARAMS)?;
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
    use rusqlite::{Connection, NO_PARAMS};

    use tempfile::NamedTempFile;

    use zcash_primitives::{
        block::BlockHash,
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use zcash_client_backend::data_api::error::ChainInvalid;

    use crate::{
        init::{init_accounts_table, init_cache_database, init_data_database},
        query::get_balance,
        tests::{
            self, fake_compact_block, fake_compact_block_spending, insert_into_cache,
            sapling_activation_height,
        },
        AccountId, CacheConnection, DataConnection, NoteId,
    };

    use super::scan_cached_blocks;

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

                //FIXME: scan_cached_blocks is leaving the database in an invalid
                //transactional state on error; this rollback should be intrinsic
                //to the failure path.
                db_data.0.execute("ROLLBACK", NO_PARAMS).unwrap();
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
