//! This migration adds decryption key scope to persisted information about received notes.

use std::collections::HashSet;

use group::ff::PrimeField;
use incrementalmerkletree::Position;
use rusqlite::{self, named_params};
use schemer;
use schemer_rusqlite::RusqliteMigration;

use shardtree::{store::ShardStore, ShardTree};
use uuid::Uuid;

use sapling::{
    note_encryption::{try_sapling_note_decryption, PreparedIncomingViewingKey, Zip212Enforcement},
    zip32::DiversifiableFullViewingKey,
    Diversifier, Node, Rseed,
};
use zcash_client_backend::{data_api::SAPLING_SHARD_HEIGHT, keys::UnifiedFullViewingKey};
use zcash_primitives::{
    consensus::{self, BlockHeight, BranchId},
    transaction::{
        components::{amount::NonNegativeAmount, sapling::zip212_enforcement},
        Transaction,
    },
    zip32::Scope,
};

use crate::{
    wallet::{
        commitment_tree::SqliteShardStore,
        init::{migrations::shardtree_support, WalletMigrationError},
        scan_queue_extrema, scope_code,
    },
    PRUNING_DEPTH, SAPLING_TABLES_PREFIX,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xee89ed2b_c1c2_421e_9e98_c1e3e54a7fc2);

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemer::Migration for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [shardtree_support::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Add decryption key scope to persisted information about received notes."
    }
}

#[allow(clippy::type_complexity)]
fn select_note_scope<S: ShardStore<H = sapling::Node, CheckpointId = BlockHeight>>(
    commitment_tree: &mut ShardTree<
        S,
        { sapling::NOTE_COMMITMENT_TREE_DEPTH },
        SAPLING_SHARD_HEIGHT,
    >,
    dfvk: &DiversifiableFullViewingKey,
    diversifier: &sapling::Diversifier,
    value: &sapling::value::NoteValue,
    rseed: &sapling::Rseed,
    note_commitment_tree_position: Position,
) -> Result<Option<Scope>, WalletMigrationError> {
    // Attempt to reconstruct the note being spent using both the internal and external dfvks
    // corresponding to the unified spending key, checking against the witness we are using
    // to spend the note that we've used the correct key.
    let external_note = dfvk
        .diversified_address(*diversifier)
        .map(|addr| addr.create_note(*value, *rseed));
    let internal_note = dfvk
        .diversified_change_address(*diversifier)
        .map(|addr| addr.create_note(*value, *rseed));

    if let Some(recorded_node) = commitment_tree
        .get_marked_leaf(note_commitment_tree_position)
        .map_err(|e| {
            WalletMigrationError::CorruptedData(format!(
                "Error querying note commitment tree: {:?}",
                e
            ))
        })?
    {
        if external_note.map(|n| Node::from_cmu(&n.cmu())) == Some(recorded_node) {
            Ok(Some(Scope::External))
        } else if internal_note.map(|n| Node::from_cmu(&n.cmu())) == Some(recorded_node) {
            Ok(Some(Scope::Internal))
        } else {
            Err(WalletMigrationError::CorruptedData(
                "Unable to reconstruct note.".to_owned(),
            ))
        }
    } else {
        Ok(None)
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            &format!(
                "ALTER TABLE sapling_received_notes ADD COLUMN recipient_key_scope INTEGER NOT NULL DEFAULT {};",
                scope_code(Scope::External)
            )
        )?;

        // For all notes we have to determine whether they were actually sent to the internal key
        // or the external key for the account, so we trial-decrypt the original output with the
        // internal IVK and update the persisted scope value if necessary. We check all notes,
        // rather than just change notes, because shielding notes may not have been considered
        // change.
        let mut stmt_select_notes = transaction.prepare(
            "SELECT
                id_note,
                output_index,
                transactions.raw,
                transactions.block,
                transactions.expiry_height,
                accounts.ufvk,
                diversifier,
                value,
                rcm,
                commitment_tree_position
             FROM sapling_received_notes
             INNER JOIN accounts on accounts.account = sapling_received_notes.account
             INNER JOIN transactions ON transactions.id_tx = sapling_received_notes.tx",
        )?;

        // In the case that we don't have the raw transaction
        let mut commitment_tree = ShardTree::new(
            SqliteShardStore::<_, _, SAPLING_SHARD_HEIGHT>::from_connection(
                transaction,
                SAPLING_TABLES_PREFIX,
            )?,
            PRUNING_DEPTH as usize,
        );

        let mut rows = stmt_select_notes.query([])?;
        while let Some(row) = rows.next()? {
            let note_id: i64 = row.get(0)?;
            let output_index: usize = row.get(1)?;
            let tx_data_opt: Option<Vec<u8>> = row.get(2)?;

            let tx_height = row.get::<_, Option<u32>>(3)?.map(BlockHeight::from);
            let tx_expiry = row.get::<_, Option<u32>>(4)?;
            let zip212_height = tx_height.map_or_else(
                || {
                    tx_expiry.filter(|h| *h != 0).map_or_else(
                        || scan_queue_extrema(transaction).map(|extrema| extrema.map(|r| *r.end())),
                        |h| Ok(Some(BlockHeight::from(h))),
                    )
                },
                |h| Ok(Some(h)),
            )?;

            let zip212_enforcement = zip212_height.map_or_else(
                || {
                    // If the transaction has not been mined and the expiry height is set to 0 (no
                    // expiry) an no chain tip information is available, then we assume it can only
                    // be mined under ZIP 212 enforcement rules, so we default to `On`
                    Zip212Enforcement::On
                },
                |h| zip212_enforcement(&self.params, h),
            );

            let ufvk_str: String = row.get(5)?;
            let ufvk = UnifiedFullViewingKey::decode(&self.params, &ufvk_str).map_err(|e| {
                WalletMigrationError::CorruptedData(format!("Stored UFVK was invalid: {:?}", e))
            })?;

            let dfvk = ufvk.sapling().ok_or_else(|| {
                WalletMigrationError::CorruptedData(
                    "UFVK must have a Sapling component to have received Sapling notes.".to_owned(),
                )
            })?;

            // We previously set the default to external scope, so we now verify whether the output
            // is decryptable using the intenally-scoped IVK and, if so, mark it as such.
            if let Some(tx_data) = tx_data_opt {
                let tx = Transaction::read(&tx_data[..], BranchId::Canopy).map_err(|e| {
                    WalletMigrationError::CorruptedData(format!(
                        "Unable to parse raw transaction: {:?}",
                        e
                    ))
                })?;
                let output = tx
                    .sapling_bundle()
                    .and_then(|b| b.shielded_outputs().get(output_index))
                    .unwrap_or_else(|| {
                        panic!("A Sapling output must exist at index {}", output_index)
                    });

                let pivk = PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::Internal));
                if try_sapling_note_decryption(&pivk, output, zip212_enforcement).is_some() {
                    transaction.execute(
                        "UPDATE sapling_received_notes SET recipient_key_scope = :scope
                         WHERE id_note = :note_id",
                        named_params! {":scope": scope_code(Scope::Internal), ":note_id": note_id},
                    )?;
                }
            } else {
                let diversifier = {
                    let d: Vec<_> = row.get(6)?;
                    Diversifier(d[..].try_into().map_err(|_| {
                        WalletMigrationError::CorruptedData(
                            "Invalid diversifier length".to_string(),
                        )
                    })?)
                };

                let note_value =
                    NonNegativeAmount::from_nonnegative_i64(row.get(7)?).map_err(|_e| {
                        WalletMigrationError::CorruptedData(
                            "Note values must be nonnegative".to_string(),
                        )
                    })?;

                let rseed = {
                    let rcm_bytes: [u8; 32] =
                        row.get::<_, Vec<u8>>(8)?[..].try_into().map_err(|_| {
                            WalletMigrationError::CorruptedData(format!(
                                "Note {} is invalid",
                                note_id
                            ))
                        })?;

                    let rcm = Option::from(jubjub::Fr::from_repr(rcm_bytes)).ok_or_else(|| {
                        WalletMigrationError::CorruptedData(format!("Note {} is invalid", note_id))
                    })?;

                    // The wallet database always stores the `rcm` value, and not `rseed`,
                    // so for note reconstruction we always use `BeforeZip212`.
                    Rseed::BeforeZip212(rcm)
                };

                let note_commitment_tree_position =
                    Position::from(u64::try_from(row.get::<_, i64>(9)?).map_err(|_| {
                        WalletMigrationError::CorruptedData(
                            "Note commitment tree position invalid.".to_string(),
                        )
                    })?);

                let scope = select_note_scope(
                    &mut commitment_tree,
                    dfvk,
                    &diversifier,
                    &sapling::value::NoteValue::from_raw(note_value.into_u64()),
                    &rseed,
                    note_commitment_tree_position,
                )?;

                if scope == Some(Scope::Internal) {
                    transaction.execute(
                        "UPDATE sapling_received_notes SET recipient_key_scope = :scope
                         WHERE id_note = :note_id",
                        named_params! {":scope": scope_code(Scope::Internal), ":note_id": note_id},
                    )?;
                }
            }
        }

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(feature = "transparent-inputs")]
#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use incrementalmerkletree::Position;
    use maybe_rayon::{
        iter::{IndexedParallelIterator, ParallelIterator},
        slice::ParallelSliceMut,
    };
    use rand_core::OsRng;
    use rusqlite::{named_params, params, Connection};
    use tempfile::NamedTempFile;
    use zcash_client_backend::{
        data_api::{BlockMetadata, WalletCommitmentTrees, SAPLING_SHARD_HEIGHT},
        decrypt_transaction,
        proto::compact_formats::{CompactBlock, CompactTx},
        scanning::{scan_block, Nullifiers, ScanningKeys},
        TransferType,
    };
    use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, Network, NetworkUpgrade, Parameters},
        legacy::keys::{IncomingViewingKey, NonHardenedChildIndex},
        memo::MemoBytes,
        transaction::{
            builder::{BuildConfig, BuildResult, Builder},
            components::{amount::NonNegativeAmount, transparent},
            fees::fixed,
        },
        zip32::{self, Scope},
    };
    use zcash_proofs::prover::LocalTxProver;

    use crate::{
        error::SqliteClientError,
        wallet::{
            init::{
                init_wallet_db_internal,
                migrations::{add_account_birthdays, shardtree_support, wallet_summaries},
            },
            memo_repr, parse_scope,
            sapling::ReceivedSaplingOutput,
        },
        AccountId, WalletDb,
    };

    // These must be different.
    const EXTERNAL_VALUE: u64 = 10;
    const INTERNAL_VALUE: u64 = 5;

    fn prepare_wallet_state<P: Parameters>(
        db_data: &mut WalletDb<Connection, P>,
    ) -> (UnifiedFullViewingKey, BlockHeight, BuildResult) {
        // Create an account in the wallet
        let usk0 =
            UnifiedSpendingKey::from_seed(&db_data.params, &[0u8; 32][..], zip32::AccountId::ZERO)
                .unwrap();
        let ufvk0 = usk0.to_unified_full_viewing_key();
        let height = db_data
            .params
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();
        db_data
            .conn
            .execute(
                "INSERT INTO accounts (account, ufvk, birthday_height) VALUES (0, ?, ?)",
                params![ufvk0.encode(&db_data.params), u32::from(height)],
            )
            .unwrap();
        let sapling_dfvk = ufvk0.sapling().unwrap();
        let ovk = sapling_dfvk.to_ovk(Scope::External);
        let (_, external_addr) = sapling_dfvk.default_address();
        let (_, internal_addr) = sapling_dfvk.change_address();

        // Create a shielding transaction that has an external note and an internal note.
        let mut builder = Builder::new(
            db_data.params.clone(),
            height,
            BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: None,
            },
        );
        builder
            .add_transparent_input(
                usk0.transparent()
                    .derive_external_secret_key(NonHardenedChildIndex::ZERO)
                    .unwrap(),
                transparent::OutPoint::new([1; 32], 0),
                transparent::TxOut {
                    value: NonNegativeAmount::const_from_u64(EXTERNAL_VALUE + INTERNAL_VALUE),
                    script_pubkey: usk0
                        .transparent()
                        .to_account_pubkey()
                        .derive_external_ivk()
                        .unwrap()
                        .default_address()
                        .0
                        .script(),
                },
            )
            .unwrap();
        builder
            .add_sapling_output::<Infallible>(
                Some(ovk),
                external_addr,
                NonNegativeAmount::const_from_u64(EXTERNAL_VALUE),
                MemoBytes::empty(),
            )
            .unwrap();
        builder
            .add_sapling_output::<Infallible>(
                Some(ovk),
                internal_addr,
                NonNegativeAmount::const_from_u64(INTERNAL_VALUE),
                MemoBytes::empty(),
            )
            .unwrap();
        let prover = LocalTxProver::bundled();
        let res = builder
            .build(
                OsRng,
                &prover,
                &prover,
                &fixed::FeeRule::non_standard(NonNegativeAmount::ZERO),
            )
            .unwrap();

        (ufvk0, height, res)
    }

    fn put_received_note_before_migration<T: ReceivedSaplingOutput>(
        conn: &Connection,
        output: &T,
        tx_ref: i64,
        spent_in: Option<i64>,
    ) -> Result<(), SqliteClientError> {
        let mut stmt_upsert_received_note = conn.prepare_cached(
            "INSERT INTO sapling_received_notes
            (tx, output_index, account, diversifier, value, rcm, memo, nf,
             is_change, spent, commitment_tree_position)
            VALUES (
                :tx,
                :output_index,
                :account,
                :diversifier,
                :value,
                :rcm,
                :memo,
                :nf,
                :is_change,
                :spent,
                :commitment_tree_position
            )
            ON CONFLICT (tx, output_index) DO UPDATE
            SET account = :account,
                diversifier = :diversifier,
                value = :value,
                rcm = :rcm,
                nf = IFNULL(:nf, nf),
                memo = IFNULL(:memo, memo),
                is_change = IFNULL(:is_change, is_change),
                spent = IFNULL(:spent, spent),
                commitment_tree_position = IFNULL(:commitment_tree_position, commitment_tree_position)",
        )?;

        let rcm = output.note().rcm().to_bytes();
        let to = output.note().recipient();
        let diversifier = to.diversifier();

        let account = output.account_id();
        let sql_args = named_params![
            ":tx": &tx_ref,
            ":output_index": i64::try_from(output.index()).expect("output indices are representable as i64"),
            ":account": account.0,
            ":diversifier": &diversifier.0.as_ref(),
            ":value": output.note().value().inner(),
            ":rcm": &rcm.as_ref(),
            ":nf": output.nullifier().map(|nf| nf.0.as_ref()),
            ":memo": memo_repr(output.memo()),
            ":is_change": output.is_change(),
            ":spent": spent_in,
            ":commitment_tree_position": output.note_commitment_tree_position().map(u64::from),
        ];

        stmt_upsert_received_note
            .execute(sql_args)
            .map_err(SqliteClientError::from)?;

        Ok(())
    }

    #[test]
    fn receiving_key_scopes_migration_enhanced() {
        let params = Network::TestNetwork;

        // Create wallet upgraded to just before the current migration.
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), params).unwrap();
        init_wallet_db_internal(
            &mut db_data,
            None,
            &[
                add_account_birthdays::MIGRATION_ID,
                shardtree_support::MIGRATION_ID,
            ],
            false,
        )
        .unwrap();

        let (ufvk0, height, res) = prepare_wallet_state(&mut db_data);
        let tx = res.transaction();
        let account_id = AccountId(0);

        // We can't use `decrypt_and_store_transaction` because we haven't migrated yet.
        // Replicate its relevant innards here.
        let d_tx = decrypt_transaction(
            &params,
            height,
            tx,
            &[(account_id, ufvk0)].into_iter().collect(),
        );

        db_data
            .transactionally::<_, _, rusqlite::Error>(|wdb| {
                let tx_ref = crate::wallet::put_tx_data(wdb.conn.0, d_tx.tx(), None, None).unwrap();

                let mut spending_account_id: Option<AccountId> = None;

                // Orchard outputs were not supported as of the wallet states that could require this
                // migration.
                for output in d_tx.sapling_outputs() {
                    match output.transfer_type() {
                        TransferType::Outgoing | TransferType::WalletInternal => {
                            // Don't need to bother with sent outputs for this test.
                            if output.transfer_type() != TransferType::Outgoing {
                                put_received_note_before_migration(
                                    wdb.conn.0, output, tx_ref, None,
                                )
                                .unwrap();
                            }
                        }
                        TransferType::Incoming => {
                            match spending_account_id {
                                Some(id) => assert_eq!(id, *output.account()),
                                None => {
                                    spending_account_id = Some(*output.account());
                                }
                            }

                            put_received_note_before_migration(wdb.conn.0, output, tx_ref, None)
                                .unwrap();
                        }
                    }
                }

                Ok(())
            })
            .unwrap();

        // Apply the current migration
        init_wallet_db_internal(&mut db_data, None, &[super::MIGRATION_ID], false).unwrap();

        // There should be two rows in the `sapling_received_notes` table with correct scopes.
        let mut q = db_data
            .conn
            .prepare(
                "SELECT value, recipient_key_scope
                FROM sapling_received_notes",
            )
            .unwrap();
        let mut rows = q.query([]).unwrap();
        let mut row_count = 0;
        while let Some(row) = rows.next().unwrap() {
            row_count += 1;
            let value: u64 = row.get(0).unwrap();
            let scope = parse_scope(row.get(1).unwrap());
            match value {
                EXTERNAL_VALUE => assert_eq!(scope, Some(Scope::External)),
                INTERNAL_VALUE => assert_eq!(scope, Some(Scope::Internal)),
                _ => {
                    panic!(
                        "(Value, Scope) pair {:?} is not expected to exist in the wallet.",
                        (value, scope),
                    );
                }
            }
        }
        assert_eq!(row_count, 2);
    }

    #[test]
    fn receiving_key_scopes_migration_non_enhanced() {
        let params = Network::TestNetwork;

        // Create wallet upgraded to just before the current migration.
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), params).unwrap();
        init_wallet_db_internal(
            &mut db_data,
            None,
            &[
                wallet_summaries::MIGRATION_ID,
                shardtree_support::MIGRATION_ID,
            ],
            false,
        )
        .unwrap();

        let (ufvk0, height, res) = prepare_wallet_state(&mut db_data);
        let tx = res.transaction();

        let mut compact_tx = CompactTx {
            hash: tx.txid().as_ref()[..].into(),
            ..Default::default()
        };
        for output in tx.sapling_bundle().unwrap().shielded_outputs() {
            compact_tx.outputs.push(output.into());
        }
        let prev_hash = BlockHash([4; 32]);
        let mut block = CompactBlock {
            height: height.into(),
            hash: vec![7; 32],
            prev_hash: prev_hash.0[..].into(),
            ..Default::default()
        };
        block.vtx.push(compact_tx);
        let scanning_keys = ScanningKeys::from_account_ufvks([(AccountId(0), ufvk0)]);

        let scanned_block = scan_block(
            &params,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            Some(&BlockMetadata::from_parts(
                height - 1,
                prev_hash,
                Some(0),
                #[cfg(feature = "orchard")]
                Some(0),
            )),
        )
        .unwrap();

        // We can't use `put_blocks` because we haven't migrated yet.
        // Replicate its relevant innards here.
        let blocks = [scanned_block];
        db_data
            .transactionally(|wdb| {
                let start_positions = blocks.first().map(|block| {
                    (
                        block.height(),
                        Position::from(
                            u64::from(block.sapling().final_tree_size())
                                - u64::try_from(block.sapling().commitments().len()).unwrap(),
                        ),
                    )
                });
                let mut sapling_commitments = vec![];
                let mut last_scanned_height = None;
                let mut note_positions = vec![];
                for block in blocks.into_iter() {
                    if last_scanned_height
                        .iter()
                        .any(|prev| block.height() != *prev + 1)
                    {
                        return Err(SqliteClientError::NonSequentialBlocks);
                    }

                    // Insert the block into the database.
                    crate::wallet::put_block(
                        wdb.conn.0,
                        block.height(),
                        block.block_hash(),
                        block.block_time(),
                        block.sapling().final_tree_size(),
                        block.sapling().commitments().len().try_into().unwrap(),
                        #[cfg(feature = "orchard")]
                        block.orchard().final_tree_size(),
                        #[cfg(feature = "orchard")]
                        block.orchard().commitments().len().try_into().unwrap(),
                    )?;

                    for tx in block.transactions() {
                        let tx_row = crate::wallet::put_tx_meta(wdb.conn.0, tx, block.height())?;

                        for output in tx.sapling_outputs() {
                            put_received_note_before_migration(wdb.conn.0, output, tx_row, None)?;
                        }
                    }

                    note_positions.extend(block.transactions().iter().flat_map(|wtx| {
                        wtx.sapling_outputs()
                            .iter()
                            .map(|out| out.note_commitment_tree_position())
                    }));

                    last_scanned_height = Some(block.height());
                    let block_commitments = block.into_commitments();
                    sapling_commitments.extend(block_commitments.sapling.into_iter().map(Some));
                }

                // We will have a start position and a last scanned height in all cases where
                // `blocks` is non-empty.
                if let Some(((_, start_position), _)) = start_positions.zip(last_scanned_height) {
                    // Create subtrees from the note commitments in parallel.
                    const CHUNK_SIZE: usize = 1024;
                    let subtrees = sapling_commitments
                        .par_chunks_mut(CHUNK_SIZE)
                        .enumerate()
                        .filter_map(|(i, chunk)| {
                            let start = start_position + (i * CHUNK_SIZE) as u64;
                            let end = start + chunk.len() as u64;

                            shardtree::LocatedTree::from_iter(
                                start..end,
                                SAPLING_SHARD_HEIGHT.into(),
                                chunk.iter_mut().map(|n| n.take().expect("always Some")),
                            )
                        })
                        .map(|res| (res.subtree, res.checkpoints))
                        .collect::<Vec<_>>();

                    // Update the Sapling note commitment tree with all newly read note commitments
                    let mut subtrees = subtrees.into_iter();
                    wdb.with_sapling_tree_mut::<_, _, SqliteClientError>(move |sapling_tree| {
                        for (tree, checkpoints) in &mut subtrees {
                            sapling_tree.insert_tree(tree, checkpoints)?;
                        }

                        Ok(())
                    })?;
                }

                Ok(())
            })
            .unwrap();

        // Apply the current migration
        init_wallet_db_internal(&mut db_data, None, &[super::MIGRATION_ID], false).unwrap();

        // There should be two rows in the `sapling_received_notes` table with correct scopes.
        let mut q = db_data
            .conn
            .prepare(
                "SELECT value, recipient_key_scope
                FROM sapling_received_notes",
            )
            .unwrap();
        let mut rows = q.query([]).unwrap();
        let mut row_count = 0;
        while let Some(row) = rows.next().unwrap() {
            row_count += 1;
            let value: u64 = row.get(0).unwrap();
            let scope = parse_scope(row.get(1).unwrap());
            match value {
                EXTERNAL_VALUE => assert_eq!(scope, Some(Scope::External)),
                INTERNAL_VALUE => assert_eq!(scope, Some(Scope::Internal)),
                _ => {
                    panic!(
                        "(Value, Scope) pair {:?} is not expected to exist in the wallet.",
                        (value, scope),
                    );
                }
            }
        }
        assert_eq!(row_count, 2);
    }
}
