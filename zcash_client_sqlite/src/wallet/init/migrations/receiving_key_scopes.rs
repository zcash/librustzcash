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
    consensus::{self, sapling_zip212_enforcement, BlockHeight, BranchId},
    transaction::{components::amount::NonNegativeAmount, Transaction},
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
                |h| sapling_zip212_enforcement(&self.params, h),
            );

            let ufvk_str: String = row.get(5)?;
            let ufvk = UnifiedFullViewingKey::decode(&self.params, &ufvk_str)
                .expect("Stored UFVKs must be valid");
            let dfvk = ufvk
                .sapling()
                .expect("UFVK must have a Sapling component to have received Sapling notes");

            // We previously set the default to external scope, so we now verify whether the output
            // is decryptable using the intenally-scoped IVK and, if so, mark it as such.
            if let Some(tx_data) = tx_data_opt {
                let tx = Transaction::read(&tx_data[..], BranchId::Canopy)
                    .expect("Transaction must be valid");
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
                    &note_value.try_into().unwrap(),
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
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}
