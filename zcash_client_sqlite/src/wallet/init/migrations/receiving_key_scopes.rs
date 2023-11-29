//! This migration adds support for the Orchard protocol to `zcash_client_sqlite`

use std::collections::HashSet;

use rusqlite::{self, named_params};
use schemer;
use schemer_rusqlite::RusqliteMigration;

use tracing::debug;
use uuid::Uuid;

use zcash_client_backend::{keys::UnifiedFullViewingKey, scanning::ScanningKey};
use zcash_primitives::{
    consensus::{self, sapling_zip212_enforcement, BlockHeight, BranchId},
    sapling::note_encryption::{try_sapling_note_decryption, PreparedIncomingViewingKey},
    transaction::Transaction,
    zip32::Scope,
};

use crate::wallet::{
    init::{migrations::shardtree_support, WalletMigrationError},
    scope_code,
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
        "Add support for receiving storage of note commitment tree data using the `shardtree` crate."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Add commitment tree sizes to block metadata.
        debug!("Adding new columns");
        transaction.execute_batch(
            &format!(
                "ALTER TABLE sapling_received_notes ADD COLUMN recipient_key_scope INTEGER NOT NULL DEFAULT {};",
                scope_code(Scope::External)
            )
        )?;

        // For all notes marked as change, we have to determine whether they were actually sent to
        // the internal key or the external key for the account, so we trial-decrypt the original
        // output with both and pick the scope of whichever worked.
        let mut stmt_select_notes = transaction.prepare(
            "SELECT id_note, output_index, transactions.raw, transactions.expiry_height, accounts.ufvk
             FROM sapling_received_notes
             INNER JOIN accounts on accounts.account = sapling_received_notes.account
             INNER JOIN transactions ON transactions.id_tx = sapling_received_notes.tx
             WHERE is_change = 1"
        )?;

        let mut rows = stmt_select_notes.query([])?;
        while let Some(row) = rows.next()? {
            let note_id: i64 = row.get(0)?;
            let output_index: usize = row.get(1)?;
            let tx_data: Vec<u8> = row.get(2)?;

            let tx = Transaction::read(&tx_data[..], BranchId::Canopy)
                .expect("Transaction must be valid");
            let output = tx
                .sapling_bundle()
                .and_then(|b| b.shielded_outputs().get(output_index))
                .unwrap_or_else(|| panic!("A Sapling output must exist at index {}", output_index));
            let tx_expiry_height = BlockHeight::from(row.get::<_, u32>(3)?);
            let zip212_enforcement = sapling_zip212_enforcement(&self.params, tx_expiry_height);

            let ufvk_str: String = row.get(4)?;
            let ufvk = UnifiedFullViewingKey::decode(&self.params, &ufvk_str)
                .expect("Stored UFVKs must be valid");
            let dfvk = ufvk
                .sapling()
                .expect("UFVK must have a Sapling component to have received Sapling notes");
            let keys = dfvk.to_sapling_keys();

            for (scope, ivk, _) in keys {
                let pivk = PreparedIncomingViewingKey::new(&ivk);
                if try_sapling_note_decryption(&pivk, output, zip212_enforcement).is_some() {
                    transaction.execute(
                        "UPDATE sapling_received_notes SET recipient_key_scope = :scope
                         WHERE id_note = :note_id",
                        named_params! {":scope": scope_code(scope), ":note_id": note_id},
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
