//! This migration adds decryption key scope to persisted information about received notes.

use std::collections::HashSet;

use rusqlite::{self, named_params};
use schemer;
use schemer_rusqlite::RusqliteMigration;

use uuid::Uuid;

use zcash_client_backend::keys::UnifiedFullViewingKey;
use zcash_primitives::{
    consensus::{self, sapling_zip212_enforcement, BlockHeight, BranchId},
    sapling::note_encryption::{
        try_sapling_note_decryption, PreparedIncomingViewingKey, Zip212Enforcement,
    },
    transaction::Transaction,
    zip32::Scope,
};

use crate::wallet::{
    init::{migrations::shardtree_support, WalletMigrationError},
    scan_queue_extrema, scope_code,
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
            "SELECT id_note, output_index, transactions.raw, transactions.block, transactions.expiry_height, accounts.ufvk
             FROM sapling_received_notes
             INNER JOIN accounts on accounts.account = sapling_received_notes.account
             INNER JOIN transactions ON transactions.id_tx = sapling_received_notes.tx"
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

            let tx_height = row.get::<_, Option<u32>>(3)?.map(BlockHeight::from);
            let tx_expiry = row.get::<_, u32>(4)?;
            let zip212_height = tx_height.map_or_else(
                || {
                    if tx_expiry == 0 {
                        scan_queue_extrema(transaction).map(|extrema| extrema.map(|r| *r.end()))
                    } else {
                        Ok(Some(BlockHeight::from(tx_expiry)))
                    }
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
            let pivk = PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::Internal));
            if try_sapling_note_decryption(&pivk, output, zip212_enforcement).is_some() {
                transaction.execute(
                    "UPDATE sapling_received_notes SET recipient_key_scope = :scope
                     WHERE id_note = :note_id",
                    named_params! {":scope": scope_code(Scope::Internal), ":note_id": note_id},
                )?;
            }
        }

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // TODO: something better than just panic?
        panic!("Cannot revert this migration.");
    }
}
