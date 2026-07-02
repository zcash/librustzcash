//! Restores `transactions.mined_height` for rows where it was erroneously cleared.
//!
//! A bug in `put_transparent_output` caused re-storing a transparent output with an unknown
//! mined height (for example, an output re-observed via the mempool, or a transaction fetched
//! from a backend that could not locate it on the best chain) to overwrite the transaction's
//! previously-recorded `mined_height` with `NULL`, marking a mined transaction as unmined. For
//! coinbase transactions (which have `expiry_height = 0` and so never expire) this permanently
//! misclassified the affected funds as pending rather than spendable.
//!
//! The same upsert preserved the `block` foreign key (`block = IFNULL(block, :block)`), so a row
//! with `block` set and `mined_height` NULL is precisely the signature of this clobbering: the
//! transaction was observed in a scanned block at height `block`. This migration restores
//! `mined_height` from `block` for such rows and clears `confirmed_unmined_at_height` to match,
//! mirroring what `put_tx_meta` records when a transaction is observed in a scanned block.
//!
//! Rows where `mined_height` was cleared but no `block` reference exists (the transaction was
//! never observed in a scanned block) cannot be repaired locally; their heights will be restored
//! by transaction-status requests during normal wallet operation.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use super::add_transparent_receiver_address_index;
use crate::wallet::init::WalletMigrationError;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x0f0c450e_5567_48cb_8d5e_62e9ac084381);

const DEPENDENCIES: &[Uuid] = &[add_transparent_receiver_address_index::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Restores transaction mined heights erroneously cleared by transparent output storage."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // `block` is only ever set when the transaction was observed in a scanned block at that
        // height (`put_tx_meta`, or upserts that verified a `blocks` row exists), and genuine
        // un-mining (`truncate_to_height`) clears `block` and `mined_height` together — so a row
        // with `block` set and `mined_height` NULL can only have been produced by the
        // `put_transparent_output` clobbering fixed alongside this migration. Restore the mined
        // height from the scanned-block reference, and clear any stale confirmed-unmined marker,
        // mirroring what `put_tx_meta` records when a transaction is observed in a block.
        transaction.execute(
            "UPDATE transactions
             SET mined_height = block,
                 confirmed_unmined_at_height = NULL
             WHERE mined_height IS NULL
             AND block IS NOT NULL",
            [],
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::named_params;
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_protocol::consensus::Network;

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::WalletMigrator,
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[test]
    fn migrate() {
        crate::wallet::init::migrations::tests::test_migrate(&[MIGRATION_ID]);
    }

    /// A transaction whose `mined_height` was clobbered to NULL while its `block` reference
    /// survived is restored to `mined_height = block` (with any stale confirmed-unmined marker
    /// cleared); a genuinely unmined transaction (no `block` reference) is left untouched.
    #[test]
    fn restores_mined_height_from_block() {
        let network = Network::TestNetwork;
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();

        // Migrate to the state just prior to this migration.
        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        // A scanned block at height 1000.
        db_data
            .conn
            .execute(
                "INSERT INTO blocks (height, hash, time, sapling_tree)
                 VALUES (1000, X'00', 0, X'00')",
                [],
            )
            .unwrap();

        // A clobbered transaction: observed in the scanned block (block = 1000) but with
        // mined_height NULL and a stale confirmed-unmined marker.
        db_data
            .conn
            .execute(
                "INSERT INTO transactions
                     (id_tx, txid, block, mined_height, confirmed_unmined_at_height,
                      min_observed_height)
                 VALUES (1, X'01', 1000, NULL, 1500, 1000)",
                [],
            )
            .unwrap();

        // A genuinely unmined transaction: no block reference.
        db_data
            .conn
            .execute(
                "INSERT INTO transactions
                     (id_tx, txid, block, mined_height, confirmed_unmined_at_height,
                      min_observed_height)
                 VALUES (2, X'02', NULL, NULL, 1500, 1000)",
                [],
            )
            .unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![0xab; 32]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        let row = |id: i64| -> (Option<u32>, Option<u32>) {
            db_data
                .conn
                .query_row(
                    "SELECT mined_height, confirmed_unmined_at_height
                     FROM transactions WHERE id_tx = :id",
                    named_params! { ":id": id },
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };

        // The clobbered transaction is restored to its scanned-block height, and the stale
        // confirmed-unmined marker is cleared.
        assert_eq!(row(1), (Some(1000), None));

        // The genuinely unmined transaction is untouched.
        assert_eq!(row(2), (None, Some(1500)));
    }
}
