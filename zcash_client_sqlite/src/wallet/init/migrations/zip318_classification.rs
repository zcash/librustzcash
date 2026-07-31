//! Adds a column recording how each transaction classifies against ZIP 318.
//!
//! A wallet that wants to label a pool-migration transaction in its history cannot rely on the
//! migration plan it scheduled the transaction from: that plan does not survive a seed restore, and
//! it says nothing about a transaction the wallet did not itself schedule. The classification is
//! instead derived from the transaction's shape, which is recoverable from chain data, and stored
//! here so that it is available to the same SQL a client already uses to read its history.
//!
//! It is stored rather than computed on read because the evidence it rests on is only all present
//! at once while the transaction is being decrypted: the action counts come from the raw
//! transaction, and whether the outputs are the account's own comes from decryption. Neither is
//! available to a view.
//!
//! # The default is "not classified", not "not a migration"
//!
//! The column defaults to zero, which decodes to
//! [`Zip318Classification::Unknown`](zcash_protocol::zip318::Zip318Classification::Unknown). This
//! migration deliberately does NOT classify existing rows. Doing so would mean re-deriving the
//! classification from stored columns alone, without the decrypted outputs, which is both the
//! weakest evidence available and a second implementation of the predicate to keep in step with the
//! real one.
//!
//! So every transaction already in the wallet keeps the default, and needs the transaction
//! rescanned before it can be labelled. That is a real value rather than NULL so those rows can be
//! found with an ordinary query, and it is distinct from the code for "nonconforming", which is a
//! decision. A client MUST render the default as no label, never as "not a migration": the two mean
//! "we never looked" and "we looked and it is not one".

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::v_transactions_pool_crossing;

/// This migration adds the `zip318_kind` column to the `transactions` table.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x0a35a9e4_6c1d_4f7a_9c02_51b8de4f7c33);

/// `v_transactions_pool_crossing` is the most recent migration to touch how transactions are
/// classified for history purposes; ordering after it keeps the two classifications' migrations in
/// a single chain rather than letting them race.
pub(super) const DEPENDENCIES: &[Uuid] = &[v_transactions_pool_crossing::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a column recording each transaction's ZIP 318 classification."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Zero is the code for "not classified"; see the module documentation for why existing
        // rows keep it rather than being classified here.
        conn.execute_batch(
            "ALTER TABLE transactions
             ADD COLUMN zip318_kind INTEGER NOT NULL DEFAULT 0;",
        )?;

        Ok(())
    }

    fn down(&self, conn: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        conn.execute_batch("ALTER TABLE transactions DROP COLUMN zip318_kind;")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use zcash_protocol::zip318::Zip318Classification;

    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    /// The column's SQL default must be the code for "not classified", so that a row this
    /// migration did not classify reads back as unclassified rather than as a decision that the
    /// transaction is not a migration transaction. The DDL is asserted against the schema constant
    /// by [`test_migrate`]; this pins the constant the DDL has to carry.
    #[test]
    fn the_column_default_means_unclassified() {
        assert_eq!(Zip318Classification::Unknown.to_code(), 0);
        assert_ne!(Zip318Classification::Nonconforming.to_code(), 0);
    }
}
