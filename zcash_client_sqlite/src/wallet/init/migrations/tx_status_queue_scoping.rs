//! Removes out-of-scope status requests for transactions with shielded components from the
//! transaction retrieval queue.

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;

use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{self, BlockHeight, BranchId};

use crate::wallet::{TxQueryType, chain_tip_height, init::WalletMigrationError};

use super::{account_delete_cascade, tx_retrieval_queue};

/// Removes out-of-scope status requests for transactions with shielded components from the
/// transaction retrieval queue.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x2c4d3ff6_9e19_4fbf_ae08_9d1263a3a455);

const DEPENDENCIES: &[Uuid] = &[
    tx_retrieval_queue::MIGRATION_ID,
    account_delete_cascade::MIGRATION_ID,
];

pub(super) struct Migration<P> {
    pub(super) params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Removes out-of-scope status requests for transactions with shielded components from the transaction retrieval queue."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, conn: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        // Status-type entries in `tx_retrieval_queue` may only exist for fully-transparent
        // transactions: the mined status of a transaction having any shielded component is
        // learned via ordinary chain scanning, so a txid-scoped status query for it is
        // redundant and out of scope for the queue.
        //
        // Prior versions of this crate violated that invariant in several ways:
        // * transactions detected via scanning for which complete transaction data was already
        //   available (in particular, the wallet's own shielded sends) were queued for status
        //   retrieval when their mined transaction was scanned;
        // * transactions whose data was stored via enhancement were classified as undetectable
        //   via scanning if they contained only an Ironwood shielded bundle, and were then
        //   queued for status retrieval when unmined;
        // * prevouts of transparent inputs whose complete transaction data was already available
        //   were queued for status retrieval even when the referenced transaction had shielded
        //   components.
        //
        // This migration deletes the resulting stale entries. Status entries are retained only
        // for as-yet-unmined transactions whose stored transaction data demonstrates that they
        // are fully transparent.
        let chain_tip = chain_tip_height(conn)?;

        let mut stale_txids: Vec<Vec<u8>> = vec![];
        {
            let mut stmt = conn.prepare(
                "SELECT q.txid, t.raw, t.mined_height
                 FROM tx_retrieval_queue q
                 LEFT OUTER JOIN transactions t ON t.txid = q.txid
                 WHERE q.query_type = :status_type",
            )?;
            let mut rows = stmt.query(named_params![":status_type": TxQueryType::Status.code()])?;
            while let Some(row) = rows.next()? {
                let txid = row.get::<_, Vec<u8>>(0)?;
                let raw = row.get::<_, Option<Vec<u8>>>(1)?;
                let mined_height = row.get::<_, Option<u32>>(2)?.map(BlockHeight::from);

                let retain = match (raw, mined_height) {
                    // The transaction is already known to have been mined; its status no longer
                    // needs to be queried.
                    (_, Some(_)) => false,
                    (Some(raw), None) => {
                        // We assume that unmined transactions were created under the current
                        // consensus branch.
                        let branch_id = chain_tip.map_or(BranchId::Sapling, |h| {
                            BranchId::for_height(&self.params, h + 1)
                        });

                        match Transaction::read(&raw[..], branch_id) {
                            Ok(tx) => {
                                tx.sapling_bundle().is_none()
                                    && tx.orchard_bundle().is_none()
                                    && tx.ironwood_bundle().is_none()
                            }
                            // If the stored transaction data cannot be parsed, we cannot rule
                            // out that the transaction has shielded components, so we treat it
                            // as out of scope and delete the status request.
                            Err(_) => false,
                        }
                    }
                    // A status request cannot be satisfied for a transaction for which we have
                    // no data, so it should never have been created; `TxidNotRecognized` would be
                    // the only possible answer for a transaction the chain does not contain.
                    (None, None) => false,
                };

                if !retain {
                    stale_txids.push(txid);
                }
            }
        }

        let mut stmt_delete = conn.prepare(
            "DELETE FROM tx_retrieval_queue
             WHERE txid = :txid
             AND query_type = :status_type",
        )?;
        for txid in stale_txids {
            stmt_delete.execute(named_params![
                ":txid": txid,
                ":status_type": TxQueryType::Status.code(),
            ])?;
        }

        Ok(())
    }

    fn down(&self, _: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    use rusqlite::named_params;
    use secrecy::Secret;
    use tempfile::NamedTempFile;

    use ::transparent::{
        address::{Script, TransparentAddress},
        bundle::{OutPoint, TxIn, TxOut},
    };
    use zcash_primitives::transaction::{
        Authorized, Transaction, TransactionData, TxVersion, testing as tx_testing,
    };
    use zcash_protocol::{
        TxId,
        consensus::{BranchId, Network},
        value::Zatoshis,
    };

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::{TxQueryType, init::WalletMigrator, init::migrations::tests::test_migrate},
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    /// Returns a deterministically-sampled transaction having at least one shielded bundle.
    fn fake_shielded_tx() -> Transaction {
        let mut runner = TestRunner::new_with_rng(
            Config::default(),
            TestRng::from_seed(RngAlgorithm::ChaCha, &[7; 32]),
        );
        loop {
            let tx_data = tx_testing::arb_txdata(BranchId::Nu5)
                .new_tree(&mut runner)
                .unwrap()
                .current();
            if tx_data.sapling_bundle().is_some() || tx_data.orchard_bundle().is_some() {
                return tx_data.freeze().unwrap();
            }
        }
    }

    /// Returns a fully-transparent transaction.
    fn fake_transparent_tx() -> Transaction {
        TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            12345678.into(),
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            Zatoshis::ZERO,
            Some(transparent::bundle::Bundle {
                vin: vec![TxIn::from_parts(OutPoint::fake(), Script::default(), 0)],
                vout: vec![TxOut::new(
                    Zatoshis::const_from_u64(10_000),
                    TransparentAddress::PublicKeyHash([7; 20]).script().into(),
                )],
                authorization: transparent::bundle::Authorized,
            }),
            None,
            None,
            None,
        )
        .freeze()
        .unwrap()
    }

    #[test]
    fn migrate_with_data() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(
            data_file.path(),
            Network::TestNetwork,
            test_clock(),
            test_rng(),
        )
        .unwrap();

        let seed_bytes = vec![0xab; 32];

        // Migrate to database state just prior to this migration.
        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes.clone()))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, DEPENDENCIES)
            .unwrap();

        // Add transactions and stale queue entries that exercise the data migration.
        let add_tx_to_wallet = |tx: &Transaction, mined_height: Option<u32>| {
            let txid = tx.txid();
            let mut raw_tx = vec![];
            tx.write(&mut raw_tx).unwrap();
            db_data
                .conn
                .execute(
                    "INSERT INTO transactions (txid, raw, mined_height, min_observed_height)
                     VALUES (:txid, :raw, :mined_height, :min_observed_height)",
                    named_params! {
                        ":txid": txid.as_ref(),
                        ":raw": raw_tx,
                        ":mined_height": mined_height,
                        ":min_observed_height": mined_height.unwrap_or(1_000_000),
                    },
                )
                .unwrap();
        };
        let add_queue_entry = |txid: &TxId, query_type: TxQueryType| {
            db_data
                .conn
                .execute(
                    "INSERT INTO tx_retrieval_queue (txid, query_type)
                     VALUES (:txid, :query_type)",
                    named_params! {
                        ":txid": txid.as_ref(),
                        ":query_type": query_type.code(),
                    },
                )
                .unwrap();
        };

        // An unmined fully-transparent transaction with a status request: the request is valid
        // and must be retained.
        let transparent_tx = fake_transparent_tx();
        add_tx_to_wallet(&transparent_tx, None);
        add_queue_entry(&transparent_tx.txid(), TxQueryType::Status);

        // An unmined shielded transaction with a status request: the transaction is detectable
        // via scanning, so the request is out of scope and must be deleted.
        let shielded_tx = fake_shielded_tx();
        add_tx_to_wallet(&shielded_tx, None);
        add_queue_entry(&shielded_tx.txid(), TxQueryType::Status);

        // A status request for a txid the wallet has no data for is unsatisfiable and must be
        // deleted.
        let unknown_status_txid = TxId::from_bytes([0x77; 32]);
        add_queue_entry(&unknown_status_txid, TxQueryType::Status);

        // An enhancement request must be unaffected by this migration.
        let enhancement_txid = TxId::from_bytes([0x88; 32]);
        add_queue_entry(&enhancement_txid, TxQueryType::Enhancement);

        // Check that we can apply this migration.
        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();

        let queued: Vec<(Vec<u8>, i64)> = db_data
            .conn
            .prepare("SELECT txid, query_type FROM tx_retrieval_queue ORDER BY txid")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        let mut expected = vec![
            (
                transparent_tx.txid().as_ref().to_vec(),
                TxQueryType::Status.code(),
            ),
            (
                enhancement_txid.as_ref().to_vec(),
                TxQueryType::Enhancement.code(),
            ),
        ];
        expected.sort();

        assert_eq!(queued, expected);
    }
}
