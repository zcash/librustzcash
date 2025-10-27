//! Adds tables for tracking transactions to be downloaded for transparent output and/or memo retrieval.

use rusqlite::{Transaction, named_params};
use schemerz_rusqlite::RusqliteMigration;
use std::collections::HashSet;
use uuid::Uuid;
use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
use zcash_protocol::consensus;

use crate::wallet::init::WalletMigrationError;

use super::{
    ensure_orchard_ua_receiver, ephemeral_addresses, nullifier_map, orchard_shardtree,
    spend_key_available,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xfec02b61_3988_4b4f_9699_98977fac9e7f);

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        AccountRef, TxRef,
        error::SqliteClientError,
        wallet::{TxQueryType, transparent::uivk_legacy_transparent_address},
    },
    rusqlite::OptionalExtension as _,
    std::convert::Infallible,
    transparent::address::TransparentAddress,
    zcash_client_backend::data_api::DecryptedTransaction,
    zcash_keys::encoding::AddressCodec,
    zcash_protocol::{
        TxId,
        consensus::{BlockHeight, BranchId},
    },
};

const DEPENDENCIES: &[Uuid] = &[
    orchard_shardtree::MIGRATION_ID,
    ensure_orchard_ua_receiver::MIGRATION_ID,
    ephemeral_addresses::MIGRATION_ID,
    spend_key_available::MIGRATION_ID,
    nullifier_map::MIGRATION_ID,
];

pub(super) struct Migration<P> {
    pub(super) _params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds tables for tracking transactions to be downloaded for transparent output and/or memo retrieval."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, conn: &Transaction) -> Result<(), WalletMigrationError> {
        conn.execute_batch(
            "CREATE TABLE tx_retrieval_queue (
                txid BLOB NOT NULL UNIQUE,
                query_type INTEGER NOT NULL,
                dependent_transaction_id INTEGER,
                FOREIGN KEY (dependent_transaction_id) REFERENCES transactions(id_tx)
            );

            ALTER TABLE transactions ADD COLUMN target_height INTEGER;

            CREATE TABLE transparent_spend_search_queue (
                address TEXT NOT NULL,
                transaction_id INTEGER NOT NULL,
                output_index INTEGER NOT NULL,
                FOREIGN KEY (transaction_id) REFERENCES transactions(id_tx),
                CONSTRAINT value_received_height UNIQUE (transaction_id, output_index)
            );

            CREATE TABLE transparent_spend_map (
                spending_transaction_id INTEGER NOT NULL,
                prevout_txid BLOB NOT NULL,
                prevout_output_index INTEGER NOT NULL,
                FOREIGN KEY (spending_transaction_id) REFERENCES transactions(id_tx)
                -- NOTE: We can't create a unique constraint on just (prevout_txid, prevout_output_index)
                -- because the same output may be attempted to be spent in multiple transactions, even
                -- though only one will ever be mined.
                CONSTRAINT transparent_spend_map_unique UNIQUE (
                    spending_transaction_id, prevout_txid, prevout_output_index
                )
            );",
        )?;

        // Add estimated target height information for each transaction we know to
        // have been created by the wallet; transactions that were discovered via
        // chain scanning will have their `created` field set to `NULL`.
        conn.execute(
            "UPDATE transactions
             SET target_height = expiry_height - :default_expiry_delta
             WHERE expiry_height > :default_expiry_delta
             AND created IS NOT NULL",
            named_params![":default_expiry_delta": DEFAULT_TX_EXPIRY_DELTA],
        )?;

        // Populate the enhancement queues with any transparent history information that we don't
        // already have.
        #[cfg(feature = "transparent-inputs")]
        {
            let mut stmt_transactions =
                conn.prepare("SELECT id_tx, raw, mined_height FROM transactions")?;
            let mut rows = stmt_transactions.query([])?;
            while let Some(row) = rows.next()? {
                let tx_ref = row.get(0).map(TxRef)?;
                let tx_data = row.get::<_, Option<Vec<u8>>>(1)?;
                let mined_height = row.get::<_, Option<u32>>(2)?.map(BlockHeight::from);

                if let Some(tx_data) = tx_data {
                    let tx = zcash_primitives::transaction::Transaction::read(
                        &tx_data[..],
                        // We assume unmined transactions are created with the current consensus branch ID.
                        mined_height.map_or(BranchId::Sapling, |h| {
                            BranchId::for_height(&self._params, h)
                        }),
                    )
                    .map_err(|_| {
                        WalletMigrationError::CorruptedData(
                            "Could not read serialized transaction data.".to_owned(),
                        )
                    })?;

                    for (txout, output_index) in tx
                        .transparent_bundle()
                        .iter()
                        .flat_map(|b| b.vout.iter())
                        .zip(0u32..)
                    {
                        if let Some(address) = txout.recipient_address() {
                            let find_address_account = || {
                                conn.query_row(
                                    "SELECT account_id FROM addresses
                                     WHERE cached_transparent_receiver_address = :address
                                     UNION
                                     SELECT account_id from ephemeral_addresses
                                     WHERE address = :address",
                                    named_params![":address": address.encode(&self._params)],
                                    |row| row.get(0).map(AccountRef),
                                )
                                .optional()
                            };
                            let find_legacy_address_account =
                                || -> Result<Option<AccountRef>, SqliteClientError> {
                                    let mut stmt = conn.prepare("SELECT id, uivk FROM accounts")?;
                                    let mut rows = stmt.query([])?;
                                    while let Some(row) = rows.next()? {
                                        let account_id = row.get(0).map(AccountRef)?;
                                        let uivk_str = row.get::<_, String>(1)?;

                                        if let Some((legacy_taddr, _)) =
                                            uivk_legacy_transparent_address(
                                                &self._params,
                                                &uivk_str,
                                            )?
                                        {
                                            if legacy_taddr == address {
                                                return Ok(Some(account_id));
                                            }
                                        }
                                    }

                                    Ok(None)
                                };

                            if find_address_account()?.is_some()
                                || find_legacy_address_account()?.is_some()
                            {
                                queue_transparent_spend_detection(
                                    conn,
                                    &self._params,
                                    address,
                                    tx_ref,
                                    output_index,
                                )?
                            }
                        }
                    }

                    let d_tx = DecryptedTransaction::<'_, Infallible>::new(
                        mined_height,
                        &tx,
                        vec![],
                        #[cfg(feature = "orchard")]
                        vec![],
                    );

                    queue_transparent_input_retrieval(conn, tx_ref, &d_tx)?;
                    queue_unmined_tx_retrieval(conn, &d_tx)?;
                }
            }
        }

        Ok(())
    }

    fn down(&self, conn: &Transaction) -> Result<(), WalletMigrationError> {
        conn.execute_batch(
            "DROP TABLE transparent_spend_map;
             DROP TABLE transparent_spend_search_queue;
             ALTER TABLE transactions DROP COLUMN target_height;
             DROP TABLE tx_retrieval_queue;",
        )?;

        Ok(())
    }
}

#[cfg(feature = "transparent-inputs")]
fn queue_transparent_spend_detection<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    receiving_address: TransparentAddress,
    tx_ref: TxRef,
    output_index: u32,
) -> Result<(), SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO transparent_spend_search_queue
         (address, transaction_id, output_index)
         VALUES
         (:address, :transaction_id, :output_index)
         ON CONFLICT (transaction_id, output_index) DO NOTHING",
    )?;

    let addr_str = receiving_address.encode(params);
    stmt.execute(named_params! {
        ":address": addr_str,
        ":transaction_id": tx_ref.0,
        ":output_index": output_index
    })?;

    Ok(())
}

#[cfg(feature = "transparent-inputs")]
fn queue_transparent_input_retrieval<AccountId>(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: TxRef,
    d_tx: &DecryptedTransaction<'_, AccountId>,
) -> Result<(), SqliteClientError> {
    if let Some(b) = d_tx.tx().transparent_bundle() {
        if !b.is_coinbase() {
            // queue the transparent inputs for enhancement
            queue_tx_retrieval(
                conn,
                b.vin.iter().map(|txin| *txin.prevout().txid()),
                Some(tx_ref),
            )?;
        }
    }

    Ok(())
}

#[cfg(feature = "transparent-inputs")]
fn queue_unmined_tx_retrieval<AccountId>(
    conn: &rusqlite::Transaction<'_>,
    d_tx: &DecryptedTransaction<'_, AccountId>,
) -> Result<(), SqliteClientError> {
    let detectable_via_scanning = d_tx.tx().sapling_bundle().is_some();
    #[cfg(feature = "orchard")]
    let detectable_via_scanning = detectable_via_scanning | d_tx.tx().orchard_bundle().is_some();

    if d_tx.mined_height().is_none() && !detectable_via_scanning {
        queue_tx_retrieval(conn, std::iter::once(d_tx.tx().txid()), None)?
    }

    Ok(())
}

#[cfg(feature = "transparent-inputs")]
fn queue_tx_retrieval(
    conn: &rusqlite::Transaction<'_>,
    txids: impl Iterator<Item = TxId>,
    dependent_tx_ref: Option<TxRef>,
) -> Result<(), SqliteClientError> {
    // Add an entry to the transaction retrieval queue if it would not be redundant.
    let mut stmt_insert_tx = conn.prepare_cached(
        "INSERT INTO tx_retrieval_queue (txid, query_type, dependent_transaction_id)
            SELECT
            :txid,
            IIF(
                EXISTS (SELECT 1 FROM transactions WHERE txid = :txid AND raw IS NOT NULL),
                :status_type,
                :enhancement_type
            ),
            :dependent_transaction_id
        ON CONFLICT (txid) DO UPDATE
        SET query_type =
            IIF(
                EXISTS (SELECT 1 FROM transactions WHERE txid = :txid AND raw IS NOT NULL),
                :status_type,
                :enhancement_type
            ),
            dependent_transaction_id = IFNULL(:dependent_transaction_id, dependent_transaction_id)",
    )?;

    for txid in txids {
        stmt_insert_tx.execute(named_params! {
            ":txid": txid.as_ref(),
            ":status_type": TxQueryType::Status.code(),
            ":enhancement_type": TxQueryType::Enhancement.code(),
            ":dependent_transaction_id": dependent_tx_ref.map(|r| r.0),
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::named_params;
    use secrecy::Secret;
    use tempfile::NamedTempFile;

    use ::transparent::{
        address::{Script, TransparentAddress},
        bundle::{OutPoint, TxIn, TxOut},
    };
    use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
    use zcash_protocol::{
        consensus::{BranchId, Network},
        value::Zatoshis,
    };

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        wallet::init::{WalletMigrator, migrations::tests::test_migrate},
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
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

        // Add transactions to the wallet that exercise the data migration.
        let add_tx_to_wallet = |tx: TransactionData<Authorized>| {
            let tx = tx.freeze().unwrap();
            let txid = tx.txid();
            let mut raw_tx = vec![];
            tx.write(&mut raw_tx).unwrap();
            db_data
                .conn
                .execute(
                    r#"INSERT INTO transactions (txid, raw) VALUES (:txid, :raw);"#,
                    named_params! {":txid": txid.as_ref(), ":raw": raw_tx},
                )
                .unwrap();
        };
        add_tx_to_wallet(TransactionData::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            12345678.into(),
            #[cfg(all(
                any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
                feature = "zip-233"
            ))]
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
        ));

        // Check that we can apply this migration.
        WalletMigrator::new()
            .with_seed(Secret::new(seed_bytes))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, &[MIGRATION_ID])
            .unwrap();
    }
}
