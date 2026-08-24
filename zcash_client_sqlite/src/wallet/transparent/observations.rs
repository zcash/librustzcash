//! Maintenance of the durable index from transparent addresses to the wallet-involved
//! transactions that name them.
//!
//! Wallet recognition of transparent involvement is the join of the wallet's stored
//! transactions with its address book, and that join has two deltas. Checking a transaction
//! against the book when the transaction is stored maintains the first; this index maintains
//! the second, by recording every address a wallet-involved transaction names — including
//! addresses the wallet does not control at the time — so that an address added afterwards can
//! be checked against everything already seen.
//!
//! See the `transparent_tx_address_observations` table documentation for how this index divides
//! labour with the two outpoint-keyed spend maps.

use rusqlite::named_params;

use zcash_client_backend::wallet::{TransparentAddressObservation, TransparentInvolvement};
use zcash_keys::encoding::AddressCodec;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{self, BranchId};

use crate::{TxRef, error::SqliteClientError};

/// The direction in which a transaction's transparent data names an address, as encoded in the
/// `involvement` column of `transparent_tx_address_observations`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Involvement {
    /// The address is paid by the transaction output at the row's `item_index`.
    Output,
    /// The address is revealed by the `scriptSig` of the transaction input at the row's
    /// `item_index`.
    Input,
}

impl Involvement {
    /// Returns the encoding of this direction as stored in the `involvement` column.
    pub(crate) fn encode(&self) -> i64 {
        match self {
            Involvement::Output => 0,
            Involvement::Input => 1,
        }
    }
}

/// Records the addresses that the transparent data of the transaction identified by `tx_ref`
/// names.
///
/// Each observation is an idempotent upsert keyed by the transaction, the involvement
/// direction, and the item index, so a transaction may be observed repeatedly and at differing
/// fidelity without the recorded state depending on the order of observation.
pub(crate) fn put_observations<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    tx_ref: TxRef,
    observations: &[TransparentAddressObservation],
) -> Result<(), SqliteClientError> {
    // A transaction with no transparent data names no address. Returning before the statement is
    // prepared keeps that case free of any database access, so a caller may record the (empty)
    // observations of a transaction whose row it has not created.
    if observations.is_empty() {
        return Ok(());
    }

    let mut stmt_upsert_observation = conn.prepare_cached(
        "INSERT INTO transparent_tx_address_observations (
            transaction_id, involvement, item_index, address,
            value_zat, prevout_txid, prevout_output_index
        )
        VALUES (
            :transaction_id, :involvement, :item_index, :address,
            :value_zat, :prevout_txid, :prevout_output_index
        )
        ON CONFLICT (transaction_id, involvement, item_index) DO UPDATE
        SET address = :address,
            value_zat = :value_zat,
            prevout_txid = :prevout_txid,
            prevout_output_index = :prevout_output_index",
    )?;

    for observation in observations {
        let (involvement, value_zat, prevout) = match observation.involvement() {
            TransparentInvolvement::Output(value) => {
                (Involvement::Output, Some(u64::from(*value)), None)
            }
            TransparentInvolvement::Input(prevout) => (Involvement::Input, None, Some(prevout)),
        };

        stmt_upsert_observation.execute(named_params![
            ":transaction_id": tx_ref.0,
            ":involvement": involvement.encode(),
            ":item_index": observation.item_index(),
            ":address": observation.address().encode(params),
            ":value_zat": value_zat,
            ":prevout_txid": prevout.map(|p| p.hash().to_vec()),
            ":prevout_output_index": prevout.map(|p| p.n()),
        ])?;
    }

    Ok(())
}

/// Parses stored transaction bytes, or returns `None` if they do not parse.
///
/// The consensus branch ID a transaction is parsed under does not affect the parse: versions
/// before v5 do not encode it, and v5 onward carry their own. Every use in this module reads only
/// the transparent bundle, so a placeholder suffices and no height needs to be resolved for an
/// unmined transaction with no expiry height.
///
/// Bytes that do not parse are data the wallet cannot act on. This module must never fail on
/// them: its reconciliation runs inside the index migration, which cannot be reverted, so an
/// error there would leave the wallet unable to open. The backfill that populates the index
/// already skips such rows, and every path that reads them back agrees with it.
///
/// A failure here is permanent for that row: `queue_tx_retrieval` records enhancement intent
/// only for a transaction whose data the wallet lacks, and a row with unusable bytes still has
/// `raw` set, so no re-fetch is ever recorded for it.
fn parse_stored(raw: &[u8]) -> Option<Transaction> {
    Transaction::read(raw, BranchId::Sprout).ok()
}

/// Records the address observations of every transaction for which the wallet stores complete
/// transaction data.
///
/// A transaction whose stored bytes cannot be parsed contributes no observations; such data
/// cannot be repaired here, and failing would leave the wallet unable to open.
pub(crate) fn backfill_observations<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
) -> Result<(), SqliteClientError> {
    let mut backfilled = vec![];
    {
        let mut stmt_stored_txs =
            conn.prepare("SELECT id_tx, raw FROM transactions WHERE raw IS NOT NULL")?;
        let mut rows = stmt_stored_txs.query([])?;
        while let Some(row) = rows.next()? {
            let tx_ref = TxRef(row.get("id_tx")?);
            let raw = row.get::<_, Vec<u8>>("raw")?;

            let Some(tx) = parse_stored(&raw) else {
                continue;
            };

            backfilled.push((
                tx_ref,
                zcash_client_backend::wallet::transparent_address_observations(&tx),
            ));
        }
    }

    for (tx_ref, observations) in backfilled {
        put_observations(conn, params, tx_ref, &observations)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use ::transparent::{
        address::{Script, TransparentAddress},
        bundle::{Authorized as TransparentAuthorized, Bundle, OutPoint, TxIn, TxOut},
    };
    use rusqlite::named_params;
    use zcash_client_backend::{
        data_api::testing::TestBuilder,
        wallet::{TransparentAddressObservation, transparent_address_observations},
    };
    use zcash_keys::encoding::AddressCodec;
    use zcash_primitives::{
        block::BlockHash,
        transaction::{Authorized, Transaction, TransactionData, TxVersion},
    };
    use zcash_protocol::{
        consensus::{BlockHeight, BranchId},
        value::Zatoshis,
    };
    use zcash_script::script;

    use super::{Involvement, backfill_observations, put_observations};
    use crate::{TxRef, testing::db::TestDbFactory};

    /// A validly-encoded compressed public key: the `0x02` prefix followed by 32 bytes.
    fn pubkey_bytes() -> Vec<u8> {
        let mut bytes = vec![0x02];
        bytes.extend_from_slice(&[0x11; 32]);
        bytes
    }

    /// Builds a push-only script from the given data pushes, each at most 75 bytes so that the
    /// single-byte length encoding applies.
    fn push_script(pushes: &[&[u8]]) -> Script {
        let mut code = vec![];
        for data in pushes {
            code.push(u8::try_from(data.len()).expect("test pushes are shorter than 76 bytes"));
            code.extend_from_slice(data);
        }
        Script(script::Code(code))
    }

    /// A transaction paying `recipient` and spending `prevout` with a P2PKH `scriptSig`.
    fn test_transaction(recipient: TransparentAddress, prevout: OutPoint) -> Transaction {
        let bundle = Bundle::<TransparentAuthorized> {
            vin: vec![TxIn::from_parts(
                prevout,
                push_script(&[&[0x30; 71], &pubkey_bytes()]),
                0,
            )],
            vout: vec![TxOut::new(
                Zatoshis::const_from_u64(100_000),
                Script::from(&recipient.script()),
            )],
            authorization: TransparentAuthorized,
        };

        TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            BlockHeight::from(0),
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            Zatoshis::ZERO,
            Some(bundle),
            None,
            None,
            None,
        )
        .freeze()
        .expect("transaction data is complete")
    }

    /// An observation row as read back for comparison: the involvement direction, the item
    /// index, the encoded address, the value, and the prevout index.
    type ObservationRow = (i64, u32, String, Option<i64>, Option<u32>);

    /// Reads back every observation row for a transaction.
    fn stored_observations(conn: &rusqlite::Connection, tx_ref: TxRef) -> Vec<ObservationRow> {
        let mut stmt = conn
            .prepare(
                "SELECT involvement, item_index, address, value_zat, prevout_output_index
                 FROM transparent_tx_address_observations
                 WHERE transaction_id = :transaction_id
                 ORDER BY involvement, item_index",
            )
            .unwrap();
        stmt.query_map(named_params! { ":transaction_id": tx_ref.0 }, |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    }

    /// Observing the same transaction repeatedly converges to a single row per
    /// `(transaction, direction, item index)`, whatever the fidelity of each observation.
    #[test]
    fn put_observations_is_idempotent() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();

        let recipient = TransparentAddress::PublicKeyHash([0x22; 20]);
        let tx = test_transaction(recipient, OutPoint::new([0x33; 32], 7));
        let observations = transparent_address_observations(&tx);
        assert_eq!(observations.len(), 2);

        let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, min_observed_height) VALUES (1, X'00', 1)",
            [],
        )
        .unwrap();
        let tx_ref = TxRef(1);

        // The output-only fidelity of a compact-block observation, then the full-data
        // observation, then the full-data observation again.
        let outputs_only = observations
            .iter()
            .filter(|o| {
                matches!(
                    o.involvement(),
                    zcash_client_backend::wallet::TransparentInvolvement::Output(_)
                )
            })
            .cloned()
            .collect::<Vec<TransparentAddressObservation>>();

        put_observations(&conn, &network, tx_ref, &outputs_only).unwrap();
        let after_compact = stored_observations(&conn, tx_ref);
        assert_eq!(after_compact.len(), 1);

        put_observations(&conn, &network, tx_ref, &observations).unwrap();
        let after_full = stored_observations(&conn, tx_ref);
        put_observations(&conn, &network, tx_ref, &observations).unwrap();
        assert_eq!(stored_observations(&conn, tx_ref), after_full);

        assert_eq!(after_full.len(), 2);
        assert_eq!(after_full[0].0, Involvement::Output.encode());
        assert_eq!(after_full[0].2, recipient.encode(&network));
        assert_eq!(after_full[0].3, Some(100_000));
        assert_eq!(after_full[1].0, Involvement::Input.encode());
        assert_eq!(after_full[1].4, Some(7));

        conn.commit().unwrap();
    }

    /// The backfill records the observations of every transaction for which complete data is
    /// already stored, and ignores rows whose stored bytes do not parse.
    #[test]
    fn backfill_records_stored_transactions() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();

        let recipient = TransparentAddress::PublicKeyHash([0x55; 20]);
        let tx = test_transaction(recipient, OutPoint::new([0x66; 32], 3));
        let mut raw = vec![];
        tx.write(&mut raw).unwrap();

        let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, raw, expiry_height, min_observed_height)
             VALUES (1, :txid, :raw, 0, 1)",
            named_params! { ":txid": tx.txid().as_ref(), ":raw": raw },
        )
        .unwrap();
        // A transaction whose stored bytes are not a transaction at all.
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, raw, expiry_height, min_observed_height)
             VALUES (2, X'0102', X'DEADBEEF', 0, 1)",
            [],
        )
        .unwrap();
        // A transaction with no stored data at all.
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, min_observed_height) VALUES (3, X'0103', 1)",
            [],
        )
        .unwrap();

        backfill_observations(&conn, &network).unwrap();

        let recorded = stored_observations(&conn, TxRef(1));
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].2, recipient.encode(&network));
        assert!(stored_observations(&conn, TxRef(2)).is_empty());
        assert!(stored_observations(&conn, TxRef(3)).is_empty());

        conn.commit().unwrap();
    }

    /// Reads back every observation row in the wallet, as `(involvement, address)`.
    fn all_observed_addresses(conn: &rusqlite::Connection) -> Vec<(i64, String)> {
        let mut stmt = conn
            .prepare(
                "SELECT involvement, address FROM transparent_tx_address_observations
                 ORDER BY involvement, address",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Recording an empty set of observations touches nothing, so a caller may record the
    /// (empty) observations of a transaction whose row it has not created.
    #[test]
    fn empty_observations_touch_nothing() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();

        let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
        // `TxRef(1)` names no row, so a write here would violate the foreign key.
        put_observations(&conn, &network, TxRef(1), &[]).unwrap();
        assert!(all_observed_addresses(&conn).is_empty());
        conn.commit().unwrap();
    }
}
