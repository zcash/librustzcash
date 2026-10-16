//! Sets the `is_change` flag on Ironwood output notes received by an internal key when input value
//! was provided from the account corresponding to that key.
//!
//! This is the Ironwood counterpart of [`super::fix_bad_change_flagging`], and runs that
//! migration's statement against the Ironwood received-note table. Two pool lists had to be kept
//! in step and only one of them was: the runtime repair, `flag_previously_received_change`,
//! covered Sapling and Orchard but not Ironwood, so the notes that needed it were never flagged.
//!
//! A note received on an account's internal address is change when that same account funded the
//! transaction. The scanner cannot always establish the second half: it infers it by matching a
//! block's nullifiers against the notes the wallet already holds, which fails whenever a block is
//! scanned before the block that created its inputs. The runtime repair supplies the missing
//! classification later, when the transaction's `sent_notes` rows are written. Because `is_change`
//! is written monotonically and nothing revisits a received note once its transaction has been
//! recorded, an Ironwood note that missed that repair kept `is_change = 0` permanently.
//!
//! Sapling and Orchard need no equivalent pass here: they were in the runtime repair's pool list
//! throughout, so any row this predicate would change was already changed when it was written.
//! Running it for them would be harmless rather than wrong, since the predicate is exactly the one
//! the live code applies on every sent-output write, but it would repair nothing.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::{
    IRONWOOD_TABLES_PREFIX,
    wallet::{KeyScope, init::WalletMigrationError},
};

use super::ironwood_received_notes;

/// Sets the `is_change` flag on Ironwood output notes received by an internal key when input value
/// was provided from the account corresponding to that key.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xcc104d0d_54d6_4e07_9404_202676561d94);

pub(super) const DEPENDENCIES: &[Uuid] = &[ironwood_received_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Sets the `is_change` flag on Ironwood output notes received by an internal key when input value was provided from the account corresponding to that key."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // The Ironwood tables exist in the schema regardless of whether the `orchard` feature is
        // enabled, so this repair is not feature-gated: a wallet whose notes were written by an
        // Orchard-enabled build is repaired even when the build applying the migration is not.
        //
        // `is_change` only ever moves from 0 to 1, so this is idempotent: applying it twice, or
        // applying it to a wallet that was never affected, changes nothing.
        let table_prefix = IRONWOOD_TABLES_PREFIX;
        transaction.execute(
            &format!(
                "UPDATE {table_prefix}_received_notes
                 SET is_change = 1
                 FROM sent_notes sn
                 WHERE sn.transaction_id = {table_prefix}_received_notes.transaction_id
                 AND sn.from_account_id = {table_prefix}_received_notes.account_id
                 AND {table_prefix}_received_notes.recipient_key_scope = :internal_scope"
            ),
            named_params! {":internal_scope": KeyScope::INTERNAL.encode()},
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // The pre-migration state is not recoverable: a note that this migration flagged is
        // indistinguishable from one the wallet flagged when it was received.
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{Transaction, named_params};
    use schemerz_rusqlite::RusqliteMigration;
    use zcash_client_backend::data_api::testing::TestBuilder;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{PoolType, ShieldedPool};

    use crate::testing::db::TestDbFactory;
    use crate::wallet::encoding::{KeyScope, pool_code};
    use crate::wallet::init::migrations::tests::test_migrate;

    /// The row id given to the single transaction each scenario builds.
    const TX_ROW_ID: i64 = 1;
    /// Placeholders for columns none of these scenarios reads back; they exist only to satisfy
    /// the tables' NOT NULL constraints, so any well-formed value will do.
    const TXID: [u8; 32] = [7; 32];
    const OBSERVED_HEIGHT: i64 = 0;
    const ACTION_INDEX: i64 = 0;
    const DIVERSIFIER: [u8; 11] = [0; 11];
    const NOTE_VALUE_ZATS: i64 = 100_000;
    const NOTE_COMPONENT: [u8; 32] = [0; 32];
    const NOTE_VERSION: i64 = 2;
    /// The transparent output the shielding scenario consumes, and the earlier transaction that
    /// paid it. Larger than the note above so the difference reads as a fee rather than as value
    /// appearing from nowhere.
    const TRANSPARENT_INPUT_ZATS: i64 = 125_000;
    const TRANSPARENT_OUTPUT_ROW_ID: i64 = 1;
    const TRANSPARENT_OUTPUT_INDEX: i64 = 0;
    const TRANSPARENT_SCRIPT: [u8; 1] = [0];
    const TRANSPARENT_ADDRESS: &str = "placeholder-transparent-address";
    const FUNDING_TX_ROW_ID: i64 = 2;
    const FUNDING_TXID: [u8; 32] = [8; 32];
    /// The Orchard note the turnstile scenario retires. Its excess over the Ironwood output is the
    /// fee, which is the only value the account actually parts with.
    const ORCHARD_INPUT_ZATS: i64 = 125_000;
    const ORCHARD_NOTE_ROW_ID: i64 = 1;

    /// A migrated wallet holding a single account. Each scenario builds one and then writes the
    /// rows it needs directly, because the states under test are ones the current code no longer
    /// produces.
    macro_rules! wallet_with_one_account {
        () => {
            TestBuilder::new()
                .with_data_store_factory(TestDbFactory::default())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build()
        };
    }

    /// The `accounts.id` of the wallet's only account, and the id of an address belonging to it.
    fn account_and_address_ids(conn: &rusqlite::Connection) -> (i64, i64) {
        let account_id = conn
            .query_row("SELECT id FROM accounts", [], |row| row.get::<_, i64>(0))
            .unwrap();
        let address_id = conn
            .query_row("SELECT id FROM addresses LIMIT 1", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();

        (account_id, address_id)
    }

    /// Reproduces the state the missing repair leaves behind: a transaction, an Ironwood note the
    /// account received on `key_scope` recorded with `is_change = 0` because the scanner could not
    /// yet link the transaction's spends, and the `sent_notes` row that later established the
    /// account funded it.
    ///
    /// The `sent_notes` row is attributed to the Ironwood pool at the note's action index, which
    /// is what `v_received_outputs` joins on, so the two describe one output rather than two.
    fn seed_unflagged_ironwood_note(conn: &Transaction, account_id: i64, key_scope: KeyScope) {
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, min_observed_height)
             VALUES (:id_tx, :txid, :min_observed_height)",
            named_params! {
                ":id_tx": TX_ROW_ID,
                ":txid": &TXID[..],
                ":min_observed_height": OBSERVED_HEIGHT,
            },
        )
        .unwrap();

        conn.execute(
            "INSERT INTO ironwood_received_notes
             (transaction_id, action_index, account_id, diversifier, value, rho, rseed,
              note_version, is_change, recipient_key_scope)
             VALUES (:tx, :action_index, :account, :diversifier, :value, :note_component,
                     :note_component, :note_version, :is_change, :key_scope)",
            named_params! {
                ":tx": TX_ROW_ID,
                ":action_index": ACTION_INDEX,
                ":account": account_id,
                ":diversifier": &DIVERSIFIER[..],
                ":value": NOTE_VALUE_ZATS,
                ":note_component": &NOTE_COMPONENT[..],
                ":note_version": NOTE_VERSION,
                ":is_change": false,
                ":key_scope": key_scope.encode(),
            },
        )
        .unwrap();

        conn.execute(
            "INSERT INTO sent_notes
             (transaction_id, output_pool, output_index, from_account_id, value)
             VALUES (:tx, :output_pool, :output_index, :from_account, :value)",
            named_params! {
                ":tx": TX_ROW_ID,
                ":output_pool": pool_code(PoolType::Shielded(ShieldedPool::Ironwood)),
                ":output_index": ACTION_INDEX,
                ":from_account": account_id,
                ":value": NOTE_VALUE_ZATS,
            },
        )
        .unwrap();
    }

    /// Gives the account a transparent output in an *earlier* transaction, and has the seeded
    /// transaction spend it. That makes the seeded transaction shielding-shaped: every output it
    /// spends is transparent, and every output it receives is shielded.
    ///
    /// The funding transaction has to be a separate one. An output received and spent within the
    /// same transaction would contribute a transparent *received* row to that transaction, and a
    /// shielding transaction by definition receives nothing transparent.
    fn spend_a_transparent_output(conn: &Transaction, account_id: i64, address_id: i64) {
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, min_observed_height)
             VALUES (:id_tx, :txid, :min_observed_height)",
            named_params! {
                ":id_tx": FUNDING_TX_ROW_ID,
                ":txid": &FUNDING_TXID[..],
                ":min_observed_height": OBSERVED_HEIGHT,
            },
        )
        .unwrap();

        conn.execute(
            "INSERT INTO transparent_received_outputs
             (id, transaction_id, output_index, account_id, address, script, value_zat, address_id)
             VALUES (:id, :tx, :output_index, :account, :address, :script, :value, :address_id)",
            named_params! {
                ":id": TRANSPARENT_OUTPUT_ROW_ID,
                ":tx": FUNDING_TX_ROW_ID,
                ":output_index": TRANSPARENT_OUTPUT_INDEX,
                ":account": account_id,
                ":address": TRANSPARENT_ADDRESS,
                ":script": &TRANSPARENT_SCRIPT[..],
                ":value": TRANSPARENT_INPUT_ZATS,
                ":address_id": address_id,
            },
        )
        .unwrap();

        conn.execute(
            "INSERT INTO transparent_received_output_spends
             (transparent_received_output_id, transaction_id)
             VALUES (:output_id, :tx)",
            named_params! { ":output_id": TRANSPARENT_OUTPUT_ROW_ID, ":tx": TX_ROW_ID },
        )
        .unwrap();
    }

    /// Gives the account an Orchard note in an earlier transaction, and has the seeded transaction
    /// spend it. Together with the Ironwood output the seeded transaction already carries, this is
    /// a turnstile crossing: after NU6.3 no value may be added to the Orchard pool, so value
    /// leaving Orchard can only reappear in Ironwood.
    fn spend_an_orchard_note(conn: &Transaction, account_id: i64) {
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, min_observed_height)
             VALUES (:id_tx, :txid, :min_observed_height)",
            named_params! {
                ":id_tx": FUNDING_TX_ROW_ID,
                ":txid": &FUNDING_TXID[..],
                ":min_observed_height": OBSERVED_HEIGHT,
            },
        )
        .unwrap();

        conn.execute(
            "INSERT INTO orchard_received_notes
             (id, transaction_id, action_index, account_id, diversifier, value, rho, rseed,
              is_change, recipient_key_scope)
             VALUES (:id, :tx, :action_index, :account, :diversifier, :value, :note_component,
                     :note_component, :is_change, :key_scope)",
            named_params! {
                ":id": ORCHARD_NOTE_ROW_ID,
                ":tx": FUNDING_TX_ROW_ID,
                ":action_index": ACTION_INDEX,
                ":account": account_id,
                ":diversifier": &DIVERSIFIER[..],
                ":value": ORCHARD_INPUT_ZATS,
                ":note_component": &NOTE_COMPONENT[..],
                ":is_change": false,
                ":key_scope": KeyScope::EXTERNAL.encode(),
            },
        )
        .unwrap();

        conn.execute(
            "INSERT INTO orchard_received_note_spends
             (orchard_received_note_id, transaction_id)
             VALUES (:note_id, :tx)",
            named_params! { ":note_id": ORCHARD_NOTE_ROW_ID, ":tx": TX_ROW_ID },
        )
        .unwrap();
    }

    fn note_is_change(conn: &Transaction) -> bool {
        conn.query_row("SELECT is_change FROM ironwood_received_notes", [], |row| {
            row.get::<_, bool>(0)
        })
        .unwrap()
    }

    /// The wallet's view of the transaction, as the columns a wallet UI reads.
    struct TxSummary {
        account_balance_delta: i64,
        has_change: bool,
        received_note_count: i64,
        sent_note_count: i64,
        is_shielding: bool,
    }

    /// Scoped to the seeded transaction: a scenario that funds it from an earlier transaction puts
    /// that one in these views too.
    fn tx_summary(conn: &Transaction) -> TxSummary {
        conn.query_row(
            "SELECT account_balance_delta, has_change, received_note_count, sent_note_count,
                    is_shielding
             FROM v_transactions WHERE txid = :txid",
            named_params! { ":txid": &TXID[..] },
            |row| {
                Ok(TxSummary {
                    account_balance_delta: row.get(0)?,
                    has_change: row.get(1)?,
                    received_note_count: row.get(2)?,
                    sent_note_count: row.get(3)?,
                    is_shielding: row.get(4)?,
                })
            },
        )
        .unwrap()
    }

    /// The outputs a wallet would offer as recipients: `v_tx_outputs` rows that are not change.
    /// This is the query a light-wallet SDK runs to render "sent to".
    fn non_change_output_count(conn: &Transaction) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM v_tx_outputs WHERE txid = :txid AND is_change = 0",
            named_params! { ":txid": &TXID[..] },
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    #[test]
    fn repairs_and_is_idempotent() {
        let mut st = wallet_with_one_account!();
        let (account_id, _) = account_and_address_ids(st.wallet().conn());
        let tx = st.wallet_mut().conn_mut().transaction().unwrap();
        seed_unflagged_ironwood_note(&tx, account_id, KeyScope::INTERNAL);

        assert!(
            !note_is_change(&tx),
            "precondition: the note starts unflagged"
        );

        super::Migration.up(&tx).unwrap();
        assert!(
            note_is_change(&tx),
            "the migration must reclassify the note"
        );

        super::Migration.up(&tx).unwrap();
        assert!(
            note_is_change(&tx),
            "re-applying the migration must not disturb it"
        );
    }

    /// The migration inherits the runtime repair's scope restriction: a note received on the
    /// account's external address is a payment the user made to themselves, not change, and must
    /// keep its classification so that it stays visible as an output of the transaction.
    #[test]
    fn leaves_external_scope_notes_alone() {
        let mut st = wallet_with_one_account!();
        let (account_id, _) = account_and_address_ids(st.wallet().conn());
        let tx = st.wallet_mut().conn_mut().transaction().unwrap();
        seed_unflagged_ironwood_note(&tx, account_id, KeyScope::EXTERNAL);

        super::Migration.up(&tx).unwrap();

        assert!(
            !note_is_change(&tx),
            "an external-scope note must not be reclassified as change"
        );
        assert_eq!(
            non_change_output_count(&tx),
            1,
            "and it must remain visible as an output of the transaction"
        );
    }

    /// Scenario: the wallet's own change is offered to the user as a recipient.
    ///
    /// A wallet renders "sent to" from the `v_tx_outputs` rows that are not change. While the
    /// change note carries `is_change = 0`, the account's own internal address is one of those
    /// rows, so the user is shown themselves as the recipient of their own transaction. The
    /// transaction summary is wrong in the same direction: the wallet reports no change, and
    /// counts the change note as both a received note and a note it sent.
    #[test]
    fn scenario_change_is_offered_as_a_recipient() {
        let mut st = wallet_with_one_account!();
        let (account_id, _) = account_and_address_ids(st.wallet().conn());
        let tx = st.wallet_mut().conn_mut().transaction().unwrap();
        seed_unflagged_ironwood_note(&tx, account_id, KeyScope::INTERNAL);

        let before = tx_summary(&tx);
        assert_eq!(
            non_change_output_count(&tx),
            1,
            "the bug: the account's own change is offered as a recipient"
        );
        assert!(!before.has_change, "the bug: the wallet reports no change");
        assert_eq!(
            before.received_note_count, 1,
            "the bug: change is counted as an incoming payment"
        );
        assert_eq!(
            before.sent_note_count, 1,
            "the bug: change is counted as a note the wallet sent"
        );

        super::Migration.up(&tx).unwrap();

        let after = tx_summary(&tx);
        assert_eq!(
            non_change_output_count(&tx),
            0,
            "after the repair there is no recipient to show"
        );
        assert!(after.has_change, "and the transaction reports its change");
        assert_eq!(after.received_note_count, 0);
        assert_eq!(after.sent_note_count, 0);
    }

    /// Scenario: a shielding transaction stops being recognised as one.
    ///
    /// `v_transactions.is_shielding` requires that the wallet knows of no external outputs, which
    /// it decides from the same non-change output set. An unflagged change note therefore reads as
    /// an external output and the flag goes false. This one changes displayed amounts rather than
    /// labels: a wallet that renders shielding transactions from `total_spent` and ordinary sends
    /// from `account_balance_delta` switches formulas when the flag flips.
    #[test]
    fn scenario_shielding_transaction_is_no_longer_recognised() {
        let mut st = wallet_with_one_account!();
        let (account_id, address_id) = account_and_address_ids(st.wallet().conn());
        let tx = st.wallet_mut().conn_mut().transaction().unwrap();
        seed_unflagged_ironwood_note(&tx, account_id, KeyScope::INTERNAL);
        spend_a_transparent_output(&tx, account_id, address_id);

        assert!(
            !tx_summary(&tx).is_shielding,
            "the bug: a shielding transaction is not recognised as shielding"
        );

        super::Migration.up(&tx).unwrap();

        assert!(
            tx_summary(&tx).is_shielding,
            "after the repair it is recognised again"
        );
    }

    /// Scenario: an Orchard-to-Ironwood turnstile crossing is reported as an incoming payment.
    ///
    /// After NU6.3 no value may be added to the Orchard pool, so value leaving Orchard can only
    /// reappear in Ironwood, and the wallet's own crossing pays itself at its internal address.
    /// The crossing has no external recipient at all: the only thing the user should see is that
    /// their balance moved pools and a fee was paid.
    ///
    /// This is the case with the widest blast radius. The turnstile makes Ironwood the pool every
    /// post-NU6.3 shielded change output lands in, so the pool this repair was missing is the one
    /// change now always uses. Unflagged, the whole crossed balance reads as money arriving from
    /// outside, and the account's own internal address is offered as the recipient of a
    /// transaction that has no recipient.
    ///
    /// Note that `account_balance_delta` is right throughout: the value accounting never depended
    /// on the flag. What the bug corrupts is the story the wallet tells about the value, not the
    /// value.
    #[test]
    fn scenario_turnstile_crossing_is_reported_as_an_incoming_payment() {
        let mut st = wallet_with_one_account!();
        let (account_id, _) = account_and_address_ids(st.wallet().conn());
        let tx = st.wallet_mut().conn_mut().transaction().unwrap();
        seed_unflagged_ironwood_note(&tx, account_id, KeyScope::INTERNAL);
        spend_an_orchard_note(&tx, account_id);

        let fee = ORCHARD_INPUT_ZATS - NOTE_VALUE_ZATS;

        let before = tx_summary(&tx);
        assert_eq!(
            before.account_balance_delta, -fee,
            "the account parts with the fee and nothing else, before and after the repair"
        );
        assert_eq!(
            before.received_note_count, 1,
            "the bug: the crossed balance reads as an incoming payment"
        );
        assert!(
            !before.has_change,
            "the bug: the crossing reports no change"
        );
        assert_eq!(
            non_change_output_count(&tx),
            1,
            "the bug: a transaction with no recipient offers the account's own address as one"
        );

        super::Migration.up(&tx).unwrap();

        let after = tx_summary(&tx);
        assert_eq!(
            after.account_balance_delta, -fee,
            "the value accounting never depended on the flag"
        );
        assert_eq!(after.received_note_count, 0);
        assert!(after.has_change, "the crossing is recognised as internal");
        assert_eq!(
            non_change_output_count(&tx),
            0,
            "and a transaction with no recipient offers none"
        );
    }
}
