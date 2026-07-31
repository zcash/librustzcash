//! Adds Ironwood received notes to the `v_address_uses` view.
//!
//! Ironwood notes ([ZIP 2005], NU6.3) are recorded in the `ironwood_received_notes` table, which
//! is separate from `orchard_received_notes` because the two pools have distinct note commitment
//! trees. Both tables carry an `address_id`, written by the same code path, so an Ironwood note
//! records which of the wallet's addresses received it just as an Orchard note does.
//!
//! `v_address_uses` unioned the Orchard, Sapling and transparent received-output tables and was
//! never extended to the Ironwood one, so those rows were simply not selected. After NU6.3 every
//! payment to an Orchard receiver is delivered in the Ironwood bundle, which makes an
//! Ironwood-only receipt the ordinary case rather than an exotic one.
//!
//! Two consequences follow from the omission:
//!
//! - `v_address_first_use`, which aggregates `v_address_uses`, reported no first-use height for an
//!   address whose only receipt was an Ironwood note. The transparent gap-limit search skips
//!   addresses with a NULL first-use height, so such an address read as never used and could be
//!   handed out again, which is an address-reuse hazard.
//! - The set of accounts involved in a transaction, which is read from `v_address_uses`, was empty
//!   for a transaction whose only wallet-relevant output was an Ironwood note.
//!
//! This migration recreates `v_address_uses` with an additional branch that unions in the
//! `ironwood_received_notes` table. `v_address_first_use` is not recreated: SQLite resolves a
//! view's references to other views by name when a query is compiled, so it picks up the new
//! definition on its own.
//!
//! [ZIP 2005]: https://zips.z.cash/zip-2005

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::ironwood_received_notes;

/// Adds Ironwood received notes to the `v_address_uses` view.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0xdab89587_cd05_43b0_a5b5_8cb64a702791);

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
        "Adds Ironwood received notes to the address-use view."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP VIEW v_address_uses;
            CREATE VIEW v_address_uses AS
                SELECT orn.address_id, orn.account_id, orn.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM orchard_received_notes orn
                JOIN addresses a ON a.id = orn.address_id
                JOIN transactions t ON t.id_tx = orn.transaction_id
            UNION
                SELECT irn.address_id, irn.account_id, irn.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM ironwood_received_notes irn
                JOIN addresses a ON a.id = irn.address_id
                JOIN transactions t ON t.id_tx = irn.transaction_id
            UNION
                SELECT srn.address_id, srn.account_id, srn.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM sapling_received_notes srn
                JOIN addresses a ON a.id = srn.address_id
                JOIN transactions t ON t.id_tx = srn.transaction_id
            UNION
                SELECT tro.address_id, tro.account_id, tro.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM transparent_received_outputs tro
                JOIN addresses a ON a.id = tro.address_id
                JOIN transactions t ON t.id_tx = tro.transaction_id;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use rusqlite::{OptionalExtension, named_params};
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::Network;

    #[cfg(feature = "transparent-inputs")]
    use crate::{TxRef, wallet::involved_accounts};
    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        util::testing::FixedClock,
        wallet::{
            encoding::{KeyScope, ReceiverFlags},
            init::{WalletMigrator, migrations::tests::test_migrate},
        },
    };

    /// The wallet type the scenarios operate on: a file-backed database with the deterministic
    /// clock and RNG the crate's other tests use.
    type TestWalletDb = WalletDb<rusqlite::Connection, Network, FixedClock, ChaChaRng>;

    /// The network the scenario wallets are built for. Any network works; the views under test do
    /// not consult consensus parameters.
    const NETWORK: Network = Network::TestNetwork;
    /// The seed the scenario wallets derive their single account from.
    const SEED_BYTE: u8 = 0xab;
    const SEED_LEN: usize = 32;

    /// Row ids for the single account, address and transaction each scenario writes. The scenarios
    /// seed exactly one of each, so any distinct values would do; fixing them keeps the assertions
    /// legible.
    const ACCOUNT_ROW_ID: i64 = 1;
    const ADDRESS_ROW_ID: i64 = 1;
    const TX_ROW_ID: i64 = 1;

    /// Identity columns for the seeded rows. The views do not interpret them; they exist to
    /// satisfy the tables' constraints.
    const ACCOUNT_UUID: [u8; 16] = [1; 16];
    const SEED_FINGERPRINT: [u8; 32] = [SEED_BYTE; 32];
    const ZIP32_ACCOUNT_INDEX: i64 = 0;
    const BIRTHDAY_HEIGHT: i64 = 0;
    /// The `account_kind` discriminant for an account derived from a ZIP 32 seed.
    const ACCOUNT_KIND_DERIVED: i64 = 0;
    /// Whether the wallet holds the account's spending key. The seeded account is a spending
    /// account, which is the ordinary case.
    const HAS_SPEND_KEY: bool = true;
    const TXID: [u8; 32] = [7; 32];
    /// The height at which the seeded transaction is mined. This is the height the address-use
    /// views must report as the address's first use, so it is deliberately not zero: a NULL and a
    /// zero must not be confusable in the assertions.
    const MINED_HEIGHT: i64 = 100;

    /// The transparent child index the seeded address is derived at. The gap-limit search orders
    /// by this column, so it must be a real index rather than NULL.
    const TRANSPARENT_CHILD_INDEX: i64 = 0;
    /// The big-endian diversifier index matching `TRANSPARENT_CHILD_INDEX`. The addresses table
    /// requires a non-NULL diversifier index for any address that is not an imported foreign one.
    const DIVERSIFIER_INDEX_BE: [u8; 11] = [0; 11];
    /// Placeholder address encodings. The views select these columns only through `address_id`,
    /// and never parse them.
    const ADDRESS: &str = "placeholder-unified-address";
    const TRANSPARENT_ADDRESS: &str = "placeholder-transparent-address";

    /// Payload columns for the seeded Ironwood note. The views do not read them.
    const ACTION_INDEX: i64 = 0;
    const NOTE_DIVERSIFIER: [u8; 11] = [0; 11];
    const NOTE_VALUE_ZATS: i64 = 100_000;
    const NOTE_COMPONENT: [u8; 32] = [0; 32];
    /// Ironwood notes are obtained from version 3 note plaintexts.
    const IRONWOOD_NOTE_VERSION: i64 = 3;
    /// The seeded note is a payment received from elsewhere, not the account's own change; that
    /// is the case the address-use views exist to record.
    const NOTE_IS_CHANGE: bool = false;

    /// Writes one account, one address of that account carrying a transparent receiver, one mined
    /// transaction, and one Ironwood note that the account received at that address in that
    /// transaction.
    ///
    /// The rows are written directly rather than through the wallet API because the scenarios need
    /// them present in a wallet that has *not* yet had this migration applied, which is the state
    /// an upgrading wallet is in.
    fn seed_ironwood_receipt(db_data: &mut TestWalletDb) {
        // The UFVK and UIVK must be real encoded values, as `verify_network_compatibility` parses
        // them when later migrations are applied.
        let seed_bytes = vec![SEED_BYTE; SEED_LEN];
        let usk = UnifiedSpendingKey::from_seed(&NETWORK, &seed_bytes, zip32::AccountId::ZERO)
            .expect("the test seed is a valid seed for account zero");
        let ufvk = usk.to_unified_full_viewing_key();

        db_data
            .conn
            .execute(
                "INSERT INTO accounts (id, uuid, account_kind, hd_seed_fingerprint,
                 hd_account_index, ufvk, uivk, has_spend_key, birthday_height)
                 VALUES (:id, :uuid, :account_kind, :seed_fingerprint,
                 :account_index, :ufvk, :uivk, :has_spend_key, :birthday_height)",
                named_params![
                    ":id": ACCOUNT_ROW_ID,
                    ":uuid": &ACCOUNT_UUID[..],
                    ":account_kind": ACCOUNT_KIND_DERIVED,
                    ":has_spend_key": HAS_SPEND_KEY,
                    ":seed_fingerprint": &SEED_FINGERPRINT[..],
                    ":account_index": ZIP32_ACCOUNT_INDEX,
                    ":ufvk": ufvk.encode(&NETWORK),
                    ":uivk": ufvk.to_unified_incoming_viewing_key().encode(&NETWORK),
                    ":birthday_height": BIRTHDAY_HEIGHT,
                ],
            )
            .unwrap();

        db_data
            .conn
            .execute(
                "INSERT INTO addresses (id, account_id, key_scope, diversifier_index_be, address,
                 transparent_child_index, cached_transparent_receiver_address, receiver_flags)
                 VALUES (:id, :account_id, :key_scope, :diversifier_index_be, :address,
                 :transparent_child_index, :transparent_address, :receiver_flags)",
                named_params![
                    ":id": ADDRESS_ROW_ID,
                    ":account_id": ACCOUNT_ROW_ID,
                    ":key_scope": KeyScope::EXTERNAL.encode(),
                    ":diversifier_index_be": &DIVERSIFIER_INDEX_BE[..],
                    ":address": ADDRESS,
                    ":transparent_child_index": TRANSPARENT_CHILD_INDEX,
                    ":transparent_address": TRANSPARENT_ADDRESS,
                    ":receiver_flags": (ReceiverFlags::ORCHARD | ReceiverFlags::P2PKH).bits(),
                ],
            )
            .unwrap();

        db_data
            .conn
            .execute(
                "INSERT INTO transactions (id_tx, txid, mined_height, min_observed_height)
                 VALUES (:id_tx, :txid, :mined_height, :mined_height)",
                named_params![
                    ":id_tx": TX_ROW_ID,
                    ":txid": &TXID[..],
                    ":mined_height": MINED_HEIGHT,
                ],
            )
            .unwrap();

        db_data
            .conn
            .execute(
                "INSERT INTO ironwood_received_notes
                 (transaction_id, action_index, account_id, address_id, diversifier, value,
                  rho, rseed, is_change, note_version, recipient_key_scope)
                 VALUES (:tx, :action_index, :account_id, :address_id, :diversifier, :value,
                  :note_component, :note_component, :is_change, :note_version, :key_scope)",
                named_params![
                    ":is_change": NOTE_IS_CHANGE,
                    ":tx": TX_ROW_ID,
                    ":action_index": ACTION_INDEX,
                    ":account_id": ACCOUNT_ROW_ID,
                    ":address_id": ADDRESS_ROW_ID,
                    ":diversifier": &NOTE_DIVERSIFIER[..],
                    ":value": NOTE_VALUE_ZATS,
                    ":note_component": &NOTE_COMPONENT[..],
                    ":note_version": IRONWOOD_NOTE_VERSION,
                    ":key_scope": KeyScope::EXTERNAL.encode(),
                ],
            )
            .unwrap();
    }

    /// The number of `v_address_uses` rows attributing a use to the seeded address.
    fn address_use_count(conn: &rusqlite::Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM v_address_uses WHERE address_id = :address_id",
            named_params![":address_id": ADDRESS_ROW_ID],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// The first-use height `v_address_first_use` reports for the seeded address, which is what
    /// the transparent gap-limit search consults to decide whether an address has been used.
    ///
    /// An address with no recorded use produces no row at all, and the search treats a missing
    /// row and a NULL height alike, so both collapse to `None` here.
    fn address_first_use_height(conn: &rusqlite::Connection) -> Option<i64> {
        conn.query_row(
            "SELECT first_use_height FROM v_address_first_use WHERE address_id = :address_id",
            named_params![":address_id": ADDRESS_ROW_ID],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()
        .unwrap()
        .flatten()
    }

    /// A wallet migrated to the state immediately preceding this migration, with an Ironwood
    /// receipt seeded into it. This is the state an upgrading wallet is in.
    ///
    /// The temporary file is returned alongside the database because dropping it would delete the
    /// database out from under the test.
    fn wallet_before_migration() -> (NamedTempFile, TestWalletDb) {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data =
            WalletDb::for_path(data_file.path(), NETWORK, test_clock(), test_rng()).unwrap();

        WalletMigrator::new()
            .with_seed(Secret::new(vec![SEED_BYTE; SEED_LEN]))
            .ignore_seed_relevance()
            .init_or_migrate_to(&mut db_data, super::DEPENDENCIES)
            .unwrap();

        seed_ironwood_receipt(&mut db_data);

        (data_file, db_data)
    }

    /// Applies this migration to a wallet already carrying seeded data.
    fn apply_migration(db_data: &mut TestWalletDb) {
        WalletMigrator::new()
            .with_seed(Secret::new(vec![SEED_BYTE; SEED_LEN]))
            .ignore_seed_relevance()
            .init_or_migrate_to(db_data, &[super::MIGRATION_ID])
            .unwrap();
    }

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    /// Scenario: an address that has received an Ironwood note reads as never used.
    ///
    /// `v_address_uses` is the wallet's record of which of its addresses have been seen on chain,
    /// and `v_address_first_use` aggregates it into the first height at which each address was
    /// used. The transparent gap-limit search selects only addresses with a non-NULL first-use
    /// height, so an address whose sole receipt is an Ironwood note is invisible to it and remains
    /// eligible to be handed out again.
    #[test]
    fn scenario_ironwood_receipt_does_not_mark_its_address_used() {
        let (_data_file, mut db_data) = wallet_before_migration();

        assert_eq!(
            address_use_count(&db_data.conn),
            0,
            "the bug: an address that received an Ironwood note records no use"
        );
        assert_eq!(
            address_first_use_height(&db_data.conn),
            None,
            "the bug: the address has no first-use height, so it reads as never used"
        );

        apply_migration(&mut db_data);

        assert_eq!(
            address_use_count(&db_data.conn),
            1,
            "the Ironwood receipt must be recorded as a use of the address"
        );
        assert_eq!(
            address_first_use_height(&db_data.conn),
            Some(MINED_HEIGHT),
            "and the address's first use must be the height its receipt was mined at"
        );
    }

    /// Scenario: a transaction whose only wallet-relevant output is an Ironwood note involves no
    /// accounts.
    ///
    /// `involved_accounts` reads `v_address_uses` to decide which of the wallet's accounts a
    /// transaction concerns. After NU6.3 every payment to an Orchard receiver is delivered in the
    /// Ironwood bundle, so this is the shape of an ordinary received payment, and the account that
    /// received it was reported as uninvolved.
    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn scenario_ironwood_receipt_leaves_its_account_uninvolved() {
        let (_data_file, mut db_data) = wallet_before_migration();

        assert!(
            involved_accounts(&db_data.conn, [TxRef(TX_ROW_ID)])
                .unwrap()
                .is_empty(),
            "the bug: the account that received the Ironwood note is not involved in the \
             transaction that paid it"
        );

        apply_migration(&mut db_data);

        let involved = involved_accounts(&db_data.conn, [TxRef(TX_ROW_ID)]).unwrap();
        assert_eq!(
            involved.len(),
            1,
            "the receiving account must be involved in the transaction that paid it"
        );
        assert!(
            involved
                .iter()
                .any(|(account_ref, _, _)| account_ref.0 == ACCOUNT_ROW_ID),
            "and it must be the account the note was received by"
        );
    }
}
