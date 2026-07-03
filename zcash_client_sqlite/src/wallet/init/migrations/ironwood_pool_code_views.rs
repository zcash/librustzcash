//! Adds Ironwood received notes to the `v_received_outputs` and `v_received_output_spends` views.
//!
//! Ironwood notes ([ZIP 2005], NU6.3) are recorded in the `ironwood_received_notes` table, which
//! is separate from `orchard_received_notes` because the two pools have distinct note commitment
//! trees. The views that aggregate received outputs and their spends across pools were previously
//! unaware of the Ironwood tables, so Ironwood notes did not appear in `v_transactions`,
//! `v_tx_outputs`, or any balance computation derived from them.
//!
//! This migration recreates `v_received_outputs` and `v_received_output_spends` with an additional
//! branch that unions in the `ironwood_received_notes` and `ironwood_received_note_spends` tables,
//! tagged with the Ironwood pool code 4 (see [`crate::wallet::encoding::pool_code`]).
//!
//! [ZIP 2005]: https://zips.z.cash/zip-2005

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::ironwood_received_notes;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xa6ef40c7_050a_43c6_a4e2_2f034168c979);

const DEPENDENCIES: &[Uuid] = &[ironwood_received_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds Ironwood received notes to the received-output and spend views."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP VIEW v_received_outputs;
            CREATE VIEW v_received_outputs AS
                SELECT
                    sapling_received_notes.id AS id_within_pool_table,
                    sapling_received_notes.transaction_id,
                    2 AS pool,
                    sapling_received_notes.output_index,
                    account_id,
                    sapling_received_notes.value,
                    is_change,
                    sapling_received_notes.memo,
                    sent_notes.id AS sent_note_id,
                    sapling_received_notes.address_id
                FROM sapling_received_notes
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (sapling_received_notes.transaction_id, 2, sapling_received_notes.output_index)
            UNION
                SELECT
                    orchard_received_notes.id AS id_within_pool_table,
                    orchard_received_notes.transaction_id,
                    3 AS pool,
                    orchard_received_notes.action_index AS output_index,
                    account_id,
                    orchard_received_notes.value,
                    is_change,
                    orchard_received_notes.memo,
                    sent_notes.id AS sent_note_id,
                    orchard_received_notes.address_id
                FROM orchard_received_notes
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (orchard_received_notes.transaction_id, 3, orchard_received_notes.action_index)
            UNION
                SELECT
                    ironwood_received_notes.id AS id_within_pool_table,
                    ironwood_received_notes.transaction_id,
                    4 AS pool,
                    ironwood_received_notes.action_index AS output_index,
                    account_id,
                    ironwood_received_notes.value,
                    is_change,
                    ironwood_received_notes.memo,
                    sent_notes.id AS sent_note_id,
                    ironwood_received_notes.address_id
                FROM ironwood_received_notes
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (ironwood_received_notes.transaction_id, 4, ironwood_received_notes.action_index)
            UNION
                SELECT
                    u.id AS id_within_pool_table,
                    u.transaction_id,
                    0 AS pool,
                    u.output_index,
                    u.account_id,
                    u.value_zat AS value,
                    0 AS is_change,
                    NULL AS memo,
                    sent_notes.id AS sent_note_id,
                    u.address_id
                FROM transparent_received_outputs u
                LEFT JOIN sent_notes
                ON (sent_notes.transaction_id, sent_notes.output_pool, sent_notes.output_index) =
                   (u.transaction_id, 0, u.output_index);

            DROP VIEW v_received_output_spends;
            CREATE VIEW v_received_output_spends AS
            SELECT
                2 AS pool,
                s.sapling_received_note_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM sapling_received_note_spends s
            JOIN sapling_received_notes rn ON rn.id = s.sapling_received_note_id
            UNION
            SELECT
                3 AS pool,
                s.orchard_received_note_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM orchard_received_note_spends s
            JOIN orchard_received_notes rn ON rn.id = s.orchard_received_note_id
            UNION
            SELECT
                4 AS pool,
                s.ironwood_received_note_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM ironwood_received_note_spends s
            JOIN ironwood_received_notes rn ON rn.id = s.ironwood_received_note_id
            UNION
            SELECT
                0 AS pool,
                s.transparent_received_output_id AS received_output_id,
                s.transaction_id,
                rn.account_id
            FROM transparent_received_output_spends s
            JOIN transparent_received_outputs rn ON rn.id = s.transparent_received_output_id;",
        )?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    /// After this migration, an Orchard note and an Ironwood note recorded at the same action
    /// index in the same transaction both surface in `v_received_outputs`, tagged with pool codes
    /// 3 and 4 respectively. The pre-existing Orchard row must keep pool code 3, and the two rows
    /// must be distinct even though they share `(transaction_id, action_index)`, because they live
    /// in separate pool tables.
    #[cfg(feature = "orchard")]
    #[test]
    fn ironwood_and_orchard_notes_appear_in_received_outputs() {
        use proptest::{prelude::ProptestConfig, prop_assert_eq, test_runner::TestRunner};
        use rusqlite::named_params;
        use secrecy::Secret;
        use tempfile::NamedTempFile;
        use zcash_keys::keys::UnifiedSpendingKey;
        use zcash_protocol::consensus::Network;

        use crate::{
            WalletDb,
            testing::db::{test_clock, test_rng},
            wallet::init::{
                WalletMigrator,
                migrations::tests::{
                    ArbIronwoodNote, ArbOrchardNote, arb_ironwood_note, arb_orchard_note,
                },
            },
        };

        let network = Network::TestNetwork;
        let seed_bytes = vec![0xab; 32];

        // The view does not transform the note payload, so a handful of cases is enough to
        // exercise the union while keeping the per-case wallet setup cheap.
        let mut runner = TestRunner::new(ProptestConfig::with_cases(8));
        runner
            .run(
                &(arb_orchard_note(), arb_ironwood_note()),
                |(orchard_note, ironwood_note): (ArbOrchardNote, ArbIronwoodNote)| {
                    let data_file = NamedTempFile::new().unwrap();
                    let mut db_data =
                        WalletDb::for_path(data_file.path(), network, test_clock(), test_rng())
                            .unwrap();

                    // Migrate through this migration, so `v_received_outputs` includes the
                    // Ironwood branch.
                    WalletMigrator::new()
                        .with_seed(Secret::new(seed_bytes.clone()))
                        .ignore_seed_relevance()
                        .init_or_migrate_to(&mut db_data, &[super::MIGRATION_ID])
                        .unwrap();

                    // A minimal account for the note rows to reference. The UFVK/UIVK must be real
                    // encoded values, as `verify_network_compatibility` parses them.
                    let usk = UnifiedSpendingKey::from_seed(
                        &network,
                        &seed_bytes,
                        zip32::AccountId::ZERO,
                    )
                    .unwrap();
                    let ufvk = usk.to_unified_full_viewing_key();
                    let ufvk_str = ufvk.encode(&network);
                    let uivk_str = ufvk.to_unified_incoming_viewing_key().encode(&network);
                    db_data
                        .conn
                        .execute(
                            "INSERT INTO accounts (id, uuid, account_kind,
                             hd_seed_fingerprint, hd_account_index,
                             ufvk, uivk, has_spend_key, birthday_height)
                             VALUES (1, X'0000000000000000000000000000AAAA', 0,
                             X'00000000000000000000000000000000000000000000000000000000000000AB',
                             0, :ufvk, :uivk, 1, 0)",
                            named_params![":ufvk": ufvk_str, ":uivk": uivk_str],
                        )
                        .unwrap();

                    db_data
                        .conn
                        .execute(
                            "INSERT INTO transactions (id_tx, txid, min_observed_height)
                             VALUES (1, X'00', 1)",
                            [],
                        )
                        .unwrap();

                    // Both notes share `(transaction_id, action_index) = (1, 0)`; they do not
                    // collide because they are stored in separate pool tables.
                    db_data
                        .conn
                        .execute(
                            "INSERT INTO orchard_received_notes (
                                 id, transaction_id, action_index, account_id, diversifier, value,
                                 rho, rseed, nf, is_change, memo, note_version
                             ) VALUES (
                                 1, 1, 0, 1, :diversifier, :value,
                                 :rho, :rseed, X'01', :is_change, :memo, 2
                             )",
                            named_params![
                                ":diversifier": orchard_note.diversifier.as_slice(),
                                ":value": orchard_note.value,
                                ":rho": orchard_note.rho.as_slice(),
                                ":rseed": orchard_note.rseed.as_slice(),
                                ":is_change": orchard_note.is_change,
                                ":memo": orchard_note.memo.as_deref(),
                            ],
                        )
                        .unwrap();

                    db_data
                        .conn
                        .execute(
                            "INSERT INTO ironwood_received_notes (
                                 id, transaction_id, action_index, account_id, diversifier, value,
                                 rho, rseed, nf, is_change, memo, note_version
                             ) VALUES (
                                 1, 1, 0, 1, :diversifier, :value,
                                 :rho, :rseed, X'02', :is_change, :memo, 3
                             )",
                            named_params![
                                ":diversifier": ironwood_note.diversifier.as_slice(),
                                ":value": ironwood_note.value,
                                ":rho": ironwood_note.rho.as_slice(),
                                ":rseed": ironwood_note.rseed.as_slice(),
                                ":is_change": ironwood_note.is_change,
                                ":memo": ironwood_note.memo.as_deref(),
                            ],
                        )
                        .unwrap();

                    // `v_received_outputs` reports exactly the Orchard row (pool 3) and the
                    // Ironwood row (pool 4), each carrying its own value.
                    let rows = db_data
                        .conn
                        .prepare(
                            "SELECT pool, value
                             FROM v_received_outputs
                             WHERE account_id = 1
                             ORDER BY pool",
                        )
                        .unwrap()
                        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();

                    prop_assert_eq!(
                        rows,
                        vec![(3, orchard_note.value), (4, ironwood_note.value)]
                    );

                    Ok(())
                },
            )
            .unwrap();
    }
}
