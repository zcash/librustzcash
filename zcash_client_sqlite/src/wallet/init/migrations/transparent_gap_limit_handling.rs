//! Add support for general transparent gap limit handling, and unify the `addresses` and
//! `ephemeral_addresses` tables.

use std::collections::HashSet;
use uuid::Uuid;

use rusqlite::{named_params, Transaction};
use schemerz_rusqlite::RusqliteMigration;

use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_protocol::consensus::{self, BlockHeight};

use super::add_account_uuids;
use crate::{
    wallet::{self, init::WalletMigrationError, KeyScope},
    AccountRef,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::{decode_diversifier_index_be, encode_diversifier_index_be},
    ::transparent::keys::{IncomingViewingKey as _, NonHardenedChildIndex},
    zcash_keys::encoding::AddressCodec as _,
    zip32::DiversifierIndex,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xc41dfc0e_e870_4859_be47_d2f572f5ca73);

const DEPENDENCIES: &[Uuid] = &[add_account_uuids::MIGRATION_ID];

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
        "Add support for general transparent gap limit handling, unifying the `addresses` and `ephemeral_addresses` tables."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, conn: &Transaction) -> Result<(), WalletMigrationError> {
        let decode_uivk = |uivk_str: String| {
            UnifiedIncomingViewingKey::decode(&self.params, &uivk_str).map_err(|e| {
                WalletMigrationError::CorruptedData(format!(
                    "Invalid UIVK encoding {}: {}",
                    uivk_str, e
                ))
            })
        };

        let external_scope_code = KeyScope::EXTERNAL.encode();

        conn.execute_batch(&format!(
            r#"
            ALTER TABLE addresses ADD COLUMN key_scope INTEGER NOT NULL DEFAULT {external_scope_code};
            ALTER TABLE addresses ADD COLUMN transparent_child_index INTEGER;
            "#
        ))?;

        #[cfg(feature = "transparent-inputs")]
        {
            // If the diversifier index is in the valid range of non-hardened child indices, set
            // `transparent_child_index` so that we can use it for gap limit handling.
            // No `DISTINCT` is necessary here due to the preexisting UNIQUE(account_id,
            // diversifier_index_be) constraint.
            let mut di_query = conn.prepare(
                r#"
                SELECT account_id, accounts.uivk AS uivk, diversifier_index_be
                FROM addresses
                JOIN accounts ON accounts.id = account_id
                "#,
            )?;
            let mut rows = di_query.query([])?;
            while let Some(row) = rows.next()? {
                let account_id: i64 = row.get("account_id")?;
                let uivk = decode_uivk(row.get("uivk")?)?;
                let di_be: Vec<u8> = row.get("diversifier_index_be")?;
                let diversifier_index = decode_diversifier_index_be(&di_be)?;

                let transparent_external = NonHardenedChildIndex::try_from(diversifier_index)
                    .ok()
                    .and_then(|idx| {
                        uivk.transparent()
                            .as_ref()
                            .and_then(|external_ivk| external_ivk.derive_address(idx).ok())
                            .map(|t_addr| (idx, t_addr))
                    });

                // Add transparent address index metadata and the transparent address corresponding
                // to the index to the addresses table. We unconditionally set the cached
                // transparent receiver address in order to simplify gap limit handling; even if a
                // unified address is generated without a transparent receiver, we still assume
                // that a transparent-only wallet for which we have imported the seed may have
                // generated an address at that index.
                if let Some((idx, t_addr)) = transparent_external {
                    conn.execute(
                        r#"
                        UPDATE addresses
                        SET transparent_child_index = :transparent_child_index,
                            cached_transparent_receiver_address = :t_addr
                        WHERE account_id = :account_id
                        AND diversifier_index_be = :diversifier_index_be
                        AND key_scope = :external_scope_code
                        "#,
                        named_params! {
                            ":account_id": account_id,
                            ":diversifier_index_be": &di_be[..],
                            ":external_scope_code": external_scope_code,
                            ":transparent_child_index": idx.index(),
                            ":t_addr": t_addr.encode(&self.params),
                        },
                    )?;
                }
            }
        }

        // We now have to re-create the `addresses` table in order to fix the constraints.
        // Note that we do not include `used_in_tx` or `seen_in_tx` columns as these are
        // duplicative of information that can be discovered via joins with the various
        // `*_received_{notes|outputs}` tables, which we will create a view to perform below.
        conn.execute_batch(&format!(
            r#"
            CREATE TABLE addresses_new (
                id INTEGER NOT NULL PRIMARY KEY,
                account_id INTEGER NOT NULL,
                key_scope INTEGER NOT NULL DEFAULT {external_scope_code},
                diversifier_index_be BLOB NOT NULL,
                address TEXT NOT NULL,
                transparent_child_index INTEGER,
                cached_transparent_receiver_address TEXT,
                exposed_at_height INTEGER,
                FOREIGN KEY (account_id) REFERENCES accounts(id),
                CONSTRAINT diversification UNIQUE (account_id, key_scope, diversifier_index_be),
                CONSTRAINT transparent_index_consistency CHECK (
                    (transparent_child_index IS NOT NULL) == (cached_transparent_receiver_address IS NOT NULL)
                )
            );

            INSERT INTO addresses_new (
                account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address
            )
            SELECT
                account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address
            FROM addresses;
            "#
        ))?;

        // Now, we add the ephemeral addresses to the newly unified `addresses` table.
        #[cfg(feature = "transparent-inputs")]
        {
            let mut ea_insert = conn.prepare(
                r#"
                INSERT INTO addresses_new (
                    account_id, key_scope, diversifier_index_be, address,
                    transparent_child_index, cached_transparent_receiver_address
                ) VALUES (
                    :account_id, :key_scope, :diversifier_index_be, :address,
                    :transparent_child_index, :cached_transparent_receiver_address
                )
                "#,
            )?;

            let mut ea_query = conn.prepare(
                r#"
                SELECT account_id, address_index, address
                FROM ephemeral_addresses
                "#,
            )?;
            let mut rows = ea_query.query([])?;
            while let Some(row) = rows.next()? {
                let account_id: i64 = row.get("account_id")?;
                let transparent_child_index = row.get::<_, i64>("address_index")?;
                let diversifier_index = DiversifierIndex::from(
                    u32::try_from(transparent_child_index).map_err(|_| {
                        WalletMigrationError::CorruptedData(
                            "ephermeral address indices must be in the range of `u32`".to_owned(),
                        )
                    })?,
                );
                let address: String = row.get("address")?;

                // We set both the `address` column and the `cached_transparent_receiver_address`
                // column to the same value here; there is no Unified address that corresponds to
                // this transparent address.
                ea_insert.execute(named_params! {
                    ":account_id": account_id,
                    ":key_scope": KeyScope::Ephemeral.encode(),
                    ":diversifier_index_be": encode_diversifier_index_be(diversifier_index),
                    ":address": address,
                    ":transparent_child_index": transparent_child_index,
                    ":cached_transparent_receiver_address": address
                })?;
            }
        }

        conn.execute_batch(
            r#"
            PRAGMA legacy_alter_table = ON;

            DROP TABLE addresses;
            ALTER TABLE addresses_new RENAME TO addresses;
            CREATE INDEX idx_addresses_accounts ON addresses (
                account_id ASC
            );
            CREATE INDEX idx_addresses_indices ON addresses (
                diversifier_index_be ASC
            );
            CREATE INDEX idx_addresses_t_indices ON addresses (
                transparent_child_index ASC
            );

            DROP TABLE ephemeral_addresses;

            PRAGMA legacy_alter_table = OFF;
            "#,
        )?;

        // Add foreign key references from the *_received_{notes|outputs} tables to the addresses
        // table to make it possible to identify which address was involved. These foreign key
        // columns  must be nullable as for shielded account-internal. Ideally the foreign key
        // relationship between `transparent_received_outputs` and `addresses` would not be
        // nullable, but we allow it to be so here in order to avoid having to re-create that
        // table.
        //
        // While it would be possible to only add the address reference to
        // `transparent_received_outputs`, that would mean that a note received at a shielded
        // component of a diversified Unified Address would not update the position of the
        // transparent "address gap". Since we will include shielded address indices in the gap
        // computation, transparent-only wallets may not be able to discover all transparent funds,
        // but users of shielded wallets will be guaranteed to be able to recover all of their
        // funds.
        conn.execute_batch(
            r#"
            ALTER TABLE orchard_received_notes
                ADD COLUMN address_id INTEGER REFERENCES addresses(id);
            ALTER TABLE sapling_received_notes
                ADD COLUMN address_id INTEGER REFERENCES addresses(id);
            ALTER TABLE transparent_received_outputs
                ADD COLUMN address_id INTEGER REFERENCES addresses(id);
            "#,
        )?;

        // Ensure that an address exists for each received Orchard note, and populate the
        // `address_id` column.
        #[cfg(feature = "orchard")]
        {
            let mut stmt_rn_diversifiers = conn.prepare(
                r#"
                SELECT orn.id, orn.account_id, accounts.uivk,
                       orn.recipient_key_scope, orn.diversifier, t.mined_height
                FROM orchard_received_notes orn
                JOIN accounts ON accounts.id = account_id
                JOIN transactions t on t.id_tx = orn.tx
                "#,
            )?;

            let mut rows = stmt_rn_diversifiers.query([])?;
            while let Some(row) = rows.next()? {
                let scope = KeyScope::decode(row.get("recipient_key_scope")?)?;
                // for Orchard and Sapling, we only store addresses for externally-scoped keys.
                if scope == KeyScope::EXTERNAL {
                    let row_id: i64 = row.get("id")?;
                    let account_id = AccountRef(row.get("account_id")?);
                    let mined_height = row
                        .get::<_, Option<u32>>("mined_height")?
                        .map(BlockHeight::from);

                    let uivk = decode_uivk(row.get("uivk")?)?;
                    let diversifier =
                        orchard::keys::Diversifier::from_bytes(row.get("diversifier")?);

                    // TODO: It's annoying that `IncomingViewingKey` doesn't expose the ability to
                    // decrypt the diversifier to find the index directly, and doesn't provide an
                    // accessor for `dk`. We already know we have the right IVK.
                    let ivk = uivk
                        .orchard()
                        .as_ref()
                        .expect("previously received an Orchard output");
                    let di = ivk
                        .diversifier_index(&ivk.address(diversifier))
                        .expect("roundtrip");
                    let ua = uivk.address(di, None)?;
                    let address_id = wallet::upsert_address(
                        conn,
                        &self.params,
                        account_id,
                        di,
                        &ua,
                        mined_height,
                    )?;

                    conn.execute(
                        "UPDATE orchard_received_notes
                         SET address_id = :address_id
                         WHERE id = :row_id",
                        named_params! {
                            ":address_id": address_id.0,
                            ":row_id": row_id
                        },
                    )?;
                }
            }
        }

        // Ensure that an address exists for each received Sapling note, and populate the
        // `address_id` column.
        {
            let mut stmt_rn_diversifiers = conn.prepare(
                r#"
                SELECT srn.id, srn.account_id, accounts.uivk,
                       srn.recipient_key_scope, srn.diversifier, t.mined_height
                FROM sapling_received_notes srn
                JOIN accounts ON accounts.id = account_id
                JOIN transactions t ON t.id_tx = srn.tx
                "#,
            )?;

            let mut rows = stmt_rn_diversifiers.query([])?;
            while let Some(row) = rows.next()? {
                let scope = KeyScope::decode(row.get("recipient_key_scope")?)?;
                // for Orchard and Sapling, we only store addresses for externally-scoped keys.
                if scope == KeyScope::EXTERNAL {
                    let row_id: i64 = row.get("id")?;
                    let account_id = AccountRef(row.get("account_id")?);
                    let mined_height = row
                        .get::<_, Option<u32>>("mined_height")?
                        .map(BlockHeight::from);

                    let uivk = decode_uivk(row.get("uivk")?)?;
                    let diversifier = sapling::Diversifier(row.get("diversifier")?);

                    // TODO: It's annoying that `IncomingViewingKey` doesn't expose the ability to
                    // decrypt the diversifier to find the index directly, and doesn't provide an
                    // accessor for `dk`. We already know we have the right IVK.
                    let ivk = uivk
                        .sapling()
                        .as_ref()
                        .expect("previously received a Sapling output");
                    let di = ivk
                        .decrypt_diversifier(
                            &ivk.address(diversifier)
                                .expect("previously generated an address"),
                        )
                        .expect("roundtrip");
                    let ua = uivk.address(di, None)?;
                    let address_id = wallet::upsert_address(
                        conn,
                        &self.params,
                        account_id,
                        di,
                        &ua,
                        mined_height,
                    )?;

                    conn.execute(
                        "UPDATE sapling_received_notes
                         SET address_id = :address_id
                         WHERE id = :row_id",
                        named_params! {
                            ":address_id": address_id.0,
                            ":row_id": row_id
                        },
                    )?;
                }
            }
        }

        // At this point, every address on which we've received a transparent output should have a
        // corresponding row in the `addresses` table with a valid
        // `cached_transparent_receiver_address` entry, because we will only have queried the light
        // wallet server for outputs from exactly these addresses. So for transparent outputs, we
        // join to the addresses table using the address itself in order to obtain the address index.
        #[cfg(feature = "transparent-inputs")]
        {
            conn.execute(
                r#"
                UPDATE transparent_received_outputs
                SET address_id = addresses.id
                FROM addresses
                WHERE addresses.cached_transparent_receiver_address = transparent_received_outputs.address
                "#,
                []
            )?;
        }

        // Construct a view that identifies the minimum block height at which each address was
        // first used
        conn.execute_batch(
            r#"
            CREATE VIEW v_address_uses AS
                SELECT orn.address_id, orn.account_id, orn.tx AS transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM orchard_received_notes orn
                JOIN addresses a ON a.id = orn.address_id
                JOIN transactions t ON t.id_tx = orn.tx
            UNION
                SELECT srn.address_id, srn.account_id, srn.tx AS transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM sapling_received_notes srn
                JOIN addresses a ON a.id = srn.address_id
                JOIN transactions t ON t.id_tx = srn.tx
            UNION
                SELECT tro.address_id, tro.account_id, tro.transaction_id, t.mined_height,
                       a.key_scope, a.diversifier_index_be, a.transparent_child_index
                FROM transparent_received_outputs tro
                JOIN addresses a ON a.id = tro.address_id
                JOIN transactions t ON t.id_tx = tro.transaction_id;

            CREATE VIEW v_address_first_use AS
            SELECT
                address_id,
                account_id,
                key_scope,
                diversifier_index_be,
                transparent_child_index,
                MIN(mined_height) AS first_use_height
            FROM v_address_uses
            GROUP BY
                address_id, account_id, key_scope,
                diversifier_index_be, transparent_child_index;

            DROP VIEW v_received_outputs;
            CREATE VIEW v_received_outputs AS
                SELECT
                    sapling_received_notes.id AS id_within_pool_table,
                    sapling_received_notes.tx AS transaction_id,
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
                ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                   (sapling_received_notes.tx, 2, sapling_received_notes.output_index)
            UNION
                SELECT
                    orchard_received_notes.id AS id_within_pool_table,
                    orchard_received_notes.tx AS transaction_id,
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
                ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                   (orchard_received_notes.tx, 3, orchard_received_notes.action_index)
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
                ON (sent_notes.tx, sent_notes.output_pool, sent_notes.output_index) =
                   (u.transaction_id, 0, u.output_index);
            "#,
        )?;

        Ok(())
    }

    fn down(&self, _: &Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}