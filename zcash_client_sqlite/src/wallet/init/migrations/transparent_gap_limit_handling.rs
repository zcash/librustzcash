//! Add support for general transparent gap limit handling, and unify the `addresses` and
//! `ephemeral_addresses` tables.

use rand_core::RngCore;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Mutex;
use uuid::Uuid;

use rusqlite::{named_params, Transaction};
use schemerz_rusqlite::RusqliteMigration;

use zcash_address::ZcashAddress;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_protocol::consensus::{self, BlockHeight};

use super::add_account_uuids;
use crate::{
    util::Clock,
    wallet::{self, encoding::ReceiverFlags, init::WalletMigrationError, KeyScope},
    AccountRef,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        wallet::{
            encoding::{decode_diversifier_index_be, encode_diversifier_index_be, epoch_seconds},
            transparent::{find_gap_start, generate_address_range_internal, next_check_time},
        },
        GapLimits,
    },
    ::transparent::keys::{IncomingViewingKey as _, NonHardenedChildIndex},
    zcash_keys::{encoding::AddressCodec as _, keys::ReceiverRequirement},
    zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA,
    zip32::DiversifierIndex,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xc41dfc0e_e870_4859_be47_d2f572f5ca73);

const DEPENDENCIES: &[Uuid] = &[add_account_uuids::MIGRATION_ID];

pub(super) struct Migration<P, C, R> {
    pub(super) params: P,
    pub(super) _clock: C,
    pub(super) _rng: Rc<Mutex<R>>,
}

impl<P, C, R> schemerz::Migration<Uuid> for Migration<P, C, R> {
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

fn decode_uivk<P: consensus::Parameters>(
    params: &P,
    uivk_str: String,
) -> Result<UnifiedIncomingViewingKey, WalletMigrationError> {
    UnifiedIncomingViewingKey::decode(params, &uivk_str).map_err(|e| {
        WalletMigrationError::CorruptedData(format!("Invalid UIVK encoding {uivk_str}: {e}"))
    })
}

fn decode_ufvk<P: consensus::Parameters>(
    params: &P,
    ufvk_str: Option<String>,
) -> Result<Option<UnifiedFullViewingKey>, WalletMigrationError> {
    ufvk_str
        .map(|ufvk_str| {
            UnifiedFullViewingKey::decode(params, &ufvk_str).map_err(|e| {
                WalletMigrationError::CorruptedData(format!(
                    "Invalid UFVK encoding {ufvk_str}: {e}"
                ))
            })
        })
        .transpose()
}

// For each account, ensure that all diversifier indexes prior to that for the default
// address have corresponding cached transparent addresses.
#[cfg(feature = "transparent-inputs")]
pub(super) fn insert_initial_transparent_addrs<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
) -> Result<(), WalletMigrationError> {
    let mut min_addr_diversifiers = conn.prepare(
        r#"
        SELECT accounts.id AS account_id,
               accounts.uivk,
               accounts.ufvk,
               MIN(addresses.transparent_child_index) AS transparent_child_index,
               MIN(addresses.diversifier_index_be) AS diversifier_index_be
        FROM accounts
        LEFT OUTER JOIN addresses
            ON accounts.id = addresses.account_id
            AND addresses.key_scope = :key_scope_external
        GROUP BY accounts.id
        "#,
    )?;

    let mut min_addr_rows = min_addr_diversifiers.query(named_params![
        ":key_scope_external": KeyScope::EXTERNAL.encode()
    ])?;
    while let Some(row) = min_addr_rows.next()? {
        let account_id = AccountRef(row.get("account_id")?);
        let uivk = decode_uivk(params, row.get("uivk")?)?;
        let ufvk = decode_ufvk(params, row.get::<_, Option<String>>("ufvk")?)?;

        let min_transparent_idx = row
            .get::<_, Option<u32>>("transparent_child_index")?
            .map(|i| {
                NonHardenedChildIndex::from_index(i).ok_or(WalletMigrationError::CorruptedData(
                    format!("{i} is not a valid transparent child index."),
                ))
            })
            .transpose()?;

        let min_diversifier_idx = row
            .get::<_, Option<Vec<u8>>>("diversifier_index_be")?
            .map(|b| decode_diversifier_index_be(&b[..]))
            .transpose()?
            .and_then(|di| NonHardenedChildIndex::try_from(di).ok());

        // Ensure that there is an address for each possible external address index prior to the
        // default UA for the account. If the default address has a diversifier index greater than
        // the gap limit, we generate transparent addresses up to that index but not beyond.
        let start = NonHardenedChildIndex::const_from_index(0);
        let end = std::cmp::min(
            min_transparent_idx
                .or(min_diversifier_idx)
                // guarantee that we have an entry at index 0; this address will have previously
                // been provided explicitly as one of the wallet's addresses in response to a call
                // to `get_transparent_receivers, even if we have no other addresses generated
                // (which shouldn't ordinarily be the case anyway)
                .unwrap_or(NonHardenedChildIndex::const_from_index(1)),
            NonHardenedChildIndex::from_index(GapLimits::default().external())
                .expect("default external gap limit fits in non-hardened child index space."),
        );

        generate_address_range_internal(
            conn,
            params,
            account_id,
            &uivk,
            ufvk.as_ref(),
            KeyScope::EXTERNAL,
            UnifiedAddressRequest::ALLOW_ALL,
            start..end,
            false,
        )?;
    }

    Ok(())
}

impl<P: consensus::Parameters, C: Clock, R: RngCore> RusqliteMigration for Migration<P, C, R> {
    type Error = WalletMigrationError;

    fn up(&self, conn: &Transaction) -> Result<(), WalletMigrationError> {
        let external_scope_code = KeyScope::EXTERNAL.encode();

        conn.execute_batch(&format!(
            r#"
            ALTER TABLE addresses ADD COLUMN key_scope INTEGER NOT NULL DEFAULT {external_scope_code};
            ALTER TABLE addresses ADD COLUMN transparent_child_index INTEGER;
            ALTER TABLE addresses ADD COLUMN exposed_at_height INTEGER;
            ALTER TABLE addresses ADD COLUMN receiver_flags INTEGER;
            "#
        ))?;

        let mut account_ids = HashMap::new();

        {
            // If the diversifier index is in the valid range of non-hardened child indices, set
            // `transparent_child_index` so that we can use it for gap limit handling.
            // No `DISTINCT` is necessary here due to the preexisting UNIQUE(account_id,
            // diversifier_index_be) constraint.
            let mut di_query = conn.prepare(
                r#"
                SELECT
                    account_id,
                    address,
                    accounts.uivk AS uivk,
                    accounts.ufvk AS ufvk,
                    diversifier_index_be,
                    accounts.birthday_height
                FROM addresses
                JOIN accounts ON accounts.id = account_id
                "#,
            )?;
            let mut rows = di_query.query([])?;
            while let Some(row) = rows.next()? {
                let account_id = AccountRef(row.get("account_id")?);
                let uivk = decode_uivk(&self.params, row.get("uivk")?)?;
                let ufvk = decode_ufvk(&self.params, row.get("ufvk")?)?;
                account_ids.insert(account_id, (uivk.clone(), ufvk));

                let addr_str: String = row.get("address")?;
                let address = ZcashAddress::try_from_encoded(&addr_str).map_err(|e| {
                    WalletMigrationError::CorruptedData(format!(
                        "Encoded address {addr_str} is not a valid zcash address: {e}"
                    ))
                })?;
                let receiver_flags = address.convert::<ReceiverFlags>().map_err(|_| {
                    WalletMigrationError::CorruptedData("Unexpected address type".to_string())
                })?;
                let di_be: Vec<u8> = row.get("diversifier_index_be")?;
                let account_birthday: i64 = row.get("birthday_height")?;

                let update_without_taddr = || {
                    conn.execute(
                        r#"
                        UPDATE addresses
                        SET exposed_at_height = :account_birthday,
                            receiver_flags = :receiver_flags
                        WHERE account_id = :account_id
                        AND diversifier_index_be = :diversifier_index_be
                        "#,
                        named_params! {
                            ":account_id": account_id.0,
                            ":diversifier_index_be": &di_be[..],
                            ":account_birthday": account_birthday,
                            ":receiver_flags": receiver_flags.bits(),
                        },
                    )
                };

                #[cfg(feature = "transparent-inputs")]
                {
                    let diversifier_index = decode_diversifier_index_be(&di_be)?;
                    let transparent_external = NonHardenedChildIndex::try_from(diversifier_index)
                        .ok()
                        .and_then(|idx| {
                            uivk.transparent()
                                .as_ref()
                                .and_then(|external_ivk| external_ivk.derive_address(idx).ok())
                                .map(|t_addr| (idx, t_addr.encode(&self.params)))
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
                                cached_transparent_receiver_address = :t_addr,
                                exposed_at_height = :account_birthday,
                                receiver_flags = :receiver_flags
                            WHERE account_id = :account_id
                            AND diversifier_index_be = :diversifier_index_be
                            "#,
                            named_params! {
                                ":account_id": account_id.0,
                                ":diversifier_index_be": &di_be[..],
                                ":transparent_child_index": idx.index(),
                                ":t_addr": t_addr,
                                ":account_birthday": account_birthday,
                                ":receiver_flags": receiver_flags.bits(),
                            },
                        )?;
                    } else {
                        update_without_taddr()?;
                    }
                }

                #[cfg(not(feature = "transparent-inputs"))]
                {
                    update_without_taddr()?;
                }
            }
        };

        // We now have to re-create the `addresses` table in order to fix the constraints. Note
        // that we do not include the `seen_in_tx` column as this is duplicative of information
        // that can be discovered via joins with the various `*_received_{notes|outputs}` tables,
        // which we will create a view to perform below. The `used_in_tx` column data is used only
        // to determine the height at which the address was exposed (for which we use the target
        // height for the transaction.)
        conn.execute_batch(r#"
            CREATE TABLE addresses_new (
                id INTEGER NOT NULL PRIMARY KEY,
                account_id INTEGER NOT NULL,
                key_scope INTEGER NOT NULL,
                diversifier_index_be BLOB NOT NULL,
                address TEXT NOT NULL,
                transparent_child_index INTEGER,
                cached_transparent_receiver_address TEXT,
                exposed_at_height INTEGER,
                receiver_flags INTEGER NOT NULL,
                transparent_receiver_next_check_time INTEGER,
                FOREIGN KEY (account_id) REFERENCES accounts(id),
                CONSTRAINT diversification UNIQUE (account_id, key_scope, diversifier_index_be),
                CONSTRAINT transparent_index_consistency CHECK (
                    (transparent_child_index IS NOT NULL) == (cached_transparent_receiver_address IS NOT NULL)
                )
            );

            -- we will only set `transparent_receiver_next_check_time` for ephemeral addresses
            INSERT INTO addresses_new (
                account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address,
                exposed_at_height, receiver_flags
            )
            SELECT
                account_id, key_scope, diversifier_index_be, address,
                transparent_child_index, cached_transparent_receiver_address,
                exposed_at_height, receiver_flags
            FROM addresses;
            "#)?;

        // Now, we add the ephemeral addresses to the newly unified `addresses` table.
        #[cfg(feature = "transparent-inputs")]
        {
            let mut ea_insert = conn.prepare(
                r#"
                INSERT INTO addresses_new (
                    account_id, key_scope, diversifier_index_be, address,
                    transparent_child_index, cached_transparent_receiver_address,
                    exposed_at_height, receiver_flags,
                    transparent_receiver_next_check_time
                ) VALUES (
                    :account_id, :key_scope, :diversifier_index_be, :address,
                    :transparent_child_index, :cached_transparent_receiver_address,
                    :exposed_at_height, :receiver_flags,
                    :transparent_receiver_next_check_time
                )
                "#,
            )?;

            let mut ea_query = conn.prepare(
                r#"
                SELECT
                    account_id, accounts.uivk, accounts.ufvk, address_index, address,
                    t.expiry_height - :expiry_delta AS exposed_at_height
                FROM ephemeral_addresses ea
                JOIN accounts ON accounts.id = account_id
                LEFT OUTER JOIN transactions t ON t.id_tx = ea.used_in_tx
                "#,
            )?;
            let rows = ea_query
                .query_and_then(
                    named_params! {":expiry_delta": DEFAULT_TX_EXPIRY_DELTA },
                    |row| {
                        let account_id = AccountRef(row.get("account_id")?);
                        let uivk = decode_uivk(&self.params, row.get("uivk")?)?;
                        let ufvk = decode_ufvk(&self.params, row.get("ufvk")?)?;
                        let transparent_child_index = row.get::<_, i64>("address_index")?;
                        let diversifier_index = DiversifierIndex::from(
                            u32::try_from(transparent_child_index)
                                .ok()
                                .and_then(NonHardenedChildIndex::from_index)
                                .ok_or(WalletMigrationError::CorruptedData(
                                    "ephemeral address indices must be in the range of `u31`"
                                        .to_owned(),
                                ))?
                                .index(),
                        );
                        let address: String = row.get("address")?;
                        let exposed_at_height: Option<i64> = row.get("exposed_at_height")?;
                        Ok((
                            account_id,
                            uivk,
                            ufvk,
                            diversifier_index,
                            transparent_child_index,
                            address,
                            exposed_at_height,
                        ))
                    },
                )?
                .collect::<Result<Vec<_>, WalletMigrationError>>()?;

            let ephemeral_address_count =
                u32::try_from(rows.len()).expect("number of ephemeral addrs fits into u32");
            let mut check_time = self._clock.now();
            for (
                account_id,
                uivk,
                ufvk,
                diversifier_index,
                transparent_child_index,
                address,
                exposed_at_height,
            ) in rows
            {
                // Compute a next check time for the address such that, when considered in the
                // context of all other allocated ephemeral addresses, it will be checked once per
                // day.
                let next_check_time = {
                    let rng = self
                        ._rng
                        .lock()
                        .expect("can obtain write lock to shared rng");

                    next_check_time(rng, check_time, (24 * 60 * 60) / ephemeral_address_count)
                        .expect("computed next check time is valid")
                };
                let next_check_epoch_seconds = epoch_seconds(next_check_time).unwrap();

                // We set both the `address` column and the `cached_transparent_receiver_address`
                // column to the same value here; there is no Unified address that corresponds to
                // this transparent address.
                ea_insert.execute(named_params! {
                    ":account_id": account_id.0,
                    ":key_scope": KeyScope::Ephemeral.encode(),
                    ":diversifier_index_be": encode_diversifier_index_be(diversifier_index),
                    ":address": address,
                    ":transparent_child_index": transparent_child_index,
                    ":cached_transparent_receiver_address": address,
                    ":exposed_at_height": exposed_at_height,
                    ":receiver_flags": ReceiverFlags::P2PKH.bits(),
                    ":transparent_receiver_next_check_time": next_check_epoch_seconds
                })?;

                account_ids.insert(account_id, (uivk, ufvk));
                check_time = next_check_time;
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

        #[cfg(feature = "transparent-inputs")]
        insert_initial_transparent_addrs(conn, &self.params)?;

        // Add foreign key references from the *_received_{notes|outputs} tables to the addresses
        // table to make it possible to identify which address was involved. These foreign key
        // columns must be nullable as for shielded account-internal. Ideally the foreign key
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

                    let uivk = decode_uivk(&self.params, row.get("uivk")?)?;
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
                    let ua = uivk.address(di, UnifiedAddressRequest::ALLOW_ALL)?;
                    let address_id = wallet::upsert_address(
                        conn,
                        &self.params,
                        account_id,
                        di,
                        &ua,
                        mined_height,
                        false,
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

                    let uivk = decode_uivk(&self.params, row.get("uivk")?)?;
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
                    let ua = uivk.address(di, UnifiedAddressRequest::ALLOW_ALL)?;
                    let address_id = wallet::upsert_address(
                        conn,
                        &self.params,
                        account_id,
                        di,
                        &ua,
                        mined_height,
                        false,
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
            conn.execute_batch(
                r#"
                PRAGMA legacy_alter_table = ON;

                UPDATE transparent_received_outputs
                SET address_id = addresses.id
                FROM addresses
                WHERE addresses.cached_transparent_receiver_address = transparent_received_outputs.address;

                CREATE TABLE transparent_received_outputs_new (
                    id INTEGER PRIMARY KEY,
                    transaction_id INTEGER NOT NULL,
                    output_index INTEGER NOT NULL,
                    account_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    script BLOB NOT NULL,
                    value_zat INTEGER NOT NULL,
                    max_observed_unspent_height INTEGER,
                    address_id INTEGER NOT NULL REFERENCES addresses(id),
                    FOREIGN KEY (transaction_id) REFERENCES transactions(id_tx),
                    FOREIGN KEY (account_id) REFERENCES accounts(id),
                    CONSTRAINT transparent_output_unique UNIQUE (transaction_id, output_index)
                );
                INSERT INTO transparent_received_outputs_new SELECT * FROM transparent_received_outputs;

                DROP TABLE transparent_received_outputs;
                ALTER TABLE transparent_received_outputs_new RENAME TO transparent_received_outputs;

                PRAGMA legacy_alter_table = OFF;
                "#,
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

        // At this point, we have completed updating the infrastructure for gap limit handling,
        // so we can regenerate the gap limit worth of addresses for each account that we
        // recorded. The body of this method duplicates thje logic in `generate_gap_addresses`
        // in order to avoid the `get_account_internal` call, since we already have the internal
        // account id in each iteration of the loop.
        #[cfg(feature = "transparent-inputs")]
        for (account_id, (uivk, ufvk)) in account_ids {
            for key_scope in [KeyScope::EXTERNAL, KeyScope::INTERNAL] {
                use ReceiverRequirement::*;
                let gap_limit = match key_scope {
                    KeyScope::Zip32(zip32::Scope::External) => GapLimits::default().external(),
                    KeyScope::Zip32(zip32::Scope::Internal) => GapLimits::default().internal(),
                    KeyScope::Ephemeral => {
                        unreachable!("Ephemeral keys are omitted by the enclosing context.")
                    }
                };

                if let Some(gap_start) = find_gap_start(conn, account_id, key_scope, gap_limit)? {
                    generate_address_range_internal(
                        conn,
                        &self.params,
                        account_id,
                        &uivk,
                        ufvk.as_ref(),
                        key_scope,
                        UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
                        gap_start..gap_start.saturating_add(gap_limit),
                        false,
                    )?;
                }
            }
        }

        Ok(())
    }

    fn down(&self, _: &Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}
