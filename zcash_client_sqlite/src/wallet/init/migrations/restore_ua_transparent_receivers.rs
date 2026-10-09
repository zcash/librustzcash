//! Restores the transparent receiver to stored unified addresses that omit it.
//!
//! In `zcash_client_sqlite` 0.23.0-pre.1, the generation of addresses to fill the transparent
//! gap limit stored each unified address without its transparent receiver. The row's
//! `cached_transparent_receiver_address` still holds that receiver. This migration adds the
//! cached receiver back to each such address that was never exposed, and sets the row's
//! receiver flags to match.
//!
//! A row can also hold a shielded-only unified address next to a cached transparent receiver
//! on purpose: the wallet caches the receiver at every index in the transparent range, and
//! an address requested without a transparent receiver keeps that cache. Such an address is
//! always exposed when it is stored, because the wallet stores it to hand it out. An
//! unexposed row of this form is therefore always one that the defect wrote, and the
//! migration does not change exposed rows. `list_addresses` reports the cached receiver of
//! an exposed row separately. A rerun of the migration finds no rows to change.

use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use transparent::address::TransparentAddress;
use uuid::Uuid;
use zcash_address::{
    ToAddress, ZcashAddress,
    unified::{self, Container, Encoding, ParseError, Revision, Uitem},
};
use zcash_keys::{address::UnifiedAddress, encoding::AddressCodec};
use zcash_protocol::consensus;

use super::standalone_address;
use crate::wallet::{
    encoding::{KeyScope, ReceiverFlags},
    init::WalletMigrationError,
};

/// Identifies this migration in the wallet's schema-migration DAG.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x3eb2409c_6b54_476e_aebc_8f769aa8950f);

/// `standalone_address` created the current form of the `addresses` table.
pub(super) const DEPENDENCIES: &[Uuid] = &[standalone_address::MIGRATION_ID];

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
        "Restores the transparent receiver to stored unified addresses that omit it."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        let mut select_rows = transaction.prepare(
            "SELECT id, address, cached_transparent_receiver_address
             FROM addresses
             WHERE cached_transparent_receiver_address IS NOT NULL
               AND exposed_at_height IS NULL
               AND key_scope != :foreign_scope
             ORDER BY id",
        )?;
        let rows = select_rows
            .query_map(
                named_params![":foreign_scope": KeyScope::Foreign.encode()],
                |row| Ok((row.get::<_, i64>(0)?, row.get(1)?, row.get(2)?)),
            )?
            .collect::<Result<Vec<(i64, String, String)>, _>>()?;

        let mut update_row = transaction.prepare(
            "UPDATE addresses
             SET address = :address, receiver_flags = :receiver_flags
             WHERE id = :id",
        )?;
        for (id, address, cached_taddr) in rows {
            if let Some((restored, receiver_flags)) =
                with_transparent_receiver(&self.params, &address, &cached_taddr)?
            {
                update_row.execute(named_params![
                    ":address": restored,
                    ":receiver_flags": receiver_flags.bits(),
                    ":id": id,
                ])?;
            }
        }

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

/// Returns the encoding of the unified address `address` with the transparent receiver
/// `cached_taddr` added, and the receiver flags of that address, if `address` has no
/// transparent receiver.
///
/// Returns `None` if `address` is not a unified address, or already has a transparent
/// receiver.
fn with_transparent_receiver<P: consensus::Parameters>(
    params: &P,
    address: &str,
    cached_taddr: &str,
) -> Result<Option<(String, ReceiverFlags)>, WalletMigrationError> {
    let corrupt = |reason: String| WalletMigrationError::CorruptedData(reason);

    let (network, _, container) = match unified::Address::decode(address) {
        Ok(decoded) => decoded,
        // The row holds the transparent address itself.
        Err(ParseError::NotUnified) => return Ok(None),
        Err(e) => return Err(corrupt(format!("Invalid unified address {address}: {e}"))),
    };
    if network != params.network_type() {
        return Err(corrupt(format!(
            "Unified address {address} is not for the wallet's network"
        )));
    }

    let mut items = container.items_as_parsed().to_vec();
    let has_transparent = items
        .iter()
        .any(|item| {
            matches!(
                item,
                Uitem::Data(unified::Receiver::P2pkh(_) | unified::Receiver::P2sh(_))
            )
        });
    if has_transparent {
        return Ok(None);
    }

    let receiver = match TransparentAddress::decode(params, cached_taddr)
        .map_err(|e| corrupt(format!("Invalid transparent address {cached_taddr}: {e}")))?
    {
        TransparentAddress::PublicKeyHash(hash) => unified::Receiver::P2pkh(hash),
        TransparentAddress::ScriptHash(hash) => unified::Receiver::P2sh(hash),
    };
    items.push(Uitem::Data(receiver));

    // Revision 2 can represent every unified address.
    let restored = unified::Address::try_from_items(Revision::R2, items)
        .map_err(|e| corrupt(format!("Cannot restore transparent receiver of {address}: {e}")))?;

    // The flags come from the parsed items, so that they cover the receivers that this
    // build holds only as unknown items.
    let receiver_flags = ZcashAddress::from_unified(network, restored.clone())
        .convert::<ReceiverFlags>()
        .map_err(|_| corrupt(format!("Cannot compute receiver flags of {address}")))?;

    // `UnifiedAddress` picks the revision that the wallet uses for new rows.
    let restored = UnifiedAddress::try_from(restored)
        .map_err(|e| corrupt(e.to_string()))?
        .to_zcash_address(network)
        .encode();
    Ok(Some((restored, receiver_flags)))
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaChaRng;
    use rusqlite::named_params;
    use schemerz::MigratorError;
    use secrecy::Secret;
    use tempfile::NamedTempFile;
    use transparent::{address::TransparentAddress, keys::NonHardenedChildIndex};
    use uuid::Uuid;
    use zcash_address::{
        ToAddress, ZcashAddress, test_vectors,
        unified::{self, Encoding, Revision, Uitem},
    };
    use zcash_keys::{encoding::AddressCodec, keys::UnifiedSpendingKey};
    use zcash_protocol::consensus::{Network, NetworkType};
    use zip32::DiversifierIndex;

    use crate::{
        WalletDb,
        testing::db::{test_clock, test_rng},
        util::testing::FixedClock,
        wallet::{
            encoding::{KeyScope, ReceiverFlags, encode_diversifier_index_be},
            init::{WalletMigrationError, WalletMigrator, migrations::tests::test_migrate},
        },
    };

    use super::{DEPENDENCIES, MIGRATION_ID};

    #[cfg(feature = "transparent-inputs")]
    use {
        assert_matches::assert_matches,
        zcash_address::unified::Typecode,
        zcash_keys::{
            address::UnifiedAddress,
            keys::{ReceiverRequirement::*, UnifiedAddressRequest, UnifiedFullViewingKey},
        },
        zcash_protocol::consensus::Parameters,
    };

    const NETWORK: Network = Network::TestNetwork;
    /// The seed of the wallet's only account.
    const SEED: [u8; 32] = [0xab; 32];
    /// The child index of an address row that stores a test-vector address.
    const VECTOR_CHILD_INDEX: u32 = 2;
    /// A cached transparent receiver that does not decode as a transparent address.
    #[cfg(feature = "transparent-inputs")]
    const INVALID_TADDR: &str = "not a transparent address";
    /// The height at which an exposed row in these tests was exposed.
    #[cfg(feature = "transparent-inputs")]
    const EXPOSURE_HEIGHT: u32 = 1;

    type TestDb = WalletDb<rusqlite::Connection, Network, FixedClock, ChaChaRng>;

    /// A wallet database at the state just before this migration, with one account.
    struct Fixture {
        _data_file: NamedTempFile,
        db_data: TestDb,
        #[cfg(feature = "transparent-inputs")]
        ufvk: UnifiedFullViewingKey,
        account_id: i64,
    }

    impl Fixture {
        fn new() -> Self {
            let data_file = NamedTempFile::new().unwrap();
            let mut db_data =
                WalletDb::for_path(data_file.path(), NETWORK, test_clock(), test_rng()).unwrap();
            WalletMigrator::new()
                .with_seed(Secret::new(SEED.to_vec()))
                .ignore_seed_relevance()
                .init_or_migrate_to(&mut db_data, DEPENDENCIES)
                .unwrap();

            let ufvk = UnifiedSpendingKey::from_seed(&NETWORK, &SEED, zip32::AccountId::ZERO)
                .unwrap()
                .to_unified_full_viewing_key();
            db_data
                .conn
                .execute(
                    "INSERT INTO accounts (uuid, account_kind, hd_seed_fingerprint,
                     hd_account_index, ufvk, uivk, has_spend_key, birthday_height)
                     VALUES (X'0000000000000000000000000000AAAA', 0,
                     X'00000000000000000000000000000000000000000000000000000000000000AB',
                     0, :ufvk, :uivk, 1, 1)",
                    named_params![
                        ":ufvk": ufvk.encode(&NETWORK).unwrap(),
                        ":uivk": ufvk.to_unified_incoming_viewing_key().encode(&NETWORK).unwrap(),
                    ],
                )
                .unwrap();
            let account_id = db_data
                .conn
                .query_row("SELECT id FROM accounts", [], |row| row.get(0))
                .unwrap();

            Fixture {
                _data_file: data_file,
                db_data,
                #[cfg(feature = "transparent-inputs")]
                ufvk,
                account_id,
            }
        }

        /// Stores `address` as the external-scope row at `child_index`, with `cached_taddr`
        /// as its cached transparent receiver, exposed at `exposed_at_height` if that is set.
        fn insert_row(
            &self,
            child_index: u32,
            address: &ZcashAddress,
            cached_taddr: &str,
            exposed_at_height: Option<u32>,
        ) {
            let index = NonHardenedChildIndex::from_index(child_index).unwrap();
            let receiver_flags = address.clone().convert::<ReceiverFlags>().unwrap();
            self.db_data
                .conn
                .execute(
                    "INSERT INTO addresses (
                        account_id, diversifier_index_be, key_scope, address,
                        transparent_child_index, cached_transparent_receiver_address,
                        receiver_flags, exposed_at_height
                     )
                     VALUES (
                        :account_id, :diversifier_index_be, :key_scope, :address,
                        :transparent_child_index, :cached_taddr, :receiver_flags,
                        :exposed_at_height
                     )",
                    named_params![
                        ":account_id": self.account_id,
                        ":diversifier_index_be":
                            encode_diversifier_index_be(DiversifierIndex::from(index)),
                        ":key_scope": KeyScope::EXTERNAL.encode(),
                        ":address": address.encode(),
                        ":transparent_child_index": index.index(),
                        ":cached_taddr": cached_taddr,
                        ":receiver_flags": receiver_flags.bits(),
                        ":exposed_at_height": exposed_at_height,
                    ],
                )
                .unwrap();
        }

        /// Returns the address that gap-limit generation derives at `child_index`. It
        /// requests every available receiver, and requires the transparent one.
        #[cfg(feature = "transparent-inputs")]
        fn gap_address(&self, child_index: u32) -> UnifiedAddress {
            self.ufvk
                .address(
                    DiversifierIndex::from(child_index),
                    UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
                )
                .unwrap()
        }

        /// Returns the first `count` child indices whose gap-limit address has a shielded
        /// receiver.
        #[cfg(feature = "transparent-inputs")]
        fn shielded_gap_indices(&self, count: usize) -> Vec<u32> {
            (0..)
                .filter(|&i| {
                    let ua = self.gap_address(i);
                    ua.has_orchard() || ua.has_sapling()
                })
                .take(count)
                .collect()
        }

        /// Returns the encoded transparent receiver of the gap-limit address at
        /// `child_index`.
        #[cfg(feature = "transparent-inputs")]
        fn gap_taddr(&self, child_index: u32) -> String {
            self.gap_address(child_index)
                .transparent()
                .unwrap()
                .encode(&NETWORK)
        }

        /// Stores the gap-limit address at `child_index` the way the defect did: without
        /// its transparent receiver, which is cached as `cached_taddr`.
        #[cfg(feature = "transparent-inputs")]
        fn insert_omitting_row(
            &self,
            child_index: u32,
            cached_taddr: &str,
            exposed_at_height: Option<u32>,
        ) {
            let omitting = self
                .gap_address(child_index)
                .prune_retaining(&[Typecode::ORCHARD, Typecode::SAPLING])
                .unwrap()
                .expect("the gap-limit address has shielded receivers");
            self.insert_row(
                child_index,
                &omitting.to_zcash_address(NETWORK.network_type()),
                cached_taddr,
                exposed_at_height,
            );
        }

        /// Returns the stored address and receiver flags of the row at `child_index`.
        fn stored_row(&self, child_index: u32) -> (String, ReceiverFlags) {
            self.db_data
                .conn
                .query_row(
                    "SELECT address, receiver_flags FROM addresses
                     WHERE transparent_child_index = :child_index",
                    named_params![":child_index": child_index],
                    |row| Ok((row.get(0)?, ReceiverFlags::from_bits_retain(row.get(1)?))),
                )
                .unwrap()
        }

        fn migrate(&mut self) -> Result<(), MigratorError<Uuid, WalletMigrationError>> {
            WalletMigrator::new()
                .with_seed(Secret::new(SEED.to_vec()))
                .ignore_seed_relevance()
                .init_or_migrate_to(&mut self.db_data, &[MIGRATION_ID])
        }
    }

    #[test]
    fn migrate() {
        test_migrate(&[MIGRATION_ID]);
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn restores_omitted_transparent_receiver() {
        let mut fixture = Fixture::new();
        let indices = fixture.shielded_gap_indices(2);
        let (omitting_index, intact_index) = (indices[0], indices[1]);

        let derived = fixture.gap_address(omitting_index);
        fixture.insert_omitting_row(
            omitting_index,
            &fixture.gap_taddr(omitting_index),
            None,
        );

        let intact = fixture.gap_address(intact_index);
        fixture.insert_row(
            intact_index,
            &intact.to_zcash_address(NETWORK.network_type()),
            &fixture.gap_taddr(intact_index),
            None,
        );
        let intact_row = fixture.stored_row(intact_index);

        fixture.migrate().unwrap();

        // The address that omitted its transparent receiver now matches its derivation.
        let (address, flags) = fixture.stored_row(omitting_index);
        assert_eq!(UnifiedAddress::decode(&NETWORK, &address), Ok(derived));
        assert!(flags.contains(ReceiverFlags::P2PKH));

        // The intact address is unchanged.
        assert_eq!(fixture.stored_row(intact_index), intact_row);
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn leaves_exposed_rows_unchanged() {
        let mut fixture = Fixture::new();
        let omitting_index = fixture.shielded_gap_indices(1)[0];

        // An exposed shielded-only address with a cached transparent receiver may have been
        // handed out in that form.
        fixture.insert_omitting_row(
            omitting_index,
            &fixture.gap_taddr(omitting_index),
            Some(EXPOSURE_HEIGHT),
        );
        let exposed_row = fixture.stored_row(omitting_index);

        fixture.migrate().unwrap();

        assert_eq!(fixture.stored_row(omitting_index), exposed_row);
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn failure_restores_no_row() {
        let mut fixture = Fixture::new();
        let indices = fixture.shielded_gap_indices(2);
        let (omitting_index, corrupt_index) = (indices[0], indices[1]);

        fixture.insert_omitting_row(
            omitting_index,
            &fixture.gap_taddr(omitting_index),
            None,
        );
        let omitting_row = fixture.stored_row(omitting_index);
        // The migration repairs rows in `id` order, so it repairs the row above before this
        // row fails.
        fixture.insert_omitting_row(corrupt_index, INVALID_TADDR, None);

        assert_matches!(
            fixture.migrate(),
            Err(MigratorError::Migration {
                error: WalletMigrationError::CorruptedData(_),
                ..
            })
        );

        // The repair of the first row rolled back with the failed migration.
        assert_eq!(fixture.stored_row(omitting_index), omitting_row);
    }

    /// The restored row's receiver flags cover every receiver of the stored address, whether
    /// or not this build parses that receiver's type.
    #[test]
    fn receiver_flags_cover_every_receiver() {
        let tv = test_vectors::UNIFIED
            .iter()
            .find(|tv| tv.orchard_raw_addr.is_some() && tv.p2pkh_bytes.is_some())
            .expect("a test vector has Orchard and P2PKH receivers");

        // The vector's address without its P2PKH receiver, on the wallet's network.
        let shielded_items = tv
            .orchard_raw_addr
            .map(unified::Receiver::Orchard)
            .into_iter()
            .chain(tv.sapling_raw_addr.map(unified::Receiver::Sapling))
            .map(Uitem::Data)
            .collect();
        let omitting = ZcashAddress::from_unified(
            NetworkType::Test,
            unified::Address::try_from_items(Revision::R0, shielded_items).unwrap(),
        );
        let taddr = TransparentAddress::PublicKeyHash(tv.p2pkh_bytes.unwrap()).encode(&NETWORK);

        let mut fixture = Fixture::new();
        fixture.insert_row(VECTOR_CHILD_INDEX, &omitting, &taddr, None);
        fixture.migrate().unwrap();

        let (_, flags) = fixture.stored_row(VECTOR_CHILD_INDEX);
        assert!(flags.contains(ReceiverFlags::ORCHARD | ReceiverFlags::P2PKH));
        assert_eq!(
            flags.contains(ReceiverFlags::SAPLING),
            tv.sapling_raw_addr.is_some()
        );
    }
}
