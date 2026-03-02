//! Functions for wallet support of ZIP 48 transparent multisig addresses.
//!
//! ZIP 48 defines a standard for deriving P2SH multisig addresses from a set of
//! participant public keys. This module handles the database operations for
//! storing and retrieving these addresses.

use std::ops::Range;

use rusqlite::{Connection, OptionalExtension, named_params};
use transparent::{
    address::TransparentAddress,
    keys::{NonHardenedChildIndex, NonHardenedChildRange, TransparentKeyScope},
};
use zcash_keys::encoding::TransparentCodecError;
use zcash_protocol::consensus::{self, BlockHeight};
use zcash_script::script;

use crate::{
    AccountRef,
    error::SqliteClientError,
    wallet::{
        KeyScope,
        encoding::{ReceiverFlags, encode_diversifier_index_be},
        transparent::AddressRef,
    },
};

/// Generates a range of ZIP 48 multisig addresses for the given account and stores them
/// in the wallet database.
///
/// This function is the ZIP 48 multisig equivalent of [`super::generate_address_range_internal`],
/// using the ZIP 48 full viewing key to derive P2SH multisig addresses instead of unified
/// addresses.
pub(crate) fn generate_zip48_multisig_address_range<P: consensus::Parameters>(
    conn: &rusqlite::Transaction,
    params: &P,
    account_id: AccountRef,
    fvk: &::transparent::zip48::FullViewingKey,
    key_scope: TransparentKeyScope,
    range_to_store: Range<NonHardenedChildIndex>,
) -> Result<(), SqliteClientError> {
    let scope = match key_scope {
        TransparentKeyScope::EXTERNAL => zip32::Scope::External,
        TransparentKeyScope::INTERNAL => zip32::Scope::Internal,
        _ => return Err(SqliteClientError::Zip48UnsupportedOperation),
    };

    for address_index in NonHardenedChildRange::from(range_to_store) {
        let (address, redeem_script) = fvk.derive_address(scope, address_index);

        insert_zip48_multisig_address(
            conn,
            params,
            account_id,
            key_scope,
            address_index,
            (&address, &redeem_script),
            None,
        )?;
    }

    Ok(())
}

/// Retrieves the ZIP 48 FVK from an account if it is a multisig account.
pub(crate) fn get_zip48_fvk(
    conn: &Connection,
    account_id: AccountRef,
) -> Result<Option<Vec<u8>>, SqliteClientError> {
    conn.query_row(
        "SELECT zip48_fvk FROM accounts WHERE id = :id AND account_kind = 2",
        named_params![":id": account_id.0],
        |row| row.get::<_, Option<Vec<u8>>>(0),
    )
    .optional()
    .map_err(SqliteClientError::from)
    .map(|opt| opt.flatten())
}

/// Inserts a new multisig address into the addresses table, or updates the `exposed_at_height`
/// of an existing address if it has not yet been exposed.
///
/// When `exposed_at_height` is `None`, the address is inserted without marking it as exposed
/// (used for gap-filling). When `Some(height)`, the address is marked as exposed at that height.
/// On conflict, `COALESCE(existing, new)` preserves an already-set exposure height.
pub(crate) fn insert_zip48_multisig_address<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    account_id: AccountRef,
    scope: TransparentKeyScope,
    address_index: NonHardenedChildIndex,
    derived: (&TransparentAddress, &script::Redeem),
    exposed_at_height: Option<BlockHeight>,
) -> Result<AddressRef, SqliteClientError> {
    use zcash_keys::encoding::AddressCodec;
    use zcash_script::script::Evaluable;

    let (address, redeem_script) = derived;

    if !matches!(address, TransparentAddress::ScriptHash(_)) {
        return Err(SqliteClientError::TransparentAddress(
            TransparentCodecError::UnsupportedAddressType("address must be P2SH".into()),
        ));
    }

    let addr_str = address.encode(params);
    let key_scope = KeyScope::try_from(scope)?;
    let diversifier_index = zip32::DiversifierIndex::from(address_index);

    let address_id = conn.query_row(
            "INSERT INTO addresses (
                account_id,
                key_scope,
                diversifier_index_be,
                address,
                transparent_child_index,
                cached_transparent_receiver_address,
                exposed_at_height,
                receiver_flags,
                redeem_script
            )
            VALUES (
                :account_id,
                :key_scope,
                :diversifier_index_be,
                :address,
                :transparent_child_index,
                :cached_transparent_receiver_address,
                :exposed_at_height,
                :receiver_flags,
                :redeem_script
            )
            ON CONFLICT (account_id, key_scope, diversifier_index_be)
            DO UPDATE SET exposed_at_height = COALESCE(addresses.exposed_at_height, :exposed_at_height)
            RETURNING id",
            named_params![
                ":account_id": account_id.0,
                ":key_scope": key_scope.encode(),
                ":diversifier_index_be": encode_diversifier_index_be(diversifier_index),
                ":address": &addr_str,
                ":transparent_child_index": address_index.index(),
                ":cached_transparent_receiver_address": &addr_str,
                ":exposed_at_height": exposed_at_height.map(u32::from),
                ":receiver_flags": ReceiverFlags::P2SH.bits(),
                ":redeem_script": redeem_script.to_bytes(),
            ],
            |row| row.get(0).map(AddressRef),
        )?;

    Ok(address_id)
}

/// Gets the next available address index for a multisig account.
///
/// This returns MAX(transparent_child_index) + 1 for existing multisig addresses.
pub(crate) fn get_next_zip48_multisig_address_index(
    conn: &Connection,
    account_id: AccountRef,
    scope: TransparentKeyScope,
) -> Result<NonHardenedChildIndex, SqliteClientError> {
    let key_scope = KeyScope::try_from(scope)?;

    let max_index: Option<u32> = conn
        .query_row(
            "SELECT MAX(transparent_child_index)
                 FROM addresses
                 WHERE account_id = :account_id
                 AND key_scope = :key_scope
                 AND redeem_script IS NOT NULL",
            named_params![
                ":account_id": account_id.0,
                ":key_scope": key_scope.encode()
            ],
            |row| row.get(0),
        )
        .optional()?
        .flatten();

    let next_index = max_index.map_or(0, |i| i.saturating_add(1));

    NonHardenedChildIndex::from_index(next_index).ok_or_else(|| {
        SqliteClientError::CorruptedData(
            "Next address index exceeds maximum non-hardened index".to_owned(),
        )
    })
}

/// Finds the first unexposed ZIP 48 multisig address for the given account and scope.
///
/// Returns the address index if an unexposed address exists, or None if all addresses
/// have been exposed.
pub(crate) fn get_first_unexposed_zip48_multisig_address_index(
    conn: &Connection,
    account_id: AccountRef,
    scope: TransparentKeyScope,
) -> Result<Option<NonHardenedChildIndex>, SqliteClientError> {
    let key_scope = KeyScope::try_from(scope)?;

    let index: Option<u32> = conn
        .query_row(
            "SELECT MIN(transparent_child_index)
                 FROM addresses
                 WHERE account_id = :account_id
                 AND key_scope = :key_scope
                 AND redeem_script IS NOT NULL
                 AND exposed_at_height IS NULL",
            named_params![
                ":account_id": account_id.0,
                ":key_scope": key_scope.encode()
            ],
            |row| row.get(0),
        )
        .optional()?
        .flatten();

    match index {
        Some(i) => NonHardenedChildIndex::from_index(i)
            .map(Some)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData(
                    "Address index exceeds maximum non-hardened index".to_owned(),
                )
            }),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
    use transparent::zip48::AccountPrivKey;
    use zcash_client_backend::data_api::{
        Account as _, AccountBirthday, WalletWrite, chain::ChainState, testing::TestBuilder,
    };
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

    use crate::{testing::db::TestDbFactory, wallet::get_account_ref};

    /// Runs a test with a fully initialized ZIP 48 test environment.
    fn with_zip48_test_env(
        f: impl FnOnce(
            &mut zcash_client_backend::data_api::testing::TestState<
                (),
                crate::testing::db::TestDb,
                zcash_protocol::local_consensus::LocalNetwork,
            >,
            AccountRef,
            &::transparent::zip48::FullViewingKey,
            zcash_protocol::local_consensus::LocalNetwork,
        ),
    ) {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let birthday = AccountBirthday::from_parts(
            ChainState::empty(
                st.network()
                    .activation_height(NetworkUpgrade::Sapling)
                    .unwrap()
                    - 1,
                BlockHash([0; 32]),
            ),
            None,
        );

        // Create a 2-of-3 FVK from three deterministic seeds.
        let account_id_zip32 = zip32::AccountId::ZERO;
        let seeds: [&[u8; 32]; 3] = [&[1; 32], &[2; 32], &[3; 32]];
        let pubkeys: Vec<_> = seeds
            .iter()
            .map(|seed| {
                AccountPrivKey::from_seed(st.network(), *seed, account_id_zip32)
                    .unwrap()
                    .to_account_pubkey()
            })
            .collect();
        let fvk = ::transparent::zip48::FullViewingKey::standard(2, pubkeys).unwrap();

        let account = st
            .wallet_mut()
            .import_account_zip48_multisig("zip48-test", &fvk, &birthday)
            .unwrap();

        let params = *st.network();
        let account_ref = get_account_ref(st.wallet().conn(), account.id()).unwrap();

        f(&mut st, account_ref, &fvk, params);
    }

    // The default gap limits pre-generate 10 external and 5 internal addresses on import.
    const GAP_EXTERNAL: u32 = 10;
    const GAP_INTERNAL: u32 = 5;

    #[test]
    fn next_index_after_import() {
        with_zip48_test_env(|st, account_ref, _fvk, _params| {
            // After import, gap fill has already generated GAP_EXTERNAL addresses (0..9).
            let next = get_next_zip48_multisig_address_index(
                st.wallet().conn(),
                account_ref,
                TransparentKeyScope::EXTERNAL,
            )
            .unwrap();
            assert_eq!(
                next,
                NonHardenedChildIndex::from_index(GAP_EXTERNAL).unwrap()
            );

            let next_internal = get_next_zip48_multisig_address_index(
                st.wallet().conn(),
                account_ref,
                TransparentKeyScope::INTERNAL,
            )
            .unwrap();
            assert_eq!(
                next_internal,
                NonHardenedChildIndex::from_index(GAP_INTERNAL).unwrap()
            );
        });
    }

    #[test]
    fn next_index_after_additional_insert() {
        with_zip48_test_env(|st, account_ref, fvk, params| {
            // Generate addresses beyond the gap fill range (10..15).
            let range_start = NonHardenedChildIndex::from_index(GAP_EXTERNAL).unwrap();
            let range_end = NonHardenedChildIndex::from_index(GAP_EXTERNAL + 5).unwrap();
            {
                let tx = st.wallet_mut().conn_mut().transaction().unwrap();
                generate_zip48_multisig_address_range(
                    &tx,
                    &params,
                    account_ref,
                    fvk,
                    TransparentKeyScope::EXTERNAL,
                    range_start..range_end,
                )
                .unwrap();
                tx.commit().unwrap();
            }

            let next = get_next_zip48_multisig_address_index(
                st.wallet().conn(),
                account_ref,
                TransparentKeyScope::EXTERNAL,
            )
            .unwrap();
            assert_eq!(
                next,
                NonHardenedChildIndex::from_index(GAP_EXTERNAL + 5).unwrap()
            );
        });
    }

    #[test]
    fn first_unexposed_returns_unexposed_index() {
        with_zip48_test_env(|st, account_ref, _fvk, _params| {
            // The gap-fill addresses created during import are all unexposed.
            let result = get_first_unexposed_zip48_multisig_address_index(
                st.wallet().conn(),
                account_ref,
                TransparentKeyScope::EXTERNAL,
            )
            .unwrap();
            assert_eq!(result, Some(NonHardenedChildIndex::ZERO));
        });
    }

    #[test]
    fn first_unexposed_none_when_all_exposed() {
        with_zip48_test_env(|st, account_ref, fvk, params| {
            // Mark all gap-fill addresses as exposed by re-inserting with exposed_at_height.
            for i in 0..GAP_EXTERNAL {
                let index = NonHardenedChildIndex::from_index(i).unwrap();
                let (address, redeem_script) = fvk.derive_address(zip32::Scope::External, index);
                {
                    let tx = st.wallet_mut().conn_mut().transaction().unwrap();
                    insert_zip48_multisig_address(
                        &tx,
                        &params,
                        account_ref,
                        TransparentKeyScope::EXTERNAL,
                        index,
                        (&address, &redeem_script),
                        Some(BlockHeight::from_u32(100)),
                    )
                    .unwrap();
                    tx.commit().unwrap();
                }
            }

            let result = get_first_unexposed_zip48_multisig_address_index(
                st.wallet().conn(),
                account_ref,
                TransparentKeyScope::EXTERNAL,
            )
            .unwrap();
            assert_eq!(result, None);
        });
    }

    #[test]
    fn insert_rejects_non_p2sh_address() {
        with_zip48_test_env(|st, account_ref, fvk, params| {
            // Create a P2PKH address (not P2SH).
            let p2pkh_address = TransparentAddress::PublicKeyHash([0u8; 20]);
            let (_address, redeem_script) =
                fvk.derive_address(zip32::Scope::External, NonHardenedChildIndex::ZERO);

            let tx = st.wallet_mut().conn_mut().transaction().unwrap();
            let result = insert_zip48_multisig_address(
                &tx,
                &params,
                account_ref,
                TransparentKeyScope::EXTERNAL,
                NonHardenedChildIndex::ZERO,
                (&p2pkh_address, &redeem_script),
                None,
            );
            assert_matches!(result, Err(SqliteClientError::TransparentAddress(_)));
        });
    }

    #[test]
    fn insert_round_trip() {
        with_zip48_test_env(|st, account_ref, fvk, params| {
            use rusqlite::named_params;
            use zcash_keys::encoding::AddressCodec;
            use zcash_script::script::Evaluable;

            let index = NonHardenedChildIndex::from_index(GAP_EXTERNAL).unwrap();
            let (address, redeem_script) = fvk.derive_address(zip32::Scope::External, index);
            let exposed_height = Some(BlockHeight::from_u32(200));

            let address_ref = {
                let tx = st.wallet_mut().conn_mut().transaction().unwrap();
                let r = insert_zip48_multisig_address(
                    &tx,
                    &params,
                    account_ref,
                    TransparentKeyScope::EXTERNAL,
                    index,
                    (&address, &redeem_script),
                    exposed_height,
                )
                .unwrap();
                tx.commit().unwrap();
                r
            };

            let row = st
                .wallet()
                .conn()
                .query_row(
                    "SELECT address, redeem_script, transparent_child_index,
                            key_scope, exposed_at_height
                     FROM addresses WHERE id = :id",
                    named_params![":id": address_ref.0],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, u32>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<u32>>(4)?,
                        ))
                    },
                )
                .unwrap();

            assert_eq!(row.0, address.encode(&params));
            assert_eq!(row.1, redeem_script.to_bytes());
            assert_eq!(row.2, index.index());
            assert_eq!(
                row.3,
                KeyScope::try_from(TransparentKeyScope::EXTERNAL)
                    .unwrap()
                    .encode()
            );
            assert_eq!(row.4, Some(200u32));
        });
    }

    #[test]
    fn generate_range_rejects_ephemeral_scope() {
        with_zip48_test_env(|st, account_ref, fvk, params| {
            let range_start = NonHardenedChildIndex::ZERO;
            let range_end = NonHardenedChildIndex::from_index(5).unwrap();
            let tx = st.wallet_mut().conn_mut().transaction().unwrap();
            let result = generate_zip48_multisig_address_range(
                &tx,
                &params,
                account_ref,
                fvk,
                TransparentKeyScope::EPHEMERAL,
                range_start..range_end,
            );
            assert_matches!(result, Err(SqliteClientError::Zip48UnsupportedOperation));
        });
    }

    #[test]
    fn generate_range_round_trip() {
        with_zip48_test_env(|st, account_ref, fvk, params| {
            use rusqlite::named_params;
            use zcash_keys::encoding::AddressCodec;
            use zcash_script::script::Evaluable;

            let range_start = NonHardenedChildIndex::from_index(GAP_EXTERNAL).unwrap();
            let range_end = NonHardenedChildIndex::from_index(GAP_EXTERNAL + 3).unwrap();
            {
                let tx = st.wallet_mut().conn_mut().transaction().unwrap();
                generate_zip48_multisig_address_range(
                    &tx,
                    &params,
                    account_ref,
                    fvk,
                    TransparentKeyScope::EXTERNAL,
                    range_start..range_end,
                )
                .unwrap();
                tx.commit().unwrap();
            }

            let key_scope = KeyScope::try_from(TransparentKeyScope::EXTERNAL).unwrap();
            for i in GAP_EXTERNAL..GAP_EXTERNAL + 3 {
                let index = NonHardenedChildIndex::from_index(i).unwrap();
                let (address, redeem_script) = fvk.derive_address(zip32::Scope::External, index);

                let row = st
                    .wallet()
                    .conn()
                    .query_row(
                        "SELECT address, redeem_script, exposed_at_height
                         FROM addresses
                         WHERE account_id = :account_id
                           AND key_scope = :key_scope
                           AND transparent_child_index = :index",
                        named_params![
                            ":account_id": account_ref.0,
                            ":key_scope": key_scope.encode(),
                            ":index": i,
                        ],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, Vec<u8>>(1)?,
                                row.get::<_, Option<u32>>(2)?,
                            ))
                        },
                    )
                    .unwrap();

                assert_eq!(
                    row.0,
                    address.encode(&params),
                    "address mismatch at index {i}"
                );
                assert_eq!(
                    row.1,
                    redeem_script.to_bytes(),
                    "redeem_script mismatch at index {i}"
                );
                assert_eq!(row.2, None, "expected unexposed at index {i}");
            }
        });
    }

    #[test]
    fn generate_range_inserts_correct_count() {
        with_zip48_test_env(|st, account_ref, fvk, params| {
            // Generate 5 more external addresses beyond the gap fill (10..15).
            let range_start = NonHardenedChildIndex::from_index(GAP_EXTERNAL).unwrap();
            let range_end = NonHardenedChildIndex::from_index(GAP_EXTERNAL + 5).unwrap();
            {
                let tx = st.wallet_mut().conn_mut().transaction().unwrap();
                generate_zip48_multisig_address_range(
                    &tx,
                    &params,
                    account_ref,
                    fvk,
                    TransparentKeyScope::EXTERNAL,
                    range_start..range_end,
                )
                .unwrap();
                tx.commit().unwrap();
            }

            // The next index should be GAP_EXTERNAL + 5.
            let next = get_next_zip48_multisig_address_index(
                st.wallet().conn(),
                account_ref,
                TransparentKeyScope::EXTERNAL,
            )
            .unwrap();
            assert_eq!(
                next,
                NonHardenedChildIndex::from_index(GAP_EXTERNAL + 5).unwrap()
            );

            // Gap-fill addresses are still unexposed, first one at index 0.
            let first_unexposed = get_first_unexposed_zip48_multisig_address_index(
                st.wallet().conn(),
                account_ref,
                TransparentKeyScope::EXTERNAL,
            )
            .unwrap();
            assert_eq!(first_unexposed, Some(NonHardenedChildIndex::ZERO));

            // Internal scope should still have only the gap fill addresses.
            let next_internal = get_next_zip48_multisig_address_index(
                st.wallet().conn(),
                account_ref,
                TransparentKeyScope::INTERNAL,
            )
            .unwrap();
            assert_eq!(
                next_internal,
                NonHardenedChildIndex::from_index(GAP_INTERNAL).unwrap()
            );
        });
    }
}
