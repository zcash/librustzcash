//! Functions for transparent input support in the wallet.
use rusqlite::OptionalExtension;
use rusqlite::{named_params, Connection, Row};
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use zcash_client_backend::data_api::AccountBalance;
use zcash_keys::address::Address;
use zip32::{DiversifierIndex, Scope};

use zcash_address::unified::{Encoding, Ivk, Uivk};
use zcash_client_backend::wallet::{TransparentAddressMetadata, WalletTransparentOutput};
use zcash_keys::encoding::AddressCodec;
use zcash_primitives::{
    legacy::{
        keys::{IncomingViewingKey, NonHardenedChildIndex},
        Script, TransparentAddress,
    },
    transaction::components::{amount::NonNegativeAmount, Amount, OutPoint, TxOut},
};
use zcash_protocol::consensus::{self, BlockHeight};

use crate::{error::SqliteClientError, AccountId, UtxoId, PRUNING_DEPTH};

use super::get_account_ids;
use super::scan_queue_extrema;

pub(crate) fn detect_spending_accounts<'a>(
    conn: &Connection,
    spent: impl Iterator<Item = &'a OutPoint>,
) -> Result<HashSet<AccountId>, rusqlite::Error> {
    let mut account_q = conn.prepare_cached(
        "SELECT received_by_account_id
        FROM utxos
        WHERE prevout_txid = :prevout_txid
        AND prevout_idx = :prevout_idx",
    )?;

    let mut acc = HashSet::new();
    for prevout in spent {
        for account in account_q.query_and_then(
            named_params![
                ":prevout_txid": prevout.hash(),
                ":prevout_idx": prevout.n()
            ],
            |row| row.get::<_, u32>(0).map(AccountId),
        )? {
            acc.insert(account?);
        }
    }

    Ok(acc)
}

pub(crate) fn get_transparent_receivers<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountId,
) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, SqliteClientError> {
    let mut ret: HashMap<TransparentAddress, Option<TransparentAddressMetadata>> = HashMap::new();

    // Get all UAs derived
    let mut ua_query = conn.prepare(
        "SELECT address, diversifier_index_be FROM addresses WHERE account_id = :account",
    )?;
    let mut rows = ua_query.query(named_params![":account": account.0])?;

    while let Some(row) = rows.next()? {
        let ua_str: String = row.get(0)?;
        let di_vec: Vec<u8> = row.get(1)?;
        let mut di: [u8; 11] = di_vec.try_into().map_err(|_| {
            SqliteClientError::CorruptedData("Diversifier index is not an 11-byte value".to_owned())
        })?;
        di.reverse(); // BE -> LE conversion

        let ua = Address::decode(params, &ua_str)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
            })
            .and_then(|addr| match addr {
                Address::Unified(ua) => Ok(ua),
                _ => Err(SqliteClientError::CorruptedData(format!(
                    "Addresses table contains {} which is not a unified address",
                    ua_str,
                ))),
            })?;

        if let Some(taddr) = ua.transparent() {
            let index = NonHardenedChildIndex::from_index(
                DiversifierIndex::from(di).try_into().map_err(|_| {
                    SqliteClientError::CorruptedData(
                        "Unable to get diversifier for transparent address.".to_string(),
                    )
                })?,
            )
            .ok_or_else(|| {
                SqliteClientError::CorruptedData(
                    "Unexpected hardened index for transparent address.".to_string(),
                )
            })?;

            ret.insert(
                *taddr,
                Some(TransparentAddressMetadata::new(
                    Scope::External.into(),
                    index,
                )),
            );
        }
    }

    if let Some((taddr, address_index)) = get_legacy_transparent_address(params, conn, account)? {
        ret.insert(
            taddr,
            Some(TransparentAddressMetadata::new(
                Scope::External.into(),
                address_index,
            )),
        );
    }

    Ok(ret)
}

pub(crate) fn get_legacy_transparent_address<P: consensus::Parameters>(
    params: &P,
    conn: &rusqlite::Connection,
    account_id: AccountId,
) -> Result<Option<(TransparentAddress, NonHardenedChildIndex)>, SqliteClientError> {
    use zcash_address::unified::Container;
    use zcash_primitives::legacy::keys::ExternalIvk;

    // Get the UIVK for the account.
    let uivk_str: Option<String> = conn
        .query_row(
            "SELECT uivk FROM accounts WHERE id = :account",
            [account_id.0],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(uivk_str) = uivk_str {
        let (network, uivk) = Uivk::decode(&uivk_str)
            .map_err(|e| SqliteClientError::CorruptedData(format!("Unable to parse UIVK: {e}")))?;
        if params.network_type() != network {
            return Err(SqliteClientError::CorruptedData(
                "Network type mismatch".to_owned(),
            ));
        }

        // Derive the default transparent address (if it wasn't already part of a derived UA).
        for item in uivk.items() {
            if let Ivk::P2pkh(tivk_bytes) = item {
                let tivk = ExternalIvk::deserialize(&tivk_bytes)?;
                return Ok(Some(tivk.default_address()));
            }
        }
    }

    Ok(None)
}

fn to_unspent_transparent_output(row: &Row) -> Result<WalletTransparentOutput, SqliteClientError> {
    let txid: Vec<u8> = row.get("prevout_txid")?;
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&txid);

    let index: u32 = row.get("prevout_idx")?;
    let script_pubkey = Script(row.get("script")?);
    let raw_value: i64 = row.get("value_zat")?;
    let value = NonNegativeAmount::from_nonnegative_i64(raw_value).map_err(|_| {
        SqliteClientError::CorruptedData(format!("Invalid UTXO value: {}", raw_value))
    })?;
    let height: u32 = row.get("height")?;

    let outpoint = OutPoint::new(txid_bytes, index);
    WalletTransparentOutput::from_parts(
        outpoint,
        TxOut {
            value,
            script_pubkey,
        },
        BlockHeight::from(height),
    )
    .ok_or_else(|| {
        SqliteClientError::CorruptedData(
            "Txout script_pubkey value did not correspond to a P2PKH or P2SH address".to_string(),
        )
    })
}

pub(crate) fn get_unspent_transparent_output(
    conn: &rusqlite::Connection,
    outpoint: &OutPoint,
) -> Result<Option<WalletTransparentOutput>, SqliteClientError> {
    let mut stmt_select_utxo = conn.prepare_cached(
        "SELECT u.prevout_txid, u.prevout_idx, u.script, u.value_zat, u.height
         FROM utxos u
         WHERE u.prevout_txid = :txid
         AND u.prevout_idx = :output_index
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE tx.block IS NOT NULL  -- the spending tx is mined
            OR tx.expiry_height IS NULL -- the spending tx will not expire
         )",
    )?;

    let result: Result<Option<WalletTransparentOutput>, SqliteClientError> = stmt_select_utxo
        .query_and_then(
            named_params![
                ":txid": outpoint.hash(),
                ":output_index": outpoint.n()
            ],
            to_unspent_transparent_output,
        )?
        .next()
        .transpose();

    result
}

/// Returns unspent transparent outputs that have been received by this wallet at the given
/// transparent address, such that the block that included the transaction was mined at a
/// height less than or equal to the provided `max_height`.
pub(crate) fn get_unspent_transparent_outputs<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    address: &TransparentAddress,
    max_height: BlockHeight,
    exclude: &[OutPoint],
) -> Result<Vec<WalletTransparentOutput>, SqliteClientError> {
    let chain_tip_height = scan_queue_extrema(conn)?.map(|range| *range.end());
    let stable_height = chain_tip_height
        .unwrap_or(max_height)
        .saturating_sub(PRUNING_DEPTH);

    let mut stmt_utxos = conn.prepare(
        "SELECT u.prevout_txid, u.prevout_idx, u.script,
                u.value_zat, u.height
         FROM utxos u
         WHERE u.address = :address
         AND u.height <= :max_height
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE
              tx.block IS NOT NULL -- the spending tx is mined
              OR tx.expiry_height IS NULL -- the spending tx will not expire
              OR tx.expiry_height > :stable_height -- the spending tx is unexpired
         )",
    )?;

    let addr_str = address.encode(params);

    let mut utxos = Vec::<WalletTransparentOutput>::new();
    let mut rows = stmt_utxos.query(named_params![
        ":address": addr_str,
        ":max_height": u32::from(max_height),
        ":stable_height": u32::from(stable_height),
    ])?;
    let excluded: BTreeSet<OutPoint> = exclude.iter().cloned().collect();
    while let Some(row) = rows.next()? {
        let output = to_unspent_transparent_output(row)?;
        if excluded.contains(output.outpoint()) {
            continue;
        }

        utxos.push(output);
    }

    Ok(utxos)
}

/// Returns the unspent balance for each transparent address associated with the specified account,
/// such that the block that included the transaction was mined at a height less than or equal to
/// the provided `max_height`.
pub(crate) fn get_transparent_address_balances<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountId,
    max_height: BlockHeight,
) -> Result<HashMap<TransparentAddress, NonNegativeAmount>, SqliteClientError> {
    let chain_tip_height = scan_queue_extrema(conn)?.map(|range| *range.end());
    let stable_height = chain_tip_height
        .unwrap_or(max_height)
        .saturating_sub(PRUNING_DEPTH);

    let mut stmt_address_balances = conn.prepare(
        "SELECT u.address, SUM(u.value_zat)
         FROM utxos u
         WHERE u.received_by_account_id = :account_id
         AND u.height <= :max_height
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE
              tx.block IS NOT NULL -- the spending tx is mined
              OR tx.expiry_height IS NULL -- the spending tx will not expire
              OR tx.expiry_height > :stable_height -- the spending tx is unexpired
         )
         GROUP BY u.address",
    )?;

    let mut res = HashMap::new();
    let mut rows = stmt_address_balances.query(named_params![
        ":account_id": account.0,
        ":max_height": u32::from(max_height),
        ":stable_height": u32::from(stable_height),
    ])?;
    while let Some(row) = rows.next()? {
        let taddr_str: String = row.get(0)?;
        let taddr = TransparentAddress::decode(params, &taddr_str)?;
        let value = NonNegativeAmount::from_nonnegative_i64(row.get(1)?)?;

        res.insert(taddr, value);
    }

    Ok(res)
}

pub(crate) fn add_transparent_account_balances(
    conn: &rusqlite::Connection,
    chain_tip_height: BlockHeight,
    min_confirmations: u32,
    account_balances: &mut HashMap<AccountId, AccountBalance>,
) -> Result<(), SqliteClientError> {
    let transparent_trace = tracing::info_span!("stmt_transparent_balances").entered();
    let zero_conf_height = (chain_tip_height + 1).saturating_sub(min_confirmations);
    let stable_height = chain_tip_height.saturating_sub(PRUNING_DEPTH);

    let mut stmt_transparent_balances = conn.prepare(
        "SELECT u.received_by_account_id, SUM(u.value_zat)
         FROM utxos u
         WHERE u.height <= :max_height
         -- and the received txo is unspent
         AND u.id NOT IN (
           SELECT transparent_received_output_id
           FROM transparent_received_output_spends txo_spends
           JOIN transactions tx
             ON tx.id_tx = txo_spends.transaction_id
           WHERE tx.block IS NOT NULL -- the spending tx is mined
           OR tx.expiry_height IS NULL -- the spending tx will not expire
           OR tx.expiry_height > :stable_height -- the spending tx is unexpired
         )
         GROUP BY u.received_by_account_id",
    )?;
    let mut rows = stmt_transparent_balances.query(named_params![
        ":max_height": u32::from(zero_conf_height),
        ":stable_height": u32::from(stable_height)
    ])?;

    while let Some(row) = rows.next()? {
        let account = AccountId(row.get(0)?);
        let raw_value = row.get(1)?;
        let value = NonNegativeAmount::from_nonnegative_i64(raw_value).map_err(|_| {
            SqliteClientError::CorruptedData(format!("Negative UTXO value {:?}", raw_value))
        })?;

        if let Some(balances) = account_balances.get_mut(&account) {
            balances.add_unshielded_value(value)?;
        }
    }
    drop(transparent_trace);
    Ok(())
}

/// Marks the given UTXO as having been spent.
pub(crate) fn mark_transparent_utxo_spent(
    conn: &rusqlite::Connection,
    tx_ref: i64,
    outpoint: &OutPoint,
) -> Result<(), SqliteClientError> {
    let mut stmt_mark_transparent_utxo_spent = conn.prepare_cached(
        "INSERT INTO transparent_received_output_spends (transparent_received_output_id, transaction_id)
         SELECT txo.id, :spent_in_tx
         FROM utxos txo
         WHERE txo.prevout_txid = :prevout_txid
         AND txo.prevout_idx = :prevout_idx
         ON CONFLICT (transparent_received_output_id, transaction_id) DO NOTHING",
    )?;

    let sql_args = named_params![
        ":spent_in_tx": &tx_ref,
        ":prevout_txid": &outpoint.hash().to_vec(),
        ":prevout_idx": &outpoint.n(),
    ];

    stmt_mark_transparent_utxo_spent.execute(sql_args)?;
    Ok(())
}

/// Adds the given received UTXO to the datastore.
pub(crate) fn put_received_transparent_utxo<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    output: &WalletTransparentOutput,
) -> Result<UtxoId, SqliteClientError> {
    let address_str = output.recipient_address().encode(params);
    let account_id = conn
        .query_row(
            "SELECT account_id FROM addresses WHERE cached_transparent_receiver_address = :address",
            named_params![":address": &address_str],
            |row| Ok(AccountId(row.get(0)?)),
        )
        .optional()?;

    if let Some(account) = account_id {
        Ok(put_legacy_transparent_utxo(conn, params, output, account)?)
    } else {
        // If the UTXO is received at the legacy transparent address (at BIP 44 address
        // index 0 within its particular account, which we specifically ensure is returned
        // from `get_transparent_receivers`), there may be no entry in the addresses table
        // that can be used to tie the address to a particular account. In this case, we
        // look up the legacy address for each account in the wallet, and check whether it
        // matches the address for the received UTXO; if so, insert/update it directly.
        get_account_ids(conn)?
            .into_iter()
            .find_map(
                |account| match get_legacy_transparent_address(params, conn, account) {
                    Ok(Some((legacy_taddr, _))) if &legacy_taddr == output.recipient_address() => {
                        Some(
                            put_legacy_transparent_utxo(conn, params, output, account)
                                .map_err(SqliteClientError::from),
                        )
                    }
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                },
            )
            // The UTXO was not for any of the legacy transparent addresses.
            .unwrap_or_else(|| {
                Err(SqliteClientError::AddressNotRecognized(
                    *output.recipient_address(),
                ))
            })
    }
}

pub(crate) fn put_legacy_transparent_utxo<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    output: &WalletTransparentOutput,
    received_by_account: AccountId,
) -> Result<UtxoId, rusqlite::Error> {
    #[cfg(feature = "transparent-inputs")]
    let mut stmt_upsert_legacy_transparent_utxo = conn.prepare_cached(
        "INSERT INTO utxos (
            prevout_txid, prevout_idx,
            received_by_account_id, address, script,
            value_zat, height)
        VALUES
            (:prevout_txid, :prevout_idx,
            :received_by_account_id, :address, :script,
            :value_zat, :height)
        ON CONFLICT (prevout_txid, prevout_idx) DO UPDATE
        SET received_by_account_id = :received_by_account_id,
            height = :height,
            address = :address,
            script = :script,
            value_zat = :value_zat
        RETURNING id",
    )?;

    let sql_args = named_params![
        ":prevout_txid": &output.outpoint().hash().to_vec(),
        ":prevout_idx": &output.outpoint().n(),
        ":received_by_account_id": received_by_account.0,
        ":address": &output.recipient_address().encode(params),
        ":script": &output.txout().script_pubkey.0,
        ":value_zat": &i64::from(Amount::from(output.txout().value)),
        ":height": &u32::from(output.height()),
    ];

    stmt_upsert_legacy_transparent_utxo.query_row(sql_args, |row| row.get::<_, i64>(0).map(UtxoId))
}

#[cfg(test)]
mod tests {
    use crate::{
        testing::{AddressType, TestBuilder, TestState},
        PRUNING_DEPTH,
    };
    use sapling::zip32::ExtendedSpendingKey;
    use zcash_client_backend::{
        data_api::{
            wallet::input_selection::GreedyInputSelector, InputSource, WalletRead, WalletWrite,
        },
        encoding::AddressCodec,
        fees::{fixed, DustOutputPolicy},
        wallet::WalletTransparentOutput,
    };
    use zcash_primitives::{
        block::BlockHash,
        consensus::BlockHeight,
        transaction::{
            components::{amount::NonNegativeAmount, OutPoint, TxOut},
            fees::fixed::FeeRule as FixedFeeRule,
        },
    };

    #[test]
    fn put_received_transparent_utxo() {
        use crate::testing::TestBuilder;

        let mut st = TestBuilder::new()
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account_id = st.test_account().unwrap().account_id();
        let uaddr = st
            .wallet()
            .get_current_address(account_id)
            .unwrap()
            .unwrap();
        let taddr = uaddr.transparent().unwrap();

        let height_1 = BlockHeight::from_u32(12345);
        let bal_absent = st
            .wallet()
            .get_transparent_balances(account_id, height_1)
            .unwrap();
        assert!(bal_absent.is_empty());

        // Create a fake transparent output.
        let value = NonNegativeAmount::const_from_u64(100000);
        let outpoint = OutPoint::fake();
        let txout = TxOut {
            value,
            script_pubkey: taddr.script(),
        };

        // Pretend the output's transaction was mined at `height_1`.
        let utxo =
            WalletTransparentOutput::from_parts(outpoint.clone(), txout.clone(), height_1).unwrap();
        let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
        assert_matches!(res0, Ok(_));

        // Confirm that we see the output unspent as of `height_1`.
        assert_matches!(
            st.wallet().get_unspent_transparent_outputs(
                taddr,
                height_1,
                &[]
            ).as_deref(),
            Ok([ret]) if (ret.outpoint(), ret.txout(), ret.height()) == (utxo.outpoint(), utxo.txout(), height_1)
        );
        assert_matches!(
            st.wallet().get_unspent_transparent_output(utxo.outpoint()),
            Ok(Some(ret)) if (ret.outpoint(), ret.txout(), ret.height()) == (utxo.outpoint(), utxo.txout(), height_1)
        );

        // Change the mined height of the UTXO and upsert; we should get back
        // the same `UtxoId`.
        let height_2 = BlockHeight::from_u32(34567);
        let utxo2 = WalletTransparentOutput::from_parts(outpoint, txout, height_2).unwrap();
        let res1 = st.wallet_mut().put_received_transparent_utxo(&utxo2);
        assert_matches!(res1, Ok(id) if id == res0.unwrap());

        // Confirm that we no longer see any unspent outputs as of `height_1`.
        assert_matches!(
            st.wallet()
                .get_unspent_transparent_outputs(taddr, height_1, &[])
                .as_deref(),
            Ok(&[])
        );

        // We can still look up the specific output, and it has the expected height.
        assert_matches!(
            st.wallet().get_unspent_transparent_output(utxo2.outpoint()),
            Ok(Some(ret)) if (ret.outpoint(), ret.txout(), ret.height()) == (utxo2.outpoint(), utxo2.txout(), height_2)
        );

        // If we include `height_2` then the output is returned.
        assert_matches!(
            st.wallet()
                .get_unspent_transparent_outputs(taddr, height_2, &[])
                .as_deref(),
            Ok([ret]) if (ret.outpoint(), ret.txout(), ret.height()) == (utxo.outpoint(), utxo.txout(), height_2)
        );

        assert_matches!(
            st.wallet().get_transparent_balances(account_id, height_2),
            Ok(h) if h.get(taddr) == Some(&value)
        );

        // Artificially delete the address from the addresses table so that
        // we can ensure the update fails if the join doesn't work.
        st.wallet()
            .conn
            .execute(
                "DELETE FROM addresses WHERE cached_transparent_receiver_address = ?",
                [Some(taddr.encode(&st.wallet().params))],
            )
            .unwrap();

        let res2 = st.wallet_mut().put_received_transparent_utxo(&utxo2);
        assert_matches!(res2, Err(_));
    }

    #[test]
    fn transparent_balance_across_shielding() {
        use zcash_client_backend::ShieldedProtocol;

        let mut st = TestBuilder::new()
            .with_block_cache()
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let uaddr = st
            .wallet()
            .get_current_address(account.account_id())
            .unwrap()
            .unwrap();
        let taddr = uaddr.transparent().unwrap();

        // Initialize the wallet with chain data that has no shielded notes for us.
        let not_our_key = ExtendedSpendingKey::master(&[]).to_diversifiable_full_viewing_key();
        let not_our_value = NonNegativeAmount::const_from_u64(10000);
        let (start_height, _, _) =
            st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
        for _ in 1..10 {
            st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
        }
        st.scan_cached_blocks(start_height, 10);

        let check_balance = |st: &TestState<_>, min_confirmations: u32, expected| {
            // Check the wallet summary returns the expected transparent balance.
            let summary = st
                .wallet()
                .get_wallet_summary(min_confirmations)
                .unwrap()
                .unwrap();
            let balance = summary
                .account_balances()
                .get(&account.account_id())
                .unwrap();
            assert_eq!(balance.unshielded(), expected);

            // Check the older APIs for consistency.
            let max_height = st.wallet().chain_height().unwrap().unwrap() + 1 - min_confirmations;
            assert_eq!(
                st.wallet()
                    .get_transparent_balances(account.account_id(), max_height)
                    .unwrap()
                    .get(taddr)
                    .cloned()
                    .unwrap_or(NonNegativeAmount::ZERO),
                expected,
            );
            assert_eq!(
                st.wallet()
                    .get_unspent_transparent_outputs(taddr, max_height, &[])
                    .unwrap()
                    .into_iter()
                    .map(|utxo| utxo.value())
                    .sum::<Option<NonNegativeAmount>>(),
                Some(expected),
            );
        };

        // The wallet starts out with zero balance.
        check_balance(&st, 0, NonNegativeAmount::ZERO);
        check_balance(&st, 1, NonNegativeAmount::ZERO);

        // Create a fake transparent output.
        let value = NonNegativeAmount::from_u64(100000).unwrap();
        let txout = TxOut {
            value,
            script_pubkey: taddr.script(),
        };

        // Pretend the output was received in the chain tip.
        let height = st.wallet().chain_height().unwrap().unwrap();
        let utxo = WalletTransparentOutput::from_parts(OutPoint::fake(), txout, height).unwrap();
        st.wallet_mut()
            .put_received_transparent_utxo(&utxo)
            .unwrap();

        // The wallet should detect the balance as having 1 confirmation.
        check_balance(&st, 0, value);
        check_balance(&st, 1, value);
        check_balance(&st, 2, NonNegativeAmount::ZERO);

        // Shield the output.
        let input_selector = GreedyInputSelector::new(
            fixed::SingleOutputChangeStrategy::new(
                FixedFeeRule::non_standard(NonNegativeAmount::ZERO),
                None,
                ShieldedProtocol::Sapling,
            ),
            DustOutputPolicy::default(),
        );
        let txid = st
            .shield_transparent_funds(&input_selector, value, account.usk(), &[*taddr], 1)
            .unwrap()[0];

        // The wallet should have zero transparent balance, because the shielding
        // transaction can be mined.
        check_balance(&st, 0, NonNegativeAmount::ZERO);
        check_balance(&st, 1, NonNegativeAmount::ZERO);
        check_balance(&st, 2, NonNegativeAmount::ZERO);

        // Mine the shielding transaction.
        let (mined_height, _) = st.generate_next_block_including(txid);
        st.scan_cached_blocks(mined_height, 1);

        // The wallet should still have zero transparent balance.
        check_balance(&st, 0, NonNegativeAmount::ZERO);
        check_balance(&st, 1, NonNegativeAmount::ZERO);
        check_balance(&st, 2, NonNegativeAmount::ZERO);

        // Unmine the shielding transaction via a reorg.
        st.wallet_mut()
            .truncate_to_height(mined_height - 1)
            .unwrap();
        assert_eq!(st.wallet().chain_height().unwrap(), Some(mined_height - 1));

        // The wallet should still have zero transparent balance.
        check_balance(&st, 0, NonNegativeAmount::ZERO);
        check_balance(&st, 1, NonNegativeAmount::ZERO);
        check_balance(&st, 2, NonNegativeAmount::ZERO);

        // Expire the shielding transaction.
        let expiry_height = st
            .wallet()
            .get_transaction(txid)
            .unwrap()
            .expect("Transaction exists in the wallet.")
            .expiry_height();
        st.wallet_mut().update_chain_tip(expiry_height).unwrap();

        // TODO: Making the transparent output spendable in this situation requires
        // changes to the transparent data model, so for now the wallet should still have
        // zero transparent balance. https://github.com/zcash/librustzcash/issues/986
        check_balance(&st, 0, NonNegativeAmount::ZERO);
        check_balance(&st, 1, NonNegativeAmount::ZERO);
        check_balance(&st, 2, NonNegativeAmount::ZERO);

        // Roll forward the chain tip until the transaction's expiry height is in the
        // stable block range (so a reorg won't make it spendable again).
        st.wallet_mut()
            .update_chain_tip(expiry_height + PRUNING_DEPTH)
            .unwrap();

        // The transparent output should be spendable again, with more confirmations.
        check_balance(&st, 0, value);
        check_balance(&st, 1, value);
        check_balance(&st, 2, value);
    }
}
