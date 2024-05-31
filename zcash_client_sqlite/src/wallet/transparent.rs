//! Functions for transparent input support in the wallet.
use rusqlite::OptionalExtension;
use rusqlite::{named_params, Connection, Row};
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

use crate::{error::SqliteClientError, AccountId, UtxoId};

use super::{chain_tip_height, get_account_ids};

pub(crate) fn detect_spending_accounts<'a>(
    conn: &Connection,
    spent: impl Iterator<Item = &'a OutPoint>,
) -> Result<HashSet<AccountId>, rusqlite::Error> {
    let mut account_q = conn.prepare_cached(
        "SELECT account_id
        FROM transparent_received_outputs o
        JOIN transactions t ON t.id_tx = o.transaction_id
        WHERE t.txid = :prevout_txid
        AND o.output_index = :prevout_idx",
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
    let txid: Vec<u8> = row.get("txid")?;
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&txid);

    let index: u32 = row.get("output_index")?;
    let script_pubkey = Script(row.get("script")?);
    let raw_value: i64 = row.get("value_zat")?;
    let value = NonNegativeAmount::from_nonnegative_i64(raw_value).map_err(|_| {
        SqliteClientError::CorruptedData(format!("Invalid UTXO value: {}", raw_value))
    })?;
    let height: u32 = row.get("received_height")?;

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

/// Select an output to fund a new transaction that is targeting at least `chain_tip_height + 1`.
pub(crate) fn get_unspent_transparent_output(
    conn: &rusqlite::Connection,
    outpoint: &OutPoint,
) -> Result<Option<WalletTransparentOutput>, SqliteClientError> {
    let chain_tip_height = chain_tip_height(conn)?;

    // This could, in very rare circumstances, return as unspent outputs that are actually not
    // spendable, if they are the outputs of deshielding transactions where the spend anchors have
    // been invalidated by a rewind. There isn't a way to detect this circumstance at present, but
    // it should be vanishingly rare as the vast majority of rewinds are of a single block.
    let mut stmt_select_utxo = conn.prepare_cached(
        "SELECT t.txid, u.output_index, u.script,
                u.value_zat, t.mined_height AS received_height
         FROM transparent_received_outputs u
         JOIN transactions t ON t.id_tx = u.transaction_id
         WHERE t.txid = :txid
         AND u.output_index = :output_index
         -- the transaction that created the output is mined or is definitely unexpired
         AND (
            t.mined_height IS NOT NULL -- tx is mined
            -- TODO: uncomment the following two lines in order to enable zero-conf spends
            -- OR t.expiry_height = 0 -- tx will not expire
            -- OR t.expiry_height >= :mempool_height -- tx has not yet expired
         )
         -- and the output is unspent
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE tx.mined_height IS NOT NULL  -- the spending tx is mined
            OR tx.expiry_height = 0 -- the spending tx will not expire
            OR tx.expiry_height >= :mempool_height -- the spending tx has not yet expired
         )",
    )?;

    let result: Result<Option<WalletTransparentOutput>, SqliteClientError> = stmt_select_utxo
        .query_and_then(
            named_params![
                ":txid": outpoint.hash(),
                ":output_index": outpoint.n(),
                ":mempool_height": chain_tip_height.map(|h| u32::from(h) + 1),
            ],
            to_unspent_transparent_output,
        )?
        .next()
        .transpose();

    result
}

pub(crate) fn get_spendable_transparent_outputs<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    address: &TransparentAddress,
    target_height: BlockHeight,
    min_confirmations: u32,
) -> Result<Vec<WalletTransparentOutput>, SqliteClientError> {
    let confirmed_height = target_height - min_confirmations;

    // This could, in very rare circumstances, return as unspent outputs that are actually not
    // spendable, if they are the outputs of deshielding transactions where the spend anchors have
    // been invalidated by a rewind. There isn't a way to detect this circumstance at present, but
    // it should be vanishingly rare as the vast majority of rewinds are of a single block.
    let mut stmt_utxos = conn.prepare(
        "SELECT t.txid, u.output_index, u.script,
                u.value_zat, t.mined_height AS received_height
         FROM transparent_received_outputs u
         JOIN transactions t ON t.id_tx = u.transaction_id
         WHERE u.address = :address
         -- the transaction that created the output is mined or unexpired as of `confirmed_height`
         AND (
            t.mined_height <= :confirmed_height -- tx is mined
            -- TODO: uncomment the following lines in order to enable zero-conf spends
            -- OR (
            --     :min_confirmations = 0
            --     AND (
            --         t.expiry_height = 0 -- tx will not expire
            --         OR t.expiry_height >= :target_height
            --     )
            -- )
         )
         -- and the output is unspent
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE tx.mined_height IS NOT NULL -- the spending transaction is mined
            OR tx.expiry_height = 0 -- the spending tx will not expire
            OR tx.expiry_height >= :target_height -- the spending tx has not yet expired
            -- we are intentionally conservative and exclude outputs that are potentially spent
            -- as of the target height, even if they might actually be spendable due to expiry
            -- of the spending transaction as of the chain tip
         )",
    )?;

    let addr_str = address.encode(params);
    let mut rows = stmt_utxos.query(named_params![
        ":address": addr_str,
        ":confirmed_height": u32::from(confirmed_height),
        ":target_height": u32::from(target_height),
        //":min_confirmations": min_confirmations
    ])?;

    let mut utxos = Vec::<WalletTransparentOutput>::new();
    while let Some(row) = rows.next()? {
        let output = to_unspent_transparent_output(row)?;
        utxos.push(output);
    }

    Ok(utxos)
}

/// Returns the unspent balance for each transparent address associated with the specified account,
/// such that the block that included the transaction was mined at a height less than or equal to
/// the provided `summary_height`.
pub(crate) fn get_transparent_address_balances<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account: AccountId,
    summary_height: BlockHeight,
) -> Result<HashMap<TransparentAddress, NonNegativeAmount>, SqliteClientError> {
    let chain_tip_height = chain_tip_height(conn)?.ok_or(SqliteClientError::ChainHeightUnknown)?;

    let mut stmt_address_balances = conn.prepare(
        "SELECT u.address, SUM(u.value_zat)
         FROM transparent_received_outputs u
         JOIN transactions t
         ON t.id_tx = u.transaction_id
         WHERE u.account_id = :account_id
         -- the transaction that created the output is mined or is definitely unexpired
         AND (
            t.mined_height <= :summary_height -- tx is mined
            OR ( -- or the caller has requested to include zero-conf funds that are not expired
                :summary_height > :chain_tip_height
                AND (
                    t.expiry_height = 0 -- tx will not expire
                    OR t.expiry_height >= :summary_height
                )
            )
         )
         -- and the output is unspent
         AND u.id NOT IN (
            SELECT txo_spends.transparent_received_output_id
            FROM transparent_received_output_spends txo_spends
            JOIN transactions tx ON tx.id_tx = txo_spends.transaction_id
            WHERE tx.mined_height IS NOT NULL -- the spending tx is mined
            OR tx.expiry_height = 0 -- the spending tx will not expire
            OR tx.expiry_height >= :spend_expiry_height -- the spending tx is unexpired
         )
         GROUP BY u.address",
    )?;

    let mut res = HashMap::new();
    let mut rows = stmt_address_balances.query(named_params![
        ":account_id": account.0,
        ":summary_height": u32::from(summary_height),
        ":chain_tip_height": u32::from(chain_tip_height),
        ":spend_expiry_height": u32::from(std::cmp::min(summary_height, chain_tip_height + 1)),
    ])?;
    while let Some(row) = rows.next()? {
        let taddr_str: String = row.get(0)?;
        let taddr = TransparentAddress::decode(params, &taddr_str)?;
        let value = NonNegativeAmount::from_nonnegative_i64(row.get(1)?)?;

        res.insert(taddr, value);
    }

    Ok(res)
}

#[tracing::instrument(skip(conn, account_balances))]
pub(crate) fn add_transparent_account_balances(
    conn: &rusqlite::Connection,
    mempool_height: BlockHeight,
    account_balances: &mut HashMap<AccountId, AccountBalance>,
) -> Result<(), SqliteClientError> {
    let transparent_trace = tracing::info_span!("stmt_transparent_balances").entered();
    let mut stmt_account_balances = conn.prepare(
        "SELECT u.account_id, SUM(u.value_zat)
         FROM transparent_received_outputs u
         JOIN transactions t
         ON t.id_tx = u.transaction_id
         -- the transaction that created the output is mined or is definitely unexpired
         WHERE (
            t.mined_height < :mempool_height -- tx is mined
            OR t.expiry_height = 0 -- tx will not expire
            OR t.expiry_height >= :mempool_height
         )
         -- and the received txo is unspent
         AND u.id NOT IN (
           SELECT transparent_received_output_id
           FROM transparent_received_output_spends txo_spends
           JOIN transactions tx
             ON tx.id_tx = txo_spends.transaction_id
           WHERE tx.mined_height IS NOT NULL -- the spending tx is mined
           OR tx.expiry_height = 0 -- the spending tx will not expire
           OR tx.expiry_height >= :mempool_height -- the spending tx is unexpired
         )
         GROUP BY u.account_id",
    )?;
    let mut rows = stmt_account_balances
        .query(named_params![":mempool_height": u32::from(mempool_height),])?;

    while let Some(row) = rows.next()? {
        let account = AccountId(row.get(0)?);
        let raw_value = row.get(1)?;
        let value = NonNegativeAmount::from_nonnegative_i64(raw_value).map_err(|_| {
            SqliteClientError::CorruptedData(format!("Negative UTXO value {:?}", raw_value))
        })?;

        account_balances
            .entry(account)
            .or_insert(AccountBalance::ZERO)
            .add_unshielded_value(value)?;
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
         FROM transparent_received_outputs txo
         JOIN transactions t ON t.id_tx = txo.transaction_id
         WHERE t.txid = :prevout_txid
         AND txo.output_index = :prevout_idx
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
        Ok(put_transparent_output(conn, params, output, account)?)
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
                            put_transparent_output(conn, params, output, account)
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

pub(crate) fn put_transparent_output<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    output: &WalletTransparentOutput,
    received_by_account: AccountId,
) -> Result<UtxoId, rusqlite::Error> {
    // Check whether we have an entry in the blocks table for the output height;
    // if not, the transaction will be updated with its mined height when the
    // associated block is scanned.
    let block = conn
        .query_row(
            "SELECT height FROM blocks WHERE height = :height",
            named_params![":height": &u32::from(output.height())],
            |row| row.get::<_, u32>(0),
        )
        .optional()?;

    let id_tx = conn.query_row(
        "INSERT INTO transactions (txid, block, mined_height)
         VALUES (:txid, :block, :mined_height)
         ON CONFLICT (txid) DO UPDATE
         SET block = IFNULL(block, :block),
             mined_height = :mined_height
         RETURNING id_tx",
        named_params![
           ":txid": &output.outpoint().hash().to_vec(),
           ":block": block,
           ":mined_height": u32::from(output.height())
        ],
        |row| row.get::<_, i64>(0),
    )?;

    let mut stmt_upsert_transparent_output = conn.prepare_cached(
        "INSERT INTO transparent_received_outputs (
            transaction_id, output_index,
            account_id, address, script,
            value_zat, max_observed_unspent_height
        )
        VALUES (
            :transaction_id, :output_index,
            :account_id, :address, :script,
            :value_zat, :height
        )
        ON CONFLICT (transaction_id, output_index) DO UPDATE
        SET account_id = :account_id,
            address = :address,
            script = :script,
            value_zat = :value_zat,
            max_observed_unspent_height = :height
        RETURNING id",
    )?;

    let sql_args = named_params![
        ":transaction_id": id_tx,
        ":output_index": &output.outpoint().n(),
        ":account_id": received_by_account.0,
        ":address": &output.recipient_address().encode(params),
        ":script": &output.txout().script_pubkey.0,
        ":value_zat": &i64::from(Amount::from(output.txout().value)),
        ":height": &u32::from(output.height()),
    ];

    stmt_upsert_transparent_output.query_row(sql_args, |row| row.get::<_, i64>(0).map(UtxoId))
}

#[cfg(test)]
mod tests {
    use crate::testing::{AddressType, TestBuilder, TestState};
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

        let birthday = st.test_account().unwrap().birthday().height();
        let account_id = st.test_account().unwrap().account_id();
        let uaddr = st
            .wallet()
            .get_current_address(account_id)
            .unwrap()
            .unwrap();
        let taddr = uaddr.transparent().unwrap();

        let height_1 = birthday + 12345;
        st.wallet_mut().update_chain_tip(height_1).unwrap();

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
            st.wallet().get_spendable_transparent_outputs(
                taddr,
                height_1,
                0
            ).as_deref(),
            Ok([ret]) if (ret.outpoint(), ret.txout(), ret.height()) == (utxo.outpoint(), utxo.txout(), height_1)
        );
        assert_matches!(
            st.wallet().get_unspent_transparent_output(utxo.outpoint()),
            Ok(Some(ret)) if (ret.outpoint(), ret.txout(), ret.height()) == (utxo.outpoint(), utxo.txout(), height_1)
        );

        // Change the mined height of the UTXO and upsert; we should get back
        // the same `UtxoId`.
        let height_2 = birthday + 34567;
        st.wallet_mut().update_chain_tip(height_2).unwrap();
        let utxo2 = WalletTransparentOutput::from_parts(outpoint, txout, height_2).unwrap();
        let res1 = st.wallet_mut().put_received_transparent_utxo(&utxo2);
        assert_matches!(res1, Ok(id) if id == res0.unwrap());

        // Confirm that we no longer see any unspent outputs as of `height_1`.
        assert_matches!(
            st.wallet()
                .get_spendable_transparent_outputs(taddr, height_1, 0)
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
                .get_spendable_transparent_outputs(taddr, height_2, 0)
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
            // TODO: in the future, we will distinguish between available and total
            // balance according to `min_confirmations`
            assert_eq!(balance.unshielded(), expected);

            // Check the older APIs for consistency.
            let mempool_height = st.wallet().chain_height().unwrap().unwrap() + 1;
            assert_eq!(
                st.wallet()
                    .get_transparent_balances(account.account_id(), mempool_height)
                    .unwrap()
                    .get(taddr)
                    .cloned()
                    .unwrap_or(NonNegativeAmount::ZERO),
                expected,
            );
            assert_eq!(
                st.wallet()
                    .get_spendable_transparent_outputs(taddr, mempool_height, 0)
                    .unwrap()
                    .into_iter()
                    .map(|utxo| utxo.value())
                    .sum::<Option<NonNegativeAmount>>(),
                Some(expected),
            );
        };

        // The wallet starts out with zero balance.
        // TODO: Once we have refactored `get_wallet_summary` to distinguish between available
        // and total balance, we should perform additional checks against available balance;
        // we use minconf 0 here because all transparent funds are considered shieldable,
        // irrespective of confirmation depth.
        check_balance(&st, 0, NonNegativeAmount::ZERO);

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

        // The wallet should detect the balance as available
        check_balance(&st, 0, value);

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

        // Mine the shielding transaction.
        let (mined_height, _) = st.generate_next_block_including(txid);
        st.scan_cached_blocks(mined_height, 1);

        // The wallet should still have zero transparent balance.
        check_balance(&st, 0, NonNegativeAmount::ZERO);

        // Unmine the shielding transaction via a reorg.
        st.wallet_mut()
            .truncate_to_height(mined_height - 1)
            .unwrap();
        assert_eq!(st.wallet().chain_height().unwrap(), Some(mined_height - 1));

        // The wallet should still have zero transparent balance.
        check_balance(&st, 0, NonNegativeAmount::ZERO);

        // Expire the shielding transaction.
        let expiry_height = st
            .wallet()
            .get_transaction(txid)
            .unwrap()
            .expect("Transaction exists in the wallet.")
            .expiry_height();
        st.wallet_mut().update_chain_tip(expiry_height).unwrap();

        check_balance(&st, 0, value);
    }
}
