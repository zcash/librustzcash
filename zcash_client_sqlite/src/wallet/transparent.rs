//! Functions for transparent input support in the wallet.
use std::collections::{HashMap, HashSet};

use rusqlite::OptionalExtension;
use rusqlite::{named_params, Connection, Row};

use ::transparent::{
    address::{Script, TransparentAddress},
    bundle::{OutPoint, TxOut},
    keys::{IncomingViewingKey, NonHardenedChildIndex},
};
use zcash_address::unified::{Ivk, Uivk};
use zcash_client_backend::{
    data_api::{AccountBalance, TransactionDataRequest},
    wallet::{TransparentAddressMetadata, WalletTransparentOutput},
};
use zcash_keys::{address::Address, encoding::AddressCodec};
use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    value::{ZatBalance, Zatoshis},
};
use zip32::{DiversifierIndex, Scope};

use super::{chain_tip_height, get_account_ids};
use crate::AccountUuid;
use crate::{error::SqliteClientError, TxRef, UtxoId};

pub(crate) mod ephemeral;

pub(crate) fn detect_spending_accounts<'a>(
    conn: &Connection,
    spent: impl Iterator<Item = &'a OutPoint>,
) -> Result<HashSet<AccountUuid>, rusqlite::Error> {
    let mut account_q = conn.prepare_cached(
        "SELECT accounts.uuid
        FROM transparent_received_outputs o
        JOIN accounts ON accounts.id = o.account_id
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
            |row| row.get(0).map(AccountUuid),
        )? {
            acc.insert(account?);
        }
    }

    Ok(acc)
}

/// Returns the `NonHardenedChildIndex` corresponding to a diversifier index
/// given as bytes in big-endian order (the reverse of the usual order).
fn address_index_from_diversifier_index_be(
    diversifier_index_be: &[u8],
) -> Result<NonHardenedChildIndex, SqliteClientError> {
    let mut di: [u8; 11] = diversifier_index_be.try_into().map_err(|_| {
        SqliteClientError::CorruptedData("Diversifier index is not an 11-byte value".to_owned())
    })?;
    di.reverse(); // BE -> LE conversion

    NonHardenedChildIndex::from_index(DiversifierIndex::from(di).try_into().map_err(|_| {
        SqliteClientError::CorruptedData(
            "Unable to get diversifier for transparent address.".to_string(),
        )
    })?)
    .ok_or_else(|| {
        SqliteClientError::CorruptedData(
            "Unexpected hardened index for transparent address.".to_string(),
        )
    })
}

pub(crate) fn get_transparent_receivers<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_uuid: AccountUuid,
) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, SqliteClientError> {
    let mut ret: HashMap<TransparentAddress, Option<TransparentAddressMetadata>> = HashMap::new();

    // Get all UAs derived
    let mut ua_query = conn.prepare(
        "SELECT address, diversifier_index_be 
         FROM addresses 
         JOIN accounts ON accounts.id = addresses.account_id
         WHERE accounts.uuid = :account_uuid",
    )?;
    let mut rows = ua_query.query(named_params![":account_uuid": account_uuid.0])?;

    while let Some(row) = rows.next()? {
        let ua_str: String = row.get(0)?;
        let di_vec: Vec<u8> = row.get(1)?;

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
            let address_index = address_index_from_diversifier_index_be(&di_vec)?;
            let metadata = TransparentAddressMetadata::new(Scope::External.into(), address_index);
            ret.insert(*taddr, Some(metadata));
        }
    }

    if let Some((taddr, address_index)) =
        get_legacy_transparent_address(params, conn, account_uuid)?
    {
        let metadata = TransparentAddressMetadata::new(Scope::External.into(), address_index);
        ret.insert(taddr, Some(metadata));
    }

    Ok(ret)
}

pub(crate) fn uivk_legacy_transparent_address<P: consensus::Parameters>(
    params: &P,
    uivk_str: &str,
) -> Result<Option<(TransparentAddress, NonHardenedChildIndex)>, SqliteClientError> {
    use ::transparent::keys::ExternalIvk;
    use zcash_address::unified::{Container as _, Encoding as _};

    let (network, uivk) = Uivk::decode(uivk_str)
        .map_err(|e| SqliteClientError::CorruptedData(format!("Unable to parse UIVK: {e}")))?;

    if params.network_type() != network {
        let network_name = |n| match n {
            consensus::NetworkType::Main => "mainnet",
            consensus::NetworkType::Test => "testnet",
            consensus::NetworkType::Regtest => "regtest",
        };
        return Err(SqliteClientError::CorruptedData(format!(
            "Network type mismatch: account UIVK is for {} but a {} address was requested.",
            network_name(network),
            network_name(params.network_type())
        )));
    }

    // Derive the default transparent address (if it wasn't already part of a derived UA).
    for item in uivk.items() {
        if let Ivk::P2pkh(tivk_bytes) = item {
            let tivk = ExternalIvk::deserialize(&tivk_bytes)?;
            return Ok(Some(tivk.default_address()));
        }
    }

    Ok(None)
}

pub(crate) fn get_legacy_transparent_address<P: consensus::Parameters>(
    params: &P,
    conn: &rusqlite::Connection,
    account_uuid: AccountUuid,
) -> Result<Option<(TransparentAddress, NonHardenedChildIndex)>, SqliteClientError> {
    // Get the UIVK for the account.
    let uivk_str: Option<String> = conn
        .query_row(
            "SELECT uivk FROM accounts WHERE uuid = :account_uuid",
            named_params![":account_uuid": account_uuid.0],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(uivk_str) = uivk_str {
        return uivk_legacy_transparent_address(params, &uivk_str);
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
    let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
        SqliteClientError::CorruptedData(format!("Invalid UTXO value: {}", raw_value))
    })?;
    let height: Option<u32> = row.get("received_height")?;

    let outpoint = OutPoint::new(txid_bytes, index);
    WalletTransparentOutput::from_parts(
        outpoint,
        TxOut {
            value,
            script_pubkey,
        },
        height.map(BlockHeight::from),
    )
    .ok_or_else(|| {
        SqliteClientError::CorruptedData(
            "Txout script_pubkey value did not correspond to a P2PKH or P2SH address".to_string(),
        )
    })
}

/// Select an output to fund a new transaction that is targeting at least `chain_tip_height + 1`.
pub(crate) fn get_wallet_transparent_output(
    conn: &rusqlite::Connection,
    outpoint: &OutPoint,
    allow_unspendable: bool,
) -> Result<Option<WalletTransparentOutput>, SqliteClientError> {
    let chain_tip_height = chain_tip_height(conn)?;

    // This could return as unspent outputs that are actually not spendable, if they are the
    // outputs of deshielding transactions where the spend anchors have been invalidated by a
    // rewind or spent in a transaction that has not been observed by this wallet. There isn't a
    // way to detect the circumstance related to anchor invalidation at present, but it should be
    // vanishingly rare as the vast majority of rewinds are of a single block.
    let mut stmt_select_utxo = conn.prepare_cached(
        "SELECT t.txid, u.output_index, u.script,
                u.value_zat, t.mined_height AS received_height
         FROM transparent_received_outputs u
         JOIN transactions t ON t.id_tx = u.transaction_id
         WHERE t.txid = :txid
         AND u.output_index = :output_index
         -- the transaction that created the output is mined or is definitely unexpired
         AND (
             :allow_unspendable
             OR (
                 (
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
                 )
             )
         )",
    )?;

    let result: Result<Option<WalletTransparentOutput>, SqliteClientError> = stmt_select_utxo
        .query_and_then(
            named_params![
                ":txid": outpoint.hash(),
                ":output_index": outpoint.n(),
                ":mempool_height": chain_tip_height.map(|h| u32::from(h) + 1),
                ":allow_unspendable": allow_unspendable
            ],
            to_unspent_transparent_output,
        )?
        .next()
        .transpose();

    result
}

/// Returns the list of spendable transparent outputs received by this wallet at `address`
/// such that, at height `target_height`:
/// * the transaction that produced the output had or will have at least `min_confirmations`
///   confirmations; and
/// * the output is unspent as of the current chain tip.
///
/// An output that is potentially spent by an unmined transaction in the mempool is excluded
/// iff the spending transaction will not be expired at `target_height`.
///
/// This could, in very rare circumstances, return as unspent outputs that are actually not
/// spendable, if they are the outputs of deshielding transactions where the spend anchors have
/// been invalidated by a rewind. There isn't a way to detect this circumstance at present, but
/// it should be vanishingly rare as the vast majority of rewinds are of a single block.
pub(crate) fn get_spendable_transparent_outputs<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    address: &TransparentAddress,
    target_height: BlockHeight,
    min_confirmations: u32,
) -> Result<Vec<WalletTransparentOutput>, SqliteClientError> {
    let confirmed_height = target_height - min_confirmations;

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

/// Returns a mapping from each transparent receiver associated with the specified account
/// to its not-yet-shielded UTXO balance, including only the effects of transactions mined
/// at a block height less than or equal to `summary_height`.
///
/// Only non-ephemeral transparent receivers with a non-zero balance at the summary height
/// will be included.
pub(crate) fn get_transparent_balances<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_uuid: AccountUuid,
    summary_height: BlockHeight,
) -> Result<HashMap<TransparentAddress, Zatoshis>, SqliteClientError> {
    let chain_tip_height = chain_tip_height(conn)?.ok_or(SqliteClientError::ChainHeightUnknown)?;

    let mut stmt_address_balances = conn.prepare(
        "SELECT u.address, SUM(u.value_zat)
         FROM transparent_received_outputs u
         JOIN accounts ON accounts.id = u.account_id
         JOIN transactions t ON t.id_tx = u.transaction_id
         WHERE accounts.uuid = :account_uuid
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
        ":account_uuid": account_uuid.0,
        ":summary_height": u32::from(summary_height),
        ":chain_tip_height": u32::from(chain_tip_height),
        ":spend_expiry_height": u32::from(std::cmp::min(summary_height, chain_tip_height + 1)),
    ])?;
    while let Some(row) = rows.next()? {
        let taddr_str: String = row.get(0)?;
        let taddr = TransparentAddress::decode(params, &taddr_str)?;
        let value = Zatoshis::from_nonnegative_i64(row.get(1)?)?;

        res.insert(taddr, value);
    }

    Ok(res)
}

#[tracing::instrument(skip(conn, account_balances))]
pub(crate) fn add_transparent_account_balances(
    conn: &rusqlite::Connection,
    mempool_height: BlockHeight,
    min_confirmations: u32,
    account_balances: &mut HashMap<AccountUuid, AccountBalance>,
) -> Result<(), SqliteClientError> {
    // TODO (#1592): Ability to distinguish between Transparent pending change and pending non-change
    let mut stmt_account_spendable_balances = conn.prepare(
        "SELECT a.uuid, SUM(u.value_zat)
         FROM transparent_received_outputs u
         JOIN accounts a ON a.id = u.account_id
         JOIN transactions t ON t.id_tx = u.transaction_id
         -- the transaction that created the output is mined and with enough confirmations
         WHERE (
            t.mined_height < :mempool_height -- tx is mined
            AND :mempool_height - t.mined_height >= :min_confirmations -- has at least min_confirmations
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
         GROUP BY a.uuid",
    )?;
    let mut rows = stmt_account_spendable_balances.query(named_params![
        ":mempool_height": u32::from(mempool_height),
        ":min_confirmations": min_confirmations,
    ])?;

    while let Some(row) = rows.next()? {
        let account = AccountUuid(row.get(0)?);
        let raw_value = row.get(1)?;
        let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
            SqliteClientError::CorruptedData(format!("Negative UTXO value {:?}", raw_value))
        })?;

        account_balances
            .entry(account)
            .or_insert(AccountBalance::ZERO)
            .with_unshielded_balance_mut(|bal| bal.add_spendable_value(value))?;
    }

    let mut stmt_account_unconfirmed_balances = conn.prepare(
        "SELECT a.uuid, SUM(u.value_zat)
         FROM transparent_received_outputs u
         JOIN accounts a ON a.id = u.account_id
         JOIN transactions t ON t.id_tx = u.transaction_id
         -- the transaction that created the output is mined with not enough confirmations or is definitely unexpired
         WHERE (
            t.mined_height < :mempool_height
            AND :mempool_height - t.mined_height < :min_confirmations -- tx is mined but not confirmed
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
         GROUP BY a.uuid",
    )?;

    let mut rows = stmt_account_unconfirmed_balances.query(named_params![
        ":mempool_height": u32::from(mempool_height),
        ":min_confirmations": min_confirmations,
    ])?;

    while let Some(row) = rows.next()? {
        let account = AccountUuid(row.get(0)?);
        let raw_value = row.get(1)?;
        let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
            SqliteClientError::CorruptedData(format!("Negative UTXO value {:?}", raw_value))
        })?;

        account_balances
            .entry(account)
            .or_insert(AccountBalance::ZERO)
            .with_unshielded_balance_mut(|bal| bal.add_pending_spendable_value(value))?;
    }
    Ok(())
}

/// Marks the given UTXO as having been spent.
///
/// Returns `true` if the UTXO was known to the wallet.
pub(crate) fn mark_transparent_utxo_spent(
    conn: &rusqlite::Connection,
    spent_in_tx: TxRef,
    outpoint: &OutPoint,
) -> Result<bool, SqliteClientError> {
    let spend_params = named_params![
        ":spent_in_tx": spent_in_tx.0,
        ":prevout_txid": outpoint.hash(),
        ":prevout_idx": outpoint.n(),
    ];
    let mut stmt_mark_transparent_utxo_spent = conn.prepare_cached(
        "INSERT INTO transparent_received_output_spends (transparent_received_output_id, transaction_id)
         SELECT txo.id, :spent_in_tx
         FROM transparent_received_outputs txo
         JOIN transactions t ON t.id_tx = txo.transaction_id
         WHERE t.txid = :prevout_txid
         AND txo.output_index = :prevout_idx
         ON CONFLICT (transparent_received_output_id, transaction_id)
         -- The following UPDATE is effectively a no-op, but we perform it anyway so that the
         -- number of affected rows can be used to determine whether a record existed.
         DO UPDATE SET transaction_id = :spent_in_tx",
    )?;
    let affected_rows = stmt_mark_transparent_utxo_spent.execute(spend_params)?;

    // Since we know that the output is spent, we no longer need to search for
    // it to find out if it has been spent.
    let mut stmt_remove_spend_detection = conn.prepare_cached(
        "DELETE FROM transparent_spend_search_queue
         WHERE output_index = :prevout_idx
         AND transaction_id IN (
            SELECT id_tx FROM transactions WHERE txid = :prevout_txid
         )",
    )?;
    stmt_remove_spend_detection.execute(named_params![
        ":prevout_txid": outpoint.hash(),
        ":prevout_idx": outpoint.n(),
    ])?;

    // If no rows were affected, we know that we don't actually have the output in
    // `transparent_received_outputs` yet, so we have to record the output as spent
    // so that when we eventually detect the output, we can create the spend record.
    if affected_rows == 0 {
        conn.execute(
            "INSERT INTO transparent_spend_map (
                spending_transaction_id,
                prevout_txid,
                prevout_output_index
            )
            VALUES (:spent_in_tx, :prevout_txid, :prevout_idx)
            ON CONFLICT (spending_transaction_id, prevout_txid, prevout_output_index)
            DO NOTHING",
            spend_params,
        )?;
    }

    Ok(affected_rows > 0)
}

/// Adds the given received UTXO to the datastore.
pub(crate) fn put_received_transparent_utxo<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    output: &WalletTransparentOutput,
) -> Result<UtxoId, SqliteClientError> {
    let address = output.recipient_address();
    if let Some(receiving_account) =
        find_account_uuid_for_transparent_address(conn, params, address)?
    {
        put_transparent_output(
            conn,
            params,
            output.outpoint(),
            output.txout(),
            output.mined_height(),
            address,
            receiving_account,
            true,
        )
    } else {
        // The UTXO was not for any of our transparent addresses.
        Err(SqliteClientError::AddressNotRecognized(*address))
    }
}

/// Returns the vector of [`TransactionDataRequest`]s that represents the information needed by the
/// wallet backend in order to be able to present a complete view of wallet history and memo data.
pub(crate) fn transaction_data_requests<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
) -> Result<Vec<TransactionDataRequest>, SqliteClientError> {
    // `lightwalletd` will return an error for `GetTaddressTxids` requests having an end height
    // greater than the current chain tip height, so we take the chain tip height into account
    // here in order to make this pothole easier for clients of the API to avoid.
    let chain_tip_height = super::chain_tip_height(conn)?;

    // We cannot construct address-based transaction data requests for the case where we cannot
    // determine the height at which to begin, so we require that either the target height or mined
    // height be set.
    let mut address_request_stmt = conn.prepare_cached(
        "SELECT ssq.address, IFNULL(t.target_height, t.mined_height)
         FROM transparent_spend_search_queue ssq
         JOIN transactions t ON t.id_tx = ssq.transaction_id
         WHERE t.target_height IS NOT NULL
         OR t.mined_height IS NOT NULL",
    )?;

    let result = address_request_stmt
        .query_and_then([], |row| {
            let address = TransparentAddress::decode(params, &row.get::<_, String>(0)?)?;
            let block_range_start = BlockHeight::from(row.get::<_, u32>(1)?);
            let max_end_height = block_range_start + DEFAULT_TX_EXPIRY_DELTA + 1;

            Ok::<TransactionDataRequest, SqliteClientError>(
                TransactionDataRequest::SpendsFromAddress {
                    address,
                    block_range_start,
                    block_range_end: Some(
                        chain_tip_height
                            .map_or(max_end_height, |h| std::cmp::min(h + 1, max_end_height)),
                    ),
                },
            )
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(result)
}

pub(crate) fn get_transparent_address_metadata<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    account_uuid: AccountUuid,
    address: &TransparentAddress,
) -> Result<Option<TransparentAddressMetadata>, SqliteClientError> {
    let address_str = address.encode(params);

    if let Some(di_vec) = conn
        .query_row(
            "SELECT diversifier_index_be FROM addresses
             JOIN accounts ON addresses.account_id = accounts.id
             WHERE accounts.uuid = :account_uuid 
             AND cached_transparent_receiver_address = :address",
            named_params![":account_uuid": account_uuid.0, ":address": &address_str],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
    {
        let address_index = address_index_from_diversifier_index_be(&di_vec)?;
        let metadata = TransparentAddressMetadata::new(Scope::External.into(), address_index);
        return Ok(Some(metadata));
    }

    if let Some((legacy_taddr, address_index)) =
        get_legacy_transparent_address(params, conn, account_uuid)?
    {
        if &legacy_taddr == address {
            let metadata = TransparentAddressMetadata::new(Scope::External.into(), address_index);
            return Ok(Some(metadata));
        }
    }

    // Search known ephemeral addresses.
    if let Some(address_index) =
        ephemeral::find_index_for_ephemeral_address_str(conn, account_uuid, &address_str)?
    {
        return Ok(Some(ephemeral::metadata(address_index)));
    }

    Ok(None)
}

/// Attempts to determine the account that received the given transparent output.
///
/// The following three locations in the wallet's key tree are searched:
/// - Transparent receivers that have been generated as part of a Unified Address.
/// - Transparent ephemeral addresses that have been reserved or are within
///   the gap limit from the last reserved address.
/// - "Legacy transparent addresses" (at BIP 44 address index 0 within an account).
///
/// Returns `Ok(None)` if the transparent output's recipient address is not in any of the
/// above locations. This means the wallet considers the output "not interesting".
pub(crate) fn find_account_uuid_for_transparent_address<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    address: &TransparentAddress,
) -> Result<Option<AccountUuid>, SqliteClientError> {
    let address_str = address.encode(params);

    if let Some(account_id) = conn
        .query_row(
            "SELECT accounts.uuid 
             FROM addresses 
             JOIN accounts ON accounts.id = addresses.account_id
             WHERE cached_transparent_receiver_address = :address",
            named_params![":address": &address_str],
            |row| Ok(AccountUuid(row.get(0)?)),
        )
        .optional()?
    {
        return Ok(Some(account_id));
    }

    // Search known ephemeral addresses.
    if let Some(account_id) = ephemeral::find_account_for_ephemeral_address_str(conn, &address_str)?
    {
        return Ok(Some(account_id));
    }

    let account_ids = get_account_ids(conn)?;

    // If the UTXO is received at the legacy transparent address (at BIP 44 address
    // index 0 within its particular account, which we specifically ensure is returned
    // from `get_transparent_receivers`), there may be no entry in the addresses table
    // that can be used to tie the address to a particular account. In this case, we
    // look up the legacy address for each account in the wallet, and check whether it
    // matches the address for the received UTXO.
    for &account_id in account_ids.iter() {
        if let Some((legacy_taddr, _)) = get_legacy_transparent_address(params, conn, account_id)? {
            if &legacy_taddr == address {
                return Ok(Some(account_id));
            }
        }
    }

    Ok(None)
}

/// Add a transparent output relevant to this wallet to the database.
///
/// `output_height` may be None if this is an ephemeral output from a
/// transaction we created, that we do not yet know to have been mined.
#[allow(clippy::too_many_arguments)]
pub(crate) fn put_transparent_output<P: consensus::Parameters>(
    conn: &rusqlite::Connection,
    params: &P,
    outpoint: &OutPoint,
    txout: &TxOut,
    output_height: Option<BlockHeight>,
    address: &TransparentAddress,
    receiving_account_uuid: AccountUuid,
    known_unspent: bool,
) -> Result<UtxoId, SqliteClientError> {
    let output_height = output_height.map(u32::from);
    let receiving_account_id = super::get_account_ref(conn, receiving_account_uuid)?;

    // Check whether we have an entry in the blocks table for the output height;
    // if not, the transaction will be updated with its mined height when the
    // associated block is scanned.
    let block = match output_height {
        Some(height) => conn
            .query_row(
                "SELECT height FROM blocks WHERE height = :height",
                named_params![":height": height],
                |row| row.get::<_, u32>(0),
            )
            .optional()?,
        None => None,
    };

    let id_tx = conn.query_row(
        "INSERT INTO transactions (txid, block, mined_height)
         VALUES (:txid, :block, :mined_height)
         ON CONFLICT (txid) DO UPDATE
         SET block = IFNULL(block, :block),
             mined_height = :mined_height
         RETURNING id_tx",
        named_params![
           ":txid": &outpoint.hash().to_vec(),
           ":block": block,
           ":mined_height": output_height
        ],
        |row| row.get::<_, i64>(0),
    )?;

    let spent_height = conn
        .query_row(
            "SELECT t.mined_height
             FROM transactions t
             JOIN transparent_received_output_spends ts ON ts.transaction_id = t.id_tx
             JOIN transparent_received_outputs tro ON tro.id = ts.transparent_received_output_id
             WHERE tro.transaction_id = :transaction_id
             AND tro.output_index = :output_index",
            named_params![
                ":transaction_id": id_tx,
                ":output_index": &outpoint.n(),
            ],
            |row| {
                row.get::<_, Option<u32>>(0)
                    .map(|o| o.map(BlockHeight::from))
            },
        )
        .optional()?
        .flatten();

    // The max observed unspent height is either the spending transaction's mined height - 1, or
    // the current chain tip height if the UTXO was received via a path that confirmed that it was
    // unspent, such as by querying the UTXO set of the network.
    let max_observed_unspent = match spent_height {
        Some(h) => Some(h - 1),
        None => {
            if known_unspent {
                chain_tip_height(conn)?
            } else {
                None
            }
        }
    };

    let mut stmt_upsert_transparent_output = conn.prepare_cached(
        "INSERT INTO transparent_received_outputs (
            transaction_id, output_index,
            account_id, address, script,
            value_zat, max_observed_unspent_height
        )
        VALUES (
            :transaction_id, :output_index,
            :account_id, :address, :script,
            :value_zat, :max_observed_unspent_height
        )
        ON CONFLICT (transaction_id, output_index) DO UPDATE
        SET account_id = :account_id,
            address = :address,
            script = :script,
            value_zat = :value_zat,
            max_observed_unspent_height = IFNULL(:max_observed_unspent_height, max_observed_unspent_height)
        RETURNING id",
    )?;

    let sql_args = named_params![
        ":transaction_id": id_tx,
        ":output_index": &outpoint.n(),
        ":account_id": receiving_account_id.0,
        ":address": &address.encode(params),
        ":script": &txout.script_pubkey.0,
        ":value_zat": &i64::from(ZatBalance::from(txout.value)),
        ":max_observed_unspent_height": max_observed_unspent.map(u32::from),
    ];

    let utxo_id = stmt_upsert_transparent_output
        .query_row(sql_args, |row| row.get::<_, i64>(0).map(UtxoId))?;

    // If we have a record of the output already having been spent, then mark it as spent using the
    // stored reference to the spending transaction.
    let spending_tx_ref = conn
        .query_row(
            "SELECT ts.spending_transaction_id
             FROM transparent_spend_map ts
             JOIN transactions t ON t.id_tx = ts.spending_transaction_id
             WHERE ts.prevout_txid = :prevout_txid
             AND ts.prevout_output_index = :prevout_idx
             ORDER BY t.block NULLS LAST LIMIT 1",
            named_params![
                ":prevout_txid": outpoint.txid().as_ref(),
                ":prevout_idx": outpoint.n()
            ],
            |row| row.get::<_, i64>(0).map(TxRef),
        )
        .optional()?;

    if let Some(spending_transaction_id) = spending_tx_ref {
        mark_transparent_utxo_spent(conn, spending_transaction_id, outpoint)?;
    }

    Ok(utxo_id)
}

/// Adds a request to retrieve transactions involving the specified address to the transparent
/// spend search queue. Note that such requests are _not_ for data related to `tx_ref`, but instead
/// a request to find where the UTXO with the outpoint `(tx_ref, output_index)` is spent.
///
/// ### Parameters
/// - `receiving_address`: The address that received the UTXO.
/// - `tx_ref`: The transaction in which the UTXO was received.
/// - `output_index`: The index of the output within `vout` of the specified transaction.
pub(crate) fn queue_transparent_spend_detection<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    receiving_address: TransparentAddress,
    tx_ref: TxRef,
    output_index: u32,
) -> Result<(), SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO transparent_spend_search_queue
         (address, transaction_id, output_index)
         VALUES
         (:address, :transaction_id, :output_index)
         ON CONFLICT (transaction_id, output_index) DO NOTHING",
    )?;

    let addr_str = receiving_address.encode(params);
    stmt.execute(named_params! {
        ":address": addr_str,
        ":transaction_id": tx_ref.0,
        ":output_index": output_index
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;
    use transparent::keys::NonHardenedChildIndex;
    use zcash_client_backend::{
        data_api::{testing::TestBuilder, Account as _, WalletWrite, GAP_LIMIT},
        wallet::TransparentAddressMetadata,
    };
    use zcash_primitives::block::BlockHash;

    use crate::{
        testing::{db::TestDbFactory, BlockCache},
        wallet::{get_account_ref, transparent::ephemeral},
        WalletDb,
    };

    #[test]
    fn put_received_transparent_utxo() {
        zcash_client_backend::data_api::testing::transparent::put_received_transparent_utxo(
            TestDbFactory::default(),
        );
    }

    #[test]
    fn transparent_balance_across_shielding() {
        zcash_client_backend::data_api::testing::transparent::transparent_balance_across_shielding(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn transparent_balance_spendability() {
        zcash_client_backend::data_api::testing::transparent::transparent_balance_spendability(
            TestDbFactory::default(),
            BlockCache::new(),
        );
    }

    #[test]
    fn ephemeral_address_management() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let birthday = st.test_account().unwrap().birthday().clone();
        let account0_uuid = st.test_account().unwrap().account().id();
        let account0_id = get_account_ref(&st.wallet().db().conn, account0_uuid).unwrap();

        let check = |db: &WalletDb<_, _>, account_id| {
            eprintln!("checking {account_id:?}");
            assert_matches!(ephemeral::first_unstored_index(&db.conn, account_id), Ok(addr_index) if addr_index == GAP_LIMIT);
            assert_matches!(ephemeral::first_unreserved_index(&db.conn, account_id), Ok(addr_index) if addr_index == 0);

            let known_addrs =
                ephemeral::get_known_ephemeral_addresses(&db.conn, &db.params, account_id, None)
                    .unwrap();

            let expected_metadata: Vec<TransparentAddressMetadata> = (0..GAP_LIMIT)
                .map(|i| ephemeral::metadata(NonHardenedChildIndex::from_index(i).unwrap()))
                .collect();
            let actual_metadata: Vec<TransparentAddressMetadata> =
                known_addrs.into_iter().map(|(_, meta)| meta).collect();
            assert_eq!(actual_metadata, expected_metadata);
        };

        check(st.wallet().db(), account0_id);

        // Creating a new account should initialize `ephemeral_addresses` for that account.
        let seed1 = vec![0x01; 32];
        let (account1_uuid, _usk) = st
            .wallet_mut()
            .db_mut()
            .create_account("test1", &Secret::new(seed1), &birthday, None)
            .unwrap();
        let account1_id = get_account_ref(&st.wallet().db().conn, account1_uuid).unwrap();
        assert_ne!(account0_id, account1_id);
        check(st.wallet().db(), account1_id);
    }
}
