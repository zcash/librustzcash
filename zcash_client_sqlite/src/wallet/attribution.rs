//! Reconstruction of the funding attribution of a stored transaction.
//!
//! Storing a transaction whose funding account is known records, for each of its outputs, the
//! account that paid for it and the recipient it paid. The funding account is derived from the
//! outputs the transaction spends, so a transaction that reaches the wallet before those outputs
//! are recognized carries no such record; the spend is linked later, and nothing revisits the
//! transaction. Its outputs are then reported forever as receipts from an unknown sender, and a
//! transfer between two accounts of one wallet reads as a payment from a stranger.
//!
//! This module replays the attribution step over the stored transaction data, and is called from
//! the paths that link a spend without recording the transaction's recipients themselves.

use rusqlite::{OptionalExtension, named_params};

use zcash_client_backend::{
    data_api::ll::{
        ReceivedShieldedOutput,
        wallet::{
            detect_wallet_transparent_outputs, shielded_sent_output_recipient,
            transparent_sent_output_recipient,
        },
    },
    decrypt_transaction,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    PoolType,
    consensus::{self, BlockHeight},
};

use crate::{
    AccountUuid, TxRef,
    error::SqliteClientError,
    wallet::{
        chain_tip_height,
        encoding::pool_code,
        get_unified_full_viewing_keys, put_sent_output, select_receiving_address,
        transparent::observations::parse_stored,
        transparent::{find_account_uuid_for_transparent_address, list_funding_accounts},
    },
};

/// Records the sent outputs of a stored transaction that the wallet now knows one of its accounts
/// funded.
///
/// Storing a transaction whose funding account is known records, for each of its transparent
/// outputs, the account that paid for it and the recipient it paid. A transaction stored while
/// the wallet could not yet recognize the outputs it spends carries no such record, and nothing
/// revisits it when those spends become known. This replays that step over the stored transaction
/// data, so that a transaction reports its funding account whatever order the evidence arrived
/// in. Every path that links such a spend without itself recording the transaction's recipients
/// calls this; a wallet creating a transaction records the recipients it intended, and does not.
///
/// Only an output for which the wallet has recorded no recipient is written. What is derived here
/// is a reconstruction from chain data, and must never displace what a wallet recorded when it
/// created the transaction and knew each output's intended recipient. Writing only what is
/// missing also makes repeated calls a no-op.
///
/// A transaction whose stored bytes are absent or do not parse contributes nothing; see
/// [`parse_stored`].
///
/// Block scanning also links spends, and calls nothing here, because a link it makes can never
/// reveal a funding account that storing the transaction would have missed: the query that makes
/// the link and the query that resolves a funding account match a prevout against
/// `transparent_received_outputs` under one and the same condition. Scanning a transaction the
/// wallet has no data for records an intent to retrieve it, and storing what arrives resolves the
/// same account; scanning one whose data the wallet already holds can only follow the recognition
/// of the spent output, which is a call site of this function.
///
/// Shielded outputs are replayed as well, by decrypting the stored bytes under every viewing key
/// the wallet holds; see [`attribute_shielded_outputs`]. What decryption cannot open is the
/// residual: an output paying an account whose keys the wallet does not have, and one whose
/// outgoing viewing key it does not hold, name a recipient the wallet has no way to learn. That
/// is precisely what storing the transaction would have left unrecorded, so the replay reaches
/// the state store-time processing reaches, not a lesser one.
pub(crate) fn attribute_funded_outputs<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    tx_ref: TxRef,
) -> Result<(), SqliteClientError> {
    let Some((raw, tx_mined_height)) = conn
        .query_row(
            "SELECT raw, mined_height FROM transactions WHERE id_tx = :id_tx",
            named_params! { ":id_tx": tx_ref.0 },
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>("raw")?,
                    row.get::<_, Option<u32>>("mined_height")?
                        .map(BlockHeight::from),
                ))
            },
        )
        .optional()?
    else {
        return Ok(());
    };

    let Some(tx) = raw.as_deref().and_then(parse_stored) else {
        return Ok(());
    };

    // A transparent output records at most one funding account; where several wallet accounts
    // contributed inputs, the largest contributor is reported, as everywhere else this crate
    // resolves a funding account.
    let Some(funding_account) = list_funding_accounts(conn, tx_ref.0)?
        .into_iter()
        .next()
        .map(|(account, _)| account)
    else {
        return Ok(());
    };

    let outputs = detect_wallet_transparent_outputs::<_, AccountUuid, SqliteClientError>(
        params,
        &tx,
        tx_mined_height,
        Some(funding_account),
        |address| {
            Ok(
                find_account_uuid_for_transparent_address(conn, params, address)?
                    .map(|(account, key_scope)| (account, key_scope.as_transparent())),
            )
        },
    )?;

    for output in &outputs {
        if has_recorded_recipient(conn, tx_ref, PoolType::TRANSPARENT, output.index())? {
            continue;
        }

        let Some((from_account, recipient)) =
            transparent_sent_output_recipient(params, output, |account, receiver| {
                select_receiving_address(conn, params, account, receiver)
            })?
        else {
            continue;
        };

        put_sent_output(
            conn,
            params,
            from_account,
            tx_ref,
            output.index(),
            &recipient,
            output.value(),
            None,
        )?;
    }

    attribute_shielded_outputs(conn, params, tx_ref, &tx, tx_mined_height, funding_account)?;

    Ok(())
}

/// Returns whether the transaction produces any shielded output, in any pool the wallet stores.
fn has_shielded_outputs(tx: &Transaction) -> bool {
    let sapling = tx
        .sapling_bundle()
        .is_some_and(|bundle| !bundle.shielded_outputs().is_empty());

    #[cfg(feature = "orchard")]
    let shielded = sapling
        || tx
            .orchard_bundle()
            .is_some_and(|bundle| !bundle.actions().is_empty())
        || tx
            .ironwood_bundle()
            .is_some_and(|bundle| !bundle.actions().is_empty());

    #[cfg(not(feature = "orchard"))]
    let shielded = sapling;

    shielded
}

/// Records the sent outputs of the shielded bundles of a stored transaction that the wallet now
/// knows `funding_account` funded.
///
/// What a transaction's shielded bundles paid is recoverable only by trial decryption, so this
/// re-runs it over the stored bytes under every viewing key the wallet holds — the same function
/// the store-time path decrypts with — and records for each output what that path would have
/// recorded with the funding account in hand.
fn attribute_shielded_outputs<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    tx_ref: TxRef,
    tx: &Transaction,
    mined_height: Option<BlockHeight>,
    funding_account: AccountUuid,
) -> Result<(), SqliteClientError> {
    // Trial decryption costs a key lookup and a pass over every output under every key, so a
    // transaction with no shielded output — the common shape for one recognized through a
    // transparent spend — is settled without paying either.
    if !has_shielded_outputs(tx) {
        return Ok(());
    }

    let ufvks = get_unified_full_viewing_keys(conn, params)?;
    if ufvks.is_empty() {
        return Ok(());
    }

    let d_tx = decrypt_transaction(params, mined_height, chain_tip_height(conn)?, tx, &ufvks);

    put_missing_sent_outputs(
        conn,
        params,
        tx_ref,
        d_tx.sapling_outputs(),
        funding_account,
    )?;

    #[cfg(feature = "orchard")]
    {
        put_missing_sent_outputs(
            conn,
            params,
            tx_ref,
            d_tx.orchard_outputs(),
            funding_account,
        )?;
        put_missing_sent_outputs(
            conn,
            params,
            tx_ref,
            d_tx.ironwood_outputs(),
            funding_account,
        )?;
    }

    Ok(())
}

/// Records the send that each of the given decrypted outputs represents, skipping any output for
/// which the wallet has already recorded a recipient.
fn put_missing_sent_outputs<P, Output>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    tx_ref: TxRef,
    outputs: &[Output],
    funding_account: AccountUuid,
) -> Result<(), SqliteClientError>
where
    P: consensus::Parameters,
    Output: ReceivedShieldedOutput<AccountId = AccountUuid>,
{
    for output in outputs {
        let pool = PoolType::Shielded(output.to_wallet_note().pool());
        if has_recorded_recipient(conn, tx_ref, pool, output.index())? {
            continue;
        }

        let Some((from_account, recipient, value)) = shielded_sent_output_recipient(
            params,
            output,
            Some(funding_account),
            |account, receiver| select_receiving_address(conn, params, account, receiver),
        )?
        else {
            continue;
        };

        put_sent_output(
            conn,
            params,
            from_account,
            tx_ref,
            output.index(),
            &recipient,
            value,
            output.memo(),
        )?;
    }

    Ok(())
}

/// Returns whether the wallet has recorded a recipient for the given output of the given
/// transaction, in the given pool.
fn has_recorded_recipient(
    conn: &rusqlite::Connection,
    tx_ref: TxRef,
    pool: PoolType,
    output_index: usize,
) -> Result<bool, SqliteClientError> {
    Ok(conn.query_row(
        "SELECT EXISTS (
            SELECT 1 FROM sent_notes
            WHERE transaction_id = :transaction_id
            AND output_pool = :output_pool
            AND output_index = :output_index
        )",
        named_params! {
            ":transaction_id": tx_ref.0,
            ":output_pool": pool_code(pool),
            ":output_index": i64::try_from(output_index)
                .expect("an output index fits in an i64"),
        },
        |row| row.get(0),
    )?)
}
