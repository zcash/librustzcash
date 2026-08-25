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

use zcash_client_backend::data_api::ll::wallet::{
    detect_wallet_transparent_outputs, transparent_sent_output_recipient,
};
use zcash_protocol::{
    PoolType,
    consensus::{self, BlockHeight},
};

use crate::{
    AccountUuid, TxRef,
    error::SqliteClientError,
    wallet::{
        encoding::pool_code,
        put_sent_output, select_receiving_address,
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
/// The shielded half of the same defect is left unrepaired here. A shielded output the wallet
/// received from elsewhere is recorded as sent only when the funding account is known at store
/// time, so a transaction that shields a transparent output the wallet did not yet recognize
/// keeps a shielded output with no recorded sender, and neither this function nor the repair
/// migration touches it. Reconstructing it needs the transaction decrypted under the wallet's
/// viewing keys rather than read from its transparent bundle; the wallet holds both the stored
/// bytes and the keys, so it is reachable offline, and simply not done here.
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
        if has_recorded_recipient(conn, tx_ref, output.index())? {
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

    Ok(())
}

/// Returns whether the wallet has recorded a recipient for the given transparent output of the
/// given transaction.
pub(crate) fn has_recorded_recipient(
    conn: &rusqlite::Connection,
    tx_ref: TxRef,
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
            ":output_pool": pool_code(PoolType::TRANSPARENT),
            ":output_index": i64::try_from(output_index)
                .expect("a transparent output index fits in an i64"),
        },
        |row| row.get(0),
    )?)
}
