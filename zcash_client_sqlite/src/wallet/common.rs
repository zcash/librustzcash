//! Functions common to Sapling and Orchard support in the wallet.

use rusqlite::{named_params, types::Value, Connection, Row};
use std::rc::Rc;

use zcash_client_backend::{wallet::ReceivedNote, ShieldedProtocol};
use zcash_primitives::transaction::{components::amount::NonNegativeAmount, TxId};
use zcash_protocol::consensus::{self, BlockHeight};

use super::wallet_birthday;
use crate::{error::SqliteClientError, AccountId, ReceivedNoteId, SAPLING_TABLES_PREFIX};

#[cfg(feature = "orchard")]
use crate::ORCHARD_TABLES_PREFIX;

fn per_protocol_names(protocol: ShieldedProtocol) -> (&'static str, &'static str, &'static str) {
    match protocol {
        ShieldedProtocol::Sapling => (SAPLING_TABLES_PREFIX, "output_index", "rcm"),
        #[cfg(feature = "orchard")]
        ShieldedProtocol::Orchard => (ORCHARD_TABLES_PREFIX, "action_index", "rho, rseed"),
        #[cfg(not(feature = "orchard"))]
        ShieldedProtocol::Orchard => {
            unreachable!("Should never be called unless the `orchard` feature is enabled")
        }
    }
}

fn unscanned_tip_exists(
    conn: &Connection,
    anchor_height: BlockHeight,
    table_prefix: &'static str,
) -> Result<bool, rusqlite::Error> {
    // v_sapling_shard_unscanned_ranges only returns ranges ending on or after wallet birthday, so
    // we don't need to refer to the birthday in this query.
    conn.query_row(
        &format!(
            "SELECT EXISTS (
                 SELECT 1 FROM v_{table_prefix}_shard_unscanned_ranges range
                 WHERE range.block_range_start <= :anchor_height
                 AND :anchor_height BETWEEN
                    range.subtree_start_height
                    AND IFNULL(range.subtree_end_height, :anchor_height)
             )"
        ),
        named_params![":anchor_height": u32::from(anchor_height),],
        |row| row.get::<_, bool>(0),
    )
}

// The `clippy::let_and_return` lint is explicitly allowed here because a bug in Clippy
// (https://github.com/rust-lang/rust-clippy/issues/11308) means it fails to identify that the `result` temporary
// is required in order to resolve the borrows involved in the `query_and_then` call.
#[allow(clippy::let_and_return)]
pub(crate) fn get_spendable_note<P: consensus::Parameters, F, Note>(
    conn: &Connection,
    params: &P,
    txid: &TxId,
    index: u32,
    protocol: ShieldedProtocol,
    to_spendable_note: F,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(&P, &Row) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
{
    let (table_prefix, index_col, note_reconstruction_cols) = per_protocol_names(protocol);
    let result = conn.query_row_and_then(
        &format!(
            "SELECT rn.id, txid, {index_col},
                diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                accounts.ufvk, recipient_key_scope
             FROM {table_prefix}_received_notes rn
             INNER JOIN accounts ON accounts.id = rn.account_id
             INNER JOIN transactions ON transactions.id_tx = rn.tx
             WHERE txid = :txid
             AND transactions.block IS NOT NULL
             AND {index_col} = :output_index
             AND accounts.ufvk IS NOT NULL
             AND recipient_key_scope IS NOT NULL
             AND nf IS NOT NULL
             AND commitment_tree_position IS NOT NULL
             AND rn.id NOT IN (
               SELECT {table_prefix}_received_note_id
               FROM {table_prefix}_received_note_spends
               JOIN transactions stx ON stx.id_tx = transaction_id
               WHERE stx.block IS NOT NULL -- the spending tx is mined
               OR stx.expiry_height IS NULL -- the spending tx will not expire
             )"
        ),
        named_params![
           ":txid": txid.as_ref(),
           ":output_index": index,
        ],
        |row| to_spendable_note(params, row),
    );

    // `OptionalExtension` doesn't work here because the error type of `Result` is already
    // `SqliteClientError`
    match result {
        Ok(r) => Ok(r),
        Err(SqliteClientError::DbError(rusqlite::Error::QueryReturnedNoRows)) => Ok(None),
        Err(e) => Err(e),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn select_spendable_notes<P: consensus::Parameters, F, Note>(
    conn: &Connection,
    params: &P,
    account: AccountId,
    target_value: NonNegativeAmount,
    anchor_height: BlockHeight,
    exclude: &[ReceivedNoteId],
    protocol: ShieldedProtocol,
    to_spendable_note: F,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(&P, &Row) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
{
    let birthday_height = match wallet_birthday(conn)? {
        Some(birthday) => birthday,
        None => {
            // the wallet birthday can only be unknown if there are no accounts in the wallet; in
            // such a case, the wallet has no notes to spend.
            return Ok(vec![]);
        }
    };

    let (table_prefix, index_col, note_reconstruction_cols) = per_protocol_names(protocol);
    if unscanned_tip_exists(conn, anchor_height, table_prefix)? {
        return Ok(vec![]);
    }

    // The goal of this SQL statement is to select the oldest notes until the required
    // value has been reached.
    // 1) Use a window function to create a view of all notes, ordered from oldest to
    //    newest, with an additional column containing a running sum:
    //    - Unspent notes accumulate the values of all unspent notes in that note's
    //      account, up to itself.
    //    - Spent notes accumulate the values of all notes in the transaction they were
    //      spent in, up to itself.
    //
    // 2) Select all unspent notes in the desired account, along with their running sum.
    //
    // 3) Select all notes for which the running sum was less than the required value, as
    //    well as a single note for which the sum was greater than or equal to the
    //    required value, bringing the sum of all selected notes across the threshold.
    let mut stmt_select_notes = conn.prepare_cached(
        &format!(
            "WITH eligible AS (
                 SELECT
                     {table_prefix}_received_notes.id AS id, txid, {index_col},
                     diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                     SUM(value) OVER (ROWS UNBOUNDED PRECEDING) AS so_far,
                     accounts.ufvk as ufvk, recipient_key_scope
                 FROM {table_prefix}_received_notes
                 INNER JOIN accounts
                    ON accounts.id = {table_prefix}_received_notes.account_id
                 INNER JOIN transactions
                    ON transactions.id_tx = {table_prefix}_received_notes.tx
                 WHERE {table_prefix}_received_notes.account_id = :account
                 AND value >= 5000 -- FIXME #1016, allow selection of a dust inputs
                 AND accounts.ufvk IS NOT NULL
                 AND recipient_key_scope IS NOT NULL
                 AND nf IS NOT NULL
                 AND commitment_tree_position IS NOT NULL
                 AND transactions.block <= :anchor_height
                 AND {table_prefix}_received_notes.id NOT IN rarray(:exclude)
                 AND {table_prefix}_received_notes.id NOT IN (
                   SELECT {table_prefix}_received_note_id
                   FROM {table_prefix}_received_note_spends
                   JOIN transactions stx ON stx.id_tx = transaction_id
                   WHERE stx.block IS NOT NULL -- the spending tx is mined
                   OR stx.expiry_height IS NULL -- the spending tx will not expire
                   OR stx.expiry_height > :anchor_height -- the spending tx is unexpired
                 )
                 AND NOT EXISTS (
                    SELECT 1 FROM v_{table_prefix}_shard_unscanned_ranges unscanned
                    -- select all the unscanned ranges involving the shard containing this note
                    WHERE {table_prefix}_received_notes.commitment_tree_position >= unscanned.start_position
                    AND {table_prefix}_received_notes.commitment_tree_position < unscanned.end_position_exclusive
                    -- exclude unscanned ranges that start above the anchor height (they don't affect spendability)
                    AND unscanned.block_range_start <= :anchor_height
                    -- exclude unscanned ranges that end below the wallet birthday
                    AND unscanned.block_range_end > :wallet_birthday
                 )
             )
             SELECT id, txid, {index_col},
                    diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                    ufvk, recipient_key_scope
             FROM eligible WHERE so_far < :target_value
             UNION
             SELECT id, txid, {index_col},
                    diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                    ufvk, recipient_key_scope
             FROM (SELECT * from eligible WHERE so_far >= :target_value LIMIT 1)",
        )
    )?;

    let excluded: Vec<Value> = exclude
        .iter()
        .filter_map(|ReceivedNoteId(p, n)| {
            if *p == protocol {
                Some(Value::from(*n))
            } else {
                None
            }
        })
        .collect();
    let excluded_ptr = Rc::new(excluded);

    let notes = stmt_select_notes.query_and_then(
        named_params![
            ":account": account.0,
            ":anchor_height": &u32::from(anchor_height),
            ":target_value": &u64::from(target_value),
            ":exclude": &excluded_ptr,
            ":wallet_birthday": u32::from(birthday_height)
        ],
        |r| to_spendable_note(params, r),
    )?;

    notes
        .filter_map(|r| r.transpose())
        .collect::<Result<_, _>>()
}
