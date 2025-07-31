//! Functions common to Sapling and Orchard support in the wallet.

use incrementalmerkletree::Position;
use rusqlite::{named_params, types::Value, Connection, Row};
use std::{num::NonZeroU64, rc::Rc};

use zcash_client_backend::{
    data_api::{
        wallet::ConfirmationsPolicy, NoteFilter, PoolMeta, TargetValue, SAPLING_SHARD_HEIGHT,
    },
    wallet::ReceivedNote,
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    consensus::{self, BlockHeight, TargetHeight},
    value::{BalanceError, Zatoshis},
    PoolType, ShieldedProtocol,
};

use super::wallet_birthday;
use crate::{
    error::SqliteClientError, wallet::pool_code, AccountUuid, ReceivedNoteId, SAPLING_TABLES_PREFIX,
};

#[cfg(feature = "orchard")]
use {crate::ORCHARD_TABLES_PREFIX, zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT};

pub(crate) struct TableConstants {
    pub(crate) table_prefix: &'static str,
    pub(crate) output_index_col: &'static str,
    pub(crate) output_count_col: &'static str,
    pub(crate) note_reconstruction_cols: &'static str,
    pub(crate) shard_height: u8,
}

const SAPLING_TABLE_CONSTANTS: TableConstants = TableConstants {
    table_prefix: SAPLING_TABLES_PREFIX,
    output_index_col: "output_index",
    output_count_col: "sapling_output_count",
    note_reconstruction_cols: "rcm",
    shard_height: SAPLING_SHARD_HEIGHT,
};

#[cfg(feature = "orchard")]
const ORCHARD_TABLE_CONSTANTS: TableConstants = TableConstants {
    table_prefix: ORCHARD_TABLES_PREFIX,
    output_index_col: "action_index",
    output_count_col: "orchard_action_count",
    note_reconstruction_cols: "rho, rseed",
    shard_height: ORCHARD_SHARD_HEIGHT,
};

#[allow(dead_code)]
pub(crate) trait ErrUnsupportedPool {
    fn unsupported_pool_type(pool_type: PoolType) -> Self;
}

pub(crate) fn table_constants<E: ErrUnsupportedPool>(
    shielded_protocol: ShieldedProtocol,
) -> Result<TableConstants, E> {
    match shielded_protocol {
        ShieldedProtocol::Sapling => Ok(SAPLING_TABLE_CONSTANTS),
        #[cfg(feature = "orchard")]
        ShieldedProtocol::Orchard => Ok(ORCHARD_TABLE_CONSTANTS),
        #[cfg(not(feature = "orchard"))]
        ShieldedProtocol::Orchard => Err(E::unsupported_pool_type(PoolType::ORCHARD)),
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
    let TableConstants {
        table_prefix,
        output_index_col,
        note_reconstruction_cols,
        ..
    } = table_constants::<SqliteClientError>(protocol)?;

    let result = conn.query_row_and_then(
        &format!(
            "SELECT rn.id, txid, {output_index_col},
                diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                accounts.ufvk, recipient_key_scope
             FROM {table_prefix}_received_notes rn
             INNER JOIN accounts ON accounts.id = rn.account_id
             INNER JOIN transactions ON transactions.id_tx = rn.tx
             WHERE txid = :txid
             AND transactions.block IS NOT NULL
             AND {output_index_col} = :output_index
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
    account: AccountUuid,
    target_value: TargetValue,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
    protocol: ShieldedProtocol,
    to_spendable_note: F,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>
where
    F: Fn(&P, &Row) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError>,
{
    match target_value {
        TargetValue::AtLeast(zats) => select_minimum_spendable_notes(
            conn,
            params,
            account,
            zats,
            target_height,
            confirmations_policy,
            exclude,
            protocol,
            to_spendable_note,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn select_minimum_spendable_notes<P: consensus::Parameters, F, Note>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    target_value: Zatoshis,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
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

    let trusted_anchor_height = target_height - u32::from(confirmations_policy.trusted);

    let TableConstants {
        table_prefix,
        output_index_col,
        note_reconstruction_cols,
        ..
    } = table_constants::<SqliteClientError>(protocol)?;
    if unscanned_tip_exists(conn, trusted_anchor_height, table_prefix)? {
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
                     {table_prefix}_received_notes.id AS id, txid, {output_index_col},
                     diversifier, value, {note_reconstruction_cols}, commitment_tree_position, 
                     SUM(value) OVER (ROWS UNBOUNDED PRECEDING) AS so_far,
                     accounts.ufvk as ufvk, recipient_key_scope,
                     transactions.block AS mined_height
                 FROM {table_prefix}_received_notes
                 INNER JOIN accounts
                    ON accounts.id = {table_prefix}_received_notes.account_id
                 INNER JOIN transactions
                    ON transactions.id_tx = {table_prefix}_received_notes.tx
                 WHERE accounts.uuid = :account_uuid
                 AND {table_prefix}_received_notes.account_id = accounts.id
                 -- FIXME #1316, allow selection of dust inputs
                 AND {table_prefix}_received_notes.value > 5000 
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
                   OR stx.expiry_height >= :target_height -- the spending tx is unexpired
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
             SELECT id, txid, {output_index_col},
                    diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                    ufvk, recipient_key_scope, mined_height 
             FROM eligible WHERE so_far < :target_value
             UNION
             SELECT id, txid, {output_index_col},
                    diversifier, value, {note_reconstruction_cols}, commitment_tree_position,
                    ufvk, recipient_key_scope, mined_height
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
            ":account_uuid": account.0,
            ":anchor_height": &u32::from(trusted_anchor_height),
            ":target_height": &u32::from(target_height),
            ":target_value": &u64::from(target_value),
            ":exclude": &excluded_ptr,
            ":wallet_birthday": u32::from(birthday_height)
        ],
        |r| -> Result<_, SqliteClientError> {
            let maybe_note = to_spendable_note(params, r)?;
            let recipient_key_scope: i64 = r.get("recipient_key_scope")?;
            let note_is_trusted = recipient_key_scope == 1;
            let mined_height: u32 = r.get("mined_height")?;
            Ok(maybe_note.map(|note| (note, note_is_trusted, mined_height)))
        },
    )?;

    notes
        .filter_map(|result_maybe_note| {
            let result_note = result_maybe_note.transpose()?;
            result_note
                .map(|(note, is_trusted, mined_height)| {
                    let number_of_confirmations = target_height - mined_height;
                    let required_confirmations = u32::from(confirmations_policy.untrusted);
                    // If the note is from a trusted source (this wallet), then we don't have to determine the
                    // number of confirmations, as we've already queried above based on the trusted anchor height.
                    // So we only check if it's trusted, or if it meets the untrusted number of confirmations.
                    let is_spendable =
                        is_trusted || u32::from(number_of_confirmations) >= required_confirmations;
                    is_spendable.then_some(note)
                })
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()
}

#[allow(dead_code)]
pub(crate) struct UnspentNoteMeta {
    note_id: ReceivedNoteId,
    txid: TxId,
    output_index: u32,
    commitment_tree_position: Position,
    value: Zatoshis,
}

#[allow(dead_code)]
impl UnspentNoteMeta {
    pub(crate) fn note_id(&self) -> ReceivedNoteId {
        self.note_id
    }

    pub(crate) fn txid(&self) -> TxId {
        self.txid
    }

    pub(crate) fn output_index(&self) -> u32 {
        self.output_index
    }

    pub(crate) fn commitment_tree_position(&self) -> Position {
        self.commitment_tree_position
    }

    pub(crate) fn value(&self) -> Zatoshis {
        self.value
    }
}

pub(crate) fn select_unspent_note_meta(
    conn: &rusqlite::Connection,
    protocol: ShieldedProtocol,
    chain_tip_height: BlockHeight,
    wallet_birthday: BlockHeight,
) -> Result<Vec<UnspentNoteMeta>, SqliteClientError> {
    let TableConstants {
        table_prefix,
        output_index_col,
        ..
    } = table_constants::<SqliteClientError>(protocol)?;

    // This query is effectively the same as the internal `eligible` subquery
    // used in `select_spendable_notes`.
    //
    // TODO: Deduplicate this in the future by introducing a view?
    let mut stmt = conn.prepare_cached(&format!("
        SELECT {table_prefix}_received_notes.id AS id, txid, {output_index_col},
               commitment_tree_position, value
        FROM {table_prefix}_received_notes
        INNER JOIN transactions
           ON transactions.id_tx = {table_prefix}_received_notes.tx
        WHERE value > 5000 -- FIXME #1316, allow selection of dust inputs
        AND recipient_key_scope IS NOT NULL
        AND nf IS NOT NULL
        AND commitment_tree_position IS NOT NULL
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
    "))?;

    let res = stmt
        .query_and_then::<_, SqliteClientError, _, _>(
            named_params![
                ":anchor_height": u32::from(chain_tip_height),
                ":wallet_birthday": u32::from(wallet_birthday),
            ],
            |row| {
                Ok(UnspentNoteMeta {
                    note_id: row.get("id").map(|id| ReceivedNoteId(protocol, id))?,
                    txid: row.get("txid").map(TxId::from_bytes)?,
                    output_index: row.get(output_index_col)?,
                    commitment_tree_position: row
                        .get::<_, u64>("commitment_tree_position")
                        .map(Position::from)?,
                    value: Zatoshis::from_nonnegative_i64(row.get("value")?)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(res)
}

pub(crate) fn spendable_notes_meta(
    conn: &rusqlite::Connection,
    protocol: ShieldedProtocol,
    chain_tip_height: BlockHeight,
    account: AccountUuid,
    filter: &NoteFilter,
    exclude: &[ReceivedNoteId],
) -> Result<Option<PoolMeta>, SqliteClientError> {
    let TableConstants { table_prefix, .. } = table_constants::<SqliteClientError>(protocol)?;

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

    fn zatoshis(value: i64) -> Result<Zatoshis, SqliteClientError> {
        Zatoshis::from_nonnegative_i64(value).map_err(|_| {
            SqliteClientError::CorruptedData(format!("Negative received note value: {value}"))
        })
    }

    let run_selection = |min_value| {
        conn.query_row_and_then::<_, SqliteClientError, _, _>(
            &format!(
                "SELECT COUNT(*), SUM(rn.value)
                 FROM {table_prefix}_received_notes rn
                 INNER JOIN accounts a ON a.id = rn.account_id
                 INNER JOIN transactions ON transactions.id_tx = rn.tx
                 WHERE a.uuid = :account_uuid
                 AND a.ufvk IS NOT NULL
                 AND rn.value >= :min_value
                 AND transactions.mined_height IS NOT NULL
                 AND rn.id NOT IN rarray(:exclude)
                 AND rn.id NOT IN (
                   SELECT {table_prefix}_received_note_id
                   FROM {table_prefix}_received_note_spends rns
                   JOIN transactions stx ON stx.id_tx = rns.transaction_id
                   WHERE stx.block IS NOT NULL -- the spending tx is mined
                   OR stx.expiry_height IS NULL -- the spending tx will not expire
                   OR stx.expiry_height > :chain_tip_height -- the spending tx is unexpired
                 )"
            ),
            named_params![
                ":account_uuid": account.0,
                ":min_value": u64::from(min_value),
                ":exclude": &excluded_ptr,
                ":chain_tip_height": u32::from(chain_tip_height)
            ],
            |row| {
                Ok((
                    row.get::<_, usize>(0)?,
                    row.get::<_, Option<i64>>(1)?.map(zatoshis).transpose()?,
                ))
            },
        )
    };

    // Evaluates the provided note filter conditions against the wallet database in order to
    // determine the minimum value of notes to be produced by note splitting.
    fn min_note_value(
        conn: &rusqlite::Connection,
        account: AccountUuid,
        filter: &NoteFilter,
        chain_tip_height: BlockHeight,
    ) -> Result<Option<Zatoshis>, SqliteClientError> {
        match filter {
            NoteFilter::ExceedsMinValue(v) => Ok(Some(*v)),
            NoteFilter::ExceedsPriorSendPercentile(n) => {
                let mut bucket_query = conn.prepare(
                    "WITH bucketed AS (
                        SELECT s.value, NTILE(10) OVER (ORDER BY s.value) AS bucket_index
                        FROM sent_notes s
                        JOIN transactions t ON s.tx = t.id_tx
                        JOIN accounts a on a.id = s.from_account_id
                        WHERE a.uuid = :account_uuid
                        -- only count mined transactions
                        AND t.mined_height IS NOT NULL
                        -- exclude change and account-internal sends
                        AND (s.to_account_id IS NULL OR s.from_account_id != s.to_account_id)
                    )
                    SELECT MAX(value) as value
                    FROM bucketed
                    GROUP BY bucket_index
                    ORDER BY bucket_index",
                )?;

                let bucket_maxima = bucket_query
                    .query_and_then::<_, SqliteClientError, _, _>(
                        named_params![":account_uuid": account.0],
                        |row| {
                            Zatoshis::from_nonnegative_i64(row.get::<_, i64>(0)?).map_err(|_| {
                                SqliteClientError::CorruptedData(format!(
                                    "Negative received note value: {}",
                                    n.value()
                                ))
                            })
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?;

                // Pick a bucket index by scaling the requested percentile to the number of buckets
                let i = (bucket_maxima.len() * usize::from(*n) / 100).saturating_sub(1);
                Ok(bucket_maxima.get(i).copied())
            }
            NoteFilter::ExceedsBalancePercentage(p) => {
                let balance = conn.query_row_and_then::<_, SqliteClientError, _, _>(
                    "SELECT SUM(rn.value)
                     FROM v_received_outputs rn
                     INNER JOIN accounts a ON a.id = rn.account_id
                     INNER JOIN transactions ON transactions.id_tx = rn.transaction_id
                     WHERE a.uuid = :account_uuid
                     AND a.ufvk IS NOT NULL
                     AND transactions.mined_height IS NOT NULL
                     AND rn.pool != :transparent_pool
                     AND (rn.pool, rn.id_within_pool_table) NOT IN (
                       SELECT rns.pool, rns.received_output_id
                       FROM v_received_output_spends rns
                       JOIN transactions stx ON stx.id_tx = rns.transaction_id
                       WHERE (
                           stx.block IS NOT NULL -- the spending tx is mined
                           OR stx.expiry_height IS NULL -- the spending tx will not expire
                           OR stx.expiry_height > :chain_tip_height -- the spending tx is unexpired
                       )
                     )",
                    named_params![
                        ":account_uuid": account.0,
                        ":chain_tip_height": u32::from(chain_tip_height),
                        ":transparent_pool": pool_code(PoolType::Transparent)
                    ],
                    |row| row.get::<_, Option<i64>>(0)?.map(zatoshis).transpose(),
                )?;

                Ok(match balance {
                    None => None,
                    Some(b) => {
                        let numerator = (b * u64::from(p.value())).ok_or(BalanceError::Overflow)?;
                        Some(numerator / NonZeroU64::new(100).expect("Constant is nonzero."))
                    }
                })
            }
            NoteFilter::Combine(a, b) => {
                // All the existing note selectors set lower bounds on note value, so the "and"
                // operation is just taking the maximum of the two lower bounds.
                let a_min_value = min_note_value(conn, account, a.as_ref(), chain_tip_height)?;
                let b_min_value = min_note_value(conn, account, b.as_ref(), chain_tip_height)?;
                Ok(a_min_value
                    .zip(b_min_value)
                    .map(|(av, bv)| std::cmp::max(av, bv))
                    .or(a_min_value)
                    .or(b_min_value))
            }
            NoteFilter::Attempt {
                condition,
                fallback,
            } => {
                let cond = min_note_value(conn, account, condition.as_ref(), chain_tip_height)?;
                if cond.is_none() {
                    min_note_value(conn, account, fallback, chain_tip_height)
                } else {
                    Ok(cond)
                }
            }
        }
    }

    // TODO: Simplify the query before executing it. Not worrying about this now because queries
    // will be developer-configured, not end-user defined.
    if let Some(min_value) = min_note_value(conn, account, filter, chain_tip_height)? {
        let (note_count, total_value) = run_selection(min_value)?;

        Ok(Some(PoolMeta::new(
            note_count,
            total_value.unwrap_or(Zatoshis::ZERO),
        )))
    } else {
        Ok(None)
    }
}
