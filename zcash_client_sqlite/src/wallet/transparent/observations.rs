//! Maintenance of the durable index from transparent addresses to the wallet-involved
//! transactions that name them.
//!
//! Wallet recognition of transparent involvement is the join of the wallet's stored
//! transactions with its address book, and that join has two deltas. Checking a transaction
//! against the book when the transaction is stored maintains the first; this index maintains
//! the second, by recording every address a wallet-involved transaction names — including
//! addresses the wallet does not control at the time — so that an address added afterwards can
//! be checked against everything already seen.
//!
//! See the `transparent_tx_address_observations` table documentation for how this index divides
//! labour with the two outpoint-keyed spend maps.
//!
//! The module also carries what recognition of a spend implies for the spending transaction.
//! Linking a spend of a wallet output to a stored transaction is the moment the wallet learns
//! which account funded that transaction, and [`attribute_funded_outputs`] then records for its
//! outputs what storing it with that knowledge would have recorded.

use rusqlite::{OptionalExtension, named_params};

use transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};
use zcash_client_backend::{
    data_api::ll::wallet::{detect_wallet_transparent_outputs, transparent_sent_output_recipient},
    wallet::{TransparentAddressObservation, TransparentInvolvement, WalletTransparentOutput},
};
use zcash_keys::{
    encoding::AddressCodec,
    keys::transparent::gap_limits::{GapLimits, ReconcileOutcome},
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    PoolType, TxId,
    consensus::{self, BlockHeight, BranchId},
    value::Zatoshis,
};

use super::{
    GapAdvance, find_account_uuid_for_transparent_address, get_wallet_transparent_output,
    list_funding_accounts, lower_account_birthday, mark_transparent_utxo_spent,
    put_transparent_output, queue_transparent_spend_detection,
};
use crate::{
    AccountUuid, TxRef,
    error::SqliteClientError,
    wallet::{
        KeyScope, encoding::pool_code, put_sent_output, queue_tx_retrieval,
        select_receiving_address, update_tx_fee,
    },
};

/// The direction in which a transaction's transparent data names an address, as encoded in the
/// `involvement` column of `transparent_tx_address_observations`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Involvement {
    /// The address is paid by the transaction output at the row's `item_index`.
    Output,
    /// The address is revealed by the `scriptSig` of the transaction input at the row's
    /// `item_index`.
    Input,
}

impl Involvement {
    /// Returns the encoding of this direction as stored in the `involvement` column.
    pub(crate) fn encode(&self) -> i64 {
        match self {
            Involvement::Output => 0,
            Involvement::Input => 1,
        }
    }

    /// Decodes a value read from the `involvement` column.
    pub(crate) fn decode(code: i64) -> Result<Self, SqliteClientError> {
        match code {
            0 => Ok(Involvement::Output),
            1 => Ok(Involvement::Input),
            other => Err(SqliteClientError::CorruptedData(format!(
                "Unrecognized transparent involvement direction {other}"
            ))),
        }
    }
}

/// Records the addresses that the transparent data of the transaction identified by `tx_ref`
/// names.
///
/// Each observation is an idempotent upsert keyed by the transaction, the involvement
/// direction, and the item index, so a transaction may be observed repeatedly and at differing
/// fidelity without the recorded state depending on the order of observation.
pub(crate) fn put_observations<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    tx_ref: TxRef,
    observations: &[TransparentAddressObservation],
) -> Result<(), SqliteClientError> {
    // A transaction with no transparent data names no address. Returning before the statement is
    // prepared keeps that case free of any database access, so a caller may record the (empty)
    // observations of a transaction whose row it has not created.
    if observations.is_empty() {
        return Ok(());
    }

    let mut stmt_upsert_observation = conn.prepare_cached(
        "INSERT INTO transparent_tx_address_observations (
            transaction_id, involvement, item_index, address,
            value_zat, prevout_txid, prevout_output_index
        )
        VALUES (
            :transaction_id, :involvement, :item_index, :address,
            :value_zat, :prevout_txid, :prevout_output_index
        )
        ON CONFLICT (transaction_id, involvement, item_index) DO UPDATE
        SET address = :address,
            value_zat = :value_zat,
            prevout_txid = :prevout_txid,
            prevout_output_index = :prevout_output_index",
    )?;

    for observation in observations {
        let (involvement, value_zat, prevout) = match observation.involvement() {
            TransparentInvolvement::Output(value) => {
                (Involvement::Output, Some(u64::from(*value)), None)
            }
            TransparentInvolvement::Input(prevout) => (Involvement::Input, None, Some(prevout)),
        };

        stmt_upsert_observation.execute(named_params![
            ":transaction_id": tx_ref.0,
            ":involvement": involvement.encode(),
            ":item_index": observation.item_index(),
            ":address": observation.address().encode(params),
            ":value_zat": value_zat,
            ":prevout_txid": prevout.map(|p| p.hash().to_vec()),
            ":prevout_output_index": prevout.map(|p| p.n()),
        ])?;
    }

    Ok(())
}

/// Parses stored transaction bytes, or returns `None` if they do not parse.
///
/// The consensus branch ID a transaction is parsed under does not affect the parse: versions
/// before v5 do not encode it, and v5 onward carry their own. Every use in this module reads only
/// the transparent bundle, so a placeholder suffices and no height needs to be resolved for an
/// unmined transaction with no expiry height.
///
/// Bytes that do not parse are data the wallet cannot act on. This module must never fail on
/// them: its reconciliation runs inside the index migration, which cannot be reverted, so an
/// error there would leave the wallet unable to open. The backfill that populates the index
/// already skips such rows, and every path that reads them back agrees with it.
///
/// A failure here is permanent for that row: `queue_tx_retrieval` records enhancement intent
/// only for a transaction whose data the wallet lacks, and a row with unusable bytes still has
/// `raw` set, so no re-fetch is ever recorded for it.
fn parse_stored(raw: &[u8]) -> Option<Transaction> {
    Transaction::read(raw, BranchId::Sprout).ok()
}

/// Returns the stored transaction with the given txid, or `None` if the wallet does not hold it
/// or cannot parse what it holds. See [`parse_stored`] for why the two are not distinguished.
fn stored_transaction(
    conn: &rusqlite::Connection,
    txid: TxId,
) -> Result<Option<Transaction>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT raw FROM transactions WHERE txid = :txid",
            named_params! { ":txid": txid.as_ref() },
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten()
        .and_then(|raw| parse_stored(&raw)))
}

/// Records the address observations of every transaction for which the wallet stores complete
/// transaction data.
///
/// A transaction whose stored bytes cannot be parsed contributes no observations; such data
/// cannot be repaired here, and failing would leave the wallet unable to open.
pub(crate) fn backfill_observations<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
) -> Result<(), SqliteClientError> {
    let mut backfilled = vec![];
    {
        let mut stmt_stored_txs =
            conn.prepare("SELECT id_tx, raw FROM transactions WHERE raw IS NOT NULL")?;
        let mut rows = stmt_stored_txs.query([])?;
        while let Some(row) = rows.next()? {
            let tx_ref = TxRef(row.get("id_tx")?);
            let raw = row.get::<_, Vec<u8>>("raw")?;

            let Some(tx) = parse_stored(&raw) else {
                continue;
            };

            backfilled.push((
                tx_ref,
                zcash_client_backend::wallet::transparent_address_observations(&tx),
            ));
        }
    }

    for (tx_ref, observations) in backfilled {
        put_observations(conn, params, tx_ref, &observations)?;
    }

    Ok(())
}

/// The addresses that a reconciliation pass checks against the involvement index.
pub(crate) enum ReconcileScope<'a> {
    /// Check only the given transparent addresses.
    Addresses(&'a [TransparentAddress]),
    /// Check every transparent address in the wallet's address book. This is what an account
    /// import and the index's own backfill need, since neither knows which addresses are new.
    AllAddresses,
}

/// An involvement of a wallet address with a stored transaction, as read from the index.
struct ObservedInvolvement {
    tx_ref: TxRef,
    txid: TxId,
    mined_height: Option<BlockHeight>,
    observation_height: BlockHeight,
    tx_has_raw: bool,
    address: TransparentAddress,
    account_uuid: AccountUuid,
    key_scope: KeyScope,
    item_index: u32,
    involvement: Involvement,
    value: Option<Zatoshis>,
    prevout: Option<OutPoint>,
}

/// The columns each reconciliation query selects, in the order [`ObservedInvolvement::from_row`]
/// reads them.
const OBSERVED_INVOLVEMENT_COLUMNS: &str = "
    o.transaction_id, o.involvement, o.item_index, o.address, o.value_zat,
    o.prevout_txid, o.prevout_output_index,
    t.txid, t.mined_height, t.min_observed_height, t.raw IS NOT NULL AS tx_has_raw,
    accounts.uuid AS account_uuid, a.key_scope";

/// The joins that resolve an index row to the transaction that carries it and the account that
/// controls the address it names. The join against `addresses` is what makes this a
/// reconciliation: an index row with no matching address is involvement the wallet still cannot
/// act on.
const OBSERVED_INVOLVEMENT_SOURCE: &str = "
    FROM transparent_tx_address_observations o
    JOIN transactions t ON t.id_tx = o.transaction_id
    JOIN addresses a ON a.cached_transparent_receiver_address = o.address
    JOIN accounts ON accounts.id = a.account_id";

impl ObservedInvolvement {
    fn from_row<P: consensus::Parameters>(
        params: &P,
        row: &rusqlite::Row<'_>,
    ) -> Result<Self, SqliteClientError> {
        let address_str = row.get::<_, String>("address")?;
        let address = TransparentAddress::decode(params, &address_str).map_err(|_| {
            SqliteClientError::CorruptedData(format!(
                "Transparent address observation names the unreadable address {address_str}"
            ))
        })?;

        let involvement = Involvement::decode(row.get("involvement")?)?;
        let value = row
            .get::<_, Option<i64>>("value_zat")?
            .map(|raw| {
                Zatoshis::from_nonnegative_i64(raw).map_err(|_| {
                    SqliteClientError::CorruptedData(format!(
                        "Transparent address observation records the invalid value {raw}"
                    ))
                })
            })
            .transpose()?;
        let prevout = row
            .get::<_, Option<[u8; 32]>>("prevout_txid")?
            .zip(row.get::<_, Option<u32>>("prevout_output_index")?)
            .map(|(txid, n)| OutPoint::new(txid, n));

        Ok(ObservedInvolvement {
            tx_ref: TxRef(row.get("transaction_id")?),
            txid: TxId::from_bytes(row.get("txid")?),
            mined_height: row
                .get::<_, Option<u32>>("mined_height")?
                .map(BlockHeight::from),
            observation_height: BlockHeight::from(row.get::<_, u32>("min_observed_height")?),
            tx_has_raw: row.get("tx_has_raw")?,
            address,
            account_uuid: AccountUuid::from_uuid(row.get("account_uuid")?),
            key_scope: KeyScope::decode(row.get("key_scope")?)?,
            item_index: row.get("item_index")?,
            involvement,
            value,
            prevout,
        })
    }
}

/// Checks the involvement index against the wallet's address book, and records everything a
/// match reveals.
///
/// This is the second delta of the recognition join: involvement that was observed before the
/// wallet held the address it names becomes wallet state as soon as the address is added. It is
/// written entirely as idempotent upserts, so it may be run against any scope at any time, and
/// running it repeatedly records nothing further.
///
/// Returns [`ReconcileOutcome::AddressesUsed`] if a match established that an address received
/// an output in a mined transaction, which is the condition under which the account's
/// transparent address gap moves.
pub(crate) fn reconcile_observations<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    gap_limits: &GapLimits,
    scope: ReconcileScope<'_>,
) -> Result<ReconcileOutcome, SqliteClientError> {
    let involvements = match scope {
        ReconcileScope::AllAddresses => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {OBSERVED_INVOLVEMENT_COLUMNS} {OBSERVED_INVOLVEMENT_SOURCE}"
            ))?;
            stmt.query_and_then([], |row| ObservedInvolvement::from_row(params, row))?
                .collect::<Result<Vec<_>, _>>()?
        }
        ReconcileScope::Addresses(addresses) => {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {OBSERVED_INVOLVEMENT_COLUMNS} {OBSERVED_INVOLVEMENT_SOURCE}
                 WHERE o.address = :address"
            ))?;
            let mut rows = vec![];
            for address in addresses {
                rows.extend(
                    stmt.query_and_then(
                        named_params! { ":address": address.encode(params) },
                        |row| ObservedInvolvement::from_row(params, row),
                    )?
                    .collect::<Result<Vec<_>, _>>()?,
                );
            }
            rows
        }
    };

    let mut outcome = ReconcileOutcome::Unchanged;
    for involvement in involvements {
        let used = match involvement.involvement {
            Involvement::Output => reconcile_output(conn, params, gap_limits, &involvement)?,
            Involvement::Input => reconcile_input(conn, params, gap_limits, &involvement)?,
        };

        if used == ReconcileOutcome::AddressesUsed {
            outcome = ReconcileOutcome::AddressesUsed;
        }
    }

    Ok(outcome)
}

/// Records a transaction output that pays a wallet address as received, and queues the work that
/// discovery of a received output implies.
fn reconcile_output<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    gap_limits: &GapLimits,
    involvement: &ObservedInvolvement,
) -> Result<ReconcileOutcome, SqliteClientError> {
    // The table's `involvement_data_consistency` constraint makes this unreachable for a row
    // this crate wrote. It is kept as a read-path guard, in the same spirit as the other
    // `CorruptedData` checks here, so that a row from a hand-edited database is reported rather
    // than silently mis-read.
    let Some(value) = involvement.value else {
        return Err(SqliteClientError::CorruptedData(format!(
            "Transparent address observation for output {} of transaction {} records no value",
            involvement.item_index, involvement.txid
        )));
    };

    // The address determines the `scriptPubKey` that paid it, for both address kinds the wallet
    // recognizes, so the output can be reconstructed without the transaction's own bytes.
    let output = WalletTransparentOutput::from_parts(
        OutPoint::new(involvement.txid.into(), involvement.item_index),
        TxOut::new(value, involvement.address.script().into()),
        involvement.mined_height,
        Some(involvement.account_uuid),
        involvement.key_scope.as_transparent(),
        None,
    )
    .ok_or_else(|| {
        SqliteClientError::CorruptedData(format!(
            "Transparent address observation names the unspendable address {}",
            involvement.address.encode(params)
        ))
    })?;

    // The gap is left to the caller: the reconciliation this is part of is itself driven by a
    // walk over successive gap windows, and advancing the gap here would re-enter that walk once
    // per recognized output.
    put_transparent_output(
        conn,
        params,
        gap_limits,
        &output,
        involvement.observation_height,
        false,
        GapAdvance::Deferred,
    )?;

    // A transparent spend is only found when the wallet knows which outpoint to watch, so an
    // output recognized here must be added to the watch set.
    queue_transparent_spend_detection(
        conn,
        params,
        involvement.address,
        involvement.tx_ref,
        involvement.item_index,
    )?;

    // The transaction now has wallet outputs, so the transactions that funded it are part of the
    // wallet's transparent history and its fee becomes computable. Both need the transaction's
    // inputs: read them from its own data when the wallet holds it, and otherwise ask for that
    // data first.
    if involvement.tx_has_raw {
        queue_prevout_retrieval(conn, involvement.tx_ref)?;
        recompute_dependent_fees(conn, involvement.tx_ref)?;
    } else {
        queue_tx_retrieval(conn, std::iter::once(involvement.txid), None)?;
    }

    Ok(if involvement.mined_height.is_some() {
        ReconcileOutcome::AddressesUsed
    } else {
        ReconcileOutcome::Unchanged
    })
}

/// Records a transaction input that spends from a wallet address as a spend, and recovers the
/// output it spent.
///
/// An input observation is the only evidence the wallet has that a transaction spends its funds
/// when the spent output was never recognized: the `scriptSig` reveals the address, but the value
/// and the receiving transaction are in the prior transaction. This is what makes a transaction
/// that only spends from the wallet — with no output paying it — wallet-involving.
fn reconcile_input<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    gap_limits: &GapLimits,
    involvement: &ObservedInvolvement,
) -> Result<ReconcileOutcome, SqliteClientError> {
    let Some(prevout) = involvement.prevout.as_ref() else {
        return Err(SqliteClientError::CorruptedData(format!(
            "Transparent address observation for input {} of transaction {} records no outpoint",
            involvement.item_index, involvement.txid
        )));
    };

    // The spent output is the authority on which address it paid, so where the wallet holds a
    // readable copy of the transaction that created it, check the `scriptSig` reading against
    // that output before anything is recorded. A reading that disagrees names an address the
    // wallet was not paid at. Stored bytes that do not parse leave the output unrecoverable
    // here, which is the same position as not holding the transaction at all.
    let prevout_txout = match stored_transaction(conn, *prevout.txid())? {
        Some(prevout_tx) => {
            let txout = prevout_tx
                .transparent_bundle()
                .and_then(|bundle| {
                    bundle
                        .vout
                        .get(usize::try_from(prevout.n()).expect("an output index fits in a usize"))
                })
                .cloned();

            match txout {
                // The reading agrees with the output, so the wallet was paid here.
                Some(txout) if txout.recipient_address() == Some(involvement.address) => {
                    Some(txout)
                }
                // Either the prior transaction has no such output, or that output paid someone
                // else. This is chain data the wallet did not produce, so it is skipped rather
                // than treated as a wallet inconsistency.
                _ => return Ok(ReconcileOutcome::Unchanged),
            }
        }
        None => None,
    };

    // The transaction spends the wallet's funds, so the wallet was active when it was mined,
    // whether or not the output it spent can be recovered. Recovering the output records it
    // through `put_transparent_output`, which accounts for the height at which it was received.
    if let Some(height) = involvement.mined_height {
        lower_account_birthday(conn, params, involvement.account_uuid, height)?;
    }

    // Record the spend. If the spent output is not yet held, this records the spend against the
    // outpoint so that it is linked when the output is recovered, whether that happens below or
    // later.
    //
    // Linking the spend establishes that a wallet account funded this transaction, which is what
    // makes its outputs the wallet's sends; the transaction was stored before that was knowable,
    // so nothing recorded them then. Where the link is deferred to the recovery below, the
    // attribution is deferred with it, and `put_transparent_output` replays it at the moment the
    // link is made.
    if mark_transparent_utxo_spent(conn, involvement.tx_ref, prevout)? {
        attribute_funded_outputs(conn, params, involvement.tx_ref)?;
    }

    // Recover the spent output from the transaction that created it, if the wallet holds that
    // transaction; otherwise ask for it. The spend recorded above is what links the two, so the
    // order in which they arrive does not matter.
    let Some(txout) = prevout_txout else {
        queue_tx_retrieval(
            conn,
            std::iter::once(*prevout.txid()),
            Some(involvement.tx_ref),
        )?;
        return Ok(ReconcileOutcome::Unchanged);
    };

    let prevout_mined_height = mined_height(conn, *prevout.txid())?;
    let output = WalletTransparentOutput::from_parts(
        prevout.clone(),
        txout,
        prevout_mined_height,
        Some(involvement.account_uuid),
        involvement.key_scope.as_transparent(),
        None,
    )
    .ok_or_else(|| {
        SqliteClientError::CorruptedData(format!(
            "Transparent address observation names the unspendable address {}",
            involvement.address.encode(params)
        ))
    })?;

    put_transparent_output(
        conn,
        params,
        gap_limits,
        &output,
        prevout_mined_height.unwrap_or(involvement.observation_height),
        false,
        GapAdvance::Deferred,
    )?;

    Ok(if prevout_mined_height.is_some() {
        ReconcileOutcome::AddressesUsed
    } else {
        ReconcileOutcome::Unchanged
    })
}

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
fn has_recorded_recipient(
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

/// Returns the height at which the given transaction was mined, if the wallet knows it.
fn mined_height(
    conn: &rusqlite::Connection,
    txid: TxId,
) -> Result<Option<BlockHeight>, SqliteClientError> {
    Ok(conn
        .query_row(
            "SELECT mined_height FROM transactions WHERE txid = :txid",
            named_params! { ":txid": txid.as_ref() },
            |row| row.get::<_, Option<u32>>(0),
        )
        .optional()?
        .flatten()
        .map(BlockHeight::from))
}

/// Requests the transactions that created the transparent inputs of the given transaction, so
/// that the wallet can trace its transparent history and compute its fee.
fn queue_prevout_retrieval(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: TxRef,
) -> Result<(), SqliteClientError> {
    let Some(raw) = conn
        .query_row(
            "SELECT raw FROM transactions WHERE id_tx = :id_tx",
            named_params! { ":id_tx": tx_ref.0 },
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten()
    else {
        return Ok(());
    };

    let Some(tx) = parse_stored(&raw) else {
        return Ok(());
    };

    if let Some(bundle) = tx.transparent_bundle()
        && !bundle.is_coinbase()
    {
        queue_tx_retrieval(
            conn,
            bundle.vin.iter().map(|txin| *txin.prevout().txid()),
            Some(tx_ref),
        )?;
    }

    Ok(())
}

/// Sets the fee of each transaction that spends a transparent output of the given transaction
/// and whose fee could not previously be computed.
///
/// Recognizing an output supplies the value of an input to every transaction that spends it,
/// which may be the last value such a transaction's fee computation was missing.
fn recompute_dependent_fees(
    conn: &rusqlite::Transaction<'_>,
    tx_ref: TxRef,
) -> Result<(), SqliteClientError> {
    // This deliberately does not reuse `get_txs_spending_transparent_outputs_of`, which resolves
    // each transaction's consensus branch ID and fails on bytes it cannot parse. A transaction
    // whose stored bytes do not parse has no computable fee, so it is skipped; see
    // [`parse_stored`] for why nothing in this module may fail on such a row.
    let spending_txs = {
        let mut stmt = conn.prepare_cached(
            "SELECT DISTINCT t.id_tx, t.raw
             FROM transactions t
             JOIN transparent_received_output_spends ts ON ts.transaction_id = t.id_tx
             JOIN transparent_received_outputs tro
                ON tro.id = ts.transparent_received_output_id
             WHERE tro.transaction_id = :transaction_id
             AND t.fee IS NULL
             AND t.raw IS NOT NULL",
        )?;

        stmt.query_map(named_params! { ":transaction_id": tx_ref.0 }, |row| {
            Ok((TxRef(row.get(0)?), row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };

    for (spending_tx_ref, raw) in spending_txs {
        let Some(spending_tx) = parse_stored(&raw) else {
            continue;
        };

        let fee = match spending_tx.fee_paid(|outpoint| {
            Ok::<_, SqliteClientError>(
                get_wallet_transparent_output(conn, outpoint, None)?.map(|out| out.txout().value()),
            )
        }) {
            Ok(fee) => fee,
            // A stored transaction whose value balances do not sum within range has no fee to
            // compute. That is bad data of the same kind as bytes that do not parse, and is
            // skipped for the same reason; a storage error raised while reading the value of a
            // spent output is a real failure and still propagates.
            Err(SqliteClientError::BalanceError(_)) => continue,
            Err(e) => return Err(e),
        };

        if let Some(fee) = fee {
            update_tx_fee(conn, spending_tx_ref, fee)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use ::transparent::{
        address::{Script, TransparentAddress},
        bundle::{Authorized as TransparentAuthorized, Bundle, OutPoint, TxIn, TxOut},
    };
    use assert_matches::assert_matches;
    use rusqlite::named_params;
    use transparent::keys::{IncomingViewingKey as _, NonHardenedChildIndex, TransparentKeyScope};
    use zcash_client_backend::{
        data_api::{
            Account as _, AccountBirthday, AccountPurpose, WalletWrite,
            chain::ChainState,
            scanning::{ScanPriority, ScanRange},
            testing::{TestBuilder, TestState},
        },
        wallet::{
            TransparentAddressObservation, TransparentInvolvement, transparent_address_observations,
        },
    };
    use zcash_keys::{
        encoding::AddressCodec,
        keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    };
    use zcash_primitives::{
        block::BlockHash,
        transaction::{Authorized, Transaction, TransactionData, TxVersion},
    };
    use zcash_protocol::{
        TxId,
        consensus::{self, BlockHeight, BranchId, NetworkUpgrade, Parameters as _},
        local_consensus::LocalNetwork,
        value::{MAX_MONEY, Zatoshis},
    };
    use zcash_script::script;
    use zip32::AccountId;

    use super::{Involvement, ReconcileScope, backfill_observations, put_observations};
    use crate::{
        GapLimits, TxRef,
        error::SqliteClientError,
        testing::{
            BlockCache,
            db::{TestDb, TestDbFactory},
        },
        wallet::{
            get_account_ref,
            scanning::{insert_queue_entries, priority_code, suggest_scan_ranges},
            transparent::{find_gap_start, generate_gap_addresses, reconcile_and_extend_gaps},
        },
    };

    /// A validly-encoded compressed public key: the `0x02` prefix followed by 32 bytes.
    fn pubkey_bytes() -> Vec<u8> {
        let mut bytes = vec![0x02];
        bytes.extend_from_slice(&[0x11; 32]);
        bytes
    }

    /// Builds a push-only script from the given data pushes, each at most 75 bytes so that the
    /// single-byte length encoding applies.
    fn push_script(pushes: &[&[u8]]) -> Script {
        let mut code = vec![];
        for data in pushes {
            code.push(u8::try_from(data.len()).expect("test pushes are shorter than 76 bytes"));
            code.extend_from_slice(data);
        }
        Script(script::Code(code))
    }

    /// A transaction with the given transparent inputs and outputs, and no shielded bundles.
    fn transaction(vin: Vec<TxIn<TransparentAuthorized>>, vout: Vec<TxOut>) -> Transaction {
        let bundle = Bundle::<TransparentAuthorized> {
            vin,
            vout,
            authorization: TransparentAuthorized,
        };

        TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            BlockHeight::from(0),
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            Zatoshis::ZERO,
            Some(bundle),
            None,
            None,
            None,
        )
        .freeze()
        .expect("transaction data is complete")
    }

    /// A transaction paying `recipient` and spending `prevout` with a P2PKH `scriptSig`.
    fn test_transaction(recipient: TransparentAddress, prevout: OutPoint) -> Transaction {
        paying_tx(recipient, 100_000, prevout)
    }

    /// An observation row as read back for comparison: the involvement direction, the item
    /// index, the encoded address, the value, and the prevout index.
    type ObservationRow = (i64, u32, String, Option<i64>, Option<u32>);

    /// Reads back every observation row for a transaction.
    fn stored_observations(conn: &rusqlite::Connection, tx_ref: TxRef) -> Vec<ObservationRow> {
        let mut stmt = conn
            .prepare(
                "SELECT involvement, item_index, address, value_zat, prevout_output_index
                 FROM transparent_tx_address_observations
                 WHERE transaction_id = :transaction_id
                 ORDER BY involvement, item_index",
            )
            .unwrap();
        stmt.query_map(named_params! { ":transaction_id": tx_ref.0 }, |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    }

    /// The index state does not depend on the order in which a transaction is observed, nor on
    /// how many times it is observed.
    ///
    /// A compact-block scan can express only the output direction, since a compact input
    /// carries no `scriptSig`; a full block and stored complete transaction data express both.
    /// Every feed writes the same output rows, so any sequence that includes a complete-data
    /// feed converges to the complete state, and a later compact observation cannot undo it.
    #[test]
    fn feed_order_is_confluent() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();

        let recipient = TransparentAddress::PublicKeyHash([0x22; 20]);
        let tx = test_transaction(recipient, OutPoint::new([0x33; 32], 7));

        // The complete-data feed, shared by full-block scanning and enhancement.
        let complete = transparent_address_observations(&tx);
        assert_eq!(complete.len(), 2);

        // The compact-block feed, which sees each output's value and script but no `scriptSig`.
        let compact = complete
            .iter()
            .filter(|o| matches!(o.involvement(), TransparentInvolvement::Output(_)))
            .cloned()
            .collect::<Vec<TransparentAddressObservation>>();
        assert_eq!(compact.len(), 1);

        let conn = st.wallet().db().conn.unchecked_transaction().unwrap();

        // Each feed sequence is applied against its own transaction row, so that the resulting
        // index states can be compared directly.
        let apply = |tx_ref: TxRef, feeds: &[&[TransparentAddressObservation]]| {
            conn.execute(
                "INSERT INTO transactions (id_tx, txid, min_observed_height)
                 VALUES (:id_tx, :txid, 1)",
                named_params! { ":id_tx": tx_ref.0, ":txid": vec![u8::try_from(tx_ref.0).unwrap()] },
            )
            .unwrap();
            for feed in feeds {
                put_observations(&conn, &network, tx_ref, feed).unwrap();
            }
            stored_observations(&conn, tx_ref)
        };

        let compact_only = apply(TxRef(1), &[&compact]);
        let complete_only = apply(TxRef(2), &[&complete]);
        let compact_then_complete = apply(TxRef(3), &[&compact, &complete]);
        let complete_then_compact = apply(TxRef(4), &[&complete, &compact]);
        let repeated = apply(TxRef(5), &[&complete, &complete, &compact, &complete]);

        // Every sequence that includes a complete-data feed reaches the same state.
        assert_eq!(compact_then_complete, complete_only);
        assert_eq!(complete_then_compact, complete_only);
        assert_eq!(repeated, complete_only);

        // The compact feed writes exactly the output rows of the complete feed.
        assert_eq!(
            compact_only,
            complete_only
                .iter()
                .filter(|row| row.0 == Involvement::Output.encode())
                .cloned()
                .collect::<Vec<_>>()
        );

        assert_eq!(complete_only.len(), 2);
        assert_eq!(complete_only[0].0, Involvement::Output.encode());
        assert_eq!(complete_only[0].2, recipient.encode(&network));
        assert_eq!(complete_only[0].3, Some(100_000));
        assert_eq!(complete_only[1].0, Involvement::Input.encode());
        assert_eq!(complete_only[1].4, Some(7));

        conn.commit().unwrap();
    }

    /// The backfill records the observations of every transaction for which complete data is
    /// already stored, and ignores rows whose stored bytes do not parse.
    #[test]
    fn backfill_records_stored_transactions() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();

        let recipient = TransparentAddress::PublicKeyHash([0x55; 20]);
        let tx = test_transaction(recipient, OutPoint::new([0x66; 32], 3));
        let mut raw = vec![];
        tx.write(&mut raw).unwrap();

        let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, raw, expiry_height, min_observed_height)
             VALUES (1, :txid, :raw, 0, 1)",
            named_params! { ":txid": tx.txid().as_ref(), ":raw": raw },
        )
        .unwrap();
        // A transaction whose stored bytes are not a transaction at all.
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, raw, expiry_height, min_observed_height)
             VALUES (2, X'0102', X'DEADBEEF', 0, 1)",
            [],
        )
        .unwrap();
        // A transaction with no stored data at all.
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, min_observed_height) VALUES (3, X'0103', 1)",
            [],
        )
        .unwrap();

        backfill_observations(&conn, &network).unwrap();

        let recorded = stored_observations(&conn, TxRef(1));
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].2, recipient.encode(&network));
        assert!(stored_observations(&conn, TxRef(2)).is_empty());
        assert!(stored_observations(&conn, TxRef(3)).is_empty());

        conn.commit().unwrap();
    }

    /// Inserts a transaction into the wallet as though its complete data had been stored, and
    /// records the address observations that data yields.
    fn store_tx<P: consensus::Parameters>(
        conn: &rusqlite::Transaction<'_>,
        params: &P,
        tx: &Transaction,
        mined_height: Option<u32>,
    ) -> TxRef {
        let mut raw = vec![];
        tx.write(&mut raw).unwrap();

        let tx_ref = conn
            .query_row(
                "INSERT INTO transactions (txid, raw, expiry_height, mined_height,
                                           min_observed_height)
                 VALUES (:txid, :raw, 0, :mined_height, :observed_height)
                 RETURNING id_tx",
                named_params! {
                    ":txid": tx.txid().as_ref(),
                    ":raw": raw,
                    ":mined_height": mined_height,
                    ":observed_height": mined_height.unwrap_or(1),
                },
                |row| row.get::<_, i64>(0).map(TxRef),
            )
            .unwrap();

        put_observations(conn, params, tx_ref, &transparent_address_observations(tx)).unwrap();

        tx_ref
    }

    /// A transaction paying `value` to `recipient`, spending a single P2PKH input.
    fn paying_tx(recipient: TransparentAddress, value: u64, prevout: OutPoint) -> Transaction {
        transaction(
            vec![TxIn::from_parts(
                prevout,
                push_script(&[&[0x30; 71], &pubkey_bytes()]),
                0,
            )],
            vec![TxOut::new(
                Zatoshis::const_from_u64(value),
                Script::from(&recipient.script()),
            )],
        )
    }

    /// A transaction spending `prevout` with a `scriptSig` that reveals `pubkey`, and paying its
    /// whole value to an address the wallet does not control.
    #[cfg(feature = "transparent-key-import")]
    fn spending_tx(pubkey: &secp256k1::PublicKey, prevout: OutPoint, value: u64) -> Transaction {
        transaction(
            vec![TxIn::from_parts(
                prevout,
                push_script(&[&[0x30; 71], &pubkey.serialize()]),
                0,
            )],
            vec![TxOut::new(
                Zatoshis::const_from_u64(value),
                Script::from(&TransparentAddress::PublicKeyHash([0xEE; 20]).script()),
            )],
        )
    }

    /// The transparent address derived for the given account UFVK at the given external child
    /// index.
    fn external_address(ufvk: &UnifiedFullViewingKey, index: u32) -> TransparentAddress {
        ufvk.transparent()
            .expect("the test account has a transparent key")
            .derive_external_ivk()
            .expect("the external scope is derivable")
            .derive_address(NonHardenedChildIndex::from_index(index).expect("valid index"))
            .expect("the address is derivable")
    }

    /// The transparent change address derived for the given account UFVK at the given internal
    /// child index.
    fn internal_address(ufvk: &UnifiedFullViewingKey, index: u32) -> TransparentAddress {
        ufvk.transparent()
            .expect("the test account has a transparent key")
            .derive_internal_ivk()
            .expect("the internal scope is derivable")
            .derive_address(NonHardenedChildIndex::from_index(index).expect("valid index"))
            .expect("the address is derivable")
    }

    /// A transaction spending `prevout` and paying each `(recipient, value)` in order. Its
    /// `scriptSig` reveals an address no test wallet controls, so the transaction is recognized
    /// only through the output it spends.
    fn spending_tx_paying(prevout: OutPoint, outputs: &[(TransparentAddress, u64)]) -> Transaction {
        transaction(
            vec![TxIn::from_parts(
                prevout,
                push_script(&[&[0x30; 71], &pubkey_bytes()]),
                0,
            )],
            outputs
                .iter()
                .map(|(recipient, value)| {
                    TxOut::new(
                        Zatoshis::const_from_u64(*value),
                        Script::from(&recipient.script()),
                    )
                })
                .collect(),
        )
    }

    /// Reads the transparent rows of `v_tx_outputs` for the given transaction, as
    /// `(output_index, from_account_uuid, to_account_uuid)`.
    fn tx_output_accounts(
        conn: &rusqlite::Connection,
        txid: TxId,
    ) -> Vec<(u32, Option<uuid::Uuid>, Option<uuid::Uuid>)> {
        let mut stmt = conn
            .prepare(
                "SELECT output_index, from_account_uuid, to_account_uuid
                 FROM v_tx_outputs
                 WHERE txid = :txid AND output_pool = 0
                 ORDER BY output_index",
            )
            .unwrap();
        stmt.query_map(named_params! { ":txid": txid.as_ref() }, |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    }

    /// The transparent outputs an external-receipt consumer selects: those the wallet received
    /// for which it holds no record of a sender, and which are not flagged as change.
    fn unattributed_receipts(conn: &rusqlite::Connection) -> Vec<(Vec<u8>, u32)> {
        let mut stmt = conn
            .prepare(
                "SELECT t.txid, ro.output_index
                 FROM v_received_outputs ro
                 JOIN transactions t ON t.id_tx = ro.transaction_id
                 WHERE ro.pool = 0 AND ro.sent_note_id IS NULL AND ro.is_change = 0
                 ORDER BY t.txid, ro.output_index",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Reads the transparent outputs the wallet has recorded as received, as
    /// `(address, value, is_spent)`.
    fn received_outputs(conn: &rusqlite::Connection) -> Vec<(String, i64, bool)> {
        let mut stmt = conn
            .prepare(
                "SELECT tro.address, tro.value_zat,
                        EXISTS (
                            SELECT 1 FROM transparent_received_output_spends s
                            WHERE s.transparent_received_output_id = tro.id
                        )
                 FROM transparent_received_outputs tro
                 ORDER BY tro.address, tro.value_zat",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Reads the txids for which the wallet has recorded an intent to retrieve complete
    /// transaction data.
    fn enhancement_queue(conn: &rusqlite::Connection) -> Vec<Vec<u8>> {
        let mut stmt = conn
            .prepare("SELECT txid FROM tx_retrieval_queue WHERE query_type = 1 ORDER BY txid")
            .unwrap();
        stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Reads the outpoints the wallet is watching for a transparent spend.
    fn spend_search_queue(conn: &rusqlite::Connection) -> Vec<(Vec<u8>, u32)> {
        let mut stmt = conn
            .prepare(
                "SELECT t.txid, q.output_index
                 FROM transparent_spend_search_queue q
                 JOIN transactions t ON t.id_tx = q.transaction_id
                 ORDER BY t.txid, q.output_index",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Importing an account recognizes transactions the wallet already stored that pay the
    /// account's addresses. This is the case the index exists for: the transactions were checked
    /// against the address book when they were stored, at which point the account did not exist,
    /// and nothing checked them again.
    #[test]
    fn account_import_recognizes_stored_involvement() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let birthday = st.test_account().unwrap().birthday().clone();

        // An account the wallet does not hold, whose first two external addresses are paid by
        // transactions the wallet stores.
        let usk = UnifiedSpendingKey::from_seed(&network, &[0x5A; 32], AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();
        let addr0 = external_address(&ufvk, 0);
        let addr1 = external_address(&ufvk, 1);

        let mined_height = u32::from(birthday.height()) + 10;
        let funding0 = OutPoint::new([0xA0; 32], 0);
        let funding1 = OutPoint::new([0xA1; 32], 1);
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_tx(
                &conn,
                &network,
                &paying_tx(addr0, 100_000, funding0.clone()),
                Some(mined_height),
            );
            store_tx(
                &conn,
                &network,
                &paying_tx(addr1, 200_000, funding1.clone()),
                Some(mined_height + 1),
            );
            conn.commit().unwrap();
        }

        // Before the import, none of this is wallet state.
        assert!(received_outputs(&st.wallet().db().conn).is_empty());

        let account = st
            .wallet_mut()
            .import_account_ufvk("imported", &ufvk, &birthday, AccountPurpose::ViewOnly, None)
            .unwrap();

        let conn = &st.wallet().db().conn;

        // Both outputs are now held by the imported account.
        assert_eq!(received_outputs(conn), {
            let mut expected = vec![
                (addr0.encode(&network), 100_000, false),
                (addr1.encode(&network), 200_000, false),
            ];
            expected.sort();
            expected
        });

        // The gap has advanced past the highest recognized index.
        let tx = conn.unchecked_transaction().unwrap();
        let account_ref = get_account_ref(&tx, account.id()).unwrap();
        assert_eq!(
            find_gap_start(
                &tx,
                account_ref,
                TransparentKeyScope::EXTERNAL,
                GapLimits::default().external(),
            )
            .unwrap(),
            NonHardenedChildIndex::from_index(2),
        );
        drop(tx);

        // Each recognized output is watched for a spend, and the transactions that funded the
        // transactions paying the wallet are requested so that transparent history can be
        // traced.
        assert_eq!(spend_search_queue(conn).len(), 2);
        let mut expected_requests = vec![funding0.hash().to_vec(), funding1.hash().to_vec()];
        expected_requests.sort();
        assert_eq!(enhancement_queue(conn), expected_requests);
    }

    /// Advancing the gap limit recognizes stored involvement with each address the advance
    /// exposes, and an address recognized in one window moves the gap far enough to expose the
    /// next, so a single call converges on involvement straddling several windows.
    #[test]
    fn gap_advance_reaches_a_fixpoint_across_windows() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account = st.test_account().unwrap();
        let account_uuid = account.id();
        let birthday_height = u32::from(account.birthday().height());
        let ufvk = account.usk().to_unified_full_viewing_key();

        // With the default external gap limit of 10, these indices straddle three successive
        // windows: 0..10 exposes 3, whose use moves the gap to 4..14, which exposes 12, whose
        // use moves it to 13..23, which exposes 21.
        let involved_indices = [3u32, 12, 21];
        let addresses = involved_indices
            .iter()
            .map(|i| external_address(&ufvk, *i))
            .collect::<Vec<_>>();

        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            for (n, address) in addresses.iter().enumerate() {
                store_tx(
                    &conn,
                    &network,
                    &paying_tx(
                        *address,
                        10_000,
                        OutPoint::new([u8::try_from(n).unwrap(); 32], 0),
                    ),
                    Some(birthday_height + 10 + u32::try_from(n).unwrap()),
                );
            }
            conn.commit().unwrap();
        }

        // A gap advance with no import: nothing has changed but the wallet's own gap machinery.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            let account_ref = get_account_ref(&conn, account_uuid).unwrap();
            generate_gap_addresses(
                &conn,
                &network,
                &GapLimits::default(),
                account_ref,
                TransparentKeyScope::EXTERNAL,
                UnifiedAddressRequest::ALLOW_ALL,
                false,
            )
            .unwrap();

            assert_eq!(
                find_gap_start(
                    &conn,
                    account_ref,
                    TransparentKeyScope::EXTERNAL,
                    GapLimits::default().external(),
                )
                .unwrap(),
                NonHardenedChildIndex::from_index(22),
                "the gap advanced past the highest recognized index",
            );
            conn.commit().unwrap();
        }

        let conn = &st.wallet().db().conn;
        let mut expected = addresses
            .iter()
            .map(|a| (a.encode(&network), 10_000, false))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(received_outputs(conn), expected);
        assert_eq!(spend_search_queue(conn).len(), involved_indices.len());
    }

    /// A stored transaction that only spends from a wallet address is recognized through its
    /// input observation. When the wallet does not hold the transaction that created the spent
    /// output, it records an intent to retrieve it.
    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn input_involvement_requests_an_absent_prevout() {
        use secp256k1::{Secp256k1, SecretKey};
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account_uuid = st.test_account().unwrap().id();
        let mined_height = u32::from(st.test_account().unwrap().birthday().height()) + 10;

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x2B; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        let prevout = OutPoint::new([0xC0; 32], 3);
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_tx(
                &conn,
                &network,
                &spending_tx(&pubkey, prevout.clone(), 50_000),
                Some(mined_height),
            );
            conn.commit().unwrap();
        }

        st.wallet_mut()
            .import_standalone_transparent_pubkey(account_uuid, pubkey)
            .unwrap();

        let conn = &st.wallet().db().conn;

        // The spent output is not recoverable from anything the wallet holds, so it asks for the
        // transaction that created it.
        assert_eq!(enhancement_queue(conn), vec![prevout.hash().to_vec()]);
        assert!(received_outputs(conn).is_empty());
    }

    /// When the wallet does hold the transaction that created the spent output, the output and
    /// its spend are recovered from stored data, with no request to the network.
    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn input_involvement_recovers_a_stored_prevout() {
        use secp256k1::{Secp256k1, SecretKey};
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account_uuid = st.test_account().unwrap().id();
        let mined_height = u32::from(st.test_account().unwrap().birthday().height()) + 10;

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x2B; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let address = TransparentAddress::from_pubkey(&pubkey);

        // The transaction that paid the address, which the wallet stores but has never
        // recognized, and the transaction that spends its output.
        let funding_tx = paying_tx(address, 75_000, OutPoint::new([0xB0; 32], 0));
        let prevout = OutPoint::new(funding_tx.txid().into(), 0);
        let spend_tx = spending_tx(&pubkey, prevout.clone(), 70_000);
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_tx(&conn, &network, &funding_tx, Some(mined_height));
            store_tx(&conn, &network, &spend_tx, Some(mined_height + 1));
            conn.commit().unwrap();
        }

        st.wallet_mut()
            .import_standalone_transparent_pubkey(account_uuid, pubkey)
            .unwrap();

        let conn = &st.wallet().db().conn;

        // The output is recovered from the stored transaction and recorded as spent.
        assert_eq!(
            received_outputs(conn),
            vec![(address.encode(&network), 75_000, true)]
        );

        // Nothing the wallet needs is missing, so it asks for nothing it already holds: the only
        // request is for the transaction that funded the one paying the wallet.
        assert_eq!(enhancement_queue(conn), vec![vec![0xB0; 32]]);
    }

    /// Reads the scan queue as `(start, end, priority)`, ordered by start height.
    fn scan_queue(conn: &rusqlite::Connection) -> Vec<(u32, u32, i64)> {
        let mut stmt = conn
            .prepare(
                "SELECT block_range_start, block_range_end, priority
                 FROM scan_queue ORDER BY block_range_start",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Involvement mined below an account's birthday lowers the birthday to the earliest height
    /// at which the account is now known to have been active, and queues the range this widens
    /// for scanning in every pool.
    #[test]
    fn involvement_below_the_birthday_lowers_it() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let activation = u32::from(st.test_account().unwrap().birthday().height());

        // An account whose recorded birthday is later than its earliest activity.
        let claimed_birthday_height = activation + 100;
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(
                BlockHeight::from(claimed_birthday_height - 1),
                BlockHash([1; 32]),
            ),
            None,
        );
        let usk = UnifiedSpendingKey::from_seed(&network, &[0x77; 32], AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();

        let earliest = activation + 20;
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            for (index, height) in [(0u32, activation + 40), (1, earliest)] {
                store_tx(
                    &conn,
                    &network,
                    &paying_tx(
                        external_address(&ufvk, index),
                        20_000,
                        OutPoint::new([u8::try_from(index).unwrap(); 32], 0),
                    ),
                    Some(height),
                );
            }
            conn.commit().unwrap();
        }

        let account = st
            .wallet_mut()
            .import_account_ufvk("imported", &ufvk, &birthday, AccountPurpose::ViewOnly, None)
            .unwrap();

        let conn = &st.wallet().db().conn;

        // The birthday follows the earliest height at which the account is now known to have
        // been involved, not the later of the two.
        assert_eq!(
            crate::wallet::account_birthday(conn, account.id()).unwrap(),
            BlockHeight::from(earliest),
        );

        // The widened range is queued for scanning, at a priority that will advance the
        // fully-scanned height.
        let historic = priority_code(&ScanPriority::Historic);
        assert!(
            scan_queue(conn).iter().any(|(start, end, priority)| {
                *priority == historic && *start <= earliest && *end >= claimed_birthday_height
            }),
            "the range from the lowered birthday to the claimed one is queued: {:?}",
            scan_queue(conn),
        );
    }

    /// The index migration recovers involvement from a wallet that already holds complete
    /// transaction data: it populates the index from the stored transactions, then checks the
    /// whole index against the address book. Both steps are exercised here in the order the
    /// migration runs them, against a wallet whose stored transaction pays an address that was
    /// never recognized.
    #[test]
    fn migration_backfill_recovers_stored_involvement() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account = st.test_account().unwrap();
        let birthday_height = u32::from(account.birthday().height());
        let ufvk = account.usk().to_unified_full_viewing_key();
        let address = external_address(&ufvk, 4);

        // A wallet as it stands before the migration: complete transaction data is stored, and
        // nothing records which addresses that data names.
        let tx = paying_tx(address, 31_000, OutPoint::new([0xE0; 32], 0));
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_tx(&conn, &network, &tx, Some(birthday_height + 10));
            conn.execute("DELETE FROM transparent_tx_address_observations", [])
                .unwrap();
            conn.commit().unwrap();
        }
        assert!(received_outputs(&st.wallet().db().conn).is_empty());

        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            backfill_observations(&conn, &network).unwrap();
            reconcile_and_extend_gaps(
                &conn,
                &network,
                &GapLimits::default(),
                ReconcileScope::AllAddresses,
            )
            .unwrap();
            conn.commit().unwrap();
        }

        assert_eq!(
            received_outputs(&st.wallet().db().conn),
            vec![(address.encode(&network), 31_000, false)]
        );
    }

    /// Reconciliation is idempotent: running it again over the same addresses records nothing
    /// further, whatever the wallet has already recorded.
    #[test]
    fn reconciliation_is_idempotent() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account = st.test_account().unwrap();
        let account_uuid = account.id();
        let birthday_height = u32::from(account.birthday().height());
        let ufvk = account.usk().to_unified_full_viewing_key();
        let address = external_address(&ufvk, 3);

        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_tx(
                &conn,
                &network,
                &paying_tx(address, 42_000, OutPoint::new([0xD0; 32], 0)),
                Some(birthday_height + 10),
            );
            conn.commit().unwrap();
        }

        let snapshot = |st: &TestState<_, TestDb, _>| {
            let conn = &st.wallet().db().conn;
            (
                received_outputs(conn),
                enhancement_queue(conn),
                spend_search_queue(conn),
            )
        };

        let reconcile = |st: &mut TestState<_, TestDb, _>| {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            let account_ref = get_account_ref(&conn, account_uuid).unwrap();
            generate_gap_addresses(
                &conn,
                &network,
                &GapLimits::default(),
                account_ref,
                TransparentKeyScope::EXTERNAL,
                UnifiedAddressRequest::ALLOW_ALL,
                false,
            )
            .unwrap();
            conn.commit().unwrap();
        };

        reconcile(&mut st);
        let after_first = snapshot(&st);
        assert_eq!(after_first.0.len(), 1);

        reconcile(&mut st);
        assert_eq!(snapshot(&st), after_first);

        // An explicit whole-book pass, as an account import and the index backfill run, reaches
        // the same state.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            reconcile_and_extend_gaps(
                &conn,
                &network,
                &GapLimits::default(),
                ReconcileScope::AllAddresses,
            )
            .unwrap();
            conn.commit().unwrap();
        }
        assert_eq!(snapshot(&st), after_first);
    }

    /// Reads back every observation row in the wallet, as `(involvement, address)`.
    fn all_observed_addresses(conn: &rusqlite::Connection) -> Vec<(i64, String)> {
        let mut stmt = conn
            .prepare(
                "SELECT involvement, address FROM transparent_tx_address_observations
                 ORDER BY involvement, address",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Scanning a compact block that pays the wallet records the addresses paid by every output
    /// of that transaction, including those the wallet does not control. A compact input carries
    /// no `scriptSig`, so no input observation is available at this fidelity.
    #[test]
    fn compact_scan_feeds_the_index() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let ufvk = st
            .test_account()
            .unwrap()
            .usk()
            .to_unified_full_viewing_key();

        let wallet_address = external_address(&ufvk, 0);
        let other_address = TransparentAddress::PublicKeyHash([0x9E; 20]);

        let (h, _, _) = st.generate_next_block_transparent(
            &[OutPoint::new([0x77; 32], 1)],
            &[
                (wallet_address, Zatoshis::const_from_u64(60_000)),
                (other_address, Zatoshis::const_from_u64(40_000)),
            ],
        );
        st.scan_cached_blocks(h, 1);

        assert_eq!(
            all_observed_addresses(&st.wallet().db().conn),
            vec![
                (Involvement::Output.encode(), other_address.encode(&network)),
                (
                    Involvement::Output.encode(),
                    wallet_address.encode(&network)
                ),
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>(),
        );
    }

    /// Storing complete transaction data records both involvement directions, for every address
    /// the data names.
    #[test]
    fn store_decrypted_tx_feeds_the_index() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account = st.test_account().unwrap();
        let birthday_height = account.birthday().height();
        let ufvk = account.usk().to_unified_full_viewing_key();

        let wallet_address = external_address(&ufvk, 0);
        let prevout = OutPoint::new([0x88; 32], 2);
        let tx = paying_tx(wallet_address, 55_000, prevout.clone());

        // Recording a received output needs the wallet's view of the chain.
        st.wallet_mut()
            .db_mut()
            .update_chain_tip(birthday_height + 10)
            .unwrap();

        zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(
            &network,
            st.wallet_mut(),
            &tx,
            Some(birthday_height + 5),
        )
        .unwrap();

        let observed = all_observed_addresses(&st.wallet().db().conn);
        assert!(
            observed.contains(&(
                Involvement::Output.encode(),
                wallet_address.encode(&network)
            )),
            "the paid address is observed: {observed:?}",
        );
        assert!(
            observed
                .iter()
                .any(|(involvement, _)| *involvement == Involvement::Input.encode()),
            "the address the input's scriptSig reveals is observed: {observed:?}",
        );
    }

    /// A transaction the wallet itself created and stored for sending feeds the index too: the
    /// wallet holds its complete data, and it may pay an address no account has derived yet.
    #[test]
    fn store_transaction_to_be_sent_feeds_the_index() {
        use zcash_client_backend::data_api::{SentTransaction, wallet::TargetHeight};

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account = st.test_account().unwrap();
        let account_uuid = account.account().id();
        let target_height = TargetHeight::from(account.birthday().height() + 1);

        let recipient = TransparentAddress::PublicKeyHash([0xAB; 20]);
        let tx = paying_tx(recipient, 12_000, OutPoint::new([0x99; 32], 0));

        st.wallet_mut()
            .store_transactions_to_be_sent(&[SentTransaction::new(
                &tx,
                time::OffsetDateTime::now_utc(),
                target_height,
                account_uuid,
                &[],
                Zatoshis::const_from_u64(1_000),
                &[],
            )])
            .unwrap();

        let observed = all_observed_addresses(&st.wallet().db().conn);
        assert!(
            observed.contains(&(Involvement::Output.encode(), recipient.encode(&network))),
            "the address the wallet paid is observed: {observed:?}",
        );
    }

    /// Recording an empty set of observations touches nothing, so a caller may record the
    /// (empty) observations of a transaction whose row it has not created.
    #[test]
    fn empty_observations_touch_nothing() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();

        let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
        // `TxRef(1)` names no row, so a write here would violate the foreign key.
        put_observations(&conn, &network, TxRef(1), &[]).unwrap();
        assert!(all_observed_addresses(&conn).is_empty());
        conn.commit().unwrap();
    }

    /// Inserts a transaction row whose stored bytes are not a transaction, as a wallet that
    /// suffered partial data loss would hold.
    #[cfg(feature = "transparent-key-import")]
    fn store_truncated_tx(conn: &rusqlite::Transaction<'_>, txid: &[u8; 32], mined: u32) -> TxRef {
        conn.query_row(
            "INSERT INTO transactions (txid, raw, expiry_height, mined_height, min_observed_height)
             VALUES (:txid, X'DEADBEEF', 0, :mined, :mined)
             RETURNING id_tx",
            named_params! { ":txid": &txid[..], ":mined": mined },
            |row| row.get::<_, i64>(0).map(TxRef),
        )
        .unwrap()
    }

    /// Reconciliation must never fail on stored bytes it cannot parse. It runs inside the index
    /// migration, which cannot be reverted, so an error there would leave the wallet unable to
    /// open; the backfill that populates the index already skips such rows, and every path that
    /// reads them back has to agree.
    ///
    /// Two sites read stored transactions back: recovering the output an input spends, and
    /// recomputing the fee of a transaction that spends a recovered output. Both are lenient
    /// shared code, reached from either path, so each is exercised once here: the fee
    /// recomputation over the migration path, and the prevout recovery over the runtime paths
    /// (receiver import and gap advance), which are also shown to complete.
    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn unparseable_stored_transactions_do_not_abort_reconciliation() {
        use secp256k1::{Secp256k1, SecretKey};

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::file_backed())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account = st.test_account().unwrap();
        let account_uuid = account.account().id();
        let birthday_height = u32::from(account.birthday().height());
        let ufvk = account.usk().to_unified_full_viewing_key();

        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[0x4D; 32]).unwrap(),
        );

        // Hazard 1: transaction B spends an output of transaction A, whose stored bytes are
        // truncated, and reveals an address the wallet is about to import.
        let truncated_txid = [0xA0; 32];
        let prevout = OutPoint::new(truncated_txid, 0);

        // Hazard 2: transaction C spends an output paying a derived address of this wallet, and
        // its own stored bytes are truncated. Recognizing that output triggers a fee
        // recomputation that must skip C rather than fail on it.
        let derived = external_address(&ufvk, 3);
        let funding_tx = paying_tx(derived, 90_000, OutPoint::new([0xB0; 32], 0));
        let funding_txid = funding_tx.txid();

        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_truncated_tx(&conn, &truncated_txid, birthday_height + 1);
            store_tx(
                &conn,
                &network,
                &spending_tx(&pubkey, prevout.clone(), 30_000),
                Some(birthday_height + 2),
            );
            store_tx(&conn, &network, &funding_tx, Some(birthday_height + 3));

            let unparseable_spender = store_truncated_tx(&conn, &[0xC0; 32], birthday_height + 4);
            conn.execute(
                "INSERT INTO transparent_spend_map
                    (spending_transaction_id, prevout_txid, prevout_output_index)
                 VALUES (:spending_tx, :prevout_txid, 0)",
                named_params! {
                    ":spending_tx": unparseable_spender.0,
                    ":prevout_txid": funding_txid.as_ref(),
                },
            )
            .unwrap();
            conn.commit().unwrap();
        }

        // The migration path: backfill, then check the whole index against the address book.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            backfill_observations(&conn, &network).unwrap();
            reconcile_and_extend_gaps(
                &conn,
                &network,
                &GapLimits::default(),
                ReconcileScope::AllAddresses,
            )
            .expect("unparseable stored data does not abort the migration");
            conn.commit().unwrap();
        }

        // The derived address was recognized despite the unparseable transaction that spends it.
        assert!(
            received_outputs(&st.wallet().db().conn)
                .iter()
                .any(|(address, _, _)| *address == derived.encode(&network)),
        );

        // The runtime path: importing the receiver that transaction B's `scriptSig` reveals.
        st.wallet_mut()
            .import_standalone_transparent_pubkey(account_uuid, pubkey)
            .expect("unparseable stored data does not abort an import");

        // The unrecoverable prevout yields no received output, and no error. Reconciliation asks
        // for the transaction that created it, but `queue_tx_retrieval` records enhancement
        // intent only for a transaction whose data the wallet lacks, and this row does hold
        // data — unusable data. Re-requesting it is that helper's decision to make, not this
        // module's; what matters here is that the wallet neither fails nor invents an output.
        assert!(
            !received_outputs(&st.wallet().db().conn)
                .iter()
                .any(|(_, value, _)| *value == 30_000),
        );

        // And the runtime gap-advance path likewise completes.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            let account_ref = get_account_ref(&conn, account_uuid).unwrap();
            generate_gap_addresses(
                &conn,
                &network,
                &GapLimits::default(),
                account_ref,
                TransparentKeyScope::EXTERNAL,
                UnifiedAddressRequest::ALLOW_ALL,
                false,
            )
            .expect("unparseable stored data does not abort a gap advance");
            conn.commit().unwrap();
        }

        // The wallet still opens: a fresh connection to the same file reads the schema back.
        let reopened = rusqlite::Connection::open(st.wallet().data_file_path()).unwrap();
        assert!(
            reopened
                .query_row(
                    "SELECT COUNT(*) FROM transparent_tx_address_observations",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
                > 0
        );
    }

    /// Recognizing involvement below Sapling activation still lowers the birthday — every height
    /// floor derived from it must follow the evidence — but queues no scanning below activation,
    /// where no shielded pool exists for the account to have history in.
    #[test]
    fn birthday_lowering_clamps_the_queued_range_to_activation() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let activation = u32::from(
            network
                .activation_height(NetworkUpgrade::Sapling)
                .expect("the test network activates Sapling"),
        );

        let claimed_birthday_height = activation + 100;
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(
                BlockHeight::from(claimed_birthday_height - 1),
                BlockHash([1; 32]),
            ),
            None,
        );
        let usk = UnifiedSpendingKey::from_seed(&network, &[0x9C; 32], AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();

        let below_activation = activation - 5;
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_tx(
                &conn,
                &network,
                &paying_tx(
                    external_address(&ufvk, 0),
                    17_000,
                    OutPoint::new([0xF0; 32], 0),
                ),
                Some(below_activation),
            );
            conn.commit().unwrap();
        }

        let account = st
            .wallet_mut()
            .import_account_ufvk("imported", &ufvk, &birthday, AccountPurpose::ViewOnly, None)
            .unwrap();

        let conn = &st.wallet().db().conn;

        // The birthday follows the evidence, below activation.
        assert_eq!(
            crate::wallet::account_birthday(conn, account.id()).unwrap(),
            BlockHeight::from(below_activation),
        );

        // No scan work is queued below activation.
        let historic = priority_code(&ScanPriority::Historic);
        let queued = scan_queue(conn);
        assert!(
            queued
                .iter()
                .all(|(start, _, priority)| *priority != historic || *start >= activation),
            "no Historic range starts below Sapling activation: {queued:?}",
        );
        assert!(
            queued.iter().any(|(start, end, priority)| {
                *priority == historic && *start == activation && *end >= claimed_birthday_height
            }),
            "the range from activation to the claimed birthday is queued: {queued:?}",
        );
    }

    /// Lowering a birthday leaves no `Ignored` range between the new birthday and the previous
    /// one. An `Ignored` entry reaching above the previous birthday is queued in full: were only
    /// the part of it below that birthday queued, the remainder would survive as a region
    /// `suggest_scan_ranges` never offers, which no later lowering revisits because the birthday
    /// no longer sits above it.
    #[test]
    fn birthday_lowering_requeues_ignored_ranges_in_full() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let activation = u32::from(st.test_account().unwrap().birthday().height());

        let claimed_birthday_height = activation + 1000;
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(
                BlockHeight::from(claimed_birthday_height - 1),
                BlockHash([4; 32]),
            ),
            None,
        );
        let usk = UnifiedSpendingKey::from_seed(&network, &[0xD3; 32], AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();

        let account = st
            .wallet_mut()
            .import_account_ufvk("imported", &ufvk, &birthday, AccountPurpose::ViewOnly, None)
            .unwrap();
        let chain_end = claimed_birthday_height + 500;
        st.wallet_mut()
            .db_mut()
            .update_chain_tip(BlockHeight::from(chain_end - 1))
            .unwrap();

        // A queue whose ignored region reaches above the recorded birthday, as it does wherever
        // the wallet's scanning floor once stood higher than that birthday. The region is
        // recorded in two adjacent entries, the shape a queue takes when successive writers each
        // skipped their own part of it.
        let ignored_split = claimed_birthday_height + 100;
        let ignored_end = claimed_birthday_height + 200;
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            conn.execute("DELETE FROM scan_queue", []).unwrap();
            insert_queue_entries(
                &conn,
                [
                    ScanRange::from_parts(
                        BlockHeight::from(activation)..BlockHeight::from(ignored_split),
                        ScanPriority::Ignored,
                    ),
                    ScanRange::from_parts(
                        BlockHeight::from(ignored_split)..BlockHeight::from(ignored_end),
                        ScanPriority::Ignored,
                    ),
                    ScanRange::from_parts(
                        BlockHeight::from(ignored_end)..BlockHeight::from(chain_end),
                        ScanPriority::Scanned,
                    ),
                ]
                .iter(),
            )
            .unwrap();
            conn.commit().unwrap();
        }

        let earlier = claimed_birthday_height - 300;
        zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(
            &network,
            st.wallet_mut(),
            &paying_tx(
                external_address(&ufvk, 0),
                29_000,
                OutPoint::new([0xD3; 32], 0),
            ),
            Some(BlockHeight::from(earlier)),
        )
        .unwrap();

        let conn = &st.wallet().db().conn;
        assert_eq!(
            crate::wallet::account_birthday(conn, account.id()).unwrap(),
            BlockHeight::from(earlier),
        );

        // Every height from the new birthday through the end of the formerly-ignored region is
        // offered for scanning, so `sync` skips none of it.
        let offered = suggest_scan_ranges(conn, ScanPriority::Historic).unwrap();
        assert!(
            offered.iter().any(|range| {
                u32::from(range.block_range().start) <= earlier
                    && u32::from(range.block_range().end) >= ignored_end
            }),
            "the widened range covers the whole formerly-ignored region: {offered:?}",
        );

        // The queue outside that region is untouched: what lies below the new birthday is still
        // ignored, and what was scanned above the region is still recorded as scanned.
        let queued = scan_queue(conn);
        assert!(
            queued.contains(&(activation, earlier, priority_code(&ScanPriority::Ignored))),
            "the range below the new birthday is still ignored: {queued:?}",
        );
        assert!(
            queued.contains(&(
                ignored_end,
                chain_end,
                priority_code(&ScanPriority::Scanned)
            )),
            "the scanned range above the widened one is untouched: {queued:?}",
        );
    }

    /// Store-time recognition lowers the birthday too, not only reconciliation: a transaction
    /// arriving for an address the wallet already holds is the same evidence of earlier activity
    /// as one recognized when the address arrives.
    #[test]
    fn store_time_recognition_lowers_the_birthday() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let activation = u32::from(st.test_account().unwrap().birthday().height());

        let claimed_birthday_height = activation + 100;
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(
                BlockHeight::from(claimed_birthday_height - 1),
                BlockHash([2; 32]),
            ),
            None,
        );
        let usk = UnifiedSpendingKey::from_seed(&network, &[0xB7; 32], AccountId::ZERO).unwrap();
        let ufvk = usk.to_unified_full_viewing_key();

        // The account is imported first, so its addresses are already in the book: recognition
        // happens when the transaction arrives, not when the address does.
        let account = st
            .wallet_mut()
            .import_account_ufvk("imported", &ufvk, &birthday, AccountPurpose::ViewOnly, None)
            .unwrap();
        st.wallet_mut()
            .db_mut()
            .update_chain_tip(BlockHeight::from(claimed_birthday_height + 10))
            .unwrap();

        let earlier = claimed_birthday_height - 40;
        let tx = paying_tx(
            external_address(&ufvk, 0),
            23_000,
            OutPoint::new([0xE1; 32], 0),
        );
        zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(
            &network,
            st.wallet_mut(),
            &tx,
            Some(BlockHeight::from(earlier)),
        )
        .unwrap();

        assert_eq!(
            crate::wallet::account_birthday(&st.wallet().db().conn, account.id()).unwrap(),
            BlockHeight::from(earlier),
        );
    }

    /// The cascade is confluent across trigger orders: importing an account and then advancing
    /// the gap reaches the same state as advancing the gap and then importing.
    #[test]
    fn cascade_is_confluent_across_trigger_orders() {
        let build = || {
            let st = TestBuilder::new()
                .with_data_store_factory(TestDbFactory::default())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();
            let network = *st.network();
            let account = st.test_account().unwrap();
            let birthday_height = u32::from(account.birthday().height());
            let host_ufvk = account.usk().to_unified_full_viewing_key();

            // One transaction pays an address of the wallet's existing account beyond its
            // current gap; another pays an address of an account not yet imported.
            let guest_usk =
                UnifiedSpendingKey::from_seed(&network, &[0x3F; 32], AccountId::ZERO).unwrap();
            let guest_ufvk = guest_usk.to_unified_full_viewing_key();

            {
                let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
                store_tx(
                    &conn,
                    &network,
                    &paying_tx(
                        external_address(&host_ufvk, 4),
                        11_000,
                        OutPoint::new([0x51; 32], 0),
                    ),
                    Some(birthday_height + 5),
                );
                store_tx(
                    &conn,
                    &network,
                    &paying_tx(
                        external_address(&guest_ufvk, 1),
                        22_000,
                        OutPoint::new([0x52; 32], 0),
                    ),
                    Some(birthday_height + 6),
                );
                conn.commit().unwrap();
            }

            (st, guest_ufvk)
        };

        let advance_gap = |st: &TestState<_, TestDb, _>, network: &LocalNetwork| {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            let mut stmt = conn.prepare("SELECT id FROM accounts").unwrap();
            let ids = stmt
                .query_map([], |row| row.get::<_, i64>(0).map(crate::AccountRef))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            drop(stmt);
            for account_ref in ids {
                generate_gap_addresses(
                    &conn,
                    network,
                    &GapLimits::default(),
                    account_ref,
                    TransparentKeyScope::EXTERNAL,
                    UnifiedAddressRequest::ALLOW_ALL,
                    false,
                )
                .unwrap();
            }
            conn.commit().unwrap();
        };

        let snapshot = |st: &TestState<_, TestDb, _>| {
            let conn = &st.wallet().db().conn;
            (
                received_outputs(conn),
                enhancement_queue(conn),
                spend_search_queue(conn),
                all_observed_addresses(conn),
            )
        };

        // Order A: import, then advance the gap.
        let (mut st_a, guest_ufvk) = build();
        let network = *st_a.network();
        let birthday = st_a.test_account().unwrap().birthday().clone();
        st_a.wallet_mut()
            .import_account_ufvk(
                "guest",
                &guest_ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap();
        advance_gap(&st_a, &network);

        // Order B: advance the gap, then import.
        let (mut st_b, guest_ufvk_b) = build();
        advance_gap(&st_b, &network);
        st_b.wallet_mut()
            .import_account_ufvk(
                "guest",
                &guest_ufvk_b,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap();

        assert_eq!(snapshot(&st_a), snapshot(&st_b));
        assert_eq!(snapshot(&st_a).0.len(), 2);
    }

    /// A cascade that fails partway leaves nothing behind: the reconciliation writes are many,
    /// and they are only ever issued inside a caller-provided transaction.
    #[test]
    fn cascade_rolls_back_on_error() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account = st.test_account().unwrap();
        let birthday_height = u32::from(account.birthday().height());
        let ufvk = account.usk().to_unified_full_viewing_key();

        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_tx(
                &conn,
                &network,
                &paying_tx(
                    external_address(&ufvk, 2),
                    64_000,
                    OutPoint::new([0x6A; 32], 0),
                ),
                Some(birthday_height + 7),
            );
            conn.commit().unwrap();
        }

        assert!(received_outputs(&st.wallet().db().conn).is_empty());

        let result = st
            .wallet_mut()
            .db_mut()
            .transactionally::<_, (), SqliteClientError>(|wdb| {
                reconcile_and_extend_gaps(
                    wdb.conn.0,
                    &network,
                    &GapLimits::default(),
                    ReconcileScope::AllAddresses,
                )?;
                // The cascade has written by this point; the error is what unwinds it.
                Err(SqliteClientError::ChainHeightUnknown)
            });

        assert_matches!(result, Err(SqliteClientError::ChainHeightUnknown));
        assert!(
            received_outputs(&st.wallet().db().conn).is_empty(),
            "no part of the cascade persisted",
        );
    }

    /// A stored transaction whose value balances do not sum within range parses cleanly but has
    /// no computable fee. Reconciliation recomputes the fee of every transaction that spends an
    /// output it recognizes, so such a transaction must be skipped there for the same reason
    /// unparseable bytes are: nothing in this module may fail on data the wallet already holds.
    #[test]
    fn fee_computation_overflow_does_not_abort_reconciliation() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account = st.test_account().unwrap();
        let birthday_height = u32::from(account.birthday().height());
        let ufvk = account.usk().to_unified_full_viewing_key();

        let derived = external_address(&ufvk, 5);
        let funding_tx = paying_tx(derived, 90_000, OutPoint::new([0xD1; 32], 0));
        let funding_txid = funding_tx.txid();

        // Three outputs of the whole money supply sum past the representable range, so
        // `Transaction::fee_paid` reports an overflow rather than a fee.
        let overflow_tx = transaction(
            vec![TxIn::from_parts(
                OutPoint::new(funding_txid.into(), 0),
                push_script(&[&[0x30; 71], &pubkey_bytes()]),
                0,
            )],
            (0..3)
                .map(|_| {
                    TxOut::new(
                        Zatoshis::const_from_u64(MAX_MONEY),
                        Script::from(&TransparentAddress::PublicKeyHash([0xD2; 20]).script()),
                    )
                })
                .collect(),
        );

        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_tx(&conn, &network, &funding_tx, Some(birthday_height + 3));
            let overflow_ref = store_tx(&conn, &network, &overflow_tx, Some(birthday_height + 4));
            // The spend is recorded against the outpoint, so recognizing the funding output
            // links it and brings the overflowing transaction into the fee recomputation.
            conn.execute(
                "INSERT INTO transparent_spend_map
                    (spending_transaction_id, prevout_txid, prevout_output_index)
                 VALUES (:spending_tx, :prevout_txid, 0)",
                named_params! {
                    ":spending_tx": overflow_ref.0,
                    ":prevout_txid": funding_txid.as_ref(),
                },
            )
            .unwrap();
            conn.commit().unwrap();
        }

        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            backfill_observations(&conn, &network).unwrap();
            reconcile_and_extend_gaps(
                &conn,
                &network,
                &GapLimits::default(),
                ReconcileScope::AllAddresses,
            )
            .expect("an uncomputable fee does not abort reconciliation");
            conn.commit().unwrap();
        }

        // The output was recognized, and the transaction with no computable fee still has none.
        let conn = &st.wallet().db().conn;
        assert!(
            received_outputs(conn)
                .iter()
                .any(|(address, _, _)| *address == derived.encode(&network)),
        );
        assert!(
            conn.query_row(
                "SELECT fee IS NULL FROM transactions WHERE txid = :txid",
                named_params! { ":txid": overflow_tx.txid().as_ref() },
                |row| row.get::<_, bool>(0),
            )
            .unwrap(),
            "the transaction with no computable fee still has none",
        );
    }

    /// The state a wallet is left in when a transaction reaches it before the output that
    /// transaction spends: the transaction is stored and its payment to a wallet account is
    /// recorded, but no account is known to have funded it, so the spend is held against the
    /// outpoint and nothing records which account paid for its outputs.
    ///
    /// Returns the spending transaction and the guest account's key.
    fn store_spend_before_its_prevout<C>(
        st: &mut TestState<C, TestDb, LocalNetwork>,
        host_address: TransparentAddress,
        stranger: TransparentAddress,
    ) -> (Transaction, UnifiedFullViewingKey) {
        let network = *st.network();
        let birthday_height = u32::from(st.test_account().unwrap().birthday().height());

        // An account the wallet has not yet imported, which funds the spending transaction.
        let guest_usk = UnifiedSpendingKey::from_seed(&network, &[0x2E; 32], AccountId::ZERO)
            .expect("the seed is a valid spending key seed");
        let guest_ufvk = guest_usk.to_unified_full_viewing_key();

        let funding_tx = paying_tx(
            external_address(&guest_ufvk, 0),
            400_000,
            OutPoint::new([0xF5; 32], 0),
        );
        let spend_tx = spending_tx_paying(
            OutPoint::new(funding_tx.txid().into(), 0),
            &[
                (internal_address(&guest_ufvk, 0), 250_000),
                (host_address, 100_000),
                (stranger, 40_000),
            ],
        );

        st.wallet_mut()
            .db_mut()
            .update_chain_tip(BlockHeight::from(birthday_height + 20))
            .unwrap();

        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_tx(&conn, &network, &funding_tx, Some(birthday_height + 5));
            conn.commit().unwrap();
        }

        zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(
            &network,
            st.wallet_mut(),
            &spend_tx,
            Some(BlockHeight::from(birthday_height + 6)),
        )
        .unwrap();

        (spend_tx, guest_ufvk)
    }

    /// Recognizing the output a stored transaction spends links the spend, which is the moment
    /// the wallet learns which account funded that transaction. The funding attribution of its
    /// outputs has to be re-derived then: `store_decrypted_tx` derived none when the transaction
    /// was stored, because the spent output was not yet the wallet's, and nothing revisits a
    /// stored transaction on its own.
    ///
    /// The spending transaction's `scriptSig` names no wallet address here, so the only thing
    /// that recognizes it is the recovery of the output it spends.
    #[test]
    fn late_spend_linkage_attributes_the_spending_transaction() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let host = st.test_account().unwrap();
        let host_uuid = host.account().id().expose_uuid();
        let birthday = host.birthday().clone();
        let host_address = external_address(&host.usk().to_unified_full_viewing_key(), 0);
        let stranger = TransparentAddress::PublicKeyHash([0x77; 20]);

        let (spend_tx, guest_ufvk) =
            store_spend_before_its_prevout(&mut st, host_address, stranger);
        let spend_txid = spend_tx.txid();

        // The wallet holds the payment to the host account as a receipt from nobody: this is the
        // shape an external-receipt consumer misreads as a payment requiring a cost basis.
        assert_eq!(
            tx_output_accounts(&st.wallet().db().conn, spend_txid),
            vec![(1, None, Some(host_uuid))],
        );
        assert!(
            unattributed_receipts(&st.wallet().db().conn)
                .contains(&(spend_txid.as_ref().to_vec(), 1)),
        );

        // Importing the account that was paid by the spent output recognizes that output, which
        // links the spend and reveals which account funded the spending transaction.
        let guest_uuid = st
            .wallet_mut()
            .import_account_ufvk(
                "guest",
                &guest_ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap()
            .id()
            .expose_uuid();

        let conn = &st.wallet().db().conn;

        // Every output of the spending transaction now reports the account that funded it: the
        // change returned to that account, the transfer to another account of the same wallet,
        // and the payment to a recipient outside the wallet, which is a sent output with no
        // receiving account.
        assert_eq!(
            tx_output_accounts(conn, spend_txid),
            vec![
                (0, Some(guest_uuid), Some(guest_uuid)),
                (1, Some(guest_uuid), Some(host_uuid)),
                (2, Some(guest_uuid), None),
            ],
        );

        // Neither wallet-received output is an external receipt any longer.
        assert!(
            unattributed_receipts(conn)
                .iter()
                .all(|(txid, _)| txid != spend_txid.as_ref()),
            "no output of the spending transaction is reported as a receipt from nobody: {:?}",
            unattributed_receipts(conn),
        );
    }

    /// The attribution replay is idempotent, and repairs a wallet in which the spend is already
    /// linked but the attribution is missing — which is the state every wallet upgraded before
    /// the replay existed is in.
    #[test]
    fn attribution_replay_is_idempotent_and_repairs() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let host = st.test_account().unwrap();
        let birthday = host.birthday().clone();
        let host_address = external_address(&host.usk().to_unified_full_viewing_key(), 0);
        let stranger = TransparentAddress::PublicKeyHash([0x77; 20]);

        let (spend_tx, guest_ufvk) =
            store_spend_before_its_prevout(&mut st, host_address, stranger);
        let spend_txid = spend_tx.txid();

        st.wallet_mut()
            .import_account_ufvk(
                "guest",
                &guest_ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap();

        let attributed = tx_output_accounts(&st.wallet().db().conn, spend_txid);
        assert_eq!(attributed.len(), 3);

        let reconcile = |st: &TestState<_, TestDb, _>| {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            reconcile_and_extend_gaps(
                &conn,
                &network,
                &GapLimits::default(),
                ReconcileScope::AllAddresses,
            )
            .unwrap();
            conn.commit().unwrap();
        };

        reconcile(&st);
        assert_eq!(
            tx_output_accounts(&st.wallet().db().conn, spend_txid),
            attributed,
            "a second pass records nothing further",
        );

        // A wallet whose spend was linked before the replay existed holds the linkage without
        // the attribution. Reconciliation restores it.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            conn.execute(
                "DELETE FROM sent_notes
                 WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = :txid)",
                named_params! { ":txid": spend_txid.as_ref() },
            )
            .unwrap();
            conn.commit().unwrap();
        }
        assert!(
            unattributed_receipts(&st.wallet().db().conn)
                .iter()
                .any(|(txid, _)| txid == spend_txid.as_ref()),
        );

        reconcile(&st);
        assert_eq!(
            tx_output_accounts(&st.wallet().db().conn, spend_txid),
            attributed,
        );
    }

    /// A transaction recognized through the address its `scriptSig` reveals is attributed too:
    /// the direction in which the wallet learns of the spend does not change what the spend
    /// establishes about who funded the transaction.
    #[test]
    #[cfg(feature = "transparent-key-import")]
    fn input_involvement_attributes_the_spending_transaction() {
        use secp256k1::{Secp256k1, SecretKey};

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let account = st.test_account().unwrap();
        let account_uuid = account.account().id();
        let birthday_height = u32::from(account.birthday().height());

        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[0x6C; 32]).unwrap(),
        );
        let address = TransparentAddress::from_pubkey(&pubkey);

        // The transaction that paid the standalone address, and the transaction that spends its
        // output; the wallet stores both without ever having recognized either.
        let funding_tx = paying_tx(address, 80_000, OutPoint::new([0xB4; 32], 0));
        let spend_tx = spending_tx(&pubkey, OutPoint::new(funding_tx.txid().into(), 0), 70_000);
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            store_tx(&conn, &network, &funding_tx, Some(birthday_height + 3));
            store_tx(&conn, &network, &spend_tx, Some(birthday_height + 4));
            conn.commit().unwrap();
        }

        st.wallet_mut()
            .import_standalone_transparent_pubkey(account_uuid, pubkey)
            .unwrap();

        // The spend of the recovered output makes the spending transaction's own output a send
        // from the importing account to a recipient outside the wallet.
        assert_eq!(
            tx_output_accounts(&st.wallet().db().conn, spend_tx.txid()),
            vec![(0, Some(account_uuid.expose_uuid()), None)],
        );
    }
}
