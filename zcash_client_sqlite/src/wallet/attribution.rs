//! Reconstruction of the funding attribution of a stored transaction.
//!
//! Storing a transaction whose funding account is known records, for each of its outputs, the
//! account that paid for it and the recipient it paid. The funding account is derived from the
//! outputs the transaction spends, so a transaction that reaches the wallet before those outputs
//! are recognized carries no such record; the spend is linked later, and nothing revisits the
//! transaction. Its outputs are then reported forever as receipts from an unknown sender, and a
//! transfer between two accounts of one wallet reads as a payment from a stranger.
//!
//! This module replays the attribution step over the stored transaction data, in every pool, and
//! is called from the paths that link a spend without recording the transaction's recipients
//! themselves. It sits outside `transparent-inputs` because the defect does: a wallet with no
//! transparent support at all still spends shielded notes, and still links those spends late.

use rusqlite::{OptionalExtension, named_params};

use zcash_client_backend::{
    data_api::ll::{ReceivedShieldedOutput, wallet::shielded_sent_output_recipient},
    decrypt_transaction,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    PoolType, ShieldedPool,
    consensus::{self, BlockHeight, BranchId},
    value::Zatoshis,
};

use crate::{
    AccountUuid, TxRef,
    error::SqliteClientError,
    wallet::{
        chain_tip_height, encoding::pool_code, get_unified_full_viewing_keys, put_sent_output,
        select_receiving_address,
    },
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::transparent::find_account_uuid_for_transparent_address,
    zcash_client_backend::data_api::ll::wallet::{
        detect_wallet_transparent_outputs, transparent_sent_output_recipient,
    },
};

/// Parses stored transaction bytes, or returns `None` if they do not parse.
///
/// The consensus branch ID a transaction is parsed under does not affect the parse: versions
/// before v5 do not encode it, and v5 onward carry their own, so a placeholder suffices and no
/// height needs to be resolved for an unmined transaction with no expiry height.
///
/// Bytes that do not parse are data the wallet cannot act on. No caller may fail on them: the
/// paths that read them run inside migrations, which cannot be reverted, so an error there would
/// leave the wallet unable to open. Every path that reads stored bytes back agrees on skipping
/// them.
///
/// A failure here is permanent for that row: `queue_tx_retrieval` records enhancement intent
/// only for a transaction whose data the wallet lacks, and a row with unusable bytes still has
/// `raw` set, so no re-fetch is ever recorded for it.
pub(crate) fn parse_stored(raw: &[u8]) -> Option<Transaction> {
    Transaction::read(raw, BranchId::Sprout).ok()
}

/// Returns the wallet accounts that contributed inputs to the transaction with the
/// given internal id, paired with the total value each account contributed. Results
/// are ordered by total contributed value descending; ties are broken in favor of
/// the account whose oldest contributed input has the lowest mined height (with
/// unmined inputs sorting last), then by `accounts.id`.
///
/// The inner `UNION ALL` must carry one branch per pool in which the wallet can record a
/// received output: transparent, Sapling, Orchard, and Ironwood. A missing branch does not
/// produce an error, it silently under-counts the accounts that funded the transaction, so
/// a pool added to the schema without a branch here changes which account this reports.
///
/// The pools are enumerated here rather than read from the cross-pool `v_received_outputs`
/// view because that view has to be materialized in full to be joined by output id, which
/// scans every received-note table. This query is run once per candidate output, so it is
/// written to be satisfied from the spend tables' `transaction_id` indexes instead.
pub(crate) fn list_funding_accounts(
    conn: &rusqlite::Connection,
    creating_tx_id: i64,
) -> Result<Vec<(AccountUuid, Zatoshis)>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT a.uuid, contribs.total_value
         FROM accounts a
         JOIN (
             SELECT account_id,
                    SUM(value) AS total_value,
                    MIN(IFNULL(mined_height, 0x7FFFFFFF)) AS oldest_mined
             FROM (
                 SELECT tro.account_id, tro.value_zat AS value, t.mined_height AS mined_height
                 FROM transparent_received_outputs tro
                 JOIN transparent_received_output_spends tros
                   ON tros.transparent_received_output_id = tro.id
                 JOIN transactions t ON t.id_tx = tro.transaction_id
                 WHERE tros.transaction_id = :creating_tx_id
                 UNION ALL
                 SELECT srn.account_id, srn.value, t.mined_height
                 FROM sapling_received_notes srn
                 JOIN sapling_received_note_spends srns
                   ON srns.sapling_received_note_id = srn.id
                 JOIN transactions t ON t.id_tx = srn.transaction_id
                 WHERE srns.transaction_id = :creating_tx_id
                 UNION ALL
                 SELECT orn.account_id, orn.value, t.mined_height
                 FROM orchard_received_notes orn
                 JOIN orchard_received_note_spends orns
                   ON orns.orchard_received_note_id = orn.id
                 JOIN transactions t ON t.id_tx = orn.transaction_id
                 WHERE orns.transaction_id = :creating_tx_id
                 UNION ALL
                 SELECT irn.account_id, irn.value, t.mined_height
                 FROM ironwood_received_notes irn
                 JOIN ironwood_received_note_spends irns
                   ON irns.ironwood_received_note_id = irn.id
                 JOIN transactions t ON t.id_tx = irn.transaction_id
                 WHERE irns.transaction_id = :creating_tx_id
             )
             GROUP BY account_id
         ) contribs ON contribs.account_id = a.id
         ORDER BY contribs.total_value DESC, contribs.oldest_mined ASC, a.id ASC",
    )?;

    stmt.query_and_then(
        named_params![":creating_tx_id": creating_tx_id],
        |row| -> Result<(AccountUuid, Zatoshis), SqliteClientError> {
            let account = AccountUuid(row.get(0)?);
            let raw_value: i64 = row.get(1)?;
            let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
                SqliteClientError::CorruptedData(format!(
                    "Invalid funding contribution value: {raw_value}"
                ))
            })?;
            Ok((account, value))
        },
    )?
    .collect()
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
/// A transparent spend that block scanning links needs nothing from here: the query that makes
/// that link and the query that resolves a funding account match a prevout against
/// `transparent_received_outputs` under one and the same condition, so such a link can never
/// reveal an account that storing the transaction would have missed. A shielded spend is not so
/// placed. Its evidence is a nullifier, which scanning records in the nullifier map before the
/// note that reveals it is necessarily known, and that map is pruned behind the fully scanned
/// height; a note discovered after its entry is gone leaves the spend to be linked by a later
/// rescan, against a transaction whose data the wallet holds by then. So scanning calls in for
/// shielded spends, and the store-time path calls in with it, where the work is redundant but
/// bounded to one decryption by the guard in [`attribute_shielded_outputs`].
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

    #[cfg(feature = "transparent-inputs")]
    attribute_transparent_outputs(conn, params, tx_ref, &tx, tx_mined_height, funding_account)?;

    attribute_shielded_outputs(conn, params, tx_ref, &tx, tx_mined_height, funding_account)?;

    Ok(())
}

/// Records the sent outputs of the transparent bundle of a stored transaction that the wallet now
/// knows `funding_account` funded.
///
/// What a transparent output paid is written in the transaction itself, so this reads it directly
/// rather than decrypting anything.
#[cfg(feature = "transparent-inputs")]
fn attribute_transparent_outputs<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
    tx_ref: TxRef,
    tx: &Transaction,
    mined_height: Option<BlockHeight>,
    funding_account: AccountUuid,
) -> Result<(), SqliteClientError> {
    let outputs = detect_wallet_transparent_outputs::<_, AccountUuid, SqliteClientError>(
        params,
        tx,
        mined_height,
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

    Ok(())
}

/// Returns how many outputs the transaction produces in each shielded pool this build stores.
fn shielded_output_counts(tx: &Transaction) -> Vec<(PoolType, usize)> {
    #[allow(unused_mut)]
    let mut counts = vec![(
        PoolType::Shielded(ShieldedPool::Sapling),
        tx.sapling_bundle()
            .map_or(0, |bundle| bundle.shielded_outputs().len()),
    )];

    #[cfg(feature = "orchard")]
    {
        counts.push((
            PoolType::Shielded(ShieldedPool::Orchard),
            tx.orchard_bundle()
                .map_or(0, |bundle| bundle.actions().len()),
        ));
        counts.push((
            PoolType::Shielded(ShieldedPool::Ironwood),
            tx.ironwood_bundle()
                .map_or(0, |bundle| bundle.actions().len()),
        ));
    }

    counts
}

/// Returns whether any shielded output of the transaction has no recorded recipient.
///
/// The comparison is made pool by pool. A recipient row is unique per transaction, pool and
/// output index, and every index a writer uses is below that pool's output count, so a pool
/// holding as many rows as it has outputs holds one for each.
///
/// Only the pools this build stores are counted, on either side. A build without `orchard`
/// neither counts an Orchard action nor writes a recipient for one, and the rows an
/// Orchard-capable build left behind say nothing about whether this build's own pools are
/// complete: totalling across pools would let those rows stand in for a missing Sapling
/// recipient, and skip the very repair this exists for.
fn has_unrecorded_shielded_recipient(
    conn: &rusqlite::Connection,
    tx_ref: TxRef,
    tx: &Transaction,
) -> Result<bool, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT COUNT(*) FROM sent_notes
         WHERE transaction_id = :transaction_id
         AND output_pool = :output_pool",
    )?;

    for (pool, output_count) in shielded_output_counts(tx) {
        let recorded: usize = stmt.query_row(
            named_params! {
                ":transaction_id": tx_ref.0,
                ":output_pool": pool_code(pool),
            },
            |row| row.get(0),
        )?;

        if recorded < output_count {
            return Ok(true);
        }
    }

    Ok(false)
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
    // Trial decryption costs a key lookup and a pass over every output under every key. A count
    // per pool settles the cases that need neither: a transaction with no shielded output — the
    // common shape for one recognized through a transparent spend — and one whose shielded
    // outputs already carry a recipient apiece. This is what keeps the replay to a single
    // decryption when a caller links several spends of one transaction in turn.
    if !has_unrecorded_shielded_recipient(conn, tx_ref, tx)? {
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

/// Repairs the funding attribution of every stored transaction the wallet records as spending one
/// of its own notes or outputs, in any pool.
///
/// A wallet whose spends were linked before the attribution replay existed holds the linkage
/// without the attribution, and nothing revisits a stored transaction on its own. This restores
/// the invariant over the wallet's whole history; it writes nothing for a transaction that is
/// already attributed. Selecting a transaction that needs nothing costs only the two counts it
/// settles for, so the selection is pool-complete rather than tailored to which transactions
/// might need repair.
pub(crate) fn repair_funding_attribution<P: consensus::Parameters>(
    conn: &rusqlite::Transaction<'_>,
    params: &P,
) -> Result<(), SqliteClientError> {
    let spending_txs = {
        let mut stmt = conn.prepare(
            "SELECT t.id_tx
             FROM transactions t
             WHERE t.raw IS NOT NULL
             AND t.id_tx IN (
                 SELECT transaction_id FROM transparent_received_output_spends
                 UNION SELECT transaction_id FROM sapling_received_note_spends
                 UNION SELECT transaction_id FROM orchard_received_note_spends
                 UNION SELECT transaction_id FROM ironwood_received_note_spends
             )",
        )?;

        stmt.query_map([], |row| row.get::<_, i64>(0).map(TxRef))?
            .collect::<Result<Vec<_>, _>>()?
    };

    for tx_ref in spending_txs {
        attribute_funded_outputs(conn, params, tx_ref)?;
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use rand_core::OsRng;
    use rusqlite::named_params;
    use zcash_client_backend::data_api::{
        Account as _, AccountPurpose, TargetValue, WalletCommitmentTrees, WalletWrite,
        testing::{AddressType, TestBuilder, TestState},
        wallet::{
            ConfirmationsPolicy, TargetHeight, decrypt_and_store_transaction,
            input_selection::LockFilter,
        },
    };
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_primitives::{
        block::BlockHash,
        transaction::{
            Transaction,
            builder::{BuildConfig, Builder, BundlePadding},
            fees::zip317,
        },
    };
    use zcash_protocol::{
        PoolType, ShieldedPool, TxId, consensus::BlockHeight, local_consensus::LocalNetwork,
        memo::MemoBytes, value::Zatoshis,
    };
    use zip32::AccountId;

    use crate::{
        AccountUuid,
        error::SqliteClientError,
        testing::{
            BlockCache,
            db::{TestDb, TestDbFactory},
        },
        wallet::encoding::pool_code,
    };
    use schemerz_rusqlite::RusqliteMigration as _;

    use super::repair_funding_attribution;

    /// The `(from_account_uuid, to_account_uuid)` pairs `v_tx_outputs` reports for the given
    /// transaction in the given pool, in a fixed order.
    ///
    /// Neither the index nor the order of a shielded output is fixed by the transaction's shape,
    /// because the bundle is padded with dummy outputs and shuffled, so the index is dropped and
    /// the pairs are sorted.
    pub(crate) fn pool_output_parties(
        conn: &rusqlite::Connection,
        txid: TxId,
        pool: PoolType,
    ) -> Vec<(Option<uuid::Uuid>, Option<uuid::Uuid>)> {
        let mut stmt = conn
            .prepare(
                "SELECT from_account_uuid, to_account_uuid
                 FROM v_tx_outputs
                 WHERE txid = :txid AND output_pool = :pool
                 ORDER BY output_index",
            )
            .unwrap();
        let mut parties = stmt
            .query_map(
                named_params! { ":txid": txid.as_ref(), ":pool": pool_code(pool) },
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        parties.sort();
        parties
    }

    /// The given pairs in the order [`pool_output_parties`] reports them.
    fn sorted(
        mut parties: Vec<(Option<uuid::Uuid>, Option<uuid::Uuid>)>,
    ) -> Vec<(Option<uuid::Uuid>, Option<uuid::Uuid>)> {
        parties.sort();
        parties
    }

    /// The shielded outputs an external-receipt consumer selects: those the wallet received for
    /// which it holds no record of a sender, and which are not flagged as change.
    pub(crate) fn unattributed_shielded_receipts(
        conn: &rusqlite::Connection,
    ) -> Vec<(Vec<u8>, u32)> {
        let mut stmt = conn
            .prepare(
                "SELECT t.txid, ro.output_index
                 FROM v_received_outputs ro
                 JOIN transactions t ON t.id_tx = ro.transaction_id
                 WHERE ro.pool != 0 AND ro.sent_note_id IS NULL AND ro.is_change = 0
                 ORDER BY t.txid, ro.output_index",
            )
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Builds a transaction spending the guest account's only Sapling note, paying `recipient`
    /// and returning the remainder, less the fee, to the guest account's own change address.
    ///
    /// The note and its witness are read from the wallet, so the nullifier the transaction
    /// reveals is the one the wallet computes for that note.
    fn sapling_transfer_tx(
        st: &mut TestState<BlockCache, TestDb, LocalNetwork>,
        guest: AccountUuid,
        guest_usk: &UnifiedSpendingKey,
        recipient: ::sapling::PaymentAddress,
        recipient_value: u64,
        anchor_height: BlockHeight,
    ) -> Transaction {
        let network = *st.network();
        let target_height = TargetHeight::from(anchor_height + 1);

        let received = crate::wallet::sapling::select_spendable_sapling_notes(
            &st.wallet().db().conn,
            &network,
            guest,
            TargetValue::AtLeast(Zatoshis::const_from_u64(1)),
            target_height,
            ConfirmationsPolicy::MIN,
            &[],
            LockFilter::Unfiltered,
        )
        .unwrap()
        .into_iter()
        .next()
        .expect("the guest account's note is spendable");

        let note = received.note().clone();
        let note_value = note.value().inner();
        let position = received.note_commitment_tree_position();

        let (anchor, merkle_path) = st
            .wallet_mut()
            .with_sapling_tree_mut::<_, _, SqliteClientError>(|tree| {
                let anchor = ::sapling::Anchor::from(
                    tree.root_at_checkpoint_id(&anchor_height)?
                        .expect("a checkpoint exists at the note's receipt height"),
                );
                let merkle_path = tree
                    .witness_at_checkpoint_id_caching(position, &anchor_height)?
                    .expect("the received note can be witnessed at its receipt height");
                Ok((anchor, merkle_path))
            })
            .unwrap();

        let extsk = guest_usk.sapling().clone();
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let change_address = dfvk.change_address().1;

        // The fee is fixed by the shape rather than the values, so the same shape is assembled
        // twice: once to measure it, and once with the change that balances it.
        let assemble = |change_value: u64| {
            let mut builder = Builder::new(
                network,
                BlockHeight::from(target_height),
                BuildConfig::Standard {
                    sapling_anchor: Some(anchor),
                    orchard_anchor: Some(orchard::Anchor::empty_tree()),
                    ironwood_anchor: Some(orchard::Anchor::empty_tree()),
                    orchard_padding: BundlePadding::DEFAULT,
                    ironwood_padding: BundlePadding::DEFAULT,
                },
            );
            builder
                .add_sapling_spend::<zip317::FeeError>(
                    dfvk.fvk().clone(),
                    note.clone(),
                    merkle_path.clone(),
                )
                .unwrap();
            builder
                .add_sapling_output::<zip317::FeeError>(
                    Some(dfvk.fvk().ovk),
                    recipient,
                    Zatoshis::from_u64(recipient_value).unwrap(),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_sapling_output::<zip317::FeeError>(
                    Some(dfvk.fvk().ovk),
                    change_address,
                    Zatoshis::from_u64(change_value).unwrap(),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
        };

        let fee = u64::from(
            assemble(1)
                .get_fee(&zip317::FeeRule::standard())
                .expect("the fee of a balanced shape is computable"),
        );

        assemble(note_value - recipient_value - fee)
            .mock_build(
                &::transparent::builder::TransparentSigningSet::new(),
                &[extsk],
                &[],
                OsRng,
            )
            .unwrap()
            .transaction()
            .clone()
    }

    /// The state the maintainer's wallet was found in: a transfer funded by a Sapling note, whose
    /// spend of that note was linked after its data was stored, so its payment to another account
    /// carries no record of a sender while its change carries one.
    ///
    /// The wallet's own writers no longer produce that state, so it is reconstructed: the transfer
    /// is stored with its funding known, and the spend link and the cross-account recipient are
    /// then removed. What remains is what a wallet upgraded before the shielded hooks existed
    /// holds.
    ///
    /// Returns the transfer, the height its funding note was received at, and the guest account
    /// that funded it.
    fn store_transfer_with_its_spend_unlinked(
        st: &mut TestState<BlockCache, TestDb, LocalNetwork>,
        host: AccountUuid,
        recipient: ::sapling::PaymentAddress,
    ) -> (Transaction, BlockHeight, uuid::Uuid) {
        let network = *st.network();
        let birthday = st.test_account().unwrap().birthday().clone();

        let guest_usk =
            UnifiedSpendingKey::from_seed(&network, &[0xC7; 32], AccountId::ZERO).unwrap();
        let guest_ufvk = guest_usk.to_unified_full_viewing_key();
        let guest_dfvk = guest_ufvk
            .sapling()
            .expect("the guest account has a Sapling key")
            .clone();
        let guest = st
            .wallet_mut()
            .import_account_ufvk(
                "guest",
                &guest_ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap()
            .id();

        let (note_height, _, _) = st.generate_next_block(
            &guest_dfvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(500_000),
        );
        st.scan_cached_blocks(note_height, 1);

        let transfer = sapling_transfer_tx(st, guest, &guest_usk, recipient, 100_000, note_height);
        decrypt_and_store_transaction(&network, st.wallet_mut(), &transfer, None).unwrap();

        // Unlink the spend, and drop the record of who sent the cross-account payment. The change
        // output keeps its record, because the arm that writes it never consulted the funding
        // account in the first place.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            conn.execute(
                "DELETE FROM sapling_received_note_spends
                 WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = :txid)",
                named_params! { ":txid": transfer.txid().as_ref() },
            )
            .unwrap();
            conn.execute(
                "DELETE FROM sent_notes
                 WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = :txid)
                 AND to_account_id = (SELECT id FROM accounts WHERE uuid = :host)",
                named_params! {
                    ":txid": transfer.txid().as_ref(),
                    ":host": host.expose_uuid(),
                },
            )
            .unwrap();
            conn.commit().unwrap();
        }

        (transfer, note_height, guest.expose_uuid())
    }

    /// A transaction funded by a Sapling note, paying another account of the same wallet. Until
    /// the wallet links the spend of that note, nothing records who sent the payment, and the
    /// receiving account reads it as a receipt from a stranger — while the change returned to the
    /// funding account is attributed, because that arm never consulted the funding account.
    #[test]
    fn sapling_funded_transfer_is_attributed_when_its_spend_is_linked() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let host = st.test_account().unwrap();
        let host_id = host.account().id();
        let host_uuid = host_id.expose_uuid();
        let host_sapling = host
            .usk()
            .to_unified_full_viewing_key()
            .sapling()
            .expect("the test account has a Sapling key")
            .default_address()
            .1;

        let (transfer, _, guest_uuid) =
            store_transfer_with_its_spend_unlinked(&mut st, host_id, host_sapling);
        let txid = transfer.txid();
        let sapling = PoolType::Shielded(ShieldedPool::Sapling);

        // The diagnosed shape: the cross-account payment is a receipt from nobody, the change is
        // attributed.
        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, txid, sapling),
            sorted(vec![
                (None, Some(host_uuid)),
                (Some(guest_uuid), Some(guest_uuid)),
            ]),
        );
        assert!(
            unattributed_shielded_receipts(&st.wallet().db().conn)
                .iter()
                .any(|(seen, _)| seen == txid.as_ref()),
        );

        // Scanning the transfer reveals its nullifier against the note the wallet holds, which
        // links the spend and establishes which account funded it.
        let (h, _) = st.generate_next_block_from_tx(1, &transfer);
        st.scan_cached_blocks(h, 1);

        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, txid, sapling),
            sorted(vec![
                (Some(guest_uuid), Some(host_uuid)),
                (Some(guest_uuid), Some(guest_uuid)),
            ]),
        );
        assert!(
            unattributed_shielded_receipts(&st.wallet().db().conn)
                .iter()
                .all(|(seen, _)| seen != txid.as_ref()),
            "no output of the transfer is reported as a receipt from nobody",
        );
    }

    /// The replay is idempotent: linking the same spend again, and reconciling afterwards,
    /// records nothing further.
    #[test]
    fn shielded_spend_attribution_is_idempotent() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let host = st.test_account().unwrap();
        let host_id = host.account().id();
        let host_sapling = host
            .usk()
            .to_unified_full_viewing_key()
            .sapling()
            .expect("the test account has a Sapling key")
            .default_address()
            .1;

        let (transfer, _, _) =
            store_transfer_with_its_spend_unlinked(&mut st, host_id, host_sapling);
        let txid = transfer.txid();
        let sapling = PoolType::Shielded(ShieldedPool::Sapling);

        let (h, _) = st.generate_next_block_from_tx(1, &transfer);
        st.scan_cached_blocks(h, 1);
        let attributed = pool_output_parties(&st.wallet().db().conn, txid, sapling);
        assert!(attributed.iter().all(|(from, _)| from.is_some()));

        let repair = |st: &TestState<BlockCache, TestDb, LocalNetwork>| {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            repair_funding_attribution(&conn, &network).unwrap();
            conn.commit().unwrap();
        };

        repair(&st);
        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, txid, sapling),
            attributed,
        );

        repair(&st);
        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, txid, sapling),
            attributed,
        );
    }

    /// The repair heals a wallet in the state the maintainer's was found in: the transfer's data
    /// stored, its Sapling spend linked, and the payment to another account carrying no sender.
    ///
    /// The transaction has no transparent spend, so only the pool-complete selection reaches it.
    #[test]
    fn repair_heals_a_shielded_funded_transfer() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let host = st.test_account().unwrap();
        let host_id = host.account().id();
        let host_uuid = host_id.expose_uuid();
        let host_sapling = host
            .usk()
            .to_unified_full_viewing_key()
            .sapling()
            .expect("the test account has a Sapling key")
            .default_address()
            .1;

        let (transfer, _, guest_uuid) =
            store_transfer_with_its_spend_unlinked(&mut st, host_id, host_sapling);
        let txid = transfer.txid();
        let sapling = PoolType::Shielded(ShieldedPool::Sapling);

        // Restore the spend linkage without the attribution, which is what a wallet upgraded
        // before the shielded hooks existed holds.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            conn.execute(
                "INSERT INTO sapling_received_note_spends (sapling_received_note_id, transaction_id)
                 SELECT n.id, (SELECT id_tx FROM transactions WHERE txid = :txid)
                 FROM sapling_received_notes n
                 WHERE n.nf IS NOT NULL",
                named_params! { ":txid": txid.as_ref() },
            )
            .unwrap();
            conn.commit().unwrap();
        }
        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, txid, sapling),
            sorted(vec![
                (None, Some(host_uuid)),
                (Some(guest_uuid), Some(guest_uuid)),
            ]),
            "the fixture starts with the cross-account payment unattributed",
        );
        assert!(
            unattributed_shielded_receipts(&st.wallet().db().conn)
                .iter()
                .any(|(seen, _)| seen == txid.as_ref()),
        );

        // The repair migration's selection reaches the transaction through its shielded spend.
        let migration =
            crate::wallet::init::migrations::repair_funding_attribution_migration(network);
        let repair = |st: &TestState<BlockCache, TestDb, LocalNetwork>| {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            migration.up(&conn).unwrap();
            conn.commit().unwrap();
        };

        repair(&st);
        let repaired = sorted(vec![
            (Some(guest_uuid), Some(host_uuid)),
            (Some(guest_uuid), Some(guest_uuid)),
        ]);
        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, txid, sapling),
            repaired,
        );
        assert!(
            unattributed_shielded_receipts(&st.wallet().db().conn)
                .iter()
                .all(|(seen, _)| seen != txid.as_ref()),
        );

        // Running it again records nothing further.
        repair(&st);
        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, txid, sapling),
            repaired,
        );
    }

    /// The other site that links a shielded spend: a nullifier observed while scanning, held in
    /// the nullifier map because the note it reveals was not yet the wallet's, and resolved when
    /// that note arrives. The spend is recorded against the *spending* transaction, which is not
    /// the transaction the note was received in, so this pins which of the two the replay is
    /// asked to attribute.
    #[test]
    fn a_note_recovered_after_its_spend_attributes_the_spending_transaction() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let host = st.test_account().unwrap();
        let host_id = host.account().id();
        let host_uuid = host_id.expose_uuid();
        let host_sapling = host
            .usk()
            .to_unified_full_viewing_key()
            .sapling()
            .expect("the test account has a Sapling key")
            .default_address()
            .1;

        let (transfer, note_height, guest_uuid) =
            store_transfer_with_its_spend_unlinked(&mut st, host_id, host_sapling);
        let txid = transfer.txid();
        let sapling = PoolType::Shielded(ShieldedPool::Sapling);

        // Take the funding note away, so that scanning the transfer cannot match its nullifier
        // and has to park it in the nullifier map.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            conn.execute("DELETE FROM sapling_received_notes", [])
                .unwrap();
            conn.commit().unwrap();
        }

        let (spend_height, _) = st.generate_next_block_from_tx(1, &transfer);
        st.scan_cached_blocks(spend_height, 1);
        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, txid, sapling),
            sorted(vec![
                (None, Some(host_uuid)),
                (Some(guest_uuid), Some(guest_uuid)),
            ]),
            "the spend is unmatched, so nothing yet says who funded the transfer",
        );

        // Recovering the note resolves the parked nullifier, and the transaction the spend
        // belongs to is the transfer, not the block the note came in.
        st.scan_cached_blocks(note_height, 1);

        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, txid, sapling),
            sorted(vec![
                (Some(guest_uuid), Some(host_uuid)),
                (Some(guest_uuid), Some(guest_uuid)),
            ]),
        );
        assert!(
            unattributed_shielded_receipts(&st.wallet().db().conn)
                .iter()
                .all(|(seen, _)| seen != txid.as_ref()),
        );
    }

    /// Recipient rows belonging to one pool must not stand in for a missing recipient in another.
    ///
    /// This is the shape a wallet takes across configurations: an Orchard-capable build records
    /// recipients for a transaction's Orchard actions, and a build without `orchard` reopens the
    /// wallet, sees those rows, and cannot see the actions they belong to. Totalling recipient
    /// rows against a total output count lets them cover an unattributed Sapling output and skip
    /// the replay for good. The fixture reproduces that arithmetic within one build by recording
    /// Orchard recipients for a transaction that has no Orchard actions, which is what the
    /// feature-off build's count amounts to.
    #[test]
    fn recipients_recorded_for_one_pool_do_not_mask_another() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let host = st.test_account().unwrap();
        let host_id = host.account().id();
        let host_uuid = host_id.expose_uuid();
        let host_sapling = host
            .usk()
            .to_unified_full_viewing_key()
            .sapling()
            .expect("the test account has a Sapling key")
            .default_address()
            .1;

        let (transfer, _, guest_uuid) =
            store_transfer_with_its_spend_unlinked(&mut st, host_id, host_sapling);
        let txid = transfer.txid();
        let sapling = PoolType::Shielded(ShieldedPool::Sapling);

        // Recipients in a pool the transaction has no outputs in, in numbers that cover every
        // Sapling output it does have.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            conn.execute(
                "INSERT INTO sent_notes
                    (transaction_id, output_pool, output_index, from_account_id, value)
                 SELECT (SELECT id_tx FROM transactions WHERE txid = :txid),
                        :orchard,
                        idx.i,
                        (SELECT id FROM accounts WHERE uuid = :guest),
                        1
                 FROM (SELECT 0 AS i UNION SELECT 1 UNION SELECT 2
                       UNION SELECT 3 UNION SELECT 4 UNION SELECT 5) idx",
                named_params! {
                    ":txid": txid.as_ref(),
                    ":orchard": pool_code(PoolType::Shielded(ShieldedPool::Orchard)),
                    ":guest": guest_uuid,
                },
            )
            .unwrap();
            conn.commit().unwrap();
        }

        // Linking the spend must still run the replay over the Sapling pool.
        let (h, _) = st.generate_next_block_from_tx(1, &transfer);
        st.scan_cached_blocks(h, 1);

        assert_eq!(
            pool_output_parties(&st.wallet().db().conn, txid, sapling),
            sorted(vec![
                (Some(guest_uuid), Some(host_uuid)),
                (Some(guest_uuid), Some(guest_uuid)),
            ]),
        );
    }
}
