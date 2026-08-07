//! The SQLite pool-migration store instantiated for the Orchard -> Ironwood migration (ZIP 318);
//! tables prefixed `orchard_ironwood_migration[s]_`.
//!
//! This is the only public surface of the pool-migration store: it wraps the generic (private)
//! store with this pool's table names, exposing a concrete [`PoolMigrations`] that implements
//! [`PoolMigrationRead`] / [`PoolMigrationWrite`], and the `init_migration_tables` DDL its schema
//! migration runs. The generic store type never leaks into this API.

use std::{
    borrow::{Borrow, BorrowMut},
    collections::BTreeSet,
};

use rusqlite::{Connection, OptionalExtension};
use zcash_client_backend::{
    data_api::anchor_retention::AnchorRetentionInterval, wallet::LockOwner,
};
use zcash_pool_migration::engine::{
    MigrationState, MigrationTransaction, MigrationTransferId, MigrationTxState, PoolMigrationRead,
    PoolMigrationWrite,
};
use zcash_pool_migration::satisfiability::{ReorgSettleDepth, StepSatisfiability};
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;

#[cfg(feature = "orchard")]
use {
    shardtree::error::ShardTreeError,
    std::collections::HashMap,
    zcash_client_backend::{
        data_api::{
            Account as _, SentTransaction, SentTransactionOutput,
            anchor_retention::PoolMigrationParams, wallet::TargetHeight,
            zip318::classify_decrypted_tx,
        },
        decrypt_transaction,
        wallet::{Note, Recipient},
    },
    zcash_protocol::value::Zatoshis,
};

use crate::{AccountRef, AccountUuid, error::SqliteClientError};

use super::store::{self, Store, Tables};

/// A failure reading or writing the pool-migration store.
pub use super::error::Error;
/// Why a proven migration PCZT could not be finalized into a `Transaction`.
#[cfg(feature = "orchard")]
pub use super::error::FinalizeError;

/// The Orchard -> Ironwood table and index names this store operates over.
static TABLES: Tables = Tables {
    migrations: "orchard_ironwood_migrations",
    crossing_values: "orchard_ironwood_migration_crossing_values",
    prep_inputs: "orchard_ironwood_migration_prep_inputs",
    prep_outputs: "orchard_ironwood_migration_prep_outputs",
    prep_direct_funding: "orchard_ironwood_migration_prep_direct_funding",
    transactions: "orchard_ironwood_migration_transactions",
    transaction_deps: "orchard_ironwood_migration_transaction_deps",
    spend_nullifiers: "orchard_ironwood_migration_spend_nullifiers",
    tx_due_index: "idx_orchard_ironwood_migration_tx_due",
    account_index: "idx_orchard_ironwood_migrations_account",
    source_notes: "orchard_received_notes",
    source_note_spends: "orchard_received_note_spends",
    source_note_spends_note_fk: "orchard_received_note_id",
    source_tree_checkpoints: "orchard_tree_checkpoints",
};

/// The Orchard note commitment tree anchor at the checkpoint `height`, as the anchor-validity
/// judgment consumes it: `None` when the tree can produce no root there.
///
/// `None` covers both "no checkpoint at that height" (never created, or pruned without being
/// retained) and a tree too incomplete to compute one from the shard data actually held — both of
/// which leave the judgment unable to conclude, which is exactly what `None` tells it. Only a
/// genuine database or deserialization failure is an error; those are conditions the caller cannot
/// act on by waiting.
///
/// This reads the tree through the same `rusqlite::Transaction` the rest of the satisfiability
/// answer is computed in, so every root compared and the `as_of_height` it is compared under come
/// from one database snapshot.
#[cfg(feature = "orchard")]
fn orchard_anchor_at(
    view: &rusqlite::Transaction<'_>,
    height: zcash_protocol::consensus::BlockHeight,
) -> Result<Option<::orchard::Anchor>, Error> {
    /// A tree failure that is NOT "no root here": a database error surfaces as itself, and
    /// anything else means the stored tree cannot be read back as it was written.
    fn lift(e: ShardTreeError<crate::wallet::commitment_tree::Error>) -> Error {
        match e {
            ShardTreeError::Storage(crate::wallet::commitment_tree::Error::Query(e)) => {
                Error::Db(e)
            }
            _ => Error::Corrupt("orchard commitment tree"),
        }
    }

    let tree = crate::orchard_tree(view).map_err(lift)?;
    match tree.root_at_checkpoint_id(&height) {
        Ok(root) => Ok(root.map(::orchard::Anchor::from)),
        // A QUERY-level failure is the tree reporting that it cannot answer for this height — the
        // shard data it holds does not complete a root, or the checkpoint has been pruned — which
        // is what `None` already expresses: the judgment cannot conclude.
        Err(ShardTreeError::Query(_)) => Ok(None),
        Err(e) => Err(lift(e)),
    }
}

/// [`orchard_anchor_at`] in the byte encoding the pool-agnostic store compares roots in: a shard
/// tree is typed by its hash, so the generic store cannot name [`orchard::Anchor`] and the
/// conversion happens here, at the facade boundary.
#[cfg(feature = "orchard")]
fn orchard_root_at(
    view: &rusqlite::Transaction<'_>,
    height: zcash_protocol::consensus::BlockHeight,
) -> Result<Option<[u8; 32]>, Error> {
    orchard_anchor_at(view, height).map(|anchor| anchor.map(|anchor| anchor.to_bytes()))
}

/// The source-pool tree access the satisfiability oracle's anchor-validity judgment needs, or
/// `None` in a build that cannot read the Orchard commitment tree at all — in which case the
/// judgment declines and the oracle keeps its conservative answer.
#[cfg(feature = "orchard")]
const SOURCE_ROOT_AT: Option<store::SourceRootAt> = Some(orchard_root_at);
#[cfg(not(feature = "orchard"))]
const SOURCE_ROOT_AT: Option<store::SourceRootAt> = None;

/// Create the Orchard -> Ironwood pool-migration tables (and the due-transaction and account
/// indexes) on `conn` in their CURRENT shape, as a wallet has them once every schema migration has
/// run; idempotent (`IF NOT EXISTS`).
///
/// No production code calls this. The `orchard_ironwood_migration_tables` schema migration is
/// published, so it creates these tables from a frozen copy of the DDL it shipped with, and the
/// migrations after it evolve that into the shape here (see [`store::init`]). What remains is the
/// canonical statement of that shape: the fixtures that build a store directly build it from here,
/// and `canonical_pool_migration_ddl_matches_the_migration_path` holds it to what the migrations
/// actually produce. The attribute keeps that statement — and everything it reaches, including the
/// index names no query needs — alive for a pool whose creating migration has yet to ship.
#[allow(dead_code)]
pub(crate) fn init_migration_tables(conn: &Connection) -> rusqlite::Result<()> {
    store::init(conn, &TABLES)
}

/// The Orchard -> Ironwood per-account uniqueness index DDL, from the store's one generator, for
/// the `orchard_ironwood_migration_history` schema migration: the migration path and the canonical
/// DDL create the index from the same text, so its non-terminal predicate cannot drift between
/// them.
pub(crate) fn account_index_sql() -> String {
    store::create_account_index_sql(&TABLES)
}

/// The Orchard -> Ironwood transactions-table DDL, from the store's one generator, for the
/// `orchard_ironwood_migration_txid_blob` schema migration's table rebuild.
pub(crate) fn transactions_table_sql() -> String {
    store::create_transactions_sql(&TABLES)
}

/// The due-transactions index DDL, from the store's one generator, recreated by the same rebuild.
pub(crate) fn tx_due_index_sql() -> String {
    store::create_tx_due_index_sql(&TABLES)
}

/// The `v_migration_transactions` view DDL over the Orchard -> Ironwood tables, from the store's
/// one generator, for the `v_migration_transactions` schema migration.
pub(crate) fn migration_tx_view_sql() -> String {
    store::create_migration_tx_view_sql(&TABLES)
}

/// The anchor bucket grids, in blocks, of every Orchard -> Ironwood migration in this database
/// that is not yet complete.
///
/// A wallet must keep retaining the boundaries of the grid each in-flight migration was committed
/// under, whatever it is currently configured to retain, or that migration's transfers become
/// unprovable. Reading the grids back from the migrations themselves is what makes that
/// independent of the application remembering to reapply a setting. See
/// [`store::active_anchor_bucket_intervals`].
pub(crate) fn active_anchor_bucket_intervals(
    conn: &Connection,
) -> Result<BTreeSet<AnchorRetentionInterval>, SqliteClientError> {
    store::active_anchor_bucket_intervals(conn, &TABLES)
        .map(|blocks| {
            blocks
                .into_iter()
                .map(AnchorRetentionInterval::custom)
                .collect()
        })
        .map_err(lift_store_error)
}

/// Roll every stored Orchard -> Ironwood migration back to `height`, which the wallet's own
/// truncation calls so that a migration's chain-derived state cannot outlive the chain state it
/// was derived from. See [`store::truncate_to_height`].
pub(crate) fn truncate_to_height(
    tx: &rusqlite::Transaction,
    height: zcash_protocol::consensus::BlockHeight,
) -> Result<(), SqliteClientError> {
    store::truncate_to_height(tx, &TABLES, height).map_err(lift_store_error)
}

/// A store failure as the wallet's own error type reports it: a database error surfaces as itself,
/// and everything else is data the store could not reconstruct.
fn lift_store_error(e: Error) -> SqliteClientError {
    match e {
        Error::Db(e) => SqliteClientError::DbError(e),
        other => SqliteClientError::CorruptedData(other.to_string()),
    }
}

/// The Orchard -> Ironwood pool-migration store: a [`PoolMigrationRead`] / [`PoolMigrationWrite`]
/// over a `rusqlite::Connection`, scoped to one account's migration. Construct it with a connection
/// borrow (`&Connection` for read-only access, `&mut Connection` to also write) over the same
/// connection a [`WalletDb`](crate::WalletDb) uses, so the pool-migration tables share the wallet
/// database.
///
/// Sharing the wallet database is what lets [`store_proved_transaction`] persist a finalized
/// migration transaction into the wallet's own transaction tables ATOMICALLY with the migration
/// state that records it proved; the network parameters and clock are what that wallet-side
/// record needs (output recovery and the sent-transaction timestamp), carried here for the same
/// reason [`WalletDb`](crate::WalletDb) carries them.
///
/// An account's migration is owned by its row in the wallet's `accounts` table through the
/// `account_id` foreign key, so deleting the account removes its migration automatically (via
/// `ON DELETE CASCADE`); no explicit cleanup is required.
///
/// [`store_proved_transaction`]: zcash_pool_migration::engine::PoolMigrationWrite::store_proved_transaction
pub struct PoolMigrations<C, P, CL> {
    store: Store<C>,
    // The wallet context `PoolMigrationWrite::store_proved_transaction` (an `orchard`-gated capability)
    // finalizes under; carried unconditionally so the store's type does not change with the
    // feature.
    #[cfg_attr(not(feature = "orchard"), allow(dead_code))]
    account: AccountUuid,
    #[cfg_attr(not(feature = "orchard"), allow(dead_code))]
    params: P,
    #[cfg_attr(not(feature = "orchard"), allow(dead_code))]
    clock: CL,
}

impl<C: Borrow<Connection>, P, CL> PoolMigrations<C, P, CL> {
    /// Wrap a connection borrow as the store, scoped to `account`'s migration.
    ///
    /// The account is resolved to its `accounts` row up front, so the store keys its migration by
    /// that row (the foreign key the schema uses) rather than by the external UUID. Returns
    /// [`Error::AccountUnknown`] if no account with this UUID exists in the wallet.
    ///
    /// `params` and `clock` serve only [`store_proved_transaction`]
    /// (output recovery and the sent-transaction timestamp); a caller that only reads and writes
    /// migration state may pass `()` for both.
    ///
    /// [`store_proved_transaction`]: zcash_pool_migration::engine::PoolMigrationWrite::store_proved_transaction
    pub fn for_account(params: P, clock: CL, conn: C, account: AccountUuid) -> Result<Self, Error> {
        let account_id = conn
            .borrow()
            .query_row(
                "SELECT id FROM accounts WHERE uuid = ?",
                rusqlite::params![account.expose_uuid()],
                |row| row.get(0).map(AccountRef),
            )
            .optional()?
            .ok_or(Error::AccountUnknown)?;
        Ok(Self {
            store: Store::new(conn, &TABLES, account_id),
            account,
            params,
            clock,
        })
    }
}

impl<C, P, CL> PoolMigrations<C, P, CL> {
    /// Recover the wrapped connection borrow.
    pub fn into_inner(self) -> C {
        self.store.into_inner()
    }
}

impl<C: Borrow<Connection>, P, CL> PoolMigrations<C, P, CL> {
    /// Returns the set of [`LockOwner`]s under which this account's in-progress pool migration
    /// has locked notes (empty if there is no migration, or it holds no locks).
    ///
    /// This is the set a caller passes to a `LockedInputPolicy::PreferUnlocked` /
    /// `PreferLocked` override so a proposal may draw on the migration's own locked notes
    /// without disturbing any other flow's locks. It is not part of [`PoolMigrationRead`]: that
    /// trait is shared with the pool-agnostic migration engine, which has no notion of
    /// [`LockOwner`] (a wallet-level concept).
    pub fn migration_lock_owners(&self) -> Result<BTreeSet<LockOwner>, Error> {
        self.store.migration_lock_owners()
    }

    /// The account's most recent migration WHATEVER its status: what a UI renders, where a
    /// finished migration must stay visible after the pending-only
    /// [`get_migration`](zcash_pool_migration::engine::PoolMigrationRead::get_migration) has
    /// moved on to `None`.
    ///
    /// Inherent rather than on [`PoolMigrationRead`]: the engine never reads history, so the
    /// trait would tax every store implementation with a method the engine never calls.
    pub fn latest_migration(&self) -> Result<Option<MigrationState>, Error> {
        self.store.latest_migration()
    }

    /// Every migration this account has run, newest first, as cheap SQL-projected summaries: no
    /// stored PCZT is read or parsed. Resolve a row to its full state with
    /// [`get_migration_by_id`](Self::get_migration_by_id).
    pub fn list_migrations(&self) -> Result<Vec<crate::pool_migration::MigrationSummary>, Error> {
        self.store.list_migrations()
    }

    /// The full state of the migration identified by `id` — historical or pending — or `None`
    /// when this account has no such migration.
    pub fn get_migration_by_id(
        &self,
        id: crate::pool_migration::MigrationUuid,
    ) -> Result<Option<MigrationState>, Error> {
        self.store.get_migration_by_id(id)
    }
}

/// Cancellation, the one inherent method that must WRITE, and so the one that cannot join the
/// read-only inherent block above: those methods need only a shared `Borrow<Connection>`, and
/// `BorrowMut` is a strict subtrait of it, so merging the two would force every reader to hold a
/// mutable borrow. It does not join the `BorrowMut` block below either, which is gated on the
/// `orchard` feature and additionally bounded by `P` and `CL`; cancel requires none of the three.
impl<C, P, CL> PoolMigrations<C, P, CL>
where
    C: BorrowMut<Connection>,
{
    /// Cancel this account's migration at the user's request: release every note reservation its
    /// never-broadcast transactions hold, then move the record to the terminal `Cancelled`
    /// status — in that order, in one database transaction, so a crash between the two leaves a
    /// still-pending migration that a retried cancel finishes. After this returns, the engine
    /// drives nothing, the released notes are back in DEFAULT note selection immediately (rather
    /// than at lock expiry), and a replacement migration may be planned and committed over the
    /// full balance; the cancelled record remains readable through
    /// [`latest_migration`](Self::latest_migration) and its siblings.
    ///
    /// Works WITHOUT deserializing the migration state — the primary use case is an
    /// unrecoverable wallet, and a record that will not parse is one of the ways to get there —
    /// and is honest about what it cannot undo: transactions already broadcast may still mine,
    /// and the returned [`CancelOutcome`](crate::pool_migration::CancelOutcome) reports them
    /// rather than refusing (a refusal would reintroduce the stuck state cancel exists to
    /// remove). Calling with no pending migration performs only the REPAIR half on the latest
    /// retained record, releasing reservations a terminal record may still hold (for instance
    /// one recorded `Failed` by an older client) without rewriting its status.
    pub fn cancel_migration(&mut self) -> Result<crate::pool_migration::CancelOutcome, Error> {
        self.store.cancel_migration()
    }
}

impl<C: Borrow<Connection>, P, CL> PoolMigrationRead for PoolMigrations<C, P, CL> {
    type Error = Error;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        self.store.get_migration()
    }

    fn check_step_satisfiability(
        &self,
        tx: &MigrationTransaction,
        settle: ReorgSettleDepth,
    ) -> Result<StepSatisfiability, Self::Error> {
        self.store
            .check_step_satisfiability(tx, settle, SOURCE_ROOT_AT)
    }

    /// Pool-independent: a transaction's inclusion is read off the wallet's own `transactions`
    /// table, so unlike the satisfiability oracle this needs no source-pool tree access.
    fn mined_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        self.store.mined_height(txid)
    }
}

impl<C, P, CL> PoolMigrationWrite for PoolMigrations<C, P, CL>
where
    C: BorrowMut<Connection>,
    P: zcash_protocol::consensus::Parameters,
    CL: crate::util::Clock,
{
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.store.replace_migration(state)
    }

    fn update_transaction(
        &mut self,
        id: MigrationTransferId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        self.store.update_transaction(id, state)
    }

    /// The wallet-database form of the contract: apply the proof to `state` and persist the
    /// migration state, and nothing else.
    ///
    /// Deliberately NO wallet-side transaction record. The reservation that keeps another flow
    /// off this transaction's inputs through the prove-to-broadcast window is the ADVISORY note
    /// lock the proof arrived with ([`ProvedTransaction::lock_owner`]), which leaves the notes in
    /// the user's spendable balance; the wallet's own record — raw bytes, sent outputs, hard
    /// input-spend marks, and the status-retrieval queue entry — is written at the broadcast seam
    /// by [`take_transaction_for_broadcast`](Self::take_transaction_for_broadcast), atomically
    /// with handing the broadcastable bytes out.
    ///
    /// [`ProvedTransaction::lock_owner`]:
    ///     zcash_pool_migration::engine::ProvedTransaction::lock_owner
    #[cfg(feature = "orchard")]
    fn store_proved_transaction(
        &mut self,
        state: &mut MigrationState,
        proven: zcash_pool_migration::engine::ProvedTransaction,
    ) -> Result<(), Self::Error> {
        proven.apply(state);
        self.replace_migration(state)
    }

    /// Without the `orchard` feature this wallet tracks no Orchard (or Ironwood) notes at all:
    /// there is nothing the wallet's transaction tables could record about a migration
    /// transaction, and no wallet-side spend the input marks would protect against. The
    /// contract's no-wallet-tables form is therefore COMPLETE here, not a degraded stand-in:
    /// apply the proof and persist the migration state alone.
    #[cfg(not(feature = "orchard"))]
    fn store_proved_transaction(
        &mut self,
        state: &mut MigrationState,
        proven: zcash_pool_migration::engine::ProvedTransaction,
    ) -> Result<(), Self::Error> {
        proven.apply(state);
        self.replace_migration(state)
    }
}

/// Finalization of a proved migration transaction into the wallet's own transaction record.
#[cfg(feature = "orchard")]
impl<C, P, CL> PoolMigrations<C, P, CL>
where
    C: BorrowMut<Connection>,
    P: zcash_protocol::consensus::Parameters,
    CL: crate::util::Clock,
{
    /// The BROADCAST seam: finalize the proved migration transaction `proved` into its
    /// broadcastable [`Transaction`](zcash_primitives::transaction::Transaction), record it in
    /// the wallet's own transaction tables, and hand
    /// it back for submission — one call, one database transaction, so the wallet record binds
    /// at the ATTEMPT. A consumer that obtains bytes here and dies mid-submit has already left
    /// the wallet record that the drive loop's `Proved`-row promotion sweep and the
    /// status-retrieval queue rely on; there is no way to hold broadcastable bytes the wallet
    /// does not know about.
    ///
    /// This — not proving — is where the transaction enters the wallet's view. From here its
    /// input notes are HARD-spent (a mempool may mine it whatever the wallet does next), its
    /// outputs are recorded as sent, and its txid may be asked after: the status-retrieval queue
    /// entry is made here, so a never-broadcast txid is never disclosed to a light wallet
    /// server. Before this call the only reservation on its inputs is the advisory lock taken at
    /// proving, which is what keeps the user's full balance spendable through the deliberately
    /// long prove-to-broadcast window.
    ///
    /// The transaction named by `proved` must be [`Proved`](MigrationTxState::Proved) in
    /// `state`: its stored bytes are then a PCZT carrying both signatures (installed at commit)
    /// and proofs, from which the final `Transaction` is extracted mechanically — the PCZT Spend
    /// Finalizer and Transaction Extractor roles, the latter of which re-verifies the proofs and
    /// signatures it assembles, so a PCZT that would not survive broadcast is rejected here
    /// rather than recorded. The outputs are recovered by trial decryption under the account's
    /// unified full viewing key (every real output of a migration transaction is internal to the
    /// migrating account; the padded dummies decrypt under no key). Idempotent: every write it
    /// makes upserts, so a consumer that crashed between obtaining these bytes and submitting
    /// them obtains the same bytes, over the same record, when the drive loop offers the
    /// broadcast again.
    ///
    /// After submitting, the consumer records the outcome exactly as before:
    /// [`MigrationState::mark_broadcast`] on success, or
    /// [`MigrationState::report_broadcast_failure`] on a rejection, then persists.
    ///
    /// [`MigrationState::mark_broadcast`]: zcash_pool_migration::engine::MigrationState::mark_broadcast
    /// [`MigrationState::report_broadcast_failure`]:
    ///     zcash_pool_migration::engine::MigrationState::report_broadcast_failure
    pub fn take_transaction_for_broadcast(
        &mut self,
        state: &MigrationState,
        proved: MigrationTransferId,
    ) -> Result<zcash_primitives::transaction::Transaction, Error> {
        let row = state
            .transactions()
            .iter()
            .find(|t| t.id() == proved)
            .ok_or(Error::UnknownTransaction(proved))?;
        if !matches!(row.state(), MigrationTxState::Proved) {
            return Err(Error::NotProved(proved));
        }

        // Finalize the spend authorizations and extract the transaction. Extraction re-verifies
        // the proofs and signatures it assembles, so a PCZT that would not survive broadcast is
        // rejected here rather than recorded.
        let pczt = ::pczt::Pczt::parse(row.pczt())
            .map_err(|e| Error::Finalize(FinalizeError::Parse(e)))?;
        let finalized = ::pczt::roles::spend_finalizer::SpendFinalizer::new(pczt)
            .finalize_spends()
            .map_err(|e| Error::Finalize(FinalizeError::Spends(e)))?;
        let tx = ::pczt::roles::tx_extractor::TransactionExtractor::new(finalized)
            .extract()
            .map_err(|e| Error::Finalize(FinalizeError::Extract(e)))?;

        // The fee is fully determined by the shielded value balances: a migration transaction has
        // no transparent bundle, so the prevout lookup is never consulted.
        let fee = tx
            .fee_paid(|_| Ok::<_, zcash_protocol::value::BalanceError>(None))
            .map_err(|e| Error::Finalize(FinalizeError::Balance(e)))?
            .ok_or(Error::Corrupt(
                "migration transaction has transparent inputs",
            ))?;

        // Recover the outputs by trial decryption under the account's own viewing key. A
        // migration transaction's real outputs are all internal to the migrating account (feeder
        // notes, or the value crossing into Ironwood), and its padded dummy outputs decrypt under
        // no key, so decryption recovers exactly the outputs the wallet must record.
        let account =
            crate::wallet::get_account(self.store.connection(), &self.params, self.account)
                .map_err(|e| Error::Wallet(Box::new(e)))?
                .ok_or(Error::AccountUnknown)?;
        let ufvk = account
            .ufvk()
            .cloned()
            .ok_or(Error::ViewingKeyUnavailable)?;
        let ufvks = HashMap::from([(self.account, ufvk)]);
        let decrypted = decrypt_transaction(
            &self.params,
            None,
            Some(row.scheduled_height()),
            &tx,
            &ufvks,
        );
        let outputs = decrypted
            .orchard_outputs()
            .iter()
            .chain(decrypted.ironwood_outputs())
            .map(|output| {
                let (note, pool) = *output.note();
                Zatoshis::from_u64(note.value().inner())
                    .map(|value| {
                        SentTransactionOutput::from_parts(
                            output.index(),
                            Recipient::InternalShielded {
                                receiving_account: *output.account(),
                                external_address: None,
                                note: Box::new(Note::Orchard { note, pool }),
                            },
                            value,
                            Some(output.memo().clone()),
                        )
                    })
                    .map_err(|e| Error::Finalize(FinalizeError::Balance(e)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // The transaction is built to be broadcast at its scheduled height, so the block it aims
        // to mine in — the standard flow's construction target — is that height's successor.
        let target_height = TargetHeight::from(u32::from(row.scheduled_height()) + 1);
        let created = time::OffsetDateTime::from(self.clock.now());
        let sent = SentTransaction::new(
            &tx,
            created,
            target_height,
            self.account,
            &outputs,
            fee,
            #[cfg(feature = "transparent-inputs")]
            &[],
        );

        let params = &self.params;
        self.store.replace_migration_with(state, |dbtx| {
            let tx_ref = crate::wallet::store_transaction_to_be_sent(
                dbtx,
                params,
                // A migration transaction has no transparent outputs, so the gap-limit machinery
                // this parameterizes is unreachable.
                #[cfg(feature = "transparent-inputs")]
                &zcash_keys::keys::transparent::gap_limits::GapLimits::default(),
                &sent,
            )
            .map_err(|e| Error::Wallet(Box::new(e)))?;

            // Record how the transaction classifies against ZIP 318, in the same database
            // transaction as the record itself. The enhance path stamps this for transactions the
            // wallet learns about by scanning, but a scheduled migration transaction sits stored
            // and UNMINED from proving until its broadcast height — up to days — and during that
            // window a wallet that wants to label (or hold back) its own migration traffic would
            // otherwise read "not classified". This is the same one-moment argument the enhance
            // path documents: the parsed transaction and its decrypted outputs are both in hand
            // right here, and nowhere later. The enhance path re-stamps the same answer after the
            // transaction mines, which is idempotent.
            //
            // Parameters are the SPECIFIED defaults, exactly as the enhance path reasons: the only
            // wallet-overridable value is the anchor bucket interval, and this evidence source
            // cannot evaluate the anchor clause at all, so the override cannot change the answer.
            let migration_params = PoolMigrationParams::from(AnchorRetentionInterval::default());
            let classification = classify_decrypted_tx(
                &tx,
                decrypted.orchard_outputs(),
                decrypted.ironwood_outputs(),
                &migration_params,
            );
            crate::wallet::put_zip318_classification(dbtx, tx_ref, classification)
                .map_err(|e| Error::Wallet(Box::new(e)))
        })?;
        Ok(tx)
    }
}

/// Retention follows the grid recorded WITH an in-flight migration, not the wallet's current
/// configuration, so an application that reopens the wallet without reapplying a non-default
/// interval cannot cause a scan to prune a boundary that migration still needs.
///
/// This is the gap the interval-mismatch check alone leaves: that check compares intervals at
/// proving time, but the damage is done at scan time, and reapplying the setting afterwards repairs
/// the comparison without bringing the checkpoint back.
#[cfg(all(test, feature = "orchard"))]
mod retention_follows_the_committed_migration {
    use core::num::NonZeroU32;
    use std::collections::BTreeSet;

    use shardtree::store::ShardStore;
    use zcash_client_backend::data_api::{
        Account as _, WalletCommitmentTrees, WalletRead,
        anchor_retention::AnchorRetentionInterval,
        testing::{TestBuilder, orchard::OrchardPoolTester, pool::ShieldedPoolTester},
    };
    use zcash_pool_migration::{
        denomination::DenominationPlan,
        engine::{MigrationState, MigrationStatus, PoolMigrationRead, PoolMigrationWrite},
        preparation::PreparationPlan,
        satisfiability::ReplanThreshold,
        scheduling::AnchorBucketInterval,
    };
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::value::Zatoshis;

    use super::PoolMigrations;
    use crate::testing::{BlockCache, db::TestDbFactory};
    use crate::util::SystemClock;

    /// A migration carrying no transactions, recorded as committed under `interval`. Only the
    /// recorded grid matters here; the retention decision does not look at the transfers.
    ///
    /// Hand-built rather than drawn from `zcash_pool_migration::testing`'s `arb_migration_state`:
    /// the grid IS the subject, and that strategy draws it arbitrarily.
    fn migration_committed_under(interval: AnchorBucketInterval) -> MigrationState {
        MigrationState::from_parts(
            MigrationStatus::Committed,
            DenominationPlan::from_stored_parts(
                Vec::new(),
                Zatoshis::ZERO,
                None,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
            )
            .expect("an empty stored plan reconstructs"),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            Vec::new(),
            interval,
            ReplanThreshold::DEFAULT,
        )
    }

    #[test]
    fn misconfigured_reopen_keeps_retaining_the_committed_grid() {
        let activation = zcash_protocol::consensus::BlockHeight::from_u32(100_000);
        let network = zcash_protocol::local_consensus::LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        };

        // The wallet is left at the ZIP 318 default: this stands for an application that
        // configured a short grid when it committed, then reopened without reapplying it.
        let mut st = TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        assert_eq!(
            st.wallet().anchor_retention_interval(),
            AnchorRetentionInterval::ZIP_318,
            "the wallet is configured with the default grid",
        );

        // Record a migration committed under a 12-block grid.
        let committed = AnchorBucketInterval::custom(NonZeroU32::new(12).expect("nonzero"));
        let account_id = st
            .test_account()
            .expect("the test account exists")
            .account()
            .id();
        PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account_id,
        )
        .expect("the account exists")
        .replace_migration(&migration_committed_under(committed))
        .expect("persists the migration");

        // Scan enough blocks to cross several boundaries of both grids. The account's birthday is
        // the Sapling activation height, so the first generated block sits just above it.
        let fvk = OrchardPoolTester::test_account_fvk(&st);
        for _ in 0..600 {
            let (h, _, _) = st.generate_next_block(
                &fvk,
                zcash_client_backend::data_api::testing::AddressType::DefaultExternal,
                Zatoshis::const_from_u64(10_000),
            );
            st.scan_cached_blocks(h, 1);
        }
        let tip = u32::from(
            st.wallet()
                .chain_height()
                .expect("reads the chain height")
                .expect("the wallet has a chain tip"),
        );
        let start = u32::from(activation);

        let retained: BTreeSet<u32> = st
            .wallet_mut()
            .with_orchard_tree_mut(|tree| {
                Ok::<_, crate::error::SqliteClientError>(
                    tree.store()
                        .retained_checkpoints()
                        .expect("reads retained checkpoints"),
                )
            })
            .expect("reads the Orchard tree")
            .into_iter()
            .map(u32::from)
            .collect();

        // Every boundary of the MIGRATION's grid in the scanned range was retained, despite the
        // wallet being configured with a different one.
        let expected_committed: BTreeSet<u32> = (start..=tip)
            .filter(|h| h % 12 == 0 && *h > start)
            .collect();
        assert!(
            expected_committed.is_subset(&retained),
            "the committed 12-block grid must stay retained; missing {:?}",
            expected_committed.difference(&retained).collect::<Vec<_>>(),
        );

        // The configured grid is retained too: the policy is the union, not a replacement.
        let expected_configured: BTreeSet<u32> = (start..=tip)
            .filter(|h| h % 144 == 0 && *h > start)
            .collect();
        assert!(
            expected_configured.is_subset(&retained),
            "the configured grid must also stay retained",
        );

        // Sanity: with no migration recorded, the 12-block grid would NOT have been retained, so
        // the assertion above is load-bearing rather than incidentally true.
        assert!(
            !expected_committed.is_empty(),
            "the scan must cross at least one boundary of the committed grid",
        );
        assert!(
            PoolMigrations::for_account(
                *st.network(),
                SystemClock,
                st.wallet_mut().conn_mut(),
                account_id
            )
            .expect("the account exists")
            .get_migration()
            .expect("reads the migration")
            .is_some(),
            "the migration is still recorded",
        );
    }
}

/// The satisfiability oracle over a REAL wallet database: each cached real-spend nullifier is
/// answered from the wallet's Orchard note and note-spend tables, expiry from the fully-scanned
/// height, and a broadcast transfer's installed anchor from the wallet's own Orchard commitment
/// tree; an empty nullifier cache on a non-mined row is corruption. The wallet fixture scans a
/// genuine received note, so the nullifier under test is one the production scanner recorded, not
/// a hand-computed stand-in, and the roots the anchor judgment compares are the tree's own.
#[cfg(all(test, feature = "orchard"))]
mod check_step_satisfiability {
    use rusqlite::named_params;

    use ::orchard::{Anchor, note::Nullifier};
    use zcash_client_backend::data_api::testing::{
        AddressType, TestBuilder, TestState, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
    };
    use zcash_client_backend::data_api::{Account as _, WalletRead};
    use zcash_pool_migration::denomination::DenominationPlan;
    use zcash_pool_migration::engine::{
        MigrationState, MigrationStatus, MigrationTransaction, MigrationTransferId,
        MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
    };
    use zcash_pool_migration::preparation::PreparationPlan;
    use zcash_pool_migration::satisfiability::{
        ReorgSettleDepth, ReplanThreshold, StepSatisfiability, UnsatisfiableCause,
    };
    use zcash_pool_migration::scheduling::AnchorBucketInterval;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::TxId;
    use zcash_protocol::consensus::{BlockHeight, BranchId};
    use zcash_protocol::local_consensus::LocalNetwork;
    use zcash_protocol::value::Zatoshis;

    use super::{Error, PoolMigrations};
    use crate::AccountUuid;
    use crate::testing::{BlockCache, db::TestDb, db::TestDbFactory};
    use crate::util::SystemClock;

    /// The settle depth the anchor-validity tests hold the oracle to; the input-level tests do not
    /// consult it.
    const SETTLE: ReorgSettleDepth = ReorgSettleDepth::new(10);

    /// The repeated byte `b` as a canonical Pallas base element. The top byte is cleared, because
    /// a canonical encoding must be numerically below the field modulus and `0xbb…bb` need not be;
    /// both `Anchor` and `Nullifier` reject anything else.
    fn field_pattern(b: u8) -> [u8; 32] {
        let mut bytes = [b; 32];
        bytes[31] = 0;
        bytes
    }

    /// A root value the wallet's Orchard tree never takes, so an anchor carrying it is displaced
    /// at every checkpoint.
    fn no_such_root() -> Anchor {
        Option::from(Anchor::from_bytes(field_pattern(0xA5)))
            .expect("the pattern is a canonical field element")
    }

    /// The nullifier of no note this wallet has ever seen.
    fn unknown_nullifier() -> Nullifier {
        Option::from(Nullifier::from_bytes(&field_pattern(0xEE)))
            .expect("the pattern is a canonical field element")
    }

    /// A wallet with one scanned Orchard note, assembled by [`scanned_note_fixture`].
    struct ScannedNoteFixture {
        /// The test state holding the wallet.
        st: TestState<BlockCache, TestDb, LocalNetwork>,
        /// The account that received the note.
        account: AccountUuid,
        /// A SECOND account's UUID when requested (same seed, next ZIP 32 index — created
        /// BEFORE anything is scanned, since account creation adjusts the scan queue and would
        /// clear the fully-scanned height afterwards).
        second_account: Option<AccountUuid>,
        /// The note's nullifier, exactly as the scanner recorded it.
        nf: Nullifier,
        /// The wallet's fully-scanned height: the observation basis every answer must carry.
        as_of_height: BlockHeight,
    }

    fn scanned_note_fixture(with_second_account: bool) -> ScannedNoteFixture {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account_id = st
            .test_account()
            .expect("the test account exists")
            .account()
            .id();
        let second_account = with_second_account.then(|| st.create_account_from_test_seed("").0);
        let fvk = OrchardPoolTester::test_account_fvk(&st);
        // The first generated block sits AT the account birthday, so scanning contiguously from
        // it leaves the wallet fully scanned to the last scanned height.
        let (h, _, _) = st.generate_next_block(
            &fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(100_000),
        );
        st.scan_cached_blocks(h, 1);
        let (h2, _) = st.generate_empty_block();
        st.scan_cached_blocks(h2, 1);
        let as_of_height = st
            .wallet()
            .block_fully_scanned()
            .expect("reads the fully-scanned block")
            .expect("the wallet is fully scanned")
            .block_height();
        assert_eq!(
            as_of_height, h2,
            "the wallet is fully scanned to the last block"
        );
        let nf_bytes: [u8; 32] = st
            .wallet()
            .conn()
            .query_row(
                "SELECT nf FROM orchard_received_notes WHERE nf IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .expect("the scanned note has a recorded nullifier");
        let nf = Option::from(Nullifier::from_bytes(&nf_bytes))
            .expect("the scanner records a well-formed nullifier");
        ScannedNoteFixture {
            st,
            account: account_id,
            second_account,
            nf,
            as_of_height,
        }
    }

    /// [`scanned_note_fixture`] without the second account (the common case).
    pub(super) fn wallet_with_scanned_note() -> (
        TestState<BlockCache, TestDb, LocalNetwork>,
        AccountUuid,
        Nullifier,
        BlockHeight,
    ) {
        let ScannedNoteFixture {
            st,
            account,
            nf,
            as_of_height,
            ..
        } = scanned_note_fixture(false);
        (st, account, nf, as_of_height)
    }

    /// A wallet holding an account but having scanned NOTHING: it has no fully-scanned height at
    /// all, so no chain state backs an observation. The counterpart to [`wallet_with_scanned_note`]
    /// for tests whose subject is what the oracle does without a scanned frontier; each such test
    /// asserts the unscanned precondition itself, since that is what its claim rests on.
    pub(super) fn unscanned_wallet() -> (TestState<BlockCache, TestDb, LocalNetwork>, AccountUuid) {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account = st
            .test_account()
            .expect("the test account exists")
            .account()
            .id();
        (st, account)
    }

    /// The real-spend nullifier cache a [`MigrationTransaction`] carries: the engine's persisted
    /// shape is pool-agnostic bytes, so the typed nullifiers a test names are encoded here.
    fn cache(nfs: Vec<Nullifier>) -> Vec<[u8; 32]> {
        nfs.into_iter().map(|nf| nf.to_bytes()).collect()
    }

    /// A pre-signed transfer caching `nfs` as its real-spend nullifiers, in the `Signed` state,
    /// with expiry height `expiry` (`0` disables expiry, per ZIP 203).
    ///
    /// Hand-built rather than drawn from `zcash_pool_migration::testing`'s
    /// `arb_migration_transaction`, like every constructor in this module: the four fields the
    /// oracle's input-level judgment reads — the cache, the expiry, the non-`mined` lifecycle
    /// state, and the absent anchor boundary that keeps the anchor path out of it — are all
    /// pinned by an assertion here. `an_empty_cache_on_a_signed_row_is_corrupt` goes further and
    /// asks for the one pairing `arb_state_and_spend_nullifiers` is written never to generate.
    fn transfer(nfs: Vec<Nullifier>, expiry: u32) -> MigrationTransaction {
        MigrationTransaction::from_parts(
            MigrationTransferId::new(0),
            MigrationTxKind::Transfer { crossing: 0 },
            vec![0xAB],
            Vec::new(),
            BlockHeight::from_u32(0),
            BlockHeight::from_u32(expiry),
            None,
            TxId::from_bytes([0; 32]),
            MigrationTxState::Signed,
            None,
            None,
            cache(nfs),
            None,
        )
    }

    /// A transfer recorded MINED at `height` with an EMPTY real-spend nullifier cache: the shape
    /// the schema migration that introduced the cache leaves behind, since a mined transaction's
    /// disposition no longer turns on its inputs.
    ///
    /// Hand-built rather than drawn from `zcash_pool_migration::testing`'s
    /// `arb_migration_transaction`: every field the assertions turn on is pinned here (the mined
    /// height must be the wallet's own `as_of_height`, and the cache must be empty), which is
    /// precisely what an arbitrary transaction does not give.
    fn mined_transfer_with_empty_cache(height: BlockHeight) -> MigrationTransaction {
        MigrationTransaction::from_parts(
            MigrationTransferId::new(0),
            MigrationTxKind::Transfer { crossing: 0 },
            vec![0xAB],
            Vec::new(),
            BlockHeight::from_u32(0),
            BlockHeight::from_u32(0),
            None,
            TxId::from_bytes([9; 32]),
            MigrationTxState::Mined {
                txid: TxId::from_bytes([9; 32]),
                height,
            },
            None,
            None,
            Vec::new(),
            None,
        )
    }

    /// A PCZT whose Orchard bundle carries `anchor` as its installed anchor, serialized as the
    /// store holds it.
    ///
    /// The anchor judgment reads exactly one field out of a proven transaction's bytes, and the
    /// Creator role installs that field directly, so this stands in for a real proof without a
    /// Halo2 proving run — the whole-migration chain simulation covers the genuinely proven
    /// article.
    fn pczt_anchored_at(anchor: Anchor) -> Vec<u8> {
        pczt::roles::creator::Creator::new(
            BranchId::Nu6_3.into(),
            0,
            133,
            None,
            Some(anchor.to_bytes()),
        )
        .expect("NU6.3 is a supported branch")
        .build()
        .expect("a v6 PCZT may carry an Orchard anchor with no actions")
        .serialize()
        .expect("the PCZT serializes")
    }

    /// A transaction of `kind` in lifecycle state `state`, storing a PCZT with `anchor` installed,
    /// recording `boundary` as the anchor boundary it was proven against, and caching `nfs` as its
    /// real-spend nullifiers.
    ///
    /// `kind`, `state`, and `boundary` are the three fields the anchor-validity tests vary against
    /// one another, so they are the parameters; the rest is filler no assertion reads. The stored
    /// PCZT is why no strategy can stand in here at all: `arb_migration_transaction` draws its
    /// `pczt` as arbitrary bytes, which do not deserialize as a PCZT — let alone carry a chosen
    /// anchor, which is the whole subject of these tests.
    fn anchored_transaction(
        kind: MigrationTxKind,
        state: MigrationTxState,
        boundary: Option<BlockHeight>,
        nfs: Vec<Nullifier>,
        anchor: Anchor,
    ) -> MigrationTransaction {
        MigrationTransaction::from_parts(
            MigrationTransferId::new(0),
            kind,
            pczt_anchored_at(anchor),
            Vec::new(),
            BlockHeight::from_u32(0),
            BlockHeight::from_u32(0),
            boundary,
            // The row's id is the one its lifecycle state carries, where the state has one: the
            // store keeps a single txid column, so a fixture stating two different ones would
            // describe a row it cannot represent.
            match state {
                MigrationTxState::Broadcast { txid } | MigrationTxState::Mined { txid, .. } => txid,
                _ => TxId::from_bytes([0; 32]),
            },
            state,
            None,
            None,
            cache(nfs),
            None,
        )
    }

    /// A pre-signed transfer that has been BROADCAST and not yet mined, proven against `boundary`
    /// with `anchor` installed, and caching `nfs` as its real-spend nullifiers. This is the only
    /// shape the anchor-validity judgment applies to.
    fn broadcast_transfer(
        nfs: Vec<Nullifier>,
        boundary: BlockHeight,
        anchor: Anchor,
    ) -> MigrationTransaction {
        anchored_transaction(
            MigrationTxKind::Transfer { crossing: 0 },
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([7; 32]),
            },
            Some(boundary),
            nfs,
            anchor,
        )
    }

    /// Record a spend of the note with nullifier `nf` by a transaction MINED at `height`, directly
    /// in the wallet tables. This is the definitive on-chain fact the oracle marks on.
    fn record_mined_spend(
        st: &mut TestState<BlockCache, TestDb, LocalNetwork>,
        nf: Nullifier,
        height: BlockHeight,
    ) {
        record_spend(st, nf, Some(height));
    }

    /// Record a spend of the note with nullifier `nf` by a transaction the wallet knows of but has
    /// not seen mined, directly in the wallet tables. The pre-signed transaction and this spender
    /// are then merely competing for the note, so the oracle must not mark on it.
    fn record_unmined_spend(st: &mut TestState<BlockCache, TestDb, LocalNetwork>, nf: Nullifier) {
        record_spend(st, nf, None);
    }

    /// The shared body behind [`record_mined_spend`] and [`record_unmined_spend`]: insert a
    /// spending transaction with mined height `mined_height` and join it to the note with
    /// nullifier `nf`. The oracle reads only the spend join and the spender's mined height, so
    /// nothing here requires a fully-formed spending transaction.
    ///
    /// The spender's txid is the SPENT NOTE'S NULLIFIER, a test-only fabrication: no transaction
    /// is built here, so there is nothing to hash. Deriving it keeps each spender's txid distinct
    /// per note without introducing randomness, which `transactions.txid` (unique) requires and a
    /// repeated constant would violate the moment a test records two spends.
    fn record_spend(
        st: &mut TestState<BlockCache, TestDb, LocalNetwork>,
        nf: Nullifier,
        mined_height: Option<BlockHeight>,
    ) {
        let conn = st.wallet_mut().conn_mut();
        conn.execute(
            "INSERT INTO transactions (txid, mined_height, min_observed_height)
             VALUES (:txid, :mined_height, :min_observed_height)",
            named_params! {
                ":txid": nf.to_bytes(),
                ":mined_height": mined_height.map(u32::from),
                // An arbitrary observation height; the constraint only requires it at or below
                // the mined height when one exists.
                ":min_observed_height": mined_height.map_or(1, u32::from),
            },
        )
        .expect("inserts the spending transaction");
        let tx_ref = conn.last_insert_rowid();
        let spends = conn
            .execute(
                "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id)
                 SELECT id, :tx_ref FROM orchard_received_notes WHERE nf = :nf",
                named_params! {":tx_ref": tx_ref, ":nf": nf.to_bytes()},
            )
            .expect("records the spend");
        assert_eq!(
            spends, 1,
            "exactly the one note with this nullifier is spent"
        );
    }

    #[test]
    fn known_unspent_inputs_are_satisfiable() {
        let (mut st, account, nf, as_of_height) = wallet_with_scanned_note();
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&transfer(vec![nf], 0), SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::Satisfiable { as_of_height },
        );
    }

    #[test]
    fn a_mined_spend_marks_inputs_spent() {
        let (mut st, account, nf, as_of_height) = wallet_with_scanned_note();
        record_mined_spend(&mut st, nf, as_of_height);
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&transfer(vec![nf], 0), SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::InputsSpent {
                    nullifiers: vec![nf.to_bytes()]
                },
                as_of_height,
            },
            "the answer carries exactly the spent nullifier",
        );
    }

    /// Spend evidence recorded AHEAD of the scanned region does not obstruct yet: a mark's
    /// evidence must lie at or below the `as_of_height` backing it, because reorg truncation
    /// clears marks by their stamped height — evidence at height <= `as_of_height` guarantees a
    /// rollback of the evidence forces a truncation below the mark, so no false mark can survive.
    /// Once scanning catches up to the evidence, the same stored state obstructs.
    #[test]
    fn evidence_ahead_of_the_scanned_region_does_not_obstruct_yet() {
        let (mut st, account, nf, as_of_height) = wallet_with_scanned_note();
        // Transaction-status polling can record a spender's mined height before scanning
        // reaches it: the spender sits one block above the fully-scanned height.
        record_mined_spend(&mut st, nf, as_of_height + 1);
        {
            let store = PoolMigrations::for_account(
                *st.network(),
                SystemClock,
                st.wallet_mut().conn_mut(),
                account,
            )
            .expect("the account exists");
            assert_eq!(
                store
                    .check_step_satisfiability(&transfer(vec![nf], 0), SETTLE)
                    .expect("the oracle answers"),
                StepSatisfiability::Satisfiable { as_of_height },
                "evidence above the scanned region must not obstruct yet",
            );
        }
        // Scan past the spender's height; the evidence now lies inside the scanned region.
        let (h3, _) = st.generate_empty_block();
        st.scan_cached_blocks(h3, 1);
        assert_eq!(
            h3,
            as_of_height + 1,
            "the next block is the spender's height"
        );
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&transfer(vec![nf], 0), SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::InputsSpent {
                    nullifiers: vec![nf.to_bytes()]
                },
                as_of_height: h3,
            },
        );
    }

    /// A recorded but UNMINED spender does not obstruct: the pre-signed transaction and the
    /// recorded spender are then merely competing for the note, and only a mined spend is the
    /// definitive on-chain fact.
    #[test]
    fn an_unmined_spend_does_not_obstruct() {
        let (mut st, account, nf, as_of_height) = wallet_with_scanned_note();
        record_unmined_spend(&mut st, nf);
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&transfer(vec![nf], 0), SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::Satisfiable { as_of_height },
        );
    }

    #[test]
    fn an_unknown_nullifier_is_not_yet_satisfiable() {
        let (mut st, account, _nf, as_of_height) = wallet_with_scanned_note();
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&transfer(vec![unknown_nullifier()], 0), SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::NotYetSatisfiable { as_of_height },
        );
    }

    /// Expiry is judged at the next block a mined observation could extend (`as_of_height + 1`),
    /// mirroring the engine's `is_expired`: an expiry AT the fully-scanned height can no longer
    /// mine, one just above it still can.
    #[test]
    fn expiry_is_judged_at_the_next_block() {
        let (mut st, account, nf, as_of_height) = wallet_with_scanned_note();
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&transfer(vec![nf], u32::from(as_of_height)), SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::Expired,
                as_of_height,
            },
        );
        assert_eq!(
            store
                .check_step_satisfiability(&transfer(vec![nf], u32::from(as_of_height) + 1), SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::Satisfiable { as_of_height },
        );
    }

    /// An empty nullifier cache on a non-mined row is CORRUPTION, never vacuous satisfiability:
    /// every validly committed transaction caches its real-spend nullifiers. The wallet here has
    /// scanned NOTHING (no fully-scanned height at all): corruption needs no chain state, so it
    /// is reported ahead of [`Error::ChainStateUnavailable`], never masked by it.
    #[test]
    fn an_empty_cache_on_a_signed_row_is_corrupt() {
        let (mut st, account) = unscanned_wallet();
        assert!(
            st.wallet()
                .block_fully_scanned()
                .expect("reads the fully-scanned block")
                .is_none(),
            "nothing is scanned, so no chain state backs an observation",
        );
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert!(matches!(
            store.check_step_satisfiability(&transfer(Vec::new(), 0), SETTLE),
            Err(Error::Corrupt("spend_nullifiers")),
        ));
    }

    /// A MINED row is exempt from the nullifier backfill, so its empty cache is not corruption:
    /// the oracle answers (vacuously satisfiable over zero observations — a mined transaction's
    /// disposition no longer turns on its inputs) rather than erroring.
    #[test]
    fn a_mined_row_with_an_empty_cache_answers() {
        let (mut st, account, _nf, as_of_height) = wallet_with_scanned_note();
        let mined = mined_transfer_with_empty_cache(as_of_height);
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&mined, SETTLE)
                .expect("the oracle answers rather than erroring"),
            StepSatisfiability::Satisfiable { as_of_height },
        );
    }

    /// Reorg truncation composes with the empty-cache corruption guard: a MINED row is exempt
    /// from the nullifier backfill, so its empty cache answers (the mined exemption above), but
    /// once `MigrationState::truncate_to_height` demotes it to `Broadcast` — driven through the
    /// pool-migration API exactly as a consumer's reorg hook would (load, truncate, replace) —
    /// the SAME row is non-mined with an empty cache: loud corruption at its next check, never
    /// vacuous satisfiability.
    #[test]
    fn truncation_demotes_a_backfill_exempt_row_into_the_corruption_guard() {
        let (mut st, account, _nf, as_of_height) = wallet_with_scanned_note();
        let mined = mined_transfer_with_empty_cache(as_of_height);
        // Hand-built for `mined_transfer_with_empty_cache`'s reason: nothing outside the mined row
        // is read, so the envelope around it is the minimum a store will accept.
        let state = MigrationState::from_parts(
            MigrationStatus::InProgress,
            DenominationPlan::from_stored_parts(
                Vec::new(),
                Zatoshis::ZERO,
                None,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
            )
            .expect("an empty stored plan reconstructs"),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![mined],
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        );
        let mut store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        store
            .replace_migration(&state)
            .expect("persists the mined row");

        // The mined exemption: the empty cache answers rather than erroring.
        let loaded = store
            .get_migration()
            .expect("reads the migration")
            .expect("the migration is present");
        assert_eq!(
            store
                .check_step_satisfiability(&loaded.transactions()[0], SETTLE)
                .expect("a mined row with an empty cache answers"),
            StepSatisfiability::Satisfiable { as_of_height },
        );

        // A rewind below the mined height: load, truncate, replace.
        let mut truncated = loaded;
        truncated.truncate_to_height(as_of_height - 1);
        assert!(matches!(
            truncated.transactions()[0].state(),
            MigrationTxState::Broadcast { txid } if txid == TxId::from_bytes([9; 32])
        ));
        store
            .replace_migration(&truncated)
            .expect("persists the demoted row");

        // The SAME row, demoted, hits the empty-cache corruption guard.
        let reloaded = store
            .get_migration()
            .expect("reads the migration")
            .expect("the migration is present");
        assert!(matches!(
            store.check_step_satisfiability(&reloaded.transactions()[0], SETTLE),
            Err(Error::Corrupt("spend_nullifiers")),
        ));
    }

    /// An in-flight transfer whose installed anchor is still the tree's root at the boundary it
    /// was proven against is not obstructed: the chain the wallet has scanned still contains the
    /// state the proof was made over.
    #[test]
    fn an_anchor_still_rooted_at_its_boundary_is_satisfiable() {
        let (mut st, account, nf, _) = wallet_with_scanned_note();
        let as_of_height = st.generate_and_scan_empty_blocks(12);
        let boundary = as_of_height - SETTLE.blocks();
        let anchor = st
            .orchard_anchor_at(boundary)
            .expect("reads the Orchard commitment tree")
            .expect("the boundary's checkpoint is retained");

        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&broadcast_transfer(vec![nf], boundary, anchor), SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::Satisfiable { as_of_height },
        );
    }

    /// The settlement boundary, exactly. A displacement is definitive only once the scanned chain
    /// has built `settle` blocks on top of the boundary whose content changed: one block short of
    /// that depth nothing is concluded, and AT that depth the transfer is unsatisfiable through
    /// `AnchorInvalidated`. Both answers come from the same stored transaction and the same
    /// wallet; only the boundary's distance below the fully-scanned height differs.
    #[test]
    fn an_anchor_displacement_marks_exactly_at_the_settle_depth() {
        let (mut st, account, nf, _) = wallet_with_scanned_note();
        let as_of_height = st.generate_and_scan_empty_blocks(12);
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");

        assert_eq!(
            store
                .check_step_satisfiability(
                    &broadcast_transfer(
                        vec![nf],
                        as_of_height - (SETTLE.blocks() - 1),
                        no_such_root()
                    ),
                    SETTLE,
                )
                .expect("the oracle answers"),
            StepSatisfiability::Satisfiable { as_of_height },
            "one block short of the settle depth concludes nothing",
        );
        assert_eq!(
            store
                .check_step_satisfiability(
                    &broadcast_transfer(vec![nf], as_of_height - SETTLE.blocks(), no_such_root()),
                    SETTLE,
                )
                .expect("the oracle answers"),
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::AnchorInvalidated,
                as_of_height,
            },
            "at the settle depth the displacement is definitive",
        );
    }

    /// A tree state the search cannot produce a root for is a state that was NOT ruled out, so it
    /// ends the search without concluding: the mark rests on an EXHAUSTIVE negative, and a search
    /// that skipped an unreadable state would not be one.
    ///
    /// The fixture is the marking case from
    /// [`an_anchor_displacement_marks_exactly_at_the_settle_depth`] — asserted first, so the
    /// difference is exactly the unreadable state — plus one checkpoint whose recorded tree
    /// position lies beyond any shard data the wallet holds, which is how a retained checkpoint
    /// the tree can no longer complete a root for presents itself.
    #[test]
    fn an_unreadable_tree_state_ends_the_search_without_marking() {
        let (mut st, account, nf, _) = wallet_with_scanned_note();
        let as_of_height = st.generate_and_scan_empty_blocks(12);
        let displaced =
            broadcast_transfer(vec![nf], as_of_height - SETTLE.blocks(), no_such_root());

        {
            let store = PoolMigrations::for_account(
                *st.network(),
                SystemClock,
                st.wallet_mut().conn_mut(),
                account,
            )
            .expect("the account exists");
            assert_eq!(
                store
                    .check_step_satisfiability(&displaced, SETTLE)
                    .expect("the oracle answers"),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::AnchorInvalidated,
                    as_of_height,
                },
                "without the unreadable state, this displacement is definitive",
            );
        }

        // A checkpoint below the scanned region whose position is past everything the tree holds:
        // the tree finds the checkpoint but cannot complete a root over that many commitments.
        st.wallet_mut()
            .conn_mut()
            .execute(
                "INSERT INTO orchard_tree_checkpoints (checkpoint_id, position)
                 VALUES (:checkpoint_id, :position)",
                named_params! {
                    ":checkpoint_id": u32::from(as_of_height) - 50,
                    ":position": u64::from(u32::MAX),
                },
            )
            .expect("records a checkpoint the tree cannot root");

        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&displaced, SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::Satisfiable { as_of_height },
            "a state the search could not read is a state it did not rule out",
        );
    }

    /// Evidence-height discipline for the anchor judgment, isolated from settlement by asking at
    /// depth zero: a boundary ABOVE the fully-scanned height is outside the region backing the
    /// answer — its checkpoint may still be rewritten by scanning that has not happened — so it
    /// concludes nothing, however displaced the anchor looks. Once scanning closes the gap, the
    /// SAME stored transaction is marked.
    #[test]
    fn an_anchor_displacement_above_the_scanned_region_does_not_mark() {
        const IMMEDIATE: ReorgSettleDepth = ReorgSettleDepth::new(0);

        let (mut st, account, nf, as_of_height) = wallet_with_scanned_note();
        // Three further blocks, of which only the last is scanned: the commitment tree gains a
        // checkpoint at that height while the fully-scanned height stays below the gap.
        let (gap, _) = st.generate_empty_block();
        let (_, _) = st.generate_empty_block();
        let (high, _) = st.generate_empty_block();
        st.scan_cached_blocks(high, 1);
        assert_eq!(
            st.wallet()
                .block_fully_scanned()
                .expect("reads the fully-scanned block")
                .expect("the wallet is fully scanned to the pre-gap height")
                .block_height(),
            as_of_height,
            "the unscanned gap holds the fully-scanned height below the new checkpoint",
        );

        let tx = broadcast_transfer(vec![nf], high, no_such_root());
        {
            let store = PoolMigrations::for_account(
                *st.network(),
                SystemClock,
                st.wallet_mut().conn_mut(),
                account,
            )
            .expect("the account exists");
            assert_eq!(
                store
                    .check_step_satisfiability(&tx, IMMEDIATE)
                    .expect("the oracle answers"),
                StepSatisfiability::Satisfiable { as_of_height },
                "a boundary above the scanned region must not obstruct yet",
            );
        }

        // Close the gap; the boundary now lies inside the region backing the answer.
        st.scan_cached_blocks(gap, 2);
        let as_of_height = st.generate_and_scan_empty_blocks(1);
        assert!(
            as_of_height >= high,
            "the scanned region now reaches the boundary at {high:?}",
        );
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&tx, IMMEDIATE)
                .expect("the oracle answers"),
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::AnchorInvalidated,
                as_of_height,
            },
        );
    }

    /// The anchor judgment applies only to a BROADCAST transaction. The same displaced anchor on a
    /// still-`Signed` transfer concludes nothing: nothing has been committed to the network, so
    /// the transfer will simply be proven afresh against a live boundary.
    #[test]
    fn a_displaced_anchor_on_an_unbroadcast_transfer_does_not_mark() {
        let (mut st, account, nf, _) = wallet_with_scanned_note();
        let as_of_height = st.generate_and_scan_empty_blocks(12);
        // Exactly `broadcast_transfer`'s shape but for the lifecycle state: the boundary still
        // sits at the settle depth, so only the state can be what prevents the mark.
        let signed = anchored_transaction(
            MigrationTxKind::Transfer { crossing: 0 },
            MigrationTxState::Signed,
            Some(as_of_height - SETTLE.blocks()),
            vec![nf],
            no_such_root(),
        );

        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&signed, SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::Satisfiable { as_of_height },
        );
    }

    /// A spent input outranks a dead anchor: the answer precedence puts `InputsSpent` above the
    /// anchor-level cause, and the in-flight sweep acts only on the latter, so an in-flight
    /// transaction seen spending its own inputs (most often because it is mining) is not marked
    /// by this route.
    #[test]
    fn a_spent_input_outranks_a_displaced_anchor() {
        let (mut st, account, nf, _) = wallet_with_scanned_note();
        let as_of_height = st.generate_and_scan_empty_blocks(12);
        record_mined_spend(&mut st, nf, as_of_height);

        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(
                    &broadcast_transfer(vec![nf], as_of_height - SETTLE.blocks(), no_such_root()),
                    SETTLE,
                )
                .expect("the oracle answers"),
            StepSatisfiability::Unsatisfiable {
                cause: UnsatisfiableCause::InputsSpent {
                    nullifiers: vec![nf.to_bytes()]
                },
                as_of_height,
            },
        );
    }

    /// A PREPARATION is not judged: it records no anchor boundary — its proving height is chosen
    /// by the caller and persisted nowhere — so there is neither a root to compare against nor a
    /// reference height to settle a comparison at. It reads as unobstructed however displaced its
    /// installed anchor is.
    #[test]
    fn a_broadcast_preparation_is_not_anchor_judged() {
        let (mut st, account, nf, _) = wallet_with_scanned_note();
        let as_of_height = st.generate_and_scan_empty_blocks(12);
        // `broadcast_transfer`'s shape but for the kind, and the absent boundary that follows from
        // it: a preparation records none.
        let prep = anchored_transaction(
            MigrationTxKind::Preparation { layer: 0, index: 0 },
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([7; 32]),
            },
            None,
            vec![nf],
            no_such_root(),
        );

        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&prep, SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::Satisfiable { as_of_height },
        );
    }

    /// The observations are scoped to the store's account: the same nullifier, asked about
    /// through a DIFFERENT account's store over the same wallet database, reads as `Unknown`
    /// (that account has seen no such note), so the answer is not-yet-satisfiable rather than
    /// anything derived from another account's notes.
    #[test]
    fn observations_are_scoped_to_the_stores_account() {
        let ScannedNoteFixture {
            mut st,
            second_account,
            nf,
            as_of_height,
            ..
        } = scanned_note_fixture(true);
        let other_account = second_account.expect("the fixture created a second account");
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            other_account,
        )
        .expect("the second account exists");
        assert_eq!(
            store
                .check_step_satisfiability(&transfer(vec![nf], 0), SETTLE)
                .expect("the oracle answers"),
            StepSatisfiability::NotYetSatisfiable { as_of_height },
        );
    }
}

/// The wallet's own truncation drives every stored migration's, at the height it ACTUALLY
/// truncated to: a migration's chain-derived state is exactly as revocable as the wallet's, and a
/// The store's MINING lookup (`PoolMigrationRead::mined_height`) — the forward half of
/// chain-derived state, answered from the wallet's own `transactions` table and bounded by the
/// fully-scanned height, on which `advance_migration` promotes an in-flight transaction to `Mined`
/// with no consumer involvement.
#[cfg(all(test, feature = "orchard"))]
mod mined_height {
    use rusqlite::named_params;

    use core::convert::Infallible;

    use zcash_client_backend::data_api::Account as _;
    use zcash_client_backend::data_api::WalletRead as _;
    use zcash_client_backend::data_api::testing::TestState;
    use zcash_pool_migration::engine::{MigrationState, MigrationTransaction, PoolMigrationRead};
    use zcash_pool_migration::satisfiability::{ReorgSettleDepth, StepSatisfiability};
    use zcash_pool_migration::wallet::WalletMigration;
    use zcash_protocol::TxId;
    use zcash_protocol::consensus::BlockHeight;
    use zcash_protocol::local_consensus::LocalNetwork;

    use super::PoolMigrations;
    use super::check_step_satisfiability::{unscanned_wallet, wallet_with_scanned_note};
    use crate::AccountUuid;
    use crate::testing::{BlockCache, db::TestDb};
    use crate::util::SystemClock;

    /// A store that refuses every question, so a [`WalletMigration`] built over it can only answer
    /// from the WALLET. That is what makes [`store_and_adapter_agree`] a real comparison: an
    /// adapter that delegated its mining lookup to its store would panic here rather than
    /// trivially agreeing with the store it delegated to.
    struct NoStore;

    impl PoolMigrationRead for NoStore {
        type Error = Infallible;

        fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            panic!("the mining comparison reads no migration")
        }

        fn check_step_satisfiability(
            &self,
            _tx: &MigrationTransaction,
            _settle: ReorgSettleDepth,
        ) -> Result<StepSatisfiability, Self::Error> {
            panic!("the mining comparison consults no oracle")
        }

        fn mined_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
            panic!("the adapter must answer mined_height from the wallet, not from its store")
        }
    }

    /// Ask both implementations of the mining lookup about `txid` over one wallet — this store,
    /// and `zcash_pool_migration`'s [`WalletMigration`] adapter reading the same wallet directly —
    /// assert they agree, and return the answer they agree on.
    ///
    /// The two encode the same rollback-safety rule at different layers: the store applies the
    /// fully-scanned bound in SQL, the adapter applies it over `WalletRead`. An application built
    /// on this crate has both in play at once (the adapter's `PoolMigrationRead` impl wraps this
    /// store), so a disagreement would make a migration's promotions depend on which one the
    /// caller happened to hold — which is precisely the reason the adapter delegates nothing here.
    fn store_and_adapter_agree(
        st: &mut TestState<BlockCache, TestDb, LocalNetwork>,
        account: AccountUuid,
        txid: TxId,
    ) -> Option<BlockHeight> {
        let from_store = {
            let store = PoolMigrations::for_account(
                *st.network(),
                SystemClock,
                st.wallet_mut().conn_mut(),
                account,
            )
            .expect("the account exists");
            store.mined_height(txid).expect("the store answers")
        };

        // The adapter reads the wallet through `WalletRead`, so it needs the wallet itself — hence
        // the store borrow above ends before this one begins.
        let ufvk = st
            .wallet()
            .db()
            .get_account(account)
            .expect("the account reads")
            .expect("the account exists")
            .ufvk()
            .expect("the account has a unified full viewing key")
            .clone();
        let adapter = WalletMigration::new(st.wallet().db(), account, ufvk, NoStore);
        let from_adapter = adapter.mined_height(txid).expect("the adapter answers");

        assert_eq!(
            from_store, from_adapter,
            "the store and the wallet-backed adapter must report one mined height for {txid:?}",
        );
        from_store
    }

    /// Insert a transaction the wallet knows of, at `mined_height`, with no spend join: the mining
    /// lookup reads `transactions` alone, so nothing here needs a note or a spender.
    fn record_transaction(
        st: &mut TestState<BlockCache, TestDb, LocalNetwork>,
        txid: TxId,
        mined_height: Option<BlockHeight>,
    ) {
        st.wallet_mut()
            .conn_mut()
            .execute(
                "INSERT INTO transactions (txid, mined_height, min_observed_height)
                 VALUES (:txid, :mined_height, :min_observed_height)",
                named_params! {
                    ":txid": txid.as_ref(),
                    ":mined_height": mined_height.map(u32::from),
                    ":min_observed_height": mined_height.map_or(1, u32::from),
                },
            )
            .expect("inserts the transaction");
    }

    /// The forward half of chain-derived state: a transaction the scan has seen mined inside the
    /// scanned region reports its height, and that is what the drive loop promotes on.
    #[test]
    fn mined_height_reports_a_transaction_inside_the_scanned_region() {
        let (mut st, account, _nf, as_of_height) = wallet_with_scanned_note();
        let txid = TxId::from_bytes([3; 32]);
        record_transaction(&mut st, txid, Some(as_of_height));
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store.mined_height(txid).expect("the store answers"),
            Some(as_of_height),
        );
    }

    /// The same discipline the unsatisfiability marks rest on, applied to inclusion:
    /// `transactions.mined_height` is also written by transaction-status retrieval, which can
    /// learn a transaction mined before scanning reaches its block. Promoting on that would stamp
    /// `Mined` above the region a rollback truncates, so it is withheld until the scan arrives.
    #[test]
    fn mined_height_withholds_a_transaction_above_the_scanned_region() {
        let (mut st, account, _nf, as_of_height) = wallet_with_scanned_note();
        let txid = TxId::from_bytes([4; 32]);
        record_transaction(&mut st, txid, Some(as_of_height + 1));
        {
            let store = PoolMigrations::for_account(
                *st.network(),
                SystemClock,
                st.wallet_mut().conn_mut(),
                account,
            )
            .expect("the account exists");
            assert_eq!(
                store.mined_height(txid).expect("the store answers"),
                None,
                "a mined height above the scanned region is not yet promotable",
            );
        }
        // Scan past it; the inclusion now lies inside the scanned region.
        let (h3, _) = st.generate_empty_block();
        st.scan_cached_blocks(h3, 1);
        assert_eq!(h3, as_of_height + 1, "the next block is the mined height");
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store.mined_height(txid).expect("the store answers"),
            Some(h3)
        );
    }

    /// The two ways there is nothing to promote: a transaction the wallet has never heard of, and
    /// one it knows of but has not seen mined (in the mempool, or awaiting retrieval).
    #[test]
    fn mined_height_is_none_for_an_unknown_or_unmined_transaction() {
        let (mut st, account, _nf, _as_of_height) = wallet_with_scanned_note();
        let unmined = TxId::from_bytes([5; 32]);
        record_transaction(&mut st, unmined, None);
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(
            store.mined_height(unmined).expect("the store answers"),
            None
        );
        assert_eq!(
            store
                .mined_height(TxId::from_bytes([6; 32]))
                .expect("the store answers"),
            None,
            "a transaction the wallet has never heard of",
        );
    }

    /// A wallet that has scanned nothing has no view to answer from, so it reports nothing mined
    /// rather than erroring: the sweep this serves runs on every drive call, including before a
    /// wallet has ever synced.
    #[test]
    fn mined_height_on_an_unscanned_wallet_is_none() {
        let (mut st, account) = unscanned_wallet();
        let txid = TxId::from_bytes([7; 32]);
        record_transaction(&mut st, txid, Some(BlockHeight::from_u32(100)));
        let store = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists");
        assert_eq!(store.mined_height(txid).expect("the store answers"), None);
    }

    /// This store and `zcash_pool_migration`'s `WalletMigration` adapter answer the mining lookup
    /// ALIKE, over one wallet, in every state that distinguishes the rule: an unscanned wallet, an
    /// inclusion inside the fully-scanned region, and one observed only above it.
    ///
    /// Two implementations of one rule is the thing worth testing here. The adapter is what an
    /// application drives the engine through, and it wraps this store, so the pair is live in
    /// every real migration; they nonetheless read the wallet by different routes (SQL over
    /// `transactions` bounded by `fully_scanned_height`, versus `WalletRead::get_tx_height`
    /// bounded by `block_fully_scanned`). Because they agree, the adapter needs no delegation to
    /// this store to be correct — and this is what would catch the day one of the two routes
    /// stopped applying the bound.
    #[test]
    fn the_store_and_the_wallet_adapter_report_one_mined_height() {
        // Nothing scanned: no chain state backs an inclusion, so a transaction the wallet has been
        // TOLD about (status retrieval, say) is still not promotable. The adapter must reach this
        // answer without erroring, which is why it reads the fully-scanned bound before asking
        // about the transaction at all.
        let (mut st, account) = unscanned_wallet();
        assert!(
            st.wallet()
                .block_fully_scanned()
                .expect("reads the fully-scanned block")
                .is_none(),
            "precondition: the wallet has scanned nothing",
        );
        let unscanned_txid = TxId::from_bytes([8; 32]);
        record_transaction(&mut st, unscanned_txid, Some(BlockHeight::from_u32(100)));
        assert_eq!(
            store_and_adapter_agree(&mut st, account, unscanned_txid),
            None,
            "an unscanned wallet promotes nothing",
        );

        let (mut st, account, _nf, as_of_height) = wallet_with_scanned_note();

        // Inside the fully-scanned region: both report the height, and the drive promotes on it.
        let mined_txid = TxId::from_bytes([9; 32]);
        record_transaction(&mut st, mined_txid, Some(as_of_height));
        assert_eq!(
            store_and_adapter_agree(&mut st, account, mined_txid),
            Some(as_of_height),
        );

        // Above it: a mined height the wallet learned ahead of scanning is withheld by both, so
        // neither can promote onto a block whose rollback would not truncate the promotion.
        let ahead_txid = TxId::from_bytes([10; 32]);
        record_transaction(&mut st, ahead_txid, Some(as_of_height + 1));
        assert_eq!(
            store_and_adapter_agree(&mut st, account, ahead_txid),
            None,
            "an inclusion above the scanned region is not yet promotable",
        );

        // And the two absences that are not about the bound at all: a known-but-unmined
        // transaction, and one the wallet has never heard of.
        let unmined_txid = TxId::from_bytes([11; 32]);
        record_transaction(&mut st, unmined_txid, None);
        assert_eq!(
            store_and_adapter_agree(&mut st, account, unmined_txid),
            None
        );
        assert_eq!(
            store_and_adapter_agree(&mut st, account, TxId::from_bytes([12; 32])),
            None,
        );
    }
}

/// consumer has no reorg hook to remember.
#[cfg(all(test, feature = "orchard"))]
mod truncation_follows_the_wallet {
    use zcash_client_backend::data_api::testing::{
        AddressType, TestBuilder, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
    };
    use zcash_client_backend::data_api::{Account as _, WalletRead, WalletWrite};
    use zcash_pool_migration::denomination::DenominationPlan;
    use zcash_pool_migration::engine::{
        MigrationState, MigrationStatus, MigrationTransaction, MigrationTransferId,
        MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
    };
    use zcash_pool_migration::preparation::PreparationPlan;
    use zcash_pool_migration::satisfiability::{ReplanThreshold, UnsatisfiableKind};
    use zcash_pool_migration::scheduling::AnchorBucketInterval;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::TxId;
    use zcash_protocol::consensus::BlockHeight;
    use zcash_protocol::value::Zatoshis;

    use super::PoolMigrations;
    use crate::testing::{BlockCache, db::TestDbFactory};
    use crate::util::SystemClock;

    /// A migration transaction in `state`, marked at `unsatisfiable_at`; the plan-shaped fields are
    /// immaterial to truncation. A mark is a stamp and a kind together, and truncation treats every
    /// kind alike, so the kind is FIXED at an observed spend — which is what lets the surviving
    /// mark be asserted whole, stamp and kind, rather than only by its height.
    ///
    /// Hand-built rather than drawn from `zcash_pool_migration::testing`'s
    /// `arb_migration_transaction`: the id orders the rows the assertions index by, and the
    /// lifecycle state and the mark are the two things truncation acts on, so all three are
    /// caller-chosen here.
    fn tx(
        id: u32,
        state: MigrationTxState,
        unsatisfiable_at: Option<BlockHeight>,
    ) -> MigrationTransaction {
        MigrationTransaction::from_parts(
            MigrationTransferId::new(id),
            MigrationTxKind::Transfer {
                crossing: id as usize,
            },
            vec![0xAB],
            Vec::new(),
            BlockHeight::from_u32(0),
            BlockHeight::from_u32(0),
            None,
            // One txid per row: where the lifecycle state carries one, that IS the row's.
            match state {
                MigrationTxState::Broadcast { txid } | MigrationTxState::Mined { txid, .. } => txid,
                _ => TxId::from_bytes([id as u8; 32]),
            },
            state,
            None,
            unsatisfiable_at.map(|at| (at, UnsatisfiableKind::InputsSpent)),
            vec![[id as u8; 32]],
            None,
        )
    }

    /// A migration in `status` carrying `transactions`.
    fn migration(
        status: MigrationStatus,
        transactions: Vec<MigrationTransaction>,
    ) -> MigrationState {
        MigrationState::from_parts(
            status,
            DenominationPlan::from_stored_parts(
                Vec::new(),
                Zatoshis::ZERO,
                None,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
            )
            .expect("an empty stored plan reconstructs"),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            transactions,
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        )
    }

    #[test]
    fn wallet_truncation_rolls_back_marks_mined_heights_and_status() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account = st
            .test_account()
            .expect("the test account exists")
            .account()
            .id();
        let fvk = OrchardPoolTester::test_account_fvk(&st);
        let (h, _, _) = st.generate_next_block(
            &fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(100_000),
        );
        st.scan_cached_blocks(h, 1);
        st.generate_and_scan_empty_blocks(12);
        let tip = st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");

        // A COMPLETE migration: one transaction mined well below the coming truncation, one mined
        // above it.
        let low = tip - 6;
        let mined = |txid: u8, height: BlockHeight| MigrationTxState::Mined {
            txid: TxId::from_bytes([txid; 32]),
            height,
        };
        {
            let mut store = PoolMigrations::for_account(
                *st.network(),
                SystemClock,
                st.wallet_mut().conn_mut(),
                account,
            )
            .expect("the account exists");
            store
                .replace_migration(&migration(
                    MigrationStatus::Complete,
                    vec![tx(0, mined(0xA0, low), None), tx(1, mined(0xA1, tip), None)],
                ))
                .expect("persists the migration");
        }

        // Truncate the WALLET; nothing tells the migration store directly.
        let truncated_to = st
            .wallet_mut()
            .truncate_to_height(tip - 3)
            .expect("the wallet truncates");
        assert!(
            truncated_to < tip,
            "the truncation moved the chain view back"
        );

        let state = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists")
        .get_migration()
        .expect("reads the migration")
        .expect("the migration is present");
        assert_eq!(
            state.transactions()[0].state(),
            mined(0xA0, low),
            "a transaction mined below the truncation stays mined",
        );
        assert_eq!(
            state.transactions()[1].state(),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([0xA1; 32])
            },
            "a transaction mined above the truncation is demoted, keeping its txid",
        );
        assert_eq!(
            state.status(),
            MigrationStatus::InProgress,
            "a Complete status the demotion unsettles reverts",
        );

        // And the marks: an in-flight transaction marked on evidence above the next truncation
        // loses that mark, while one marked below keeps it.
        {
            let mut store = PoolMigrations::for_account(
                *st.network(),
                SystemClock,
                st.wallet_mut().conn_mut(),
                account,
            )
            .expect("the account exists");
            store
                .replace_migration(&migration(
                    MigrationStatus::InProgress,
                    vec![
                        tx(
                            0,
                            MigrationTxState::Broadcast {
                                txid: TxId::from_bytes([0xB0; 32]),
                            },
                            Some(truncated_to),
                        ),
                        tx(
                            1,
                            MigrationTxState::Broadcast {
                                txid: TxId::from_bytes([0xB1; 32]),
                            },
                            Some(low),
                        ),
                    ],
                ))
                .expect("persists the marked migration");
        }

        let deeper = st
            .wallet_mut()
            .truncate_to_height(truncated_to - 2)
            .expect("the wallet truncates again");
        assert!(deeper < truncated_to);
        assert!(
            low <= deeper,
            "the surviving mark rests below the truncation"
        );

        let state = PoolMigrations::for_account(
            *st.network(),
            SystemClock,
            st.wallet_mut().conn_mut(),
            account,
        )
        .expect("the account exists")
        .get_migration()
        .expect("reads the migration")
        .expect("the migration is present");
        assert_eq!(
            (
                state.transactions()[0].unsatisfiable_at(),
                state.transactions()[0].unsatisfiable_kind()
            ),
            (None, None),
            "a mark resting on chain state the truncation discarded is cleared, kind and all",
        );
        assert_eq!(
            (
                state.transactions()[1].unsatisfiable_at(),
                state.transactions()[1].unsatisfiable_kind()
            ),
            (Some(low), Some(UnsatisfiableKind::InputsSpent)),
            "a mark resting on retained chain state stands, keeping what it recorded",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, PoolMigrations, init_migration_tables};
    use zcash_protocol::TxId;

    use proptest::prelude::*;
    use rusqlite::Connection;
    use uuid::Uuid;

    use zcash_pool_migration::{
        denomination::DenominationPlan,
        engine::{
            MigrationLockOwner, MigrationState, MigrationStatus, MigrationTransaction,
            MigrationTransferId, MigrationTxKind, MigrationTxState, PoolMigrationRead,
            PoolMigrationWrite,
        },
        preparation::PreparationPlan,
        satisfiability::{
            DuenessTargets, ReorgSettleDepth, ReplanThreshold, StepSatisfiability,
            UnsatisfiableCause, UnsatisfiableKind,
        },
        scheduling::AnchorBucketInterval,
        testing::{
            arb_migration_state, arb_migration_tx_state, assert_empty_is_none,
            assert_put_get_roundtrip, assert_put_replaces, assert_update_transaction,
            first_transaction_id,
        },
    };

    use crate::AccountUuid;
    use crate::util::SystemClock;

    use core::num::NonZeroU32;
    use std::collections::BTreeSet;
    use zcash_client_backend::data_api::testing::TestBuilder;
    use zcash_client_backend::wallet::LockOwner;
    use zcash_protocol::local_consensus::LocalNetwork;
    use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

    /// Consensus parameters for stores whose wallet context is carried but never consulted: no
    /// test in this module finalizes a proved transaction.
    const NET: LocalNetwork = TestBuilder::<(), ()>::DEFAULT_NETWORK;

    /// A fresh in-memory database with a minimal `accounts` table (the `account_id` foreign-key
    /// target) and the migration tables created, but not yet wrapped as a store for any particular
    /// account. Used by tests that put more than one account's [`PoolMigrations`] over the same
    /// connection.
    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        // A minimal stand-in for the wallet's `accounts` table: the migration tables' `account_id`
        // foreign key references `accounts(id)`, and `for_account` resolves an `AccountUuid` to its
        // row through `accounts(uuid)`.
        conn.execute_batch(
            "CREATE TABLE accounts (id INTEGER PRIMARY KEY, uuid BLOB NOT NULL);
             CREATE UNIQUE INDEX accounts_uuid ON accounts (uuid);
             -- A minimal stand-in for the wallet's scan queue, which the identity-stamping half
             -- of `replace_migration` reads the chain tip from (empty: no chain view yet).
             CREATE TABLE scan_queue (
                block_range_start INTEGER NOT NULL,
                block_range_end INTEGER NOT NULL,
                priority INTEGER NOT NULL
             );
             -- A minimal stand-in for the source pool's received-note rows: the columns note
             -- locking records on them, which cancel and every terminal transition release.
             CREATE TABLE orchard_received_notes (
                id INTEGER PRIMARY KEY,
                lock_expiry_height INTEGER,
                lock_owner BLOB
             );",
        )
        .expect("create accounts table");
        init_migration_tables(&conn).expect("create tables");
        conn
    }

    /// Insert a fresh random account into `conn`'s `accounts` table and return its UUID, so a store
    /// can be scoped to it.
    fn insert_account(conn: &Connection) -> AccountUuid {
        let account = AccountUuid::from_uuid(Uuid::new_v4());
        conn.execute(
            "INSERT INTO accounts (uuid) VALUES (?)",
            rusqlite::params![account.expose_uuid()],
        )
        .expect("insert account");
        account
    }

    /// A fresh, empty store over a new in-memory database with the migration tables created, scoped
    /// to a fresh account. Each proptest case and test gets its own database and account, so writes
    /// never bleed between cases.
    fn fresh_store() -> PoolMigrations<Connection, LocalNetwork, SystemClock> {
        let conn = fresh_conn();
        let account = insert_account(&conn);
        PoolMigrations::for_account(NET, SystemClock, conn, account).expect("account exists")
    }

    #[test]
    fn get_migration_empty_is_none() {
        assert_empty_is_none(&fresh_store());
    }

    /// A migration keeps ONE identity — row id and uuid alike — for its whole life, and its
    /// terminal record is retained beside its successor's. The parent row is updated in place on
    /// every re-persistence (the state is persisted on every broadcast and every mine),
    /// including the one that marks the migration terminal — which is how it enters the retained
    /// history — while a replacement migration is a genuinely new row under a fresh identity,
    /// leaving the history readable beside it.
    #[test]
    fn replace_preserves_identity_and_retains_history() {
        let mut conn = fresh_conn();
        let account = insert_account(&conn);
        let interval = AnchorBucketInterval::ZIP_318;
        let rows = |conn: &Connection| -> Vec<(i64, uuid::Uuid, String)> {
            conn.prepare("SELECT id, uuid, status FROM orchard_ironwood_migrations ORDER BY id")
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };

        let mut live = migration_under(MigrationStatus::Committed, interval);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&live)
            .expect("first persist");
        let first = rows(&conn);
        assert_eq!(first.len(), 1, "one pending row");
        let (row_id, original, _) = first[0].clone();
        assert!(!original.is_nil());

        // Re-persisting the live migration updates the row in place: same id, same uuid.
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&live)
            .expect("re-persist");
        assert_eq!(rows(&conn), vec![(row_id, original, "committed".into())]);

        // Marking it terminal moves it into retained history, identity intact, and it leaves
        // the pending read.
        live.mark_superseded();
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&live)
            .expect("terminal persist");
        assert_eq!(rows(&conn), vec![(row_id, original, "superseded".into())]);
        assert_eq!(
            PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
                .expect("account exists")
                .get_migration()
                .expect("read"),
            None,
            "a terminal migration is history, not the migration in progress"
        );

        // A successor migration commits beside the history under its own identity.
        let successor = migration_under(MigrationStatus::Committed, interval);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&successor)
            .expect("successor persist");
        let after = rows(&conn);
        assert_eq!(
            after.len(),
            2,
            "the history survives the successor's commit"
        );
        assert_eq!(after[0], (row_id, original, "superseded".into()));
        assert_ne!(after[1].1, original, "a new migration is a new identity");
        assert_eq!(after[1].2, "committed");
        assert_eq!(
            PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
                .expect("account exists")
                .get_migration()
                .expect("read"),
            Some(successor),
            "the successor is the migration in progress"
        );
    }

    /// A migration with one crossing of `value` zatoshis carried by one transfer in `tx_state`,
    /// for exercising the history projections: the crossing list is what `value_migrated` sums
    /// over, and the transfer's lifecycle state is what gates that sum.
    fn migration_with_transfer(
        status: MigrationStatus,
        value: u64,
        tx_state: MigrationTxState,
    ) -> MigrationState {
        let value = Zatoshis::const_from_u64(value);
        let txid = match tx_state {
            MigrationTxState::Broadcast { txid } | MigrationTxState::Mined { txid, .. } => txid,
            _ => TxId::from_bytes([7; 32]),
        };
        MigrationState::from_parts(
            status,
            DenominationPlan::from_stored_parts(
                vec![value],
                Zatoshis::ZERO,
                None,
                Zatoshis::ZERO,
                value,
                value,
            )
            .expect("a consistent stored plan reconstructs"),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![MigrationTransaction::from_parts(
                MigrationTransferId::new(0),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![0xAB; 4],
                Vec::new(),
                BlockHeight::from_u32(10),
                BlockHeight::from_u32(0),
                None,
                txid,
                tx_state,
                None,
                None,
                vec![[9; 32]],
                None,
            )],
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        )
    }

    /// The history reads: `latest_migration` keeps a finished migration visible after the
    /// pending-only `get_migration` has moved on; `list_migrations` projects newest-first
    /// summaries IN SQL — proven by corrupting every stored PCZT first, which a projection that
    /// parsed them could not survive — and `get_migration_by_id` resolves a summary's identity
    /// back to the full state, historical or pending.
    #[test]
    fn history_reads_survive_replacement() {
        let mut conn = fresh_conn();
        let account = insert_account(&conn);

        // A finished migration: one 40k crossing, mined.
        let mined = MigrationTxState::Mined {
            txid: TxId::from_bytes([0xA0; 32]),
            height: BlockHeight::from_u32(90),
        };
        let finished = migration_with_transfer(MigrationStatus::Complete, 40_000, mined);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&finished)
            .expect("persist finished");

        // Its successor: pending, one 25k crossing, proved but not yet broadcast.
        let successor =
            migration_with_transfer(MigrationStatus::Committed, 25_000, MigrationTxState::Proved);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&successor)
            .expect("persist successor");

        // The listing never touches the stored PCZTs: corrupt them all, and it must not notice.
        conn.execute(
            "UPDATE orchard_ironwood_migration_transactions SET pczt = X'DEAD'",
            [],
        )
        .expect("corrupt every stored pczt");

        let store =
            PoolMigrations::for_account(NET, SystemClock, &mut conn, account).expect("account");
        let summaries = store.list_migrations().expect("list");
        assert_eq!(summaries.len(), 2, "history retains both migrations");

        let newest = &summaries[0];
        assert_eq!(newest.status(), MigrationStatus::Committed);
        assert_eq!(newest.total_migratable(), Zatoshis::const_from_u64(25_000));
        assert_eq!(newest.transaction_count(), 1);
        assert_eq!(newest.mined_count(), 0);
        assert_eq!(newest.value_migrated(), Zatoshis::ZERO);

        let history = &summaries[1];
        assert_eq!(history.status(), MigrationStatus::Complete);
        assert_eq!(history.transaction_count(), 1);
        assert_eq!(history.mined_count(), 1);
        assert_eq!(
            history.value_migrated(),
            Zatoshis::const_from_u64(40_000),
            "the mined transfer's crossing value has crossed"
        );
        assert_ne!(newest.id(), history.id());

        // The latest migration is the successor, whatever `get_migration` says; the identities
        // resolve to the full states (with the corrupted bytes read back verbatim, unparsed).
        let latest = store.latest_migration().expect("latest");
        assert_eq!(
            latest.as_ref().map(|s| s.status()),
            Some(MigrationStatus::Committed)
        );
        assert_eq!(
            store
                .get_migration_by_id(history.id())
                .expect("by id")
                .map(|s| s.status()),
            Some(MigrationStatus::Complete),
            "a historical record resolves by identity"
        );
        assert_eq!(
            store
                .get_migration_by_id(crate::pool_migration::MigrationUuid::from_uuid(
                    Uuid::new_v4()
                ))
                .expect("by unknown id"),
            None,
            "an unknown identity resolves to nothing"
        );
    }

    /// A freshly committed migration is stamped with the chain height the wallet knew at first
    /// persistence — the "when" a history listing sorts by — and the stamp never moves with the
    /// tip afterwards. With no chain view at all, no value is invented.
    #[test]
    fn committed_height_is_stamped_at_first_persistence() {
        let mut conn = fresh_conn();
        let account = insert_account(&conn);

        // No chain view: nothing to stamp.
        let first = migration_under(MigrationStatus::Committed, AnchorBucketInterval::ZIP_318);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&first)
            .expect("persist without a chain view");
        let committed = |conn: &Connection| -> Vec<Option<u32>> {
            conn.prepare("SELECT committed_height FROM orchard_ironwood_migrations ORDER BY id")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(committed(&conn), vec![None]);

        // The wallet learns a chain tip; re-persisting the SAME migration does not invent a
        // stamp for it retroactively, but its successor is stamped at first persistence.
        conn.execute(
            "INSERT INTO scan_queue (block_range_start, block_range_end, priority)
             VALUES (0, 1001, 0)",
            [],
        )
        .expect("record a scan range");
        let mut ended = first.clone();
        ended.mark_superseded();
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&ended)
            .expect("re-persist");
        let second = migration_under(MigrationStatus::Committed, AnchorBucketInterval::ZIP_318);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&second)
            .expect("persist successor");
        assert_eq!(committed(&conn), vec![None, Some(1_000)]);
    }

    /// A locked source-note row under `owner`, standing in for the reservation the prover takes.
    fn lock_note(conn: &Connection, id: u32, owner: [u8; 32]) {
        conn.execute(
            "INSERT INTO orchard_received_notes (id, lock_expiry_height, lock_owner)
             VALUES (:id, 99999, :owner)",
            rusqlite::named_params![":id": id, ":owner": owner],
        )
        .unwrap();
    }

    /// The owners currently holding locks in the stand-in note table.
    fn locked_owners(conn: &Connection) -> Vec<[u8; 32]> {
        conn.prepare(
            "SELECT lock_owner FROM orchard_received_notes
              WHERE lock_owner IS NOT NULL ORDER BY id",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// Cancel classifies every transaction off its lifecycle column, releases exactly the
    /// never-broadcast transactions' reservations (another flow's lock is untouched), flips the
    /// record to `Cancelled`, and leaves it readable as history while `get_migration` moves on.
    #[test]
    fn cancel_releases_reservations_and_terminates() {
        let mut conn = fresh_conn();
        let account = insert_account(&conn);

        let owner = [7u8; 32];
        let rival = [9u8; 32];
        lock_note(&conn, 1, owner);
        lock_note(&conn, 2, rival);

        // One transaction per disposition: proved-and-locked (released), broadcast (in flight),
        // mined (history).
        let mined_state = MigrationTxState::Mined {
            txid: TxId::from_bytes([0xC0; 32]),
            height: BlockHeight::from_u32(50),
        };
        let mut proved = migration_with_transfer(
            MigrationStatus::InProgress,
            40_000,
            MigrationTxState::Proved,
        );
        let mut txs = proved.transactions().to_vec();
        txs[0] = MigrationTransaction::from_parts(
            txs[0].id(),
            txs[0].kind(),
            txs[0].pczt().to_vec(),
            txs[0].depends_on().to_vec(),
            txs[0].scheduled_height(),
            txs[0].expiry_height(),
            txs[0].anchor_boundary(),
            txs[0].txid(),
            MigrationTxState::Proved,
            Some(MigrationLockOwner::from_bytes(owner)),
            None,
            txs[0].spend_nullifiers().to_vec(),
            None,
        );
        txs.push(MigrationTransaction::from_parts(
            MigrationTransferId::new(1),
            MigrationTxKind::Preparation { layer: 0, index: 0 },
            vec![1],
            Vec::new(),
            BlockHeight::from_u32(5),
            BlockHeight::from_u32(0),
            None,
            TxId::from_bytes([0xB0; 32]),
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes([0xB0; 32]),
            },
            None,
            None,
            Vec::new(),
            None,
        ));
        txs.push(MigrationTransaction::from_parts(
            MigrationTransferId::new(2),
            MigrationTxKind::Preparation { layer: 0, index: 1 },
            vec![2],
            Vec::new(),
            BlockHeight::from_u32(5),
            BlockHeight::from_u32(0),
            None,
            TxId::from_bytes([0xC0; 32]),
            mined_state,
            None,
            None,
            Vec::new(),
            None,
        ));
        proved = MigrationState::from_parts(
            MigrationStatus::InProgress,
            proved.denominations().clone(),
            proved.preparation().clone(),
            txs,
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        );
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&proved)
            .expect("persist");

        let outcome = PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .cancel_migration()
            .expect("cancel succeeds");

        assert_eq!(outcome.released(), &[MigrationTransferId::new(0)]);
        assert_eq!(outcome.in_flight(), &[MigrationTransferId::new(1)]);
        assert_eq!(outcome.mined(), &[MigrationTransferId::new(2)]);
        assert_eq!(
            locked_owners(&conn),
            vec![rival],
            "the migration's reservation is released; the rival flow's is untouched"
        );

        let store =
            PoolMigrations::for_account(NET, SystemClock, &mut conn, account).expect("account");
        assert_eq!(store.get_migration().expect("read"), None);
        assert_eq!(
            store
                .latest_migration()
                .expect("history reads back")
                .map(|s| s.status()),
            Some(MigrationStatus::Cancelled),
            "the cancelled record is retained history"
        );
        // A replacement commits over it.
        let successor = migration_under(MigrationStatus::Committed, AnchorBucketInterval::ZIP_318);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&successor)
            .expect("the commit guard's terminality requirement is satisfied");
    }

    /// Cancel succeeds against a migration whose STATE will not deserialize: it never parses the
    /// record — the primary use case is an unrecoverable wallet, and a corrupt row is one of the
    /// ways to get there.
    #[test]
    fn cancel_survives_a_corrupt_migration() {
        let mut conn = fresh_conn();
        let account = insert_account(&conn);
        let live =
            migration_with_transfer(MigrationStatus::Committed, 40_000, MigrationTxState::Proved);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&live)
            .expect("persist");

        // Corrupt the transaction row's KIND, which the state reader must parse and cancel must
        // not.
        conn.execute(
            "UPDATE orchard_ironwood_migration_transactions SET kind = 'garbage'",
            [],
        )
        .expect("corrupts the row");
        assert!(
            PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
                .expect("account exists")
                .get_migration()
                .is_err(),
            "premise: the state no longer deserializes"
        );

        let outcome = PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .cancel_migration()
            .expect("cancel does not read what it does not need");
        assert_eq!(outcome.released(), &[MigrationTransferId::new(0)]);
        let status: String = conn
            .query_row("SELECT status FROM orchard_ironwood_migrations", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(status, "cancelled");
    }

    /// Cancel with no PENDING migration performs the repair half only: the latest retained
    /// record's reservations are released, and its recorded status — history — is untouched.
    #[test]
    fn cancel_repairs_an_already_terminal_record_without_rewriting_it() {
        let mut conn = fresh_conn();
        let account = insert_account(&conn);
        let owner = [4u8; 32];
        lock_note(&conn, 1, owner);

        let mut txs =
            migration_with_transfer(MigrationStatus::Failed, 40_000, MigrationTxState::Proved)
                .transactions()
                .to_vec();
        txs[0] = MigrationTransaction::from_parts(
            txs[0].id(),
            txs[0].kind(),
            txs[0].pczt().to_vec(),
            txs[0].depends_on().to_vec(),
            txs[0].scheduled_height(),
            txs[0].expiry_height(),
            txs[0].anchor_boundary(),
            txs[0].txid(),
            MigrationTxState::Proved,
            Some(MigrationLockOwner::from_bytes(owner)),
            None,
            txs[0].spend_nullifiers().to_vec(),
            None,
        );
        let failed =
            migration_with_transfer(MigrationStatus::Failed, 40_000, MigrationTxState::Proved);
        let failed = MigrationState::from_parts(
            MigrationStatus::Failed,
            failed.denominations().clone(),
            failed.preparation().clone(),
            txs,
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        );
        // Insert the terminal record DIRECTLY as an old client would have left it (the
        // terminal-transition release in `replace_migration` would otherwise discharge the lock
        // on the way in, which is itself the behavior `supersede_releases_reservations` pins).
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&failed)
            .expect("persist");
        // Re-take the lock, modeling the stranded field state.
        conn.execute(
            "UPDATE orchard_received_notes SET lock_owner = :owner, lock_expiry_height = 99999",
            rusqlite::named_params![":owner": owner],
        )
        .unwrap();

        let outcome = PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .cancel_migration()
            .expect("repair succeeds");
        assert_eq!(outcome.released(), &[MigrationTransferId::new(0)]);
        assert!(locked_owners(&conn).is_empty(), "the stranded lock is gone");
        let status: String = conn
            .query_row("SELECT status FROM orchard_ironwood_migrations", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(status, "failed", "history is never rewritten");
    }

    /// EVERY terminal transition that flows through the ordinary persist path releases the
    /// never-broadcast reservations: the consumer's `mark_superseded` response to `Replan` must
    /// not strand the live transfers' locks behind a record nothing will revisit.
    #[test]
    fn supersede_releases_reservations_on_persist() {
        let mut conn = fresh_conn();
        let account = insert_account(&conn);
        let owner = [5u8; 32];
        lock_note(&conn, 1, owner);

        let live = migration_with_transfer(
            MigrationStatus::InProgress,
            40_000,
            MigrationTxState::Proved,
        );
        let mut txs = live.transactions().to_vec();
        txs[0] = MigrationTransaction::from_parts(
            txs[0].id(),
            txs[0].kind(),
            txs[0].pczt().to_vec(),
            txs[0].depends_on().to_vec(),
            txs[0].scheduled_height(),
            txs[0].expiry_height(),
            txs[0].anchor_boundary(),
            txs[0].txid(),
            MigrationTxState::Proved,
            Some(MigrationLockOwner::from_bytes(owner)),
            None,
            txs[0].spend_nullifiers().to_vec(),
            None,
        );
        let mut live = MigrationState::from_parts(
            MigrationStatus::InProgress,
            live.denominations().clone(),
            live.preparation().clone(),
            txs,
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        );
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&live)
            .expect("persist live");
        assert_eq!(locked_owners(&conn), vec![owner]);

        live.mark_superseded();
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&live)
            .expect("persist superseded");
        assert!(
            locked_owners(&conn).is_empty(),
            "persisting the terminal state released the reservation"
        );
    }

    /// A migration in `status`, recorded under `interval`. The plan itself is empty filler: the
    /// test using this is about which grids a status still owes retention to, and nothing else.
    fn migration_under(status: MigrationStatus, interval: AnchorBucketInterval) -> MigrationState {
        MigrationState::from_parts(
            status,
            DenominationPlan::from_stored_parts(
                Vec::new(),
                Zatoshis::ZERO,
                None,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
            )
            .expect("an empty stored plan reconstructs"),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            Vec::new(),
            interval,
            ReplanThreshold::DEFAULT,
        )
    }

    /// Anchor-checkpoint retention is owed by every NON-TERMINAL migration, and by no terminal one
    /// — not merely by every migration that is not `complete`.
    ///
    /// The distinction is the point: `complete` is the only terminal status a migration reaches by
    /// finishing its work, so a query written against it alone lets a `failed`, `superseded`, or
    /// `cancelled` migration pin its grid for the lifetime of the wallet. Nothing will ever drive
    /// those migrations again, so the checkpoints are kept for proofs that will never be requested,
    /// and being terminal they are never revisited to notice.
    ///
    /// One account per status, each under its own grid, so the surviving intervals name exactly
    /// which statuses still owe retention.
    #[test]
    fn anchor_retention_is_owed_by_every_non_terminal_status() {
        /// Grid width recorded for the first status; each subsequent one takes the next block
        /// count, so an interval identifies the status that was recorded under it.
        const FIRST_GRID_BLOCKS: u32 = 10;

        let mut conn = fresh_conn();
        let mut expected: BTreeSet<u32> = BTreeSet::new();

        for (i, status) in MigrationStatus::ALL.iter().copied().enumerate() {
            let blocks = FIRST_GRID_BLOCKS + u32::try_from(i).expect("a handful of statuses");
            let interval =
                AnchorBucketInterval::custom(NonZeroU32::new(blocks).expect("nonzero grid"));
            let account = insert_account(&conn);
            let mut store = PoolMigrations::for_account(NET, SystemClock, conn, account)
                .expect("the account exists");
            store
                .replace_migration(&migration_under(status, interval))
                .expect("persists the migration");
            conn = store.into_inner();

            if !status.is_terminal() {
                expected.insert(blocks);
            }
        }

        let active: BTreeSet<u32> = super::active_anchor_bucket_intervals(&conn)
            .expect("reads the active grids")
            .into_iter()
            .map(|interval| interval.block_count().get())
            .collect();

        assert_eq!(
            active, expected,
            "exactly the non-terminal migrations' grids are still retained"
        );

        // Spelled out for the three statuses the previous `status <> 'complete'` query retained
        // forever, since that is the regression this pins.
        for status in [
            MigrationStatus::Failed,
            MigrationStatus::Superseded,
            MigrationStatus::Cancelled,
        ] {
            let position = MigrationStatus::ALL
                .iter()
                .position(|s| *s == status)
                .expect("every status is in ALL");
            let blocks =
                FIRST_GRID_BLOCKS + u32::try_from(position).expect("a handful of statuses");
            assert!(
                !active.contains(&blocks),
                "{status:?} must not pin its {blocks}-block grid",
            );
        }
    }

    /// A transaction's `lock_owner` round-trips exactly through the store's `BLOB` column: a
    /// `Some` token comes back byte-for-byte and a `None` comes back as `None`, not a zeroed or
    /// otherwise substituted token. This pins the two cases the column must distinguish; the
    /// general `put_then_get_round_trips` property (whose generator also produces `lock_owner`)
    /// covers the type more broadly.
    #[test]
    fn lock_owner_round_trips() {
        let denominations = DenominationPlan::from_stored_parts(
            Vec::new(),
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
        )
        .expect("an empty stored plan reconstructs");

        // The `from_parts` slots this test does not exercise, named so the positional argument
        // lists below read as what they are: both transactions are identical filler apart from the
        // `lock_owner` slot that is the subject.
        let depends_on: Vec<MigrationTransferId> = Vec::new();
        let anchor_boundary: Option<BlockHeight> = None;
        let unsatisfiable: Option<(BlockHeight, UnsatisfiableKind)> = None;
        let spend_nullifiers: Vec<[u8; 32]> = Vec::new();
        let broadcast_failure_at: Option<BlockHeight> = None;

        let owner = MigrationLockOwner::from_bytes([7u8; 32]);
        let locked = MigrationTransaction::from_parts(
            MigrationTransferId::new(0),
            MigrationTxKind::Preparation { layer: 0, index: 0 },
            vec![1, 2, 3],
            depends_on.clone(),
            BlockHeight::from_u32(100),
            BlockHeight::from_u32(200),
            anchor_boundary,
            TxId::from_bytes([0; 32]),
            MigrationTxState::Signed,
            Some(owner),
            unsatisfiable,
            spend_nullifiers.clone(),
            broadcast_failure_at,
        );
        let unlocked = MigrationTransaction::from_parts(
            MigrationTransferId::new(1),
            MigrationTxKind::Transfer { crossing: 0 },
            vec![4, 5, 6],
            depends_on,
            BlockHeight::from_u32(100),
            BlockHeight::from_u32(200),
            anchor_boundary,
            TxId::from_bytes([1; 32]),
            MigrationTxState::Signed,
            None,
            unsatisfiable,
            spend_nullifiers,
            broadcast_failure_at,
        );
        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            denominations,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![locked, unlocked],
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        );

        let mut store = fresh_store();
        store.replace_migration(&state).expect("write succeeds");
        let loaded = store
            .get_migration()
            .expect("read succeeds")
            .expect("a migration is stored");

        assert_eq!(
            loaded, state,
            "the whole migration, including lock_owner, must round-trip unchanged"
        );
        assert_eq!(
            loaded.transactions()[0].lock_owner(),
            Some(owner),
            "a `Some` lock_owner must survive exactly"
        );
        assert_eq!(
            loaded.transactions()[1].lock_owner(),
            None,
            "a `None` lock_owner must round-trip as `None`"
        );
    }

    /// `migration_lock_owners` returns exactly the distinct, non-`None` lock owners across an
    /// account's migration transactions: an account with no migration returns the empty set,
    /// a `None` lock_owner contributes nothing, and repeated owners collapse to one entry.
    #[test]
    fn migration_lock_owners_collects_distinct_non_none_owners() {
        let mut store = fresh_store();
        assert_eq!(
            store.migration_lock_owners().expect("read succeeds"),
            BTreeSet::new(),
            "an account with no migration must report no lock owners"
        );

        let owner_a = MigrationLockOwner::from_bytes([0xA1u8; 32]);
        let owner_b = MigrationLockOwner::from_bytes([0xB2u8; 32]);

        let denominations = DenominationPlan::from_stored_parts(
            Vec::new(),
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
        )
        .expect("an empty stored plan reconstructs");

        let tx = |id: u32, crossing: usize, lock_owner: Option<MigrationLockOwner>| {
            MigrationTransaction::from_parts(
                MigrationTransferId::new(id),
                MigrationTxKind::Transfer { crossing },
                vec![id as u8],
                Vec::new(),
                BlockHeight::from_u32(100),
                BlockHeight::from_u32(200),
                None,
                TxId::from_bytes([0; 32]),
                MigrationTxState::Signed,
                lock_owner,
                None,
                Vec::new(),
                None,
            )
        };

        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            denominations,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![
                tx(0, 0, Some(owner_a)),
                tx(1, 1, Some(owner_b)),
                tx(2, 2, None),
                // A second transaction locked by A, to prove duplicates collapse.
                tx(3, 3, Some(owner_a)),
            ],
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        );

        store.replace_migration(&state).expect("write succeeds");

        let owners = store.migration_lock_owners().expect("read succeeds");
        assert_eq!(
            owners,
            BTreeSet::from([
                LockOwner::new(*owner_a.as_bytes()),
                LockOwner::new(*owner_b.as_bytes()),
            ]),
            "must contain exactly the distinct non-None lock owners, deduped"
        );
    }

    /// A state with an empty preparation layer is rejected on write rather than silently
    /// renumbered: the layers/transactions grid is stored only through the input and output rows,
    /// so an empty layer would leave no trace (and the engine never produces one).
    #[test]
    fn empty_prep_layer_is_rejected() {
        let denominations = DenominationPlan::from_stored_parts(
            Vec::new(),
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
        )
        .expect("an empty stored plan reconstructs");
        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            denominations,
            PreparationPlan::from_parts(vec![Vec::new()], Vec::new()),
            Vec::new(),
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        );
        let err = fresh_store()
            .replace_migration(&state)
            .expect_err("an empty layer cannot be persisted");
        assert!(matches!(err, Error::Unrepresentable(_)));
    }

    /// A minimal committed migration holding one signed transfer with a one-entry nullifier
    /// cache, for tests that corrupt its stored row directly.
    ///
    /// Hand-built rather than drawn from `arb_migration_state`, because its users need exactly one
    /// transaction to EXIST: a blanket `UPDATE` that corrupts every stored row would pass
    /// vacuously against a zero-transaction draw, and the round-trip tests address
    /// `MigrationTransferId::new(0)` by name.
    fn single_transfer_state() -> MigrationState {
        let denominations = DenominationPlan::from_stored_parts(
            Vec::new(),
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
            Zatoshis::ZERO,
        )
        .expect("an empty stored plan reconstructs");
        MigrationState::from_parts(
            MigrationStatus::Committed,
            denominations,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![MigrationTransaction::from_parts(
                MigrationTransferId::new(0),
                MigrationTxKind::Transfer { crossing: 0 },
                vec![1, 2, 3],
                Vec::new(),
                BlockHeight::from_u32(100),
                BlockHeight::from_u32(200),
                None,
                TxId::from_bytes([0; 32]),
                MigrationTxState::Signed,
                None,
                None,
                vec![[7u8; 32]],
                None,
            )],
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        )
    }

    /// The 32-byte stride of the nullifier cache is a `CHECK` on the table that holds it, so a
    /// value of any other width is refused at the point of storage. This is the guard that
    /// replaced a read-side length check over a concatenated blob: the ragged cache that check
    /// existed to catch is no longer a state this schema can be put into.
    #[test]
    fn a_cached_nullifier_of_the_wrong_width_cannot_be_stored() {
        let mut conn = fresh_conn();
        let account = insert_account(&conn);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&single_transfer_state())
            .expect("write succeeds");
        assert!(
            conn.execute(
                "UPDATE orchard_ironwood_migration_spend_nullifiers SET nullifier = X'0102030405'",
                [],
            )
            .is_err(),
            "the stride CHECK refuses a nullifier that is not 32 bytes",
        );
    }

    /// What the schema can still lose is the cache itself: a transaction whose nullifier rows are
    /// gone reads back with an EMPTY cache, which is corruption on any row that is not `mined`
    /// (only a mined row is exempt from the backfill that supplies it). The satisfiability oracle
    /// reports that before it consults any chain state, which is why this store — over a database
    /// with no scanned chain at all — reaches the corruption rather than a missing fully-scanned
    /// height.
    #[test]
    fn a_signed_row_whose_cached_nullifiers_are_gone_is_corrupt() {
        let mut conn = fresh_conn();
        let account = insert_account(&conn);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&single_transfer_state())
            .expect("write succeeds");
        conn.execute(
            "DELETE FROM orchard_ironwood_migration_spend_nullifiers",
            [],
        )
        .expect("discards the stored cache");

        let store =
            PoolMigrations::for_account(NET, SystemClock, &conn, account).expect("account exists");
        let loaded = store
            .get_migration()
            .expect("read succeeds")
            .expect("a migration is stored");
        let transfer = &loaded.transactions()[0];
        assert!(
            transfer.spend_nullifiers().is_empty(),
            "the rows are gone, so the transaction reads back caching nothing",
        );
        assert!(matches!(
            store.check_step_satisfiability(transfer, ReorgSettleDepth::new(10)),
            Err(Error::Corrupt("spend_nullifiers")),
        ));
    }

    /// A mark recorded through the engine's single door survives the store: the stamp AND the
    /// kind that says why come back exactly, for a direct observation and for the mark the
    /// dependency closure applies behind it.
    #[test]
    fn recorded_unsatisfiability_kinds_round_trip() {
        // Hand-built rather than drawn from `arb_migration_transaction`, because the subject is
        // the specific tx1 -> tx0 dependency edge the mark's closure travels along: that strategy
        // draws `depends_on` arbitrarily, and `arb_migration_state` re-keys transaction ids
        // sequentially without remapping it, so a drawn edge can dangle.
        let transfer = |id: u32, depends_on: Vec<MigrationTransferId>| {
            MigrationTransaction::from_parts(
                MigrationTransferId::new(id),
                MigrationTxKind::Transfer {
                    crossing: id as usize,
                },
                vec![1, 2, 3],
                depends_on,
                BlockHeight::from_u32(100),
                BlockHeight::from_u32(0),
                None,
                TxId::from_bytes([0; 32]),
                MigrationTxState::Signed,
                None,
                None,
                vec![[id as u8; 32]],
                None,
            )
        };
        let mut state = MigrationState::from_parts(
            MigrationStatus::Committed,
            DenominationPlan::from_stored_parts(
                Vec::new(),
                Zatoshis::ZERO,
                None,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
                Zatoshis::ZERO,
            )
            .expect("an empty stored plan reconstructs"),
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            vec![
                transfer(0, Vec::new()),
                transfer(1, vec![MigrationTransferId::new(0)]),
            ],
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        );
        let as_of_height = BlockHeight::from_u32(500);
        state.record_satisfiability(
            DuenessTargets::at(BlockHeight::from_u32(600)),
            &[(
                MigrationTransferId::new(0),
                StepSatisfiability::Unsatisfiable {
                    cause: UnsatisfiableCause::InputsSpent {
                        nullifiers: vec![[9u8; 32]],
                    },
                    as_of_height,
                },
            )],
        );

        let mut store = fresh_store();
        store.replace_migration(&state).expect("write succeeds");
        let loaded = store
            .get_migration()
            .expect("read succeeds")
            .expect("a migration is stored");
        assert_eq!(loaded, state, "the whole migration round-trips unchanged");
        assert_eq!(
            (
                loaded.transactions()[0].unsatisfiable_at(),
                loaded.transactions()[0].unsatisfiable_kind()
            ),
            (Some(as_of_height), Some(UnsatisfiableKind::InputsSpent)),
            "the observed cause's kind is stored beside its stamp",
        );
        assert_eq!(
            (
                loaded.transactions()[1].unsatisfiable_at(),
                loaded.transactions()[1].unsatisfiable_kind()
            ),
            (Some(as_of_height), Some(UnsatisfiableKind::Inherited)),
            "a closure-applied mark is stored as inherited",
        );
    }

    /// A broadcast-failure report survives the store: it is written and read back as its own
    /// column, independently of the unsatisfiability mark, and an unreported transaction reads
    /// back as unreported.
    #[test]
    fn a_broadcast_failure_report_round_trips() {
        let mut store = fresh_store();
        store
            .replace_migration(&single_transfer_state())
            .expect("write succeeds");
        // The report applies only to a `Proved` transaction, which is the state a broadcast the
        // node refused is left in.
        store
            .update_transaction(MigrationTransferId::new(0), MigrationTxState::Proved)
            .expect("the row advances");
        let mut state = store
            .get_migration()
            .expect("read succeeds")
            .expect("a migration is stored");
        let observed_tip = BlockHeight::from_u32(1700);
        state.report_broadcast_failure(MigrationTransferId::new(0), observed_tip);
        store.replace_migration(&state).expect("write succeeds");
        let loaded = store
            .get_migration()
            .expect("read succeeds")
            .expect("a migration is stored");
        assert_eq!(loaded, state, "the whole migration round-trips unchanged");
        assert_eq!(
            (
                loaded.transactions()[0].broadcast_failure_at(),
                loaded.transactions()[0].unsatisfiable(),
            ),
            (Some(observed_tip), None),
            "the report is stored on its own, carrying no mark with it",
        );

        // Discharging the report writes the column back to NULL rather than leaving the stale
        // tip standing.
        let mut discharged = loaded;
        discharged.truncate_to_height(BlockHeight::from_u32(1699));
        store
            .replace_migration(&discharged)
            .expect("write succeeds");
        assert_eq!(
            store
                .get_migration()
                .expect("read succeeds")
                .expect("a migration is stored")
                .transactions()[0]
                .broadcast_failure_at(),
            None,
        );
    }

    /// The unsatisfiability columns are one value in two places: a stamp without a kind cannot be
    /// rendered and a kind without a stamp has no height for reorg truncation to judge it against,
    /// so a row holding either half alone was not written by this store. A kind name this build
    /// does not know is corruption for the same reason an unrecognized `state` discriminant is:
    /// reading it as "unmarked" would return a dead transaction to the prove and broadcast queues.
    #[test]
    fn a_half_written_or_unknown_unsatisfiability_mark_is_corrupt() {
        for (sql, what) in [
            (
                "UPDATE orchard_ironwood_migration_transactions SET unsatisfiable_at = 500",
                "a stamp with no kind",
            ),
            (
                "UPDATE orchard_ironwood_migration_transactions
                    SET unsatisfiable_kind = 'inputs_spent'",
                "a kind with no stamp",
            ),
        ] {
            let mut conn = fresh_conn();
            let account = insert_account(&conn);
            PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
                .expect("account exists")
                .replace_migration(&single_transfer_state())
                .expect("write succeeds");
            conn.execute(sql, []).expect("corrupts the stored row");
            let err = PoolMigrations::for_account(NET, SystemClock, &conn, account)
                .expect("account exists")
                .get_migration()
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::Corrupt("unsatisfiable_at / unsatisfiable_kind disagree")
                ),
                "{what} must not decode, got {err:?}"
            );
        }

        let mut conn = fresh_conn();
        let account = insert_account(&conn);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&single_transfer_state())
            .expect("write succeeds");
        conn.execute(
            "UPDATE orchard_ironwood_migration_transactions
                SET unsatisfiable_at = 500, unsatisfiable_kind = 'from_the_future'",
            [],
        )
        .expect("stores an unrecognized kind");
        let err = PoolMigrations::for_account(NET, SystemClock, &conn, account)
            .expect("account exists")
            .get_migration()
            .unwrap_err();
        assert!(matches!(err, Error::Corrupt("unsatisfiable_kind")));
    }

    /// A stored `replan_threshold` above 100 names no valid percent; reading it back is
    /// corruption, never a silently clamped policy.
    #[test]
    fn replan_threshold_above_100_is_corrupt() {
        let mut conn = fresh_conn();
        let account = insert_account(&conn);
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account)
            .expect("account exists")
            .replace_migration(&single_transfer_state())
            .expect("write succeeds");
        conn.execute(
            "UPDATE orchard_ironwood_migrations SET replan_threshold = 101",
            [],
        )
        .expect("corrupts the stored threshold");
        let err = PoolMigrations::for_account(NET, SystemClock, &conn, account)
            .expect("account exists")
            .get_migration()
            .expect_err("an out-of-range threshold must not decode");
        assert!(matches!(err, Error::Corrupt("replan_threshold")));
    }

    /// Deleting an account cascades to its in-progress migration: the `account_id` foreign key
    /// carries `ON DELETE CASCADE`, so removing the account's row removes its migration, whose child
    /// rows cascade from it in turn. A different account's migration is untouched. This is the
    /// cleanup the wallet's account-deletion path now relies on entirely (no explicit delete).
    #[test]
    fn deleting_an_account_cascades_to_its_migration() {
        let mut conn = fresh_conn();
        // Enforce foreign keys so the account -> migration -> child cascade actually fires, exactly
        // as the wallet database does at runtime.
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("enable foreign keys");

        let account_a = insert_account(&conn);
        let account_b = insert_account(&conn);

        // A minimal but non-trivial migration (one crossing value) so the cascade is observed to
        // reach a child table, not only the parent row.
        let denominations = DenominationPlan::from_stored_parts(
            vec![Zatoshis::const_from_u64(1)],
            Zatoshis::ZERO,
            None,
            Zatoshis::ZERO,
            Zatoshis::const_from_u64(1),
            Zatoshis::const_from_u64(1),
        )
        .expect("a one-crossing stored plan reconstructs");
        let state = MigrationState::from_parts(
            MigrationStatus::Committed,
            denominations,
            PreparationPlan::from_parts(Vec::new(), Vec::new()),
            Vec::new(),
            AnchorBucketInterval::ZIP_318,
            ReplanThreshold::DEFAULT,
        );

        PoolMigrations::for_account(NET, SystemClock, &mut conn, account_a)
            .expect("account A exists")
            .replace_migration(&state)
            .expect("write A's migration");
        PoolMigrations::for_account(NET, SystemClock, &mut conn, account_b)
            .expect("account B exists")
            .replace_migration(&state)
            .expect("write B's migration");

        let count = |conn: &Connection, table: &str| -> i64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count")
        };
        assert_eq!(count(&conn, "orchard_ironwood_migrations"), 2);
        assert_eq!(
            count(&conn, "orchard_ironwood_migration_crossing_values"),
            2
        );

        // Delete account A directly, as the wallet's `delete_account` does; the cascade removes its
        // migration and children with it, and nothing else.
        conn.execute(
            "DELETE FROM accounts WHERE uuid = ?",
            rusqlite::params![account_a.expose_uuid()],
        )
        .expect("delete account A");

        // Only A's migration row and its child rows are gone; B's migration remains intact.
        assert_eq!(
            count(&conn, "orchard_ironwood_migrations"),
            1,
            "only account A's migration row must cascade away"
        );
        assert_eq!(
            count(&conn, "orchard_ironwood_migration_crossing_values"),
            1,
            "account A's child rows must cascade away, and only those"
        );
        assert_eq!(
            PoolMigrations::for_account(NET, SystemClock, &conn, account_b)
                .expect("account B exists")
                .get_migration()
                .expect("read B"),
            Some(state),
            "account B's migration must be untouched",
        );
    }

    proptest! {
        /// Any generated migration round-trips through the SQLite store unchanged: the shared
        /// put/get conformance property, proving the SQLite backend satisfies the suite.
        #[test]
        fn put_then_get_round_trips(state in arb_migration_state()) {
            assert_put_get_roundtrip(&mut fresh_store(), &state);
        }

        /// A second put replaces the first migration (the shared replace property).
        #[test]
        fn put_replaces_previous_migration(
            first in arb_migration_state(),
            second in arb_migration_state(),
        ) {
            assert_put_replaces(&mut fresh_store(), &first, &second);
        }

        /// Updating a stored transaction's lifecycle state persists (the shared update property),
        /// exercised across every state variant, including the `Mined` and `Broadcast` payloads.
        #[test]
        fn update_transaction_advances_state(
            state in arb_migration_state(),
            new in arb_migration_tx_state(),
        ) {
            // The shared assertion needs an id the migration contains; skip the (valid) empty case.
            prop_assume!(!state.transactions().is_empty());
            let id = first_transaction_id(&state).expect("non-empty by the assumption above");
            assert_update_transaction(&mut fresh_store(), &state, id, new);
        }

        /// Updating a transaction the stored migration does not contain is a store error. This is
        /// SQLite-specific (the shared conformance suite covers only the success path).
        #[test]
        fn update_unknown_transaction_errors(state in arb_migration_state()) {
            let mut s = fresh_store();
            s.replace_migration(&state).expect("write");
            // Generated ids are `0..transactions.len()` (< 6), so `u32::MAX` is always absent.
            let err = s
                .update_transaction(MigrationTransferId::new(u32::MAX), MigrationTxState::Proved)
                .expect_err("no such transaction");
            prop_assert!(matches!(err, Error::Corrupt(_)));
        }

        /// Two accounts sharing one connection are isolated: writing account A's migration
        /// creates no row visible to account B (which reads back `None`, exactly as an untouched
        /// store would), while account A itself round-trips normally.
        #[test]
        fn accounts_are_isolated(state in arb_migration_state()) {
            let mut conn = fresh_conn();
            let account_a = insert_account(&conn);
            let account_b = insert_account(&conn);

            PoolMigrations::for_account(NET, SystemClock, &mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state)
                .expect("write for A");

            prop_assert_eq!(
                PoolMigrations::for_account(NET, SystemClock, &conn, account_b)
                    .expect("account B exists")
                    .get_migration()
                    .expect("read for B"),
                None
            );
            // Pending-only: a terminal state was persisted into A's retained history rather
            // than as its migration in progress.
            let expected_a = (!state.is_terminal()).then_some(state);
            prop_assert_eq!(
                PoolMigrations::for_account(NET, SystemClock, &conn, account_a)
                    .expect("account A exists")
                    .get_migration()
                    .expect("read for A"),
                expected_a
            );
        }

        /// Replacing account A's migration touches only A's row and children: account B's
        /// previously written migration, on the same connection, is unaffected.
        #[test]
        fn replace_migration_is_scoped_to_its_account(
            state_a_1 in arb_migration_state(),
            state_a_2 in arb_migration_state(),
            state_b in arb_migration_state(),
        ) {
            let mut conn = fresh_conn();
            let account_a = insert_account(&conn);
            let account_b = insert_account(&conn);

            PoolMigrations::for_account(NET, SystemClock, &mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state_a_1)
                .expect("write A first");
            PoolMigrations::for_account(NET, SystemClock, &mut conn, account_b)
                .expect("account B exists")
                .replace_migration(&state_b)
                .expect("write B");
            PoolMigrations::for_account(NET, SystemClock, &mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state_a_2)
                .expect("write A second");

            // Pending-only reads on both sides: a terminal write lands in retained history.
            let expected_a = (!state_a_2.is_terminal()).then_some(state_a_2);
            let expected_b = (!state_b.is_terminal()).then_some(state_b);
            prop_assert_eq!(
                PoolMigrations::for_account(NET, SystemClock, &conn, account_a)
                    .expect("account A exists")
                    .get_migration()
                    .expect("read A"),
                expected_a
            );
            prop_assert_eq!(
                PoolMigrations::for_account(NET, SystemClock, &conn, account_b)
                    .expect("account B exists")
                    .get_migration()
                    .expect("read B"),
                expected_b
            );
        }

        /// A second `replace_migration` for the same account still replaces the account's
        /// migration IN PROGRESS: at most one pending row per account (enforced by the partial
        /// unique index over `account_id`), because the account's pending row is deleted before
        /// the new one is inserted, while terminal rows accumulate as retained history.
        #[test]
        fn replace_migration_replaces_same_account(
            first in arb_migration_state(),
            second in arb_migration_state(),
        ) {
            let conn = fresh_conn();
            let account = insert_account(&conn);
            let mut store = PoolMigrations::for_account(NET, SystemClock, conn, account).expect("account exists");
            store.replace_migration(&first).expect("write first");
            store.replace_migration(&second).expect("write second");
            let expected = (!second.is_terminal()).then_some(second);
            prop_assert_eq!(store.get_migration().expect("read"), expected);
        }

        /// `update_transaction` is scoped to its account: advancing a transaction's state for
        /// account A does not affect account B's migration on the same connection, even when both
        /// accounts started from the same migration state (and so share the updated `transfer_id`).
        #[test]
        fn update_transaction_is_scoped_to_its_account(
            state in arb_migration_state(),
            new in arb_migration_tx_state(),
        ) {
            prop_assume!(!state.transactions().is_empty());
            // A terminal migration has no pending row to update; lifecycle updates are a
            // pending-migration operation, which is all this scoping property is about.
            prop_assume!(!state.is_terminal());
            let id = first_transaction_id(&state).expect("non-empty by the assumption above");

            let mut conn = fresh_conn();
            let account_a = insert_account(&conn);
            let account_b = insert_account(&conn);

            PoolMigrations::for_account(NET, SystemClock, &mut conn, account_a)
                .expect("account A exists")
                .replace_migration(&state)
                .expect("write A");
            PoolMigrations::for_account(NET, SystemClock, &mut conn, account_b)
                .expect("account B exists")
                .replace_migration(&state)
                .expect("write B");

            PoolMigrations::for_account(NET, SystemClock, &mut conn, account_a)
                .expect("account A exists")
                .update_transaction(id, new)
                .expect("update A");

            prop_assert_eq!(
                PoolMigrations::for_account(NET, SystemClock, &conn, account_b)
                    .expect("account B exists")
                    .get_migration()
                    .expect("read B"),
                Some(state),
                "account B's migration must be unaffected by account A's update_transaction",
            );
        }
    }
}
