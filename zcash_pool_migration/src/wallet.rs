//! A wallet-backed adapter that turns any `zcash_client_backend` wallet into a migration wallet.
//!
//! The engine's build and commit path needs an implementation of [`MigrationBackend`] +
//! [`MigrationCrypto`] (the account's viewing key, its spendable notes' plaintexts) and a
//! [`PoolMigrationRead`] / [`PoolMigrationWrite`] store. This module supplies the first two for
//! free over the traits a `zcash_client_backend` wallet already implements ([`WalletRead`],
//! [`InputSource`]) plus the account's viewing key, and delegates the store to a value the caller
//! supplies (for example `zcash_client_sqlite`'s `pool_migration` store over the same wallet
//! database). A consuming application (zallet, or any other `zcash_client_backend` wallet) then
//! runs [`commit_preparation`] with no hand-wired cryptography.
//!
//! [`WalletMigration`] holds VIEWING authority and nothing more. It is built from an account's
//! [`UnifiedFullViewingKey`], and there is no way to give it a spending key: the engine takes the
//! spend authority as an argument to the operations that actually sign
//! ([`commit_preparation`] and [`rebuild_expired_transfer`]), so the key is live for one call
//! rather than for the lifetime of an adapter that mostly does not need it. A watch-only account
//! and one whose key lives on a hardware wallet are therefore ordinary users of this adapter:
//! they plan and build here and route the signing elsewhere.
//!
//! [`WalletMigration`] holds the wallet by a SHARED borrow and touches no note commitment tree:
//! every migration transaction is built and signed with its anchor and witnesses deferred to
//! proving time (ZIP 374). Proving is the separate [`WalletMigrationProver`], which borrows the
//! wallet as `&mut W` to resolve the source anchor and each spend's witness from the wallet's
//! Orchard commitment tree and installs them through the PCZT `Updater` role before proving the
//! transaction (a transfer's Orchard + Ironwood bundles, or a preparation's Orchard bundle), just
//! before broadcast.
//!
//! [`commit_preparation`]: crate::engine::commit_preparation
//! [`rebuild_expired_transfer`]: crate::engine::rebuild_expired_transfer

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::{Ref, RefCell};
use core::fmt;
use core::num::NonZeroU32;

use ::orchard::Anchor;
use ::orchard::circuit::OrchardCircuitVersion;
use ::orchard::keys::FullViewingKey;
use ::orchard::note::{Note as OrchardNote, Nullifier};
use ::orchard::tree::MerklePath;
use incrementalmerkletree::Position;
use shardtree::error::ShardTreeError;

use ::pczt::roles::prover::Prover;
use ::pczt::roles::updater::{AnchorUpdateError, SpendWitnessUpdateError, Updater};
use zcash_client_backend::data_api::{
    Account as _, InputSource, WalletCommitmentTrees, WalletRead,
    locking::{LockError, LockOwner, OutputLockStore},
    wallet::{
        TargetHeight,
        input_selection::{LockFilter, LockedInputPolicy},
    },
};
use zcash_client_backend::wallet::OutputRef;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::TxId;
use zcash_primitives::transaction::builder::cached_orchard_proving_key;
use zcash_protocol::{PoolType, ShieldedPool, consensus::BlockHeight, value::Zatoshis};

use crate::build::AccountDerivation;
use crate::engine::{
    MigrationBackend, MigrationCrypto, MigrationLockOwner, MigrationProver, MigrationState,
    MigrationTransaction, MigrationTransferId, MigrationTxState, PoolMigrationRead,
    PoolMigrationWrite, ProveFailure,
};
use crate::pczt_spends::RealSpendError;
use crate::satisfiability::{ReorgSettleDepth, StepSatisfiability};
use crate::scheduling::{AnchorBucketInterval, DelayDistribution, SchedulingParams};

/// A failure of the wallet-backed migration adapter. Parameterized by the error types of the two
/// wallet traits and the store, which for `zcash_client_sqlite`'s `WalletDb` are all one type but in
/// general need not be.
#[derive(Debug)]
pub enum Error<WRE, ISE, SE> {
    /// A `WalletRead` failure (chain-tip lookup).
    WalletRead(WRE),
    /// An `InputSource` failure (spendable-note selection).
    InputSource(ISE),
    /// A store failure (`PoolMigrationRead` / `PoolMigrationWrite`).
    Store(SE),
    /// No spendable note exists at the requested index.
    NoteNotFound(usize),
    /// The wallet has no chain tip (it has never synced), so no note selection target exists.
    ChainTipUnknown,
    /// The spendable note at this index has a value that is not a valid [`Zatoshis`] amount
    /// (it exceeds the money-supply cap).
    InvalidNoteValue(usize),
}

impl<WRE: fmt::Display, ISE: fmt::Display, SE: fmt::Display> fmt::Display for Error<WRE, ISE, SE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WalletRead(e) => write!(f, "wallet read error: {e}"),
            Error::InputSource(e) => write!(f, "input source error: {e}"),
            Error::Store(e) => write!(f, "migration store error: {e}"),
            Error::NoteNotFound(i) => write!(f, "no spendable note at index {i}"),
            Error::ChainTipUnknown => f.write_str("the wallet has no chain tip"),
            Error::InvalidNoteValue(i) => {
                write!(f, "spendable note {i} has an invalid (out-of-range) value")
            }
        }
    }
}

impl<WRE, ISE, SE> core::error::Error for Error<WRE, ISE, SE>
where
    WRE: fmt::Debug + fmt::Display,
    ISE: fmt::Debug + fmt::Display,
    SE: fmt::Debug + fmt::Display,
{
}

/// The adapter's error type for a wallet `W` and store `St`.
type AdapterError<W, St> =
    Error<<W as WalletRead>::Error, <W as InputSource>::Error, <St as PoolMigrationRead>::Error>;

/// A spendable Orchard note as the adapter tracks it: the note, its note-commitment-tree position,
/// and its value in zatoshi.
type SpendableNote = (OrchardNote, Position, u64);

/// A migration wallet built over a `zcash_client_backend` wallet `W`, an account, that account's
/// Orchard VIEWING key, and a migration store `St`.
///
/// The wallet is held by a shared borrow: the migration never touches the note commitment tree
/// (anchors and witnesses are deferred to proving time), so nothing here needs `&mut W`.
///
/// There is no spending key here, and no constructor that takes one. Signing is a parameter of
/// the engine calls that sign, so this type cannot be the thing that holds an account's spend
/// authority alive.
pub struct WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
{
    wallet: &'a W,
    account: <W as InputSource>::AccountId,
    /// The account's unified full viewing key, as the caller supplied it.
    ///
    /// Stored whole rather than reduced to its Orchard component at construction, so that
    /// constructing an adapter asks nothing of the key: an account whose unified key has no
    /// Orchard component is a real account, and the fact that this crate cannot serve it is
    /// reported by the operation that needs the Orchard key, not by the act of naming the account
    /// (see [`MigrationCrypto::orchard_fvk`]).
    ufvk: UnifiedFullViewingKey,
    store: St,
    /// The inter-arrival delays to schedule under, or `None` to derive them from the wallet's own
    /// anchor bucket interval by the ZIP 318 ratios.
    scheduling_delays: Option<(DelayDistribution, DelayDistribution)>,
    /// The spendable-note snapshot every read is served from, filled on first use — see
    /// [`Self::spendable_orchard`].
    spendable: RefCell<Option<Vec<SpendableNote>>>,
}

impl<'a, W, St> WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    /// Wrap a wallet, an account, that account's unified FULL VIEWING key, and a store as a
    /// migration wallet.
    ///
    /// Everything a migration does short of signing — selecting the account's notes, planning the
    /// denomination split and the schedule, building each transaction's PCZT, reading and writing
    /// the store, and (through [`WalletMigrationProver`]) proving — is a viewing-key operation, so
    /// viewing authority is all this adapter ever needs. The spend authority for the two engine
    /// calls that sign is passed to those calls; a watch-only account and a hardware-wallet
    /// account, which have none to give, use the unsigned entry points instead
    /// (`build_preparation_unsigned`, `rebuild_expired_transfer_unsigned`) and route the signing
    /// to whoever holds the key.
    ///
    /// The migration is scheduled under the wallet's own anchor retention interval — not
    /// configurable here; see [`MigrationBackend::scheduling_params`] — with inter-arrival delays
    /// derived from that interval by the ZIP 318 ratios. A wallet on the standard grid therefore
    /// gets exactly the ZIP 318 delays, and a wallet configured with a shortened grid gets the same
    /// schedule shape compressed by the same factor, rather than a short grid crossed with
    /// ninety-minute delays. Override the delays with [`Self::with_scheduling_delays`].
    ///
    /// The viewing key is the CALLER's to choose rather than being read from the account record,
    /// because a wallet may hold several keys that view one account (an imported UFVK beside a
    /// derived one) and only the caller knows which the migration's notes belong to. Pass the key
    /// the account's spendable notes were received with — the same one
    /// [`WalletMigrationProver::new`] must be given, since a mismatched key computes nullifiers
    /// that match no note and every spend resolution fails, and the same one whose spend authority
    /// the signing calls are given.
    ///
    /// A key with no Orchard component is accepted here and refused where it is USED: an
    /// account this crate cannot migrate is still an account, and the engine's build, commit and
    /// prove paths are already fallible, so they are where "this account has no Orchard key" is
    /// worth saying. Construction asks nothing of the key at all.
    pub fn new(
        wallet: &'a W,
        account: <W as InputSource>::AccountId,
        ufvk: UnifiedFullViewingKey,
        store: St,
    ) -> Self {
        Self {
            wallet,
            account,
            ufvk,
            store,
            scheduling_delays: None,
            spendable: RefCell::new(None),
        }
    }

    /// Sets the inter-arrival delay distributions between successive transfer and preparation
    /// broadcasts, replacing the ones otherwise derived from the wallet's anchor bucket interval.
    ///
    /// Only the delays are settable. The anchor bucket interval is read from the wallet, because a
    /// transfer can only be proved against a boundary whose checkpoint the wallet retained.
    pub fn with_scheduling_delays(
        mut self,
        transfer_delay: DelayDistribution,
        preparation_delay: DelayDistribution,
    ) -> Self {
        self.scheduling_delays = Some((transfer_delay, preparation_delay));
        self
    }

    /// Recover the store.
    pub fn into_store(self) -> St {
        self.store
    }

    /// The target height for note selection (the chain tip plus one).
    fn selection_target(&self) -> Result<TargetHeight, AdapterError<W, St>> {
        let tip = self
            .wallet
            .chain_height()
            .map_err(Error::WalletRead)?
            .ok_or(Error::ChainTipUnknown)?;
        Ok(TargetHeight::from(u32::from(tip) + 1))
    }

    /// The account's spendable Orchard notes as `(note, tree position, value)`, sorted by tree
    /// position and SNAPSHOTTED on the first read: the engine addresses a note by its index into
    /// this sequence (a plan's `PrepInput::Wallet { index, .. }` names the selection its planning
    /// call observed), so every read through one adapter must see the same set. The snapshot also
    /// keeps a commit linear in the plan's inputs — resolving each spent note through a fresh
    /// selection made signing a large plan quadratic in the wallet's note count.
    ///
    /// Wallet changes are observed by constructing a fresh adapter; this one's selection is fixed.
    fn spendable_orchard(&self) -> Result<Ref<'_, [SpendableNote]>, AdapterError<W, St>> {
        if self.spendable.borrow().is_none() {
            let target = self.selection_target()?;
            let received = self
                .wallet
                .select_unspent_notes(
                    self.account,
                    &[ShieldedPool::Orchard],
                    target,
                    &[],
                    LockFilter::Policy(&LockedInputPolicy::Exclude),
                )
                .map_err(Error::InputSource)?;
            let mut notes: Vec<SpendableNote> = received
                .orchard()
                .iter()
                .map(|rn| {
                    let note = *rn.note();
                    let value = note.value().inner();
                    (note, rn.note_commitment_tree_position(), value)
                })
                .collect();
            notes.sort_by_key(|(_, pos, _)| *pos);
            *self.spendable.borrow_mut() = Some(notes);
        }
        Ok(Ref::map(self.spendable.borrow(), |cached| {
            cached.as_deref().expect("filled above")
        }))
    }
}

impl<'a, W, St> MigrationBackend for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    type Error = AdapterError<W, St>;

    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
        self.spendable_orchard()?
            .iter()
            .enumerate()
            .map(|(i, &(_, _, value))| {
                Zatoshis::from_u64(value).map_err(|_| Error::InvalidNoteValue(i))
            })
            .collect()
    }

    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
        self.wallet
            .chain_height()
            .map_err(Error::WalletRead)?
            .ok_or(Error::ChainTipUnknown)
    }

    /// The anchor bucket interval is the wallet's own anchor retention interval, converted; the
    /// delays are derived from it unless [`Self::with_scheduling_delays`] overrode them. Deriving
    /// the grid from the wallet rather than accepting it here is what makes it impossible for a
    /// migration to anchor to a boundary whose checkpoint the wallet has not retained.
    fn scheduling_params(&self) -> SchedulingParams {
        let interval = self.wallet.anchor_retention_interval();
        match self.scheduling_delays {
            Some((transfer_delay, preparation_delay)) => {
                SchedulingParams::new(interval, transfer_delay, preparation_delay)
            }
            None => SchedulingParams::new_with_default_distributions(interval),
        }
    }
}

impl<'a, W, St> MigrationCrypto for WalletMigration<'a, W, St>
where
    // Reading the account record requires the wallet's two account-id types to agree; a wallet
    // whose note source and account store disagree could not identify one account anyway.
    W: WalletRead<AccountId = <W as InputSource>::AccountId> + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    type Error = AdapterError<W, St>;

    /// The Orchard component of the key the adapter was constructed with — never re-read from the
    /// account record, so a migration is built against exactly the key its caller named.
    ///
    /// `None` for a unified key that carries no Orchard component: such an account holds no notes
    /// this crate can migrate, which each engine entry point reports for itself.
    fn orchard_fvk(&self) -> Option<&FullViewingKey> {
        self.ufvk.orchard()
    }

    /// The account's derivation as the wallet records it, or `None` for an account the wallet
    /// holds no ZIP 32 derivation for.
    fn account_derivation(&self) -> Result<Option<AccountDerivation>, Self::Error> {
        Ok(self
            .wallet
            .get_account(self.account)
            .map_err(Error::WalletRead)?
            .and_then(|account| {
                account
                    .source()
                    .key_derivation()
                    .map(AccountDerivation::from)
            }))
    }

    fn resolve_wallet_note(&self, index: usize) -> Result<OrchardNote, Self::Error> {
        let notes = self.spendable_orchard()?;
        let &(note, _, _) = notes.get(index).ok_or(Error::NoteNotFound(index))?;
        Ok(note)
    }
}

impl<'a, W, St> PoolMigrationRead for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    type Error = AdapterError<W, St>;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        self.store.get_migration().map_err(Error::Store)
    }

    fn check_step_satisfiability(
        &self,
        tx: &MigrationTransaction,
        settle: ReorgSettleDepth,
    ) -> Result<StepSatisfiability, Self::Error> {
        self.store
            .check_step_satisfiability(tx, settle)
            .map_err(Error::Store)
    }

    /// Answered from the WALLET, not the store: inclusion is what the wallet's scan discovers, and
    /// this adapter is the seam that has one. The fully-scanned bound is applied here rather than
    /// left to `get_tx_height` — which reports a mined height as soon as the wallet learns it,
    /// including ahead of scanning — so a promotion cannot rest on a block outside the region a
    /// rollback would truncate.
    ///
    /// The bound is read FIRST, and a wallet with no fully-scanned region answers `None` without
    /// the inclusion lookup ever being made. That is not an optimization: nothing is promotable
    /// when there is no scanned region — every answer this gives has to be one a rollback of the
    /// block carrying the transaction would withdraw, and a wallet that has scanned nothing has no
    /// such region to withdraw from — so the question the second lookup asks does not arise. It
    /// also keeps this total on a wallet that has never synced, where a backend may have no chain
    /// tip to answer `get_tx_height` against at all, which is the state in which a store applying
    /// the same rule at its own layer (`zcash_client_sqlite`'s does) answers `None`. The two agree
    /// on every value, so a wallet whose store also implements this needs no delegation here.
    ///
    /// Errors from either lookup are propagated, never read as an absence: an answer the wallet
    /// could not give is not the answer that nothing is mined.
    fn mined_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        let Some(scanned) = self
            .wallet
            .block_fully_scanned()
            .map_err(Error::WalletRead)?
        else {
            return Ok(None);
        };
        Ok(self
            .wallet
            .get_tx_height(txid)
            .map_err(Error::WalletRead)?
            .filter(|mined| *mined <= scanned.block_height()))
    }
}

impl<'a, W, St> PoolMigrationWrite for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationWrite,
{
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.store.replace_migration(state).map_err(Error::Store)
    }

    fn update_transaction(
        &mut self,
        id: MigrationTransferId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        self.store
            .update_transaction(id, state)
            .map_err(Error::Store)
    }

    /// Delegated to the underlying store, whose implementation owns the wallet-side record (for
    /// `zcash_client_sqlite`'s store, the atomic finalize-and-persist into the wallet's own
    /// transaction tables).
    fn store_proved_transaction(
        &mut self,
        state: &mut MigrationState,
        proven: crate::engine::ProvedTransaction,
    ) -> Result<(), Self::Error> {
        self.store
            .store_proved_transaction(state, proven)
            .map_err(Error::Store)
    }
}

/// Why proving a migration transaction through the wallet-backed prover failed. `TE` is the
/// wallet's commitment-tree error type ([`WalletCommitmentTrees::Error`]); `NE` is its note-source
/// error type ([`InputSource::Error`]); `RE` is its chain-state error type
/// ([`WalletRead::Error`]).
#[derive(Debug)]
pub enum WalletProveError<TE, NE, RE, LE> {
    /// The PCZT presents no well-formed set of deferred-witness Orchard spends, so it is not a
    /// deferred-anchor migration transaction awaiting proof. See [`RealSpendError`].
    RealSpends(RealSpendError),
    /// No spendable Orchard note in the wallet matches a spend's revealed nullifier, so its tree
    /// position is unknown: the note the transaction spends is not among the account's unspent
    /// notes (it was never scanned, or has already been spent).
    UnknownSpentNote(Nullifier),
    /// Looking up the note-selection target height (the chain tip) through the wallet failed.
    TargetHeight(RE),
    /// The wallet's fully-scanned height could not be read, so a spend absent from the account's
    /// unspent notes could not be reported as [`ProveFailure::InputNotAvailable`]: that absence is
    /// only meaningful relative to the chain state it was observed against, and an observation
    /// with no honest backing height must not reach the engine. Reported only where the missing
    /// height actually blocked the classification.
    ScannedHeight(RE),
    /// The wallet knows of no block data, so the note-selection target height (the chain tip) is
    /// unavailable.
    ChainTipUnknown,
    /// Enumerating the account's spendable Orchard notes (to locate each spend by nullifier) failed.
    Notes(NE),
    /// A commitment tree (the Orchard source tree, or the Ironwood destination tree for a transfer)
    /// has no root at the anchor checkpoint (the checkpoint was never created, or was pruned before
    /// proving; see issue #2700).
    AnchorNotFound(BlockHeight),
    /// A spent note has no witness at the anchor checkpoint (the checkpoint was pruned, or the
    /// note's position is not marked in the tree).
    WitnessNotFound(BlockHeight),
    /// The wallet backend tracks no Ironwood commitment tree, so a transfer's Ironwood destination
    /// anchor cannot be resolved (the backend does not support the Ironwood pool).
    IronwoodTreeUnavailable,
    /// A commitment-tree query failed.
    Tree(ShardTreeError<TE>),
    /// Installing the Orchard source or Ironwood destination anchor through the PCZT `Updater` role
    /// failed.
    Anchor(AnchorUpdateError),
    /// Installing a spend witness through the PCZT `Updater` role failed.
    Witness(SpendWitnessUpdateError),
    /// Creating the Orchard or Ironwood proof failed. The two proof roles return distinct error
    /// types and `pczt` does not export the Ironwood one, so the failure is carried as a labeled
    /// diagnostic string rather than a typed value.
    Prove(alloc::string::String),
    /// Reserving the notes this transaction spends failed, so it did not become `Proved`.
    ///
    /// [`LockError::LockFailure`] is the interesting case: the named note is already locked by a
    /// DIFFERENT owner, so another flow (typically a user payment proposed while this transaction
    /// was being proved) has committed to spending it. That is a conflict this transaction cannot
    /// win, because the notes it spends were fixed by its signature. It is not necessarily fatal:
    /// the other flow may release its lock or let it expire without broadcasting, in which case a
    /// later proving attempt succeeds. It IS fatal once the other flow's transaction mines, which
    /// the next attempt reports as [`Self::UnknownSpentNote`].
    Lock(LockError<LE>),
}

impl<TE, NE, RE, LE> From<ShardTreeError<TE>> for WalletProveError<TE, NE, RE, LE> {
    fn from(e: ShardTreeError<TE>) -> Self {
        WalletProveError::Tree(e)
    }
}

impl<TE: fmt::Debug, NE: fmt::Debug, RE: fmt::Debug, LE: fmt::Debug> fmt::Display
    for WalletProveError<TE, NE, RE, LE>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletProveError::RealSpends(e) => {
                write!(f, "the PCZT has no spends to prove: {e}")
            }
            WalletProveError::UnknownSpentNote(nf) => {
                write!(
                    f,
                    "no spendable Orchard note matches spend nullifier {nf:?}"
                )
            }
            WalletProveError::TargetHeight(e) => {
                write!(
                    f,
                    "looking up the note-selection target height failed: {e:?}"
                )
            }
            WalletProveError::ScannedHeight(e) => {
                write!(
                    f,
                    "a spend's note is not among the account's unspent notes, and the wallet's \
                     fully-scanned height — the chain state that observation would rest on — could \
                     not be read: {e:?}"
                )
            }
            WalletProveError::ChainTipUnknown => {
                f.write_str("the wallet knows of no block data, so the chain tip is unavailable")
            }
            WalletProveError::Notes(e) => {
                write!(f, "enumerating spendable Orchard notes failed: {e:?}")
            }
            WalletProveError::AnchorNotFound(h) => write!(
                f,
                "a commitment tree has no root at the anchor checkpoint {}",
                u32::from(*h)
            ),
            WalletProveError::WitnessNotFound(h) => write!(
                f,
                "a spent note has no witness at the anchor checkpoint {}",
                u32::from(*h)
            ),
            WalletProveError::IronwoodTreeUnavailable => {
                f.write_str("the wallet backend tracks no Ironwood commitment tree")
            }
            WalletProveError::Tree(e) => write!(f, "commitment-tree query failed: {e:?}"),
            WalletProveError::Anchor(e) => write!(f, "installing an anchor failed: {e:?}"),
            WalletProveError::Witness(e) => write!(f, "installing a spend witness failed: {e:?}"),
            WalletProveError::Prove(msg) => write!(f, "creating a bundle proof failed: {msg}"),
            WalletProveError::Lock(e) => {
                write!(
                    f,
                    "reserving the notes this transaction spends failed: {e:?}"
                )
            }
        }
    }
}

impl<TE: fmt::Debug, NE: fmt::Debug, RE: fmt::Debug, LE: fmt::Debug> core::error::Error
    for WalletProveError<TE, NE, RE, LE>
{
}

/// The wallet-backed prover's error for a wallet `W`: a [`WalletProveError`] over the wallet's
/// commitment-tree, note-source, and chain-state error types.
type ProverError<W> = WalletProveError<
    <W as WalletCommitmentTrees>::Error,
    <W as InputSource>::Error,
    <W as WalletRead>::Error,
    <W as OutputLockStore>::Error,
>;

/// A wallet-backed prover for migration transactions: the mutable counterpart to [`WalletMigration`].
///
/// Proving resolves a transaction's DEFERRED Orchard anchor and its spends' Merkle witnesses against
/// a checkpoint (ZIP 374), which needs MUTABLE access to the wallet's Orchard commitment tree
/// ([`WalletCommitmentTrees::with_orchard_tree_mut`], whose witness resolution caches into the
/// tree). That is why proving lives here, borrowing the wallet as `&mut W`, rather than on the
/// shared-borrow [`WalletMigration`] used to build and sign.
///
/// Each spend is located by the nullifier it reveals: the prover enumerates the account's unspent
/// Orchard notes ([`InputSource::select_unspent_notes`]), recomputes each note's nullifier under the
/// account's full viewing key, and matches. This serves both a transfer (one funding-note spend
/// plus an Ironwood output) and a preparation transaction (one or more spends, no Ironwood). The
/// anchor checkpoint the witnesses are taken against must still exist in the tree at proving time
/// (the wallet backend must retain that checkpoint until the migration's transfers are proven).
pub struct WalletMigrationProver<'a, W>
where
    W: InputSource,
{
    wallet: &'a mut W,
    account: <W as InputSource>::AccountId,
    fvk: FullViewingKey,
}

/// One deferred-witness Orchard spend of a migration transaction, resolved against the account's
/// unspent notes: which action it is, where the note sits in the commitment tree (to witness it),
/// and how the wallet refers to the note (to lock it).
struct ResolvedSpend {
    /// The index of the Orchard action this spend belongs to, as the PCZT `Updater` role addresses
    /// it when installing the witness.
    action_index: usize,
    /// The spent note's position in the Orchard note commitment tree.
    position: Position,
    /// The spent note as the wallet's lock tables key it: the output its creating transaction
    /// produced.
    output: OutputRef,
}

/// The BLAKE2b personalization for [`migration_lock_owner`]. Sixteen bytes, as BLAKE2b requires.
const LOCK_OWNER_PERSONALIZATION: &[u8; 16] = b"ZcashMigLockOwnr";

/// Derive the lock-owner token for a migration transaction from the notes it spends.
///
/// The token is the BLAKE2b-256 hash of the transaction's spent-note references, sorted so the
/// result does not depend on action order. Deriving it rather than drawing it at random makes it
/// RECOVERABLE: the notes a transaction spends are fixed once it is signed, so a wallet that
/// crashed between taking the locks and persisting the token can re-derive exactly the same token
/// from the stored PCZT and release them. A random token would be lost with the crash, stranding
/// the reservation until the lock expiry passed or the account's locks were cleared wholesale.
///
/// Distinct migration transactions spend disjoint note sets (each funding note is spent once), so
/// distinct transactions get distinct tokens; and a 256-bit hash will not collide with the random
/// tokens other flows use.
fn migration_lock_owner(spends: &[ResolvedSpend]) -> MigrationLockOwner {
    let mut refs: Vec<(TxId, u32)> = spends
        .iter()
        .map(|s| (*s.output.txid(), s.output.output_index()))
        .collect();
    refs.sort_unstable();
    refs.dedup();

    let mut hasher = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(LOCK_OWNER_PERSONALIZATION)
        .to_state();
    for (txid, output_index) in refs {
        hasher.update(txid.as_ref());
        hasher.update(&output_index.to_le_bytes());
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(hasher.finalize().as_bytes());
    MigrationLockOwner::from_bytes(bytes)
}

impl<'a, W> WalletMigrationProver<'a, W>
where
    W: InputSource,
{
    /// Wrap a wallet (borrowed mutably for commitment-tree access), the account whose notes the
    /// migration spends, and that account's Orchard full viewing key (used to recompute each spent
    /// note's nullifier when locating it among the account's unspent notes).
    pub fn new(
        wallet: &'a mut W,
        account: <W as InputSource>::AccountId,
        fvk: FullViewingKey,
    ) -> Self {
        Self {
            wallet,
            account,
            fvk,
        }
    }
}

impl<'a, W> WalletMigrationProver<'a, W>
where
    W: WalletCommitmentTrees + InputSource + WalletRead + OutputLockStore,
    <W as InputSource>::AccountId: Copy,
{
    /// Prove one migration transaction's Orchard bundle (and its Ironwood bundle, when it has one)
    /// against `anchor_height`: install the source anchor and every deferred spend's witness through the
    /// PCZT `Updater` role, then run the provers. Shared by
    /// [`prove_transfer`](MigrationProver::prove_transfer) (a transfer: one Orchard spend plus an
    /// Ironwood output) and [`prove_preparation`](MigrationProver::prove_preparation) (a preparation:
    /// one or more Orchard spends, no Ironwood).
    ///
    /// The anchor and witnesses are resolved at `anchor_height`, but the spent notes are located at
    /// the wallet's standard note-selection target height (the chain tip, from
    /// [`WalletRead::get_target_and_anchor_heights`]), so a note already spent by a mined migration
    /// transaction is excluded from the candidate set.
    /// Locate every deferred-witness Orchard spend of `pczt` among the account's unspent notes.
    ///
    /// Each such spend reveals a nullifier; recomputing every unspent note's nullifier under the
    /// account's full viewing key identifies which note it spends, yielding both the tree position
    /// the witness is taken at and the reference the wallet locks the note by. Shared by
    /// [`prove_orchard`](Self::prove_orchard) and
    /// [`lock_spent_notes`](MigrationProver::lock_spent_notes), which need the two halves of the
    /// same lookup.
    ///
    /// Notes are selected at the wallet's standard note-selection target height (the chain tip,
    /// from [`WalletRead::get_target_and_anchor_heights`]), so a note already spent by a mined
    /// migration transaction is excluded from the candidate set and its spend is reported as
    /// [`WalletProveError::UnknownSpentNote`] rather than silently resolved. Only the target is
    /// needed; `min_confirmations` bounds only the (unused) anchor height, so the minimum is
    /// passed to avoid a spurious absence near genesis.
    ///
    /// Lock state is deliberately NOT filtered ([`LockFilter::Unfiltered`]): this resolves notes
    /// the transaction already commits to spending rather than choosing new ones, so a note locked
    /// by this very transaction's earlier proof attempt, or by any other flow, must still be found.
    fn resolve_spends(&self, pczt: &::pczt::Pczt) -> Result<Vec<ResolvedSpend>, ProverError<W>> {
        // Every Orchard action whose witness is still deferred is a real spend to witness; the padded
        // dummy spends keep their (arbitrary) witnesses from build time (ZIP 374).
        let real_spends: Vec<(usize, Nullifier)> = crate::pczt_spends::real_spend_nullifiers(pczt)
            .map_err(WalletProveError::RealSpends)?;

        let (target, _anchor) = self
            .wallet
            .get_target_and_anchor_heights(NonZeroU32::MIN)
            .map_err(WalletProveError::TargetHeight)?
            .ok_or(WalletProveError::ChainTipUnknown)?;
        let received = self
            .wallet
            .select_unspent_notes(
                self.account,
                &[ShieldedPool::Orchard],
                target,
                &[],
                LockFilter::Unfiltered,
            )
            .map_err(WalletProveError::Notes)?;
        let by_nullifier: BTreeMap<Nullifier, (Position, OutputRef)> = received
            .orchard()
            .iter()
            .map(|rn| {
                let output = OutputRef::new(
                    *rn.txid(),
                    PoolType::Shielded(ShieldedPool::Orchard),
                    rn.output_index().into(),
                );
                (
                    rn.note().nullifier(&self.fvk),
                    (rn.note_commitment_tree_position(), output),
                )
            })
            .collect();

        real_spends
            .iter()
            .map(|(action_index, nf)| {
                by_nullifier
                    .get(nf)
                    .map(|(position, output)| ResolvedSpend {
                        action_index: *action_index,
                        position: *position,
                        output: *output,
                    })
                    .ok_or(WalletProveError::UnknownSpentNote(*nf))
            })
            .collect()
    }

    fn prove_orchard(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor_height: BlockHeight,
    ) -> Result<::pczt::Pczt, ProverError<W>> {
        let spend_positions: Vec<(usize, Position)> = self
            .resolve_spends(&pczt)?
            .into_iter()
            .map(|s| (s.action_index, s.position))
            .collect();

        // A transfer carries an Ironwood output bundle; a preparation transaction is Orchard-only.
        let has_ironwood = !pczt.ironwood().actions().is_empty();

        // Resolve the source anchor (the tree root at the checkpoint) and each spend's Merkle witness
        // against it, mirroring `create_proposed_transactions`.
        let (anchor, witnesses): (Anchor, Vec<(usize, MerklePath)>) = self
            .wallet
            .with_orchard_tree_mut::<_, _, ProverError<W>>(|tree| {
                let root: Anchor = tree
                    .root_at_checkpoint_id(&anchor_height)?
                    .ok_or(WalletProveError::AnchorNotFound(anchor_height))?
                    .into();
                let mut witnesses = Vec::with_capacity(spend_positions.len());
                for (index, position) in &spend_positions {
                    let path: MerklePath = tree
                        .witness_at_checkpoint_id_caching(*position, &anchor_height)?
                        .ok_or(WalletProveError::WitnessNotFound(anchor_height))?
                        .into();
                    witnesses.push((*index, path));
                }
                Ok((root, witnesses))
            })?;

        // A transfer's Ironwood destination bundle must anchor at the SAME height as its Orchard
        // source bundle: all anchors in a transaction are computed for one height. Resolve the
        // Ironwood tree root at `anchor_height` (its output-only action's padding spend is a value-0
        // dummy whose Merkle path the circuit does not enforce, so no Ironwood witness is installed,
        // but the anchor must still be a real historical Ironwood root the consensus rules accept:
        // the empty-tree root is only valid while no Ironwood notes have been committed).
        let ironwood_anchor: Option<Anchor> = if has_ironwood {
            Some(
                self.wallet
                    .with_ironwood_tree_mut::<_, Anchor, ProverError<W>>(|tree| {
                        Ok(tree
                            .root_at_checkpoint_id(&anchor_height)?
                            .ok_or(WalletProveError::AnchorNotFound(anchor_height))?
                            .into())
                    })?
                    .ok_or(WalletProveError::IronwoodTreeUnavailable)?,
            )
        } else {
            None
        };

        // Install the deferred data through the Updater role: the Orchard source anchor and every
        // spend's witness, plus (for a transfer) the Ironwood destination anchor.
        let mut updater = Updater::new(pczt)
            .set_orchard_anchor(anchor)
            .map_err(WalletProveError::Anchor)?
            .set_orchard_spend_witnesses(witnesses)
            .map_err(WalletProveError::Witness)?;
        if let Some(ironwood_anchor) = ironwood_anchor {
            updater = updater
                .set_ironwood_anchor(ironwood_anchor)
                .map_err(WalletProveError::Anchor)?;
        }
        let updated = updater.finish();

        // Prove the Orchard bundle, and the Ironwood bundle too when present, with the single
        // post-NU6.3 Orchard proving key.
        let pk = cached_orchard_proving_key(OrchardCircuitVersion::PostNu6_3);
        let orchard_proven = Prover::new(updated)
            .create_orchard_proof(pk)
            .map_err(|e| WalletProveError::Prove(alloc::format!("orchard proof: {e:?}")))?;
        let proven = if has_ironwood {
            orchard_proven
                .create_ironwood_proof(pk)
                .map_err(|e| WalletProveError::Prove(alloc::format!("ironwood proof: {e:?}")))?
        } else {
            orchard_proven
        };
        Ok(proven.finish())
    }

    /// [`prove_orchard`](Self::prove_orchard) with its "no unspent note matches this spend"
    /// failure lifted into the engine's typed [`ProveFailure::InputNotAvailable`], the shared body
    /// of both [`MigrationProver`] methods.
    ///
    /// The observation the engine needs is MEMBERSHIP — the spend's note is not among the
    /// account's unspent notes — together with the chain state that absence rests on. The honest
    /// backing height is the wallet's FULLY-SCANNED height ([`WalletRead::block_fully_scanned`]),
    /// not the chain tip: the tip may run far ahead of what has been trial-decrypted, and the
    /// engine reads the height as "everything at or below this was scanned" when it decides
    /// whether an unmined-input explanation is still open. It is read BEFORE the note lookup it
    /// backs, so it can only understate the scan the observation actually rests on — understating
    /// costs a retry, whereas overstating could mark a live transaction dead. On the
    /// reorg-truncation side the trade runs the other way — an understated stamp clears LESS
    /// readily, retaining a mark whose evidence was rolled back — but reaching that case needs the
    /// wallet to scan new blocks between two adjacent queries of one prove call, the spend to land
    /// exactly in that window, and the window to reorg out, whereas an overstated height is the
    /// NORMAL state of a syncing wallet; the rare stale mark is recoverable by a deeper truncation,
    /// a false death is not.
    ///
    /// A wallet that reports no fully-scanned height at all has scanned nothing, so it can back no
    /// observation; the membership failure then surfaces unclassified as
    /// [`ProveFailure::Other`], and a wallet whose height lookup FAILED reports that failure
    /// ([`WalletProveError::ScannedHeight`]) — but only in this corner, since a proof that
    /// succeeded never needed the height.
    fn prove_orchard_classified(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor_height: BlockHeight,
    ) -> Result<::pczt::Pczt, ProveFailure<ProverError<W>>> {
        let as_of = self
            .wallet
            .block_fully_scanned()
            .map(|meta| meta.map(|m| m.block_height()));
        self.prove_orchard(pczt, anchor_height)
            .map_err(|e| match (e, as_of) {
                (WalletProveError::UnknownSpentNote(nf), Ok(Some(as_of))) => {
                    ProveFailure::InputNotAvailable {
                        nullifier: nf.to_bytes(),
                        as_of,
                    }
                }
                (WalletProveError::UnknownSpentNote(_), Err(e)) => {
                    ProveFailure::Other(WalletProveError::ScannedHeight(e))
                }
                (e, _) => ProveFailure::Other(e),
            })
    }
}

impl<'a, W> MigrationProver for WalletMigrationProver<'a, W>
where
    W: WalletCommitmentTrees + InputSource + WalletRead + OutputLockStore,
    <W as InputSource>::AccountId: Copy,
{
    type Error = ProverError<W>;

    fn prove_transfer(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor_boundary: BlockHeight,
    ) -> Result<::pczt::Pczt, ProveFailure<Self::Error>> {
        self.prove_orchard_classified(pczt, anchor_boundary)
    }

    fn prove_preparation(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor: BlockHeight,
    ) -> Result<::pczt::Pczt, ProveFailure<Self::Error>> {
        self.prove_orchard_classified(pczt, anchor)
    }

    /// The grid the wallet this prover reads its commitment trees from currently retains anchor
    /// checkpoints on, so a transfer committed against a different grid is rejected before its
    /// (by then pruned) checkpoint is looked up.
    fn anchor_bucket_interval(&self) -> AnchorBucketInterval {
        self.wallet.anchor_retention_interval()
    }

    /// Lock the account's notes that this proven transaction spends, under a token derived from
    /// those very notes, until `lock_expiry_height`.
    ///
    /// Locking is all-or-nothing at the storage layer, and re-locking under the same owner is
    /// idempotent, so re-proving a transaction (after a crash, or a rebuild that reuses the same
    /// funding note) simply extends its own locks rather than failing.
    ///
    /// A note already locked by a DIFFERENT owner means another flow has committed to spending it,
    /// most likely a user payment created while this transaction was being proved. That is a real
    /// conflict this transaction cannot win: the notes it spends are fixed by its signature, so
    /// the failure is surfaced as [`WalletProveError::Lock`] and the transaction stays
    /// `Signed`. The proof just computed is discarded, which is the correct trade: the user's
    /// payment takes precedence, and a proof over a note the wallet has promised elsewhere is
    /// worth nothing.
    fn lock_spent_notes(
        &mut self,
        pczt: &::pczt::Pczt,
        lock_expiry_height: BlockHeight,
    ) -> Result<Option<MigrationLockOwner>, Self::Error> {
        let spends = self.resolve_spends(pczt)?;
        let owner = migration_lock_owner(&spends);
        let outputs: Vec<OutputRef> = spends.iter().map(|s| s.output).collect();

        self.wallet
            .lock_outputs(
                &outputs,
                LockOwner::new(*owner.as_bytes()),
                lock_expiry_height,
            )
            .map_err(WalletProveError::Lock)?;

        Ok(Some(owner))
    }
}

#[cfg(all(test, feature = "wallet"))]
mod tests {
    use super::*;

    use rand_core::{CryptoRng, RngCore};
    use zcash_client_backend::data_api::testing::MockWalletDb;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::consensus::{Network, Parameters};

    use crate::build::test_util::{TARGET_HEIGHT, regtest_network};
    use crate::engine::commit_preparation;

    /// A store that persists nothing and observes nothing: the adapter's KEY handling is what the
    /// tests below exercise, and the account's viewing key is not routed through the store. Every
    /// answer is the empty one a store with no migration gives.
    struct NoStore;

    impl PoolMigrationRead for NoStore {
        type Error = core::convert::Infallible;

        fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(None)
        }

        fn check_step_satisfiability(
            &self,
            _tx: &MigrationTransaction,
            _settle: ReorgSettleDepth,
        ) -> Result<StepSatisfiability, Self::Error> {
            Ok(StepSatisfiability::NotYetSatisfiable {
                as_of_height: BlockHeight::from_u32(TARGET_HEIGHT),
            })
        }

        fn mined_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
            Ok(None)
        }
    }

    /// An account's unified spending key, derived from a `seed` byte so the tests can vary the
    /// account. Only its unified FULL VIEWING key reaches the adapter; the spending key stays
    /// here, which is the property under test.
    fn account_usk(seed: u8) -> UnifiedSpendingKey {
        UnifiedSpendingKey::from_seed(&regtest_network(true), &[seed; 32], zip32::AccountId::ZERO)
            .expect("the seed derives a unified spending key")
    }

    /// The adapter serves the Orchard viewing key it was CONSTRUCTED with, and that key is the
    /// account's — the one whose spend authority the signing calls will be given, so what this
    /// adapter plans and builds is what that authority can sign.
    ///
    /// There is deliberately no counterpart test for signing through the adapter: it holds no
    /// spending key and offers no way to give it one, so "the adapter signs" is not a state this
    /// type can be in. The compiler enforces what a runtime error used to report.
    #[test]
    fn the_adapter_serves_the_viewing_key_it_was_built_with() {
        let wallet = MockWalletDb::new(Network::TestNetwork);
        let usk = account_usk(3);
        let expected = FullViewingKey::from(usk.orchard());

        let adapter = WalletMigration::new(&wallet, 0, usk.to_unified_full_viewing_key(), NoStore);

        assert_eq!(
            adapter.orchard_fvk(),
            Some(&expected),
            "the adapter extracts the Orchard component of the key it was given",
        );
    }

    /// Compile-time proof that `WalletMigration` over ANY `zcash_client_backend` wallet `W` and ANY
    /// migration store `St` satisfies every trait bound `commit_preparation` requires (backend +
    /// crypto + store, all sharing one error type). Naming the generic function instantiated at
    /// `WalletMigration<W, St>` forces the type checker to verify that instantiation's bounds hold;
    /// if the four trait impls ever stop lining up with the commit path, this stops compiling. It
    /// is never called and needs no wallet instance, so it pulls in no test-only wallet dependency
    /// (which would otherwise force `zcash_client_backend`'s Orchard feature on across the whole
    /// workspace's test build).
    #[allow(dead_code)]
    fn assert_commit_bounds<'a, P, W, St, R>()
    where
        P: Parameters + Clone,
        W: WalletRead<AccountId = <W as InputSource>::AccountId> + InputSource + 'a,
        <W as InputSource>::AccountId: Copy,
        St: PoolMigrationWrite,
        R: RngCore + CryptoRng,
    {
        let _ = commit_preparation::<P, WalletMigration<'a, W, St>, R>;
    }
}
