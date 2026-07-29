//! The trait seams a wallet implements to become a migration wallet: what the engine needs FROM a
//! wallet, stated as five traits and nothing else.
//!
//! Read together these are the crate's interface to the outside world, split along the axis of what
//! each one costs a wallet to provide. [`MigrationBackend`] is the planning view (spendable note
//! values, the chain tip, the scheduling grid) and [`PoolMigrationRead`] / [`PoolMigrationWrite`]
//! are the store, both of which a wallet can satisfy without any key material.
//! [`MigrationCrypto`] additionally needs the account's viewing key and spend authority, and
//! [`MigrationProver`] needs mutable commitment-tree access and the proving parameters. A consumer
//! can therefore supply the cheap capabilities from one type and the expensive ones from another,
//! which is exactly what the wallet adapter does.
//!
//! Naming them together in one module makes the interface readable in a single screen, and keeps
//! the [`engine`](crate::engine) module to the operations that CONSUME these seams. All five are
//! re-exported from [`engine`](crate::engine), so existing paths keep resolving.

use alloc::vec::Vec;

use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

#[cfg(feature = "orchard")]
use crate::build::AccountDerivation;
use crate::model::{MigrationState, MigrationTransferId, MigrationTxState};

/// What the migration engine needs from a wallet to PLAN a migration: the account's spendable notes and
/// the chain state. Following the `zcash_client_backend` pattern, a later slice replaces this with the
/// wallet's own note-source and chain-view traits (`WalletRead` / `InputSource`), so any such wallet is a
/// migration wallet; for now a backend implements it directly over its note store and chain view.
pub trait MigrationBackend {
    /// The backend's own error type (a store or chain-access failure).
    type Error;

    /// The values of the account's spendable source-pool (Orchard) notes. The migration decomposes
    /// their total into denominations; the same notes are later spent by the preparation
    /// transactions, so the values must line up with what the build step will resolve to witnesses.
    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error>;

    /// The current chain-tip height, from which the transfer schedule's delays accumulate.
    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error>;

    /// The parameters this backend's migrations are scheduled under: the anchor bucket grid and the
    /// transfer and preparation inter-arrival delays.
    ///
    /// The engine never takes these as its own argument; it asks the backend, because the anchor
    /// bucket interval is not free to choose. A transfer proves against the note commitment tree
    /// state at the boundary it anchored to, which requires the wallet to have RETAINED that
    /// boundary's checkpoint. Sourcing the interval from the same backend that performs the
    /// retention is what makes the two grids incapable of disagreeing; a backend that returns an
    /// interval it does not retain on will produce transfers it cannot prove.
    ///
    /// A backend on the production network must return [`SchedulingParams::ZIP_318`].
    ///
    /// [`SchedulingParams::ZIP_318`]: crate::scheduling::SchedulingParams::ZIP_318
    fn scheduling_params(&self) -> crate::scheduling::SchedulingParams;
}

/// Read access to a persisted pool migration: the store side of the migration interface, mirroring
/// `zcash_client_backend`'s `WalletRead`. A store implements this over its own tables
/// (`zcash_client_sqlite`'s `pool_migration` module does so over tables registered into its
/// `WalletDb` schema). The committed migration is a set of pre-signed PCZTs plus their schedule and
/// lifecycle state, so a wallet resumes a migration entirely from the store after being closed or
/// restarted.
pub trait PoolMigrationRead {
    /// The store's own error type.
    type Error;

    /// The migration currently in progress, if any.
    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error>;
}

/// Write access to a persisted pool migration, mirroring `zcash_client_backend`'s `WalletWrite`.
pub trait PoolMigrationWrite: PoolMigrationRead {
    /// Persist a committed migration: every transaction as its pre-signed PCZT plus the metadata the
    /// application needs to prove, schedule, and broadcast it. Storing the pre-signed transactions, not
    /// just the plan, is what lets a wallet resume a migration after being closed or restarted.
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error>;

    /// Advance one stored transaction's lifecycle state (for example after the application broadcasts
    /// it, or the chain mines it).
    fn update_transaction(
        &mut self,
        id: MigrationTransferId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error>;
}

/// The Orchard-specific wallet operations the engine needs to BUILD and PRE-SIGN a migration: the
/// account's viewing key, its spendable notes' plaintexts, and spend-authorization signing. Kept
/// separate from [`MigrationBackend`] so the planning and persistence parts stay pure; one wallet
/// implements both over the same account. Behind the `orchard` feature.
///
/// No anchors and no witnesses appear here: every migration transaction is built and signed with
/// its anchor and witnesses DEFERRED to proving time ([ZIP 374]) — a spent note's plaintext fully
/// determines the signed data, and its tree position matters only to the proof, which the consumer
/// creates through the PCZT `Updater` role once the note is mined.
///
/// [ZIP 374]: https://zips.z.cash/zip-0374
#[cfg(feature = "orchard")]
pub trait MigrationCrypto {
    /// The backend's error type (shared with its [`MigrationBackend`] impl).
    type Error;

    /// The account's Orchard full viewing key.
    fn orchard_fvk(&self) -> Result<orchard::keys::FullViewingKey, Self::Error>;

    /// The ZIP 32 account the migration's notes belong to, or `None` if the account has no known
    /// derivation (an imported viewing key, say).
    ///
    /// The builders stamp this onto every spend a migration transaction still needs a signature
    /// for, which is how an EXTERNAL Signer recognizes those spends as the account's. A backend
    /// that returns `None` while signing is delegated to an external signer produces
    /// transactions no derivation-matching Signer can authorize, so return the derivation whenever
    /// the wallet knows it, even if it currently signs in process.
    fn account_derivation(&self) -> Result<Option<AccountDerivation>, Self::Error>;

    /// The plaintext of the spendable wallet note at `index` (into
    /// `spendable_orchard_note_values`).
    fn resolve_wallet_note(&self, index: usize) -> Result<orchard::note::Note, Self::Error>;

    /// Add the account's Orchard spend-authorization signatures to a finalized, unproven PCZT.
    fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error>;
}

/// The proving seam for a migration transfer: install a transfer's deferred anchors and witnesses
/// (ZIP 374) against the boundary its schedule drew, then prove it.
///
/// This is deliberately SEPARATE from [`MigrationCrypto`]. Signing needs only the account's spend
/// authority and is a cheap, read-only (`&self`) operation; proving needs MUTABLE access to the
/// wallet's Orchard commitment tree at a historical checkpoint (resolving a witness caches into the
/// tree) plus the Orchard and Ironwood proving keys, a heavier capability with a different lifetime.
/// Keeping proving in its own trait lets a wallet expose signing without dragging commitment-tree
/// access and proving parameters into the same type, and lets a consumer supply a prover
/// independently of the signer.
#[cfg(feature = "orchard")]
pub trait MigrationProver {
    /// The prover's error type.
    type Error;

    /// Prove a pre-signed transfer against the boundary its schedule drew.
    ///
    /// This is where a transfer's DEFERRED anchors and witnesses (ZIP 374) are finally resolved and
    /// installed: the implementation reads the Orchard source-tree root at the `anchor_boundary`
    /// checkpoint (the source anchor) and the funding note's Merkle witness against it, installs both
    /// through the PCZT `Updater` role (`set_anchor` / `set_spend_witness`), installs the Ironwood
    /// destination anchor for the output bundle, then proves both bundles and returns the proven
    /// PCZT, ready to broadcast. The `anchor_boundary` is the boundary height drawn at SCHEDULING
    /// time and persisted on the transaction
    /// ([`MigrationTransaction::anchor_boundary`](crate::model::MigrationTransaction::anchor_boundary));
    /// passing it
    /// here is what makes the drawn boundary, not the tip, the tree state the transfer proves
    /// against.
    ///
    /// Resolving the funding note's witness requires the boundary checkpoint to still exist in the
    /// wallet's commitment tree at proving time; a wallet backend keeps it alive through migration
    /// anchor-checkpoint retention (see issue #2700).
    fn prove_transfer(
        &mut self,
        pczt: pczt::Pczt,
        anchor_boundary: BlockHeight,
    ) -> Result<pczt::Pczt, Self::Error>;

    /// Prove a pre-signed PREPARATION transaction against a checkpoint at which its spent notes are
    /// witnessable.
    ///
    /// Like a transfer, a preparation transaction defers its Orchard anchor and its spends'
    /// witnesses to proving time (ZIP 374), but it carries NO drawn
    /// [`anchor_boundary`](crate::model::MigrationTransaction::anchor_boundary) (it anchors to
    /// its already-mined
    /// dependencies, not to a bucketed boundary), so the `anchor` height is passed in: the caller
    /// proves a preparation once its inputs are mined and picks a checkpoint at or after that (for
    /// example the current chain tip). A preparation spends the wallet's own notes (layer 0) or
    /// feeder notes minted by an earlier layer — one or MANY, unlike a transfer's single funding
    /// note — and produces only an Orchard bundle (no Ironwood output), so the implementation
    /// installs the anchor and every real spend's witness through the PCZT `Updater` role and proves
    /// the single Orchard bundle.
    fn prove_preparation(
        &mut self,
        pczt: pczt::Pczt,
        anchor: BlockHeight,
    ) -> Result<pczt::Pczt, Self::Error>;

    /// The anchor bucket grid the wallet backing this prover currently retains its durable anchor
    /// checkpoints on.
    ///
    /// [`prove_transfer`](crate::engine::prove_transfer) compares this against the grid the
    /// migration was committed under and
    /// refuses to prove a transfer whose boundary is no longer retained, so a reconfiguration
    /// mid-migration surfaces as
    /// [`ProveError::AnchorIntervalMismatch`](crate::engine::ProveError::AnchorIntervalMismatch)
    /// rather than as a bare
    /// missing checkpoint at witness-resolution time.
    fn anchor_bucket_interval(&self) -> crate::scheduling::AnchorBucketInterval;
}
