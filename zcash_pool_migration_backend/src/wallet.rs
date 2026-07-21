//! A wallet-backed adapter that turns any `zcash_client_backend` wallet into a migration wallet.
//!
//! The engine's build and commit path needs an implementation of [`MigrationBackend`] +
//! [`MigrationCrypto`] (the account's viewing key, its spendable notes' plaintexts, and signing)
//! and a [`PoolMigrationRead`] / [`PoolMigrationWrite`] store. This module supplies the first two
//! for free over the traits a `zcash_client_backend` wallet already implements ([`WalletRead`],
//! [`InputSource`]) plus the account's [`UnifiedSpendingKey`], and delegates the store to a value
//! the caller supplies (for example `zcash_client_sqlite`'s `pool_migration` store over the same
//! wallet database). A consuming application (zallet, or any other `zcash_client_backend` wallet)
//! then
//! runs [`commit_preparation`] with no hand-wired cryptography.
//!
//! [`WalletMigration`] holds the wallet by a SHARED borrow and touches no note commitment tree:
//! every migration transaction is built and signed with its anchor and witnesses deferred to
//! proving time (ZIP 374). Proving is the separate [`WalletMigrationProver`], which borrows the
//! wallet as `&mut W` to resolve the drawn source anchor and the funding note's witness from the
//! wallet's Orchard commitment tree and installs them through the PCZT `Updater` role before
//! proving both bundles, just before broadcast.
//!
//! [`commit_preparation`]: crate::engine::commit_preparation

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;
use std::sync::OnceLock;

use ::orchard::Anchor;
use ::orchard::circuit::{OrchardCircuitVersion, ProvingKey};
use ::orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use ::orchard::note::Note as OrchardNote;
use ::orchard::tree::MerklePath;
use incrementalmerkletree::Position;
use shardtree::error::ShardTreeError;

use ::pczt::roles::prover::Prover;
use ::pczt::roles::updater::{AnchorUpdateError, SpendWitnessUpdateError, Updater};
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::{InputSource, WalletCommitmentTrees, WalletRead};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::build::sign_pczt;
use crate::engine::{
    MigrationBackend, MigrationCrypto, MigrationProver, MigrationState, MigrationTxId,
    MigrationTxState, PoolMigrationRead, PoolMigrationWrite,
};

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
    /// Signing the migration PCZT failed.
    Sign(crate::build::BuildError),
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
            Error::Sign(e) => write!(f, "signing the migration failed: {e}"),
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

/// A migration wallet built over a `zcash_client_backend` wallet `W`, an account, its
/// [`UnifiedSpendingKey`], and a migration store `St`.
///
/// The wallet is held by a shared borrow: the migration never touches the note commitment tree
/// (anchors and witnesses are deferred to proving time), so nothing here needs `&mut W`.
pub struct WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
{
    wallet: &'a W,
    account: <W as InputSource>::AccountId,
    usk: UnifiedSpendingKey,
    store: St,
}

impl<'a, W, St> WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    /// Wrap a wallet, an account, its spending key, and a store as a migration wallet.
    pub fn new(
        wallet: &'a W,
        account: <W as InputSource>::AccountId,
        usk: UnifiedSpendingKey,
        store: St,
    ) -> Self {
        Self {
            wallet,
            account,
            usk,
            store,
        }
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
    /// position so the index is stable across calls (the engine maps a value index from
    /// `spendable_orchard_note_values` back to a note by the same order).
    fn spendable_orchard(&self) -> Result<Vec<SpendableNote>, AdapterError<W, St>> {
        let target = self.selection_target()?;
        let received = self
            .wallet
            .select_unspent_notes(self.account, &[ShieldedPool::Orchard], target, &[])
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
        Ok(notes)
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
            .into_iter()
            .enumerate()
            .map(|(i, (_, _, value))| {
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
}

impl<'a, W, St> MigrationCrypto for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    type Error = AdapterError<W, St>;

    fn orchard_fvk(&self) -> Result<FullViewingKey, Self::Error> {
        Ok(FullViewingKey::from(self.usk.orchard()))
    }

    fn resolve_wallet_note(&self, index: usize) -> Result<OrchardNote, Self::Error> {
        let notes = self.spendable_orchard()?;
        let &(note, _, _) = notes.get(index).ok_or(Error::NoteNotFound(index))?;
        Ok(note)
    }

    fn sign(&self, pczt: ::pczt::Pczt) -> Result<::pczt::Pczt, Self::Error> {
        let ask = SpendAuthorizingKey::from(self.usk.orchard());
        sign_pczt(pczt, &ask).map_err(Error::Sign)
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
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        self.store
            .update_transaction(id, state)
            .map_err(Error::Store)
    }
}

/// The single Orchard proving key used for both the source (Orchard) and destination (Ironwood)
/// bundles of a post-NU6.3 migration transfer. Building it is expensive (it materializes the halo2
/// circuit parameters), so it is built once and cached for the process. Ironwood proofs reuse the
/// same key as Orchard (both are the `PostNu6_3` circuit).
fn post_nu6_3_orchard_proving_key() -> &'static ProvingKey {
    static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();
    PROVING_KEY.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::PostNu6_3))
}

/// Why proving a migration transfer through the wallet-backed prover failed. `TE` is the wallet's
/// commitment-tree error type ([`WalletCommitmentTrees::Error`]).
#[derive(Debug)]
pub enum WalletProveError<TE> {
    /// The transfer PCZT has no real Orchard spend to witness. Every migration transfer spends one
    /// funding note, so its bundle carries exactly one action whose witness is still deferred (all
    /// the fabricated dummy spends keep their own witnesses); its absence means the PCZT is not a
    /// deferred-anchor transfer awaiting proof.
    NoRealSpend,
    /// No tree position is known for the funding note the transfer spends (keyed by the revealed
    /// spend nullifier). The caller's position map does not cover this note.
    UnknownFundingNote([u8; 32]),
    /// The Orchard commitment tree has no root at the drawn anchor-boundary checkpoint (the
    /// checkpoint was never created, or was pruned before proving; see issue #2700).
    AnchorNotFound(BlockHeight),
    /// The funding note has no witness at the drawn anchor-boundary checkpoint (the checkpoint was
    /// pruned, or the note's position is not marked in the tree).
    WitnessNotFound(BlockHeight),
    /// A commitment-tree query failed.
    Tree(ShardTreeError<TE>),
    /// Installing the Orchard source or Ironwood destination anchor through the PCZT `Updater` role
    /// failed.
    Anchor(AnchorUpdateError),
    /// Installing the funding note's spend witness through the PCZT `Updater` role failed.
    Witness(SpendWitnessUpdateError),
    /// Creating the Orchard or Ironwood proof failed. The two proof roles return distinct error
    /// types and `pczt` does not export the Ironwood one, so the failure is carried as a labeled
    /// diagnostic string rather than a typed value.
    Prove(alloc::string::String),
}

impl<TE> From<ShardTreeError<TE>> for WalletProveError<TE> {
    fn from(e: ShardTreeError<TE>) -> Self {
        WalletProveError::Tree(e)
    }
}

impl<TE: fmt::Debug> fmt::Display for WalletProveError<TE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletProveError::NoRealSpend => {
                f.write_str("the transfer PCZT has no deferred-witness Orchard spend to prove")
            }
            WalletProveError::UnknownFundingNote(nf) => {
                write!(
                    f,
                    "no tree position known for funding note nullifier {nf:?}"
                )
            }
            WalletProveError::AnchorNotFound(h) => write!(
                f,
                "the Orchard tree has no root at the drawn anchor-boundary checkpoint {}",
                u32::from(*h)
            ),
            WalletProveError::WitnessNotFound(h) => write!(
                f,
                "the funding note has no witness at the drawn anchor-boundary checkpoint {}",
                u32::from(*h)
            ),
            WalletProveError::Tree(e) => write!(f, "commitment-tree query failed: {e:?}"),
            WalletProveError::Anchor(e) => write!(f, "installing an anchor failed: {e:?}"),
            WalletProveError::Witness(e) => write!(f, "installing the spend witness failed: {e:?}"),
            WalletProveError::Prove(msg) => write!(f, "creating a bundle proof failed: {msg}"),
        }
    }
}

impl<TE: fmt::Debug> core::error::Error for WalletProveError<TE> {}

/// A wallet-backed prover for migration transfers: the mutable counterpart to [`WalletMigration`].
///
/// Proving a transfer resolves its DEFERRED Orchard source anchor and the funding note's Merkle
/// witness against the boundary the schedule drew (ZIP 374), which needs MUTABLE access to the
/// wallet's Orchard commitment tree ([`WalletCommitmentTrees::with_orchard_tree_mut`], whose witness
/// resolution caches into the tree). That is why proving lives here, borrowing the wallet as
/// `&mut W`, rather than on the shared-borrow [`WalletMigration`] used to build and sign.
///
/// The funding note a transfer spends is identified by the revealed spend nullifier; `funding_positions`
/// maps that nullifier to the note's position in the wallet's Orchard commitment tree. A production
/// consumer fills this map from the wallet's own note store (looking each nullifier up in the
/// received-notes table); the anchor-boundary checkpoint the witness is taken against must still
/// exist in the tree at proving time (migration anchor-checkpoint retention, issue #2700).
pub struct WalletMigrationProver<'a, W> {
    wallet: &'a mut W,
    funding_positions: BTreeMap<[u8; 32], Position>,
}

impl<'a, W> WalletMigrationProver<'a, W> {
    /// Wrap a wallet (borrowed mutably for commitment-tree access) and the map from each funding
    /// note's revealed spend nullifier to its position in the wallet's Orchard commitment tree.
    pub fn new(wallet: &'a mut W, funding_positions: BTreeMap<[u8; 32], Position>) -> Self {
        Self {
            wallet,
            funding_positions,
        }
    }
}

impl<'a, W> MigrationProver for WalletMigrationProver<'a, W>
where
    W: WalletCommitmentTrees,
{
    type Error = WalletProveError<<W as WalletCommitmentTrees>::Error>;

    fn prove_transfer(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor_boundary: BlockHeight,
    ) -> Result<::pczt::Pczt, Self::Error> {
        // The one Orchard action whose witness is still deferred is the real funding-note spend; the
        // padded dummy spends keep their (arbitrary) witnesses from build time (ZIP 374).
        let (spend_index, nullifier) = pczt
            .orchard()
            .actions()
            .iter()
            .enumerate()
            .find(|(_, action)| action.spend().witness().is_none())
            .map(|(index, action)| (index, *action.spend().nullifier()))
            .ok_or(WalletProveError::NoRealSpend)?;

        let position = *self
            .funding_positions
            .get(&nullifier)
            .ok_or(WalletProveError::UnknownFundingNote(nullifier))?;

        // Resolve the source anchor (the tree root at the boundary checkpoint) and the funding note's
        // Merkle witness against it, mirroring `create_proposed_transactions`.
        let (anchor, merkle_path): (Anchor, MerklePath) = self
            .wallet
            .with_orchard_tree_mut::<_, _, WalletProveError<<W as WalletCommitmentTrees>::Error>>(
                |tree| {
                    let anchor: Anchor = tree
                        .root_at_checkpoint_id(&anchor_boundary)?
                        .ok_or(WalletProveError::AnchorNotFound(anchor_boundary))?
                        .into();
                    let merkle_path: MerklePath = tree
                        .witness_at_checkpoint_id_caching(position, &anchor_boundary)?
                        .ok_or(WalletProveError::WitnessNotFound(anchor_boundary))?
                        .into();
                    Ok((anchor, merkle_path))
                },
            )?;

        // Install the deferred data through the Updater role: the Orchard source anchor and the
        // funding note's witness, and the Ironwood destination anchor (the output side anchors to the
        // empty tree; it has no spend to witness).
        let updated = Updater::new(pczt)
            .set_orchard_anchor(anchor)
            .map_err(WalletProveError::Anchor)?
            .set_orchard_spend_witnesses([(spend_index, merkle_path)])
            .map_err(WalletProveError::Witness)?
            .set_ironwood_anchor(Anchor::empty_tree())
            .map_err(WalletProveError::Anchor)?
            .finish();

        // Prove both bundles with the single post-NU6.3 Orchard proving key.
        let pk = post_nu6_3_orchard_proving_key();
        let proven = Prover::new(updated)
            .create_orchard_proof(pk)
            .map_err(|e| WalletProveError::Prove(alloc::format!("orchard proof: {e:?}")))?
            .create_ironwood_proof(pk)
            .map_err(|e| WalletProveError::Prove(alloc::format!("ironwood proof: {e:?}")))?
            .finish();

        Ok(proven)
    }
}

#[cfg(all(test, feature = "wallet"))]
mod tests {
    use super::*;

    use rand_core::{CryptoRng, RngCore};
    use zcash_protocol::consensus::Parameters;

    use crate::engine::commit_preparation;

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
        W: WalletRead + InputSource + 'a,
        <W as InputSource>::AccountId: Copy,
        St: PoolMigrationWrite,
        R: RngCore + CryptoRng,
    {
        let _ = commit_preparation::<P, WalletMigration<'a, W, St>, R>;
    }
}
