//! A wallet-backed adapter that turns any `zcash_client_backend` wallet into a migration wallet.
//!
//! The engine's build and commit path needs an implementation of [`MigrationBackend`] +
//! [`MigrationCrypto`] (the account's viewing key, note witnesses, an anchor, and signing) and a
//! [`PoolMigrationRead`] / [`PoolMigrationWrite`] store. This module supplies the first two for free
//! over the traits a `zcash_client_backend` wallet already implements ([`WalletRead`],
//! [`InputSource`], [`WalletCommitmentTrees`]) plus the account's [`UnifiedSpendingKey`], and
//! delegates the store to a value the caller supplies (for example
//! `zcash_pool_migration_sqlite`'s store over the same wallet database). A consuming application
//! (zallet, or any other `zcash_client_backend` wallet) then runs [`commit_preparation`] /
//! [`commit_transfers`] with no hand-wired cryptography.
//!
//! [`commit_preparation`]: crate::engine::commit_preparation
//! [`commit_transfers`]: crate::engine::commit_transfers

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;

use ::orchard::Anchor;
use ::orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use ::orchard::note::Note as OrchardNote;
use ::orchard::tree::MerklePath;
use incrementalmerkletree::Position;
use shardtree::error::ShardTreeError;

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::{InputSource, WalletCommitmentTrees, WalletRead};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::build::sign_pczt;
use crate::engine::{
    MigrationBackend, MigrationCrypto, MigrationState, MigrationTxId, MigrationTxState,
    PoolMigrationRead, PoolMigrationWrite,
};

/// A failure of the wallet-backed migration adapter. Parameterized by the error types of the three
/// wallet traits and the store, which for `zcash_client_sqlite`'s `WalletDb` are all one type but in
/// general need not be.
#[derive(Debug)]
pub enum Error<WRE, ISE, SE> {
    /// A `WalletRead` failure (chain tip or anchor-height lookup).
    WalletRead(WRE),
    /// An `InputSource` failure (spendable-note selection).
    InputSource(ISE),
    /// A store failure (`PoolMigrationRead` / `PoolMigrationWrite`).
    Store(SE),
    /// No spendable note matched the requested index or value (for `index`, the position into the
    /// spendable set; for a funding value, its index into the requested values).
    NoteNotFound(usize),
    /// No usable anchor could be obtained: the wallet has no chain tip, or the anchor checkpoint is
    /// not present in the note commitment tree yet.
    AnchorUnavailable,
    /// Signing the migration PCZT failed.
    Sign(String),
    /// A note commitment tree (shardtree) error, rendered to a string (the tree error type is a
    /// fourth, `WalletCommitmentTrees`-specific type, kept out of this enum's parameters).
    Tree(String),
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
            Error::NoteNotFound(i) => write!(f, "no spendable note for index/value {i}"),
            Error::AnchorUnavailable => f.write_str("no usable anchor checkpoint is available"),
            Error::Sign(m) => write!(f, "signing the migration failed: {m}"),
            Error::Tree(m) => write!(f, "note commitment tree error: {m}"),
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

impl<WRE, ISE, SE, WCE: fmt::Debug> From<ShardTreeError<WCE>> for Error<WRE, ISE, SE> {
    fn from(e: ShardTreeError<WCE>) -> Self {
        Error::Tree(format!("{e:?}"))
    }
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
/// The wallet is held by a mutable borrow behind a [`RefCell`], because
/// [`WalletCommitmentTrees::with_orchard_tree_mut`] requires `&mut W` while the [`MigrationCrypto`]
/// methods take `&self`. The engine calls those methods sequentially (never nested), so the
/// `RefCell` never observes an overlapping borrow.
pub struct WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
{
    wallet: RefCell<&'a mut W>,
    account: <W as InputSource>::AccountId,
    usk: UnifiedSpendingKey,
    store: St,
}

impl<'a, W, St> WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource + WalletCommitmentTrees,
    <W as InputSource>::AccountId: Copy,
    <W as WalletCommitmentTrees>::Error: fmt::Debug,
    St: PoolMigrationRead,
{
    /// Wrap a wallet, an account, its spending key, and a store as a migration wallet.
    pub fn new(
        wallet: &'a mut W,
        account: <W as InputSource>::AccountId,
        usk: UnifiedSpendingKey,
        store: St,
    ) -> Self {
        Self {
            wallet: RefCell::new(wallet),
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
        let guard = self.wallet.borrow();
        let wallet: &W = &guard;
        let tip = wallet
            .chain_height()
            .map_err(Error::WalletRead)?
            .ok_or(Error::AnchorUnavailable)?;
        Ok(TargetHeight::from(u32::from(tip) + 1))
    }

    /// The account's spendable Orchard notes as `(note, tree position, value)`, sorted by tree
    /// position so the index is stable across calls (the engine maps a value index from
    /// `spendable_orchard_note_values` back to a note by the same order).
    fn spendable_orchard(&self) -> Result<Vec<SpendableNote>, AdapterError<W, St>> {
        let target = self.selection_target()?;
        let guard = self.wallet.borrow();
        let wallet: &W = &guard;
        let received = wallet
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

    /// Resolve the anchor and a witness for each requested tree position, all against the single
    /// checkpoint at `anchor_height`. The caller (the engine) names the tree state — a bucketed
    /// boundary height — so the witnesses are certain to match the anchor the transaction proves
    /// against; the checkpoint must exist in the note commitment tree ([`Error::AnchorUnavailable`]
    /// otherwise).
    fn witness(
        &self,
        anchor_height: BlockHeight,
        positions: &[Position],
    ) -> Result<(Anchor, Vec<MerklePath>), AdapterError<W, St>> {
        let mut guard = self.wallet.borrow_mut();
        let wallet: &mut W = &mut guard;
        wallet.with_orchard_tree_mut::<_, (Anchor, Vec<MerklePath>), AdapterError<W, St>>(|tree| {
            let anchor: Anchor = tree
                .root_at_checkpoint_id(&anchor_height)?
                .ok_or(Error::AnchorUnavailable)?
                .into();
            let mut paths = Vec::with_capacity(positions.len());
            for pos in positions {
                let path: MerklePath = tree
                    .witness_at_checkpoint_id_caching(*pos, &anchor_height)?
                    .ok_or_else(|| Error::Tree(String::from("checkpoint pruned")))?
                    .into();
                paths.push(path);
            }
            Ok((anchor, paths))
        })
    }
}

impl<'a, W, St> MigrationBackend for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource + WalletCommitmentTrees,
    <W as InputSource>::AccountId: Copy,
    <W as WalletCommitmentTrees>::Error: fmt::Debug,
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
        let guard = self.wallet.borrow();
        let wallet: &W = &guard;
        wallet
            .chain_height()
            .map_err(Error::WalletRead)?
            .ok_or(Error::AnchorUnavailable)
    }
}

impl<'a, W, St> MigrationCrypto for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource + WalletCommitmentTrees,
    <W as InputSource>::AccountId: Copy,
    <W as WalletCommitmentTrees>::Error: fmt::Debug,
    St: PoolMigrationRead,
{
    type Error = AdapterError<W, St>;

    fn orchard_fvk(&self) -> Result<FullViewingKey, Self::Error> {
        Ok(FullViewingKey::from(self.usk.orchard()))
    }

    fn orchard_anchor(&self, anchor_height: BlockHeight) -> Result<Anchor, Self::Error> {
        Ok(self.witness(anchor_height, &[])?.0)
    }

    fn ironwood_anchor(&self, anchor_height: BlockHeight) -> Result<Anchor, Self::Error> {
        let mut guard = self.wallet.borrow_mut();
        let wallet: &mut W = &mut guard;
        let root = wallet.with_ironwood_tree_mut::<_, _, AdapterError<W, St>>(|tree| {
            Ok(tree.root_at_checkpoint_id(&anchor_height)?)
        })?;
        match root {
            // The backend tracks an Ironwood tree, so the checkpoint at the anchor height must
            // exist in it.
            Some(root) => Ok(root.ok_or(Error::AnchorUnavailable)?.into()),
            // The backend tracks no Ironwood tree: as far as this wallet knows the pool holds no
            // notes, and the empty-tree root is the valid anchor for exactly that state.
            None => Ok(Anchor::empty_tree()),
        }
    }

    fn resolve_wallet_note(
        &self,
        index: usize,
        anchor_height: BlockHeight,
    ) -> Result<(OrchardNote, MerklePath), Self::Error> {
        let notes = self.spendable_orchard()?;
        let &(note, position, _) = notes.get(index).ok_or(Error::NoteNotFound(index))?;
        let (_, mut paths) = self.witness(anchor_height, &[position])?;
        Ok((note, paths.remove(0)))
    }

    fn resolve_funding_notes(
        &self,
        values: &[Zatoshis],
        anchor_height: BlockHeight,
    ) -> Result<Vec<(OrchardNote, MerklePath)>, Self::Error> {
        let notes = self.spendable_orchard()?;
        let mut used = vec![false; notes.len()];
        let mut chosen: Vec<(OrchardNote, Position)> = Vec::with_capacity(values.len());
        for (value_index, &value) in values.iter().enumerate() {
            // Each funding value is matched to a DISTINCT spendable note of exactly that value; notes
            // of equal value are interchangeable, so a greedy first-unused match is correct.
            let note_index = notes
                .iter()
                .enumerate()
                .position(|(i, (_, _, note_value))| !used[i] && *note_value == u64::from(value))
                .ok_or(Error::NoteNotFound(value_index))?;
            used[note_index] = true;
            chosen.push((notes[note_index].0, notes[note_index].1));
        }
        let positions: Vec<Position> = chosen.iter().map(|(_, pos)| *pos).collect();
        let (_, paths) = self.witness(anchor_height, &positions)?;
        Ok(chosen
            .into_iter()
            .map(|(note, _)| note)
            .zip(paths)
            .collect())
    }

    fn sign(&self, pczt: ::pczt::Pczt) -> Result<::pczt::Pczt, Self::Error> {
        let ask = SpendAuthorizingKey::from(self.usk.orchard());
        sign_pczt(pczt, &ask).map_err(|e| Error::Sign(format!("{e:?}")))
    }
}

impl<'a, W, St> PoolMigrationRead for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource + WalletCommitmentTrees,
    <W as InputSource>::AccountId: Copy,
    <W as WalletCommitmentTrees>::Error: fmt::Debug,
    St: PoolMigrationRead,
{
    type Error = AdapterError<W, St>;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        self.store.get_migration().map_err(Error::Store)
    }
}

impl<'a, W, St> PoolMigrationWrite for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource + WalletCommitmentTrees,
    <W as InputSource>::AccountId: Copy,
    <W as WalletCommitmentTrees>::Error: fmt::Debug,
    St: PoolMigrationWrite,
{
    fn put_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.store.put_migration(state).map_err(Error::Store)
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

#[cfg(all(test, feature = "wallet"))]
mod tests {
    use super::*;

    use rand_core::{CryptoRng, RngCore};
    use zcash_protocol::consensus::Parameters;

    use crate::engine::{commit_preparation, commit_transfers};

    /// Compile-time proof that `WalletMigration` over ANY `zcash_client_backend` wallet `W` and ANY
    /// migration store `St` satisfies every trait bound `commit_preparation` / `commit_transfers`
    /// require (backend + crypto + store, all sharing one error type). Naming the two generic
    /// functions instantiated at `WalletMigration<W, St>` forces the type checker to verify that
    /// instantiation's bounds hold; if the four trait impls ever stop lining up with the commit path,
    /// this stops compiling. It is never called and needs no wallet instance, so it pulls in no
    /// test-only wallet dependency (which would otherwise force `zcash_client_backend`'s Orchard
    /// feature on across the whole workspace's test build).
    #[allow(dead_code)]
    fn assert_commit_bounds<'a, P, W, St, R>()
    where
        P: Parameters + Clone,
        W: WalletRead + InputSource + WalletCommitmentTrees + 'a,
        <W as InputSource>::AccountId: Copy,
        <W as WalletCommitmentTrees>::Error: fmt::Debug,
        St: PoolMigrationWrite,
        R: RngCore + CryptoRng,
    {
        let _ = commit_preparation::<P, WalletMigration<'a, W, St>, R>;
        let _ = commit_transfers::<P, WalletMigration<'a, W, St>, R>;
    }
}
