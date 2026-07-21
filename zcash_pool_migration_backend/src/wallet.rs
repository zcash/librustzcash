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
//! No note commitment tree access appears here: every migration transaction is built and signed
//! with its anchor and witnesses deferred to proving time (ZIP 374), so the adapter never
//! resolves a witness — the consumer installs anchors and witnesses through the PCZT `Updater`
//! role when it proves each transaction, just before broadcast.
//!
//! [`commit_preparation`]: crate::engine::commit_preparation

use alloc::vec::Vec;
use core::fmt;

use ::orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use ::orchard::note::Note as OrchardNote;
use incrementalmerkletree::Position;

use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::{InputSource, WalletRead};
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
    /// Proving a transfer requires resolving the funding note's witness against the drawn anchor
    /// boundary checkpoint, which the wallet keeps alive through migration anchor-checkpoint
    /// retention (issue #2700). Until that retention lands, the wallet adapter cannot prove a
    /// transfer; the engine's [`prove_transfer`](crate::engine::prove_transfer) flow and the
    /// in-memory mock exercise the path in the meantime.
    ProvingUnsupported,
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
            Error::ProvingUnsupported => f.write_str(
                "proving a migration transfer is not yet supported by the wallet adapter; it \
                 requires migration anchor-checkpoint retention (issue #2700)",
            ),
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
            .select_unspent_notes(self.account, &[ShieldedPool::Orchard], target, &[], false)
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

impl<'a, W, St> MigrationProver for WalletMigration<'a, W, St>
where
    W: WalletRead + InputSource,
    <W as InputSource>::AccountId: Copy,
    St: PoolMigrationRead,
{
    type Error = AdapterError<W, St>;

    fn prove_transfer(
        &mut self,
        _pczt: ::pczt::Pczt,
        _anchor_boundary: zcash_protocol::consensus::BlockHeight,
    ) -> Result<::pczt::Pczt, Self::Error> {
        // Resolving the funding note's witness against the drawn boundary requires that boundary's
        // checkpoint to still exist in the wallet's Orchard commitment tree at proving time, via
        // `WalletCommitmentTrees::with_orchard_tree_mut` at the retained checkpoint. That retention
        // is migration anchor-checkpoint retention (issue #2700), which is not yet wired here; until
        // it lands, the wallet adapter cannot prove a transfer. The engine `prove_transfer` step and
        // the in-memory mock exercise the flow in the meantime.
        //
        // This stub stays on `WalletMigration` because the adapter borrows the wallet immutably
        // (`&W`); the real body needs `&mut W` plus proving keys, so it will move to a dedicated
        // mutable prover adapter when #2700 lands.
        Err(Error::ProvingUnsupported)
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
