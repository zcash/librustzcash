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
//! wallet as `&mut W` to resolve the source anchor and each spend's witness from the wallet's
//! Orchard commitment tree and installs them through the PCZT `Updater` role before proving the
//! transaction (a transfer's Orchard + Ironwood bundles, or a preparation's Orchard bundle), just
//! before broadcast.
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

/// Why proving a migration transaction through the wallet-backed prover failed. `TE` is the
/// wallet's commitment-tree error type ([`WalletCommitmentTrees::Error`]); `NE` is its note-source
/// error type ([`InputSource::Error`]).
#[derive(Debug)]
pub enum WalletProveError<TE, NE> {
    /// The PCZT has no real Orchard spend whose witness is still deferred. A migration transfer
    /// spends one funding note and a preparation transaction one or more, so the Orchard bundle
    /// carries at least one action with an absent witness (the fabricated dummy spends keep their
    /// own); none means the PCZT is not a deferred-anchor migration transaction awaiting proof.
    NoRealSpend,
    /// No spendable Orchard note in the wallet matches a spend's revealed nullifier, so its tree
    /// position is unknown: the note the transaction spends is not among the account's unspent
    /// notes (it was never scanned, or has already been spent).
    UnknownSpentNote([u8; 32]),
    /// Enumerating the account's spendable Orchard notes (to locate each spend by nullifier) failed.
    Notes(NE),
    /// The Orchard commitment tree has no root at the anchor checkpoint (the checkpoint was never
    /// created, or was pruned before proving; see issue #2700).
    AnchorNotFound(BlockHeight),
    /// A spent note has no witness at the anchor checkpoint (the checkpoint was pruned, or the
    /// note's position is not marked in the tree).
    WitnessNotFound(BlockHeight),
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
}

impl<TE, NE> From<ShardTreeError<TE>> for WalletProveError<TE, NE> {
    fn from(e: ShardTreeError<TE>) -> Self {
        WalletProveError::Tree(e)
    }
}

impl<TE: fmt::Debug, NE: fmt::Debug> fmt::Display for WalletProveError<TE, NE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletProveError::NoRealSpend => {
                f.write_str("the PCZT has no deferred-witness Orchard spend to prove")
            }
            WalletProveError::UnknownSpentNote(nf) => {
                write!(
                    f,
                    "no spendable Orchard note matches spend nullifier {nf:?}"
                )
            }
            WalletProveError::Notes(e) => {
                write!(f, "enumerating spendable Orchard notes failed: {e:?}")
            }
            WalletProveError::AnchorNotFound(h) => write!(
                f,
                "the Orchard tree has no root at the anchor checkpoint {}",
                u32::from(*h)
            ),
            WalletProveError::WitnessNotFound(h) => write!(
                f,
                "a spent note has no witness at the anchor checkpoint {}",
                u32::from(*h)
            ),
            WalletProveError::Tree(e) => write!(f, "commitment-tree query failed: {e:?}"),
            WalletProveError::Anchor(e) => write!(f, "installing an anchor failed: {e:?}"),
            WalletProveError::Witness(e) => write!(f, "installing a spend witness failed: {e:?}"),
            WalletProveError::Prove(msg) => write!(f, "creating a bundle proof failed: {msg}"),
        }
    }
}

impl<TE: fmt::Debug, NE: fmt::Debug> core::error::Error for WalletProveError<TE, NE> {}

/// The wallet-backed prover's error for a wallet `W`: a [`WalletProveError`] over the wallet's
/// commitment-tree and note-source error types.
type ProverError<W> =
    WalletProveError<<W as WalletCommitmentTrees>::Error, <W as InputSource>::Error>;

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
    W: WalletCommitmentTrees + InputSource,
    <W as InputSource>::AccountId: Copy,
{
    /// Prove one migration transaction's Orchard bundle (and its Ironwood bundle, when it has one)
    /// against `anchor`: install the source anchor and every deferred spend's witness through the
    /// PCZT `Updater` role, then run the provers. Shared by
    /// [`prove_transfer`](MigrationProver::prove_transfer) (a transfer: one Orchard spend plus an
    /// Ironwood output) and [`prove_preparation`](MigrationProver::prove_preparation) (a preparation:
    /// one or more Orchard spends, no Ironwood).
    fn prove_orchard(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor: BlockHeight,
    ) -> Result<::pczt::Pczt, ProverError<W>> {
        // Every Orchard action whose witness is still deferred is a real spend to witness; the padded
        // dummy spends keep their (arbitrary) witnesses from build time (ZIP 374).
        let real_spends: Vec<(usize, [u8; 32])> = pczt
            .orchard()
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| action.spend().witness().is_none())
            .map(|(index, action)| (index, *action.spend().nullifier()))
            .collect();
        if real_spends.is_empty() {
            return Err(WalletProveError::NoRealSpend);
        }

        // Locate each spend in the wallet's note store: map every unspent Orchard note's nullifier
        // (recomputed under the account FVK) to its commitment-tree position, then look up each spend.
        let target = TargetHeight::from(u32::from(anchor) + 1);
        let received = self
            .wallet
            .select_unspent_notes(self.account, &[ShieldedPool::Orchard], target, &[])
            .map_err(WalletProveError::Notes)?;
        let positions: BTreeMap<[u8; 32], Position> = received
            .orchard()
            .iter()
            .map(|rn| {
                (
                    rn.note().nullifier(&self.fvk).to_bytes(),
                    rn.note_commitment_tree_position(),
                )
            })
            .collect();
        let spend_positions: Vec<(usize, Position)> = real_spends
            .iter()
            .map(|(index, nf)| {
                positions
                    .get(nf)
                    .map(|pos| (*index, *pos))
                    .ok_or(WalletProveError::UnknownSpentNote(*nf))
            })
            .collect::<Result<_, _>>()?;

        // A transfer carries an Ironwood output bundle; a preparation transaction is Orchard-only.
        let has_ironwood = !pczt.ironwood().actions().is_empty();

        // Resolve the source anchor (the tree root at the checkpoint) and each spend's Merkle witness
        // against it, mirroring `create_proposed_transactions`.
        let (anchor_root, witnesses): (Anchor, Vec<(usize, MerklePath)>) =
            self.wallet
                .with_orchard_tree_mut::<_, _, ProverError<W>>(|tree| {
                    let root: Anchor = tree
                        .root_at_checkpoint_id(&anchor)?
                        .ok_or(WalletProveError::AnchorNotFound(anchor))?
                        .into();
                    let mut witnesses = Vec::with_capacity(spend_positions.len());
                    for (index, position) in &spend_positions {
                        let path: MerklePath = tree
                            .witness_at_checkpoint_id_caching(*position, &anchor)?
                            .ok_or(WalletProveError::WitnessNotFound(anchor))?
                            .into();
                        witnesses.push((*index, path));
                    }
                    Ok((root, witnesses))
                })?;

        // Install the deferred data through the Updater role: the Orchard source anchor and every
        // spend's witness, plus (for a transfer) the Ironwood destination anchor (the output side
        // anchors to the empty tree; it has no spend to witness).
        let mut updater = Updater::new(pczt)
            .set_orchard_anchor(anchor_root)
            .map_err(WalletProveError::Anchor)?
            .set_orchard_spend_witnesses(witnesses)
            .map_err(WalletProveError::Witness)?;
        if has_ironwood {
            updater = updater
                .set_ironwood_anchor(Anchor::empty_tree())
                .map_err(WalletProveError::Anchor)?;
        }
        let updated = updater.finish();

        // Prove the Orchard bundle, and the Ironwood bundle too when present, with the single
        // post-NU6.3 Orchard proving key.
        let pk = post_nu6_3_orchard_proving_key();
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
}

impl<'a, W> MigrationProver for WalletMigrationProver<'a, W>
where
    W: WalletCommitmentTrees + InputSource,
    <W as InputSource>::AccountId: Copy,
{
    type Error = ProverError<W>;

    fn prove_transfer(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor_boundary: BlockHeight,
    ) -> Result<::pczt::Pczt, Self::Error> {
        self.prove_orchard(pczt, anchor_boundary)
    }

    fn prove_preparation(
        &mut self,
        pczt: ::pczt::Pczt,
        anchor: BlockHeight,
    ) -> Result<::pczt::Pczt, Self::Error> {
        self.prove_orchard(pczt, anchor)
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
