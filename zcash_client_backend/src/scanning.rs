//! Tools for scanning a compact representation of the Zcash block chain.

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt::{self, Debug};
use std::hash::Hash;

use incrementalmerkletree::{Marking, Position, Retention};
use sapling::{SaplingIvk, note_encryption::SaplingDomain};
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};

use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_note_encryption::{BatchDomain, Domain, ShieldedOutput};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    ShieldedProtocol,
    consensus::{self, BlockHeight},
};
use zip32::Scope;

use crate::{
    data_api::{BlockMetadata, NullifierQuery, ScannedBlock, WalletRead},
    proto::compact_formats::CompactBlock,
    scan::DecryptedOutput,
    wallet::WalletOutput,
};

#[cfg(feature = "orchard")]
use orchard::note_encryption::OrchardDomain;

pub(crate) mod compact;

/// A key that can be used to perform trial decryption and nullifier
/// computation for a [`CompactSaplingOutput`] or [`CompactOrchardAction`].
///
/// The purpose of this trait is to enable [`scan_block`]
/// and related methods to be used with either incoming viewing keys
/// or full viewing keys, with the data returned from trial decryption
/// being dependent upon the type of key used. In the case that an
/// incoming viewing key is used, only the note and payment address
/// will be returned; in the case of a full viewing key, the
/// nullifier for the note can also be obtained.
///
/// [`CompactSaplingOutput`]: crate::proto::compact_formats::CompactSaplingOutput
/// [`CompactOrchardAction`]: crate::proto::compact_formats::CompactOrchardAction
/// [`scan_block`]: crate::scanning::scan_block
pub trait ScanningKeyOps<D: Domain, AccountId, Nf> {
    /// Prepare the key for use in batch trial decryption.
    fn prepare(&self) -> D::IncomingViewingKey;

    /// Returns the account identifier for this key. An account identifier corresponds
    /// to at most a single unified spending key's worth of spend authority, such that
    /// both received notes and change spendable by that spending authority will be
    /// interpreted as belonging to that account.
    fn account_id(&self) -> &AccountId;

    /// Returns the [`zip32::Scope`] for which this key was derived, if known.
    fn key_scope(&self) -> Option<Scope>;

    /// Produces the nullifier for the specified note and witness, if possible.
    ///
    /// IVK-based implementations of this trait cannot successfully derive
    /// nullifiers, in which this function will always return `None`.
    fn nf(&self, note: &D::Note, note_position: Position) -> Option<Nf>;
}

impl<D: Domain, AccountId, Nf, K: ScanningKeyOps<D, AccountId, Nf>> ScanningKeyOps<D, AccountId, Nf>
    for &K
{
    fn prepare(&self) -> D::IncomingViewingKey {
        (*self).prepare()
    }

    fn account_id(&self) -> &AccountId {
        (*self).account_id()
    }

    fn key_scope(&self) -> Option<Scope> {
        (*self).key_scope()
    }

    fn nf(&self, note: &D::Note, note_position: Position) -> Option<Nf> {
        (*self).nf(note, note_position)
    }
}

impl<D: Domain, AccountId, Nf> ScanningKeyOps<D, AccountId, Nf>
    for Box<dyn ScanningKeyOps<D, AccountId, Nf>>
{
    fn prepare(&self) -> D::IncomingViewingKey {
        self.as_ref().prepare()
    }

    fn account_id(&self) -> &AccountId {
        self.as_ref().account_id()
    }

    fn key_scope(&self) -> Option<Scope> {
        self.as_ref().key_scope()
    }

    fn nf(&self, note: &D::Note, note_position: Position) -> Option<Nf> {
        self.as_ref().nf(note, note_position)
    }
}

impl<D: Domain, AccountId: Send + Sync, Nf> ScanningKeyOps<D, AccountId, Nf>
    for Box<dyn ScanningKeyOps<D, AccountId, Nf> + Send + Sync>
{
    fn prepare(&self) -> D::IncomingViewingKey {
        self.as_ref().prepare()
    }

    fn account_id(&self) -> &AccountId {
        self.as_ref().account_id()
    }

    fn key_scope(&self) -> Option<Scope> {
        self.as_ref().key_scope()
    }

    fn nf(&self, note: &D::Note, note_position: Position) -> Option<Nf> {
        self.as_ref().nf(note, note_position)
    }
}

/// An incoming viewing key, paired with an optional nullifier key and key source metadata.
pub struct ScanningKey<Ivk, Nk, AccountId> {
    ivk: Ivk,
    nk: Option<Nk>,
    account_id: AccountId,
    key_scope: Option<Scope>,
}

impl<AccountId> ScanningKeyOps<SaplingDomain, AccountId, sapling::Nullifier>
    for ScanningKey<sapling::SaplingIvk, sapling::NullifierDerivingKey, AccountId>
{
    fn prepare(&self) -> sapling::note_encryption::PreparedIncomingViewingKey {
        sapling::note_encryption::PreparedIncomingViewingKey::new(&self.ivk)
    }

    fn nf(&self, note: &sapling::Note, position: Position) -> Option<sapling::Nullifier> {
        self.nk.as_ref().map(|key| note.nf(key, position.into()))
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn key_scope(&self) -> Option<Scope> {
        self.key_scope
    }
}

impl<AccountId> ScanningKeyOps<SaplingDomain, AccountId, sapling::Nullifier>
    for (AccountId, SaplingIvk)
{
    fn prepare(&self) -> sapling::note_encryption::PreparedIncomingViewingKey {
        sapling::note_encryption::PreparedIncomingViewingKey::new(&self.1)
    }

    fn nf(&self, _note: &sapling::Note, _position: Position) -> Option<sapling::Nullifier> {
        None
    }

    fn account_id(&self) -> &AccountId {
        &self.0
    }

    fn key_scope(&self) -> Option<Scope> {
        None
    }
}

#[cfg(feature = "orchard")]
impl<AccountId> ScanningKeyOps<OrchardDomain, AccountId, orchard::note::Nullifier>
    for ScanningKey<orchard::keys::IncomingViewingKey, orchard::keys::FullViewingKey, AccountId>
{
    fn prepare(&self) -> orchard::keys::PreparedIncomingViewingKey {
        orchard::keys::PreparedIncomingViewingKey::new(&self.ivk)
    }

    fn nf(
        &self,
        note: &orchard::note::Note,
        _position: Position,
    ) -> Option<orchard::note::Nullifier> {
        self.nk.as_ref().map(|key| note.nullifier(key))
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn key_scope(&self) -> Option<Scope> {
        self.key_scope
    }
}

/// A set of keys to be used in scanning for decryptable transaction outputs.
pub struct ScanningKeys<AccountId, IvkTag> {
    sapling: HashMap<
        IvkTag,
        Box<dyn ScanningKeyOps<SaplingDomain, AccountId, sapling::Nullifier> + Send + Sync>,
    >,
    #[cfg(feature = "orchard")]
    orchard: HashMap<
        IvkTag,
        Box<dyn ScanningKeyOps<OrchardDomain, AccountId, orchard::note::Nullifier> + Send + Sync>,
    >,
}

impl<AccountId, IvkTag> ScanningKeys<AccountId, IvkTag> {
    /// Constructs a new set of scanning keys.
    pub fn new(
        sapling: HashMap<
            IvkTag,
            Box<dyn ScanningKeyOps<SaplingDomain, AccountId, sapling::Nullifier> + Send + Sync>,
        >,
        #[cfg(feature = "orchard")] orchard: HashMap<
            IvkTag,
            Box<
                dyn ScanningKeyOps<OrchardDomain, AccountId, orchard::note::Nullifier>
                    + Send
                    + Sync,
            >,
        >,
    ) -> Self {
        Self {
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
        }
    }

    /// Constructs a new empty set of scanning keys.
    pub fn empty() -> Self {
        Self {
            sapling: HashMap::new(),
            #[cfg(feature = "orchard")]
            orchard: HashMap::new(),
        }
    }

    /// Returns the Sapling keys to be used for incoming note detection.
    pub fn sapling(
        &self,
    ) -> &HashMap<
        IvkTag,
        Box<dyn ScanningKeyOps<SaplingDomain, AccountId, sapling::Nullifier> + Send + Sync>,
    > {
        &self.sapling
    }

    /// Returns the Orchard keys to be used for incoming note detection.
    #[cfg(feature = "orchard")]
    pub fn orchard(
        &self,
    ) -> &HashMap<
        IvkTag,
        Box<dyn ScanningKeyOps<OrchardDomain, AccountId, orchard::note::Nullifier> + Send + Sync>,
    > {
        &self.orchard
    }
}

impl<AccountId: Copy + Eq + Hash + Send + Sync + 'static>
    ScanningKeys<AccountId, (AccountId, Scope)>
{
    /// Constructs a [`ScanningKeys`] from an iterator of [`UnifiedFullViewingKey`]s,
    /// along with the account identifiers corresponding to those UFVKs.
    pub fn from_account_ufvks(
        ufvks: impl IntoIterator<Item = (AccountId, UnifiedFullViewingKey)>,
    ) -> Self {
        #![allow(clippy::type_complexity)]

        let mut sapling: HashMap<
            (AccountId, Scope),
            Box<dyn ScanningKeyOps<SaplingDomain, AccountId, sapling::Nullifier> + Send + Sync>,
        > = HashMap::new();
        #[cfg(feature = "orchard")]
        let mut orchard: HashMap<
            (AccountId, Scope),
            Box<
                dyn ScanningKeyOps<OrchardDomain, AccountId, orchard::note::Nullifier>
                    + Send
                    + Sync,
            >,
        > = HashMap::new();

        for (account_id, ufvk) in ufvks {
            if let Some(dfvk) = ufvk.sapling() {
                for scope in [Scope::External, Scope::Internal] {
                    sapling.insert(
                        (account_id, scope),
                        Box::new(ScanningKey {
                            ivk: dfvk.to_ivk(scope),
                            nk: Some(dfvk.to_nk(scope)),
                            account_id,
                            key_scope: Some(scope),
                        }),
                    );
                }
            }

            #[cfg(feature = "orchard")]
            if let Some(fvk) = ufvk.orchard() {
                for scope in [Scope::External, Scope::Internal] {
                    orchard.insert(
                        (account_id, scope),
                        Box::new(ScanningKey {
                            ivk: fvk.to_ivk(scope),
                            nk: Some(fvk.clone()),
                            account_id,
                            key_scope: Some(scope),
                        }),
                    );
                }
            }
        }

        Self {
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
        }
    }
}

/// The set of nullifiers being tracked by a wallet.
pub struct Nullifiers<AccountId> {
    sapling: Vec<(AccountId, sapling::Nullifier)>,
    #[cfg(feature = "orchard")]
    orchard: Vec<(AccountId, orchard::note::Nullifier)>,
}

impl<AccountId> Nullifiers<AccountId> {
    /// Constructs a new empty set of nullifiers
    pub fn empty() -> Self {
        Self {
            sapling: vec![],
            #[cfg(feature = "orchard")]
            orchard: vec![],
        }
    }

    /// Fetches the nullifiers for the unspent notes being tracked by the given wallet.
    pub(crate) fn unspent<DbT: WalletRead<AccountId = AccountId>>(
        db_data: &DbT,
    ) -> Result<Self, DbT::Error> {
        Ok(Self::new(
            db_data.get_sapling_nullifiers(NullifierQuery::Unspent)?,
            #[cfg(feature = "orchard")]
            db_data.get_orchard_nullifiers(NullifierQuery::Unspent)?,
        ))
    }

    /// Construct a nullifier set from its constituent parts.
    pub(crate) fn new(
        sapling: Vec<(AccountId, sapling::Nullifier)>,
        #[cfg(feature = "orchard")] orchard: Vec<(AccountId, orchard::note::Nullifier)>,
    ) -> Self {
        Self {
            sapling,
            #[cfg(feature = "orchard")]
            orchard,
        }
    }

    /// Returns the Sapling nullifiers for notes that the wallet is tracking.
    pub fn sapling(&self) -> &[(AccountId, sapling::Nullifier)] {
        self.sapling.as_ref()
    }

    /// Returns the Orchard nullifiers for notes that the wallet is tracking.
    #[cfg(feature = "orchard")]
    pub fn orchard(&self) -> &[(AccountId, orchard::note::Nullifier)] {
        self.orchard.as_ref()
    }

    /// Discards Sapling nullifiers from the tracked nullifier set, retaining only those that
    /// satisfy the given predicate.
    pub(crate) fn retain_sapling(&mut self, f: impl Fn(&(AccountId, sapling::Nullifier)) -> bool) {
        self.sapling.retain(f);
    }

    /// Adds the given nullifiers to the tracked nullifier set.
    pub(crate) fn extend_sapling(
        &mut self,
        nfs: impl IntoIterator<Item = (AccountId, sapling::Nullifier)>,
    ) {
        self.sapling.extend(nfs);
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn retain_orchard(
        &mut self,
        f: impl Fn(&(AccountId, orchard::note::Nullifier)) -> bool,
    ) {
        self.orchard.retain(f);
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn extend_orchard(
        &mut self,
        nfs: impl IntoIterator<Item = (AccountId, orchard::note::Nullifier)>,
    ) {
        self.orchard.extend(nfs);
    }
}

impl<AccountId: Copy> Nullifiers<AccountId> {
    /// Updates this set of unspent nullifiers based on the results of scanning a block.
    ///
    /// This is intended for use when scanning multiple sequential blocks in memory, prior
    /// to updating the wallet's state (after which [`Self::unspent`] would produce the
    /// same set).
    ///
    /// - Notes spent by the wallet in this block will have their nullifiers removed from
    ///   the set, so we don't bother .
    /// - Notes received by the wallet in this block will have their nullifiers added to
    ///   the set, enabling spend detection in subsequent blocks.
    pub(crate) fn update_with(&mut self, scanned_block: &ScannedBlock<AccountId>) {
        let sapling_spent_nf: Vec<&sapling::Nullifier> = scanned_block
            .transactions()
            .iter()
            .flat_map(|tx| tx.sapling_spends().iter().map(|spend| spend.nf()))
            .collect();

        self.retain_sapling(|(_, nf)| !sapling_spent_nf.contains(&nf));
        self.extend_sapling(scanned_block.transactions().iter().flat_map(|tx| {
            tx.sapling_outputs()
                .iter()
                .flat_map(|out| out.nf().into_iter().map(|nf| (*out.account_id(), *nf)))
        }));

        #[cfg(feature = "orchard")]
        {
            let orchard_spent_nf: Vec<&orchard::note::Nullifier> = scanned_block
                .transactions()
                .iter()
                .flat_map(|tx| tx.orchard_spends().iter().map(|spend| spend.nf()))
                .collect();

            self.retain_orchard(|(_, nf)| !orchard_spent_nf.contains(&nf));
            self.extend_orchard(scanned_block.transactions().iter().flat_map(|tx| {
                tx.orchard_outputs()
                    .iter()
                    .flat_map(|out| out.nf().into_iter().map(|nf| (*out.account_id(), *nf)))
            }));
        }
    }
}

/// Errors that may occur in chain scanning
#[derive(Clone, Debug)]
pub enum ScanError {
    /// The encoding of a compact Sapling output or compact Orchard action was invalid.
    EncodingInvalid {
        at_height: BlockHeight,
        txid: TxId,
        pool_type: ShieldedProtocol,
        index: usize,
    },

    /// The hash of the parent block given by a proposed new chain tip does not match the hash of
    /// the current chain tip.
    PrevHashMismatch { at_height: BlockHeight },

    /// The block height field of the proposed new block is not equal to the height of the previous
    /// block + 1.
    BlockHeightDiscontinuity {
        prev_height: BlockHeight,
        new_height: BlockHeight,
    },

    /// The note commitment tree size for the given protocol at the proposed new block is not equal
    /// to the size at the previous block plus the count of this block's outputs.
    TreeSizeMismatch {
        protocol: ShieldedProtocol,
        at_height: BlockHeight,
        given: u32,
        computed: u32,
    },

    /// The size of the note commitment tree for the given protocol was not provided as part of a
    /// [`CompactBlock`] being scanned, making it impossible to construct the nullifier for a
    /// detected note.
    TreeSizeUnknown {
        protocol: ShieldedProtocol,
        at_height: BlockHeight,
    },

    /// We were provided chain metadata for a block containing note commitment tree metadata
    /// that is invalidated by the data in the block itself. This may be caused by the presence
    /// of default values in the chain metadata.
    TreeSizeInvalid {
        protocol: ShieldedProtocol,
        at_height: BlockHeight,
    },
}

impl ScanError {
    /// Returns whether this error is the result of a failed continuity check
    pub fn is_continuity_error(&self) -> bool {
        use ScanError::*;
        match self {
            EncodingInvalid { .. } => false,
            PrevHashMismatch { .. } => true,
            BlockHeightDiscontinuity { .. } => true,
            TreeSizeMismatch { .. } => true,
            TreeSizeUnknown { .. } => false,
            TreeSizeInvalid { .. } => false,
        }
    }

    /// Returns the block height at which the scan error occurred
    pub fn at_height(&self) -> BlockHeight {
        use ScanError::*;
        match self {
            EncodingInvalid { at_height, .. } => *at_height,
            PrevHashMismatch { at_height } => *at_height,
            BlockHeightDiscontinuity { new_height, .. } => *new_height,
            TreeSizeMismatch { at_height, .. } => *at_height,
            TreeSizeUnknown { at_height, .. } => *at_height,
            TreeSizeInvalid { at_height, .. } => *at_height,
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ScanError::*;
        match &self {
            EncodingInvalid {
                txid,
                pool_type,
                index,
                ..
            } => write!(
                f,
                "{pool_type:?} output {index} of transaction {txid} was improperly encoded."
            ),
            PrevHashMismatch { at_height } => write!(
                f,
                "The parent hash of proposed block does not correspond to the block hash at height {at_height}."
            ),
            BlockHeightDiscontinuity {
                prev_height,
                new_height,
            } => {
                write!(
                    f,
                    "Block height discontinuity at height {new_height}; previous height was: {prev_height}"
                )
            }
            TreeSizeMismatch {
                protocol,
                at_height,
                given,
                computed,
            } => {
                write!(
                    f,
                    "The {protocol:?} note commitment tree size provided by a compact block did not match the expected size at height {at_height}; given {given}, expected {computed}"
                )
            }
            TreeSizeUnknown {
                protocol,
                at_height,
            } => {
                write!(
                    f,
                    "Unable to determine {protocol:?} note commitment tree size at height {at_height}"
                )
            }
            TreeSizeInvalid {
                protocol,
                at_height,
            } => {
                write!(
                    f,
                    "Received invalid (potentially default) {protocol:?} note commitment tree size metadata at height {at_height}"
                )
            }
        }
    }
}

/// Scans a [`CompactBlock`] with a set of [`ScanningKeys`].
///
/// Returns a vector of [`WalletTx`]s decryptable by any of the given keys. If an output is
/// decrypted by a full viewing key, the nullifiers of that output will also be computed.
///
/// [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
/// [`WalletTx`]: crate::wallet::WalletTx
pub fn scan_block<P, AccountId, IvkTag>(
    params: &P,
    block: CompactBlock,
    scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    nullifiers: &Nullifiers<AccountId>,
    prior_block_metadata: Option<&BlockMetadata>,
) -> Result<ScannedBlock<AccountId>, ScanError>
where
    P: consensus::Parameters + Send + 'static,
    AccountId: Default + Eq + Hash + ConditionallySelectable + Send + Sync + 'static,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
{
    compact::scan_block_with_runners::<_, _, _, (), ()>(
        params,
        block,
        scanning_keys,
        nullifiers,
        prior_block_metadata,
        None,
    )
}

/// Tracks the scanner's position within the note commitment trees, in order to calculate
/// received note positions.
struct PositionTracker {
    sapling_tree_position: u32,
    sapling_final_tree_size: u32,
    #[cfg(feature = "orchard")]
    orchard_tree_position: u32,
    #[cfg(feature = "orchard")]
    orchard_final_tree_size: u32,
}

impl PositionTracker {
    fn sapling_note_position(&self, output_idx: usize) -> Position {
        Position::from(u64::from(
            self.sapling_tree_position + u32::try_from(output_idx).unwrap(),
        ))
    }

    #[cfg(feature = "orchard")]
    fn orchard_note_position(&self, output_idx: usize) -> Position {
        Position::from(u64::from(
            self.orchard_tree_position + u32::try_from(output_idx).unwrap(),
        ))
    }
}

/// Check for spent notes. The comparison against known-unspent nullifiers is done
/// in constant time.
fn find_spent<
    AccountId: ConditionallySelectable + Default,
    Spend,
    Nf: ConstantTimeEq + Copy,
    WS,
>(
    spends: &[Spend],
    nullifiers: &[(AccountId, Nf)],
    extract_nf: impl Fn(&Spend) -> Nf,
    construct_wallet_spend: impl Fn(usize, Nf, AccountId) -> WS,
) -> (Vec<WS>, Vec<Nf>) {
    // TODO: this is O(|nullifiers| * |notes|); does using constant-time operations here really
    // make sense?
    let mut found_spent = vec![];
    let mut unlinked_nullifiers = Vec::with_capacity(spends.len());
    for (index, spend) in spends.iter().enumerate() {
        let spend_nf = extract_nf(spend);

        // Find whether any tracked nullifier that matches this spend, and produce a
        // WalletShieldedSpend in constant time.
        let ct_spend = nullifiers
            .iter()
            .map(|&(account, nf)| CtOption::new(account, nf.ct_eq(&spend_nf)))
            .fold(
                CtOption::new(AccountId::default(), 0.into()),
                |first, next| CtOption::conditional_select(&next, &first, first.is_some()),
            )
            .map(|account| construct_wallet_spend(index, spend_nf, account));

        if let Some(spend) = ct_spend.into() {
            found_spent.push(spend);
        } else {
            // This nullifier didn't match any we are currently tracking; save it in
            // case it matches an earlier block range we haven't scanned yet.
            unlinked_nullifiers.push(spend_nf);
        }
    }

    (found_spent, unlinked_nullifiers)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn find_received<
    AccountId: Copy + Eq + Hash,
    D: BatchDomain,
    M,
    Nf,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
    SK: ScanningKeyOps<D, AccountId, Nf>,
    Output: ShieldedOutput<D, CIPHERTEXT_SIZE>,
    NoteCommitment,
    const CIPHERTEXT_SIZE: usize,
>(
    block_height: BlockHeight,
    last_commitments_in_block: bool,
    txid: TxId,
    note_position: impl Fn(usize) -> Position,
    keys: &HashMap<IvkTag, SK>,
    spent_from_accounts: &HashSet<AccountId>,
    decoded: &[(D, Output)],
    batch_results: Option<impl FnOnce(TxId) -> HashMap<usize, DecryptedOutput<IvkTag, D, M>>>,
    decrypt_inline: impl FnOnce(
        &[D::IncomingViewingKey],
        &[(D, Output)],
    ) -> Vec<Option<((D::Note, D::Recipient, M), usize)>>,
    extract_note_commitment: impl Fn(&Output) -> NoteCommitment,
) -> (
    Vec<WalletOutput<D::Note, Nf, AccountId>>,
    Vec<(NoteCommitment, Retention<BlockHeight>)>,
) {
    // Check for incoming notes while incrementing tree and witnesses
    let (decrypted_opts, decrypted_len) = if let Some(collect_results) = batch_results {
        let mut decrypted = collect_results(txid);
        let decrypted_len = decrypted.len();
        (
            (0..decoded.len())
                .map(|i| {
                    decrypted
                        .remove(&i)
                        .map(|d_out| (d_out.ivk_tag, d_out.note))
                })
                .collect::<Vec<_>>(),
            decrypted_len,
        )
    } else {
        let mut ivks = Vec::with_capacity(keys.len());
        let mut ivk_lookup = Vec::with_capacity(keys.len());
        for (key_id, key) in keys.iter() {
            ivks.push(key.prepare());
            ivk_lookup.push(key_id);
        }

        let mut decrypted_len = 0;
        (
            decrypt_inline(&ivks, decoded)
                .into_iter()
                .map(|v| {
                    v.map(|((note, _, _), ivk_idx)| {
                        decrypted_len += 1;
                        (*ivk_lookup[ivk_idx], note)
                    })
                })
                .collect::<Vec<_>>(),
            decrypted_len,
        )
    };

    let mut shielded_outputs = Vec::with_capacity(decrypted_len);
    let mut note_commitments = Vec::with_capacity(decoded.len());
    for (output_idx, ((_, output), decrypted_note)) in
        decoded.iter().zip(decrypted_opts).enumerate()
    {
        // Collect block note commitments
        let node = extract_note_commitment(output);
        // If the commitment is the last in the block, ensure that is retained as a checkpoint
        let is_checkpoint = output_idx + 1 == decoded.len() && last_commitments_in_block;
        let retention = match (decrypted_note.is_some(), is_checkpoint) {
            (is_marked, true) => Retention::Checkpoint {
                id: block_height,
                marking: if is_marked {
                    Marking::Marked
                } else {
                    Marking::None
                },
            },
            (true, false) => Retention::Marked,
            (false, false) => Retention::Ephemeral,
        };

        if let Some((key_id, note)) = decrypted_note {
            let key = keys
                .get(&key_id)
                .expect("Key is available for decrypted output");

            // A note is marked as "change" if the account that received it
            // also spent notes in the same transaction. This will catch,
            // for instance:
            // - Change created by spending fractions of notes.
            // - Notes created by consolidation transactions.
            // - Notes sent from one account to itself.
            let is_change = spent_from_accounts.contains(key.account_id());
            let note_commitment_tree_position = note_position(output_idx);
            let nf = key.nf(&note, note_commitment_tree_position);

            shielded_outputs.push(WalletOutput::from_parts(
                output_idx,
                output.ephemeral_key(),
                note,
                is_change,
                note_commitment_tree_position,
                nf,
                *key.account_id(),
                key.key_scope(),
            ));
        }

        note_commitments.push((node, retention))
    }

    (shielded_outputs, note_commitments)
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use group::{
        GroupEncoding,
        ff::{Field, PrimeField},
    };
    use rand_core::{OsRng, RngCore};
    use sapling::{
        Nullifier,
        constants::SPENDING_KEY_GENERATOR,
        note_encryption::{SaplingDomain, sapling_note_encryption},
        util::generate_random_rseed,
        value::NoteValue,
        zip32::DiversifiableFullViewingKey,
    };
    use zcash_note_encryption::{COMPACT_NOTE_SIZE, Domain};
    use zcash_primitives::{
        block::BlockHash, transaction::components::sapling::zip212_enforcement,
    };
    use zcash_protocol::{
        consensus::{BlockHeight, Network},
        memo::MemoBytes,
        value::Zatoshis,
    };

    use crate::proto::compact_formats::{
        self as compact, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
    };

    fn random_compact_tx(mut rng: impl RngCore) -> CompactTx {
        let fake_nf = {
            let mut nf = vec![0; 32];
            rng.fill_bytes(&mut nf);
            nf
        };
        let fake_cmu = {
            let fake_cmu = bls12_381::Scalar::random(&mut rng);
            fake_cmu.to_repr().to_vec()
        };
        let fake_epk = {
            let mut buffer = [0; 64];
            rng.fill_bytes(&mut buffer);
            let fake_esk = jubjub::Fr::from_bytes_wide(&buffer);
            let fake_epk = SPENDING_KEY_GENERATOR * fake_esk;
            fake_epk.to_bytes().to_vec()
        };
        let cspend = CompactSaplingSpend { nf: fake_nf };
        let cout = CompactSaplingOutput {
            cmu: fake_cmu,
            ephemeral_key: fake_epk,
            ciphertext: vec![0; COMPACT_NOTE_SIZE],
        };
        let mut ctx = CompactTx::default();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.txid = txid;
        ctx.spends.push(cspend);
        ctx.outputs.push(cout);
        ctx
    }

    /// Create a fake CompactBlock at the given height, with a transaction containing a
    /// single spend of the given nullifier and a single output paying the given address.
    /// Returns the CompactBlock.
    ///
    /// Set `initial_tree_sizes` to `None` to simulate a `CompactBlock` retrieved
    /// from a `lightwalletd` that is not currently tracking note commitment tree sizes.
    pub fn fake_compact_block(
        height: BlockHeight,
        prev_hash: BlockHash,
        nf: Nullifier,
        dfvk: &DiversifiableFullViewingKey,
        value: Zatoshis,
        tx_after: bool,
        initial_tree_sizes: Option<(u32, u32)>,
    ) -> CompactBlock {
        let zip212_enforcement = zip212_enforcement(&Network::TestNetwork, height);
        let to = dfvk.default_address().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let rseed = generate_random_rseed(zip212_enforcement, &mut rng);
        let note = sapling::Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
        let encryptor = sapling_note_encryption(
            Some(dfvk.fvk().ovk),
            note.clone(),
            MemoBytes::empty().into_bytes(),
            &mut rng,
        );
        let cmu = note.cmu().to_bytes().to_vec();
        let ephemeral_key = SaplingDomain::epk_bytes(encryptor.epk()).0.to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let mut cb = CompactBlock {
            hash: {
                let mut hash = vec![0; 32];
                rng.fill_bytes(&mut hash);
                hash
            },
            prev_hash: prev_hash.0.to_vec(),
            height: height.into(),
            ..Default::default()
        };

        // Add a random Sapling tx before ours
        {
            let mut tx = random_compact_tx(&mut rng);
            tx.index = cb.vtx.len() as u64;
            cb.vtx.push(tx);
        }

        let cspend = CompactSaplingSpend { nf: nf.0.to_vec() };
        let cout = CompactSaplingOutput {
            cmu,
            ephemeral_key,
            ciphertext: enc_ciphertext[..52].to_vec(),
        };
        let mut ctx = CompactTx::default();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.txid = txid;
        ctx.spends.push(cspend);
        ctx.outputs.push(cout);
        ctx.index = cb.vtx.len() as u64;
        cb.vtx.push(ctx);

        // Optionally add another random Sapling tx after ours
        if tx_after {
            let mut tx = random_compact_tx(&mut rng);
            tx.index = cb.vtx.len() as u64;
            cb.vtx.push(tx);
        }

        cb.chain_metadata =
            initial_tree_sizes.map(|(initial_sapling_tree_size, initial_orchard_tree_size)| {
                compact::ChainMetadata {
                    sapling_commitment_tree_size: initial_sapling_tree_size
                        + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
                    orchard_commitment_tree_size: initial_orchard_tree_size
                        + cb.vtx.iter().map(|tx| tx.actions.len() as u32).sum::<u32>(),
                }
            });

        cb
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread::spawn;

    use super::ScanningKeys;

    #[test]
    fn arc_scanning_keys() {
        let keys = Arc::new(ScanningKeys::<(), ()>::empty());
        spawn(move || {
            let _ = keys.sapling().get(&());
        });
    }
}
