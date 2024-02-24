//! Tools for scanning a compact representation of the Zcash block chain.

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt::{self, Debug};
use std::hash::Hash;

use incrementalmerkletree::{Position, Retention};
use sapling::{
    note_encryption::{CompactOutputDescription, SaplingDomain},
    SaplingIvk,
};
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_note_encryption::{batch, BatchDomain, Domain, ShieldedOutput};
use zcash_primitives::{
    consensus::{self, BlockHeight, NetworkUpgrade},
    transaction::TxId,
};
use zip32::Scope;

use crate::data_api::{BlockMetadata, ScannedBlock, ScannedBundles};
use crate::{
    proto::compact_formats::CompactBlock,
    scan::{Batch, BatchRunner, CompactDecryptor, DecryptedOutput, Tasks},
    wallet::{WalletSaplingOutput, WalletSaplingSpend, WalletTx},
    ShieldedProtocol,
};

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

/// A set of scanning keys, along with the vector of `(Account, Nullifier)` pairs that
/// notes the wallet is tracking.
pub struct ScanningKeys<AccountId, IvkTag> {
    sapling_keys:
        HashMap<IvkTag, Box<dyn ScanningKeyOps<SaplingDomain, AccountId, sapling::Nullifier>>>,
    sapling_nullifiers: Vec<(AccountId, sapling::Nullifier)>,
}

impl<AccountId, IvkTag> ScanningKeys<AccountId, IvkTag> {
    /// Constructs a new empty set of scanning keys.
    pub fn empty() -> Self {
        Self {
            sapling_keys: HashMap::new(),
            sapling_nullifiers: vec![],
        }
    }

    /// Returns the Sapling keys to be used for incoming note detection.
    pub fn sapling_keys(
        &self,
    ) -> &HashMap<IvkTag, Box<dyn ScanningKeyOps<SaplingDomain, AccountId, sapling::Nullifier>>>
    {
        &self.sapling_keys
    }

    /// Returns the Sapling nullifiers for notes that the wallet is tracking.
    pub fn sapling_nullifiers(&self) -> &[(AccountId, sapling::Nullifier)] {
        self.sapling_nullifiers.as_ref()
    }
}

impl<AccountId: Copy + Eq + Hash + 'static> ScanningKeys<AccountId, (AccountId, Scope)> {
    /// Constructs a [`ScanningKeys`] from an iterator of [`UnifiedFullViewingKey`]s,
    /// along with the account identifiers corresponding to those UFVKs.
    pub fn from_account_ufvks(
        ufvks: impl IntoIterator<Item = (AccountId, UnifiedFullViewingKey)>,
    ) -> Self {
        let sapling_keys = ufvks
            .into_iter()
            .flat_map(|(account_id, ufvk)| {
                if let Some(dfvk) = ufvk.sapling() {
                    vec![
                        ScanningKey {
                            ivk: dfvk.to_ivk(Scope::External),
                            nk: Some(dfvk.to_nk(Scope::External)),
                            account_id,
                            key_scope: Some(Scope::External),
                        },
                        ScanningKey {
                            ivk: dfvk.to_ivk(Scope::Internal),
                            nk: Some(dfvk.to_nk(Scope::Internal)),
                            account_id,
                            key_scope: Some(Scope::Internal),
                        },
                    ]
                } else {
                    vec![]
                }
                .into_iter()
            })
            .map(|k| {
                let key_id = (k.account_id, k.key_scope.unwrap());
                let v: Box<dyn ScanningKeyOps<SaplingDomain, AccountId, sapling::Nullifier>> =
                    Box::new(k);
                (key_id, v)
            })
            .collect();

        Self {
            sapling_keys,
            sapling_nullifiers: vec![],
        }
    }

    /// Discards Sapling nullifiers from the tracked nullifier set, retaining only those that
    /// satisfy the given predicate.
    pub(crate) fn retain_sapling_nullifiers(
        &mut self,
        f: impl Fn(&(AccountId, sapling::Nullifier)) -> bool,
    ) {
        self.sapling_nullifiers.retain(f);
    }

    /// Adds the given nullifiers to the tracked nullifier set.
    pub(crate) fn extend_sapling_nullifiers(
        &mut self,
        nfs: impl IntoIterator<Item = (AccountId, sapling::Nullifier)>,
    ) {
        self.sapling_nullifiers.extend(nfs);
    }
}

/// Errors that may occur in chain scanning
#[derive(Clone, Debug)]
pub enum ScanError {
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
            PrevHashMismatch { at_height } => write!(
                f,
                "The parent hash of proposed block does not correspond to the block hash at height {}.",
                at_height
            ),
            BlockHeightDiscontinuity { prev_height, new_height } => {
                write!(f, "Block height discontinuity at height {}; previous height was: {}", new_height, prev_height)
            }
            TreeSizeMismatch { protocol, at_height, given, computed } => {
                write!(f, "The {:?} note commitment tree size provided by a compact block did not match the expected size at height {}; given {}, expected {}", protocol, at_height, given, computed)
            }
            TreeSizeUnknown { protocol, at_height } => {
                write!(f, "Unable to determine {:?} note commitment tree size at height {}", protocol, at_height)
            }
            TreeSizeInvalid { protocol, at_height } => {
                write!(f, "Received invalid (potentially default) {:?} note commitment tree size metadata at height {}", protocol, at_height)
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
    prior_block_metadata: Option<&BlockMetadata>,
) -> Result<ScannedBlock<AccountId>, ScanError>
where
    P: consensus::Parameters + Send + 'static,
    AccountId: Default + Eq + Hash + ConditionallySelectable + Send + 'static,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
{
    scan_block_with_runner::<_, _, _, ()>(params, block, scanning_keys, prior_block_metadata, None)
}

type TaggedBatch<IvkTag> = Batch<IvkTag, SaplingDomain, CompactOutputDescription, CompactDecryptor>;
type TaggedBatchRunner<IvkTag, BatchTag> =
    BatchRunner<IvkTag, SaplingDomain, CompactOutputDescription, CompactDecryptor, BatchTag>;

#[tracing::instrument(skip_all, fields(height = block.height))]
pub(crate) fn add_block_to_runner<P, IvkTag, T>(
    params: &P,
    block: CompactBlock,
    batch_runner: &mut TaggedBatchRunner<IvkTag, T>,
) where
    P: consensus::Parameters + Send + 'static,
    IvkTag: Copy + Send + 'static,
    T: Tasks<TaggedBatch<IvkTag>>,
{
    let block_hash = block.hash();
    let block_height = block.height();
    let zip212_enforcement = consensus::sapling_zip212_enforcement(params, block_height);

    for tx in block.vtx.into_iter() {
        let txid = tx.txid();
        let outputs = tx
            .outputs
            .iter()
            .map(|output| {
                CompactOutputDescription::try_from(output)
                    .expect("Invalid output found in compact block decoding.")
            })
            .collect::<Vec<_>>();

        batch_runner.add_outputs(
            block_hash,
            txid,
            || SaplingDomain::new(zip212_enforcement),
            &outputs,
        )
    }
}

fn check_hash_continuity(
    block: &CompactBlock,
    prior_block_metadata: Option<&BlockMetadata>,
) -> Option<ScanError> {
    if let Some(prev) = prior_block_metadata {
        if block.height() != prev.block_height() + 1 {
            return Some(ScanError::BlockHeightDiscontinuity {
                prev_height: prev.block_height(),
                new_height: block.height(),
            });
        }

        if block.prev_hash() != prev.block_hash() {
            return Some(ScanError::PrevHashMismatch {
                at_height: block.height(),
            });
        }
    }

    None
}

#[tracing::instrument(skip_all, fields(height = block.height))]
pub(crate) fn scan_block_with_runner<P, AccountId, IvkTag, T>(
    params: &P,
    block: CompactBlock,
    scanning_keys: &ScanningKeys<AccountId, IvkTag>,
    prior_block_metadata: Option<&BlockMetadata>,
    mut sapling_batch_runner: Option<&mut TaggedBatchRunner<IvkTag, T>>,
) -> Result<ScannedBlock<AccountId>, ScanError>
where
    P: consensus::Parameters + Send + 'static,
    AccountId: Default + Eq + Hash + ConditionallySelectable + Send + 'static,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
    T: Tasks<TaggedBatch<IvkTag>> + Sync,
{
    if let Some(scan_error) = check_hash_continuity(&block, prior_block_metadata) {
        return Err(scan_error);
    }

    let cur_height = block.height();
    let cur_hash = block.hash();
    let zip212_enforcement = consensus::sapling_zip212_enforcement(params, cur_height);

    let mut sapling_commitment_tree_size = prior_block_metadata
        .and_then(|m| m.sapling_tree_size())
        .map_or_else(
            || {
                block.chain_metadata.as_ref().map_or_else(
                    || {
                        // If we're below Sapling activation, or Sapling activation is not set, the tree size is zero
                        params
                            .activation_height(NetworkUpgrade::Sapling)
                            .map_or_else(
                                || Ok(0),
                                |sapling_activation| {
                                    if cur_height < sapling_activation {
                                        Ok(0)
                                    } else {
                                        Err(ScanError::TreeSizeUnknown {
                                            protocol: ShieldedProtocol::Sapling,
                                            at_height: cur_height,
                                        })
                                    }
                                },
                            )
                    },
                    |m| {
                        let sapling_output_count: u32 = block
                            .vtx
                            .iter()
                            .map(|tx| tx.outputs.len())
                            .sum::<usize>()
                            .try_into()
                            .expect("Sapling output count cannot exceed a u32");

                        // The default for m.sapling_commitment_tree_size is zero, so we need to check
                        // that the subtraction will not underflow; if it would do so, we were given
                        // invalid chain metadata for a block with Sapling outputs.
                        m.sapling_commitment_tree_size
                            .checked_sub(sapling_output_count)
                            .ok_or(ScanError::TreeSizeInvalid {
                                protocol: ShieldedProtocol::Sapling,
                                at_height: cur_height,
                            })
                    },
                )
            },
            Ok,
        )?;

    #[cfg(feature = "orchard")]
    let mut orchard_commitment_tree_size = prior_block_metadata
        .and_then(|m| m.orchard_tree_size())
        .map_or_else(
            || {
                block.chain_metadata.as_ref().map_or_else(
                    || {
                        // If we're below Orchard activation, or Orchard activation is not set, the tree size is zero
                        params.activation_height(NetworkUpgrade::Nu5).map_or_else(
                            || Ok(0),
                            |orchard_activation| {
                                if cur_height < orchard_activation {
                                    Ok(0)
                                } else {
                                    Err(ScanError::TreeSizeUnknown {
                                        protocol: ShieldedProtocol::Orchard,
                                        at_height: cur_height,
                                    })
                                }
                            },
                        )
                    },
                    |m| {
                        let orchard_action_count: u32 = block
                            .vtx
                            .iter()
                            .map(|tx| tx.actions.len())
                            .sum::<usize>()
                            .try_into()
                            .expect("Orchard action count cannot exceed a u32");

                        // The default for m.orchard_commitment_tree_size is zero, so we need to check
                        // that the subtraction will not underflow; if it would do so, we were given
                        // invalid chain metadata for a block with Orchard actions.
                        m.orchard_commitment_tree_size
                            .checked_sub(orchard_action_count)
                            .ok_or(ScanError::TreeSizeInvalid {
                                protocol: ShieldedProtocol::Orchard,
                                at_height: cur_height,
                            })
                    },
                )
            },
            Ok,
        )?;

    let compact_block_tx_count = block.vtx.len();
    let mut wtxs: Vec<WalletTx<AccountId>> = vec![];
    let mut sapling_nullifier_map = Vec::with_capacity(block.vtx.len());
    let mut sapling_note_commitments: Vec<(sapling::Node, Retention<BlockHeight>)> = vec![];
    for (tx_idx, tx) in block.vtx.into_iter().enumerate() {
        let txid = tx.txid();
        let tx_index =
            u16::try_from(tx.index).expect("Cannot fit more than 2^16 transactions in a block");

        let (sapling_spends, sapling_unlinked_nullifiers) = find_spent(
            &tx.spends,
            &scanning_keys.sapling_nullifiers,
            |spend| {
                spend.nf().expect(
                    "Could not deserialize nullifier for spend from protobuf representation.",
                )
            },
            WalletSaplingSpend::from_parts,
        );

        sapling_nullifier_map.push((txid, tx_index, sapling_unlinked_nullifiers));

        // Collect the set of accounts that were spent from in this transaction
        let spent_from_accounts: HashSet<_> = sapling_spends
            .iter()
            .map(|spend| *spend.account())
            .collect();

        let (sapling_outputs, mut sapling_nc) = find_received(
            cur_height,
            compact_block_tx_count,
            txid,
            tx_idx,
            sapling_commitment_tree_size,
            &scanning_keys.sapling_keys,
            &spent_from_accounts,
            &tx.outputs
                .iter()
                .map(|output| {
                    (
                        SaplingDomain::new(zip212_enforcement),
                        CompactOutputDescription::try_from(output)
                            .expect("Invalid output found in compact block decoding."),
                    )
                })
                .collect::<Vec<_>>(),
            sapling_batch_runner
                .as_mut()
                .map(|runner| |txid| runner.collect_results(cur_hash, txid)),
            |output| sapling::Node::from_cmu(&output.cmu),
            |output_idx, output, note, is_change, position, nf, account_id, key_scope| {
                WalletSaplingOutput::from_parts(
                    output_idx,
                    output.cmu,
                    output.ephemeral_key.clone(),
                    account_id,
                    note,
                    is_change,
                    position,
                    nf,
                    key_scope,
                )
            },
        );
        sapling_note_commitments.append(&mut sapling_nc);

        if !(sapling_spends.is_empty() && sapling_outputs.is_empty()) {
            wtxs.push(WalletTx::new(
                txid,
                tx_index as usize,
                sapling_spends,
                sapling_outputs,
            ));
        }

        sapling_commitment_tree_size +=
            u32::try_from(tx.outputs.len()).expect("Sapling output count cannot exceed a u32");
        #[cfg(feature = "orchard")]
        {
            orchard_commitment_tree_size +=
                u32::try_from(tx.actions.len()).expect("Orchard action count cannot exceed a u32");
        }
    }

    if let Some(chain_meta) = block.chain_metadata {
        if chain_meta.sapling_commitment_tree_size != sapling_commitment_tree_size {
            return Err(ScanError::TreeSizeMismatch {
                protocol: ShieldedProtocol::Sapling,
                at_height: cur_height,
                given: chain_meta.sapling_commitment_tree_size,
                computed: sapling_commitment_tree_size,
            });
        }

        #[cfg(feature = "orchard")]
        if chain_meta.orchard_commitment_tree_size != orchard_commitment_tree_size {
            return Err(ScanError::TreeSizeMismatch {
                protocol: ShieldedProtocol::Orchard,
                at_height: cur_height,
                given: chain_meta.orchard_commitment_tree_size,
                computed: orchard_commitment_tree_size,
            });
        }
    }

    Ok(ScannedBlock::from_parts(
        cur_height,
        cur_hash,
        block.time,
        wtxs,
        ScannedBundles::new(
            sapling_commitment_tree_size,
            sapling_note_commitments,
            sapling_nullifier_map,
        ),
        #[cfg(feature = "orchard")]
        ScannedBundles::new(
            orchard_commitment_tree_size,
            vec![], // FIXME: collect the Orchard nullifiers
            vec![], // FIXME: collect the Orchard note commitments
        ),
    ))
}

// Check for spent notes. The comparison against known-unspent nullifiers is done
// in constant time.
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
    Nf,
    IvkTag: Copy + std::hash::Hash + Eq + Send + 'static,
    SK: ScanningKeyOps<D, AccountId, Nf>,
    Output: ShieldedOutput<D, 52>,
    WalletOutput,
    NoteCommitment,
>(
    block_height: BlockHeight,
    block_tx_count: usize,
    txid: TxId,
    tx_idx: usize,
    commitment_tree_size: u32,
    keys: &HashMap<IvkTag, SK>,
    spent_from_accounts: &HashSet<AccountId>,
    decoded: &[(D, Output)],
    batch_results: Option<
        impl FnOnce(TxId) -> HashMap<(TxId, usize), DecryptedOutput<IvkTag, D, ()>>,
    >,
    extract_note_commitment: impl Fn(&Output) -> NoteCommitment,
    new_wallet_output: impl Fn(
        usize,
        &Output,
        D::Note,
        bool,
        Position,
        Option<Nf>,
        AccountId,
        Option<zip32::Scope>,
    ) -> WalletOutput,
) -> (
    Vec<WalletOutput>,
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
                        .remove(&(txid, i))
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
            batch::try_compact_note_decryption(&ivks, decoded)
                .into_iter()
                .map(|v| {
                    v.map(|((note, _), ivk_idx)| {
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
        let is_checkpoint = output_idx + 1 == decoded.len() && tx_idx + 1 == block_tx_count;
        let retention = match (decrypted_note.is_some(), is_checkpoint) {
            (is_marked, true) => Retention::Checkpoint {
                id: block_height,
                is_marked,
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
            let note_commitment_tree_position = Position::from(u64::from(
                commitment_tree_size + u32::try_from(output_idx).unwrap(),
            ));
            let nf = key.nf(&note, note_commitment_tree_position);

            shielded_outputs.push(new_wallet_output(
                output_idx,
                output,
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

#[cfg(test)]
mod tests {

    use group::{
        ff::{Field, PrimeField},
        GroupEncoding,
    };
    use incrementalmerkletree::{Position, Retention};
    use rand_core::{OsRng, RngCore};
    use sapling::{
        constants::SPENDING_KEY_GENERATOR,
        note_encryption::{sapling_note_encryption, SaplingDomain},
        util::generate_random_rseed,
        value::NoteValue,
        zip32::DiversifiableFullViewingKey,
        Nullifier,
    };
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_note_encryption::Domain;
    use zcash_primitives::{
        block::BlockHash,
        consensus::{sapling_zip212_enforcement, BlockHeight, Network},
        memo::MemoBytes,
        transaction::components::amount::NonNegativeAmount,
        zip32::AccountId,
    };

    use crate::{
        data_api::BlockMetadata,
        proto::compact_formats::{
            self as compact, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
        },
        scan::BatchRunner,
        scanning::ScanningKeys,
    };

    use super::{add_block_to_runner, scan_block, scan_block_with_runner};

    fn random_compact_tx(mut rng: impl RngCore) -> CompactTx {
        let fake_nf = {
            let mut nf = vec![0; 32];
            rng.fill_bytes(&mut nf);
            nf
        };
        let fake_cmu = {
            let fake_cmu = bls12_381::Scalar::random(&mut rng);
            fake_cmu.to_repr().as_ref().to_owned()
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
            ciphertext: vec![0; 52],
        };
        let mut ctx = CompactTx::default();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.hash = txid;
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
    fn fake_compact_block(
        height: BlockHeight,
        prev_hash: BlockHash,
        nf: Nullifier,
        dfvk: &DiversifiableFullViewingKey,
        value: NonNegativeAmount,
        tx_after: bool,
        initial_tree_sizes: Option<(u32, u32)>,
    ) -> CompactBlock {
        let zip212_enforcement = sapling_zip212_enforcement(&Network::TestNetwork, height);
        let to = dfvk.default_address().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let rseed = generate_random_rseed(zip212_enforcement, &mut rng);
        let note = sapling::Note::from_parts(to, NoteValue::from(value), rseed);
        let encryptor = sapling_note_encryption(
            Some(dfvk.fvk().ovk),
            note.clone(),
            *MemoBytes::empty().as_array(),
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
            ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
        };
        let mut ctx = CompactTx::default();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.hash = txid;
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

    #[test]
    fn scan_block_with_my_tx() {
        fn go(scan_multithreaded: bool) {
            let network = Network::TestNetwork;
            let account = AccountId::ZERO;
            let usk =
                UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
            let ufvk = usk.to_unified_full_viewing_key();
            let sapling_dfvk = ufvk.sapling().expect("Sapling key is present").clone();
            let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);

            let cb = fake_compact_block(
                1u32.into(),
                BlockHash([0; 32]),
                Nullifier([0; 32]),
                &sapling_dfvk,
                NonNegativeAmount::const_from_u64(5),
                false,
                None,
            );
            assert_eq!(cb.vtx.len(), 2);

            let mut batch_runner = if scan_multithreaded {
                let mut runner = BatchRunner::<_, _, _, _, ()>::new(
                    10,
                    scanning_keys
                        .sapling_keys()
                        .iter()
                        .map(|(key_id, key)| (*key_id, key.prepare())),
                );

                add_block_to_runner(&Network::TestNetwork, cb.clone(), &mut runner);
                runner.flush();

                Some(runner)
            } else {
                None
            };

            let scanned_block = scan_block_with_runner(
                &network,
                cb,
                &scanning_keys,
                Some(&BlockMetadata::from_parts(
                    BlockHeight::from(0),
                    BlockHash([0u8; 32]),
                    Some(0),
                    #[cfg(feature = "orchard")]
                    Some(0),
                )),
                batch_runner.as_mut(),
            )
            .unwrap();
            let txs = scanned_block.transactions();
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.block_index(), 1);
            assert_eq!(tx.sapling_spends().len(), 0);
            assert_eq!(tx.sapling_outputs().len(), 1);
            assert_eq!(tx.sapling_outputs()[0].index(), 0);
            assert_eq!(tx.sapling_outputs()[0].account_id(), &account);
            assert_eq!(tx.sapling_outputs()[0].note().value().inner(), 5);
            assert_eq!(
                tx.sapling_outputs()[0].note_commitment_tree_position(),
                Position::from(1)
            );

            assert_eq!(scanned_block.sapling().final_tree_size(), 2);
            assert_eq!(
                scanned_block
                    .sapling()
                    .commitments()
                    .iter()
                    .map(|(_, retention)| *retention)
                    .collect::<Vec<_>>(),
                vec![
                    Retention::Ephemeral,
                    Retention::Checkpoint {
                        id: scanned_block.height(),
                        is_marked: true
                    }
                ]
            );
        }

        go(false);
        go(true);
    }

    #[test]
    fn scan_block_with_txs_after_my_tx() {
        fn go(scan_multithreaded: bool) {
            let network = Network::TestNetwork;
            let account = AccountId::ZERO;
            let usk =
                UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
            let ufvk = usk.to_unified_full_viewing_key();
            let sapling_dfvk = ufvk.sapling().expect("Sapling key is present").clone();
            let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);

            let cb = fake_compact_block(
                1u32.into(),
                BlockHash([0; 32]),
                Nullifier([0; 32]),
                &sapling_dfvk,
                NonNegativeAmount::const_from_u64(5),
                true,
                Some((0, 0)),
            );
            assert_eq!(cb.vtx.len(), 3);

            let mut batch_runner = if scan_multithreaded {
                let mut runner = BatchRunner::<_, _, _, _, ()>::new(
                    10,
                    scanning_keys
                        .sapling_keys()
                        .iter()
                        .map(|(key_id, key)| (*key_id, key.prepare())),
                );

                add_block_to_runner(&Network::TestNetwork, cb.clone(), &mut runner);
                runner.flush();

                Some(runner)
            } else {
                None
            };

            let scanned_block =
                scan_block_with_runner(&network, cb, &scanning_keys, None, batch_runner.as_mut())
                    .unwrap();
            let txs = scanned_block.transactions();
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.block_index(), 1);
            assert_eq!(tx.sapling_spends().len(), 0);
            assert_eq!(tx.sapling_outputs().len(), 1);
            assert_eq!(tx.sapling_outputs()[0].index(), 0);
            assert_eq!(tx.sapling_outputs()[0].account_id(), &AccountId::ZERO);
            assert_eq!(tx.sapling_outputs()[0].note().value().inner(), 5);

            assert_eq!(
                scanned_block
                    .sapling()
                    .commitments()
                    .iter()
                    .map(|(_, retention)| *retention)
                    .collect::<Vec<_>>(),
                vec![
                    Retention::Ephemeral,
                    Retention::Marked,
                    Retention::Checkpoint {
                        id: scanned_block.height(),
                        is_marked: false
                    }
                ]
            );
        }

        go(false);
        go(true);
    }

    #[test]
    fn scan_block_with_my_spend() {
        let network = Network::TestNetwork;
        let account = AccountId::try_from(12).unwrap();
        let usk = UnifiedSpendingKey::from_seed(&network, &[0u8; 32], account).expect("Valid USK");
        let ufvk = usk.to_unified_full_viewing_key();
        let mut scanning_keys = ScanningKeys::empty();

        let nf = Nullifier([7; 32]);
        scanning_keys.extend_sapling_nullifiers([(account, nf)]);

        let cb = fake_compact_block(
            1u32.into(),
            BlockHash([0; 32]),
            nf,
            ufvk.sapling().unwrap(),
            NonNegativeAmount::const_from_u64(5),
            false,
            Some((0, 0)),
        );
        assert_eq!(cb.vtx.len(), 2);

        let scanned_block = scan_block(&network, cb, &scanning_keys, None).unwrap();
        let txs = scanned_block.transactions();
        assert_eq!(txs.len(), 1);

        let tx = &txs[0];
        assert_eq!(tx.block_index(), 1);
        assert_eq!(tx.sapling_spends().len(), 1);
        assert_eq!(tx.sapling_outputs().len(), 0);
        assert_eq!(tx.sapling_spends()[0].index(), 0);
        assert_eq!(tx.sapling_spends()[0].nf(), &nf);
        assert_eq!(tx.sapling_spends()[0].account(), &account);

        assert_eq!(
            scanned_block
                .sapling()
                .commitments()
                .iter()
                .map(|(_, retention)| *retention)
                .collect::<Vec<_>>(),
            vec![
                Retention::Ephemeral,
                Retention::Checkpoint {
                    id: scanned_block.height(),
                    is_marked: false
                }
            ]
        );
    }
}
