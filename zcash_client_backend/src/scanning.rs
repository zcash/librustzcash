//! Tools for scanning a compact representation of the Zcash block chain.

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt::{self, Debug};

use incrementalmerkletree::{Position, Retention};
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};
use zcash_note_encryption::batch;
use zcash_primitives::consensus::BlockHeight;
use zcash_primitives::{
    consensus,
    sapling::{
        self,
        note_encryption::{PreparedIncomingViewingKey, SaplingDomain},
        SaplingIvk,
    },
    transaction::components::sapling::CompactOutputDescription,
    zip32::{sapling::DiversifiableFullViewingKey, AccountId, Scope},
};

use crate::data_api::{BlockMetadata, ScannedBlock, ShieldedProtocol};
use crate::{
    proto::compact_formats::CompactBlock,
    scan::{Batch, BatchRunner, Tasks},
    wallet::{WalletSaplingOutput, WalletSaplingSpend, WalletTx},
};

/// A key that can be used to perform trial decryption and nullifier
/// computation for a Sapling [`CompactSaplingOutput`]
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
/// [`scan_block`]: crate::scanning::scan_block
pub trait ScanningKey {
    /// The type representing the scope of the scanning key.
    type Scope: Clone + Eq + std::hash::Hash + Send + 'static;

    /// The type of key that is used to decrypt Sapling outputs;
    type SaplingNk: Clone;

    type SaplingKeys: IntoIterator<Item = (Self::Scope, SaplingIvk, Self::SaplingNk)>;

    /// The type of nullifier extracted when a note is successfully
    /// obtained by trial decryption.
    type Nf;

    /// Obtain the underlying Sapling incoming viewing key(s) for this scanning key.
    fn to_sapling_keys(&self) -> Self::SaplingKeys;

    /// Produces the nullifier for the specified note and witness, if possible.
    ///
    /// IVK-based implementations of this trait cannot successfully derive
    /// nullifiers, in which case `Self::Nf` should be set to the unit type
    /// and this function is a no-op.
    fn sapling_nf(key: &Self::SaplingNk, note: &sapling::Note, note_position: Position)
        -> Self::Nf;
}

impl<K: ScanningKey> ScanningKey for &K {
    type Scope = K::Scope;
    type SaplingNk = K::SaplingNk;
    type SaplingKeys = K::SaplingKeys;
    type Nf = K::Nf;

    fn to_sapling_keys(&self) -> Self::SaplingKeys {
        (*self).to_sapling_keys()
    }

    fn sapling_nf(key: &Self::SaplingNk, note: &sapling::Note, position: Position) -> Self::Nf {
        K::sapling_nf(key, note, position)
    }
}

impl ScanningKey for DiversifiableFullViewingKey {
    type Scope = Scope;
    type SaplingNk = sapling::NullifierDerivingKey;
    type SaplingKeys = [(Self::Scope, SaplingIvk, Self::SaplingNk); 2];
    type Nf = sapling::Nullifier;

    fn to_sapling_keys(&self) -> Self::SaplingKeys {
        [
            (
                Scope::External,
                self.to_ivk(Scope::External),
                self.to_nk(Scope::External),
            ),
            (
                Scope::Internal,
                self.to_ivk(Scope::Internal),
                self.to_nk(Scope::Internal),
            ),
        ]
    }

    fn sapling_nf(key: &Self::SaplingNk, note: &sapling::Note, position: Position) -> Self::Nf {
        note.nf(key, position.into())
    }
}

impl ScanningKey for (Scope, SaplingIvk, sapling::NullifierDerivingKey) {
    type Scope = Scope;
    type SaplingNk = sapling::NullifierDerivingKey;
    type SaplingKeys = [(Self::Scope, SaplingIvk, Self::SaplingNk); 1];
    type Nf = sapling::Nullifier;

    fn to_sapling_keys(&self) -> Self::SaplingKeys {
        [self.clone()]
    }

    fn sapling_nf(key: &Self::SaplingNk, note: &sapling::Note, position: Position) -> Self::Nf {
        note.nf(key, position.into())
    }
}

/// The [`ScanningKey`] implementation for [`SaplingIvk`]s.
/// Nullifiers cannot be derived when scanning with these keys.
///
/// [`SaplingIvk`]: zcash_primitives::sapling::SaplingIvk
impl ScanningKey for SaplingIvk {
    type Scope = ();
    type SaplingNk = ();
    type SaplingKeys = [(Self::Scope, SaplingIvk, Self::SaplingNk); 1];
    type Nf = ();

    fn to_sapling_keys(&self) -> Self::SaplingKeys {
        [((), self.clone(), ())]
    }

    fn sapling_nf(_key: &Self::SaplingNk, _note: &sapling::Note, _position: Position) {}
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
        }
    }
}

/// Scans a [`CompactBlock`] with a set of [`ScanningKey`]s.
///
/// Returns a vector of [`WalletTx`]s belonging to any of the given
/// [`ScanningKey`]s. If scanning with a full viewing key, the nullifiers
/// of the resulting [`WalletSaplingOutput`]s will also be computed.
///
/// The given [`CommitmentTree`] and existing [`IncrementalWitness`]es are
/// incremented appropriately.
///
/// The implementation of [`ScanningKey`] may either support or omit the computation of
/// the nullifiers for received notes; the implementation for [`ExtendedFullViewingKey`]
/// will derive the nullifiers for received notes and return them as part of the resulting
/// [`WalletSaplingOutput`]s, whereas the implementation for [`SaplingIvk`] cannot
/// do so and will return the unit value in those outputs instead.
///
/// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
/// [`SaplingIvk`]: zcash_primitives::sapling::SaplingIvk
/// [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
/// [`ScanningKey`]: crate::scanning::ScanningKey
/// [`CommitmentTree`]: zcash_primitives::sapling::CommitmentTree
/// [`IncrementalWitness`]: zcash_primitives::sapling::IncrementalWitness
/// [`WalletSaplingOutput`]: crate::wallet::WalletSaplingOutput
/// [`WalletTx`]: crate::wallet::WalletTx
pub fn scan_block<P: consensus::Parameters + Send + 'static, K: ScanningKey>(
    params: &P,
    block: CompactBlock,
    vks: &[(&AccountId, &K)],
    sapling_nullifiers: &[(AccountId, sapling::Nullifier)],
    prior_block_metadata: Option<&BlockMetadata>,
) -> Result<ScannedBlock<K::Nf>, ScanError> {
    scan_block_with_runner::<_, _, ()>(
        params,
        block,
        vks,
        sapling_nullifiers,
        prior_block_metadata,
        None,
    )
}

type TaggedBatch<P, S> = Batch<(AccountId, S), SaplingDomain<P>, CompactOutputDescription>;
type TaggedBatchRunner<P, S, T> =
    BatchRunner<(AccountId, S), SaplingDomain<P>, CompactOutputDescription, T>;

#[tracing::instrument(skip_all, fields(height = block.height))]
pub(crate) fn add_block_to_runner<P, S, T>(
    params: &P,
    block: CompactBlock,
    batch_runner: &mut TaggedBatchRunner<P, S, T>,
) where
    P: consensus::Parameters + Send + 'static,
    S: Clone + Send + 'static,
    T: Tasks<TaggedBatch<P, S>>,
{
    let block_hash = block.hash();
    let block_height = block.height();

    for tx in block.vtx.into_iter() {
        let txid = tx.txid();
        let outputs = tx
            .outputs
            .into_iter()
            .map(|output| {
                CompactOutputDescription::try_from(output)
                    .expect("Invalid output found in compact block decoding.")
            })
            .collect::<Vec<_>>();

        batch_runner.add_outputs(
            block_hash,
            txid,
            || SaplingDomain::for_height(params.clone(), block_height),
            &outputs,
        )
    }
}

pub(crate) fn check_continuity(
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

        if let Some(given) = block
            .chain_metadata
            .as_ref()
            .map(|m| m.sapling_commitment_tree_size)
        {
            let computed = prev.sapling_tree_size()
                + u32::try_from(block.vtx.iter().map(|tx| tx.outputs.len()).sum::<usize>())
                    .unwrap();
            if given != computed {
                return Some(ScanError::TreeSizeMismatch {
                    protocol: ShieldedProtocol::Sapling,
                    at_height: block.height(),
                    given,
                    computed,
                });
            }
        }
    }

    None
}

#[tracing::instrument(skip_all, fields(height = block.height))]
pub(crate) fn scan_block_with_runner<
    P: consensus::Parameters + Send + 'static,
    K: ScanningKey,
    T: Tasks<TaggedBatch<P, K::Scope>> + Sync,
>(
    params: &P,
    block: CompactBlock,
    vks: &[(&AccountId, K)],
    nullifiers: &[(AccountId, sapling::Nullifier)],
    prior_block_metadata: Option<&BlockMetadata>,
    mut batch_runner: Option<&mut TaggedBatchRunner<P, K::Scope, T>>,
) -> Result<ScannedBlock<K::Nf>, ScanError> {
    if let Some(scan_error) = check_continuity(&block, prior_block_metadata) {
        return Err(scan_error);
    }

    let cur_height = block.height();
    let cur_hash = block.hash();

    // It's possible to make progress without a Sapling tree position if we don't have any Sapling
    // notes in the block, since we only use the position for constructing nullifiers for our own
    // received notes. Thus, we allow it to be optional here, and only produce an error if we try
    // to use it. `block.sapling_commitment_tree_size` is expected to be correct as of the end of
    // the block, and we can't have a note of ours in a block with no outputs so treating the zero
    // default value from the protobuf as `None` is always correct.
    let mut sapling_commitment_tree_size = block
        .chain_metadata
        .as_ref()
        .and_then(|m| {
            if m.sapling_commitment_tree_size == 0 {
                None
            } else {
                let block_note_count: u32 = block
                    .vtx
                    .iter()
                    .map(|tx| {
                        u32::try_from(tx.outputs.len()).expect("output count cannot exceed a u32")
                    })
                    .sum();
                Some(m.sapling_commitment_tree_size - block_note_count)
            }
        })
        .or_else(|| prior_block_metadata.map(|m| m.sapling_tree_size()))
        .ok_or(ScanError::TreeSizeUnknown {
            protocol: ShieldedProtocol::Sapling,
            at_height: cur_height,
        })?;

    let compact_block_tx_count = block.vtx.len();
    let mut wtxs: Vec<WalletTx<K::Nf>> = vec![];
    let mut sapling_nullifier_map = Vec::with_capacity(block.vtx.len());
    let mut sapling_note_commitments: Vec<(sapling::Node, Retention<BlockHeight>)> = vec![];
    for (tx_idx, tx) in block.vtx.into_iter().enumerate() {
        let txid = tx.txid();
        let tx_index =
            u16::try_from(tx.index).expect("Cannot fit more than 2^16 transactions in a block");

        // Check for spent notes. The comparison against known-unspent nullifiers is done
        // in constant time.
        // TODO: However, this is O(|nullifiers| * |notes|); does using
        // constant-time operations here really make sense?
        let mut shielded_spends = vec![];
        let mut sapling_unlinked_nullifiers = Vec::with_capacity(tx.spends.len());
        for (index, spend) in tx.spends.into_iter().enumerate() {
            let spend_nf = spend
                .nf()
                .expect("Could not deserialize nullifier for spend from protobuf representation.");

            // Find the first tracked nullifier that matches this spend, and produce
            // a WalletShieldedSpend if there is a match, in constant time.
            let spend = nullifiers
                .iter()
                .map(|&(account, nf)| CtOption::new(account, nf.ct_eq(&spend_nf)))
                .fold(
                    CtOption::new(AccountId::from(0), 0.into()),
                    |first, next| CtOption::conditional_select(&next, &first, first.is_some()),
                )
                .map(|account| WalletSaplingSpend::from_parts(index, spend_nf, account));

            if spend.is_some().into() {
                shielded_spends.push(spend.unwrap());
            } else {
                // This nullifier didn't match any we are currently tracking; save it in
                // case it matches an earlier block range we haven't scanned yet.
                sapling_unlinked_nullifiers.push(spend_nf);
            }
        }
        sapling_nullifier_map.push((txid, tx_index, sapling_unlinked_nullifiers));

        // Collect the set of accounts that were spent from in this transaction
        let spent_from_accounts: HashSet<_> = shielded_spends
            .iter()
            .map(|spend| spend.account())
            .collect();

        // Check for incoming notes while incrementing tree and witnesses
        let mut shielded_outputs: Vec<WalletSaplingOutput<K::Nf>> = vec![];
        let tx_outputs_len = u32::try_from(tx.outputs.len()).unwrap();
        {
            let decoded = &tx
                .outputs
                .into_iter()
                .map(|output| {
                    (
                        SaplingDomain::for_height(params.clone(), cur_height),
                        CompactOutputDescription::try_from(output)
                            .expect("Invalid output found in compact block decoding."),
                    )
                })
                .collect::<Vec<_>>();

            let decrypted: Vec<_> = if let Some(runner) = batch_runner.as_mut() {
                let vks = vks
                    .iter()
                    .flat_map(|(a, k)| {
                        k.to_sapling_keys()
                            .into_iter()
                            .map(move |(scope, _, nk)| ((**a, scope), nk))
                    })
                    .collect::<HashMap<_, _>>();

                let mut decrypted = runner.collect_results(cur_hash, txid);
                (0..decoded.len())
                    .map(|i| {
                        decrypted.remove(&(txid, i)).map(|d_note| {
                            let a = d_note.ivk_tag.0;
                            let nk = vks.get(&d_note.ivk_tag).expect(
                                "The batch runner and scan_block must use the same set of IVKs.",
                            );

                            (d_note.note, a, (*nk).clone())
                        })
                    })
                    .collect()
            } else {
                let vks = vks
                    .iter()
                    .flat_map(|(a, k)| {
                        k.to_sapling_keys()
                            .into_iter()
                            .map(move |(_, ivk, nk)| (**a, ivk, nk))
                    })
                    .collect::<Vec<_>>();

                let ivks = vks
                    .iter()
                    .map(|(_, ivk, _)| ivk)
                    .map(PreparedIncomingViewingKey::new)
                    .collect::<Vec<_>>();

                batch::try_compact_note_decryption(&ivks, &decoded[..])
                    .into_iter()
                    .map(|v| {
                        v.map(|((note, _), ivk_idx)| {
                            let (account, _, nk) = &vks[ivk_idx];
                            (note, *account, (*nk).clone())
                        })
                    })
                    .collect()
            };

            for (output_idx, ((_, output), dec_output)) in decoded.iter().zip(decrypted).enumerate()
            {
                // Collect block note commitments
                let node = sapling::Node::from_cmu(&output.cmu);
                let is_checkpoint =
                    output_idx + 1 == decoded.len() && tx_idx + 1 == compact_block_tx_count;
                let retention = match (dec_output.is_some(), is_checkpoint) {
                    (is_marked, true) => Retention::Checkpoint {
                        id: cur_height,
                        is_marked,
                    },
                    (true, false) => Retention::Marked,
                    (false, false) => Retention::Ephemeral,
                };

                if let Some((note, account, nk)) = dec_output {
                    // A note is marked as "change" if the account that received it
                    // also spent notes in the same transaction. This will catch,
                    // for instance:
                    // - Change created by spending fractions of notes.
                    // - Notes created by consolidation transactions.
                    // - Notes sent from one account to itself.
                    let is_change = spent_from_accounts.contains(&account);
                    let note_commitment_tree_position = Position::from(u64::from(
                        sapling_commitment_tree_size + u32::try_from(output_idx).unwrap(),
                    ));
                    let nf = K::sapling_nf(&nk, &note, note_commitment_tree_position);

                    shielded_outputs.push(WalletSaplingOutput::from_parts(
                        output_idx,
                        output.cmu,
                        output.ephemeral_key.clone(),
                        account,
                        note,
                        is_change,
                        note_commitment_tree_position,
                        nf,
                    ));
                }

                sapling_note_commitments.push((node, retention));
            }
        }

        if !(shielded_spends.is_empty() && shielded_outputs.is_empty()) {
            wtxs.push(WalletTx {
                txid,
                index: tx_index as usize,
                sapling_spends: shielded_spends,
                sapling_outputs: shielded_outputs,
            });
        }

        sapling_commitment_tree_size += tx_outputs_len;
    }

    Ok(ScannedBlock::from_parts(
        BlockMetadata::from_parts(cur_height, cur_hash, sapling_commitment_tree_size),
        block.time,
        wtxs,
        sapling_nullifier_map,
        sapling_note_commitments,
    ))
}

#[cfg(test)]
mod tests {
    use group::{
        ff::{Field, PrimeField},
        GroupEncoding,
    };
    use incrementalmerkletree::{Position, Retention};
    use rand_core::{OsRng, RngCore};
    use zcash_note_encryption::Domain;
    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, Network},
        constants::SPENDING_KEY_GENERATOR,
        memo::MemoBytes,
        sapling::{
            self,
            note_encryption::{sapling_note_encryption, PreparedIncomingViewingKey, SaplingDomain},
            util::generate_random_rseed,
            value::NoteValue,
            Nullifier, SaplingIvk,
        },
        transaction::components::Amount,
        zip32::{AccountId, DiversifiableFullViewingKey, ExtendedSpendingKey},
    };

    use crate::{
        data_api::BlockMetadata,
        proto::compact_formats::{
            self as compact, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
        },
        scan::BatchRunner,
    };

    use super::{add_block_to_runner, scan_block, scan_block_with_runner, ScanningKey};

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
    /// Set `initial_sapling_tree_size` to `None` to simulate a `CompactBlock` retrieved
    /// from a `lightwalletd` that is not currently tracking note commitment tree sizes.
    fn fake_compact_block(
        height: BlockHeight,
        prev_hash: BlockHash,
        nf: Nullifier,
        dfvk: &DiversifiableFullViewingKey,
        value: Amount,
        tx_after: bool,
        initial_sapling_tree_size: Option<u32>,
    ) -> CompactBlock {
        let to = dfvk.default_address().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let rseed = generate_random_rseed(&Network::TestNetwork, height, &mut rng);
        let note = sapling::Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
        let encryptor = sapling_note_encryption::<_, Network>(
            Some(dfvk.fvk().ovk),
            note.clone(),
            MemoBytes::empty(),
            &mut rng,
        );
        let cmu = note.cmu().to_bytes().to_vec();
        let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
            .0
            .to_vec();
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

        cb.chain_metadata = initial_sapling_tree_size.map(|s| compact::ChainMetadata {
            sapling_commitment_tree_size: s + cb
                .vtx
                .iter()
                .map(|tx| tx.outputs.len() as u32)
                .sum::<u32>(),
            ..Default::default()
        });

        cb
    }

    #[test]
    fn scan_block_with_my_tx() {
        fn go(scan_multithreaded: bool) {
            let account = AccountId::from(0);
            let extsk = ExtendedSpendingKey::master(&[]);
            let dfvk = extsk.to_diversifiable_full_viewing_key();

            let cb = fake_compact_block(
                1u32.into(),
                BlockHash([0; 32]),
                Nullifier([0; 32]),
                &dfvk,
                Amount::from_u64(5).unwrap(),
                false,
                None,
            );
            assert_eq!(cb.vtx.len(), 2);

            let mut batch_runner = if scan_multithreaded {
                let mut runner = BatchRunner::<_, _, _, ()>::new(
                    10,
                    dfvk.to_sapling_keys()
                        .iter()
                        .map(|(scope, ivk, _)| ((account, *scope), ivk))
                        .map(|(tag, ivk)| (tag, PreparedIncomingViewingKey::new(ivk))),
                );

                add_block_to_runner(&Network::TestNetwork, cb.clone(), &mut runner);
                runner.flush();

                Some(runner)
            } else {
                None
            };

            let scanned_block = scan_block_with_runner(
                &Network::TestNetwork,
                cb,
                &[(&account, &dfvk)],
                &[],
                Some(&BlockMetadata::from_parts(
                    BlockHeight::from(0),
                    BlockHash([0u8; 32]),
                    0,
                )),
                batch_runner.as_mut(),
            )
            .unwrap();
            let txs = scanned_block.transactions();
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.index, 1);
            assert_eq!(tx.sapling_spends.len(), 0);
            assert_eq!(tx.sapling_outputs.len(), 1);
            assert_eq!(tx.sapling_outputs[0].index(), 0);
            assert_eq!(tx.sapling_outputs[0].account(), account);
            assert_eq!(tx.sapling_outputs[0].note().value().inner(), 5);
            assert_eq!(
                tx.sapling_outputs[0].note_commitment_tree_position(),
                Position::from(1)
            );

            assert_eq!(scanned_block.metadata().sapling_tree_size(), 2);
            assert_eq!(
                scanned_block
                    .sapling_commitments()
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
            let account = AccountId::from(0);
            let extsk = ExtendedSpendingKey::master(&[]);
            let dfvk = extsk.to_diversifiable_full_viewing_key();

            let cb = fake_compact_block(
                1u32.into(),
                BlockHash([0; 32]),
                Nullifier([0; 32]),
                &dfvk,
                Amount::from_u64(5).unwrap(),
                true,
                Some(0),
            );
            assert_eq!(cb.vtx.len(), 3);

            let mut batch_runner = if scan_multithreaded {
                let mut runner = BatchRunner::<_, _, _, ()>::new(
                    10,
                    dfvk.to_sapling_keys()
                        .iter()
                        .map(|(scope, ivk, _)| ((account, *scope), ivk))
                        .map(|(tag, ivk)| (tag, PreparedIncomingViewingKey::new(ivk))),
                );

                add_block_to_runner(&Network::TestNetwork, cb.clone(), &mut runner);
                runner.flush();

                Some(runner)
            } else {
                None
            };

            let scanned_block = scan_block_with_runner(
                &Network::TestNetwork,
                cb,
                &[(&AccountId::from(0), &dfvk)],
                &[],
                None,
                batch_runner.as_mut(),
            )
            .unwrap();
            let txs = scanned_block.transactions();
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.index, 1);
            assert_eq!(tx.sapling_spends.len(), 0);
            assert_eq!(tx.sapling_outputs.len(), 1);
            assert_eq!(tx.sapling_outputs[0].index(), 0);
            assert_eq!(tx.sapling_outputs[0].account(), AccountId::from(0));
            assert_eq!(tx.sapling_outputs[0].note().value().inner(), 5);

            assert_eq!(
                scanned_block
                    .sapling_commitments()
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
        let extsk = ExtendedSpendingKey::master(&[]);
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let nf = Nullifier([7; 32]);
        let account = AccountId::from(12);

        let cb = fake_compact_block(
            1u32.into(),
            BlockHash([0; 32]),
            nf,
            &dfvk,
            Amount::from_u64(5).unwrap(),
            false,
            Some(0),
        );
        assert_eq!(cb.vtx.len(), 2);
        let vks: Vec<(&AccountId, &SaplingIvk)> = vec![];

        let scanned_block =
            scan_block(&Network::TestNetwork, cb, &vks[..], &[(account, nf)], None).unwrap();
        let txs = scanned_block.transactions();
        assert_eq!(txs.len(), 1);

        let tx = &txs[0];
        assert_eq!(tx.index, 1);
        assert_eq!(tx.sapling_spends.len(), 1);
        assert_eq!(tx.sapling_outputs.len(), 0);
        assert_eq!(tx.sapling_spends[0].index(), 0);
        assert_eq!(tx.sapling_spends[0].nf(), &nf);
        assert_eq!(tx.sapling_spends[0].account(), account);

        assert_eq!(
            scanned_block
                .sapling_commitments()
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
