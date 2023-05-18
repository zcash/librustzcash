//! Tools for scanning a compact representation of the Zcash block chain.

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;

use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};
use zcash_note_encryption::batch;
use zcash_primitives::{
    consensus,
    sapling::{
        self,
        note_encryption::{PreparedIncomingViewingKey, SaplingDomain},
        Node, Note, Nullifier, NullifierDerivingKey, SaplingIvk,
    },
    transaction::components::sapling::CompactOutputDescription,
    zip32::{sapling::DiversifiableFullViewingKey, AccountId, Scope},
};

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
/// [`scan_block`]: crate::welding_rig::scan_block
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
    fn sapling_nf(
        key: &Self::SaplingNk,
        note: &Note,
        witness: &sapling::IncrementalWitness,
    ) -> Self::Nf;
}

impl ScanningKey for DiversifiableFullViewingKey {
    type Scope = Scope;
    type SaplingNk = NullifierDerivingKey;
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

    fn sapling_nf(
        key: &Self::SaplingNk,
        note: &Note,
        witness: &sapling::IncrementalWitness,
    ) -> Self::Nf {
        note.nf(
            key,
            u64::try_from(witness.position())
                .expect("Sapling note commitment tree position must fit into a u64"),
        )
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

    fn sapling_nf(_key: &Self::SaplingNk, _note: &Note, _witness: &sapling::IncrementalWitness) {}
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
/// [`ScanningKey`]: crate::welding_rig::ScanningKey
/// [`CommitmentTree`]: zcash_primitives::sapling::CommitmentTree
/// [`IncrementalWitness`]: zcash_primitives::sapling::IncrementalWitness
/// [`WalletSaplingOutput`]: crate::wallet::WalletSaplingOutput
/// [`WalletTx`]: crate::wallet::WalletTx
pub fn scan_block<P: consensus::Parameters + Send + 'static, K: ScanningKey>(
    params: &P,
    block: CompactBlock,
    vks: &[(&AccountId, &K)],
    nullifiers: &[(AccountId, Nullifier)],
    tree: &mut sapling::CommitmentTree,
    existing_witnesses: &mut [&mut sapling::IncrementalWitness],
) -> Vec<WalletTx<K::Nf>> {
    scan_block_with_runner::<_, _, ()>(
        params,
        block,
        vks,
        nullifiers,
        tree,
        existing_witnesses,
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

#[tracing::instrument(skip_all, fields(height = block.height))]
pub(crate) fn scan_block_with_runner<
    P: consensus::Parameters + Send + 'static,
    K: ScanningKey,
    T: Tasks<TaggedBatch<P, K::Scope>> + Sync,
>(
    params: &P,
    block: CompactBlock,
    vks: &[(&AccountId, &K)],
    nullifiers: &[(AccountId, Nullifier)],
    tree: &mut sapling::CommitmentTree,
    existing_witnesses: &mut [&mut sapling::IncrementalWitness],
    mut batch_runner: Option<&mut TaggedBatchRunner<P, K::Scope, T>>,
) -> Vec<WalletTx<K::Nf>> {
    let mut wtxs: Vec<WalletTx<K::Nf>> = vec![];
    let block_height = block.height();
    let block_hash = block.hash();

    for tx in block.vtx.into_iter() {
        let txid = tx.txid();
        let index = tx.index as usize;

        // Check for spent notes
        // The only step that is not constant-time is the filter() at the end.
        let shielded_spends: Vec<_> = tx
            .spends
            .into_iter()
            .enumerate()
            .map(|(index, spend)| {
                let spend_nf = spend.nf().expect(
                    "Could not deserialize nullifier for spend from protobuf representation.",
                );
                // Find the first tracked nullifier that matches this spend, and produce
                // a WalletShieldedSpend if there is a match, in constant time.
                nullifiers
                    .iter()
                    .map(|&(account, nf)| CtOption::new(account, nf.ct_eq(&spend_nf)))
                    .fold(
                        CtOption::new(AccountId::from(0), 0.into()),
                        |first, next| CtOption::conditional_select(&next, &first, first.is_some()),
                    )
                    .map(|account| WalletSaplingSpend::from_parts(index, spend_nf, account))
            })
            .filter(|spend| spend.is_some().into())
            .map(|spend| spend.unwrap())
            .collect();

        // Collect the set of accounts that were spent from in this transaction
        let spent_from_accounts: HashSet<_> = shielded_spends
            .iter()
            .map(|spend| spend.account())
            .collect();

        // Check for incoming notes while incrementing tree and witnesses
        let mut shielded_outputs: Vec<WalletSaplingOutput<K::Nf>> = vec![];
        {
            // Grab mutable references to new witnesses from previous transactions
            // in this block so that we can update them. Scoped so we don't hold
            // mutable references to wtxs for too long.
            let mut block_witnesses: Vec<_> = wtxs
                .iter_mut()
                .flat_map(|tx| {
                    tx.sapling_outputs
                        .iter_mut()
                        .map(|output| output.witness_mut())
                })
                .collect();

            let decoded = &tx
                .outputs
                .into_iter()
                .map(|output| {
                    (
                        SaplingDomain::for_height(params.clone(), block_height),
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

                let mut decrypted = runner.collect_results(block_hash, txid);
                (0..decoded.len())
                    .map(|i| {
                        decrypted.remove(&(txid, i)).map(|d_note| {
                            let a = d_note.ivk_tag.0;
                            let nk = vks.get(&d_note.ivk_tag).expect(
                                "The batch runner and scan_block must use the same set of IVKs.",
                            );

                            ((d_note.note, d_note.recipient), a, (*nk).clone())
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

                batch::try_compact_note_decryption(&ivks, decoded)
                    .into_iter()
                    .map(|v| {
                        v.map(|(note_data, ivk_idx)| {
                            let (account, _, nk) = &vks[ivk_idx];
                            (note_data, *account, (*nk).clone())
                        })
                    })
                    .collect()
            };

            for (index, ((_, output), dec_output)) in decoded.iter().zip(decrypted).enumerate() {
                // Grab mutable references to new witnesses from previous outputs
                // in this transaction so that we can update them. Scoped so we
                // don't hold mutable references to shielded_outputs for too long.
                let new_witnesses: Vec<_> = shielded_outputs
                    .iter_mut()
                    .map(|out| out.witness_mut())
                    .collect();

                // Increment tree and witnesses
                let node = Node::from_cmu(&output.cmu);
                for witness in &mut *existing_witnesses {
                    witness.append(node).unwrap();
                }
                for witness in &mut block_witnesses {
                    witness.append(node).unwrap();
                }
                for witness in new_witnesses {
                    witness.append(node).unwrap();
                }
                tree.append(node).unwrap();

                if let Some(((note, _), account, nk)) = dec_output {
                    // A note is marked as "change" if the account that received it
                    // also spent notes in the same transaction. This will catch,
                    // for instance:
                    // - Change created by spending fractions of notes.
                    // - Notes created by consolidation transactions.
                    // - Notes sent from one account to itself.
                    let is_change = spent_from_accounts.contains(&account);
                    let witness = sapling::IncrementalWitness::from_tree(tree.clone());
                    let nf = K::sapling_nf(&nk, &note, &witness);

                    shielded_outputs.push(WalletSaplingOutput::from_parts(
                        index,
                        output.cmu,
                        output.ephemeral_key.clone(),
                        account,
                        note,
                        is_change,
                        witness,
                        nf,
                    ))
                }
            }
        }

        if !(shielded_spends.is_empty() && shielded_outputs.is_empty()) {
            wtxs.push(WalletTx {
                txid,
                index,
                sapling_spends: shielded_spends,
                sapling_outputs: shielded_outputs,
            });
        }
    }

    wtxs
}

#[cfg(test)]
mod tests {
    use group::{
        ff::{Field, PrimeField},
        GroupEncoding,
    };
    use rand_core::{OsRng, RngCore};
    use zcash_note_encryption::Domain;
    use zcash_primitives::{
        consensus::{BlockHeight, Network},
        constants::SPENDING_KEY_GENERATOR,
        memo::MemoBytes,
        sapling::{
            note_encryption::{sapling_note_encryption, PreparedIncomingViewingKey, SaplingDomain},
            util::generate_random_rseed,
            value::NoteValue,
            CommitmentTree, Note, Nullifier, SaplingIvk,
        },
        transaction::components::Amount,
        zip32::{AccountId, DiversifiableFullViewingKey, ExtendedSpendingKey},
    };

    use crate::{
        proto::compact_formats::{
            CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
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
    fn fake_compact_block(
        height: BlockHeight,
        nf: Nullifier,
        dfvk: &DiversifiableFullViewingKey,
        value: Amount,
        tx_after: bool,
    ) -> CompactBlock {
        let to = dfvk.default_address().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let rseed = generate_random_rseed(&Network::TestNetwork, height, &mut rng);
        let note = Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
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
                Nullifier([0; 32]),
                &dfvk,
                Amount::from_u64(5).unwrap(),
                false,
            );
            assert_eq!(cb.vtx.len(), 2);

            let mut tree = CommitmentTree::empty();
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

            let txs = scan_block_with_runner(
                &Network::TestNetwork,
                cb,
                &[(&account, &dfvk)],
                &[],
                &mut tree,
                &mut [],
                batch_runner.as_mut(),
            );
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.index, 1);
            assert_eq!(tx.sapling_spends.len(), 0);
            assert_eq!(tx.sapling_outputs.len(), 1);
            assert_eq!(tx.sapling_outputs[0].index(), 0);
            assert_eq!(tx.sapling_outputs[0].account(), account);
            assert_eq!(tx.sapling_outputs[0].note().value().inner(), 5);

            // Check that the witness root matches
            assert_eq!(tx.sapling_outputs[0].witness().root(), tree.root());
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
                Nullifier([0; 32]),
                &dfvk,
                Amount::from_u64(5).unwrap(),
                true,
            );
            assert_eq!(cb.vtx.len(), 3);

            let mut tree = CommitmentTree::empty();
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

            let txs = scan_block_with_runner(
                &Network::TestNetwork,
                cb,
                &[(&AccountId::from(0), &dfvk)],
                &[],
                &mut tree,
                &mut [],
                batch_runner.as_mut(),
            );
            assert_eq!(txs.len(), 1);

            let tx = &txs[0];
            assert_eq!(tx.index, 1);
            assert_eq!(tx.sapling_spends.len(), 0);
            assert_eq!(tx.sapling_outputs.len(), 1);
            assert_eq!(tx.sapling_outputs[0].index(), 0);
            assert_eq!(tx.sapling_outputs[0].account(), AccountId::from(0));
            assert_eq!(tx.sapling_outputs[0].note().value().inner(), 5);

            // Check that the witness root matches
            assert_eq!(tx.sapling_outputs[0].witness().root(), tree.root());
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

        let cb = fake_compact_block(1u32.into(), nf, &dfvk, Amount::from_u64(5).unwrap(), false);
        assert_eq!(cb.vtx.len(), 2);
        let vks: Vec<(&AccountId, &SaplingIvk)> = vec![];

        let mut tree = CommitmentTree::empty();
        let txs = scan_block(
            &Network::TestNetwork,
            cb,
            &vks[..],
            &[(account, nf)],
            &mut tree,
            &mut [],
        );
        assert_eq!(txs.len(), 1);

        let tx = &txs[0];
        assert_eq!(tx.index, 1);
        assert_eq!(tx.sapling_spends.len(), 1);
        assert_eq!(tx.sapling_outputs.len(), 0);
        assert_eq!(tx.sapling_spends[0].index(), 0);
        assert_eq!(tx.sapling_spends[0].nf(), &nf);
        assert_eq!(tx.sapling_spends[0].account(), account);
    }
}
