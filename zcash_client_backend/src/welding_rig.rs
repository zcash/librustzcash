//! Tools for scanning a compact representation of the Zcash block chain.

use ff::PrimeField;
use std::collections::HashSet;
use std::convert::TryFrom;
use subtle::{ConditionallySelectable, ConstantTimeEq, CtOption};
use zcash_note_encryption::batch;
use zcash_primitives::{
    consensus,
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::{
        self,
        keys::{DiversifiableFullViewingKey, Scope},
        note_encryption::SaplingDomain,
        Node, Note, Nullifier, NullifierDerivingKey, SaplingIvk,
    },
    transaction::components::sapling::CompactOutputDescription,
    zip32::{AccountId, ExtendedFullViewingKey},
};

use crate::proto::compact_formats::CompactBlock;
use crate::wallet::{WalletShieldedOutput, WalletShieldedSpend, WalletTx};

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
    /// The type of key that is used to decrypt Sapling outputs;
    type SaplingNk;

    type SaplingKeys: IntoIterator<Item = (SaplingIvk, Self::SaplingNk)>;

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
        witness: &IncrementalWitness<Node>,
    ) -> Self::Nf;
}

impl ScanningKey for DiversifiableFullViewingKey {
    type SaplingNk = NullifierDerivingKey;
    type SaplingKeys = [(SaplingIvk, Self::SaplingNk); 2];
    type Nf = sapling::Nullifier;

    fn to_sapling_keys(&self) -> Self::SaplingKeys {
        [
            (self.to_ivk(Scope::External), self.to_nk(Scope::External)),
            (self.to_ivk(Scope::Internal), self.to_nk(Scope::Internal)),
        ]
    }

    fn sapling_nf(
        key: &Self::SaplingNk,
        note: &Note,
        witness: &IncrementalWitness<Node>,
    ) -> Self::Nf {
        note.nf(key, witness.position() as u64)
    }
}

/// The [`ScanningKey`] implementation for [`ExtendedFullViewingKey`]s.
/// Nullifiers may be derived when scanning with these keys.
///
/// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
impl ScanningKey for ExtendedFullViewingKey {
    type SaplingNk = NullifierDerivingKey;
    type SaplingKeys = [(SaplingIvk, Self::SaplingNk); 1];
    type Nf = sapling::Nullifier;

    fn to_sapling_keys(&self) -> Self::SaplingKeys {
        [(self.fvk.vk.ivk(), self.fvk.vk.nk)]
    }

    fn sapling_nf(
        key: &Self::SaplingNk,
        note: &Note,
        witness: &IncrementalWitness<Node>,
    ) -> Self::Nf {
        note.nf(key, witness.position() as u64)
    }
}

/// The [`ScanningKey`] implementation for [`SaplingIvk`]s.
/// Nullifiers cannot be derived when scanning with these keys.
///
/// [`SaplingIvk`]: zcash_primitives::sapling::SaplingIvk
impl ScanningKey for SaplingIvk {
    type SaplingNk = ();
    type SaplingKeys = [(SaplingIvk, Self::SaplingNk); 1];
    type Nf = ();

    fn to_sapling_keys(&self) -> Self::SaplingKeys {
        [(self.clone(), ())]
    }

    fn sapling_nf(_key: &Self::SaplingNk, _note: &Note, _witness: &IncrementalWitness<Node>) {}
}

/// Scans a [`CompactBlock`] with a set of [`ScanningKey`]s.
///
/// Returns a vector of [`WalletTx`]s belonging to any of the given
/// [`ScanningKey`]s. If scanning with a full viewing key, the nullifiers
/// of the resulting [`WalletShieldedOutput`]s will also be computed.
///
/// The given [`CommitmentTree`] and existing [`IncrementalWitness`]es are
/// incremented appropriately.
///
/// The implementation of [`ScanningKey`] may either support or omit the computation of
/// the nullifiers for received notes; the implementation for [`ExtendedFullViewingKey`]
/// will derive the nullifiers for received notes and return them as part of the resulting
/// [`WalletShieldedOutput`]s, whereas the implementation for [`SaplingIvk`] cannot
/// do so and will return the unit value in those outputs instead.
///
/// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
/// [`SaplingIvk`]: zcash_primitives::sapling::SaplingIvk
/// [`CompactBlock`]: crate::proto::compact_formats::CompactBlock
/// [`ScanningKey`]: crate::welding_rig::ScanningKey
/// [`CommitmentTree`]: zcash_primitives::merkle_tree::CommitmentTree
/// [`IncrementalWitness`]: zcash_primitives::merkle_tree::IncrementalWitness
/// [`WalletShieldedOutput`]: crate::wallet::WalletShieldedOutput
/// [`WalletTx`]: crate::wallet::WalletTx
pub fn scan_block<P: consensus::Parameters, K: ScanningKey>(
    params: &P,
    block: CompactBlock,
    vks: &[(&AccountId, &K)],
    nullifiers: &[(AccountId, Nullifier)],
    tree: &mut CommitmentTree<Node>,
    existing_witnesses: &mut [&mut IncrementalWitness<Node>],
) -> Vec<WalletTx<K::Nf>> {
    let mut wtxs: Vec<WalletTx<K::Nf>> = vec![];
    let block_height = block.height();

    for tx in block.vtx.into_iter() {
        let txid = tx.txid();
        let index = tx.index as usize;
        let num_spends = tx.spends.len();
        let num_outputs = tx.outputs.len();

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
                    .map(|account| WalletShieldedSpend {
                        index,
                        nf: spend_nf,
                        account,
                    })
            })
            .filter(|spend| spend.is_some().into())
            .map(|spend| spend.unwrap())
            .collect();

        // Collect the set of accounts that were spent from in this transaction
        let spent_from_accounts: HashSet<_> =
            shielded_spends.iter().map(|spend| spend.account).collect();

        // Check for incoming notes while incrementing tree and witnesses
        let mut shielded_outputs: Vec<WalletShieldedOutput<K::Nf>> = vec![];
        {
            // Grab mutable references to new witnesses from previous transactions
            // in this block so that we can update them. Scoped so we don't hold
            // mutable references to wtxs for too long.
            let mut block_witnesses: Vec<_> = wtxs
                .iter_mut()
                .flat_map(|tx| {
                    tx.shielded_outputs
                        .iter_mut()
                        .map(|output| &mut output.witness)
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

            let vks = vks
                .iter()
                .flat_map(|(a, k)| {
                    k.to_sapling_keys()
                        .into_iter()
                        .map(move |(ivk, nk)| (**a, ivk, nk))
                })
                .collect::<Vec<_>>();

            let ivks = vks
                .iter()
                .map(|(_, ivk, _)| (*ivk).clone())
                .collect::<Vec<_>>();

            let decrypted = batch::try_compact_note_decryption(&ivks, decoded);

            for (index, ((_, output), dec_output)) in decoded.iter().zip(decrypted).enumerate() {
                // Grab mutable references to new witnesses from previous outputs
                // in this transaction so that we can update them. Scoped so we
                // don't hold mutable references to shielded_outputs for too long.
                let new_witnesses: Vec<_> = shielded_outputs
                    .iter_mut()
                    .map(|out| &mut out.witness)
                    .collect();

                // Increment tree and witnesses
                let node = Node::new(output.cmu.to_repr());
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

                if let Some(((note, to), ivk_idx)) = dec_output {
                    // A note is marked as "change" if the account that received it
                    // also spent notes in the same transaction. This will catch,
                    // for instance:
                    // - Change created by spending fractions of notes.
                    // - Notes created by consolidation transactions.
                    // - Notes sent from one account to itself.
                    let (account, _, nk) = &vks[ivk_idx];
                    let is_change = spent_from_accounts.contains(account);
                    let witness = IncrementalWitness::from_tree(tree);
                    let nf = K::sapling_nf(nk, &note, &witness);

                    shielded_outputs.push(WalletShieldedOutput {
                        index,
                        cmu: output.cmu,
                        ephemeral_key: output.ephemeral_key.clone(),
                        account: *account,
                        note,
                        to,
                        is_change,
                        witness,
                        nf,
                    })
                }
            }
        }

        if !(shielded_spends.is_empty() && shielded_outputs.is_empty()) {
            wtxs.push(WalletTx {
                txid,
                index,
                num_spends,
                num_outputs,
                shielded_spends,
                shielded_outputs,
            });
        }
    }

    wtxs
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use group::GroupEncoding;
    use rand_core::{OsRng, RngCore};
    use zcash_primitives::{
        consensus::{BlockHeight, Network},
        constants::SPENDING_KEY_GENERATOR,
        memo::MemoBytes,
        merkle_tree::CommitmentTree,
        sapling::{
            note_encryption::sapling_note_encryption, util::generate_random_rseed, Note, Nullifier,
            SaplingIvk,
        },
        transaction::components::Amount,
        zip32::{AccountId, ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use super::scan_block;
    use crate::proto::compact_formats::{
        CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
    };

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
        let mut cspend = CompactSaplingSpend::new();
        cspend.set_nf(fake_nf);
        let mut cout = CompactSaplingOutput::new();
        cout.set_cmu(fake_cmu);
        cout.set_ephemeralKey(fake_epk);
        cout.set_ciphertext(vec![0; 52]);
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
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
        extfvk: ExtendedFullViewingKey,
        value: Amount,
        tx_after: bool,
    ) -> CompactBlock {
        let to = extfvk.default_address().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let rseed = generate_random_rseed(&Network::TestNetwork, height, &mut rng);
        let note = Note {
            g_d: to.diversifier().g_d().unwrap(),
            pk_d: *to.pk_d(),
            value: value.into(),
            rseed,
        };
        let encryptor = sapling_note_encryption::<_, Network>(
            Some(extfvk.fvk.ovk),
            note.clone(),
            to,
            MemoBytes::empty(),
            &mut rng,
        );
        let cmu = note.cmu().to_repr().as_ref().to_owned();
        let epk = encryptor.epk().to_bytes().to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let mut cb = CompactBlock::new();
        cb.set_height(height.into());

        // Add a random Sapling tx before ours
        {
            let mut tx = random_compact_tx(&mut rng);
            tx.index = cb.vtx.len() as u64;
            cb.vtx.push(tx);
        }

        let mut cspend = CompactSaplingSpend::new();
        cspend.set_nf(nf.0.to_vec());
        let mut cout = CompactSaplingOutput::new();
        cout.set_cmu(cmu);
        cout.set_ephemeralKey(epk);
        cout.set_ciphertext(enc_ciphertext.as_ref()[..52].to_vec());
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
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
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);

        let cb = fake_compact_block(
            1u32.into(),
            Nullifier([0; 32]),
            extfvk.clone(),
            Amount::from_u64(5).unwrap(),
            false,
        );
        assert_eq!(cb.vtx.len(), 2);

        let mut tree = CommitmentTree::empty();
        let txs = scan_block(
            &Network::TestNetwork,
            cb,
            &[(&AccountId::from(0), &extfvk)],
            &[],
            &mut tree,
            &mut [],
        );
        assert_eq!(txs.len(), 1);

        let tx = &txs[0];
        assert_eq!(tx.index, 1);
        assert_eq!(tx.num_spends, 1);
        assert_eq!(tx.num_outputs, 1);
        assert_eq!(tx.shielded_spends.len(), 0);
        assert_eq!(tx.shielded_outputs.len(), 1);
        assert_eq!(tx.shielded_outputs[0].index, 0);
        assert_eq!(tx.shielded_outputs[0].account, AccountId::from(0));
        assert_eq!(tx.shielded_outputs[0].note.value, 5);

        // Check that the witness root matches
        assert_eq!(tx.shielded_outputs[0].witness.root(), tree.root());
    }

    #[test]
    fn scan_block_with_txs_after_my_tx() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);

        let cb = fake_compact_block(
            1u32.into(),
            Nullifier([0; 32]),
            extfvk.clone(),
            Amount::from_u64(5).unwrap(),
            true,
        );
        assert_eq!(cb.vtx.len(), 3);

        let mut tree = CommitmentTree::empty();
        let txs = scan_block(
            &Network::TestNetwork,
            cb,
            &[(&AccountId::from(0), &extfvk)],
            &[],
            &mut tree,
            &mut [],
        );
        assert_eq!(txs.len(), 1);

        let tx = &txs[0];
        assert_eq!(tx.index, 1);
        assert_eq!(tx.num_spends, 1);
        assert_eq!(tx.num_outputs, 1);
        assert_eq!(tx.shielded_spends.len(), 0);
        assert_eq!(tx.shielded_outputs.len(), 1);
        assert_eq!(tx.shielded_outputs[0].index, 0);
        assert_eq!(tx.shielded_outputs[0].account, AccountId::from(0));
        assert_eq!(tx.shielded_outputs[0].note.value, 5);

        // Check that the witness root matches
        assert_eq!(tx.shielded_outputs[0].witness.root(), tree.root());
    }

    #[test]
    fn scan_block_with_my_spend() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let nf = Nullifier([7; 32]);
        let account = AccountId::from(12);

        let cb = fake_compact_block(1u32.into(), nf, extfvk, Amount::from_u64(5).unwrap(), false);
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
        assert_eq!(tx.num_spends, 1);
        assert_eq!(tx.num_outputs, 1);
        assert_eq!(tx.shielded_spends.len(), 1);
        assert_eq!(tx.shielded_outputs.len(), 0);
        assert_eq!(tx.shielded_spends[0].index, 0);
        assert_eq!(tx.shielded_spends[0].nf, nf);
        assert_eq!(tx.shielded_spends[0].account, account);
    }
}
