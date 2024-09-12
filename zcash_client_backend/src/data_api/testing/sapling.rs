use std::hash::Hash;

use incrementalmerkletree::{Hashable, Level};
use sapling::{
    note_encryption::try_sapling_output_recovery,
    zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey},
};
use shardtree::error::ShardTreeError;
use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_primitives::transaction::{components::sapling::zip212_enforcement, Transaction};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    value::Zatoshis,
    ShieldedProtocol,
};
use zip32::Scope;

use crate::{
    data_api::{
        chain::{CommitmentTreeRoot, ScanSummary},
        DecryptedTransaction, InputSource, WalletCommitmentTrees, WalletSummary, WalletTest,
    },
    wallet::{Note, ReceivedNote},
};

use super::{pool::ShieldedPoolTester, TestState};

pub struct SaplingPoolTester;
impl ShieldedPoolTester for SaplingPoolTester {
    const SHIELDED_PROTOCOL: ShieldedProtocol = ShieldedProtocol::Sapling;
    // const MERKLE_TREE_DEPTH: u8 = sapling::NOTE_COMMITMENT_TREE_DEPTH;

    type Sk = ExtendedSpendingKey;
    type Fvk = DiversifiableFullViewingKey;
    type MerkleTreeHash = sapling::Node;
    type Note = sapling::Note;

    fn test_account_fvk<Cache, DbT: WalletTest, P: consensus::Parameters>(
        st: &TestState<Cache, DbT, P>,
    ) -> Self::Fvk {
        st.test_account_sapling().unwrap().clone()
    }

    fn usk_to_sk(usk: &UnifiedSpendingKey) -> &Self::Sk {
        usk.sapling()
    }

    fn sk(seed: &[u8]) -> Self::Sk {
        ExtendedSpendingKey::master(seed)
    }

    fn sk_to_fvk(sk: &Self::Sk) -> Self::Fvk {
        sk.to_diversifiable_full_viewing_key()
    }

    fn sk_default_address(sk: &Self::Sk) -> Address {
        sk.default_address().1.into()
    }

    fn fvk_default_address(fvk: &Self::Fvk) -> Address {
        fvk.default_address().1.into()
    }

    fn fvks_equal(a: &Self::Fvk, b: &Self::Fvk) -> bool {
        a.to_bytes() == b.to_bytes()
    }

    fn empty_tree_leaf() -> Self::MerkleTreeHash {
        ::sapling::Node::empty_leaf()
    }

    fn empty_tree_root(level: Level) -> Self::MerkleTreeHash {
        ::sapling::Node::empty_root(level)
    }

    fn put_subtree_roots<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        start_index: u64,
        roots: &[CommitmentTreeRoot<Self::MerkleTreeHash>],
    ) -> Result<(), ShardTreeError<<DbT as WalletCommitmentTrees>::Error>> {
        st.wallet_mut()
            .put_sapling_subtree_roots(start_index, roots)
    }

    fn next_subtree_index<A: Hash + Eq>(s: &WalletSummary<A>) -> u64 {
        s.next_sapling_subtree_index()
    }

    fn select_spendable_notes<Cache, DbT: InputSource + WalletTest, P>(
        st: &TestState<Cache, DbT, P>,
        account: <DbT as InputSource>::AccountId,
        target_value: Zatoshis,
        anchor_height: BlockHeight,
        exclude: &[DbT::NoteRef],
    ) -> Result<Vec<ReceivedNote<DbT::NoteRef, Self::Note>>, <DbT as InputSource>::Error> {
        st.wallet()
            .select_spendable_notes(
                account,
                target_value,
                &[ShieldedProtocol::Sapling],
                anchor_height,
                exclude,
            )
            .map(|n| n.take_sapling())
    }

    fn decrypted_pool_outputs_count<A>(d_tx: &DecryptedTransaction<'_, A>) -> usize {
        d_tx.sapling_outputs().len()
    }

    fn with_decrypted_pool_memos<A>(
        d_tx: &DecryptedTransaction<'_, A>,
        mut f: impl FnMut(&MemoBytes),
    ) {
        for output in d_tx.sapling_outputs() {
            f(output.memo());
        }
    }

    fn try_output_recovery<P: consensus::Parameters>(
        params: &P,
        height: BlockHeight,
        tx: &Transaction,
        fvk: &Self::Fvk,
    ) -> Option<(Note, Address, MemoBytes)> {
        for output in tx.sapling_bundle().unwrap().shielded_outputs() {
            // Find the output that decrypts with the external OVK
            let result = try_sapling_output_recovery(
                &fvk.to_ovk(Scope::External),
                output,
                zip212_enforcement(params, height),
            );

            if result.is_some() {
                return result.map(|(note, addr, memo)| {
                    (
                        Note::Sapling(note),
                        addr.into(),
                        MemoBytes::from_bytes(&memo).expect("correct length"),
                    )
                });
            }
        }

        None
    }

    fn received_note_count(summary: &ScanSummary) -> usize {
        summary.received_sapling_note_count()
    }
}
