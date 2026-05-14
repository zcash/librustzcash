use std::hash::Hash;

use group::ff::Field;
use incrementalmerkletree::{
    Address as TreeAddress, Hashable, Level, Position, Retention,
    frontier::{Frontier, NonEmptyFrontier},
};
use rand::RngCore;
use sapling::{
    note_encryption::try_sapling_output_recovery,
    zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey},
};
use shardtree::error::ShardTreeError;
use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, components::sapling::zip212_enforcement};
use zcash_protocol::{
    ShieldedProtocol,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    value::Zatoshis,
};
use zip32::Scope;

use crate::{
    data_api::{
        DecryptedTransaction, InputSource, TargetValue, WalletCommitmentTrees, WalletSummary,
        WalletTest,
        chain::{self, CommitmentTreeRoot, ScanSummary},
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::{Note, ReceivedNote},
};

use super::{TestState, pool::ShieldedPoolTester};

/// Type for running pool-agnostic tests on the Sapling pool.
pub struct SaplingPoolTester;
impl ShieldedPoolTester for SaplingPoolTester {
    const SHIELDED_PROTOCOL: ShieldedProtocol = ShieldedProtocol::Sapling;
    const SHARD_HEIGHT: u8 = crate::data_api::SAPLING_SHARD_HEIGHT;

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

    fn shard_root<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        shard_index: u64,
    ) -> Result<Self::MerkleTreeHash, ShardTreeError<<DbT as WalletCommitmentTrees>::Error>> {
        use incrementalmerkletree::Position;
        let shard_height = crate::data_api::SAPLING_SHARD_HEIGHT;
        let addr = TreeAddress::from_parts(Level::from(shard_height), shard_index);
        let end_position = Position::from((shard_index + 1) << shard_height);
        st.wallet_mut()
            .with_sapling_tree_mut(|tree| tree.root(addr, end_position))
    }

    fn insert_subtree_stub<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        addr: TreeAddress,
        hash: Self::MerkleTreeHash,
    ) -> Result<(), ShardTreeError<<DbT as WalletCommitmentTrees>::Error>> {
        st.wallet_mut()
            .with_sapling_tree_mut(|tree| tree.insert(addr, hash))
    }

    fn random_subtree_hash(mut rng: impl RngCore) -> Self::MerkleTreeHash {
        ::sapling::Node::from_scalar(bls12_381::Scalar::random(&mut rng))
    }

    fn read_tree_root<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        addr: TreeAddress,
        truncate_at: Position,
    ) -> Result<Self::MerkleTreeHash, ShardTreeError<<DbT as WalletCommitmentTrees>::Error>> {
        st.wallet_mut()
            .with_sapling_tree_mut(|tree| tree.root(addr, truncate_at))
    }

    fn insert_frontier_into_tree<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        frontier: NonEmptyFrontier<Self::MerkleTreeHash>,
        leaf_retention: Retention<BlockHeight>,
    ) -> Result<(), ShardTreeError<<DbT as WalletCommitmentTrees>::Error>> {
        let frontier_ref = &frontier;
        st.wallet_mut().with_sapling_tree_mut(|tree| {
            tree.insert_frontier_nodes(frontier_ref.clone(), leaf_retention)
        })
    }

    fn pool_frontier_in_chain_state(
        chain_state: &chain::ChainState,
    ) -> Frontier<Self::MerkleTreeHash, { super::shard_stub::NOTE_COMMITMENT_TREE_DEPTH }> {
        chain_state.final_sapling_tree().clone()
    }

    fn build_chain_state_with_pool_frontier(
        block_height: BlockHeight,
        block_hash: BlockHash,
        pool_frontier: Frontier<
            Self::MerkleTreeHash,
            { super::shard_stub::NOTE_COMMITMENT_TREE_DEPTH },
        >,
        other_pools_chain_state: &chain::ChainState,
    ) -> chain::ChainState {
        chain::ChainState::new(
            block_height,
            block_hash,
            pool_frontier,
            #[cfg(feature = "orchard")]
            other_pools_chain_state.final_orchard_tree().clone(),
        )
    }

    fn next_subtree_index<A: Hash + Eq>(s: &WalletSummary<A>) -> u64 {
        s.next_sapling_subtree_index()
    }

    fn note_value(note: &Self::Note) -> Zatoshis {
        Zatoshis::const_from_u64(note.value().inner())
    }

    fn select_spendable_notes<Cache, DbT: InputSource + WalletTest, P>(
        st: &TestState<Cache, DbT, P>,
        account: <DbT as InputSource>::AccountId,
        target_value: TargetValue,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[DbT::NoteRef],
    ) -> Result<Vec<ReceivedNote<DbT::NoteRef, Self::Note>>, <DbT as InputSource>::Error> {
        st.wallet()
            .select_spendable_notes(
                account,
                target_value,
                &[ShieldedProtocol::Sapling],
                target_height,
                confirmations_policy,
                exclude,
            )
            .map(|n| n.take_sapling())
    }

    fn select_unspent_notes<Cache, DbT: InputSource + WalletTest, P>(
        st: &TestState<Cache, DbT, P>,
        account: <DbT as InputSource>::AccountId,
        target_height: TargetHeight,
        exclude: &[DbT::NoteRef],
    ) -> Result<Vec<ReceivedNote<DbT::NoteRef, Self::Note>>, <DbT as InputSource>::Error> {
        st.wallet()
            .select_unspent_notes(
                account,
                &[ShieldedProtocol::Sapling],
                target_height,
                exclude,
            )
            .map(|n| n.take_sapling())
    }

    fn decrypted_pool_outputs_count<A>(d_tx: &DecryptedTransaction<Transaction, A>) -> usize {
        d_tx.sapling_outputs().len()
    }

    fn with_decrypted_pool_memos<A>(
        d_tx: &DecryptedTransaction<Transaction, A>,
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

    #[cfg(feature = "pczt")]
    fn add_proof_generation_keys(
        pczt: pczt::Pczt,
        usk: &UnifiedSpendingKey,
    ) -> Result<pczt::Pczt, pczt::roles::updater::SaplingError> {
        let extsk = Self::usk_to_sk(usk);

        Ok(pczt::roles::updater::Updater::new(pczt)
            .update_sapling_with(|mut updater| {
                let non_dummy_spends = updater
                    .bundle()
                    .spends()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, spend)| {
                        // Dummy spends will already have a proof generation key.
                        spend.proof_generation_key().is_none().then_some(index)
                    })
                    .collect::<Vec<_>>();

                // Assume all non-dummy spent notes are from the same account.
                for index in non_dummy_spends {
                    updater.update_spend_with(index, |mut spend_updater| {
                        spend_updater.set_proof_generation_key(extsk.expsk.proof_generation_key())
                    })?;
                }

                Ok(())
            })?
            .finish())
    }

    #[cfg(feature = "pczt")]
    fn apply_signatures_to_pczt(
        signer: &mut pczt::roles::signer::Signer,
        usk: &UnifiedSpendingKey,
    ) -> Result<(), pczt::roles::signer::Error> {
        let extsk = Self::usk_to_sk(usk);

        // Figuring out which one is for us is hard. Let's just try signing all of them!
        for index in 0.. {
            match signer.sign_sapling(index, &extsk.expsk.ask) {
                // Loop termination.
                Err(pczt::roles::signer::Error::InvalidIndex) => break,
                // Ignore any errors due to using the wrong key.
                Ok(())
                | Err(pczt::roles::signer::Error::SaplingSign(
                    sapling::pczt::SignerError::WrongSpendAuthorizingKey,
                )) => Ok(()),
                // Raise any unexpected errors.
                Err(e) => Err(e),
            }?;
        }

        Ok(())
    }
}
