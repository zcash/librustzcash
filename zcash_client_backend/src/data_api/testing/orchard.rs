use std::hash::Hash;

use ::orchard::{
    keys::{FullViewingKey, SpendingKey},
    note_encryption::OrchardDomain,
    tree::MerkleHashOrchard,
};
use incrementalmerkletree::{Hashable, Level};
use shardtree::error::ShardTreeError;

use zcash_keys::{
    address::{Address, UnifiedAddress},
    keys::UnifiedSpendingKey,
};
use zcash_note_encryption::try_output_recovery_with_ovk;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    value::TargetValue,
    ShieldedProtocol,
};

use crate::{
    data_api::{
        chain::{CommitmentTreeRoot, ScanSummary},
        testing::{pool::ShieldedPoolTester, TestState},
        DecryptedTransaction, InputSource, WalletCommitmentTrees, WalletSummary, WalletTest,
    },
    wallet::{Note, ReceivedNote},
};

/// Type for running pool-agnostic tests on the Orchard pool.
pub struct OrchardPoolTester;
impl ShieldedPoolTester for OrchardPoolTester {
    const SHIELDED_PROTOCOL: ShieldedProtocol = ShieldedProtocol::Orchard;
    // const MERKLE_TREE_DEPTH: u8 = {orchard::NOTE_COMMITMENT_TREE_DEPTH as u8};

    type Sk = SpendingKey;
    type Fvk = FullViewingKey;
    type MerkleTreeHash = MerkleHashOrchard;
    type Note = orchard::note::Note;

    fn test_account_fvk<Cache, DbT: WalletTest, P: consensus::Parameters>(
        st: &TestState<Cache, DbT, P>,
    ) -> Self::Fvk {
        st.test_account_orchard().unwrap().clone()
    }

    fn usk_to_sk(usk: &UnifiedSpendingKey) -> &Self::Sk {
        usk.orchard()
    }

    fn sk(seed: &[u8]) -> Self::Sk {
        let mut account = zip32::AccountId::ZERO;
        loop {
            if let Ok(sk) = SpendingKey::from_zip32_seed(seed, 1, account) {
                break sk;
            }
            account = account.next().unwrap();
        }
    }

    fn sk_to_fvk(sk: &Self::Sk) -> Self::Fvk {
        sk.into()
    }

    fn sk_default_address(sk: &Self::Sk) -> Address {
        Self::fvk_default_address(&Self::sk_to_fvk(sk))
    }

    fn fvk_default_address(fvk: &Self::Fvk) -> Address {
        UnifiedAddress::from_receivers(
            Some(fvk.address_at(0u32, zip32::Scope::External)),
            None,
            None,
        )
        .unwrap()
        .into()
    }

    fn fvks_equal(a: &Self::Fvk, b: &Self::Fvk) -> bool {
        a == b
    }

    fn empty_tree_leaf() -> Self::MerkleTreeHash {
        MerkleHashOrchard::empty_leaf()
    }

    fn empty_tree_root(level: Level) -> Self::MerkleTreeHash {
        MerkleHashOrchard::empty_root(level)
    }

    fn put_subtree_roots<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        start_index: u64,
        roots: &[CommitmentTreeRoot<Self::MerkleTreeHash>],
    ) -> Result<(), ShardTreeError<<DbT as WalletCommitmentTrees>::Error>> {
        st.wallet_mut()
            .put_orchard_subtree_roots(start_index, roots)
    }

    fn next_subtree_index<A: Hash + Eq>(s: &WalletSummary<A>) -> u64 {
        s.next_orchard_subtree_index()
    }

    fn select_spendable_notes<Cache, DbT: InputSource + WalletTest, P>(
        st: &TestState<Cache, DbT, P>,
        account: <DbT as InputSource>::AccountId,
        target_value: TargetValue,
        anchor_height: BlockHeight,
        exclude: &[DbT::NoteRef],
    ) -> Result<Vec<ReceivedNote<DbT::NoteRef, Self::Note>>, <DbT as InputSource>::Error> {
        st.wallet()
            .select_spendable_notes(
                account,
                target_value,
                &[ShieldedProtocol::Orchard],
                anchor_height,
                exclude,
            )
            .map(|n| n.take_orchard())
    }

    fn decrypted_pool_outputs_count<A>(d_tx: &DecryptedTransaction<'_, A>) -> usize {
        d_tx.orchard_outputs().len()
    }

    fn with_decrypted_pool_memos<A>(
        d_tx: &DecryptedTransaction<'_, A>,
        mut f: impl FnMut(&MemoBytes),
    ) {
        for output in d_tx.orchard_outputs() {
            f(output.memo());
        }
    }

    fn try_output_recovery<P: consensus::Parameters>(
        _params: &P,
        _: BlockHeight,
        tx: &Transaction,
        fvk: &Self::Fvk,
    ) -> Option<(Note, Address, MemoBytes)> {
        for action in tx.orchard_bundle().unwrap().actions() {
            // Find the output that decrypts with the external OVK
            let result = try_output_recovery_with_ovk(
                &OrchardDomain::for_action(action),
                &fvk.to_ovk(zip32::Scope::External),
                action,
                action.cv_net(),
                &action.encrypted_note().out_ciphertext,
            );

            if result.is_some() {
                return result.map(|(note, addr, memo)| {
                    (
                        Note::Orchard(note),
                        UnifiedAddress::from_receivers(Some(addr), None, None)
                            .unwrap()
                            .into(),
                        MemoBytes::from_bytes(&memo).expect("correct length"),
                    )
                });
            }
        }

        None
    }

    fn received_note_count(summary: &ScanSummary) -> usize {
        summary.received_orchard_note_count()
    }

    #[cfg(feature = "pczt")]
    fn add_proof_generation_keys(
        pczt: pczt::Pczt,
        _: &UnifiedSpendingKey,
    ) -> Result<pczt::Pczt, pczt::roles::updater::SaplingError> {
        // No-op; Orchard doesn't have proof generation keys.
        Ok(pczt)
    }

    #[cfg(feature = "pczt")]
    fn apply_signatures_to_pczt(
        signer: &mut pczt::roles::signer::Signer,
        usk: &UnifiedSpendingKey,
    ) -> Result<(), pczt::roles::signer::Error> {
        let sk = Self::usk_to_sk(usk);
        let ask = orchard::keys::SpendAuthorizingKey::from(sk);

        // Figuring out which one is for us is hard. Let's just try signing all of them!
        for index in 0.. {
            match signer.sign_orchard(index, &ask) {
                // Loop termination.
                Err(pczt::roles::signer::Error::InvalidIndex) => break,
                // Ignore any errors due to using the wrong key.
                Ok(())
                | Err(pczt::roles::signer::Error::OrchardSign(
                    orchard::pczt::SignerError::WrongSpendAuthorizingKey,
                )) => Ok(()),
                // Raise any unexpected errors.
                Err(e) => Err(e),
            }?;
        }

        Ok(())
    }
}
