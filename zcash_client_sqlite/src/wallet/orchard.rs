#[cfg(test)]
pub(crate) mod tests {
    use incrementalmerkletree::{Hashable, Level};
    use orchard::{
        keys::{FullViewingKey, SpendingKey},
        note_encryption::OrchardDomain,
        tree::MerkleHashOrchard,
    };
    use shardtree::error::ShardTreeError;
    use zcash_client_backend::{
        data_api::{
            chain::CommitmentTreeRoot, DecryptedTransaction, WalletCommitmentTrees, WalletSummary,
        },
        wallet::{Note, ReceivedNote},
    };
    use zcash_keys::{
        address::{Address, UnifiedAddress},
        keys::UnifiedSpendingKey,
    };
    use zcash_note_encryption::try_output_recovery_with_ovk;
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, ShieldedProtocol};

    use crate::{
        error::SqliteClientError,
        testing::{
            self,
            pool::{OutputRecoveryError, ShieldedPoolTester},
            TestState,
        },
        wallet::commitment_tree,
        ORCHARD_TABLES_PREFIX,
    };

    pub(crate) struct OrchardPoolTester;
    impl ShieldedPoolTester for OrchardPoolTester {
        const SHIELDED_PROTOCOL: ShieldedProtocol = ShieldedProtocol::Orchard;
        const TABLES_PREFIX: &'static str = ORCHARD_TABLES_PREFIX;

        type Sk = SpendingKey;
        type Fvk = FullViewingKey;
        type MerkleTreeHash = MerkleHashOrchard;

        fn test_account_fvk<Cache>(st: &TestState<Cache>) -> Self::Fvk {
            st.test_account_orchard().unwrap()
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

        fn put_subtree_roots<Cache>(
            st: &mut TestState<Cache>,
            start_index: u64,
            roots: &[CommitmentTreeRoot<Self::MerkleTreeHash>],
        ) -> Result<(), ShardTreeError<commitment_tree::Error>> {
            st.wallet_mut()
                .put_orchard_subtree_roots(start_index, roots)
        }

        fn next_subtree_index(s: &WalletSummary<crate::AccountId>) -> u64 {
            todo!()
        }

        fn select_spendable_notes<Cache>(
            st: &TestState<Cache>,
            account: crate::AccountId,
            target_value: zcash_protocol::value::Zatoshis,
            anchor_height: BlockHeight,
            exclude: &[crate::ReceivedNoteId],
        ) -> Result<Vec<ReceivedNote<crate::ReceivedNoteId, Note>>, SqliteClientError> {
            todo!()
        }

        fn decrypted_pool_outputs_count(
            d_tx: &DecryptedTransaction<'_, crate::AccountId>,
        ) -> usize {
            d_tx.orchard_outputs().len()
        }

        fn with_decrypted_pool_memos(
            d_tx: &DecryptedTransaction<'_, crate::AccountId>,
            mut f: impl FnMut(&MemoBytes),
        ) {
            for output in d_tx.orchard_outputs() {
                f(output.memo());
            }
        }

        fn try_output_recovery<Cache>(
            _: &TestState<Cache>,
            _: BlockHeight,
            tx: &Transaction,
            fvk: &Self::Fvk,
        ) -> Result<Option<(Note, Address, MemoBytes)>, OutputRecoveryError> {
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
                    return Ok(result.map(|(note, addr, memo)| {
                        (
                            Note::Orchard(note),
                            UnifiedAddress::from_receivers(Some(addr), None, None)
                                .unwrap()
                                .into(),
                            MemoBytes::from_bytes(&memo).expect("correct length"),
                        )
                    }));
                }
            }

            Ok(None)
        }
    }

    #[test]
    fn send_single_step_proposed_transfer() {
        testing::pool::send_single_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn send_multi_step_proposed_transfer() {
        testing::pool::send_multi_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    #[allow(deprecated)]
    fn create_to_address_fails_on_incorrect_usk() {
        testing::pool::create_to_address_fails_on_incorrect_usk::<OrchardPoolTester>()
    }

    #[test]
    #[allow(deprecated)]
    fn proposal_fails_with_no_blocks() {
        testing::pool::proposal_fails_with_no_blocks::<OrchardPoolTester>()
    }

    #[test]
    fn spend_fails_on_unverified_notes() {
        testing::pool::spend_fails_on_unverified_notes::<OrchardPoolTester>()
    }

    #[test]
    fn spend_fails_on_locked_notes() {
        testing::pool::spend_fails_on_locked_notes::<OrchardPoolTester>()
    }

    #[test]
    fn ovk_policy_prevents_recovery_from_chain() {
        testing::pool::ovk_policy_prevents_recovery_from_chain::<OrchardPoolTester>()
    }

    #[test]
    fn spend_succeeds_to_t_addr_zero_change() {
        testing::pool::spend_succeeds_to_t_addr_zero_change::<OrchardPoolTester>()
    }

    #[test]
    fn change_note_spends_succeed() {
        testing::pool::change_note_spends_succeed::<OrchardPoolTester>()
    }

    #[test]
    fn external_address_change_spends_detected_in_restore_from_seed() {
        testing::pool::external_address_change_spends_detected_in_restore_from_seed::<
            OrchardPoolTester,
        >()
    }

    #[test]
    fn zip317_spend() {
        testing::pool::zip317_spend::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn shield_transparent() {
        testing::pool::shield_transparent::<OrchardPoolTester>()
    }

    #[test]
    fn birthday_in_anchor_shard() {
        testing::pool::birthday_in_anchor_shard::<OrchardPoolTester>()
    }

    #[test]
    fn checkpoint_gaps() {
        testing::pool::checkpoint_gaps::<OrchardPoolTester>()
    }
}
