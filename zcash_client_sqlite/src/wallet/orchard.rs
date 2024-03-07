use incrementalmerkletree::Position;
use rusqlite::{named_params, Connection};

use zcash_client_backend::{wallet::WalletOrchardOutput, DecryptedOutput, TransferType};
use zcash_protocol::memo::MemoBytes;
use zip32::Scope;

use crate::{error::SqliteClientError, AccountId};

use super::{memo_repr, scope_code};

/// This trait provides a generalization over shielded output representations.
pub(crate) trait ReceivedOrchardOutput {
    fn index(&self) -> usize;
    fn account_id(&self) -> AccountId;
    fn note(&self) -> &orchard::note::Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> bool;
    fn nullifier(&self) -> Option<&orchard::note::Nullifier>;
    fn note_commitment_tree_position(&self) -> Option<Position>;
    fn recipient_key_scope(&self) -> Option<Scope>;
}

impl ReceivedOrchardOutput for WalletOrchardOutput<AccountId> {
    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> AccountId {
        *WalletOrchardOutput::account_id(self)
    }
    fn note(&self) -> &orchard::note::Note {
        WalletOrchardOutput::note(self)
    }
    fn memo(&self) -> Option<&MemoBytes> {
        None
    }
    fn is_change(&self) -> bool {
        WalletOrchardOutput::is_change(self)
    }
    fn nullifier(&self) -> Option<&orchard::note::Nullifier> {
        self.nf()
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        Some(WalletOrchardOutput::note_commitment_tree_position(self))
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        self.recipient_key_scope()
    }
}

impl ReceivedOrchardOutput for DecryptedOutput<orchard::note::Note, AccountId> {
    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> AccountId {
        *self.account()
    }
    fn note(&self) -> &orchard::note::Note {
        self.note()
    }
    fn memo(&self) -> Option<&MemoBytes> {
        Some(self.memo())
    }
    fn is_change(&self) -> bool {
        self.transfer_type() == TransferType::WalletInternal
    }
    fn nullifier(&self) -> Option<&orchard::note::Nullifier> {
        None
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        None
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        if self.transfer_type() == TransferType::WalletInternal {
            Some(Scope::Internal)
        } else {
            Some(Scope::External)
        }
    }
}

/// Records the specified shielded output as having been received.
///
/// This implementation relies on the facts that:
/// - A transaction will not contain more than 2^63 shielded outputs.
/// - A note value will never exceed 2^63 zatoshis.
pub(crate) fn put_received_note<T: ReceivedOrchardOutput>(
    conn: &Connection,
    output: &T,
    tx_ref: i64,
    spent_in: Option<i64>,
) -> Result<(), SqliteClientError> {
    let mut stmt_upsert_received_note = conn.prepare_cached(
        "INSERT INTO orchard_received_notes
        (tx, action_index, account_id, diversifier, value, rseed, memo, nf,
         is_change, spent, commitment_tree_position,
         recipient_key_scope)
        VALUES (
            :tx,
            :action_index,
            :account_id,
            :diversifier,
            :value,
            :rseed,
            :memo,
            :nf,
            :is_change,
            :spent,
            :commitment_tree_position,
            :recipient_key_scope
        )
        ON CONFLICT (tx, action_index) DO UPDATE
        SET account_id = :account_id,
            diversifier = :diversifier,
            value = :value,
            rseed = :rseed,
            nf = IFNULL(:nf, nf),
            memo = IFNULL(:memo, memo),
            is_change = IFNULL(:is_change, is_change),
            spent = IFNULL(:spent, spent),
            commitment_tree_position = IFNULL(:commitment_tree_position, commitment_tree_position),
            recipient_key_scope = :recipient_key_scope",
    )?;

    let rseed = output.note().rseed();
    let to = output.note().recipient();
    let diversifier = to.diversifier();

    let sql_args = named_params![
        ":tx": &tx_ref,
        ":output_index": i64::try_from(output.index()).expect("output indices are representable as i64"),
        ":account_id": output.account_id().0,
        ":diversifier": diversifier.as_array(),
        ":value": output.note().value().inner(),
        ":rseed": &rseed.as_bytes(),
        ":nf": output.nullifier().map(|nf| nf.to_bytes()),
        ":memo": memo_repr(output.memo()),
        ":is_change": output.is_change(),
        ":spent": spent_in,
        ":commitment_tree_position": output.note_commitment_tree_position().map(u64::from),
        ":recipient_key_scope": output.recipient_key_scope().map(scope_code),
    ];

    stmt_upsert_received_note
        .execute(sql_args)
        .map_err(SqliteClientError::from)?;

    Ok(())
}

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
            s.next_orchard_subtree_index()
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

        fn received_note_count(
            summary: &zcash_client_backend::data_api::chain::ScanSummary,
        ) -> usize {
            summary.received_orchard_note_count()
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

    #[test]
    fn scan_cached_blocks_detects_spends_out_of_order() {
        testing::pool::scan_cached_blocks_detects_spends_out_of_order::<OrchardPoolTester>()
    }

    #[test]
    fn cross_pool_exchange() {
        use crate::wallet::sapling::tests::SaplingPoolTester;

        testing::pool::cross_pool_exchange::<OrchardPoolTester, SaplingPoolTester>()
    }
}
