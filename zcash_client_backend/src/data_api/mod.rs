use std::cmp;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    note_encryption::Memo,
    primitives::{Note, PaymentAddress},
    sapling::Node,
    transaction::{components::Amount, Transaction, TxId},
    zip32::ExtendedFullViewingKey,
};

use crate::{
    address::RecipientAddress,
    data_api::wallet::ANCHOR_OFFSET,
    decrypt::DecryptedOutput,
    proto::compact_formats::CompactBlock,
    wallet::{AccountId, SpendableNote, WalletShieldedOutput, WalletTx},
};

pub mod chain;
pub mod error;
pub mod wallet;

pub trait DBOps {
    type Error;
    type NoteRef: Copy; // Backend-specific note identifier
    type TxRef: Copy;
    type UpdateOps: DBUpdate<Error = Self::Error, NoteRef = Self::NoteRef, TxRef = Self::TxRef>;

    fn init_db(&self) -> Result<(), Self::Error>;

    fn init_account_storage<P: consensus::Parameters>(
        &self,
        params: &P,
        extfvks: &[ExtendedFullViewingKey],
    ) -> Result<(), Self::Error>;

    fn init_block_storage(
        &self,
        height: BlockHeight,
        hash: BlockHash,
        time: u32,           //TODO: Newtype!
        sapling_tree: &[u8], //TODO: Newtype!
    ) -> Result<(), Self::Error>;

    fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error>;

    fn get_target_and_anchor_heights(
        &self,
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        self.block_height_extrema().map(|heights| {
            heights.map(|(min_height, max_height)| {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height = BlockHeight::from(cmp::max(
                    u32::from(target_height).saturating_sub(ANCHOR_OFFSET),
                    u32::from(min_height),
                ));

                (target_height, anchor_height)
            })
        })
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error>;

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error>;

    fn get_address<P: consensus::Parameters>(
        &self,
        params: &P,
        account: AccountId,
    ) -> Result<Option<PaymentAddress>, Self::Error>;

    fn get_extended_full_viewing_keys<P: consensus::Parameters>(
        &self,
        params: &P,
    ) -> Result<Vec<ExtendedFullViewingKey>, Self::Error>;

    fn is_valid_account_extfvk<P: consensus::Parameters>(
        &self,
        params: &P,
        account: AccountId,
        extfvk: &ExtendedFullViewingKey,
    ) -> Result<bool, Self::Error>;

    fn get_balance(&self, account: AccountId) -> Result<Amount, Self::Error>;

    fn get_verified_balance(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Amount, Self::Error>;

    fn get_received_memo_as_utf8(
        &self,
        id_note: Self::NoteRef,
    ) -> Result<Option<String>, Self::Error>;

    fn get_sent_memo_as_utf8(&self, id_note: Self::NoteRef) -> Result<Option<String>, Self::Error>;

    fn get_commitment_tree(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<CommitmentTree<Node>>, Self::Error>;

    fn get_witnesses(
        &self,
        block_height: BlockHeight,
    ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error>;

    fn get_nullifiers(&self) -> Result<Vec<(Vec<u8>, AccountId)>, Self::Error>;

    fn select_spendable_notes(
        &self,
        account: AccountId,
        target_value: Amount,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error>;

    fn get_update_ops(&self) -> Result<Self::UpdateOps, Self::Error>;
}

pub trait DBUpdate {
    type Error;
    type NoteRef: Copy;
    type TxRef: Copy;

    fn transactionally<F, A>(&mut self, f: F) -> Result<A, Self::Error>
    where
        F: FnOnce(&mut Self) -> Result<A, Self::Error>;

    fn insert_block(
        &mut self,
        block_height: BlockHeight,
        block_hash: BlockHash,
        block_time: u32,
        commitment_tree: &CommitmentTree<Node>,
    ) -> Result<(), Self::Error>;

    fn rewind_to_height<P: consensus::Parameters>(
        &mut self,
        parameters: &P,
        block_height: BlockHeight,
    ) -> Result<(), Self::Error>;

    fn put_tx_meta(
        &mut self,
        tx: &WalletTx,
        height: BlockHeight,
    ) -> Result<Self::TxRef, Self::Error>;

    fn put_tx_data(
        &mut self,
        tx: &Transaction,
        created_at: Option<time::OffsetDateTime>,
    ) -> Result<Self::TxRef, Self::Error>;

    fn mark_spent(&mut self, tx_ref: Self::TxRef, nf: &[u8]) -> Result<(), Self::Error>;

    fn put_received_note<T: ShieldedOutput>(
        &mut self,
        output: &T,
        nf: Option<&[u8]>,
        tx_ref: Self::TxRef,
    ) -> Result<Self::NoteRef, Self::Error>;

    fn insert_witness(
        &mut self,
        note_id: Self::NoteRef,
        witness: &IncrementalWitness<Node>,
        height: BlockHeight,
    ) -> Result<(), Self::Error>;

    fn prune_witnesses(&mut self, from_height: BlockHeight) -> Result<(), Self::Error>;

    fn update_expired_notes(&mut self, from_height: BlockHeight) -> Result<(), Self::Error>;

    fn put_sent_note<P: consensus::Parameters>(
        &mut self,
        params: &P,
        output: &DecryptedOutput,
        tx_ref: Self::TxRef,
    ) -> Result<(), Self::Error>;

    fn insert_sent_note<P: consensus::Parameters>(
        &mut self,
        params: &P,
        tx_ref: Self::TxRef,
        output_index: usize,
        account: AccountId,
        to: &RecipientAddress,
        value: Amount,
        memo: Option<Memo>,
    ) -> Result<(), Self::Error>;
}

pub trait CacheOps {
    type Error;

    fn init_cache(&self) -> Result<(), Self::Error>;

    // Validate the cached chain by applying a function that checks pairwise constraints
    // (top_block :: &CompactBlock, next_block :: &CompactBlock) -> Result<(), Self::Error)
    // beginning with the current maximum height walking backward through the chain, terminating
    // with the block at `from_height`. Returns the hash of the block at height `from_height`
    fn validate_chain<F>(
        &self,
        from_height: BlockHeight,
        validate: F,
    ) -> Result<Option<BlockHash>, Self::Error>
    where
        F: Fn(&CompactBlock, &CompactBlock) -> Result<(), Self::Error>;

    fn with_cached_blocks<F>(
        &self,
        from_height: BlockHeight,
        limit: Option<u32>,
        with_row: F,
    ) -> Result<(), Self::Error>
    where
        F: FnMut(BlockHeight, CompactBlock) -> Result<(), Self::Error>;
}

pub trait ShieldedOutput {
    fn index(&self) -> usize;
    fn account(&self) -> AccountId;
    fn to(&self) -> &PaymentAddress;
    fn note(&self) -> &Note;
    fn memo(&self) -> Option<&Memo>;
    fn is_change(&self) -> Option<bool>;
}

impl ShieldedOutput for WalletShieldedOutput {
    fn index(&self) -> usize {
        self.index
    }
    fn account(&self) -> AccountId {
        AccountId(self.account as u32)
    }
    fn to(&self) -> &PaymentAddress {
        &self.to
    }
    fn note(&self) -> &Note {
        &self.note
    }
    fn memo(&self) -> Option<&Memo> {
        None
    }
    fn is_change(&self) -> Option<bool> {
        Some(self.is_change)
    }
}

impl ShieldedOutput for DecryptedOutput {
    fn index(&self) -> usize {
        self.index
    }
    fn account(&self) -> AccountId {
        AccountId(self.account as u32)
    }
    fn to(&self) -> &PaymentAddress {
        &self.to
    }
    fn note(&self) -> &Note {
        &self.note
    }
    fn memo(&self) -> Option<&Memo> {
        Some(&self.memo)
    }
    fn is_change(&self) -> Option<bool> {
        None
    }
}
