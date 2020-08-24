use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    primitives::PaymentAddress,
    sapling::Node,
    transaction::components::Amount,
    zip32::ExtendedFullViewingKey,
};

use crate::{
    proto::compact_formats::CompactBlock,
    wallet::{AccountId, WalletShieldedOutput, WalletTx},
};

pub mod chain;
pub mod error;

pub trait DBOps {
    type Error;
    type NoteRef: Copy; // Backend-specific note identifier
    type UpdateOps: DBUpdate<Error = Self::Error, NoteRef = Self::NoteRef>;

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

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error>;

    fn rewind_to_height<P: consensus::Parameters>(
        &self,
        parameters: &P,
        block_height: BlockHeight,
    ) -> Result<(), Self::Error>;

    fn get_address<P: consensus::Parameters>(
        &self,
        params: &P,
        account: AccountId,
    ) -> Result<Option<PaymentAddress>, Self::Error>;

    fn get_balance(&self, account: AccountId) -> Result<Amount, Self::Error>;

    fn get_verified_balance(&self, account: AccountId) -> Result<Amount, Self::Error>;

    fn get_received_memo_as_utf8(
        &self,
        id_note: Self::NoteRef,
    ) -> Result<Option<String>, Self::Error>;

    fn get_sent_memo_as_utf8(&self, id_note: Self::NoteRef) -> Result<Option<String>, Self::Error>;

    fn get_extended_full_viewing_keys<P: consensus::Parameters>(
        &self,
        params: &P,
    ) -> Result<Vec<ExtendedFullViewingKey>, Self::Error>;

    fn get_commitment_tree(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<CommitmentTree<Node>>, Self::Error>;

    fn get_witnesses(
        &self,
        block_height: BlockHeight,
    ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error>;

    fn get_nullifiers(&self) -> Result<Vec<(Vec<u8>, AccountId)>, Self::Error>;

    fn get_update_ops(&self) -> Result<Self::UpdateOps, Self::Error>;

    fn transactionally<F>(&self, mutator: &mut Self::UpdateOps, f: F) -> Result<(), Self::Error>
    where
        F: FnOnce(&mut Self::UpdateOps) -> Result<(), Self::Error>;

    //    fn put_sent_note(tx_ref: Self::TxRef, output: DecryptedOutput) -> Result<(), Self::Error>;
    //
    //    fn put_received_note(tx_ref: Self::TxRef, output: DecryptedOutput) -> Result<(), Self::Error>;
}

pub trait DBUpdate {
    type Error;
    type TxRef: Copy;
    type NoteRef: Copy;

    fn insert_block(
        &mut self,
        block_height: BlockHeight,
        block_hash: BlockHash,
        block_time: u32,
        commitment_tree: &CommitmentTree<Node>,
    ) -> Result<(), Self::Error>;

    fn put_tx(&mut self, tx: &WalletTx, height: BlockHeight) -> Result<Self::TxRef, Self::Error>;

    fn mark_spent(&mut self, tx_ref: Self::TxRef, nf: &Vec<u8>) -> Result<(), Self::Error>;

    fn put_note(
        &mut self,
        output: &WalletShieldedOutput,
        nf: &Vec<u8>,
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
