use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    primitives::PaymentAddress,
    sapling::Node,
    transaction::components::Amount,
    zip32::ExtendedFullViewingKey,
};

use crate::proto::compact_formats::CompactBlock;

pub mod chain;
pub mod error;

pub trait DBOps {
    type Error;
    type AccountId;
    type NoteId;
    //    type TxRef;   // Backend-specific transaction handle
    //    type NoteRef; // Backend-specific note identifier`

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
        account: Self::AccountId,
    ) -> Result<Option<PaymentAddress>, Self::Error>;

    fn get_balance(&self, account: Self::AccountId) -> Result<Amount, Self::Error>;

    fn get_verified_balance(&self, account: Self::AccountId) -> Result<Amount, Self::Error>;

    fn get_received_memo_as_utf8(
        &self,
        id_note: Self::NoteId,
    ) -> Result<Option<String>, Self::Error>;

    fn get_sent_memo_as_utf8(&self, id_note: Self::NoteId) -> Result<Option<String>, Self::Error>;

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
    ) -> Result<Vec<(Self::NoteId, IncrementalWitness<Node>)>, Self::Error>;

    //    fn get_witnesses(block_height: BlockHeight) -> Result<Box<dyn Iterator<Item = IncrementalWitness<Node>>>, Self::Error>;
    //
    //    fn get_nullifiers() -> Result<(Vec<u8>, Account), Self::Error>;
    //
    //    fn create_block(block_height: BlockHeight, hash: BlockHash, time: u32, sapling_tree: CommitmentTree<Node>) -> Result<(), Self::Error>;
    //
    //    fn put_transaction(transaction: Transaction, block_height: BlockHeight) -> Result<Self::TxRef, Self::Error>;
    //
    //    fn get_txref(txid: TxId) -> Result<Option<Self::TxRef>, Self::Error>;
    //
    //    fn mark_spent(tx_ref: Self::TxRef, nullifier: Vec<u8>) -> Result<(), Self::Error>;
    //
    //    fn put_note(output: WalletShieldedOutput, tx_ref: Self::TxRef, nullifier: Vec<u8>) -> Result<(), Self::Error>;
    //
    //    fn get_note(tx_ref: Self::TxRef, output_index: i64) -> Result<Self::NoteRef, Self::Error>;
    //
    //    fn prune_witnesses(to_height: BlockHeight) -> Result<(), Self::Error>;
    //
    //    fn mark_expired_unspent(to_height: BlockHeight) -> Result<(), Self::Error>;
    //
    //    fn put_sent_note(tx_ref: Self::TxRef, output: DecryptedOutput) -> Result<(), Self::Error>;
    //
    //    fn put_received_note(tx_ref: Self::TxRef, output: DecryptedOutput) -> Result<(), Self::Error>;
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
}
