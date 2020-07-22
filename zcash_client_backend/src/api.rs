use std::collections::HashMap;

use zcash_primitives::{
    note_encryption::Memo,
    primitives::Diversifier,
    //prover::TxProver,
    transaction::{
        //builder::Builder,
        components::{Amount, OutPoint},
        Transaction,
        TxId,
    },
    zip32::ExtendedSpendingKey,
};

use crate::proto::compact_formats::CompactBlock;

#[derive(Debug, Copy, Clone)]
pub struct AccountId(pub u32);

pub struct AccountKey<'a> {
    pub account: AccountId,
    pub extsk: &'a ExtendedSpendingKey,
}

/// A proof that a transaction is included with a particular block.
///
/// For now, no proof is included, as the lightwalletd server is trusted to provide
/// accurate compact blocks. This will eventually include a FlyClient proof.
pub struct TxProof {
    pub block_hash: [u8; 32],
}

/// A transaction that was sent or received by the wallet.
pub struct WalletTx {
    /// The transaction.
    pub tx: Transaction,
    /// The time we first created or received this transaction.
    pub added: u64,
    /// Proof that the transaction is mined in the main chain.
    ///
    /// Will be `None` if the transaction is not mined. We may have received this directly
    /// from the sender, or it may be a transaction we detected in a block that was
    /// subsequently rolled back in a chain reorg.
    pub proof: Option<TxProof>,
}

pub struct Note {
    /// The viewing key for this note? Or its derivation path?
    pub ivk: [u8; 32], // TODO type
    /// The diversifier for the address this note was sent to.
    pub diversifier: Diversifier,
    /// The value of the note.
    pub value: Amount,
    /// The commitment randomness.
    pub rcm: [u8; 32], // TODO type
    /// The memo, if any.
    pub memo: Memo,
}

pub struct NoteRef {
    pub txid: TxId,
    pub n: usize,
}

/// An in-memory wallet.
pub struct MemoryWallet {
    /// Transactions sent or received by the wallet.
    pub txs: HashMap<TxId, WalletTx>,
    /// Notes that have been received but not mined.
    // TODO: combine with mined_notes? We determine "verified" on the fly already.
    pub unmined_notes: HashMap<OutPoint, Note>,
    /// Notes that have been mined. These will have corresponding transactions in `txs`
    /// with proofs of inclusion.
    pub mined_notes: HashMap<OutPoint, Note>,
    /// Available witnesses for the notes.
    pub witnesses: HashMap<u32, ()>,
}

pub trait BlockConsumer {
    type Error;

    fn block_received(&mut self, block: CompactBlock) -> Result<(), Self::Error>;
}

pub trait Wallet {
    type Error;

    fn get_address(&self, account: AccountId) -> Result<String, Self::Error>;

    // fn get_note(&self, note: NoteRef) -> Result<Note, Self::Error>;

    // fn get_memo(&self, note: NoteRef) -> Result<Memo, Self::Error>;

    fn get_unspent_notes(&self) -> Result<Vec<Note>, Self::Error>;

    fn lock_notes(&mut self, notes: &[OutPoint]) -> Result<(), Self::Error>;

    fn get_balance(&self, _account: AccountId) -> Result<Amount, Self::Error> {
        self.get_unspent_notes().map(|notes| {
            notes
                .into_iter()
                // .map(|note| self.get_note(note))
                .fold(Amount::zero(), |total, note| total + note.value)
        })
    }

    fn get_verified_balance(&self, account: AccountId) -> Result<Amount, Self::Error>;

    fn select_notes(&mut self, _value: Amount) -> Result<Vec<Note>, Self::Error>;
}
