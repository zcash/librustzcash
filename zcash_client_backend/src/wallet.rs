//! Structs representing transaction data scanned from the block chain by a wallet or
//! light client.

use zcash_note_encryption::EphemeralKeyBytes;
use zcash_primitives::{
    consensus::BlockHeight,
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    merkle_tree::IncrementalWitness,
    sapling::{
        note::ExtractedNoteCommitment, Diversifier, Node, Note, Nullifier, PaymentAddress, Rseed,
    },
    transaction::{
        components::{
            sapling,
            transparent::{self, OutPoint, TxOut},
            Amount,
        },
        TxId,
    },
    zip32::AccountId,
};

/// A subset of a [`Transaction`] relevant to wallets and light clients.
///
/// [`Transaction`]: zcash_primitives::transaction::Transaction
pub struct WalletTx<N> {
    pub txid: TxId,
    pub index: usize,
    pub num_spends: usize,
    pub num_outputs: usize,
    pub shielded_spends: Vec<WalletShieldedSpend>,
    pub shielded_outputs: Vec<WalletShieldedOutput<N>>,
}

#[derive(Debug, Clone)]
pub struct WalletTransparentOutput {
    outpoint: OutPoint,
    txout: TxOut,
    height: BlockHeight,
    recipient_address: TransparentAddress,
}

impl WalletTransparentOutput {
    pub fn from_parts(
        outpoint: OutPoint,
        txout: TxOut,
        height: BlockHeight,
    ) -> Option<WalletTransparentOutput> {
        txout
            .recipient_address()
            .map(|recipient_address| WalletTransparentOutput {
                outpoint,
                txout,
                height,
                recipient_address,
            })
    }

    pub fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    pub fn txout(&self) -> &TxOut {
        &self.txout
    }

    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn recipient_address(&self) -> &TransparentAddress {
        &self.recipient_address
    }

    pub fn value(&self) -> Amount {
        self.txout.value
    }
}

impl transparent::fees::InputView for WalletTransparentOutput {
    fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }
    fn coin(&self) -> &TxOut {
        &self.txout
    }
}

/// A subset of a [`SpendDescription`] relevant to wallets and light clients.
///
/// [`SpendDescription`]: zcash_primitives::transaction::components::SpendDescription
pub struct WalletShieldedSpend {
    pub index: usize,
    pub nf: Nullifier,
    pub account: AccountId,
}

/// A subset of an [`OutputDescription`] relevant to wallets and light clients.
///
/// [`OutputDescription`]: zcash_primitives::transaction::components::OutputDescription
pub struct WalletShieldedOutput<N> {
    pub index: usize,
    pub cmu: ExtractedNoteCommitment,
    pub ephemeral_key: EphemeralKeyBytes,
    pub account: AccountId,
    pub note: Note,
    pub to: PaymentAddress,
    pub is_change: bool,
    pub witness: IncrementalWitness<Node>,
    pub nf: N,
}

/// Information about a note that is tracked by the wallet that is available for spending,
/// with sufficient information for use in note selection.
pub struct SpendableNote<NoteRef> {
    pub note_id: NoteRef,
    pub diversifier: Diversifier,
    pub note_value: Amount,
    pub rseed: Rseed,
    pub witness: IncrementalWitness<Node>,
}

impl<NoteRef> sapling::fees::InputView<NoteRef> for SpendableNote<NoteRef> {
    fn note_id(&self) -> &NoteRef {
        &self.note_id
    }

    fn value(&self) -> Amount {
        self.note_value
    }
}

/// Describes a policy for which outgoing viewing key should be able to decrypt
/// transaction outputs.
///
/// For details on what transaction information is visible to the holder of an outgoing
/// viewing key, refer to [ZIP 310].
///
/// [ZIP 310]: https://zips.z.cash/zip-0310
pub enum OvkPolicy {
    /// Use the outgoing viewing key from the sender's [`ExtendedFullViewingKey`].
    ///
    /// Transaction outputs will be decryptable by the sender, in addition to the
    /// recipients.
    ///
    /// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
    Sender,

    /// Use a custom outgoing viewing key. This might for instance be derived from a
    /// separate seed than the wallet's spending keys.
    ///
    /// Transaction outputs will be decryptable by the recipients, and whoever controls
    /// the provided outgoing viewing key.
    Custom(OutgoingViewingKey),

    /// Use no outgoing viewing key. Transaction outputs will be decryptable by their
    /// recipients, but not by the sender.
    Discard,
}
