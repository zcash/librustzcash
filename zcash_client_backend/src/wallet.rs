//! Structs representing transaction data scanned from the block chain by a wallet or
//! light client.

use incrementalmerkletree::Position;
use zcash_note_encryption::EphemeralKeyBytes;
use zcash_primitives::{
    consensus::BlockHeight,
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    sapling,
    transaction::{
        components::{
            sapling::fees as sapling_fees,
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
    pub sapling_spends: Vec<WalletSaplingSpend>,
    pub sapling_outputs: Vec<WalletSaplingOutput<N>>,
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
pub struct WalletSaplingSpend {
    index: usize,
    nf: sapling::Nullifier,
    account: AccountId,
}

impl WalletSaplingSpend {
    pub fn from_parts(index: usize, nf: sapling::Nullifier, account: AccountId) -> Self {
        Self { index, nf, account }
    }

    pub fn index(&self) -> usize {
        self.index
    }
    pub fn nf(&self) -> &sapling::Nullifier {
        &self.nf
    }
    pub fn account(&self) -> AccountId {
        self.account
    }
}

/// A subset of an [`OutputDescription`] relevant to wallets and light clients.
///
/// [`OutputDescription`]: zcash_primitives::transaction::components::OutputDescription
pub struct WalletSaplingOutput<N> {
    index: usize,
    cmu: sapling::note::ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    account: AccountId,
    note: sapling::Note,
    is_change: bool,
    note_commitment_tree_position: Position,
    nf: N,
}

impl<N> WalletSaplingOutput<N> {
    /// Constructs a new `WalletSaplingOutput` value from its constituent parts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        index: usize,
        cmu: sapling::note::ExtractedNoteCommitment,
        ephemeral_key: EphemeralKeyBytes,
        account: AccountId,
        note: sapling::Note,
        is_change: bool,
        note_commitment_tree_position: Position,
        nf: N,
    ) -> Self {
        Self {
            index,
            cmu,
            ephemeral_key,
            account,
            note,
            is_change,
            note_commitment_tree_position,
            nf,
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }
    pub fn cmu(&self) -> &sapling::note::ExtractedNoteCommitment {
        &self.cmu
    }
    pub fn ephemeral_key(&self) -> &EphemeralKeyBytes {
        &self.ephemeral_key
    }
    pub fn account(&self) -> AccountId {
        self.account
    }
    pub fn note(&self) -> &sapling::Note {
        &self.note
    }
    pub fn is_change(&self) -> bool {
        self.is_change
    }
    pub fn note_commitment_tree_position(&self) -> Position {
        self.note_commitment_tree_position
    }
    pub fn nf(&self) -> &N {
        &self.nf
    }
}

/// Information about a note that is tracked by the wallet that is available for spending,
/// with sufficient information for use in note selection.
#[derive(Debug)]
pub struct ReceivedSaplingNote<NoteRef> {
    pub note_id: NoteRef,
    pub diversifier: sapling::Diversifier,
    pub note_value: Amount,
    pub rseed: sapling::Rseed,
    pub note_commitment_tree_position: Position,
}

impl<NoteRef> sapling_fees::InputView<NoteRef> for ReceivedSaplingNote<NoteRef> {
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
