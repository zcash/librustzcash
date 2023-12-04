//! Structs representing transaction data scanned from the block chain by a wallet or
//! light client.

use incrementalmerkletree::Position;
use zcash_note_encryption::EphemeralKeyBytes;
use zcash_primitives::{
    consensus::BlockHeight,
    legacy::TransparentAddress,
    transaction::{
        components::{
            amount::NonNegativeAmount,
            transparent::{OutPoint, TxOut},
        },
        fees::transparent as transparent_fees,
        TxId,
    },
    zip32::{AccountId, Scope},
};

use crate::{address::UnifiedAddress, fees::sapling as sapling_fees, PoolType, ShieldedProtocol};

#[cfg(feature = "orchard")]
use crate::fees::orchard as orchard_fees;

/// A unique identifier for a shielded transaction output
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoteId {
    txid: TxId,
    protocol: ShieldedProtocol,
    output_index: u16,
}

impl NoteId {
    /// Constructs a new `NoteId` from its parts.
    pub fn new(txid: TxId, protocol: ShieldedProtocol, output_index: u16) -> Self {
        Self {
            txid,
            protocol,
            output_index,
        }
    }

    /// Returns the ID of the transaction containing this note.
    pub fn txid(&self) -> &TxId {
        &self.txid
    }

    /// Returns the shielded protocol used by this note.
    pub fn protocol(&self) -> ShieldedProtocol {
        self.protocol
    }

    /// Returns the index of this note within its transaction's corresponding list of
    /// shielded outputs.
    pub fn output_index(&self) -> u16 {
        self.output_index
    }
}

/// A type that represents the recipient of a transaction output: a recipient address (and, for
/// unified addresses, the pool to which the payment is sent) in the case of an outgoing output, or an
/// internal account ID and the pool to which funds were sent in the case of a wallet-internal
/// output.
#[derive(Debug, Clone)]
pub enum Recipient {
    Transparent(TransparentAddress),
    Sapling(sapling::PaymentAddress),
    Unified(UnifiedAddress, PoolType),
    InternalAccount(AccountId, PoolType),
}

/// A subset of a [`Transaction`] relevant to wallets and light clients.
///
/// [`Transaction`]: zcash_primitives::transaction::Transaction
pub struct WalletTx<N, S> {
    pub txid: TxId,
    pub index: usize,
    pub sapling_spends: Vec<WalletSaplingSpend>,
    pub sapling_outputs: Vec<WalletSaplingOutput<N, S>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

    pub fn value(&self) -> NonNegativeAmount {
        self.txout.value
    }
}

impl transparent_fees::InputView for WalletTransparentOutput {
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
/// The type parameter `<N>` is used to specify the nullifier type, which may vary between
/// `Sapling` and `Orchard`, and also may vary depending upon the type of key that was used to
/// decrypt this output; incoming viewing keys do not have the capability to derive the nullifier
/// for a note, and the `<N>` will be `()` in these cases.
///
/// The type parameter `<S>` is used to specify the type of the scope of the key used to recover
/// this output; this will usually be [`zcash_primitives::zip32::Scope`] for received notes, and
/// `()` for sent notes.
///
/// [`OutputDescription`]: zcash_primitives::transaction::components::OutputDescription
pub struct WalletSaplingOutput<N, S> {
    index: usize,
    cmu: sapling::note::ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    account: AccountId,
    note: sapling::Note,
    is_change: bool,
    note_commitment_tree_position: Position,
    nf: N,
    recipient_key_scope: S,
}

impl<N, S> WalletSaplingOutput<N, S> {
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
        recipient_key_scope: S,
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
            recipient_key_scope,
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
    pub fn recipient_key_scope(&self) -> &S {
        &self.recipient_key_scope
    }
}

/// An enumeration of supported shielded note types for use in [`ReceivedNote`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    Sapling(sapling::Note),
    #[cfg(feature = "orchard")]
    Orchard(orchard::Note),
}

impl Note {
    pub fn value(&self) -> NonNegativeAmount {
        match self {
            Note::Sapling(n) => n.value().try_into().expect(
                "Sapling notes must have values in the range of valid non-negative ZEC values.",
            ),
            #[cfg(feature = "orchard")]
            Note::Orchard(n) => NonNegativeAmount::from_u64(n.value().inner()).expect(
                "Orchard notes must have values in the range of valid non-negative ZEC values.",
            ),
        }
    }

    pub fn protocol(&self) -> ShieldedProtocol {
        match self {
            Note::Sapling(_) => ShieldedProtocol::Sapling,
            #[cfg(feature = "orchard")]
            Note::Orchard(_) => ShieldedProtocol::Orchard,
        }
    }
}

/// Information about a note that is tracked by the wallet that is available for spending,
/// with sufficient information for use in note selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedNote<NoteRef, NoteT> {
    note_id: NoteRef,
    txid: TxId,
    output_index: u16,
    note: NoteT,
    spending_key_scope: Scope,
    note_commitment_tree_position: Position,
}

impl<NoteRef, NoteT> ReceivedNote<NoteRef, NoteT> {
    pub fn from_parts(
        note_id: NoteRef,
        txid: TxId,
        output_index: u16,
        note: NoteT,
        spending_key_scope: Scope,
        note_commitment_tree_position: Position,
    ) -> Self {
        ReceivedNote {
            note_id,
            txid,
            output_index,
            note,
            spending_key_scope,
            note_commitment_tree_position,
        }
    }

    pub fn internal_note_id(&self) -> &NoteRef {
        &self.note_id
    }
    pub fn txid(&self) -> &TxId {
        &self.txid
    }
    pub fn output_index(&self) -> u16 {
        self.output_index
    }
    pub fn note(&self) -> &NoteT {
        &self.note
    }
    pub fn spending_key_scope(&self) -> Scope {
        self.spending_key_scope
    }
    pub fn note_commitment_tree_position(&self) -> Position {
        self.note_commitment_tree_position
    }

    /// Applies the given function to the `note` field of this ReceivedNote and returns
    /// `None` if that function returns `None`, or otherwise a `Some` containing
    /// a `ReceivedNote` with its `note` field swapped out for the result of the function.
    ///
    /// The name `traverse` refers to the general operation that has the Haskell type
    /// `Applicative f => (a -> f b) -> t a -> f (t b)`, that this method specializes
    /// with `ReceivedNote<NoteRef, _>` for `t` and `Option<_>` for `f`.
    pub fn traverse_opt<B>(
        self,
        f: impl FnOnce(NoteT) -> Option<B>,
    ) -> Option<ReceivedNote<NoteRef, B>> {
        f(self.note).map(|n0| ReceivedNote {
            note_id: self.note_id,
            txid: self.txid,
            output_index: self.output_index,
            note: n0,
            spending_key_scope: self.spending_key_scope,
            note_commitment_tree_position: self.note_commitment_tree_position,
        })
    }
}

impl<NoteRef> ReceivedNote<NoteRef, Note> {
    pub fn protocol(&self) -> ShieldedProtocol {
        match self.note() {
            Note::Sapling(_) => ShieldedProtocol::Sapling,
            #[cfg(feature = "orchard")]
            Note::Orchard(_) => ShieldedProtocol::Orchard,
        }
    }
}

impl<NoteRef> sapling_fees::InputView<NoteRef> for ReceivedNote<NoteRef, sapling::Note> {
    fn note_id(&self) -> &NoteRef {
        &self.note_id
    }

    fn value(&self) -> NonNegativeAmount {
        self.note
            .value()
            .try_into()
            .expect("Sapling note values are indirectly checked by consensus.")
    }
}

#[cfg(feature = "orchard")]
impl<NoteRef> orchard_fees::InputView<NoteRef> for ReceivedNote<NoteRef, orchard::Note> {
    fn note_id(&self) -> &NoteRef {
        &self.note_id
    }

    fn value(&self) -> NonNegativeAmount {
        self.note
            .value()
            .try_into()
            .expect("Orchard note values are indirectly checked by consensus.")
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
    /// [`ExtendedFullViewingKey`]: sapling::zip32::ExtendedFullViewingKey
    Sender,

    /// Use a custom outgoing viewing key. This might for instance be derived from a
    /// separate seed than the wallet's spending keys.
    ///
    /// Transaction outputs will be decryptable by the recipients, and whoever controls
    /// the provided outgoing viewing key.
    Custom(sapling::keys::OutgoingViewingKey),

    /// Use no outgoing viewing key. Transaction outputs will be decryptable by their
    /// recipients, but not by the sender.
    Discard,
}
