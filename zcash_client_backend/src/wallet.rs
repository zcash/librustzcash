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
    zip32::Scope,
};

use crate::{address::UnifiedAddress, fees::sapling as sapling_fees, PoolType, ShieldedProtocol};

#[cfg(feature = "orchard")]
use crate::fees::orchard as orchard_fees;

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::legacy::keys::{NonHardenedChildIndex, TransparentKeyScope};

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
pub enum Recipient<AccountId, N> {
    Transparent(TransparentAddress),
    Sapling(sapling::PaymentAddress),
    Unified(UnifiedAddress, PoolType),
    InternalAccount(AccountId, N),
}

impl<AccountId, N> Recipient<AccountId, N> {
    pub fn map_internal_account_note<B, F: FnOnce(N) -> B>(self, f: F) -> Recipient<AccountId, B> {
        match self {
            Recipient::Transparent(t) => Recipient::Transparent(t),
            Recipient::Sapling(s) => Recipient::Sapling(s),
            Recipient::Unified(u, p) => Recipient::Unified(u, p),
            Recipient::InternalAccount(a, n) => Recipient::InternalAccount(a, f(n)),
        }
    }
}

impl<AccountId, N> Recipient<AccountId, Option<N>> {
    pub fn internal_account_note_transpose_option(self) -> Option<Recipient<AccountId, N>> {
        match self {
            Recipient::Transparent(t) => Some(Recipient::Transparent(t)),
            Recipient::Sapling(s) => Some(Recipient::Sapling(s)),
            Recipient::Unified(u, p) => Some(Recipient::Unified(u, p)),
            Recipient::InternalAccount(a, n) => n.map(|n0| Recipient::InternalAccount(a, n0)),
        }
    }
}

/// The shielded subset of a [`Transaction`]'s data that is relevant to a particular wallet.
///
/// [`Transaction`]: zcash_primitives::transaction::Transaction
pub struct WalletTx<AccountId> {
    txid: TxId,
    block_index: usize,
    sapling_spends: Vec<WalletSaplingSpend<AccountId>>,
    sapling_outputs: Vec<WalletSaplingOutput<AccountId>>,
}

impl<AccountId> WalletTx<AccountId> {
    /// Constructs a new [`WalletTx`] from its constituent parts
    pub fn new(
        txid: TxId,
        block_index: usize,
        sapling_spends: Vec<WalletSaplingSpend<AccountId>>,
        sapling_outputs: Vec<WalletSaplingOutput<AccountId>>,
    ) -> Self {
        Self {
            txid,
            block_index,
            sapling_spends,
            sapling_outputs,
        }
    }

    /// Returns the [`TxId`] for the corresponding [`Transaction`]
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// Returns the index of the transaction in the containing block.
    pub fn block_index(&self) -> usize {
        self.block_index
    }

    /// Returns a record for each Sapling note belonging to the wallet that was spent in the
    /// transaction.
    pub fn sapling_spends(&self) -> &[WalletSaplingSpend<AccountId>] {
        self.sapling_spends.as_ref()
    }

    /// Returns a record for each Sapling note belonging to and/or produced by the wallet in the
    /// transaction.
    pub fn sapling_outputs(&self) -> &[WalletSaplingOutput<AccountId>] {
        self.sapling_outputs.as_ref()
    }
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
/// [`SpendDescription`]: sapling::bundle::SpendDescription
pub struct WalletSaplingSpend<AccountId> {
    index: usize,
    nf: sapling::Nullifier,
    account: AccountId,
}

impl<AccountId> WalletSaplingSpend<AccountId> {
    pub fn from_parts(index: usize, nf: sapling::Nullifier, account: AccountId) -> Self {
        Self { index, nf, account }
    }

    pub fn index(&self) -> usize {
        self.index
    }
    pub fn nf(&self) -> &sapling::Nullifier {
        &self.nf
    }
    pub fn account(&self) -> &AccountId {
        &self.account
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
/// [`OutputDescription`]: sapling::bundle::OutputDescription
pub struct WalletSaplingOutput<AccountId> {
    index: usize,
    cmu: sapling::note::ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    account_id: AccountId,
    note: sapling::Note,
    is_change: bool,
    note_commitment_tree_position: Position,
    nf: Option<sapling::Nullifier>,
    recipient_key_scope: Option<zip32::Scope>,
}

impl<AccountId> WalletSaplingOutput<AccountId> {
    /// Constructs a new `WalletSaplingOutput` value from its constituent parts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        index: usize,
        cmu: sapling::note::ExtractedNoteCommitment,
        ephemeral_key: EphemeralKeyBytes,
        account_id: AccountId,
        note: sapling::Note,
        is_change: bool,
        note_commitment_tree_position: Position,
        nf: Option<sapling::Nullifier>,
        recipient_key_scope: Option<zip32::Scope>,
    ) -> Self {
        Self {
            index,
            cmu,
            ephemeral_key,
            note,
            is_change,
            note_commitment_tree_position,
            nf,
            account_id,
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
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
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
    pub fn nf(&self) -> Option<&sapling::Nullifier> {
        self.nf.as_ref()
    }
    pub fn recipient_key_scope(&self) -> Option<zip32::Scope> {
        self.recipient_key_scope
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

    /// Returns the shielded protocol used by this note.
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
#[derive(Debug, Clone)]
pub enum OvkPolicy {
    /// Use the outgoing viewing key from the sender's [`UnifiedFullViewingKey`].
    ///
    /// Transaction outputs will be decryptable by the sender, in addition to the
    /// recipients.
    ///
    /// [`UnifiedFullViewingKey`]: zcash_keys::keys::UnifiedFullViewingKey
    Sender,

    /// Use custom outgoing viewing keys. These might for instance be derived from a
    /// different seed than the wallet's spending keys.
    ///
    /// Transaction outputs will be decryptable by the recipients, and whoever controls
    /// the provided outgoing viewing keys.
    Custom {
        sapling: sapling::keys::OutgoingViewingKey,
        #[cfg(feature = "orchard")]
        orchard: orchard::keys::OutgoingViewingKey,
    },
    /// Use no outgoing viewing keys. Transaction outputs will be decryptable by their
    /// recipients, but not by the sender.
    Discard,
}

impl OvkPolicy {
    /// Constructs an [`OvkPolicy::Custom`] value from a single arbitrary 32-byte key.
    ///
    /// Outputs of transactions created with this OVK policy will be recoverable using
    /// this key irrespective of the output pool.
    pub fn custom_from_common_bytes(key: &[u8; 32]) -> Self {
        OvkPolicy::Custom {
            sapling: sapling::keys::OutgoingViewingKey(*key),
            #[cfg(feature = "orchard")]
            orchard: orchard::keys::OutgoingViewingKey::from(*key),
        }
    }
}

/// Metadata related to the ZIP 32 derivation of a transparent address.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "transparent-inputs")]
pub struct TransparentAddressMetadata {
    scope: TransparentKeyScope,
    address_index: NonHardenedChildIndex,
}

#[cfg(feature = "transparent-inputs")]
impl TransparentAddressMetadata {
    pub fn new(scope: TransparentKeyScope, address_index: NonHardenedChildIndex) -> Self {
        Self {
            scope,
            address_index,
        }
    }

    pub fn scope(&self) -> TransparentKeyScope {
        self.scope
    }

    pub fn address_index(&self) -> NonHardenedChildIndex {
        self.address_index
    }
}
