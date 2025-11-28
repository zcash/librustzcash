//! Structs representing transaction data scanned from the block chain by a wallet or
//! light client.
use std::fmt::Debug;

use incrementalmerkletree::Position;

use ::transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};
use zcash_address::ZcashAddress;
use zcash_keys::keys::OutgoingViewingKey;
use zcash_note_encryption::EphemeralKeyBytes;
use zcash_primitives::transaction::{TxId, fees::transparent as transparent_fees};
use zcash_protocol::{
    PoolType, ShieldedProtocol,
    consensus::BlockHeight,
    value::{BalanceError, Zatoshis},
};
use zip32::Scope;

use crate::fees::sapling as sapling_fees;

#[cfg(feature = "orchard")]
use crate::fees::orchard as orchard_fees;

#[cfg(feature = "transparent-inputs")]
use {
    ::transparent::keys::{NonHardenedChildIndex, TransparentKeyScope},
    std::time::SystemTime,
};

/// A unique identifier for a shielded transaction output
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// A type that represents the recipient of a transaction output:
///
/// * a recipient address;
/// * for external unified addresses, the pool to which the payment is sent;
/// * for wallet-internal outputs, the internal account ID and metadata about the note.
/// * if the `transparent-inputs` feature is enabled, for ephemeral transparent outputs, the
///   internal account ID and metadata about the outpoint;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient<AccountId> {
    External {
        recipient_address: ZcashAddress,
        output_pool: PoolType,
    },
    #[cfg(feature = "transparent-inputs")]
    EphemeralTransparent {
        receiving_account: AccountId,
        ephemeral_address: TransparentAddress,
        outpoint: OutPoint,
    },
    InternalAccount {
        receiving_account: AccountId,
        external_address: Option<ZcashAddress>,
        note: Box<Note>,
    },
}

/// The shielded subset of a [`Transaction`]'s data that is relevant to a particular wallet.
///
/// [`Transaction`]: zcash_primitives::transaction::Transaction
#[derive(Clone)]
pub struct WalletTx<AccountId> {
    txid: TxId,
    block_index: usize,
    sapling_spends: Vec<WalletSaplingSpend<AccountId>>,
    sapling_outputs: Vec<WalletSaplingOutput<AccountId>>,
    #[cfg(feature = "orchard")]
    orchard_spends: Vec<WalletOrchardSpend<AccountId>>,
    #[cfg(feature = "orchard")]
    orchard_outputs: Vec<WalletOrchardOutput<AccountId>>,
}

impl<AccountId> WalletTx<AccountId> {
    /// Constructs a new [`WalletTx`] from its constituent parts.
    pub fn new(
        txid: TxId,
        block_index: usize,
        sapling_spends: Vec<WalletSaplingSpend<AccountId>>,
        sapling_outputs: Vec<WalletSaplingOutput<AccountId>>,
        #[cfg(feature = "orchard")] orchard_spends: Vec<
            WalletSpend<orchard::note::Nullifier, AccountId>,
        >,
        #[cfg(feature = "orchard")] orchard_outputs: Vec<WalletOrchardOutput<AccountId>>,
    ) -> Self {
        Self {
            txid,
            block_index,
            sapling_spends,
            sapling_outputs,
            #[cfg(feature = "orchard")]
            orchard_spends,
            #[cfg(feature = "orchard")]
            orchard_outputs,
        }
    }

    /// Returns the [`TxId`] for the corresponding [`Transaction`].
    ///
    /// [`Transaction`]: zcash_primitives::transaction::Transaction
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

    /// Returns a record for each Sapling note received or produced by the wallet in the
    /// transaction.
    pub fn sapling_outputs(&self) -> &[WalletSaplingOutput<AccountId>] {
        self.sapling_outputs.as_ref()
    }

    /// Returns a record for each Orchard note belonging to the wallet that was spent in the
    /// transaction.
    #[cfg(feature = "orchard")]
    pub fn orchard_spends(&self) -> &[WalletOrchardSpend<AccountId>] {
        self.orchard_spends.as_ref()
    }

    /// Returns a record for each Orchard note received or produced by the wallet in the
    /// transaction.
    #[cfg(feature = "orchard")]
    pub fn orchard_outputs(&self) -> &[WalletOrchardOutput<AccountId>] {
        self.orchard_outputs.as_ref()
    }
}

/// A transparent output controlled by the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletTransparentOutput {
    outpoint: OutPoint,
    txout: TxOut,
    mined_height: Option<BlockHeight>,
    recipient_address: TransparentAddress,
}

impl WalletTransparentOutput {
    /// Constructs a new [`WalletTransparentOutput`] from its constituent parts.
    ///
    /// Returns `None` if the recipient address for the provided [`TxOut`] cannot be
    /// determined based on the set of output script patterns understood by this wallet.
    pub fn from_parts(
        outpoint: OutPoint,
        txout: TxOut,
        mined_height: Option<BlockHeight>,
    ) -> Option<WalletTransparentOutput> {
        txout
            .recipient_address()
            .map(|recipient_address| WalletTransparentOutput {
                outpoint,
                txout,
                mined_height,
                recipient_address,
            })
    }

    /// Returns the [`OutPoint`] corresponding to the output.
    pub fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    /// Returns the transaction output itself.
    pub fn txout(&self) -> &TxOut {
        &self.txout
    }

    /// Returns the height at which the UTXO was mined, if any.
    pub fn mined_height(&self) -> Option<BlockHeight> {
        self.mined_height
    }

    /// Returns the wallet address that received the UTXO.
    pub fn recipient_address(&self) -> &TransparentAddress {
        &self.recipient_address
    }

    /// Returns the value of the UTXO
    pub fn value(&self) -> Zatoshis {
        self.txout.value()
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

/// A reference to a spent note belonging to the wallet within a transaction.
#[derive(Clone)]
pub struct WalletSpend<Nf, AccountId> {
    index: usize,
    nf: Nf,
    account_id: AccountId,
}

impl<Nf, AccountId> WalletSpend<Nf, AccountId> {
    /// Constructs a `WalletSpend` from its constituent parts.
    pub fn from_parts(index: usize, nf: Nf, account_id: AccountId) -> Self {
        Self {
            index,
            nf,
            account_id,
        }
    }

    /// Returns the index of the Sapling spend or Orchard action within the transaction that
    /// created this spend.
    pub fn index(&self) -> usize {
        self.index
    }
    /// Returns the nullifier of the spent note.
    pub fn nf(&self) -> &Nf {
        &self.nf
    }
    /// Returns the identifier to the account_id to which the note belonged.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

/// A type alias for Sapling [`WalletSpend`]s.
pub type WalletSaplingSpend<AccountId> = WalletSpend<sapling::Nullifier, AccountId>;

/// A type alias for Orchard [`WalletSpend`]s.
#[cfg(feature = "orchard")]
pub type WalletOrchardSpend<AccountId> = WalletSpend<orchard::note::Nullifier, AccountId>;

/// An output that was successfully decrypted in the process of wallet scanning.
#[derive(Clone)]
pub struct WalletOutput<Note, Nullifier, AccountId> {
    index: usize,
    ephemeral_key: EphemeralKeyBytes,
    note: Note,
    is_change: bool,
    note_commitment_tree_position: Position,
    nf: Option<Nullifier>,
    account_id: AccountId,
    recipient_key_scope: Option<zip32::Scope>,
}

impl<Note, Nullifier, AccountId> WalletOutput<Note, Nullifier, AccountId> {
    /// Constructs a new `WalletOutput` value from its constituent parts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        index: usize,
        ephemeral_key: EphemeralKeyBytes,
        note: Note,
        is_change: bool,
        note_commitment_tree_position: Position,
        nf: Option<Nullifier>,
        account_id: AccountId,
        recipient_key_scope: Option<zip32::Scope>,
    ) -> Self {
        Self {
            index,
            ephemeral_key,
            note,
            is_change,
            note_commitment_tree_position,
            nf,
            account_id,
            recipient_key_scope,
        }
    }

    /// The index of the output or action in the transaction that created this output.
    pub fn index(&self) -> usize {
        self.index
    }
    /// The [`EphemeralKeyBytes`] used in the decryption of the note.
    pub fn ephemeral_key(&self) -> &EphemeralKeyBytes {
        &self.ephemeral_key
    }
    /// The note.
    pub fn note(&self) -> &Note {
        &self.note
    }
    /// A flag indicating whether the process of note decryption determined that this
    /// output should be classified as change.
    pub fn is_change(&self) -> bool {
        self.is_change
    }
    /// The position of the note in the global note commitment tree.
    pub fn note_commitment_tree_position(&self) -> Position {
        self.note_commitment_tree_position
    }
    /// The nullifier for the note, if the key used to decrypt the note was able to compute it.
    pub fn nf(&self) -> Option<&Nullifier> {
        self.nf.as_ref()
    }
    /// The identifier for the account to which the output belongs.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
    /// The ZIP 32 scope for which the viewing key that decrypted this output was derived, if
    /// known.
    pub fn recipient_key_scope(&self) -> Option<zip32::Scope> {
        self.recipient_key_scope
    }
}

/// A subset of an [`OutputDescription`] relevant to wallets and light clients.
///
/// [`OutputDescription`]: sapling::bundle::OutputDescription
pub type WalletSaplingOutput<AccountId> =
    WalletOutput<sapling::Note, sapling::Nullifier, AccountId>;

/// The output part of an Orchard [`Action`] that was decrypted in the process of scanning.
///
/// [`Action`]: orchard::Action
#[cfg(feature = "orchard")]
pub type WalletOrchardOutput<AccountId> =
    WalletOutput<orchard::note::Note, orchard::note::Nullifier, AccountId>;

/// An enumeration of supported shielded note types for use in [`ReceivedNote`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    Sapling(sapling::Note),
    #[cfg(feature = "orchard")]
    Orchard(orchard::Note),
}

impl Note {
    pub fn value(&self) -> Zatoshis {
        match self {
            Note::Sapling(n) => n.value().inner().try_into().expect(
                "Sapling notes must have values in the range of valid non-negative ZEC values.",
            ),
            #[cfg(feature = "orchard")]
            Note::Orchard(n) => Zatoshis::from_u64(n.value().inner()).expect(
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

/// A note that was received by the wallet, along with contextual information about the output that
/// generated the note and the key that is required to spend it.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedNote<NoteRef, NoteT> {
    note_id: NoteRef,
    txid: TxId,
    output_index: u16,
    note: NoteT,
    spending_key_scope: Scope,
    note_commitment_tree_position: Position,
    mined_height: Option<BlockHeight>,
    max_shielding_input_height: Option<BlockHeight>,
}

impl<NoteRef, NoteT> ReceivedNote<NoteRef, NoteT> {
    /// Constructs a new [`ReceivedNote`] from its constituent parts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        note_id: NoteRef,
        txid: TxId,
        output_index: u16,
        note: NoteT,
        spending_key_scope: Scope,
        note_commitment_tree_position: Position,
        mined_height: Option<BlockHeight>,
        max_shielding_input_height: Option<BlockHeight>,
    ) -> Self {
        ReceivedNote {
            note_id,
            txid,
            output_index,
            note,
            spending_key_scope,
            note_commitment_tree_position,
            mined_height,
            max_shielding_input_height,
        }
    }

    /// Returns the storage backend's internal identifier for the note.
    pub fn internal_note_id(&self) -> &NoteRef {
        &self.note_id
    }
    /// Returns the txid of the transaction that constructed the note.
    pub fn txid(&self) -> &TxId {
        &self.txid
    }
    /// Returns the output index of the note within the transaction, according to the note's
    /// shielded protocol.
    pub fn output_index(&self) -> u16 {
        self.output_index
    }
    /// Returns the note data.
    pub fn note(&self) -> &NoteT {
        &self.note
    }
    /// Returns the [`Scope`] of the spending key required to make spend authorizing signatures for
    /// the note.
    pub fn spending_key_scope(&self) -> Scope {
        self.spending_key_scope
    }
    /// Returns the position of the note in the note commitment tree.
    pub fn note_commitment_tree_position(&self) -> Position {
        self.note_commitment_tree_position
    }
    /// Returns the block height at which the transaction that produced the note was mined.
    pub fn mined_height(&self) -> Option<BlockHeight> {
        self.mined_height
    }
    /// Returns the maximum block height among those at which transparent inputs to the transaction
    /// that produced the note were created, considering only transparent inputs that belong to the
    /// same wallet account as the note. This height is used in determining the effective number of
    /// confirmations for externally-received value. See [`ZIP 315`] for additional information.
    ///
    /// [`ZIP 315`]: https://zips.z.cash/zip-0315
    pub fn max_shielding_input_height(&self) -> Option<BlockHeight> {
        self.max_shielding_input_height
    }

    /// Map over the `note` field of this data structure.
    ///
    /// Consume this value, applying the provided function to the value of its `note` field and
    /// returning a new `ReceivedNote` with the result as its `note` field value.
    pub fn map_note<N, F: Fn(NoteT) -> N>(self, f: F) -> ReceivedNote<NoteRef, N> {
        ReceivedNote {
            note_id: self.note_id,
            txid: self.txid,
            output_index: self.output_index,
            note: f(self.note),
            spending_key_scope: self.spending_key_scope,
            note_commitment_tree_position: self.note_commitment_tree_position,
            mined_height: self.mined_height,
            max_shielding_input_height: self.max_shielding_input_height,
        }
    }
}

impl<NoteRef: Debug> Debug for ReceivedNote<NoteRef, sapling::Note> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedNote")
            .field("note_id", &self.note_id)
            .field("txid", &self.txid)
            .field("output_index", &self.output_index)
            .field("note_value", &self.note_value())
            .field("spending_key_scope", &self.spending_key_scope)
            .field(
                "note_commitment_tree_position",
                &self.note_commitment_tree_position,
            )
            .field("mined_height", &self.mined_height)
            .finish()
    }
}

#[cfg(feature = "orchard")]
impl<NoteRef: Debug> Debug for ReceivedNote<NoteRef, orchard::note::Note> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivedNote")
            .field("note_id", &self.note_id)
            .field("txid", &self.txid)
            .field("output_index", &self.output_index)
            .field("note_value", &self.note_value())
            .field("spending_key_scope", &self.spending_key_scope)
            .field(
                "note_commitment_tree_position",
                &self.note_commitment_tree_position,
            )
            .field("mined_height", &self.mined_height)
            .finish()
    }
}

impl<NoteRef> ReceivedNote<NoteRef, sapling::Note> {
    pub fn note_value(&self) -> Result<Zatoshis, BalanceError> {
        self.note.value().inner().try_into()
    }
}

#[cfg(feature = "orchard")]
impl<NoteRef> ReceivedNote<NoteRef, orchard::note::Note> {
    pub fn note_value(&self) -> Result<Zatoshis, BalanceError> {
        self.note.value().inner().try_into()
    }
}

impl<NoteRef> sapling_fees::InputView<NoteRef> for (NoteRef, sapling::value::NoteValue) {
    fn note_id(&self) -> &NoteRef {
        &self.0
    }

    fn value(&self) -> Zatoshis {
        self.1
            .inner()
            .try_into()
            .expect("Sapling note values are indirectly checked by consensus.")
    }
}

impl<NoteRef> sapling_fees::InputView<NoteRef> for ReceivedNote<NoteRef, sapling::Note> {
    fn note_id(&self) -> &NoteRef {
        &self.note_id
    }

    fn value(&self) -> Zatoshis {
        self.note
            .value()
            .inner()
            .try_into()
            .expect("Sapling note values are indirectly checked by consensus.")
    }
}

#[cfg(feature = "orchard")]
impl<NoteRef> orchard_fees::InputView<NoteRef> for (NoteRef, orchard::value::NoteValue) {
    fn note_id(&self) -> &NoteRef {
        &self.0
    }

    fn value(&self) -> Zatoshis {
        self.1
            .inner()
            .try_into()
            .expect("Orchard note values are indirectly checked by consensus.")
    }
}

#[cfg(feature = "orchard")]
impl<NoteRef> orchard_fees::InputView<NoteRef> for ReceivedNote<NoteRef, orchard::Note> {
    fn note_id(&self) -> &NoteRef {
        &self.note_id
    }

    fn value(&self) -> Zatoshis {
        self.note
            .value()
            .inner()
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
    /// Use an outgoing viewing key produced from the sender's [`UnifiedFullViewingKey`],
    /// selected via the policy documented in [`UnifiedFullViewingKey::select_ovk`].
    ///
    /// External transaction outputs will be decryptable by the sender, in addition to the
    /// recipients. Wallet-internal transaction outputs will be decryptable only with the wallet's
    /// internal-scoped incoming viewing key.
    ///
    /// [`UnifiedFullViewingKey`]: zcash_keys::keys::UnifiedFullViewingKey
    /// [`UnifiedFullViewingKey::select_ovk`]: zcash_keys::keys::UnifiedFullViewingKey::select_ovk
    Sender,

    /// Use custom outgoing viewing keys. These might for instance be derived from a
    /// different seed than the wallet's spending keys.
    ///
    /// Transaction outputs will be decryptable by the recipients, and whoever controls
    /// the provided outgoing viewing keys.
    Custom {
        external_ovk: OutgoingViewingKey,
        internal_ovk: Option<OutgoingViewingKey>,
    },
    /// Use no outgoing viewing keys. Transaction outputs will be decryptable by their
    /// recipients, but not by the sender.
    Discard,
}

impl OvkPolicy {
    /// Constructs an [`OvkPolicy::Custom`] value from a single arbitrary 32-byte key with both the
    /// external_ovk and internal_ovk components set to the same key.
    ///
    /// Outputs of transactions created with this OVK policy will be recoverable using this key
    /// irrespective of whether they are external outputs or wallet-internal change outputs.
    pub fn custom_from_common_bytes(key: &[u8; 32]) -> Self {
        let k = OutgoingViewingKey::from(*key);
        OvkPolicy::Custom {
            external_ovk: k,
            internal_ovk: Some(k),
        }
    }
}

/// Metadata describing the gap limit position of a transparent address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapMetadata {
    /// The address, or an address at a greater child index, has received transparent funds and
    /// will be discovered by wallet recovery by exploration over the space of
    /// [`NonHardenedChildIndex`]es using the provided gap limit.
    GapRecoverable { gap_limit: u32 },
    /// The address exists within an address gap of the given limit size, and will be discovered by
    /// wallet recovery by exploration using the provided gap limit. In the view of the wallet, no
    /// addresses at the given position or greater (up to the gap limit) have received funds. The
    /// number of addresses remaining within the gap limit before no additional addresses can be
    /// allocated is given by `gap_limit - (gap_position + 1)`.
    InGap {
        /// A zero-based index over the child indices in the gap.
        gap_position: u32,
        /// The maximum number of sequential child indices that can be allocated to addresses
        /// without any of those addresses having received funds.
        gap_limit: u32,
    },
    /// The wallet does not contain derivation information for the associated address, and so its
    /// relationship to other addresses in the wallet cannot be determined.
    DerivationUnknown,
}

/// Metadata describing whether and when a transparent address was exposed by the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "transparent-inputs")]
pub enum Exposure {
    /// The address has been exposed by the wallet.
    Exposed {
        /// The address was first exposed to the wider ecosystem at this height, to the best
        /// of our knowledge.
        ///
        /// - For user-generated addresses, this is the chain tip height at the time that the
        ///   address was generated by an explicit request by the user or reserved for use in
        ///   a ZIP 320 transaction. These heights are not recoverable from chain.
        /// - In the case of an address with its first use discovered in a transaction
        ///   obtained by scanning the chain, this will be set to the mined height of that
        ///   transaction. In recover from seed cases, this is what user-generated addresses
        ///   will be assigned.
        at_height: BlockHeight,
        /// Transparent address gap metadata, as of the time the query that produced this exposure
        /// metadata was executed.
        gap_metadata: GapMetadata,
    },
    /// The address is not known to have been exposed to an external caller by the wallet.
    ///
    /// The wallet makes its determination based on observed chain data and inference from
    /// standard wallet address generation patterns. In particular, this is the state that
    /// an address is in when it has been generated by the advancement of the transparent
    /// address gap. This judgement may be incorrect for restored wallets.
    Unknown,
    /// It is not possible for the wallet to determine whether the address has been exposed,
    /// given the information the wallet has access to.
    CannotKnow,
}

/// Information about a transparent address controlled by the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "transparent-inputs")]
pub struct TransparentAddressMetadata {
    source: TransparentAddressSource,
    exposure: Exposure,
    next_check_time: Option<SystemTime>,
}

#[cfg(feature = "transparent-inputs")]
impl TransparentAddressMetadata {
    /// Constructs a new [`TransparentAddressMetadata`] value from its constituent parts.
    pub fn new(
        source: TransparentAddressSource,
        exposure: Exposure,
        next_check_time: Option<SystemTime>,
    ) -> Self {
        Self {
            source,
            exposure,
            next_check_time,
        }
    }

    /// Returns a [`TransparentAddressMetadata`] with [`TransparentAddressSource::Derived`] source
    /// information and the specified exposure height.
    pub fn derived(
        scope: TransparentKeyScope,
        address_index: NonHardenedChildIndex,
        exposure: Exposure,
        next_check_time: Option<SystemTime>,
    ) -> Self {
        Self {
            source: TransparentAddressSource::Derived {
                scope,
                address_index,
            },
            exposure,
            next_check_time,
        }
    }

    /// Returns a [`TransparentAddressMetadata`] with [`TransparentAddressSource::Standalone`] source
    /// information and the specified exposure height.
    #[cfg(feature = "transparent-key-import")]
    pub fn standalone(
        pubkey: secp256k1::PublicKey,
        exposure: Exposure,
        next_check_time: Option<SystemTime>,
    ) -> Self {
        Self {
            source: TransparentAddressSource::Standalone(pubkey),
            exposure,
            next_check_time,
        }
    }

    /// Returns the source metadata for the address.
    pub fn source(&self) -> &TransparentAddressSource {
        &self.source
    }

    /// Returns the exposure metadata for this transparent address.
    pub fn exposure(&self) -> Exposure {
        self.exposure
    }

    /// Returns a copy of this metadata, with its exposure metadata updated
    pub fn with_exposure_at(
        &self,
        exposure_height: BlockHeight,
        gap_metadata: GapMetadata,
    ) -> Self {
        Self {
            source: self.source.clone(),
            exposure: Exposure::Exposed {
                at_height: exposure_height,
                gap_metadata,
            },
            next_check_time: self.next_check_time,
        }
    }

    /// Returns the timestamp of the earliest time that the light wallet server may be queried for
    /// UTXOs associated with this address, or `None` if the wallet backend is not placing any
    /// restrictions on when this address can be queried. Unless the wallet application is
    /// requesting address information from a light wallet server that is trusted for privacy,
    /// only one such query should be performed at a time, to avoid linking multiple transparent
    /// addresses as belonging to the same wallet in the view of the light wallet server.
    pub fn next_check_time(&self) -> Option<SystemTime> {
        self.next_check_time
    }

    /// Returns the [`TransparentKeyScope`] of the private key from which the address was derived,
    /// if known. Returns `None` for standalone addresses in the wallet.
    pub fn scope(&self) -> Option<TransparentKeyScope> {
        self.source.scope()
    }

    /// Returns the BIP 44 [`NonHardenedChildIndex`] at which the address was derived, if known.
    /// Returns `None` for standalone addresses in the wallet.
    pub fn address_index(&self) -> Option<NonHardenedChildIndex> {
        self.source.address_index()
    }
}

/// Source information for a transparent address.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "transparent-inputs")]
pub enum TransparentAddressSource {
    /// BIP 44 path derivation information for the address below account pubkey level, i.e. the
    /// `change` and `index` elements of the path.
    Derived {
        scope: TransparentKeyScope,
        address_index: NonHardenedChildIndex,
    },
    /// The address was derived from a secp256k1 public key for which derivation information is
    /// unknown or for which the associated spending key was produced from system randomness.
    /// This variant provides the public key directly.
    #[cfg(feature = "transparent-key-import")]
    Standalone(secp256k1::PublicKey),
}

#[cfg(feature = "transparent-inputs")]
impl TransparentAddressSource {
    /// Returns the [`TransparentKeyScope`] of the private key from which the address was derived,
    /// if known. Returns `None` for standalone addresses in the wallet.
    pub fn scope(&self) -> Option<TransparentKeyScope> {
        match self {
            TransparentAddressSource::Derived { scope, .. } => Some(*scope),
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::Standalone(_) => None,
        }
    }

    /// Returns the BIP 44 [`NonHardenedChildIndex`] at which the address was derived, if known.
    /// Returns `None` for standalone addresses in the wallet.
    pub fn address_index(&self) -> Option<NonHardenedChildIndex> {
        match self {
            TransparentAddressSource::Derived { address_index, .. } => Some(*address_index),
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::Standalone(_) => None,
        }
    }
}
