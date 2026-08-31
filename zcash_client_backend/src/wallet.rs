//! Structs representing transaction data scanned from the block chain by a wallet or
//! light client.
use std::fmt::Debug;

use incrementalmerkletree::Position;

use ::transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
    keys::TransparentKeyScope,
};
use zcash_address::ZcashAddress;
use zcash_keys::{address::Receiver, keys::OutgoingViewingKey};
use zcash_note_encryption::EphemeralKeyBytes;
use zcash_primitives::transaction::{TxId, fees::transparent as transparent_fees};
use zcash_protocol::{
    PoolType, ShieldedPool,
    consensus::{BlockHeight, TxIndex},
    value::{BalanceError, Zatoshis},
};
#[cfg(feature = "transparent-inputs")]
use zcash_script::script;
use zip32::Scope;

use crate::{TransferType, fees::sapling as sapling_fees};

#[cfg(feature = "orchard")]
use crate::fees::orchard as orchard_fees;

#[cfg(feature = "transparent-inputs")]
use {::transparent::keys::NonHardenedChildIndex, std::time::SystemTime};

/// A unique identifier for a shielded transaction output
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoteId {
    txid: TxId,
    protocol: ShieldedPool,
    output_index: u16,
}

impl NoteId {
    /// Constructs a new `NoteId` from its parts.
    pub fn new(txid: TxId, protocol: ShieldedPool, output_index: u16) -> Self {
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
    pub fn protocol(&self) -> ShieldedPool {
        self.protocol
    }

    /// Returns the index of this note within its transaction's corresponding list of
    /// shielded outputs.
    pub fn output_index(&self) -> u16 {
        self.output_index
    }
}

/// A reference to a transaction output received by the wallet, across all pools.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputRef {
    txid: TxId,
    pool: PoolType,
    output_index: u32,
}

impl OutputRef {
    /// Constructs a new `OutputRef` from its parts.
    pub fn new(txid: TxId, pool: PoolType, output_index: u32) -> Self {
        Self {
            txid,
            pool,
            output_index,
        }
    }

    /// Returns the ID of the transaction containing this output.
    pub fn txid(&self) -> &TxId {
        &self.txid
    }

    /// Returns the pool type of this output.
    pub fn pool(&self) -> PoolType {
        self.pool
    }

    /// Returns the index of this output within its transaction.
    pub fn output_index(&self) -> u32 {
        self.output_index
    }
}

impl From<NoteId> for OutputRef {
    fn from(note_id: NoteId) -> Self {
        Self {
            txid: note_id.txid,
            pool: PoolType::Shielded(note_id.protocol),
            output_index: note_id.output_index.into(),
        }
    }
}

pub use crate::data_api::locking::LockOwner;

/// A type that represents the recipient of a transaction output.
///
/// Variants vary along two independent axes:
///
/// * **Relationship to the wallet**: whether the recipient address is [`Self::External`] to
///   the wallet, an [`Self::EphemeralTransparent`] address of a wallet account (used
///   transiently as a middle hop), or otherwise internal to a wallet account (recorded as
///   [`Self::InternalShielded`] or [`Self::InternalTransparent`], depending on payload
///   domain).
/// * **Payload domain**: whether the output is shielded (in which case what is recorded is
///   the decrypted [`Note`], since the recipient address is not itself externally
///   meaningful) or transparent (in which case what is recorded is the on-chain-observable
///   recipient address, since transparent outputs carry no analogous decryptable payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient<AccountId> {
    /// An output sent to a recipient external to the wallet.
    External {
        recipient_address: ZcashAddress,
        output_pool: PoolType,
    },
    /// A transparent output sent to an ephemeral address of a wallet account
    /// (e.g. the middle hop of a ZIP 320 / TEX flow). The `outpoint` is
    /// recorded so the wallet can later detect when this output is spent
    /// without relying on a continuous address watch.
    #[cfg(feature = "transparent-inputs")]
    EphemeralTransparent {
        receiving_account: AccountId,
        ephemeral_address: TransparentAddress,
        outpoint: OutPoint,
    },
    /// A transparent output sent to a non-ephemeral transparent address belonging to
    /// a wallet account. Used to record the send side of a transparent output that
    /// the wallet both funded and received.
    ///
    /// Distinct from [`Self::InternalShielded`] because for transparent outputs
    /// the recipient address is observable on chain and must be recorded;
    /// additionally, the receiving account may not be known at the point the
    /// send is recorded. For shielded outputs the recipient address is not
    /// externally meaningful, so wallet-internal sends are recorded against
    /// the receiving account alone.
    #[cfg(feature = "transparent-inputs")]
    InternalTransparent {
        receiving_account: AccountId,
        recipient_address: TransparentAddress,
    },
    /// A shielded output recorded against a wallet account. Used for
    /// same-account outputs such as change (`external_address` is `None`) and
    /// for outputs received via an external IVK but funded by another wallet
    /// account, in which case `external_address` is the address that was paid.
    InternalShielded {
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
    block_index: TxIndex,
    transparent_spends: Vec<WalletTransparentSpend<AccountId>>,
    transparent_outputs: Vec<WalletTransparentOutput<AccountId>>,
    #[cfg(feature = "transparent-inputs")]
    transparent_address_observations: Vec<TransparentAddressObservation>,
    sapling_spends: Vec<WalletSaplingSpend<AccountId>>,
    sapling_outputs: Vec<WalletSaplingOutput<AccountId>>,
    #[cfg(feature = "orchard")]
    orchard_spends: Vec<WalletOrchardSpend<AccountId>>,
    #[cfg(feature = "orchard")]
    orchard_outputs: Vec<WalletOrchardOutput<AccountId>>,
    #[cfg(feature = "orchard")]
    ironwood_spends: Vec<WalletIronwoodSpend<AccountId>>,
    #[cfg(feature = "orchard")]
    ironwood_outputs: Vec<WalletIronwoodOutput<AccountId>>,
}

impl<AccountId> WalletTx<AccountId> {
    /// Constructs a new [`WalletTx`] from its constituent parts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        txid: TxId,
        block_index: TxIndex,
        transparent_spends: Vec<WalletTransparentSpend<AccountId>>,
        transparent_outputs: Vec<WalletTransparentOutput<AccountId>>,
        #[cfg(feature = "transparent-inputs")] transparent_address_observations: Vec<
            TransparentAddressObservation,
        >,
        sapling_spends: Vec<WalletSaplingSpend<AccountId>>,
        sapling_outputs: Vec<WalletSaplingOutput<AccountId>>,
        #[cfg(feature = "orchard")] orchard_spends: Vec<
            WalletSpend<orchard::note::Nullifier, AccountId>,
        >,
        #[cfg(feature = "orchard")] orchard_outputs: Vec<WalletOrchardOutput<AccountId>>,
        #[cfg(feature = "orchard")] ironwood_spends: Vec<
            WalletSpend<orchard::note::Nullifier, AccountId>,
        >,
        #[cfg(feature = "orchard")] ironwood_outputs: Vec<WalletIronwoodOutput<AccountId>>,
    ) -> Self {
        Self {
            txid,
            block_index,
            transparent_spends,
            transparent_outputs,
            #[cfg(feature = "transparent-inputs")]
            transparent_address_observations,
            sapling_spends,
            sapling_outputs,
            #[cfg(feature = "orchard")]
            orchard_spends,
            #[cfg(feature = "orchard")]
            orchard_outputs,
            #[cfg(feature = "orchard")]
            ironwood_spends,
            #[cfg(feature = "orchard")]
            ironwood_outputs,
        }
    }

    /// Returns the [`TxId`] for the corresponding [`Transaction`].
    ///
    /// [`Transaction`]: zcash_primitives::transaction::Transaction
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// Returns the index of the transaction in the containing block.
    pub fn block_index(&self) -> TxIndex {
        self.block_index
    }

    /// Returns a record for each transparent output belonging to the wallet that was spent in
    /// the transaction.
    pub fn transparent_spends(&self) -> &[WalletTransparentSpend<AccountId>] {
        &self.transparent_spends
    }

    /// Returns a record for each transparent coin received or produced by the wallet.
    pub fn transparent_outputs(&self) -> &[WalletTransparentOutput<AccountId>] {
        &self.transparent_outputs
    }

    /// Returns a record of every transparent address that this transaction's transparent data
    /// names, whether or not the wallet controls it.
    ///
    /// The set covers only the involvement directions the data this record was built from can
    /// express: scanning a compact block yields output observations, since a compact input
    /// carries no `scriptSig` and so names no address, while scanning a full block yields both
    /// directions.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent_address_observations(&self) -> &[TransparentAddressObservation] {
        &self.transparent_address_observations
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

    /// Returns a record for each Ironwood note belonging to the wallet that was spent in the
    /// transaction.
    #[cfg(feature = "orchard")]
    pub fn ironwood_spends(&self) -> &[WalletIronwoodSpend<AccountId>] {
        self.ironwood_spends.as_ref()
    }

    /// Returns a record for each Ironwood note received or produced by the wallet in the
    /// transaction.
    #[cfg(feature = "orchard")]
    pub fn ironwood_outputs(&self) -> &[WalletIronwoodOutput<AccountId>] {
        self.ironwood_outputs.as_ref()
    }
}

/// A transparent output controlled by the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletTransparentOutput<AccountId> {
    outpoint: OutPoint,
    txout: TxOut,
    mined_height: Option<BlockHeight>,
    recipient_account: Option<AccountId>,
    recipient_key_scope: Option<TransparentKeyScope>,
    recipient_address: TransparentAddress,
    funding_account: Option<AccountId>,
    /// The known serialized input size for this output, if available.
    /// This is set for P2SH outputs where the redeem script is known.
    known_input_size: Option<usize>,
}

impl<AccountId> WalletTransparentOutput<AccountId> {
    /// Constructs a new [`WalletTransparentOutput`] from its constituent parts.
    ///
    /// Returns `None` if the recipient address for the provided [`TxOut`] cannot be
    /// determined based on the set of output script patterns understood by this wallet.
    pub fn from_parts(
        outpoint: OutPoint,
        txout: TxOut,
        mined_height: Option<BlockHeight>,
        recipient_account: Option<AccountId>,
        recipient_key_scope: Option<TransparentKeyScope>,
        funding_account: Option<AccountId>,
    ) -> Option<Self> {
        txout
            .recipient_address()
            .map(|recipient_address| WalletTransparentOutput {
                outpoint,
                txout,
                mined_height,
                recipient_account,
                recipient_key_scope,
                recipient_address,
                funding_account,
                known_input_size: None,
            })
    }

    /// Returns a copy of this output with account-identifying data redacted,
    /// for inclusion in a [`Proposal`].
    ///
    /// Specifically:
    /// - The `AccountId` type parameter is replaced with `()`, erasing the value
    ///   of `recipient_account` while preserving whether the output is
    ///   wallet-owned (the `Some` / `None` distinction is retained).
    /// - `funding_account` is cleared to `None`, since a proposal does not
    ///   carry information about which account funded prior outputs.
    ///
    /// Used when constructing or reconstructing a [`Proposal`], whose
    /// transparent inputs are deliberately account-agnostic so that proposals
    /// can be wire-encoded and shared without revealing wallet account
    /// structure.
    ///
    /// [`Proposal`]: crate::proposal::Proposal
    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn redact_account_data(self) -> WalletTransparentOutput<()> {
        WalletTransparentOutput {
            outpoint: self.outpoint,
            txout: self.txout,
            mined_height: self.mined_height,
            recipient_account: self.recipient_account.map(|_| ()),
            recipient_key_scope: self.recipient_key_scope,
            recipient_address: self.recipient_address,
            funding_account: None,
            known_input_size: self.known_input_size,
        }
    }

    /// Sets the known serialized input size for this output.
    ///
    /// This should be used for P2SH outputs where the wallet knows the redeem script
    /// and can compute the expected input size for fee calculation.
    pub fn with_known_input_size(mut self, size: usize) -> Self {
        self.known_input_size = Some(size);
        self
    }

    /// Returns the [`OutPoint`] corresponding to the output.
    pub fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    /// The index of the output in the transaction that created this output.
    pub fn index(&self) -> usize {
        self.outpoint.n() as usize
    }

    /// Returns the transaction output itself.
    pub fn txout(&self) -> &TxOut {
        &self.txout
    }

    /// Returns the height at which the UTXO was mined, if any.
    pub fn mined_height(&self) -> Option<BlockHeight> {
        self.mined_height
    }

    /// Returns the transparent key scope at which this address was derived, if known.
    ///
    /// This metadata MUST be returned for any transparent address derived by the wallet;
    /// this metadata is used by `propose_shielding` to ensure that shielding transactions
    /// do not inadvertently link ephemeral addresses to other wallet activity on-chain.
    pub fn recipient_key_scope(&self) -> Option<TransparentKeyScope> {
        self.recipient_key_scope
    }

    /// Returns the [`TransferType`] for this output, derived from the recipient,
    /// recipient-key-scope, and funding-account information stored on the output:
    ///
    /// - [`TransferType::Outgoing`] when [`recipient_account`](Self::recipient_account)
    ///   is `None` (the recipient is external to the wallet).
    /// - [`TransferType::AccountInternal`] when the recipient is a wallet account and
    ///   the output is a same-account self-transfer. This is detected either
    ///   structurally, when [`recipient_key_scope`](Self::recipient_key_scope) is
    ///   `INTERNAL` or `EPHEMERAL` (those key scopes exist only within a single
    ///   account), or by observation, when the recipient account is also the
    ///   [`funding_account`](Self::funding_account). The latter case also covers
    ///   standalone addresses, which have no key scope.
    /// - [`TransferType::WalletInternal`] when the recipient is a wallet account and
    ///   the [`funding_account`](Self::funding_account) is a different wallet account
    ///   (a cross-account transfer within the wallet).
    /// - [`TransferType::Incoming`] when the recipient is a wallet account and no
    ///   wallet funding account is known.
    pub fn transfer_type(&self) -> TransferType
    where
        AccountId: PartialEq,
    {
        match (
            self.recipient_account.as_ref(),
            self.recipient_key_scope,
            self.funding_account.as_ref(),
        ) {
            (None, _, _) => TransferType::Outgoing,
            (Some(_), Some(TransparentKeyScope::INTERNAL | TransparentKeyScope::EPHEMERAL), _) => {
                TransferType::AccountInternal
            }
            (Some(r), _, Some(r0)) if r == r0 => TransferType::AccountInternal,
            (Some(_), _, Some(_)) => TransferType::WalletInternal,
            (Some(_), _, _) => TransferType::Incoming,
        }
    }

    /// The identifier for the account that received this output, if known to belong to the
    /// wallet. Returns `None` for outputs sent to addresses outside the wallet.
    pub fn recipient_account(&self) -> Option<&AccountId> {
        self.recipient_account.as_ref()
    }

    /// Returns the wallet address that received the UTXO.
    pub fn recipient_address(&self) -> &TransparentAddress {
        &self.recipient_address
    }

    /// The identifier for the wallet account that provided funds in the transaction
    /// that created the output, if known.
    ///
    /// Note: the Zcash protocol permits construction of transactions where multiple distinct
    /// accounts provide funds; however, `zcash_client_backend` does not currently support the
    /// construction of transactions of this form. In cases where multiple funding accounts are
    /// detected, the account that provided the most significant source of funds should be selected
    /// if possible; in the future, this should be either expanded to support a set of funding
    /// accounts (which will require potentially invasive storage backend changes).
    pub fn funding_account(&self) -> Option<&AccountId> {
        self.funding_account.as_ref()
    }

    /// Returns the value of the UTXO
    pub fn value(&self) -> Zatoshis {
        self.txout.value()
    }
}

/// The way in which a transaction's transparent data names an address, and the data that the
/// involvement carries.
#[cfg(feature = "transparent-inputs")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInvolvement {
    /// The observed address is paid by the transaction output at the observed index, which has
    /// the given value.
    Output(Zatoshis),
    /// The observed address is revealed by the `scriptSig` of the transaction input at the
    /// observed index, which spends the given outpoint.
    Input(OutPoint),
}

/// A record that a transaction's transparent data names a particular address.
///
/// An observation is recorded for every address a wallet-involved transaction names, whether or
/// not the wallet controls that address, so that the involvement can be recognized if a key
/// covering the address is added to the wallet afterwards.
///
/// An observation is identified by the transaction it belongs to, the direction of its
/// [`Self::involvement`], and its [`Self::item_index`]; the address and the involvement data
/// are functions of that identity, so observing the same transaction twice yields identical
/// records.
#[cfg(feature = "transparent-inputs")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentAddressObservation {
    address: TransparentAddress,
    item_index: u32,
    involvement: TransparentInvolvement,
}

#[cfg(feature = "transparent-inputs")]
impl TransparentAddressObservation {
    /// Constructs an observation of the address paid by the transaction output at `item_index`.
    pub fn output(item_index: u32, address: TransparentAddress, value: Zatoshis) -> Self {
        Self {
            address,
            item_index,
            involvement: TransparentInvolvement::Output(value),
        }
    }

    /// Constructs an observation of the address revealed by the `scriptSig` of the transaction
    /// input at `item_index`, which spends `prevout`.
    pub fn input(item_index: u32, address: TransparentAddress, prevout: OutPoint) -> Self {
        Self {
            address,
            item_index,
            involvement: TransparentInvolvement::Input(prevout),
        }
    }

    /// Returns the observed address.
    pub fn address(&self) -> &TransparentAddress {
        &self.address
    }

    /// Returns the index of the output or input that names the address, within the
    /// transaction's `vout` or `vin` respectively.
    pub fn item_index(&self) -> u32 {
        self.item_index
    }

    /// Returns the direction of the involvement, and the data that it carries.
    pub fn involvement(&self) -> &TransparentInvolvement {
        &self.involvement
    }
}

/// The serialized length of a compressed secp256k1 public key.
#[cfg(feature = "transparent-inputs")]
const COMPRESSED_PUBKEY_LEN: usize = 33;

/// The serialized length of an uncompressed secp256k1 public key.
#[cfg(feature = "transparent-inputs")]
const UNCOMPRESSED_PUBKEY_LEN: usize = 65;

/// The number of pushes in a P2PKH `scriptSig`: the signature, then the public key.
#[cfg(feature = "transparent-inputs")]
const P2PKH_SIG_PUSH_COUNT: usize = 2;

/// Returns the address that a `scriptSig` reveals as the recipient of the output it spends, if
/// the script has a shape from which the address can be recovered.
///
/// Both recognized shapes end with the material that the spent `scriptPubKey` commits to: a
/// P2PKH `scriptSig` is `<sig> <pubkey>`, whose address is the HASH160 of the public key; any
/// other push-only `scriptSig` is read as a P2SH spend, whose address is the HASH160 of its
/// final push (the redeem script). A `scriptSig` that is empty or not push-only yields `None`.
///
/// The two shapes are distinguished without reference to the output being spent, which the
/// wallet need not hold: a two-push `scriptSig` whose final push is a valid public key encoding
/// is read as P2PKH. A P2SH redeem script that is itself a valid public key encoding, spent by a
/// single-signature `scriptSig`, is therefore misread as P2PKH; no standard redeem script has
/// that shape. A misread names an address of the wrong kind, which matches nothing the wallet
/// holds, so the input direction misses that spend permanently — unless the transaction that
/// created the spent output is itself stored, since its output observation names the address
/// correctly.
#[cfg(feature = "transparent-inputs")]
fn address_from_script_sig(
    script_sig: &::transparent::address::Script,
) -> Option<TransparentAddress> {
    let pushes = script::Sig::parse(&script_sig.0).ok()?.0;
    let last = pushes.last()?.value();

    // Equivalent to `CPubKey::GetLen` composed with `CPubKey::ValidSize`: the leading byte of a
    // serialized public key determines the length the encoding must have.
    let is_pubkey = match last.first() {
        Some(2 | 3) => last.len() == COMPRESSED_PUBKEY_LEN,
        Some(4 | 6 | 7) => last.len() == UNCOMPRESSED_PUBKEY_LEN,
        _ => false,
    };

    Some(if pushes.len() == P2PKH_SIG_PUSH_COUNT && is_pubkey {
        TransparentAddress::PublicKeyHash(::transparent::util::hash160::hash(&last))
    } else {
        TransparentAddress::ScriptHash(::transparent::util::hash160::hash(&last))
    })
}

/// Returns an observation for every address named by the given transaction's transparent data:
/// one for each output whose `scriptPubKey` describes an address, and one for each non-coinbase
/// input whose `scriptSig` reveals the address of the output it spends.
///
/// Outputs and inputs whose scripts name no address are omitted. Script data that does not
/// parse names no address; it is chain data the wallet does not control, so it is skipped
/// rather than reported as an error.
#[cfg(feature = "transparent-inputs")]
pub fn transparent_address_observations(
    tx: &zcash_primitives::transaction::Transaction,
) -> Vec<TransparentAddressObservation> {
    let mut observations = vec![];

    let Some(bundle) = tx.transparent_bundle() else {
        return observations;
    };

    for (output_index, txout) in bundle.vout.iter().enumerate() {
        if let Some(address) = txout.recipient_address() {
            observations.push(TransparentAddressObservation::output(
                u32::try_from(output_index).expect("a transaction has fewer than 2^32 outputs"),
                address,
                txout.value(),
            ));
        }
    }

    // A coinbase transaction's single input carries arbitrary data in its `scriptSig` and
    // spends the null outpoint, so it reveals no address and references no prior output.
    if !bundle.is_coinbase() {
        for (input_index, txin) in bundle.vin.iter().enumerate() {
            if let Some(address) = address_from_script_sig(txin.script_sig()) {
                observations.push(TransparentAddressObservation::input(
                    u32::try_from(input_index).expect("a transaction has fewer than 2^32 inputs"),
                    address,
                    txin.prevout().clone(),
                ));
            }
        }
    }

    observations
}

impl<AccountId: Debug> transparent_fees::InputView for WalletTransparentOutput<AccountId> {
    fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }
    fn coin(&self) -> &TxOut {
        &self.txout
    }
    fn serialized_size(&self) -> transparent_fees::InputSize {
        match self.known_input_size {
            Some(size) => transparent_fees::InputSize::Known(size),
            None => {
                match zcash_script::script::PubKey::parse(&self.txout.script_pubkey().0)
                    .ok()
                    .as_ref()
                    .and_then(zcash_script::solver::standard)
                {
                    Some(zcash_script::solver::ScriptKind::PubKeyHash { .. }) => {
                        transparent_fees::InputSize::STANDARD_P2PKH
                    }
                    Some(zcash_script::solver::ScriptKind::ScriptHash { .. }) => {
                        // P2SH input size depends on the redeem script, which the
                        // wallet must set via `with_known_input_size` (the SQLite
                        // backend does this by reading the redeem script from the DB
                        // and computing the exact size via
                        // `p2sh_input_serialized_len`). Without it we cannot
                        // determine the exact input size; return `Unknown` so the
                        // estimator falls back to the consensus-maximum input size
                        // rather than guessing.
                        transparent_fees::InputSize::Unknown(self.outpoint.clone())
                    }
                    _ => transparent_fees::InputSize::Unknown(self.outpoint.clone()),
                }
            }
        }
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

/// A type alias for Ironwood [`WalletSpend`]s.
///
/// Ironwood notes are Orchard-shaped and therefore share the Orchard nullifier type, but Ironwood
/// is a distinct pool from Orchard.
#[cfg(feature = "orchard")]
pub type WalletIronwoodSpend<AccountId> = WalletSpend<orchard::note::Nullifier, AccountId>;

/// A reference to a transparent output belonging to the wallet that is spent within a
/// transaction.
///
/// This is the transparent counterpart of [`WalletSpend`]. A transparent output is identified by
/// the [`OutPoint`] that names it rather than by a nullifier, so unlike a shielded spend it can be
/// recognized only by a wallet that already knows of the output being spent.
#[derive(Clone, Debug)]
pub struct WalletTransparentSpend<AccountId> {
    index: usize,
    outpoint: OutPoint,
    account_id: AccountId,
}

impl<AccountId> WalletTransparentSpend<AccountId> {
    /// Constructs a `WalletTransparentSpend` from its constituent parts.
    pub fn from_parts(index: usize, outpoint: OutPoint, account_id: AccountId) -> Self {
        Self {
            index,
            outpoint,
            account_id,
        }
    }

    /// Returns the index of the transparent input within the spending transaction.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the outpoint of the output being spent.
    pub fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    /// Returns the identifier for the account to which the spent output belonged.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

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
    WalletOutput<(orchard::note::Note, orchard::ValuePool), orchard::note::Nullifier, AccountId>;

/// The output part of an Ironwood [`Action`] that was decrypted in the process of scanning.
///
/// [`Action`]: orchard::Action
#[cfg(feature = "orchard")]
pub type WalletIronwoodOutput<AccountId> =
    WalletOutput<(orchard::note::Note, orchard::ValuePool), orchard::note::Nullifier, AccountId>;

/// An enumeration of supported shielded note types for use in [`ReceivedNote`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    Sapling(sapling::Note),
    #[cfg(feature = "orchard")]
    Orchard {
        note: orchard::Note,
        pool: orchard::ValuePool,
    },
}

impl Note {
    /// Returns the receiver of this note.
    pub fn receiver(&self) -> Receiver {
        match self {
            Note::Sapling(n) => Receiver::Sapling(n.recipient()),
            #[cfg(feature = "orchard")]
            Note::Orchard { note, .. } => Receiver::Orchard(note.recipient()),
        }
    }

    pub fn value(&self) -> Zatoshis {
        match self {
            Note::Sapling(n) => n.value().inner().try_into().expect(
                "Sapling notes must have values in the range of valid non-negative ZEC values.",
            ),
            #[cfg(feature = "orchard")]
            Note::Orchard { note, .. } => Zatoshis::from_u64(note.value().inner()).expect(
                "Orchard notes must have values in the range of valid non-negative ZEC values.",
            ),
        }
    }

    /// Returns the shielded value pool to which this note belongs.
    pub fn pool(&self) -> ShieldedPool {
        match self {
            Note::Sapling(_) => ShieldedPool::Sapling,
            #[cfg(feature = "orchard")]
            Note::Orchard { pool, .. } => shielded_pool_for_value_pool(*pool),
        }
    }
}

/// Returns the shielded pool corresponding to an Orchard-protocol value pool. The Orchard protocol
/// serves both the Orchard pool (version-2 notes) and the Ironwood pool (version-3 notes); this is
/// the single point at which that classification is made.
#[cfg(feature = "orchard")]
pub(crate) fn shielded_pool_for_value_pool(pool: orchard::ValuePool) -> ShieldedPool {
    match pool {
        orchard::ValuePool::Orchard => ShieldedPool::Orchard,
        orchard::ValuePool::Ironwood => ShieldedPool::Ironwood,
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
#[cfg(feature = "transparent-inputs")]
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

    /// Returns a [`TransparentAddressMetadata`] with [`TransparentAddressSource::StandalonePubkey`]
    /// source information for a P2PKH address and the specified exposure height.
    #[cfg(feature = "transparent-key-import")]
    pub fn standalone_p2pkh(
        pubkey: secp256k1::PublicKey,
        exposure: Exposure,
        next_check_time: Option<SystemTime>,
    ) -> Self {
        Self {
            source: TransparentAddressSource::StandalonePubkey(pubkey),
            exposure,
            next_check_time,
        }
    }

    /// Returns a [`TransparentAddressMetadata`] with [`TransparentAddressSource::StandaloneScript`]
    /// source information for a P2SH address and the specified exposure height.
    #[cfg(feature = "transparent-key-import")]
    pub fn standalone_script(
        redeem_script: script::Redeem,
        exposure: Exposure,
        next_check_time: Option<SystemTime>,
    ) -> Self {
        Self {
            source: TransparentAddressSource::StandaloneScript(redeem_script),
            exposure,
            next_check_time,
        }
    }

    /// Returns a [`TransparentAddressMetadata`] with [`TransparentAddressSource::StandaloneAddress`]
    /// source information for an imported bare transparent address and the specified exposure
    /// height.
    #[cfg(feature = "transparent-key-import")]
    pub fn standalone_address(exposure: Exposure, next_check_time: Option<SystemTime>) -> Self {
        Self {
            source: TransparentAddressSource::StandaloneAddress,
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

    /// Returns the redeem script for the address, if this is a P2SH address.
    /// Returns `None` for non-P2SH addresses.
    #[cfg(feature = "transparent-key-import")]
    pub fn redeem_script(&self) -> Option<&script::Redeem> {
        self.source.redeem_script()
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
    StandalonePubkey(secp256k1::PublicKey),

    /// The address was derived from a P2SH redeem_script for which derivation information is
    /// unknown.
    /// This variant provides the redeem script directly.
    #[cfg(feature = "transparent-key-import")]
    StandaloneScript(script::Redeem),

    /// The address was imported as a bare transparent address, without any associated key
    /// material. The wallet watches for outputs received by the address, but holds neither
    /// the public key (P2PKH) nor the redeem script (P2SH) from which it was derived, so
    /// funds received by it cannot be spent unless that material is subsequently imported.
    #[cfg(feature = "transparent-key-import")]
    StandaloneAddress,
}

#[cfg(feature = "transparent-inputs")]
impl TransparentAddressSource {
    /// Returns the [`TransparentKeyScope`] of the private key from which the address was derived,
    /// if known. Returns `None` for standalone addresses in the wallet.
    pub fn scope(&self) -> Option<TransparentKeyScope> {
        match self {
            TransparentAddressSource::Derived { scope, .. } => Some(*scope),
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::StandalonePubkey(_) => None,
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::StandaloneScript(_) => None,
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::StandaloneAddress => None,
        }
    }

    /// Returns the BIP 44 [`NonHardenedChildIndex`] at which the address was derived, if known.
    /// Returns `None` for standalone addresses in the wallet.
    pub fn address_index(&self) -> Option<NonHardenedChildIndex> {
        match self {
            TransparentAddressSource::Derived { address_index, .. } => Some(*address_index),
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::StandalonePubkey(_) => None,
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::StandaloneScript(_) => None,
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::StandaloneAddress => None,
        }
    }

    /// Returns the redeem script for the address, if this is a P2SH address.
    /// Returns `None` for non-P2SH addresses.
    #[cfg(feature = "transparent-key-import")]
    pub fn redeem_script(&self) -> Option<&script::Redeem> {
        match self {
            TransparentAddressSource::Derived { .. } => None,
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::StandalonePubkey(_) => None,
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::StandaloneScript(redeem_script) => Some(redeem_script),
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::StandaloneAddress => None,
        }
    }
}

/// Property tests for [`OutputRef`], whose identity (txid, pool, output index) is the key the
/// note-locking tables and the proposal double-spend check operate on.
#[cfg(test)]
mod output_ref_tests {
    use proptest::prelude::*;
    use zcash_protocol::{PoolType, ShieldedPool, TxId};

    use super::{NoteId, OutputRef};

    fn arb_shielded_pool() -> impl Strategy<Value = ShieldedPool> {
        prop_oneof![
            Just(ShieldedPool::Sapling),
            Just(ShieldedPool::Orchard),
            Just(ShieldedPool::Ironwood),
        ]
    }

    fn arb_pool_type() -> impl Strategy<Value = PoolType> {
        prop_oneof![
            Just(PoolType::Transparent),
            arb_shielded_pool().prop_map(PoolType::Shielded),
        ]
    }

    fn arb_output_ref() -> impl Strategy<Value = OutputRef> {
        (any::<[u8; 32]>(), arb_pool_type(), any::<u32>())
            .prop_map(|(txid, pool, idx)| OutputRef::new(TxId::from_bytes(txid), pool, idx))
    }

    proptest! {
        /// Converting a `NoteId` preserves every component: the note's pool maps into the
        /// shielded arm of `PoolType`, and the `u16` output index widens losslessly.
        #[test]
        fn from_note_id_preserves_fields(
            txid in any::<[u8; 32]>(),
            pool in arb_shielded_pool(),
            idx in any::<u16>(),
        ) {
            let txid = TxId::from_bytes(txid);
            let output_ref = OutputRef::from(NoteId::new(txid, pool, idx));
            prop_assert_eq!(output_ref.txid(), &txid);
            prop_assert_eq!(output_ref.pool(), PoolType::Shielded(pool));
            prop_assert_eq!(output_ref.output_index(), u32::from(idx));
        }

        /// Identity is exactly the (txid, pool, output index) triple: a reference equals
        /// itself, differs from any single-field mutation of itself, and `Ord` agrees with
        /// `Eq` (the `BTreeSet` double-spend check in proposal construction and the lock
        /// tables both rely on this).
        #[test]
        fn identity_is_the_full_triple(a in arb_output_ref()) {
            prop_assert_eq!(a, a);
            prop_assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);

            // A different output index is a different output.
            let other_index = OutputRef::new(
                *a.txid(),
                a.pool(),
                a.output_index().wrapping_add(1),
            );
            prop_assert_ne!(a, other_index);
            prop_assert_ne!(a.cmp(&other_index), std::cmp::Ordering::Equal);

            // A different pool is a different output, even at the same (txid, index): the
            // same transaction may have outputs at the same index in several pools.
            let other_pool = OutputRef::new(
                *a.txid(),
                match a.pool() {
                    PoolType::Transparent => PoolType::SAPLING,
                    PoolType::Shielded(_) => PoolType::Transparent,
                },
                a.output_index(),
            );
            prop_assert_ne!(a, other_pool);
            prop_assert_ne!(a.cmp(&other_pool), std::cmp::Ordering::Equal);

            // A different transaction is a different output.
            let mut txid = <[u8; 32]>::from(*a.txid());
            txid[0] = txid[0].wrapping_add(1);
            let other_txid = OutputRef::new(TxId::from_bytes(txid), a.pool(), a.output_index());
            prop_assert_ne!(a, other_txid);
            prop_assert_ne!(a.cmp(&other_txid), std::cmp::Ordering::Equal);
        }

        /// Two independently drawn references are equal exactly when all three components
        /// match.
        #[test]
        fn equality_is_component_wise(a in arb_output_ref(), b in arb_output_ref()) {
            let components_equal = a.txid() == b.txid()
                && a.pool() == b.pool()
                && a.output_index() == b.output_index();
            prop_assert_eq!(a == b, components_equal);
        }
    }
}

#[cfg(all(test, feature = "transparent-inputs"))]
mod transparent_observation_tests {
    use ::transparent::{
        address::{Script, TransparentAddress},
        bundle::{Authorized as TransparentAuthorized, Bundle, OutPoint, TxIn, TxOut},
        util::hash160,
    };
    use zcash_primitives::transaction::{Authorized, Transaction, TransactionData, TxVersion};
    use zcash_protocol::{
        consensus::{BlockHeight, BranchId},
        value::Zatoshis,
    };
    use zcash_script::script;

    use proptest::prelude::*;

    use super::{
        TransparentAddressObservation, TransparentInvolvement, address_from_script_sig,
        transparent_address_observations,
    };

    /// The `OP_CHECKSIG` opcode, which is not a push and so makes a `scriptSig` unreadable.
    const OP_CHECKSIG: u8 = 0xAC;

    /// A validly-encoded compressed public key: the `0x02` prefix followed by 32 bytes.
    fn pubkey_bytes() -> Vec<u8> {
        let mut bytes = vec![0x02];
        bytes.extend_from_slice(&[0x11; 32]);
        bytes
    }

    /// Builds a push-only script from the given data pushes. Each push is at most 75 bytes, so
    /// each is encoded as its own length byte followed by its data.
    fn push_script(pushes: &[&[u8]]) -> Script {
        let mut code = vec![];
        for data in pushes {
            assert!(
                data.len() < 76,
                "test pushes use the single-byte length form"
            );
            code.push(u8::try_from(data.len()).expect("checked above"));
            code.extend_from_slice(data);
        }
        Script(script::Code(code))
    }

    fn tx_from_bundle(bundle: Bundle<TransparentAuthorized>) -> Transaction {
        TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            BlockHeight::from(0),
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            Zatoshis::ZERO,
            Some(bundle),
            None,
            None,
            None,
        )
        .freeze()
        .expect("transaction data is complete")
    }

    /// A two-push `scriptSig` whose final push is a valid public key encoding is read as a
    /// P2PKH spend, so the revealed address is the HASH160 of that public key.
    #[test]
    fn script_sig_address_reads_p2pkh_shape() {
        let pubkey = pubkey_bytes();
        let script_sig = push_script(&[&[0x30; 71], &pubkey]);

        assert_eq!(
            address_from_script_sig(&script_sig),
            Some(TransparentAddress::PublicKeyHash(hash160::hash(&pubkey)))
        );
    }

    /// Any other push-only `scriptSig` is read as a P2SH spend, so the revealed address is the
    /// HASH160 of its final push, which is the redeem script.
    #[test]
    fn script_sig_address_reads_p2sh_shape() {
        let redeem_script = vec![0xAB; 40];
        let script_sig = push_script(&[&[0x30; 71], &[0x30; 71], &redeem_script]);

        assert_eq!(
            address_from_script_sig(&script_sig),
            Some(TransparentAddress::ScriptHash(hash160::hash(
                &redeem_script
            )))
        );
    }

    /// A `scriptSig` that is empty, or that contains an opcode that is not a push, reveals no
    /// address. Both are chain data the wallet does not control, so neither is an error.
    #[test]
    fn script_sig_address_rejects_unusable_scripts() {
        assert_eq!(address_from_script_sig(&Script(script::Code(vec![]))), None);
        assert_eq!(
            address_from_script_sig(&Script(script::Code(vec![OP_CHECKSIG]))),
            None
        );
    }

    /// Both involvement directions are extracted from a complete transaction, indexed by
    /// position within `vout` and `vin` respectively.
    #[test]
    fn observations_cover_both_directions() {
        let recipient = TransparentAddress::PublicKeyHash([0x22; 20]);
        let pubkey = pubkey_bytes();
        let prevout = OutPoint::new([0x33; 32], 7);
        let value = Zatoshis::const_from_u64(1000);

        let bundle = Bundle::<TransparentAuthorized> {
            vin: vec![TxIn::from_parts(
                prevout.clone(),
                push_script(&[&[0x30; 71], &pubkey]),
                0,
            )],
            vout: vec![TxOut::new(value, Script::from(&recipient.script()))],
            authorization: TransparentAuthorized,
        };

        assert_eq!(
            transparent_address_observations(&tx_from_bundle(bundle)),
            vec![
                TransparentAddressObservation::output(0, recipient, value),
                TransparentAddressObservation::input(
                    0,
                    TransparentAddress::PublicKeyHash(hash160::hash(&pubkey)),
                    prevout,
                ),
            ]
        );
    }

    proptest! {
        /// Script data comes from the chain, so `address_from_script_sig` must be total over
        /// arbitrary bytes: it may recognize no address, but it may not panic, and whatever it
        /// recognizes must be the HASH160 of the script's final push.
        #[test]
        fn script_sig_address_is_total(code in prop::collection::vec(any::<u8>(), 0..300)) {
            let script = Script(script::Code(code.clone()));
            let recognized = address_from_script_sig(&script);

            match script::Sig::parse(&script.0).ok().map(|sig| sig.0) {
                // A push-only script with at least one push always names an address, and that
                // address is the HASH160 of its final push.
                Some(pushes) if !pushes.is_empty() => {
                    let expected = hash160::hash(&pushes.last().unwrap().value());
                    prop_assert_eq!(
                        recognized.map(|address| match address {
                            TransparentAddress::PublicKeyHash(h) => h,
                            TransparentAddress::ScriptHash(h) => h,
                        }),
                        Some(expected)
                    );
                }
                // Anything else names none.
                _ => prop_assert_eq!(recognized, None),
            }
        }

        /// Observation extraction is likewise total: arbitrary `scriptSig` bytes on a
        /// transaction's inputs yield observations or none, never a panic, and every observation
        /// index addresses a real item of the transaction.
        #[test]
        fn observations_are_total(
            script_sigs in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 0..80),
                0..4,
            ),
            output_count in 0usize..4,
        ) {
            let bundle = Bundle::<TransparentAuthorized> {
                vin: script_sigs
                    .iter()
                    .enumerate()
                    .map(|(i, code)| {
                        TxIn::from_parts(
                            OutPoint::new([u8::try_from(i).unwrap(); 32], 0),
                            Script(script::Code(code.clone())),
                            0,
                        )
                    })
                    .collect(),
                vout: (0..output_count)
                    .map(|i| {
                        TxOut::new(
                            Zatoshis::const_from_u64(1),
                            Script::from(
                                &TransparentAddress::PublicKeyHash([u8::try_from(i).unwrap(); 20])
                                    .script(),
                            ),
                        )
                    })
                    .collect(),
                authorization: TransparentAuthorized,
            };
            let is_coinbase = bundle.is_coinbase();
            let tx = tx_from_bundle(bundle);

            for observation in transparent_address_observations(&tx) {
                let index = usize::try_from(observation.item_index()).unwrap();
                match observation.involvement() {
                    TransparentInvolvement::Output(_) => prop_assert!(index < output_count),
                    TransparentInvolvement::Input(_) => {
                        prop_assert!(!is_coinbase);
                        prop_assert!(index < script_sigs.len());
                    }
                }
            }
        }
    }

    /// A coinbase transaction's single input carries arbitrary data and spends the null
    /// outpoint, so it contributes no input observation.
    #[test]
    fn observations_skip_coinbase_inputs() {
        let recipient = TransparentAddress::PublicKeyHash([0x44; 20]);
        let value = Zatoshis::const_from_u64(500);

        let bundle = Bundle::<TransparentAuthorized> {
            vin: vec![TxIn::from_parts(
                OutPoint::NULL,
                push_script(&[&[0x01, 0x02, 0x03]]),
                0,
            )],
            vout: vec![TxOut::new(value, Script::from(&recipient.script()))],
            authorization: TransparentAuthorized,
        };

        assert_eq!(
            transparent_address_observations(&tx_from_bundle(bundle)),
            vec![TransparentAddressObservation::output(0, recipient, value)]
        );
    }
}
