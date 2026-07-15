//! This module contains generated code for handling light client protobuf structs.

use incrementalmerkletree::frontier::CommitmentTree;
use nonempty::NonEmpty;
use std::{
    array::TryFromSliceError,
    collections::BTreeMap,
    fmt::{self, Display},
    io,
    num::NonZeroU32,
};
use zcash_address::unified::{self, Encoding};

use sapling::{self, Node, note::ExtractedNoteCommitment};
use zcash_note_encryption::{COMPACT_NOTE_SIZE, EphemeralKeyBytes};
use zcash_primitives::{
    block::{BlockHash, BlockHeader},
    merkle_tree::read_commitment_tree,
    transaction::{TxId, TxVersion},
};
use zcash_protocol::{
    PoolType, ShieldedPool,
    consensus::{self, BlockHeight, NetworkType},
    memo::{self, MemoBytes},
    value::Zatoshis,
};
use zip321::{TransactionRequest, Zip321Error};

use crate::{
    data_api::{
        InputSource,
        chain::ChainState,
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    fees::{ChangeValue, StandardFeeRule, TransactionBalance},
    proposal::{
        Proposal, ProposalError, ShieldedInputs, Step, StepOutput, StepOutputIndex,
        produces_shielded_bundle,
    },
};

#[cfg(feature = "transparent-inputs")]
use transparent::{
    address::{Script, TransparentAddress},
    bundle::OutPoint,
};

#[cfg(feature = "transparent-inputs")]
use zcash_script::script;

#[cfg(feature = "orchard")]
use orchard::tree::MerkleHashOrchard;

#[rustfmt::skip]
#[allow(unknown_lints)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[allow(clippy::doc_overindented_list_items)]
pub mod compact_formats;

#[rustfmt::skip]
#[allow(unknown_lints)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[allow(clippy::doc_overindented_list_items)]
pub mod proposal;

#[rustfmt::skip]
#[allow(unknown_lints)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[allow(clippy::doc_overindented_list_items)]
pub mod service;

impl compact_formats::CompactBlock {
    /// Returns the [`BlockHash`] for this block.
    ///
    /// # Panics
    ///
    /// This function will panic if [`field@Self::header`] is not set and
    /// [`field@Self::hash`] is not exactly 32 bytes.
    pub fn hash(&self) -> BlockHash {
        if let Some(header) = self.header() {
            header.hash()
        } else {
            BlockHash::from_slice(&self.hash)
        }
    }

    /// Returns the [`BlockHash`] for this block's parent.
    ///
    /// # Panics
    ///
    /// This function will panic if [`field@Self::header`] is not set and
    /// [`field@Self::prev_hash`] is not exactly 32 bytes.
    pub fn prev_hash(&self) -> BlockHash {
        if let Some(header) = self.header() {
            header.prev_block
        } else {
            BlockHash::from_slice(&self.prev_hash)
        }
    }

    /// Returns the [`BlockHeight`] value for this block
    ///
    /// # Panics
    ///
    /// This function will panic if [`field@Self::height`] is not representable within a
    /// `u32`.
    pub fn height(&self) -> BlockHeight {
        self.height.try_into().unwrap()
    }

    /// Returns the [`BlockHeader`] for this block if present.
    ///
    /// A convenience method that parses [`field@Self::header`] if present.
    pub fn header(&self) -> Option<BlockHeader> {
        if self.header.is_empty() {
            None
        } else {
            BlockHeader::read(&self.header[..]).ok()
        }
    }
}

impl compact_formats::CompactTx {
    /// Returns the transaction Id
    pub fn txid(&self) -> TxId {
        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&self.txid);
        TxId::from_bytes(txid_bytes)
    }
}

/// An error indicating that a field of a compact format structure could not be parsed.
#[derive(Clone, Debug)]
pub enum CompactFormatError {
    /// A byte slice had an invalid length for the expected field.
    InvalidLength(TryFromSliceError),
    /// A field value did not represent a valid protocol element.
    InvalidValue,
}

impl Display for CompactFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompactFormatError::InvalidLength(e) => write!(f, "Invalid compact format field: {e}"),
            CompactFormatError::InvalidValue => {
                write!(f, "Compact format field is not a valid protocol element")
            }
        }
    }
}

impl compact_formats::CompactSaplingOutput {
    /// Returns the note commitment for this output.
    ///
    /// A convenience method that parses [`field@Self::cmu`].
    pub fn cmu(&self) -> Result<ExtractedNoteCommitment, CompactFormatError> {
        let mut repr = [0; 32];
        repr.copy_from_slice(&self.cmu[..]);
        Option::from(ExtractedNoteCommitment::from_bytes(&repr))
            .ok_or(CompactFormatError::InvalidValue)
    }

    /// Returns the ephemeral public key for this output.
    ///
    /// A convenience method that parses [`field@Self::ephemeral_key`].
    pub fn ephemeral_key(&self) -> Result<EphemeralKeyBytes, CompactFormatError> {
        self.ephemeral_key[..]
            .try_into()
            .map(EphemeralKeyBytes)
            .map_err(CompactFormatError::InvalidLength)
    }
}

impl<Proof> From<&sapling::bundle::OutputDescription<Proof>>
    for compact_formats::CompactSaplingOutput
{
    fn from(
        out: &sapling::bundle::OutputDescription<Proof>,
    ) -> compact_formats::CompactSaplingOutput {
        compact_formats::CompactSaplingOutput {
            cmu: out.cmu().to_bytes().to_vec(),
            ephemeral_key: out.ephemeral_key().as_ref().to_vec(),
            ciphertext: out.enc_ciphertext()[..COMPACT_NOTE_SIZE].to_vec(),
        }
    }
}

impl TryFrom<compact_formats::CompactSaplingOutput>
    for sapling::note_encryption::CompactOutputDescription
{
    type Error = CompactFormatError;

    fn try_from(value: compact_formats::CompactSaplingOutput) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&compact_formats::CompactSaplingOutput>
    for sapling::note_encryption::CompactOutputDescription
{
    type Error = CompactFormatError;

    fn try_from(value: &compact_formats::CompactSaplingOutput) -> Result<Self, Self::Error> {
        Ok(sapling::note_encryption::CompactOutputDescription {
            cmu: value.cmu()?,
            ephemeral_key: value.ephemeral_key()?,
            enc_ciphertext: value.ciphertext[..]
                .try_into()
                .map_err(CompactFormatError::InvalidLength)?,
        })
    }
}

impl compact_formats::CompactSaplingSpend {
    /// Returns the nullifier for this spend.
    ///
    /// A convenience method that parses [`field@Self::nf`].
    pub fn nf(&self) -> Result<sapling::Nullifier, CompactFormatError> {
        sapling::Nullifier::from_slice(&self.nf).map_err(CompactFormatError::InvalidLength)
    }
}

#[cfg(feature = "orchard")]
impl TryFrom<&compact_formats::CompactOrchardAction> for orchard::note_encryption::CompactAction {
    type Error = CompactFormatError;

    fn try_from(value: &compact_formats::CompactOrchardAction) -> Result<Self, Self::Error> {
        Ok(orchard::note_encryption::CompactAction::from_parts(
            value.nf()?,
            value.cmx()?,
            value.ephemeral_key()?,
            value.ciphertext[..]
                .try_into()
                .map_err(CompactFormatError::InvalidLength)?,
        ))
    }
}

#[cfg(feature = "orchard")]
impl compact_formats::CompactOrchardAction {
    /// Returns the note commitment for the output of this action.
    ///
    /// A convenience method that parses [`field@Self::cmx`].
    pub fn cmx(&self) -> Result<orchard::note::ExtractedNoteCommitment, CompactFormatError> {
        Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(
            &self.cmx[..]
                .try_into()
                .map_err(CompactFormatError::InvalidLength)?,
        ))
        .ok_or(CompactFormatError::InvalidValue)
    }

    /// Returns the nullifier for the spend of this action.
    ///
    /// A convenience method that parses [`field@Self::nullifier`].
    pub fn nf(&self) -> Result<orchard::note::Nullifier, CompactFormatError> {
        let nf_bytes: [u8; 32] = self.nullifier[..]
            .try_into()
            .map_err(CompactFormatError::InvalidLength)?;
        Option::from(orchard::note::Nullifier::from_bytes(&nf_bytes))
            .ok_or(CompactFormatError::InvalidValue)
    }

    /// Returns the ephemeral public key for the output of this action.
    ///
    /// A convenience method that parses [`field@Self::ephemeral_key`].
    pub fn ephemeral_key(&self) -> Result<EphemeralKeyBytes, CompactFormatError> {
        self.ephemeral_key[..]
            .try_into()
            .map(EphemeralKeyBytes)
            .map_err(CompactFormatError::InvalidLength)
    }
}

impl<A: sapling::bundle::Authorization> From<&sapling::bundle::SpendDescription<A>>
    for compact_formats::CompactSaplingSpend
{
    fn from(spend: &sapling::bundle::SpendDescription<A>) -> compact_formats::CompactSaplingSpend {
        compact_formats::CompactSaplingSpend {
            nf: spend.nullifier().to_vec(),
        }
    }
}

#[cfg(feature = "orchard")]
impl<SpendAuth> From<&orchard::Action<SpendAuth>> for compact_formats::CompactOrchardAction {
    fn from(action: &orchard::Action<SpendAuth>) -> compact_formats::CompactOrchardAction {
        compact_formats::CompactOrchardAction {
            nullifier: action.nullifier().to_bytes().to_vec(),
            cmx: action.cmx().to_bytes().to_vec(),
            ephemeral_key: action.encrypted_note().epk_bytes.to_vec(),
            ciphertext: action.encrypted_note().enc_ciphertext[..COMPACT_NOTE_SIZE].to_vec(),
        }
    }
}

impl service::LightdInfo {
    /// Returns the network type for the chain this server is following, or `None` if it
    /// is not recognised.
    pub fn chain_name(&self) -> Option<NetworkType> {
        match self.chain_name.as_str() {
            "main" => Some(NetworkType::Main),
            "test" => Some(NetworkType::Test),
            "regtest" => Some(NetworkType::Regtest),
            _ => None,
        }
    }

    /// Returns the Sapling activation height for the chain this server is following.
    ///
    /// # Panics
    ///
    /// This function will panic if [`field@Self::sapling_activation_height`] is not
    /// representable within a `u32`.
    pub fn sapling_activation_height(&self) -> BlockHeight {
        self.sapling_activation_height
            .try_into()
            .expect("lightwalletd should provide in-range heights")
    }

    /// Returns the current consensus branch ID for the chain tip of the chain this server
    /// is following, or `None` if it is not recognised.
    pub fn consensus_branch_id(&self) -> Option<consensus::BranchId> {
        u32::from_str_radix(&self.consensus_branch_id, 16)
            .ok()?
            .try_into()
            .ok()
    }

    /// Returns the chain tip height reported by the full node backing this server.
    ///
    /// If the full node is still syncing, this may not be the network's chain tip; in
    /// this case, [`Self::estimated_height`] will report a larger height.
    ///
    /// # Panics
    ///
    /// This function will panic if [`field@Self::block_height`] is not representable
    /// within a `u32`.
    pub fn block_height(&self) -> BlockHeight {
        self.block_height
            .try_into()
            .expect("lightwalletd should provide in-range heights")
    }

    /// Returns the estimated chain tip height for the chain this server is following.
    ///
    /// If the full node backing this server is fully synced, this is always equal to
    /// [`Self::block_height`].
    ///
    /// # Panics
    ///
    /// This function will panic if [`field@Self::estimated_height`] is not representable
    /// within a `u32`.
    pub fn estimated_height(&self) -> BlockHeight {
        self.estimated_height
            .try_into()
            .expect("lightwalletd should provide in-range heights")
    }

    /// Returns the donation address for this server.
    ///
    /// Returns `None` if:
    /// - no donation address was provided.
    /// - the provided donation address is not a valid [`unified::Address`].
    /// - the provided donation address is for a different chain.
    pub fn donation_address(&self) -> Option<unified::Address> {
        if self.donation_address.is_empty() {
            None
        } else {
            let (network_type, address) = unified::Address::decode(&self.donation_address).ok()?;
            (Some(network_type) == self.chain_name()).then_some(address)
        }
    }
}

impl service::TreeState {
    /// Deserializes and returns the Sapling note commitment tree field of the tree state.
    pub fn sapling_tree(
        &self,
    ) -> io::Result<CommitmentTree<Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>> {
        if self.sapling_tree.is_empty() {
            Ok(CommitmentTree::empty())
        } else {
            let sapling_tree_bytes = hex::decode(&self.sapling_tree).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Hex decoding of Sapling tree bytes failed: {e:?}"),
                )
            })?;
            read_commitment_tree::<Node, _, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>(
                &sapling_tree_bytes[..],
            )
        }
    }

    /// Deserializes and returns the Sapling note commitment tree field of the tree state.
    #[cfg(feature = "orchard")]
    pub fn orchard_tree(
        &self,
    ) -> io::Result<CommitmentTree<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>>
    {
        if self.orchard_tree.is_empty() {
            Ok(CommitmentTree::empty())
        } else {
            let orchard_tree_bytes = hex::decode(&self.orchard_tree).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Hex decoding of Orchard tree bytes failed: {e:?}"),
                )
            })?;
            read_commitment_tree::<
                MerkleHashOrchard,
                _,
                { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
            >(&orchard_tree_bytes[..])
        }
    }

    /// Deserializes and returns the Ironwood note commitment tree field of the tree state.
    ///
    /// The Ironwood tree is Orchard-shaped, but Ironwood is a distinct pool tracked separately
    /// from Orchard. An empty field yields an empty tree, which is the correct treestate at the
    /// Ironwood pool's activation.
    #[cfg(feature = "orchard")]
    pub fn ironwood_tree(
        &self,
    ) -> io::Result<CommitmentTree<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>>
    {
        if self.ironwood_tree.is_empty() {
            Ok(CommitmentTree::empty())
        } else {
            let ironwood_tree_bytes = hex::decode(&self.ironwood_tree).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Hex decoding of Ironwood tree bytes failed: {e:?}"),
                )
            })?;
            read_commitment_tree::<
                MerkleHashOrchard,
                _,
                { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
            >(&ironwood_tree_bytes[..])
        }
    }

    /// Parses this tree state into a [`ChainState`] for use with [`scan_cached_blocks`].
    ///
    /// [`scan_cached_blocks`]: crate::data_api::chain::scan_cached_blocks
    pub fn to_chain_state(&self) -> io::Result<ChainState> {
        let mut hash_bytes = hex::decode(&self.hash).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Block hash is not valid hex: {e:?}"),
            )
        })?;
        // Zcashd hex strings for block hashes are byte-reversed.
        hash_bytes.reverse();

        Ok(ChainState::new(
            self.height
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid block height"))?,
            BlockHash::try_from_slice(&hash_bytes).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid block hash length.")
            })?,
            self.sapling_tree()?.to_frontier(),
            #[cfg(feature = "orchard")]
            self.orchard_tree()?.to_frontier(),
            #[cfg(feature = "orchard")]
            self.ironwood_tree()?.to_frontier(),
        ))
    }
}

/// Constant for the V1 proposal serialization version.
pub const PROPOSAL_SER_V1: u32 = 1;

/// Errors that can occur in the process of decoding a [`Proposal`] from its protobuf
/// representation.
#[derive(Debug, Clone)]
pub enum ProposalDecodingError<DbError> {
    /// The encoded proposal contained no steps.
    NoSteps,
    /// The ZIP 321 transaction request URI was invalid.
    Zip321(Zip321Error),
    /// A proposed input was null.
    NullInput(usize),
    /// A transaction identifier string did not decode to a valid transaction ID.
    TxIdInvalid(TryFromSliceError),
    /// An invalid value pool identifier was encountered.
    ValuePoolNotSupported(i32),
    /// A failure occurred trying to retrieve an unspent note or UTXO from the wallet database.
    InputRetrieval(DbError),
    /// The unspent note or UTXO corresponding to a proposal input was not found in the wallet
    /// database.
    InputNotFound(TxId, PoolType, u32),
    /// The transaction balance, or a component thereof, failed to decode correctly.
    BalanceInvalid,
    /// Failed to decode a ZIP-302-compliant memo from the provided memo bytes.
    MemoInvalid(memo::Error),
    /// The serialization version returned by the protobuf was not recognized.
    VersionInvalid(u32),
    /// The fee rule specified by the proposal is not supported by the wallet.
    FeeRuleNotSupported(proposal::FeeRule),
    /// The proposal violated balance or structural constraints.
    ProposalInvalid(ProposalError),
    /// An inputs field for the given protocol was present, but contained no input note references.
    EmptyShieldedInputs(ShieldedPool),
    /// A memo field was provided for a transparent output.
    TransparentMemo,
    /// Change outputs to the specified pool are not supported.
    InvalidChangeRecipient(PoolType),
    /// Ephemeral outputs to the specified pool are not supported.
    InvalidEphemeralRecipient(PoolType),
    /// The encoded confirmations policy was not valid (for example, a zero confirmation count or
    /// trusted confirmations exceeding untrusted).
    ConfirmationsPolicyInvalid,
    /// A payment was directed to the Orchard pool while Ironwood is active at the proposal's target
    /// height. Once Ironwood is active, Orchard-receiver payments target the Ironwood pool and only
    /// change may return to Orchard, so such a payment cannot appear in a well-formed proposal.
    OrchardPaymentProhibited,
    /// A proposal step produces a shielded bundle (it spends shielded notes, pays to a shielded
    /// pool, or returns shielded change) but its encoded anchor height is the zero sentinel. Every
    /// shielded-tree lookup the step performs — including the dummy spends that pad an output-only
    /// bundle — must be bound to a real anchor, so this combination cannot appear in a well-formed
    /// proposal.
    MissingShieldedAnchor,
    /// The proposal specified an explicit transaction version header that the wallet does not
    /// recognize.
    ProposedVersionInvalid(u32),
    /// The `transparentChangeRecipientScript` field contained a script that is not the
    /// scriptPubKey of a valid transparent address, or was set on a change value for which an
    /// explicit transparent recipient is not permitted.
    #[cfg(feature = "transparent-inputs")]
    TransparentChangeRecipientInvalid,
}

impl<E> From<Zip321Error> for ProposalDecodingError<E> {
    fn from(value: Zip321Error) -> Self {
        Self::Zip321(value)
    }
}

impl<E: Display> Display for ProposalDecodingError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProposalDecodingError::NoSteps => write!(f, "The proposal had no steps."),
            ProposalDecodingError::Zip321(err) => write!(f, "Transaction request invalid: {err}"),
            ProposalDecodingError::NullInput(i) => {
                write!(f, "Proposed input was null at index {i}")
            }
            ProposalDecodingError::TxIdInvalid(err) => {
                write!(f, "Invalid transaction id: {err:?}")
            }
            ProposalDecodingError::ValuePoolNotSupported(id) => {
                write!(f, "Invalid value pool identifier: {id:?}")
            }
            ProposalDecodingError::InputRetrieval(err) => {
                write!(f, "An error occurred retrieving a transaction input: {err}")
            }
            ProposalDecodingError::InputNotFound(txid, pool, idx) => {
                write!(f, "No {pool} input found for txid {txid}, index {idx}")
            }
            ProposalDecodingError::BalanceInvalid => {
                write!(f, "An error occurred decoding the proposal balance.")
            }
            ProposalDecodingError::MemoInvalid(err) => {
                write!(f, "An error occurred decoding a proposed memo: {err}")
            }
            ProposalDecodingError::VersionInvalid(v) => {
                write!(f, "Unrecognized proposal version {v}")
            }
            ProposalDecodingError::FeeRuleNotSupported(r) => {
                write!(
                    f,
                    "Fee calculation using the {r:?} fee rule is not supported."
                )
            }
            ProposalDecodingError::ProposalInvalid(err) => write!(f, "{err}"),
            ProposalDecodingError::EmptyShieldedInputs(protocol) => write!(
                f,
                "An inputs field was present for {protocol:?}, but contained no note references."
            ),
            ProposalDecodingError::TransparentMemo => {
                write!(f, "Transparent outputs cannot have memos.")
            }
            ProposalDecodingError::InvalidChangeRecipient(pool_type) => write!(
                f,
                "Change outputs to the {pool_type} pool are not supported."
            ),
            ProposalDecodingError::InvalidEphemeralRecipient(pool_type) => write!(
                f,
                "Ephemeral outputs to the {pool_type} pool are not supported."
            ),
            ProposalDecodingError::ConfirmationsPolicyInvalid => {
                write!(f, "The encoded confirmations policy was not valid.")
            }
            ProposalDecodingError::OrchardPaymentProhibited => write!(
                f,
                "A payment may not be directed to the Orchard pool once Ironwood is active."
            ),
            ProposalDecodingError::MissingShieldedAnchor => write!(
                f,
                "A proposal step that produces a shielded bundle must specify an anchor height."
            ),
            ProposalDecodingError::ProposedVersionInvalid(header) => write!(
                f,
                "The proposal specified an unrecognized transaction version header {header:#x}."
            ),
            #[cfg(feature = "transparent-inputs")]
            ProposalDecodingError::TransparentChangeRecipientInvalid => write!(
                f,
                "The transparent change recipient script was invalid, or was set on a change \
                 value that may not carry an explicit transparent recipient."
            ),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ProposalDecodingError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProposalDecodingError::Zip321(e) => Some(e),
            ProposalDecodingError::InputRetrieval(e) => Some(e),
            ProposalDecodingError::MemoInvalid(e) => Some(e),
            _ => None,
        }
    }
}

fn pool_type<T>(pool_id: i32) -> Result<PoolType, ProposalDecodingError<T>> {
    match proposal::ValuePool::try_from(pool_id) {
        Ok(proposal::ValuePool::Transparent) => Ok(PoolType::TRANSPARENT),
        Ok(proposal::ValuePool::Sapling) => Ok(PoolType::SAPLING),
        Ok(proposal::ValuePool::Orchard) => Ok(PoolType::ORCHARD),
        Ok(proposal::ValuePool::Ironwood) => Ok(PoolType::IRONWOOD),
        _ => Err(ProposalDecodingError::ValuePoolNotSupported(pool_id)),
    }
}

impl proposal::ReceivedOutput {
    pub fn parse_txid(&self) -> Result<TxId, TryFromSliceError> {
        Ok(TxId::from_bytes(self.txid[..].try_into()?))
    }

    pub fn pool_type<T>(&self) -> Result<PoolType, ProposalDecodingError<T>> {
        pool_type(self.value_pool)
    }
}

impl proposal::ChangeValue {
    pub fn pool_type<T>(&self) -> Result<PoolType, ProposalDecodingError<T>> {
        pool_type(self.value_pool)
    }
}

impl From<PoolType> for proposal::ValuePool {
    fn from(value: PoolType) -> Self {
        match value {
            PoolType::Transparent => proposal::ValuePool::Transparent,
            PoolType::Shielded(p) => p.into(),
        }
    }
}

impl From<ShieldedPool> for proposal::ValuePool {
    fn from(value: ShieldedPool) -> Self {
        match value {
            ShieldedPool::Sapling => proposal::ValuePool::Sapling,
            ShieldedPool::Orchard => proposal::ValuePool::Orchard,
            ShieldedPool::Ironwood => proposal::ValuePool::Ironwood,
        }
    }
}

impl proposal::Proposal {
    /// Serializes a [`Proposal`] based upon a supported [`StandardFeeRule`] to its protobuf
    /// representation.
    pub fn from_standard_proposal<NoteRef>(value: &Proposal<StandardFeeRule, NoteRef>) -> Self {
        use proposal::proposed_input;
        use proposal::{PriorStepChange, PriorStepOutput, ReceivedOutput};
        let steps = value
            .steps()
            .iter()
            .map(|step| {
                let transaction_request = step.transaction_request().to_uri();

                // A decoded legacy step that defers its anchor encodes as the zero sentinel.
                let anchor_height = step.anchor_height().map_or(0, u32::from);

                let inputs = step
                    .transparent_inputs()
                    .iter()
                    .map(|utxo| proposal::ProposedInput {
                        value: Some(proposed_input::Value::ReceivedOutput(ReceivedOutput {
                            txid: utxo.outpoint().hash().to_vec(),
                            value_pool: proposal::ValuePool::Transparent.into(),
                            index: utxo.outpoint().n(),
                            value: utxo.txout().value().into(),
                        })),
                    })
                    .chain(step.shielded_inputs().iter().flat_map(|s_in| {
                        s_in.notes().iter().map(|rec_note| proposal::ProposedInput {
                            value: Some(proposed_input::Value::ReceivedOutput(ReceivedOutput {
                                txid: rec_note.txid().as_ref().to_vec(),
                                value_pool: proposal::ValuePool::from(rec_note.note().pool())
                                    .into(),
                                index: rec_note.output_index().into(),
                                value: rec_note.note().value().into(),
                            })),
                        })
                    }))
                    .chain(step.prior_step_inputs().iter().map(|p_in| {
                        match p_in.output_index() {
                            StepOutputIndex::Payment(i) => proposal::ProposedInput {
                                value: Some(proposed_input::Value::PriorStepOutput(
                                    PriorStepOutput {
                                        step_index: p_in
                                            .step_index()
                                            .try_into()
                                            .expect("Step index fits into a u32"),
                                        payment_index: i
                                            .try_into()
                                            .expect("Payment index fits into a u32"),
                                    },
                                )),
                            },
                            StepOutputIndex::Change(i) => proposal::ProposedInput {
                                value: Some(proposed_input::Value::PriorStepChange(
                                    PriorStepChange {
                                        step_index: p_in
                                            .step_index()
                                            .try_into()
                                            .expect("Step index fits into a u32"),
                                        change_index: i
                                            .try_into()
                                            .expect("Payment index fits into a u32"),
                                    },
                                )),
                            },
                        }
                    }))
                    .collect();

                let payment_output_pools = step
                    .payment_pools()
                    .iter()
                    .map(|(idx, pool_type)| proposal::PaymentOutputPool {
                        payment_index: u32::try_from(*idx).expect("Payment index fits into a u32"),
                        value_pool: proposal::ValuePool::from(*pool_type).into(),
                    })
                    .collect();

                let balance = Some(proposal::TransactionBalance {
                    proposed_change: step
                        .balance()
                        .proposed_change()
                        .iter()
                        .map(|change| proposal::ChangeValue {
                            value: change.value().into(),
                            value_pool: proposal::ValuePool::from(change.output_pool()).into(),
                            memo: change.memo().map(|memo_bytes| proposal::MemoBytes {
                                value: memo_bytes.as_slice().to_vec(),
                            }),
                            is_ephemeral: change.is_ephemeral(),
                            #[cfg(feature = "transparent-inputs")]
                            transparent_change_recipient_script: change
                                .transparent_recipient()
                                .map(|addr| Script::from(addr.script()).0.0),
                            #[cfg(not(feature = "transparent-inputs"))]
                            transparent_change_recipient_script: None,
                        })
                        .collect(),
                    fee_required: step.balance().fee_required().into(),
                });

                proposal::ProposalStep {
                    transaction_request,
                    payment_output_pools,
                    anchor_height,
                    inputs,
                    balance,
                    is_shielding: step.is_shielding(),
                }
            })
            .collect();

        let confirmations_policy = value.confirmations_policy();
        proposal::Proposal {
            proto_version: PROPOSAL_SER_V1,
            fee_rule: match value.fee_rule() {
                StandardFeeRule::Zip317 => proposal::FeeRule::Zip317,
            }
            .into(),
            min_target_height: value.min_target_height().into(),
            steps,
            confirmations_policy: Some(proposal::ConfirmationsPolicy {
                trusted: confirmations_policy.trusted().into(),
                untrusted: confirmations_policy.untrusted().into(),
                #[cfg(feature = "transparent-inputs")]
                allow_zero_conf_shielding: confirmations_policy.allow_zero_conf_shielding(),
                #[cfg(not(feature = "transparent-inputs"))]
                allow_zero_conf_shielding: true,
            }),
            proposed_version: value.proposed_version().map(|v| v.header()),
        }
    }

    /// Attempts to parse a [`Proposal`] based upon a supported [`StandardFeeRule`] from its
    /// protobuf representation.
    pub fn try_into_standard_proposal<ParamsT, DbT, DbError>(
        &self,
        params: &ParamsT,
        wallet_db: &DbT,
    ) -> Result<Proposal<StandardFeeRule, DbT::NoteRef>, ProposalDecodingError<DbError>>
    where
        ParamsT: consensus::Parameters,
        DbT: InputSource<Error = DbError>,
    {
        use self::proposal::proposed_input::Value::*;
        match self.proto_version {
            PROPOSAL_SER_V1 => {
                let fee_rule = match self.fee_rule() {
                    proposal::FeeRule::Zip317 => StandardFeeRule::Zip317,
                    other => {
                        return Err(ProposalDecodingError::FeeRuleNotSupported(other));
                    }
                };

                let target_height = TargetHeight::from(self.min_target_height);
                // Steps are checked against the Orchard turnstile when Ironwood is
                // active at the height for which the proposal was constructed.
                #[cfg(feature = "orchard")]
                let ironwood_active = params.is_nu_active(
                    consensus::NetworkUpgrade::Nu6_3,
                    BlockHeight::from(target_height),
                );
                #[cfg(not(feature = "orchard"))]
                let _ = params;

                let mut steps = Vec::with_capacity(self.steps.len());
                for step in &self.steps {
                    let transaction_request =
                        TransactionRequest::from_uri(&step.transaction_request)?;

                    let payment_pools = step
                        .payment_output_pools
                        .iter()
                        .map(|pop| {
                            Ok((
                                usize::try_from(pop.payment_index)
                                    .expect("Payment index fits into a usize"),
                                pool_type(pop.value_pool)?,
                            ))
                        })
                        .collect::<Result<BTreeMap<usize, PoolType>, ProposalDecodingError<DbError>>>()?;

                    // With Ironwood active, no payment may be directed to the Orchard pool: an
                    // Orchard-receiver payment targets the Ironwood pool, and only change may
                    // return to Orchard. Reject such a payment from untrusted or legacy input here,
                    // rather than letting it reach the `debug_assert!` in `Step::from_parts`.
                    #[cfg(feature = "orchard")]
                    if ironwood_active
                        && payment_pools
                            .values()
                            .any(|pool| *pool == PoolType::ORCHARD)
                    {
                        return Err(ProposalDecodingError::OrchardPaymentProhibited);
                    }

                    #[allow(unused_mut)]
                    let mut transparent_inputs = vec![];
                    let mut received_notes = vec![];
                    let mut prior_step_inputs = vec![];
                    for (i, input) in step.inputs.iter().enumerate() {
                        match input
                            .value
                            .as_ref()
                            .ok_or(ProposalDecodingError::NullInput(i))?
                        {
                            ReceivedOutput(out) => {
                                let txid = out
                                    .parse_txid()
                                    .map_err(ProposalDecodingError::TxIdInvalid)?;

                                match out.pool_type()? {
                                    PoolType::Transparent => {
                                        #[cfg(not(feature = "transparent-inputs"))]
                                        return Err(ProposalDecodingError::ValuePoolNotSupported(
                                            out.value_pool,
                                        ));

                                        #[cfg(feature = "transparent-inputs")]
                                        {
                                            let outpoint = OutPoint::new(txid.into(), out.index);
                                            transparent_inputs.push(
                                                wallet_db
                                                    .get_unspent_transparent_output(
                                                        &outpoint,
                                                        target_height,
                                                    )
                                                    .map_err(ProposalDecodingError::InputRetrieval)?
                                                    .ok_or({
                                                        ProposalDecodingError::InputNotFound(
                                                            txid,
                                                            PoolType::TRANSPARENT,
                                                            out.index,
                                                        )
                                                    })?
                                                    .redact_account_data(),
                                            );
                                        }
                                    }
                                    PoolType::Shielded(protocol) => received_notes.push(
                                        wallet_db
                                            .get_spendable_note(
                                                &txid,
                                                protocol,
                                                out.index,
                                                target_height,
                                            )
                                            .map_err(ProposalDecodingError::InputRetrieval)
                                            .and_then(|opt| {
                                                opt.ok_or({
                                                    ProposalDecodingError::InputNotFound(
                                                        txid,
                                                        PoolType::Shielded(protocol),
                                                        out.index,
                                                    )
                                                })
                                            })?,
                                    ),
                                }
                            }
                            PriorStepOutput(s_ref) => {
                                prior_step_inputs.push(StepOutput::new(
                                    s_ref
                                        .step_index
                                        .try_into()
                                        .expect("Step index fits into a usize"),
                                    StepOutputIndex::Payment(
                                        s_ref
                                            .payment_index
                                            .try_into()
                                            .expect("Payment index fits into a usize"),
                                    ),
                                ));
                            }
                            PriorStepChange(s_ref) => {
                                prior_step_inputs.push(StepOutput::new(
                                    s_ref
                                        .step_index
                                        .try_into()
                                        .expect("Step index fits into a usize"),
                                    StepOutputIndex::Change(
                                        s_ref
                                            .change_index
                                            .try_into()
                                            .expect("Payment index fits into a usize"),
                                    ),
                                ));
                            }
                        }
                    }

                    let shielded_inputs =
                        NonEmpty::from_vec(received_notes).map(ShieldedInputs::from_parts);

                    let proto_balance = step
                        .balance
                        .as_ref()
                        .ok_or(ProposalDecodingError::BalanceInvalid)?;
                    let balance = TransactionBalance::new(
                        proto_balance
                            .proposed_change
                            .iter()
                            .map(|cv| -> Result<ChangeValue, ProposalDecodingError<_>> {
                                let value = Zatoshis::from_u64(cv.value)
                                    .map_err(|_| ProposalDecodingError::BalanceInvalid)?;
                                let memo = cv
                                    .memo
                                    .as_ref()
                                    .map(|bytes| {
                                        MemoBytes::from_bytes(&bytes.value)
                                            .map_err(ProposalDecodingError::MemoInvalid)
                                    })
                                    .transpose()?;

                                // A `transparentChangeRecipientScript` may only be set on a
                                // non-ephemeral transparent change value; reject it up front for
                                // every other combination so that the match below only needs to
                                // handle it for `(Transparent, false)`.
                                #[cfg(feature = "transparent-inputs")]
                                if cv.transparent_change_recipient_script.is_some()
                                    && !(cv.pool_type()? == PoolType::Transparent
                                        && !cv.is_ephemeral)
                                {
                                    return Err(
                                        ProposalDecodingError::TransparentChangeRecipientInvalid,
                                    );
                                }

                                match (cv.pool_type()?, cv.is_ephemeral) {
                                    (PoolType::Shielded(ShieldedPool::Sapling), false) => {
                                        Ok(ChangeValue::sapling(value, memo))
                                    }
                                    #[cfg(feature = "orchard")]
                                    (PoolType::Shielded(ShieldedPool::Orchard), false) => {
                                        Ok(ChangeValue::orchard(value, memo))
                                    }
                                    #[cfg(feature = "orchard")]
                                    (PoolType::Shielded(ShieldedPool::Ironwood), false) => Ok(
                                        ChangeValue::shielded(ShieldedPool::Ironwood, value, memo),
                                    ),
                                    (PoolType::Transparent, _) if memo.is_some() => {
                                        Err(ProposalDecodingError::TransparentMemo)
                                    }
                                    #[cfg(feature = "transparent-inputs")]
                                    (PoolType::Transparent, true) => {
                                        Ok(ChangeValue::ephemeral_transparent(value))
                                    }
                                    #[cfg(feature = "transparent-inputs")]
                                    (PoolType::Transparent, false) => {
                                        match cv.transparent_change_recipient_script.as_deref() {
                                            None => Ok(ChangeValue::transparent(value)),
                                            Some(script_bytes) => {
                                                script::PubKey::parse(&script::Code(
                                                    script_bytes.to_vec(),
                                                ))
                                                .ok()
                                                .as_ref()
                                                .and_then(TransparentAddress::from_script_pubkey)
                                                .map(|addr| {
                                                    ChangeValue::transparent_to_address(
                                                        value, addr,
                                                    )
                                                })
                                                .ok_or(
                                                    ProposalDecodingError::TransparentChangeRecipientInvalid,
                                                )
                                            }
                                        }
                                    }
                                    // When all pool features are enabled, the explicit arms above
                                    // are exhaustive over the non-ephemeral cases; this fallback
                                    // remains reachable when some pool features are disabled.
                                    #[allow(unreachable_patterns)]
                                    (pool, false) => {
                                        Err(ProposalDecodingError::InvalidChangeRecipient(pool))
                                    }
                                    (pool, true) => {
                                        Err(ProposalDecodingError::InvalidEphemeralRecipient(pool))
                                    }
                                }
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                        Zatoshis::from_u64(proto_balance.fee_required)
                            .map_err(|_| ProposalDecodingError::BalanceInvalid)?,
                    )
                    .map_err(|_| ProposalDecodingError::BalanceInvalid)?;

                    // The `anchorHeight` field's zero value is the wire sentinel for a step that
                    // carries no anchor. Only a purely transparent step may lack one: any step that
                    // produces a shielded bundle binds every shielded-tree lookup — including the
                    // dummy spends that pad an output-only bundle — to a real anchor. Reject the
                    // invalid combination here at the parse boundary rather than letting it reach
                    // `Step::from_parts`.
                    let anchor_height = match step.anchor_height {
                        0 if produces_shielded_bundle(
                            shielded_inputs.is_some(),
                            &payment_pools,
                            &balance,
                        ) =>
                        {
                            return Err(ProposalDecodingError::MissingShieldedAnchor);
                        }
                        0 => None,
                        h => Some(BlockHeight::from_u32(h)),
                    };

                    let step = Step::from_parts(
                        &steps,
                        transaction_request,
                        payment_pools,
                        transparent_inputs,
                        shielded_inputs,
                        anchor_height,
                        prior_step_inputs,
                        balance,
                        step.is_shielding,
                        #[cfg(feature = "orchard")]
                        ironwood_active,
                    )
                    .map_err(ProposalDecodingError::ProposalInvalid)?;

                    steps.push(step);
                }

                // Reconstruct the confirmations policy the proposal was built under. Proposals
                // serialized before this field existed omit it and are interpreted using the
                // default policy.
                let confirmations_policy = match &self.confirmations_policy {
                    Some(cp) => ConfirmationsPolicy::new(
                        NonZeroU32::new(cp.trusted)
                            .ok_or(ProposalDecodingError::ConfirmationsPolicyInvalid)?,
                        NonZeroU32::new(cp.untrusted)
                            .ok_or(ProposalDecodingError::ConfirmationsPolicyInvalid)?,
                        #[cfg(feature = "transparent-inputs")]
                        cp.allow_zero_conf_shielding,
                    )
                    .map_err(|_| ProposalDecodingError::ConfirmationsPolicyInvalid)?,
                    None => ConfirmationsPolicy::default(),
                };

                // Recover the explicitly-requested transaction version, if any. Proposals
                // serialized before this field existed, or built without a version request, omit
                // it and fall back to the version implied by the target height.
                let proposed_version = self
                    .proposed_version
                    .map(|header| {
                        if header == TxVersion::V5.header() {
                            Ok(TxVersion::V5)
                        } else if header == TxVersion::V6.header() {
                            Ok(TxVersion::V6)
                        } else {
                            Err(ProposalDecodingError::ProposedVersionInvalid(header))
                        }
                    })
                    .transpose()?;

                Proposal::multi_step(
                    fee_rule,
                    target_height,
                    confirmations_policy,
                    NonEmpty::from_vec(steps).ok_or(ProposalDecodingError::NoSteps)?,
                )
                .map(|proposal| proposal.with_proposed_version(proposed_version))
                .map_err(ProposalDecodingError::ProposalInvalid)
            }
            other => Err(ProposalDecodingError::VersionInvalid(other)),
        }
    }
}

#[cfg(feature = "lightwalletd-tonic-transport")]
impl service::compact_tx_streamer_client::CompactTxStreamerClient<tonic::transport::Channel> {
    /// Attempt to create a new client by connecting to a given endpoint.
    pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
    where
        D: TryInto<tonic::transport::Endpoint>,
        D::Error: Into<tonic::codegen::StdError>,
    {
        let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
        Ok(Self::new(conn))
    }
}

// These tests exercise the serialization of `ChangeValue`'s explicit transparent change
// recipient, which only exists when the `transparent-inputs` feature is enabled.
#[cfg(all(test, feature = "transparent-inputs"))]
mod tests {
    use std::collections::BTreeMap;

    use nonempty::NonEmpty;
    use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};
    use zip321::TransactionRequest;

    use super::{ProposalDecodingError, StandardFeeRule, proposal};
    use crate::{
        data_api::{
            AccountMeta, InputSource, NoteFilter, ReceivedNotes, TargetValue,
            wallet::{ConfirmationsPolicy, TargetHeight},
        },
        fees::{ChangeValue, TransactionBalance},
        proposal::{Proposal, ShieldedInputs, Step},
        wallet::{Note, ReceivedNote, WalletTransparentOutput},
    };
    use ::transparent::{
        address::TransparentAddress,
        bundle::{OutPoint, TxOut},
    };

    // A `LocalNetwork` value used to pin consensus state for these tests; Ironwood/NU6.3 is
    // inactive, which is irrelevant to a purely transparent step.
    fn test_network() -> LocalNetwork {
        LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(1)),
            blossom: Some(BlockHeight::from_u32(1)),
            heartwood: Some(BlockHeight::from_u32(1)),
            canopy: Some(BlockHeight::from_u32(1)),
            nu5: Some(BlockHeight::from_u32(1)),
            nu6: None,
            nu6_1: None,
            nu6_2: None,
            nu6_3: None,
            #[cfg(zcash_unstable = "nu7")]
            nu7: None,
        }
    }

    /// A minimal [`InputSource`] that resolves exactly one transparent UTXO, by outpoint; used to
    /// decode a proposal whose only chain input is that UTXO.
    struct FakeInputSource(WalletTransparentOutput<()>);

    impl InputSource for FakeInputSource {
        type Error = ();
        type AccountId = ();
        type NoteRef = u32;

        fn get_spendable_note(
            &self,
            _txid: &zcash_primitives::transaction::TxId,
            _protocol: zcash_protocol::ShieldedPool,
            _index: u32,
            _target_height: TargetHeight,
        ) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error> {
            Ok(None)
        }

        fn select_spendable_notes(
            &self,
            _account: Self::AccountId,
            _target_value: TargetValue,
            _sources: &[zcash_protocol::ShieldedPool],
            _target_height: TargetHeight,
            _confirmations_policy: ConfirmationsPolicy,
            _exclude: &[Self::NoteRef],
        ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
            Ok(ReceivedNotes::empty())
        }

        fn select_unspent_notes(
            &self,
            _account: Self::AccountId,
            _sources: &[zcash_protocol::ShieldedPool],
            _target_height: TargetHeight,
            _exclude: &[Self::NoteRef],
        ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
            Ok(ReceivedNotes::empty())
        }

        fn get_account_metadata(
            &self,
            _account: Self::AccountId,
            _selector: &NoteFilter,
            _target_height: TargetHeight,
            _exclude: &[Self::NoteRef],
        ) -> Result<AccountMeta, Self::Error> {
            Err(())
        }

        fn get_unspent_transparent_output(
            &self,
            outpoint: &OutPoint,
            _target_height: TargetHeight,
        ) -> Result<Option<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
            Ok((*outpoint == *self.0.outpoint()).then(|| self.0.clone()))
        }
    }

    /// Builds a single-step proposal with one P2SH transparent input and a transparent change
    /// output, encodes it to its protobuf representation, and returns everything needed to decode
    /// it again.
    fn proto_with_transparent_change(
        change: ChangeValue,
    ) -> (
        proposal::Proposal,
        Proposal<StandardFeeRule, u32>,
        LocalNetwork,
        FakeInputSource,
    ) {
        let funding_addr = TransparentAddress::ScriptHash([7u8; 20]);

        let input = WalletTransparentOutput::<()>::from_parts(
            OutPoint::fake(),
            TxOut::new(
                Zatoshis::const_from_u64(60_000),
                funding_addr.script().into(),
            ),
            None,
            None,
            None,
            None,
        )
        .expect("valid P2SH output");

        let balance =
            TransactionBalance::new(vec![change], Zatoshis::const_from_u64(10_000)).unwrap();

        let step = Step::from_parts(
            &[],
            TransactionRequest::empty(),
            BTreeMap::new(),
            vec![input.clone()],
            None::<ShieldedInputs<u32>>,
            None,
            vec![],
            balance,
            false,
            #[cfg(feature = "orchard")]
            false,
        )
        .expect("valid step");

        let proposal = Proposal::multi_step(
            StandardFeeRule::Zip317,
            TargetHeight::from(100u32),
            ConfirmationsPolicy::default(),
            NonEmpty::singleton(step),
        )
        .expect("valid proposal");

        let proto = proposal::Proposal::from_standard_proposal(&proposal);
        let network = test_network();
        let wallet_data = FakeInputSource(input);

        (proto, proposal, network, wallet_data)
    }

    /// A proposal whose transparent change carries an explicit recipient matching the P2SH input
    /// of the same step round-trips through protobuf encoding and decoding unchanged.
    #[test]
    fn transparent_change_recipient_round_trips_through_proposal_proto() {
        let (proto, proposal, network, wallet_data) =
            proto_with_transparent_change(ChangeValue::transparent_to_address(
                Zatoshis::const_from_u64(50_000),
                TransparentAddress::ScriptHash([7u8; 20]),
            ));

        let decoded = proto
            .try_into_standard_proposal(&network, &wallet_data)
            .expect("decodes successfully");
        assert_eq!(decoded, proposal);
    }

    /// A legacy transparent change value, with no explicit recipient, round-trips to
    /// `ChangeValue::transparent` (the absent-field, wallet-change-address semantics).
    #[test]
    fn legacy_transparent_change_round_trips_through_proposal_proto() {
        let (proto, proposal, network, wallet_data) = proto_with_transparent_change(
            ChangeValue::transparent(Zatoshis::const_from_u64(50_000)),
        );

        // The wire representation omits the new field entirely for legacy change values.
        assert_eq!(
            proto.steps[0].balance.as_ref().unwrap().proposed_change[0]
                .transparent_change_recipient_script,
            None
        );

        let decoded = proto
            .try_into_standard_proposal(&network, &wallet_data)
            .expect("decodes successfully");
        assert_eq!(decoded, proposal);
    }

    /// A `transparentChangeRecipientScript` that does not parse to the scriptPubKey of a valid
    /// transparent address is rejected.
    #[test]
    fn transparent_change_recipient_script_invalid_bytes_rejected() {
        let (mut proto, _, network, wallet_data) =
            proto_with_transparent_change(ChangeValue::transparent_to_address(
                Zatoshis::const_from_u64(50_000),
                TransparentAddress::ScriptHash([7u8; 20]),
            ));
        proto.steps[0].balance.as_mut().unwrap().proposed_change[0]
            .transparent_change_recipient_script = Some(vec![0xff, 0x00]);

        assert_matches!(
            proto.try_into_standard_proposal(&network, &wallet_data),
            Err(ProposalDecodingError::TransparentChangeRecipientInvalid)
        );
    }

    /// A `transparentChangeRecipientScript` set together with `isEphemeral` is rejected: an
    /// explicit recipient is only meaningful for non-ephemeral transparent change.
    #[test]
    fn transparent_change_recipient_script_with_ephemeral_rejected() {
        let (mut proto, _, network, wallet_data) =
            proto_with_transparent_change(ChangeValue::transparent_to_address(
                Zatoshis::const_from_u64(50_000),
                TransparentAddress::ScriptHash([7u8; 20]),
            ));
        proto.steps[0].balance.as_mut().unwrap().proposed_change[0].is_ephemeral = true;

        assert_matches!(
            proto.try_into_standard_proposal(&network, &wallet_data),
            Err(ProposalDecodingError::TransparentChangeRecipientInvalid)
        );
    }
}
