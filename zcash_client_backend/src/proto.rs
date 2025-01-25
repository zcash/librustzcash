//! Generated code for handling light client protobuf structs.

use incrementalmerkletree::frontier::CommitmentTree;
use nonempty::NonEmpty;
use std::{
    array::TryFromSliceError,
    collections::BTreeMap,
    fmt::{self, Display},
    io,
};

use sapling::{self, note::ExtractedNoteCommitment, note_encryption::COMPACT_NOTE_SIZE, Node};
use zcash_note_encryption::EphemeralKeyBytes;
use zcash_primitives::{
    block::{BlockHash, BlockHeader},
    consensus::BlockHeight,
    memo::{self, MemoBytes},
    merkle_tree::read_commitment_tree,
    transaction::{components::amount::NonNegativeAmount, fees::StandardFeeRule, TxId},
};

use crate::{
    data_api::{chain::ChainState, InputSource},
    fees::{ChangeValue, TransactionBalance},
    proposal::{Proposal, ProposalError, ShieldedInputs, Step, StepOutput, StepOutputIndex},
    zip321::{TransactionRequest, Zip321Error},
    PoolType, ShieldedProtocol,
};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::transaction::components::OutPoint;

#[cfg(feature = "orchard")]
use orchard::tree::MerkleHashOrchard;

#[rustfmt::skip]
#[allow(unknown_lints)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod compact_formats;

#[rustfmt::skip]
#[allow(unknown_lints)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod proposal;

#[rustfmt::skip]
#[allow(unknown_lints)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod service;

impl compact_formats::CompactBlock {
    /// Returns the [`BlockHash`] for this block.
    ///
    /// # Panics
    ///
    /// This function will panic if [`CompactBlock.header`] is not set and
    /// [`CompactBlock.hash`] is not exactly 32 bytes.
    ///
    /// [`CompactBlock.header`]: #structfield.header
    /// [`CompactBlock.hash`]: #structfield.hash
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
    /// This function will panic if [`CompactBlock.header`] is not set and
    /// [`CompactBlock.prevHash`] is not exactly 32 bytes.
    ///
    /// [`CompactBlock.header`]: #structfield.header
    /// [`CompactBlock.prevHash`]: #structfield.prevHash
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
    /// This function will panic if [`CompactBlock.height`] is not
    /// representable within a u32.
    pub fn height(&self) -> BlockHeight {
        self.height.try_into().unwrap()
    }

    /// Returns the [`BlockHeader`] for this block if present.
    ///
    /// A convenience method that parses [`CompactBlock.header`] if present.
    ///
    /// [`CompactBlock.header`]: #structfield.header
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
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&self.hash);
        TxId::from_bytes(hash)
    }
}

impl compact_formats::CompactSaplingOutput {
    /// Returns the note commitment for this output.
    ///
    /// A convenience method that parses [`CompactOutput.cmu`].
    ///
    /// [`CompactOutput.cmu`]: #structfield.cmu
    pub fn cmu(&self) -> Result<ExtractedNoteCommitment, ()> {
        let mut repr = [0; 32];
        repr.as_mut().copy_from_slice(&self.cmu[..]);
        Option::from(ExtractedNoteCommitment::from_bytes(&repr)).ok_or(())
    }

    /// Returns the ephemeral public key for this output.
    ///
    /// A convenience method that parses [`CompactOutput.epk`].
    ///
    /// [`CompactOutput.epk`]: #structfield.epk
    pub fn ephemeral_key(&self) -> Result<EphemeralKeyBytes, ()> {
        self.ephemeral_key[..]
            .try_into()
            .map(EphemeralKeyBytes)
            .map_err(|_| ())
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
            ciphertext: out.enc_ciphertext().as_ref()[..COMPACT_NOTE_SIZE].to_vec(),
        }
    }
}

impl TryFrom<compact_formats::CompactSaplingOutput>
    for sapling::note_encryption::CompactOutputDescription
{
    type Error = ();

    fn try_from(value: compact_formats::CompactSaplingOutput) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&compact_formats::CompactSaplingOutput>
    for sapling::note_encryption::CompactOutputDescription
{
    type Error = ();

    fn try_from(value: &compact_formats::CompactSaplingOutput) -> Result<Self, Self::Error> {
        Ok(sapling::note_encryption::CompactOutputDescription {
            cmu: value.cmu()?,
            ephemeral_key: value.ephemeral_key()?,
            enc_ciphertext: value.ciphertext[..].try_into().map_err(|_| ())?,
        })
    }
}

impl compact_formats::CompactSaplingSpend {
    pub fn nf(&self) -> Result<sapling::Nullifier, ()> {
        sapling::Nullifier::from_slice(&self.nf).map_err(|_| ())
    }
}

#[cfg(feature = "orchard")]
impl TryFrom<&compact_formats::CompactOrchardAction>
    for orchard::domain::CompactAction<orchard::orchard_flavor::OrchardVanilla>
{
    type Error = ();

    fn try_from(value: &compact_formats::CompactOrchardAction) -> Result<Self, Self::Error> {
        Ok(orchard::domain::CompactAction::from_parts(
            value.nf()?,
            value.cmx()?,
            value.ephemeral_key()?,
            zcash_note_encryption::note_bytes::NoteBytesData(
                value.ciphertext[..].try_into().map_err(|_| ())?,
            ),
        ))
    }
}

#[cfg(feature = "orchard")]
impl compact_formats::CompactOrchardAction {
    /// Returns the note commitment for the output of this action.
    ///
    /// A convenience method that parses [`CompactOrchardAction.cmx`].
    ///
    /// [`CompactOrchardAction.cmx`]: #structfield.cmx
    pub fn cmx(&self) -> Result<orchard::note::ExtractedNoteCommitment, ()> {
        Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(
            &self.cmx[..].try_into().map_err(|_| ())?,
        ))
        .ok_or(())
    }

    /// Returns the nullifier for the spend of this action.
    ///
    /// A convenience method that parses [`CompactOrchardAction.nullifier`].
    ///
    /// [`CompactOrchardAction.nullifier`]: #structfield.nullifier
    pub fn nf(&self) -> Result<orchard::note::Nullifier, ()> {
        let nf_bytes: [u8; 32] = self.nullifier[..].try_into().map_err(|_| ())?;
        Option::from(orchard::note::Nullifier::from_bytes(&nf_bytes)).ok_or(())
    }

    /// Returns the ephemeral public key for the output of this action.
    ///
    /// A convenience method that parses [`CompactOrchardAction.ephemeral_key`].
    ///
    /// [`CompactOrchardAction.ephemeral_key`]: #structfield.ephemeral_key
    pub fn ephemeral_key(&self) -> Result<EphemeralKeyBytes, ()> {
        self.ephemeral_key[..]
            .try_into()
            .map(EphemeralKeyBytes)
            .map_err(|_| ())
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
impl<SpendAuth> From<&orchard::Action<SpendAuth, orchard::orchard_flavor::OrchardVanilla>>
    for compact_formats::CompactOrchardAction
{
    fn from(
        action: &orchard::Action<SpendAuth, orchard::orchard_flavor::OrchardVanilla>,
    ) -> compact_formats::CompactOrchardAction {
        compact_formats::CompactOrchardAction {
            nullifier: action.nullifier().to_bytes().to_vec(),
            cmx: action.cmx().to_bytes().to_vec(),
            ephemeral_key: action.encrypted_note().epk_bytes.to_vec(),
            ciphertext: action.encrypted_note().enc_ciphertext.as_ref()[..COMPACT_NOTE_SIZE]
                .to_vec(),
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
                    format!("Hex decoding of Sapling tree bytes failed: {:?}", e),
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
                    format!("Hex decoding of Orchard tree bytes failed: {:?}", e),
                )
            })?;
            read_commitment_tree::<
                MerkleHashOrchard,
                _,
                { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
            >(&orchard_tree_bytes[..])
        }
    }

    /// Parses this tree state into a [`ChainState`] for use with [`scan_cached_blocks`].
    ///
    /// [`scan_cached_blocks`]: crate::data_api::chain::scan_cached_blocks
    pub fn to_chain_state(&self) -> io::Result<ChainState> {
        let mut hash_bytes = hex::decode(&self.hash).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Block hash is not valid hex: {:?}", e),
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
        ))
    }
}

/// Constant for the V1 proposal serialization version.
pub const PROPOSAL_SER_V1: u32 = 1;

/// Errors that can occur in the process of decoding a [`Proposal`] from its protobuf
/// representation.
#[derive(Debug, Clone)]
pub enum ProposalDecodingError<DbError> {
    /// The encoded proposal contained no steps
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
    /// The proposal did not correctly specify a standard fee rule.
    FeeRuleNotSpecified,
    /// The proposal violated balance or structural constraints.
    ProposalInvalid(ProposalError),
    /// An inputs field for the given protocol was present, but contained no input note references.
    EmptyShieldedInputs(ShieldedProtocol),
    /// A memo field was provided for a transparent output.
    TransparentMemo,
    /// Change outputs to the specified pool are not supported.
    InvalidChangeRecipient(PoolType),
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
            ProposalDecodingError::Zip321(err) => write!(f, "Transaction request invalid: {}", err),
            ProposalDecodingError::NullInput(i) => {
                write!(f, "Proposed input was null at index {}", i)
            }
            ProposalDecodingError::TxIdInvalid(err) => {
                write!(f, "Invalid transaction id: {:?}", err)
            }
            ProposalDecodingError::ValuePoolNotSupported(id) => {
                write!(f, "Invalid value pool identifier: {:?}", id)
            }
            ProposalDecodingError::InputRetrieval(err) => write!(
                f,
                "An error occurred retrieving a transaction input: {}",
                err
            ),
            ProposalDecodingError::InputNotFound(txid, pool, idx) => write!(
                f,
                "No {} input found for txid {}, index {}",
                pool, txid, idx
            ),
            ProposalDecodingError::BalanceInvalid => {
                write!(f, "An error occurred decoding the proposal balance.")
            }
            ProposalDecodingError::MemoInvalid(err) => {
                write!(f, "An error occurred decoding a proposed memo: {}", err)
            }
            ProposalDecodingError::VersionInvalid(v) => {
                write!(f, "Unrecognized proposal version {}", v)
            }
            ProposalDecodingError::FeeRuleNotSpecified => {
                write!(f, "Proposal did not specify a known fee rule.")
            }
            ProposalDecodingError::ProposalInvalid(err) => write!(f, "{}", err),
            ProposalDecodingError::EmptyShieldedInputs(protocol) => write!(
                f,
                "An inputs field was present for {:?}, but contained no note references.",
                protocol
            ),
            ProposalDecodingError::TransparentMemo => {
                write!(f, "Transparent outputs cannot have memos.")
            }
            ProposalDecodingError::InvalidChangeRecipient(pool_type) => write!(
                f,
                "Change outputs to the {} pool are not supported.",
                pool_type
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
        Ok(proposal::ValuePool::Transparent) => Ok(PoolType::Transparent),
        Ok(proposal::ValuePool::Sapling) => Ok(PoolType::Shielded(ShieldedProtocol::Sapling)),
        Ok(proposal::ValuePool::Orchard) => Ok(PoolType::Shielded(ShieldedProtocol::Orchard)),
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

impl From<ShieldedProtocol> for proposal::ValuePool {
    fn from(value: ShieldedProtocol) -> Self {
        match value {
            ShieldedProtocol::Sapling => proposal::ValuePool::Sapling,
            ShieldedProtocol::Orchard => proposal::ValuePool::Orchard,
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

                let anchor_height = step
                    .shielded_inputs()
                    .map_or_else(|| 0, |i| u32::from(i.anchor_height()));

                let inputs = step
                    .transparent_inputs()
                    .iter()
                    .map(|utxo| proposal::ProposedInput {
                        value: Some(proposed_input::Value::ReceivedOutput(ReceivedOutput {
                            txid: utxo.outpoint().hash().to_vec(),
                            value_pool: proposal::ValuePool::Transparent.into(),
                            index: utxo.outpoint().n(),
                            value: utxo.txout().value.into(),
                        })),
                    })
                    .chain(step.shielded_inputs().iter().flat_map(|s_in| {
                        s_in.notes().iter().map(|rec_note| proposal::ProposedInput {
                            value: Some(proposed_input::Value::ReceivedOutput(ReceivedOutput {
                                txid: rec_note.txid().as_ref().to_vec(),
                                value_pool: proposal::ValuePool::from(rec_note.note().protocol())
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

        #[allow(deprecated)]
        proposal::Proposal {
            proto_version: PROPOSAL_SER_V1,
            fee_rule: match value.fee_rule() {
                StandardFeeRule::PreZip313 => proposal::FeeRule::PreZip313,
                StandardFeeRule::Zip313 => proposal::FeeRule::Zip313,
                StandardFeeRule::Zip317 => proposal::FeeRule::Zip317,
            }
            .into(),
            min_target_height: value.min_target_height().into(),
            steps,
        }
    }

    /// Attempts to parse a [`Proposal`] based upon a supported [`StandardFeeRule`] from its
    /// protobuf representation.
    pub fn try_into_standard_proposal<DbT, DbError>(
        &self,
        wallet_db: &DbT,
    ) -> Result<Proposal<StandardFeeRule, DbT::NoteRef>, ProposalDecodingError<DbError>>
    where
        DbT: InputSource<Error = DbError>,
    {
        use self::proposal::proposed_input::Value::*;
        match self.proto_version {
            PROPOSAL_SER_V1 => {
                #[allow(deprecated)]
                let fee_rule = match self.fee_rule() {
                    proposal::FeeRule::PreZip313 => StandardFeeRule::PreZip313,
                    proposal::FeeRule::Zip313 => StandardFeeRule::Zip313,
                    proposal::FeeRule::Zip317 => StandardFeeRule::Zip317,
                    proposal::FeeRule::NotSpecified => {
                        return Err(ProposalDecodingError::FeeRuleNotSpecified);
                    }
                };

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

                    #[cfg(not(feature = "transparent-inputs"))]
                    let transparent_inputs = vec![];
                    #[cfg(feature = "transparent-inputs")]
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
                                            1,
                                        ));

                                        #[cfg(feature = "transparent-inputs")]
                                        {
                                            let outpoint = OutPoint::new(txid.into(), out.index);
                                            transparent_inputs.push(
                                                wallet_db
                                                    .get_unspent_transparent_output(&outpoint)
                                                    .map_err(ProposalDecodingError::InputRetrieval)?
                                                    .ok_or({
                                                        ProposalDecodingError::InputNotFound(
                                                            txid,
                                                            PoolType::Transparent,
                                                            out.index,
                                                        )
                                                    })?,
                                            );
                                        }
                                    }
                                    PoolType::Shielded(protocol) => received_notes.push(
                                        wallet_db
                                            .get_spendable_note(&txid, protocol, out.index)
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

                    let shielded_inputs = NonEmpty::from_vec(received_notes)
                        .map(|notes| ShieldedInputs::from_parts(step.anchor_height.into(), notes));

                    let proto_balance = step
                        .balance
                        .as_ref()
                        .ok_or(ProposalDecodingError::BalanceInvalid)?;
                    let balance = TransactionBalance::new(
                        proto_balance
                            .proposed_change
                            .iter()
                            .map(|cv| -> Result<ChangeValue, ProposalDecodingError<_>> {
                                let value = NonNegativeAmount::from_u64(cv.value)
                                    .map_err(|_| ProposalDecodingError::BalanceInvalid)?;
                                let memo = cv
                                    .memo
                                    .as_ref()
                                    .map(|bytes| {
                                        MemoBytes::from_bytes(&bytes.value)
                                            .map_err(ProposalDecodingError::MemoInvalid)
                                    })
                                    .transpose()?;
                                match cv.pool_type()? {
                                    PoolType::Shielded(ShieldedProtocol::Sapling) => {
                                        Ok(ChangeValue::sapling(value, memo))
                                    }
                                    #[cfg(feature = "orchard")]
                                    PoolType::Shielded(ShieldedProtocol::Orchard) => {
                                        Ok(ChangeValue::orchard(value, memo))
                                    }
                                    PoolType::Transparent if memo.is_some() => {
                                        Err(ProposalDecodingError::TransparentMemo)
                                    }
                                    t => Err(ProposalDecodingError::InvalidChangeRecipient(t)),
                                }
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                        NonNegativeAmount::from_u64(proto_balance.fee_required)
                            .map_err(|_| ProposalDecodingError::BalanceInvalid)?,
                    )
                    .map_err(|_| ProposalDecodingError::BalanceInvalid)?;

                    let step = Step::from_parts(
                        &steps,
                        transaction_request,
                        payment_pools,
                        transparent_inputs,
                        shielded_inputs,
                        prior_step_inputs,
                        balance,
                        step.is_shielding,
                    )
                    .map_err(ProposalDecodingError::ProposalInvalid)?;

                    steps.push(step);
                }

                Proposal::multi_step(
                    fee_rule,
                    self.min_target_height.into(),
                    NonEmpty::from_vec(steps).ok_or(ProposalDecodingError::NoSteps)?,
                )
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
