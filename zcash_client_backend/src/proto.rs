//! Generated code for handling light client protobuf structs.

use std::{
    array::TryFromSliceError,
    fmt::{self, Display},
    io,
};

use incrementalmerkletree::frontier::CommitmentTree;

use nonempty::NonEmpty;
use sapling::{self, note::ExtractedNoteCommitment, Node, Nullifier, NOTE_COMMITMENT_TREE_DEPTH};
use zcash_primitives::{
    block::{BlockHash, BlockHeader},
    consensus::{self, BlockHeight, Parameters},
    memo::{self, MemoBytes},
    merkle_tree::read_commitment_tree,
    transaction::{components::amount::NonNegativeAmount, fees::StandardFeeRule, TxId},
};

use zcash_note_encryption::{EphemeralKeyBytes, COMPACT_NOTE_SIZE};

use crate::{
    data_api::{
        wallet::input_selection::{Proposal, ProposalError, ShieldedInputs},
        InputSource,
    },
    fees::{ChangeValue, TransactionBalance},
    zip321::{TransactionRequest, Zip321Error},
    PoolType, ShieldedProtocol,
};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::transaction::components::OutPoint;

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
            ciphertext: out.enc_ciphertext()[..COMPACT_NOTE_SIZE].to_vec(),
        }
    }
}

impl TryFrom<compact_formats::CompactSaplingOutput>
    for sapling::note_encryption::CompactOutputDescription
{
    type Error = ();

    fn try_from(value: compact_formats::CompactSaplingOutput) -> Result<Self, Self::Error> {
        Ok(sapling::note_encryption::CompactOutputDescription {
            cmu: value.cmu()?,
            ephemeral_key: value.ephemeral_key()?,
            enc_ciphertext: value.ciphertext.try_into().map_err(|_| ())?,
        })
    }
}

impl compact_formats::CompactSaplingSpend {
    pub fn nf(&self) -> Result<Nullifier, ()> {
        Nullifier::from_slice(&self.nf).map_err(|_| ())
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

impl service::TreeState {
    /// Deserializes and returns the Sapling note commitment tree field of the tree state.
    pub fn sapling_tree(&self) -> io::Result<CommitmentTree<Node, NOTE_COMMITMENT_TREE_DEPTH>> {
        let sapling_tree_bytes = hex::decode(&self.sapling_tree).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Hex decoding of Sapling tree bytes failed: {:?}", e),
            )
        })?;
        read_commitment_tree::<Node, _, NOTE_COMMITMENT_TREE_DEPTH>(&sapling_tree_bytes[..])
    }
}

/// Constant for the V1 proposal serialization version.
pub const PROPOSAL_SER_V1: u32 = 1;

/// Errors that can occur in the process of decoding a [`Proposal`] from its protobuf
/// representation.
#[derive(Debug, Clone)]
pub enum ProposalDecodingError<DbError> {
    /// The ZIP 321 transaction request URI was invalid.
    Zip321(Zip321Error),
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
            ProposalDecodingError::Zip321(err) => write!(f, "Transaction request invalid: {}", err),
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
        #[cfg(zcash_unstable = "orchard")]
        Ok(proposal::ValuePool::Orchard) => Ok(PoolType::Shielded(ShieldedProtocol::Orchard)),
        _ => Err(ProposalDecodingError::ValuePoolNotSupported(pool_id)),
    }
}

impl proposal::ProposedInput {
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

impl From<ShieldedProtocol> for proposal::ValuePool {
    fn from(value: ShieldedProtocol) -> Self {
        match value {
            ShieldedProtocol::Sapling => proposal::ValuePool::Sapling,
            #[cfg(zcash_unstable = "orchard")]
            ShieldedProtocol::Orchard => proposal::ValuePool::Orchard,
        }
    }
}

impl proposal::Proposal {
    /// Serializes a [`Proposal`] based upon a supported [`StandardFeeRule`] to its protobuf
    /// representation.
    pub fn from_standard_proposal<P: Parameters, NoteRef>(
        params: &P,
        value: &Proposal<StandardFeeRule, NoteRef>,
    ) -> Option<Self> {
        let transaction_request = value.transaction_request().to_uri(params)?;

        let anchor_height = value
            .shielded_inputs()
            .map_or_else(|| 0, |i| u32::from(i.anchor_height()));

        let inputs = value
            .transparent_inputs()
            .iter()
            .map(|utxo| proposal::ProposedInput {
                txid: utxo.outpoint().hash().to_vec(),
                value_pool: proposal::ValuePool::Transparent.into(),
                index: utxo.outpoint().n(),
                value: utxo.txout().value.into(),
            })
            .chain(value.shielded_inputs().iter().flat_map(|s_in| {
                s_in.notes().iter().map(|rec_note| proposal::ProposedInput {
                    txid: rec_note.txid().as_ref().to_vec(),
                    value_pool: proposal::ValuePool::from(rec_note.note().protocol()).into(),
                    index: rec_note.output_index().into(),
                    value: rec_note.note().value().into(),
                })
            }))
            .collect();

        let balance = Some(proposal::TransactionBalance {
            proposed_change: value
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
            fee_required: value.balance().fee_required().into(),
        });

        #[allow(deprecated)]
        Some(proposal::Proposal {
            proto_version: PROPOSAL_SER_V1,
            transaction_request,
            anchor_height,
            inputs,
            balance,
            fee_rule: match value.fee_rule() {
                StandardFeeRule::PreZip313 => proposal::FeeRule::PreZip313,
                StandardFeeRule::Zip313 => proposal::FeeRule::Zip313,
                StandardFeeRule::Zip317 => proposal::FeeRule::Zip317,
            }
            .into(),
            min_target_height: value.min_target_height().into(),
            is_shielding: value.is_shielding(),
        })
    }

    /// Attempts to parse a [`Proposal`] based upon a supported [`StandardFeeRule`] from its
    /// protobuf representation.
    pub fn try_into_standard_proposal<P: consensus::Parameters, DbT, DbError>(
        &self,
        params: &P,
        wallet_db: &DbT,
    ) -> Result<Proposal<StandardFeeRule, DbT::NoteRef>, ProposalDecodingError<DbError>>
    where
        DbT: InputSource<Error = DbError>,
    {
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

                let transaction_request =
                    TransactionRequest::from_uri(params, &self.transaction_request)?;

                #[cfg(not(feature = "transparent-inputs"))]
                let transparent_inputs = vec![];
                #[cfg(feature = "transparent-inputs")]
                let mut transparent_inputs = vec![];

                let mut received_notes = vec![];
                for input in self.inputs.iter() {
                    let txid = input
                        .parse_txid()
                        .map_err(ProposalDecodingError::TxIdInvalid)?;

                    match input.pool_type()? {
                        PoolType::Transparent => {
                            #[cfg(not(feature = "transparent-inputs"))]
                            return Err(ProposalDecodingError::ValuePoolNotSupported(1));

                            #[cfg(feature = "transparent-inputs")]
                            {
                                let outpoint = OutPoint::new(txid.into(), input.index);
                                transparent_inputs.push(
                                    wallet_db
                                        .get_unspent_transparent_output(&outpoint)
                                        .map_err(ProposalDecodingError::InputRetrieval)?
                                        .ok_or({
                                            ProposalDecodingError::InputNotFound(
                                                txid,
                                                PoolType::Transparent,
                                                input.index,
                                            )
                                        })?,
                                );
                            }
                        }
                        PoolType::Shielded(protocol) => received_notes.push(
                            wallet_db
                                .get_spendable_note(&txid, protocol, input.index)
                                .map_err(ProposalDecodingError::InputRetrieval)
                                .and_then(|opt| {
                                    opt.ok_or({
                                        ProposalDecodingError::InputNotFound(
                                            txid,
                                            PoolType::Shielded(protocol),
                                            input.index,
                                        )
                                    })
                                })?,
                        ),
                    }
                }

                let shielded_inputs = NonEmpty::from_vec(received_notes)
                    .map(|notes| ShieldedInputs::from_parts(self.anchor_height.into(), notes));

                let proto_balance = self
                    .balance
                    .as_ref()
                    .ok_or(ProposalDecodingError::BalanceInvalid)?;
                let balance = TransactionBalance::new(
                    proto_balance
                        .proposed_change
                        .iter()
                        .map(|cv| -> Result<ChangeValue, ProposalDecodingError<_>> {
                            match cv.pool_type()? {
                                PoolType::Shielded(ShieldedProtocol::Sapling) => {
                                    Ok(ChangeValue::sapling(
                                        NonNegativeAmount::from_u64(cv.value)
                                            .map_err(|_| ProposalDecodingError::BalanceInvalid)?,
                                        cv.memo
                                            .as_ref()
                                            .map(|bytes| {
                                                MemoBytes::from_bytes(&bytes.value)
                                                    .map_err(ProposalDecodingError::MemoInvalid)
                                            })
                                            .transpose()?,
                                    ))
                                }
                                t => Err(ProposalDecodingError::InvalidChangeRecipient(t)),
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    NonNegativeAmount::from_u64(proto_balance.fee_required)
                        .map_err(|_| ProposalDecodingError::BalanceInvalid)?,
                )
                .map_err(|_| ProposalDecodingError::BalanceInvalid)?;

                Proposal::from_parts(
                    transaction_request,
                    transparent_inputs,
                    shielded_inputs,
                    balance,
                    fee_rule,
                    self.min_target_height.into(),
                    self.is_shielding,
                )
                .map_err(ProposalDecodingError::ProposalInvalid)
            }
            other => Err(ProposalDecodingError::VersionInvalid(other)),
        }
    }
}
