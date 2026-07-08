//! Types related to the construction and evaluation of transaction proposals.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Display},
};

use nonempty::NonEmpty;
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    PoolType, ShieldedPool,
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
};
use zip321::{TransactionRequest, Zip321Error};

use crate::{
    data_api::wallet::{ConfirmationsPolicy, TargetHeight},
    fees::TransactionBalance,
    wallet::{Note, ReceivedNote, WalletTransparentOutput},
};

/// Errors that can occur in construction of a [`Step`].
#[derive(Debug, Clone)]
pub enum ProposalError {
    /// The total output value of the transaction request is not a valid Zcash amount.
    RequestTotalInvalid,
    /// The total of transaction inputs overflows the valid range of Zcash values.
    Overflow,
    /// The input total and output total of the payment request are not equal to one another. The
    /// sum of transaction outputs, change, and fees is required to be exactly equal to the value
    /// of provided inputs.
    BalanceError {
        input_total: Zatoshis,
        output_total: Zatoshis,
    },
    /// The `is_shielding` flag may only be set to `true` under the following conditions:
    /// * The total of transparent inputs is nonzero
    /// * There exist no Sapling inputs
    /// * There provided transaction request is empty; i.e. the only output values specified
    ///   are change and fee amounts.
    ShieldingInvalid,
    /// No anchor information could be obtained for the specified block height.
    AnchorNotFound(BlockHeight),
    /// A reference to the output of a prior step is invalid.
    ReferenceError(StepOutput),
    /// An attempted double-spend of a prior step output was detected.
    StepDoubleSpend(StepOutput),
    /// An attempted double-spend of an output belonging to the wallet was detected.
    ChainDoubleSpend(PoolType, TxId, u32),
    /// There was a mismatch between the payments in the proposal's transaction request
    /// and the payment pool selection values.
    PaymentPoolsMismatch,
    /// The proposal tried to spend a change output. Mark the `ChangeValue` as ephemeral if this is intended.
    SpendsChange(StepOutput),
    /// The proposal results in an invalid payment request according to ZIP-321.
    Zip321(Zip321Error),
    /// The ZIP 321 payment request at the wrapped index lacked payment amount information.
    PaymentAmountMissing(usize),
    /// A proposal step created an ephemeral output that was not spent in any later step.
    #[cfg(feature = "transparent-inputs")]
    EphemeralOutputLeftUnspent(StepOutput),
    /// The proposal included a payment to a TEX address and a spend from a shielded input in the same step.
    #[cfg(feature = "transparent-inputs")]
    PaysTexFromShielded,
    /// The change strategy provided to input selection failed to correctly generate an ephemeral
    /// change output when needed for sending to a TEX address.
    #[cfg(feature = "transparent-inputs")]
    EphemeralOutputsInvalid,
    /// The requested proposal would link activity on an ephemeral address to other wallet
    /// activity.
    #[cfg(feature = "transparent-inputs")]
    EphemeralAddressLinkability,
    /// A shielding proposal was constructed with a destination address that has no shielded
    /// receiver. Shielding requires the destination to be able to receive shielded value.
    #[cfg(feature = "transparent-inputs")]
    ShieldingRequiresShieldedRecipient,
    /// The transaction version requested is not compatible with the consensus branch for which the
    /// transaction is intended.
    IncompatibleTxVersion(BranchId),
    /// After Ironwood activation, a proposal step would create value in the Orchard pool.
    /// The turnstile only permits value to leave the pool: a step may return change to it
    /// only when strictly less value returns than the step's Orchard inputs remove.
    /// (Payments may never be directed to the Orchard pool after Ironwood activation;
    /// payment classification maintains that invariant, and step construction enforces it
    /// by assertion.)
    #[cfg(feature = "orchard")]
    OrchardPoolValueCreation {
        /// The total value of the Orchard notes spent by the step.
        input_total: Zatoshis,
        /// The total value of the Orchard-pool change outputs created by the step.
        output_total: Zatoshis,
    },
}

impl Display for ProposalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProposalError::RequestTotalInvalid => write!(
                f,
                "The total requested output value is not a valid Zcash amount."
            ),
            ProposalError::Overflow => write!(
                f,
                "The total of transaction inputs overflows the valid range of Zcash values."
            ),
            ProposalError::BalanceError {
                input_total,
                output_total,
            } => write!(
                f,
                "Balance error: the output total {} was not equal to the input total {}",
                u64::from(*output_total),
                u64::from(*input_total)
            ),
            ProposalError::ShieldingInvalid => write!(
                f,
                "The proposal violates the rules for a shielding transaction."
            ),
            ProposalError::AnchorNotFound(h) => {
                write!(f, "Unable to compute anchor for block height {h:?}")
            }
            ProposalError::ReferenceError(r) => {
                write!(f, "No prior step output found for reference {r:?}")
            }
            ProposalError::StepDoubleSpend(r) => write!(
                f,
                "The proposal uses the output of step {r:?} in more than one place."
            ),
            ProposalError::ChainDoubleSpend(pool, txid, index) => write!(
                f,
                "The proposal attempts to spend the same output twice: {pool}, {txid}, {index}"
            ),
            ProposalError::PaymentPoolsMismatch => write!(
                f,
                "The chosen payment pools did not match the payments of the transaction request."
            ),
            ProposalError::SpendsChange(r) => write!(
                f,
                "The proposal attempts to spends the change output created at step {r:?}.",
            ),
            ProposalError::Zip321(r) => {
                write!(f, "The proposal results in an invalid payment {r:?}.",)
            }
            ProposalError::PaymentAmountMissing(idx) => {
                write!(
                    f,
                    "Payment amount not specified for requested payment at index {idx}."
                )
            }
            #[cfg(feature = "transparent-inputs")]
            ProposalError::EphemeralOutputLeftUnspent(r) => write!(
                f,
                "The proposal created an ephemeral output at step {r:?} that was not spent in any later step.",
            ),
            #[cfg(feature = "transparent-inputs")]
            ProposalError::PaysTexFromShielded => write!(
                f,
                "The proposal included a payment to a TEX address and a spend from a shielded input in the same step.",
            ),
            #[cfg(feature = "transparent-inputs")]
            ProposalError::EphemeralOutputsInvalid => write!(
                f,
                "The proposal generator failed to correctly generate an ephemeral change output when needed for sending to a TEX address."
            ),
            #[cfg(feature = "transparent-inputs")]
            ProposalError::EphemeralAddressLinkability => write!(
                f,
                "The proposal requested spending funds in a way that would link activity on an ephemeral address to other wallet activity."
            ),
            #[cfg(feature = "transparent-inputs")]
            ProposalError::ShieldingRequiresShieldedRecipient => write!(
                f,
                "A shielding proposal's destination must have a shielded receiver."
            ),
            #[cfg(feature = "orchard")]
            ProposalError::OrchardPoolValueCreation {
                input_total,
                output_total,
            } => write!(
                f,
                "After Ironwood activation, a step that spends {} zatoshis from the Orchard pool may not return {} zatoshis to it.",
                u64::from(*input_total),
                u64::from(*output_total),
            ),
            ProposalError::IncompatibleTxVersion(branch_id) => write!(
                f,
                "The requested transaction version is incompatible with consensus branch {branch_id:?}"
            ),
        }
    }
}

impl std::error::Error for ProposalError {}

/// The Sapling inputs to a proposed transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct ShieldedInputs<NoteRef> {
    notes: NonEmpty<ReceivedNote<NoteRef, Note>>,
}

impl<NoteRef> ShieldedInputs<NoteRef> {
    /// Constructs a [`ShieldedInputs`] from its constituent parts.
    pub fn from_parts(notes: NonEmpty<ReceivedNote<NoteRef, Note>>) -> Self {
        Self { notes }
    }

    /// Returns the list of Sapling notes to be used as inputs to the proposed transaction.
    pub fn notes(&self) -> &NonEmpty<ReceivedNote<NoteRef, Note>> {
        &self.notes
    }
}

/// A proposal for a series of transactions to be created.
///
/// Each step of the proposal represents a separate transaction to be created. At present, only
/// transparent outputs of earlier steps may be spent in later steps; the ability to chain shielded
/// transaction steps may be added in a future update.
#[derive(Clone, PartialEq, Eq)]
pub struct Proposal<FeeRuleT, NoteRef> {
    fee_rule: FeeRuleT,
    min_target_height: TargetHeight,
    /// The confirmations policy under which the proposal was constructed. It is used to resolve
    /// the anchor for any step that defers its anchor choice (a step with no shielded inputs; see
    /// [`Step::anchor_height`]).
    confirmations_policy: ConfirmationsPolicy,
    steps: NonEmpty<Step<NoteRef>>,
}

impl<FeeRuleT, NoteRef> Proposal<FeeRuleT, NoteRef> {
    /// Constructs a validated multi-step [`Proposal`].
    ///
    /// This operation validates the proposal for agreement between outputs and inputs
    /// in the case of multi-step proposals, and ensures that no double-spends are being
    /// proposed.
    ///
    /// Parameters:
    /// * `fee_rule`: The fee rule observed by the proposed transaction.
    /// * `min_target_height`: The minimum block height at which the transaction may be created.
    /// * `steps`: A vector of steps that make up the proposal.
    pub fn multi_step(
        fee_rule: FeeRuleT,
        min_target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        steps: NonEmpty<Step<NoteRef>>,
    ) -> Result<Self, ProposalError> {
        let mut consumed_chain_inputs: BTreeSet<(PoolType, TxId, u32)> = BTreeSet::new();
        let mut consumed_prior_inputs: BTreeSet<StepOutput> = BTreeSet::new();

        for (i, step) in steps.iter().enumerate() {
            for prior_ref in step.prior_step_inputs() {
                // check that there are no forward references
                if prior_ref.step_index() >= i {
                    return Err(ProposalError::ReferenceError(*prior_ref));
                }
                // check that the reference is valid
                let prior_step = &steps[prior_ref.step_index()];
                match prior_ref.output_index() {
                    StepOutputIndex::Payment(idx) => {
                        if prior_step.transaction_request().payments().len() <= idx {
                            return Err(ProposalError::ReferenceError(*prior_ref));
                        }
                    }
                    StepOutputIndex::Change(idx) => {
                        if prior_step.balance().proposed_change().len() <= idx {
                            return Err(ProposalError::ReferenceError(*prior_ref));
                        }
                    }
                }
                // check that there are no double-spends
                if !consumed_prior_inputs.insert(*prior_ref) {
                    return Err(ProposalError::StepDoubleSpend(*prior_ref));
                }
            }

            for t_out in step.transparent_inputs() {
                let key = (
                    PoolType::TRANSPARENT,
                    TxId::from_bytes(*t_out.outpoint().hash()),
                    t_out.outpoint().n(),
                );
                if !consumed_chain_inputs.insert(key) {
                    return Err(ProposalError::ChainDoubleSpend(key.0, key.1, key.2));
                }
            }

            for s_out in step.shielded_inputs().iter().flat_map(|i| i.notes().iter()) {
                let key = (
                    PoolType::Shielded(s_out.note().pool()),
                    *s_out.txid(),
                    s_out.output_index().into(),
                );
                if !consumed_chain_inputs.insert(key) {
                    return Err(ProposalError::ChainDoubleSpend(key.0, key.1, key.2));
                }
            }
        }

        Ok(Self {
            fee_rule,
            min_target_height,
            confirmations_policy,
            steps,
        })
    }

    /// Constructs a validated [`Proposal`] having only a single step from its constituent parts.
    ///
    /// This operation validates the proposal for balance consistency and agreement between
    /// the `is_shielding` flag and the structure of the proposal.
    ///
    /// Parameters:
    /// * `transaction_request`: The ZIP 321 transaction request describing the payments to be
    ///   made.
    /// * `payment_pools`: A map from payment index to pool type.
    /// * `transparent_inputs`: The set of previous transparent outputs to be spent.
    /// * `shielded_inputs`: The sets of previous shielded outputs to be spent.
    /// * `anchor_height`: See [`Step::from_parts`].
    /// * `balance`: The change outputs to be added the transaction and the fee to be paid.
    /// * `fee_rule`: The fee rule observed by the proposed transaction.
    /// * `min_target_height`: The minimum block height at which the transaction may be created.
    /// * `is_shielding`: A flag that identifies whether this is a wallet-internal shielding
    ///   transaction.
    /// * `ironwood_active`: See [`Step::from_parts`].
    #[allow(clippy::too_many_arguments)]
    pub fn single_step(
        transaction_request: TransactionRequest,
        payment_pools: BTreeMap<usize, PoolType>,
        transparent_inputs: Vec<WalletTransparentOutput<()>>,
        shielded_inputs: Option<ShieldedInputs<NoteRef>>,
        anchor_height: BlockHeight,
        balance: TransactionBalance,
        fee_rule: FeeRuleT,
        min_target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        is_shielding: bool,
        #[cfg(feature = "orchard")] ironwood_active: bool,
    ) -> Result<Self, ProposalError> {
        Ok(Self {
            fee_rule,
            min_target_height,
            confirmations_policy,
            steps: NonEmpty::singleton(Step::from_parts(
                &[],
                transaction_request,
                payment_pools,
                transparent_inputs,
                shielded_inputs,
                anchor_height,
                vec![],
                balance,
                is_shielding,
                #[cfg(feature = "orchard")]
                ironwood_active,
            )?),
        })
    }

    /// Returns the fee rule to be used by the transaction builder.
    pub fn fee_rule(&self) -> &FeeRuleT {
        &self.fee_rule
    }

    /// Returns the target height for which the proposal was prepared.
    ///
    /// The chain must contain at least this many blocks in order for the proposal to
    /// be executed.
    pub fn min_target_height(&self) -> TargetHeight {
        self.min_target_height
    }

    /// Returns the confirmations policy under which the proposal was constructed. It is used to
    /// resolve the anchor for any step that defers its anchor choice (a step with no shielded
    /// inputs; see [`Step::anchor_height`]).
    pub fn confirmations_policy(&self) -> ConfirmationsPolicy {
        self.confirmations_policy
    }

    /// Returns the steps of the proposal. Each step corresponds to an independent transaction to
    /// be generated as a result of this proposal.
    pub fn steps(&self) -> &NonEmpty<Step<NoteRef>> {
        &self.steps
    }

    /// Returns the total number of inputs across all steps of this proposal that belong to the
    /// given pool.
    ///
    /// For a shielded pool this is the number of spent notes of that pool (Ironwood notes are
    /// counted for [`PoolType::IRONWOOD`], not [`PoolType::ORCHARD`]); for
    /// [`PoolType::Transparent`] it is the number of transparent inputs. See
    /// [`Step::input_count_in_pool`].
    pub fn input_count_in_pool(&self, pool_type: PoolType) -> usize {
        self.steps
            .iter()
            .map(|step| step.input_count_in_pool(pool_type))
            .sum()
    }
}

impl<FeeRuleT: Debug, NoteRef> Debug for Proposal<FeeRuleT, NoteRef> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proposal")
            .field("fee_rule", &self.fee_rule)
            .field("min_target_height", &self.min_target_height)
            .field("steps", &self.steps)
            .finish()
    }
}

/// A reference to either a payment or change output within a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepOutputIndex {
    Payment(usize),
    Change(usize),
}

/// A reference to the output of a step in a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepOutput {
    step_index: usize,
    output_index: StepOutputIndex,
}

impl StepOutput {
    /// Constructs a new [`StepOutput`] from its constituent parts.
    pub fn new(step_index: usize, output_index: StepOutputIndex) -> Self {
        Self {
            step_index,
            output_index,
        }
    }

    /// Returns the step index to which this reference refers.
    pub fn step_index(&self) -> usize {
        self.step_index
    }

    /// Returns the identifier for the payment or change output within
    /// the referenced step.
    pub fn output_index(&self) -> StepOutputIndex {
        self.output_index
    }
}

/// The inputs to be consumed and outputs to be produced in a proposed transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct Step<NoteRef> {
    transaction_request: TransactionRequest,
    payment_pools: BTreeMap<usize, PoolType>,
    transparent_inputs: Vec<WalletTransparentOutput<()>>,
    shielded_inputs: Option<ShieldedInputs<NoteRef>>,
    /// The anchor height that binds every shielded-tree lookup performed while building this
    /// step's transaction — both shielded-input witnesses and shielded-output anchors.
    ///
    /// This is `Some` only when the step spends shielded notes, which must be witnessed against a
    /// specific anchor. A step with no shielded inputs carries `None` and defers the choice of
    /// anchor to interpretation time, where it is derived from the proposal's confirmations policy
    /// and target height; such a step witnesses no notes, so any recent valid anchor is sound. The
    /// resolved anchor is still applied to every shielded-output bundle, so a transaction with only
    /// routed shielded outputs (for example an Orchard-receiver payment routed into the Ironwood
    /// bundle post-NU6.3) remains indistinguishable from one that spends real shielded notes.
    anchor_height: Option<BlockHeight>,
    prior_step_inputs: Vec<StepOutput>,
    balance: TransactionBalance,
    is_shielding: bool,
}

impl<NoteRef> Step<NoteRef> {
    /// Constructs a validated [`Step`] from its constituent parts.
    ///
    /// This operation validates the proposal for balance consistency and agreement between
    /// the `is_shielding` flag and the structure of the proposal.
    ///
    /// Parameters:
    /// * `transaction_request`: The ZIP 321 transaction request describing the payments
    ///   to be made.
    /// * `payment_pools`: A map from payment index to pool type. The set of payment indices
    ///   provided here must exactly match the set of payment indices in the [`TransactionRequest`],
    ///   and the selected pool for an index must correspond to a valid receiver of the
    ///   address at that index (or the address itself in the case of bare transparent or Sapling
    ///   addresses).
    /// * `transparent_inputs`: The set of previous transparent outputs to be spent.
    /// * `shielded_inputs`: The sets of previous shielded outputs to be spent.
    /// * `anchor_height`: The anchor height that binds every shielded-tree lookup performed
    ///   while building this step's transaction — both shielded-input witnesses and
    ///   shielded-output anchors.
    /// * `balance`: The change outputs to be added the transaction and the fee to be paid.
    /// * `is_shielding`: A flag that identifies whether this is a wallet-internal shielding
    ///   transaction.
    /// * `ironwood_active`: Whether the Ironwood pool is active at the target height for
    ///   which this step is proposed. When active, the step is checked against the
    ///   Orchard turnstile: no payment may be directed to the Orchard pool, and change
    ///   may be returned to it only when strictly less value returns than the step's
    ///   Orchard inputs remove.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        prior_steps: &[Step<NoteRef>],
        transaction_request: TransactionRequest,
        payment_pools: BTreeMap<usize, PoolType>,
        transparent_inputs: Vec<WalletTransparentOutput<()>>,
        shielded_inputs: Option<ShieldedInputs<NoteRef>>,
        anchor_height: BlockHeight,
        prior_step_inputs: Vec<StepOutput>,
        balance: TransactionBalance,
        is_shielding: bool,
        #[cfg(feature = "orchard")] ironwood_active: bool,
    ) -> Result<Self, ProposalError> {
        // Verify that the set of payment pools matches exactly a set of valid payment recipients
        if transaction_request.payments().len() != payment_pools.len() {
            return Err(ProposalError::PaymentPoolsMismatch);
        }
        for (idx, pool) in &payment_pools {
            if let Some(payment) = transaction_request.payments().get(idx) {
                // Ironwood notes are Orchard-shaped and delivered to the recipient's Orchard
                // receiver, so an Ironwood-pool payment is valid whenever the recipient can
                // receive Orchard.
                let deliverable = payment.recipient_address().can_receive_as(*pool)
                    || (*pool == PoolType::IRONWOOD
                        && payment
                            .recipient_address()
                            .can_receive_as(PoolType::ORCHARD));
                if !deliverable {
                    return Err(ProposalError::PaymentPoolsMismatch);
                }
                if payment.amount().is_none() {
                    return Err(ProposalError::PaymentAmountMissing(*idx));
                }
            } else {
                return Err(ProposalError::PaymentPoolsMismatch);
            }
        }

        let transparent_input_total = transparent_inputs
            .iter()
            .map(|out| out.txout().value())
            .try_fold(Zatoshis::ZERO, |acc, a| {
                (acc + a).ok_or(ProposalError::Overflow)
            })?;

        let shielded_input_total = shielded_inputs
            .iter()
            .flat_map(|s_in| s_in.notes().iter())
            .map(|out| out.note().value())
            .try_fold(Zatoshis::ZERO, |acc, a| acc + a)
            .ok_or(ProposalError::Overflow)?;

        let prior_step_input_total = prior_step_inputs
            .iter()
            .map(|s_ref| {
                let step = prior_steps
                    .get(s_ref.step_index)
                    .ok_or(ProposalError::ReferenceError(*s_ref))?;
                Ok(match s_ref.output_index {
                    StepOutputIndex::Payment(i) => step
                        .transaction_request
                        .payments()
                        .get(&i)
                        .ok_or(ProposalError::ReferenceError(*s_ref))?
                        .amount()
                        .ok_or(ProposalError::PaymentAmountMissing(i))?,
                    StepOutputIndex::Change(i) => step
                        .balance
                        .proposed_change()
                        .get(i)
                        .ok_or(ProposalError::ReferenceError(*s_ref))?
                        .value(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .try_fold(Zatoshis::ZERO, |acc, a| acc + a)
            .ok_or(ProposalError::Overflow)?;

        let input_total = (transparent_input_total + shielded_input_total + prior_step_input_total)
            .ok_or(ProposalError::Overflow)?;

        let request_total = transaction_request
            .total()
            .map_err(|_| ProposalError::RequestTotalInvalid)?
            .expect("all payments previously checked to have amount values");
        let output_total = (request_total + balance.total()).ok_or(ProposalError::Overflow)?;

        if is_shielding
            && (transparent_input_total == Zatoshis::ZERO
                || shielded_input_total > Zatoshis::ZERO
                || request_total > Zatoshis::ZERO)
        {
            return Err(ProposalError::ShieldingInvalid);
        }

        // After Ironwood activation, the Orchard turnstile only permits value to leave
        // the pool: payments may not be directed to the Orchard pool, and change may be
        // returned to it only when strictly less value returns than the step's Orchard
        // inputs remove.
        #[cfg(feature = "orchard")]
        if ironwood_active {
            // With Ironwood active, payment classification routes every Orchard-receiver
            // payment to the Ironwood pool before a step is constructed, so a payment
            // directed to the Orchard pool here is a programming error, not a condition a
            // well-formed proposal can exhibit. The only Orchard-pool outputs a step may
            // create are change, which is validated below. This is a `debug_assert!` for the
            // internal (input-selection) caller; the untrusted decode path must reject such a
            // payment pool before calling `from_parts` (see `try_into_standard_proposal`).
            debug_assert!(
                !payment_pools
                    .iter()
                    .any(|(_, pool)| *pool == PoolType::ORCHARD),
                "with Ironwood active, no payment may be directed to the Orchard pool",
            );

            let orchard_input_total = shielded_inputs
                .iter()
                .flat_map(|s_in| s_in.notes().iter())
                .filter(|n| n.note().pool() == ShieldedPool::Orchard)
                .map(|n| n.note().value())
                .try_fold(Zatoshis::ZERO, |acc, a| acc + a)
                .ok_or(ProposalError::Overflow)?;

            let orchard_change_total = balance
                .proposed_change()
                .iter()
                .filter(|c| c.output_pool() == PoolType::ORCHARD)
                .map(|c| c.value())
                .try_fold(Zatoshis::ZERO, |acc, a| acc + a)
                .ok_or(ProposalError::Overflow)?;

            if orchard_change_total.is_positive() && orchard_change_total >= orchard_input_total {
                return Err(ProposalError::OrchardPoolValueCreation {
                    input_total: orchard_input_total,
                    output_total: orchard_change_total,
                });
            }
        }

        // Only a step that spends shielded notes binds a concrete anchor (needed to witness those
        // notes). An input-less step defers to interpretation time, so its stored anchor is `None`
        // regardless of the value passed here.
        let anchor_height = shielded_inputs.as_ref().map(|_| anchor_height);

        if input_total == output_total {
            Ok(Self {
                transaction_request,
                payment_pools,
                transparent_inputs,
                shielded_inputs,
                anchor_height,
                prior_step_inputs,
                balance,
                is_shielding,
            })
        } else {
            Err(ProposalError::BalanceError {
                input_total,
                output_total,
            })
        }
    }

    /// Returns the transaction request that describes the payments to be made.
    pub fn transaction_request(&self) -> &TransactionRequest {
        &self.transaction_request
    }
    /// Returns the map from payment index to the pool that has been selected
    /// for the output that will fulfill that payment.
    pub fn payment_pools(&self) -> &BTreeMap<usize, PoolType> {
        &self.payment_pools
    }
    /// Returns the transparent inputs that have been selected to fund the transaction.
    pub fn transparent_inputs(&self) -> &[WalletTransparentOutput<()>] {
        &self.transparent_inputs
    }
    /// Returns the shielded inputs that have been selected to fund the transaction.
    pub fn shielded_inputs(&self) -> Option<&ShieldedInputs<NoteRef>> {
        self.shielded_inputs.as_ref()
    }
    /// Returns the anchor height that binds every shielded-tree lookup performed while building
    /// this step's transaction, or `None` if the step spends no shielded notes and therefore
    /// defers the choice of anchor to interpretation time.
    pub fn anchor_height(&self) -> Option<BlockHeight> {
        self.anchor_height
    }
    /// Returns the inputs that should be obtained from the outputs of the transaction
    /// created to satisfy a previous step of the proposal.
    pub fn prior_step_inputs(&self) -> &[StepOutput] {
        self.prior_step_inputs.as_ref()
    }
    /// Returns the change outputs to be added to the transaction and the fee to be paid.
    pub fn balance(&self) -> &TransactionBalance {
        &self.balance
    }
    /// Returns a flag indicating whether or not the proposed transaction
    /// is exclusively wallet-internal (if it does not involve any external
    /// recipients).
    pub fn is_shielding(&self) -> bool {
        self.is_shielding
    }

    /// Returns whether or not this proposal requires interaction with the specified pool.
    pub fn involves(&self, pool_type: PoolType) -> bool {
        self.input_in_pool(pool_type)
            || self.output_in_pool(pool_type)
            || self.change_in_pool(pool_type)
    }

    /// Returns whether or not this step spends any inputs from the given pool.
    ///
    /// For a shielded pool this is true when a note of that protocol is spent; for
    /// [`PoolType::Transparent`] it is true when the step is a shielding step or has any
    /// transparent inputs.
    pub fn input_in_pool(&self, pool_type: PoolType) -> bool {
        match pool_type {
            PoolType::Transparent => self.is_shielding() || !self.transparent_inputs().is_empty(),
            PoolType::SAPLING => self.shielded_inputs().iter().any(|s_in| {
                s_in.notes()
                    .iter()
                    .any(|note| matches!(note.note().pool(), ShieldedPool::Sapling))
            }),
            PoolType::ORCHARD => self.shielded_inputs().iter().any(|s_in| {
                s_in.notes()
                    .iter()
                    .any(|note| matches!(note.note().pool(), ShieldedPool::Orchard))
            }),
            PoolType::IRONWOOD => self.shielded_inputs().iter().any(|s_in| {
                s_in.notes()
                    .iter()
                    .any(|note| matches!(note.note().pool(), ShieldedPool::Ironwood))
            }),
        }
    }

    /// Returns whether or not this step directs any payment output to the given pool.
    ///
    /// This does not consider change outputs; use [`Step::change_in_pool`] for those.
    pub fn output_in_pool(&self, pool_type: PoolType) -> bool {
        self.payment_pools().values().any(|pool| *pool == pool_type)
    }

    /// Returns whether or not this step directs any change output to the given pool.
    pub fn change_in_pool(&self, pool_type: PoolType) -> bool {
        self.balance()
            .proposed_change()
            .iter()
            .any(|c| c.output_pool() == pool_type)
    }

    /// Returns the number of inputs to this step that belong to the given pool.
    ///
    /// For a shielded pool this is the number of spent notes of that protocol; for
    /// [`PoolType::Transparent`] it is the number of transparent inputs.
    pub fn input_count_in_pool(&self, pool_type: PoolType) -> usize {
        match pool_type {
            PoolType::Transparent => self.transparent_inputs().len(),
            PoolType::SAPLING => self
                .shielded_inputs()
                .iter()
                .flat_map(|s_in| s_in.notes())
                .filter(|note| note.note().pool() == ShieldedPool::Sapling)
                .count(),
            PoolType::ORCHARD => self
                .shielded_inputs()
                .iter()
                .flat_map(|s_in| s_in.notes())
                .filter(|note| note.note().pool() == ShieldedPool::Orchard)
                .count(),
            PoolType::IRONWOOD => self
                .shielded_inputs()
                .iter()
                .flat_map(|s_in| s_in.notes())
                .filter(|note| note.note().pool() == ShieldedPool::Ironwood)
                .count(),
        }
    }

    /// Returns the number of payment outputs of this step that are directed to the given pool.
    ///
    /// This does not include change outputs; use [`Step::change_count_in_pool`] for those.
    pub fn output_count_in_pool(&self, pool_type: PoolType) -> usize {
        self.payment_pools()
            .values()
            .filter(|pool| **pool == pool_type)
            .count()
    }

    /// Returns the number of change outputs of this step that are directed to the given pool.
    pub fn change_count_in_pool(&self, pool_type: PoolType) -> usize {
        self.balance()
            .proposed_change()
            .iter()
            .filter(|c| c.output_pool() == pool_type)
            .count()
    }

    /// Returns the number of Orchard actions required by this step.
    ///
    /// Each Orchard action can carry both a spend and an output, so the number of actions is
    /// the greater of the number of Orchard note spends and the number of Orchard outputs
    /// (payments plus change) in this step.
    pub fn orchard_action_count(&self) -> usize {
        let spends = self.input_count_in_pool(PoolType::ORCHARD);
        let outputs = self.output_count_in_pool(PoolType::ORCHARD)
            + self.change_count_in_pool(PoolType::ORCHARD);
        spends.max(outputs)
    }
}

impl<NoteRef> Debug for Step<NoteRef> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Step")
            .field("transaction_request", &self.transaction_request)
            .field("transparent_inputs", &self.transparent_inputs)
            .field(
                "shielded_inputs",
                &self.shielded_inputs().map(|i| i.notes.len()),
            )
            .field("prior_step_inputs", &self.prior_step_inputs)
            .field("anchor_height", &self.anchor_height)
            .field("balance", &self.balance)
            .field("is_shielding", &self.is_shielding)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "orchard"))]
mod tests {
    use std::collections::BTreeMap;

    use incrementalmerkletree::Position;
    use nonempty::NonEmpty;
    use orchard::{
        ValuePool,
        keys::{FullViewingKey, SpendingKey},
        note::{Note as OrchardNote, NoteVersion, RandomSeed, Rho},
        value::NoteValue,
    };
    use proptest::prelude::*;
    use zcash_primitives::transaction::TxId;
    use zcash_protocol::{PoolType, ShieldedPool, consensus::BlockHeight, value::Zatoshis};
    use zip321::TransactionRequest;

    use super::{Proposal, ProposalError, ShieldedInputs, Step};
    use crate::{
        data_api::wallet::{ConfirmationsPolicy, TargetHeight},
        fees::{ChangeValue, TransactionBalance},
        wallet::Note,
    };

    // Builds an Orchard note of the given version and value. The recipient, rho, and rseed are
    // fixed; only the version and value vary, which is all `Note::pool`/`Note::protocol` depend on.
    fn orchard_note(value: u64, version: NoteVersion) -> Option<OrchardNote> {
        let sk: SpendingKey = Option::from(SpendingKey::from_bytes([0x2a; 32]))?;
        let recipient = FullViewingKey::from(&sk).address_at(0u32, zip32::Scope::External);
        let rho = Option::from(Rho::from_bytes(&[0; 32]))?;
        let rseed = Option::from(RandomSeed::from_bytes([0x1b; 32], &rho))?;
        Option::from(OrchardNote::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            rseed,
            version,
        ))
    }

    // Wraps a list of notes as the shielded inputs of a step.
    fn shielded_inputs_for(notes: Vec<Note>) -> Option<ShieldedInputs<u32>> {
        let received = notes
            .into_iter()
            .enumerate()
            .map(|(i, note)| {
                crate::wallet::ReceivedNote::from_parts(
                    i as u32,
                    TxId::from_bytes([0; 32]),
                    i as u16,
                    note,
                    zip32::Scope::External,
                    Position::from(i as u64),
                    Some(BlockHeight::from_u32(100)),
                    None,
                )
            })
            .collect::<Vec<_>>();
        NonEmpty::from_vec(received).map(ShieldedInputs::from_parts)
    }

    // Wraps a list of notes into a single `Step` whose only inputs are those shielded notes.
    fn step_with_notes(notes: Vec<Note>) -> Step<u32> {
        let shielded_inputs = shielded_inputs_for(notes);
        Step {
            transaction_request: TransactionRequest::empty(),
            payment_pools: BTreeMap::new(),
            transparent_inputs: vec![],
            shielded_inputs,
            anchor_height: Some(BlockHeight::from_u32(100)),
            prior_step_inputs: vec![],
            balance: TransactionBalance::new(vec![], Zatoshis::ZERO).unwrap(),
            is_shielding: false,
        }
    }

    // Constructs a validated step spending the given notes, with no payments.
    fn validated_step(
        notes: Vec<Note>,
        balance: TransactionBalance,
        ironwood_active: bool,
    ) -> Result<Step<u32>, ProposalError> {
        Step::from_parts(
            &[],
            TransactionRequest::empty(),
            BTreeMap::new(),
            vec![],
            shielded_inputs_for(notes),
            BlockHeight::from_u32(100),
            vec![],
            balance,
            false,
            ironwood_active,
        )
    }

    fn shielded_change(pool: ShieldedPool, value: u64) -> ChangeValue {
        ChangeValue::shielded(pool, Zatoshis::const_from_u64(value), None)
    }

    /// Proposal construction conserves value: the total output value of a step (payments +
    /// change + fee) may never exceed its total input value. A step whose outputs exceed its
    /// inputs is rejected with [`ProposalError::BalanceError`] rather than being constructed.
    /// This is the value-conservation floor that pool-selection policy builds on: no selection
    /// of inputs can ever be assembled into a proposal that spends more than it takes in.
    #[test]
    fn proposal_construction_conserves_value() {
        // Inputs: one 10_000 Orchard note. Outputs: 8_000 change + 4_000 fee = 12_000, which
        // exceeds the 10_000 of input value. (ironwood_active = false so the balance check,
        // not the turnstile, is what rejects this.)
        assert_matches!(
            validated_step(
                orchard_and_ironwood_notes(1, 0),
                TransactionBalance::new(
                    vec![shielded_change(ShieldedPool::Orchard, 8_000)],
                    Zatoshis::const_from_u64(4_000),
                )
                .unwrap(),
                false,
            ),
            Err(ProposalError::BalanceError {
                input_total,
                output_total,
            }) if input_total == Zatoshis::const_from_u64(10_000)
                && output_total == Zatoshis::const_from_u64(12_000)
        );

        // The matching balanced step (6_000 change + 4_000 fee == 10_000 input) is accepted,
        // confirming the rejection above is due to the value imbalance and not some unrelated
        // constraint.
        assert_matches!(
            validated_step(
                orchard_and_ironwood_notes(1, 0),
                TransactionBalance::new(
                    vec![shielded_change(ShieldedPool::Orchard, 6_000)],
                    Zatoshis::const_from_u64(4_000),
                )
                .unwrap(),
                false,
            ),
            Ok(_)
        );
    }

    #[test]
    fn orchard_turnstile_permits_only_strict_pool_balance_decrease() {
        // Post-activation, change may return to Orchard when strictly less value returns
        // than the step's Orchard inputs remove: 6_000 change < 10_000 input.
        assert_matches!(
            validated_step(
                orchard_and_ironwood_notes(1, 0),
                TransactionBalance::new(
                    vec![shielded_change(ShieldedPool::Orchard, 6_000)],
                    Zatoshis::const_from_u64(4_000),
                )
                .unwrap(),
                true,
            ),
            Ok(_)
        );

        // Post-activation, Orchard change equal to the Orchard input total would leave the
        // pool balance unchanged, which the turnstile forbids.
        assert_matches!(
            validated_step(
                orchard_and_ironwood_notes(1, 1),
                TransactionBalance::new(
                    vec![
                        shielded_change(ShieldedPool::Orchard, 10_000),
                        shielded_change(ShieldedPool::Ironwood, 16_000),
                    ],
                    Zatoshis::const_from_u64(4_000),
                )
                .unwrap(),
                true,
            ),
            Err(ProposalError::OrchardPoolValueCreation {
                input_total,
                output_total,
            }) if input_total == Zatoshis::const_from_u64(10_000)
                && output_total == Zatoshis::const_from_u64(10_000)
        );

        // Post-activation, a step that spends no Orchard notes may not create Orchard
        // change at all.
        assert_matches!(
            validated_step(
                orchard_and_ironwood_notes(0, 1),
                TransactionBalance::new(
                    vec![shielded_change(ShieldedPool::Orchard, 16_000)],
                    Zatoshis::const_from_u64(4_000),
                )
                .unwrap(),
                true,
            ),
            Err(ProposalError::OrchardPoolValueCreation {
                input_total,
                output_total,
            }) if input_total == Zatoshis::ZERO
                && output_total == Zatoshis::const_from_u64(16_000)
        );

        // Before activation, value may freely enter the Orchard pool: the same step is
        // valid.
        assert_matches!(
            validated_step(
                orchard_and_ironwood_notes(0, 1),
                TransactionBalance::new(
                    vec![shielded_change(ShieldedPool::Orchard, 16_000)],
                    Zatoshis::const_from_u64(4_000),
                )
                .unwrap(),
                false,
            ),
            Ok(_)
        );
    }

    // Constructs a step that spends a 10_000-zatoshi Orchard note to pay 6_000 zatoshis to
    // an Orchard receiver, with the payment assigned to the given pool.
    fn orchard_payment_step(
        pool: PoolType,
        ironwood_active: bool,
    ) -> Result<Step<u32>, ProposalError> {
        use zcash_keys::address::{Address, UnifiedAddress};
        use zcash_protocol::consensus::Network;

        let sk: SpendingKey = Option::from(SpendingKey::from_bytes([0x2a; 32])).unwrap();
        let recipient = FullViewingKey::from(&sk).address_at(0u32, zip32::Scope::External);
        let ua = UnifiedAddress::from_receivers(Some(recipient), None, None).unwrap();
        let to = Address::Unified(ua).to_zcash_address(&Network::TestNetwork);

        let request = TransactionRequest::new(vec![
            zip321::Payment::new(
                to,
                Some(Zatoshis::const_from_u64(6_000)),
                None,
                None,
                None,
                vec![],
            )
            .unwrap(),
        ])
        .unwrap();

        Step::from_parts(
            &[],
            request,
            BTreeMap::from([(0usize, pool)]),
            vec![],
            shielded_inputs_for(orchard_and_ironwood_notes(1, 0)),
            BlockHeight::from_u32(100),
            vec![],
            TransactionBalance::new(vec![], Zatoshis::const_from_u64(4_000)).unwrap(),
            false,
            ironwood_active,
        )
    }

    #[test]
    fn orchard_turnstile_permits_routed_and_pre_activation_payments() {
        // A payment routed through the Ironwood bundle (the post-activation representation
        // of an Orchard-receiver payment) is valid.
        assert_matches!(orchard_payment_step(PoolType::IRONWOOD, true), Ok(_));

        // Before activation, an Orchard-pool payment is valid.
        assert_matches!(orchard_payment_step(PoolType::ORCHARD, false), Ok(_));
    }

    // Post-activation, payment classification never assigns a payment to the Orchard pool,
    // so a step constructed with one is a programming error and step construction asserts.
    #[test]
    #[should_panic(expected = "no payment may be directed to the Orchard pool")]
    fn orchard_pool_payment_with_ironwood_active_is_a_programming_error() {
        let _ = orchard_payment_step(PoolType::ORCHARD, true);
    }

    // Builds `n` version-2 (Orchard) notes followed by `m` version-3 (Ironwood) notes.
    fn orchard_and_ironwood_notes(n: usize, m: usize) -> Vec<Note> {
        let mut notes = Vec::with_capacity(n + m);
        for _ in 0..n {
            notes.push(Note::Orchard {
                note: orchard_note(10_000, NoteVersion::V2).unwrap(),
                pool: ValuePool::Orchard,
            });
        }
        for _ in 0..m {
            notes.push(Note::Orchard {
                note: orchard_note(20_000, NoteVersion::V3).unwrap(),
                pool: ValuePool::Ironwood,
            });
        }
        notes
    }

    proptest! {
        // `Note::pool` reports the `ValuePool` recorded alongside an Orchard note.
        #[test]
        fn note_pool_reports_stored_value_pool(
            value in 1u64..1_000_000_000u64,
            is_ironwood in any::<bool>(),
        ) {
            let (version, pool, expected) = if is_ironwood {
                (NoteVersion::V3, ValuePool::Ironwood, ShieldedPool::Ironwood)
            } else {
                (NoteVersion::V2, ValuePool::Orchard, ShieldedPool::Orchard)
            };
            let Some(note) = orchard_note(value, version) else {
                // A handful of (value, rho, rseed) combinations do not form a valid note; skip them.
                return Err(TestCaseError::reject("invalid orchard note"));
            };
            let note = Note::Orchard { note, pool };
            prop_assert_eq!(note.pool(), expected);
        }

        // `Step::input_count_in_pool` returns the number of selected notes in each pool, splitting
        // Orchard (version 2) from Ironwood (version 3); Sapling is zero here. `input_in_pool`
        // agrees with `input_count_in_pool > 0`, and `Proposal::input_count_in_pool` sums the
        // per-step counts.
        #[test]
        fn step_and_proposal_input_counts_match_constructed_notes(
            n_orchard in 0usize..5,
            n_ironwood in 0usize..5,
            m_orchard in 0usize..5,
            m_ironwood in 0usize..5,
        ) {
            let step1 = step_with_notes(orchard_and_ironwood_notes(n_orchard, n_ironwood));
            prop_assert_eq!(step1.input_count_in_pool(PoolType::SAPLING), 0);
            prop_assert_eq!(step1.input_count_in_pool(PoolType::ORCHARD), n_orchard);
            prop_assert_eq!(step1.input_count_in_pool(PoolType::IRONWOOD), n_ironwood);

            for pool in [ShieldedPool::Sapling, ShieldedPool::Orchard, ShieldedPool::Ironwood] {
                let pool_type = PoolType::Shielded(pool);
                prop_assert_eq!(
                    step1.input_in_pool(pool_type),
                    step1.input_count_in_pool(pool_type) > 0
                );
            }

            let step2 = step_with_notes(orchard_and_ironwood_notes(m_orchard, m_ironwood));
            let proposal = Proposal::<(), u32> {
                fee_rule: (),
                min_target_height: TargetHeight::from(100u32),
                confirmations_policy: ConfirmationsPolicy::default(),
                steps: NonEmpty::from_vec(vec![step1, step2]).unwrap(),
            };
            prop_assert_eq!(proposal.input_count_in_pool(PoolType::SAPLING), 0);
            prop_assert_eq!(
                proposal.input_count_in_pool(PoolType::ORCHARD),
                n_orchard + m_orchard
            );
            prop_assert_eq!(
                proposal.input_count_in_pool(PoolType::IRONWOOD),
                n_ironwood + m_ironwood
            );
        }
    }
}
