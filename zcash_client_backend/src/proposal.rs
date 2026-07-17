//! Types related to the construction and evaluation of transaction proposals.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Display},
};

#[cfg(feature = "transparent-inputs")]
use ::transparent::address::TransparentAddress;
use nonempty::NonEmpty;
use zcash_primitives::transaction::{TxId, TxVersion};
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
    /// A proposal step produces a shielded bundle — it spends shielded notes, pays to a shielded
    /// pool, or returns shielded change — but does not specify an anchor height against which its
    /// shielded-tree lookups are performed. Only a purely transparent step may omit its anchor.
    MissingShieldedAnchor,
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
    /// A transparent change output carries an explicit recipient address that is not the
    /// address of any of the transparent inputs of the same proposal step.
    #[cfg(feature = "transparent-inputs")]
    TransparentChangeRecipientMismatch(TransparentAddress),
    /// The transaction version requested is not compatible with the consensus branch for which the
    /// transaction is intended.
    IncompatibleTxVersion(BranchId),
    /// After NU6.3 activation, a payment to an Orchard receiver must be delivered through the
    /// Ironwood pool, which requires a version 6 transaction. The explicitly-requested transaction
    /// version has no Ironwood bundle, so it cannot carry the payment. (The Orchard turnstile is a
    /// consensus rule after NU6.3: no payment may add value to the Orchard pool, so such a payment
    /// cannot be delivered as a plain Orchard output either.)
    OrchardReceiverRequiresIronwood(TxVersion),
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
            ProposalError::MissingShieldedAnchor => write!(
                f,
                "A proposal step that produces a shielded bundle must specify an anchor height."
            ),
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
            #[cfg(feature = "transparent-inputs")]
            ProposalError::TransparentChangeRecipientMismatch(addr) => write!(
                f,
                "Transparent change may only be returned to an address that funds the transparent inputs of the same step (got {addr:?})."
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
            ProposalError::OrchardReceiverRequiresIronwood(version) => write!(
                f,
                "After NU6.3 activation, a payment to an Orchard receiver requires a version 6 (Ironwood) transaction, but version {version:?} was requested."
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
    /// the anchor for a step that carries no explicit anchor height (a purely transparent step;
    /// see [`Step::anchor_height`]).
    confirmations_policy: ConfirmationsPolicy,
    steps: NonEmpty<Step<NoteRef>>,
    /// The transaction version explicitly requested when the proposal was constructed, if any.
    /// When `None`, the transaction is built at the version implied by the target height (version 6
    /// from NU6.3 onward).
    proposed_version: Option<TxVersion>,
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
            proposed_version: None,
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
            proposed_version: None,
            steps: NonEmpty::singleton(Step::from_parts(
                &[],
                transaction_request,
                payment_pools,
                transparent_inputs,
                shielded_inputs,
                Some(anchor_height),
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
    /// resolve the anchor for a step that carries no explicit anchor height (a purely transparent
    /// step; see [`Step::anchor_height`]).
    pub fn confirmations_policy(&self) -> ConfirmationsPolicy {
        self.confirmations_policy
    }

    /// Returns the transaction version explicitly requested when the proposal was constructed, if
    /// any. When `None`, the transaction is built at the version implied by the target height
    /// (version 6 from NU6.3 onward).
    pub fn proposed_version(&self) -> Option<TxVersion> {
        self.proposed_version
    }

    /// Returns this proposal with its requested transaction version set to the given value.
    ///
    /// This records the version passed to proposal construction so that it is carried through to
    /// transaction building; it does not re-validate the proposal against the version.
    pub fn with_proposed_version(mut self, proposed_version: Option<TxVersion>) -> Self {
        self.proposed_version = proposed_version;
        self
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
            .field("proposed_version", &self.proposed_version)
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
    /// This is `Some` for any step that produces a shielded bundle — one that spends shielded
    /// notes, pays to a shielded pool, or returns shielded change. The anchor is selected from the
    /// wallet's checkpoints at proposal construction time and applied to every shielded-tree
    /// lookup, so a transaction with only routed shielded outputs (for example an Orchard-receiver
    /// payment routed into the Ironwood bundle post-NU6.3) remains indistinguishable from one that
    /// spends real shielded notes. Only a purely transparent step may carry `None`.
    anchor_height: Option<BlockHeight>,
    prior_step_inputs: Vec<StepOutput>,
    balance: TransactionBalance,
    is_shielding: bool,
}

/// Returns whether a step produces any shielded bundle — it spends shielded notes, pays to a
/// shielded pool, or returns change to a shielded pool. Such a step performs shielded-tree lookups
/// (including the dummy spends that pad an output-only bundle so it is indistinguishable from one
/// that spends real notes), so it must bind a concrete anchor against which those lookups are made.
pub(crate) fn produces_shielded_bundle(
    has_shielded_inputs: bool,
    payment_pools: &BTreeMap<usize, PoolType>,
    balance: &TransactionBalance,
) -> bool {
    has_shielded_inputs
        || payment_pools
            .values()
            .any(|pool| matches!(pool, PoolType::Shielded(_)))
        || balance
            .proposed_change()
            .iter()
            .any(|change| matches!(change.output_pool(), PoolType::Shielded(_)))
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
    ///   shielded-output anchors. A step that produces a shielded bundle (spends shielded notes,
    ///   pays to a shielded pool, or returns shielded change) must provide `Some`; only a purely
    ///   transparent step may pass `None`.
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
        anchor_height: Option<BlockHeight>,
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

        // Transparent change carrying an explicit recipient may only be returned to an
        // address that funded the transparent inputs of this step.
        #[cfg(feature = "transparent-inputs")]
        for cv in balance.proposed_change() {
            if let Some(addr) = cv.transparent_recipient()
                && !transparent_inputs
                    .iter()
                    .any(|i| i.recipient_address() == addr)
            {
                return Err(ProposalError::TransparentChangeRecipientMismatch(*addr));
            }
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

        // A step that produces any shielded bundle must bind a concrete anchor: every shielded-tree
        // lookup it performs — including the dummy spends that pad an output-only bundle so it is
        // indistinguishable from one that spends real notes — is made against that anchor. Only a
        // purely transparent step may omit it. The untrusted decode path rejects this same
        // combination at the parse boundary (see `try_into_standard_proposal`).
        if anchor_height.is_none()
            && produces_shielded_bundle(shielded_inputs.is_some(), &payment_pools, &balance)
        {
            return Err(ProposalError::MissingShieldedAnchor);
        }

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
    /// this step's transaction, or `None` for a purely transparent step that performs no such
    /// lookup.
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

    #[cfg(feature = "orchard")]
    fn orchard_style_action_count(
        &self,
        pool_type: PoolType,
        bundle_type: ::orchard::builder::BundleType,
        bundle_version: ::orchard::bundle::BundleVersion,
    ) -> Result<usize, &'static str> {
        crate::fees::orchard::transactional_action_count(
            bundle_type,
            bundle_version,
            self.input_count_in_pool(pool_type),
            self.output_count_in_pool(pool_type) + self.change_count_in_pool(pool_type),
        )
    }

    /// Returns the number of actions the transaction builder will produce for this step's
    /// Orchard-pool bundle, given the bundle type and version it will be configured with.
    ///
    /// The count depends upon the bundle version: prior to NU6.3, an action may carry both a
    /// spend and an output, so a bundle requires `max(spends, outputs)` actions; from NU6.3
    /// onwards the Orchard pool disables cross-address transfers, and each requested spend and
    /// output is instead paired with a fabricated zero-valued counterpart, so a bundle requires
    /// `spends + outputs` actions. The bundle type determines the padding applied on top of
    /// that count.
    ///
    /// The caller must pass the same bundle type and version the transaction builder will be
    /// configured with, otherwise the count will not match the bundle that is built.
    /// [`bundle_version_for_branch`] returns the version applicable to a given consensus branch
    /// and pool; the bundle type is determined by the change strategy that produced the
    /// proposal (see [`SingleOutputChangeStrategy::with_unpadded_orchard_pool_bundles`]).
    ///
    /// # Errors
    ///
    /// Returns an error if this step's Orchard spend and output counts are incompatible with
    /// the given bundle type and version.
    ///
    /// [`bundle_version_for_branch`]: zcash_primitives::transaction::components::orchard::bundle_version_for_branch
    /// [`SingleOutputChangeStrategy::with_unpadded_orchard_pool_bundles`]: crate::fees::zip317::SingleOutputChangeStrategy::with_unpadded_orchard_pool_bundles
    #[cfg(feature = "orchard")]
    pub fn orchard_action_count(
        &self,
        bundle_type: ::orchard::builder::BundleType,
        bundle_version: ::orchard::bundle::BundleVersion,
    ) -> Result<usize, &'static str> {
        self.orchard_style_action_count(PoolType::ORCHARD, bundle_type, bundle_version)
    }

    /// Returns the number of actions the transaction builder will produce for this step's
    /// Ironwood-pool bundle, given the bundle type and version it will be configured with.
    ///
    /// See [`Step::orchard_action_count`] for how the count is determined; the Ironwood pool
    /// permits cross-address transfers, so an Ironwood bundle requires
    /// `max(spends, outputs)` actions before padding.
    ///
    /// # Errors
    ///
    /// Returns an error if this step's Ironwood spend and output counts are incompatible with
    /// the given bundle type and version.
    #[cfg(feature = "orchard")]
    pub fn ironwood_action_count(
        &self,
        bundle_type: ::orchard::builder::BundleType,
        bundle_version: ::orchard::bundle::BundleVersion,
    ) -> Result<usize, &'static str> {
        self.orchard_style_action_count(PoolType::IRONWOOD, bundle_type, bundle_version)
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
        builder::BundleType,
        bundle::BundleVersion,
        keys::{FullViewingKey, SpendingKey},
        note::{Note as OrchardNote, NoteVersion, RandomSeed, Rho},
        value::NoteValue,
    };
    use proptest::prelude::*;
    use zcash_primitives::transaction::{
        TxId,
        components::orchard::{ACTION_SIZE, bundle_version_for_branch},
    };
    use zcash_protocol::{
        PoolType, ShieldedPool,
        consensus::{BlockHeight, BranchId, Network, NetworkUpgrade, Parameters},
        constants::MAX_BLOCK_BYTES,
        value::Zatoshis,
    };
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
        step_with_notes_and_change(notes, vec![])
    }

    // Wraps a list of notes into a single `Step` spending those shielded notes and returning the
    // given change outputs. The step is constructed directly rather than via `Step::from_parts`,
    // so the change values need not be covered by the input values.
    fn step_with_notes_and_change(notes: Vec<Note>, change: Vec<ChangeValue>) -> Step<u32> {
        let shielded_inputs = shielded_inputs_for(notes);
        Step {
            transaction_request: TransactionRequest::empty(),
            payment_pools: BTreeMap::new(),
            transparent_inputs: vec![],
            shielded_inputs,
            anchor_height: Some(BlockHeight::from_u32(100)),
            prior_step_inputs: vec![],
            balance: TransactionBalance::new(change, Zatoshis::ZERO).unwrap(),
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
            Some(BlockHeight::from_u32(100)),
            vec![],
            balance,
            false,
            ironwood_active,
        )
    }

    fn shielded_change(pool: ShieldedPool, value: u64) -> ChangeValue {
        ChangeValue::shielded(pool, Zatoshis::const_from_u64(value), None)
    }

    /// A step that produces any shielded bundle must bind a concrete anchor. Passing `None` (the
    /// decoded state of the wire-format zero sentinel) for such a step is rejected, whether the
    /// shielded bundle comes from spent notes or from shielded outputs. Only a purely transparent
    /// step may carry `None`.
    #[test]
    fn shielded_step_requires_anchor() {
        // A step that spends shielded notes with no anchor is rejected.
        assert_matches!(
            Step::from_parts(
                &[],
                TransactionRequest::empty(),
                BTreeMap::new(),
                vec![],
                shielded_inputs_for(orchard_and_ironwood_notes((1, 10_000), (0, 0))),
                None,
                vec![],
                TransactionBalance::new(vec![], Zatoshis::const_from_u64(10_000)).unwrap(),
                false,
                false,
            ),
            Err(ProposalError::MissingShieldedAnchor)
        );

        // A step with a shielded output but no shielded inputs must also bind an anchor: the dummy
        // spends padding the output bundle commit to it.
        assert_matches!(
            Step::from_parts(
                &[],
                TransactionRequest::empty(),
                BTreeMap::new(),
                vec![],
                None::<ShieldedInputs<u32>>,
                None,
                vec![],
                TransactionBalance::new(
                    vec![shielded_change(ShieldedPool::Orchard, 10_000)],
                    Zatoshis::ZERO,
                )
                .unwrap(),
                false,
                false,
            ),
            Err(ProposalError::MissingShieldedAnchor)
        );

        // A purely transparent step may carry no anchor.
        assert_matches!(
            Step::from_parts(
                &[],
                TransactionRequest::empty(),
                BTreeMap::new(),
                vec![],
                None::<ShieldedInputs<u32>>,
                None,
                vec![],
                TransactionBalance::new(vec![], Zatoshis::ZERO).unwrap(),
                false,
                false,
            ),
            Ok(step) if step.anchor_height().is_none()
        );
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
                orchard_and_ironwood_notes((1, 10_000), (0, 0)),
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
                orchard_and_ironwood_notes((1, 10_000), (0, 0)),
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
                orchard_and_ironwood_notes((1, 10_000), (0, 0)),
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
                orchard_and_ironwood_notes((1, 10_000), (1, 20_000)),
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
                orchard_and_ironwood_notes((0, 0), (1, 20_000)),
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
                orchard_and_ironwood_notes((0, 0), (1, 20_000)),
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
            shielded_inputs_for(orchard_and_ironwood_notes((1, 10_000), (0, 0))),
            Some(BlockHeight::from_u32(100)),
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

    // Builds `orchard.0` version-2 (Orchard) notes of value `orchard.1`, followed by `ironwood.0`
    // version-3 (Ironwood) notes of value `ironwood.1`.
    //
    // Every note of a given pool is identical, so each is derived once and cloned: deriving a full
    // viewing key per note makes the large-transaction cases below cost seconds rather than
    // milliseconds. Only the count and the pool of each note matter to an action count.
    fn orchard_and_ironwood_notes(
        (n, orchard_value): (usize, u64),
        (m, ironwood_value): (usize, u64),
    ) -> Vec<Note> {
        let mut notes = Vec::with_capacity(n + m);
        if n > 0 {
            let note = Note::Orchard {
                note: orchard_note(orchard_value, NoteVersion::V2).unwrap(),
                pool: ValuePool::Orchard,
            };
            notes.extend(std::iter::repeat_n(note, n));
        }
        if m > 0 {
            let note = Note::Orchard {
                note: orchard_note(ironwood_value, NoteVersion::V3).unwrap(),
                pool: ValuePool::Ironwood,
            };
            notes.extend(std::iter::repeat_n(note, m));
        }
        notes
    }

    // Note and change values, spanning a zero-valued note through a large one. An action count is a
    // function of how many notes and outputs a step has in each pool, never of what they are worth,
    // so every value here must give the same answer. The upper bound keeps the total value of even
    // the largest generated step well inside `MAX_MONEY`, so that `TransactionBalance` construction
    // cannot fail for a reason these tests are not about.
    fn arb_note_value() -> impl Strategy<Value = u64> {
        prop_oneof![
            1 => Just(0u64),
            8 => 1u64..1_000_000_000,
        ]
    }

    // An upper bound on the actions a single bundle can contain on-chain: a transaction may not
    // exceed a block, and each action costs at least its action description. The true ceiling is
    // lower, since `ACTION_SIZE` excludes each action's spend authorization signature and the
    // bundle's proof, but an over-estimate is what these tests want: it exercises counts at least
    // as large as anything buildable.
    const MAX_ACTIONS_PER_BUNDLE: usize = MAX_BLOCK_BYTES / ACTION_SIZE;

    // Spend and output counts spanning what a wallet can actually produce: ordinary payments, large
    // note-consolidation transactions, and bundles at the block ceiling. Each side is capped at
    // half the ceiling, because from NU6.3 an Orchard spend and an output no longer share an
    // action, so `spends + outputs` must itself fit. Small counts are weighted heavily: that is
    // where the padding floor binds, and where real transactions live.
    fn arb_note_count() -> impl Strategy<Value = usize> {
        prop_oneof![
            6 => 0usize..8,
            2 => 8usize..100,
            1 => 100usize..=MAX_ACTIONS_PER_BUNDLE / 2,
        ]
    }

    // The network upgrades at which the Orchard pool exists but still permits cross-address
    // transfers, so that a requested spend and a requested output may share an action.
    fn arb_pre_nu6_3_upgrade() -> impl Strategy<Value = NetworkUpgrade> {
        prop::sample::select(vec![
            NetworkUpgrade::Nu5,
            NetworkUpgrade::Nu6,
            NetworkUpgrade::Nu6_1,
            NetworkUpgrade::Nu6_2,
        ])
    }

    // The network upgrades from which the Orchard pool disables cross-address transfers. `Nu7` is
    // excluded: it has no activation height on any network yet, so no bundle can be built for it.
    fn arb_nu6_3_or_later_upgrade() -> impl Strategy<Value = NetworkUpgrade> {
        prop::sample::select(vec![NetworkUpgrade::Nu6_3])
    }

    // Resolves the bundle version applicable to a pool at an upgrade's testnet activation height,
    // the way the fee and builder paths do: height -> consensus branch -> `BundleVersion`.
    fn bundle_version_at(upgrade: NetworkUpgrade, pool: ValuePool) -> BundleVersion {
        let height = Network::TestNetwork.activation_height(upgrade).unwrap();
        bundle_version_for_branch(BranchId::for_height(&Network::TestNetwork, height), pool)
            .unwrap()
    }

    // A step that requires no actions in a pool produces no bundle in that pool, so it is charged
    // nothing, no matter how much padding the bundle type would otherwise apply. The exception is
    // a bundle type that requires a bundle: the builder then produces one consisting entirely of
    // dummy actions, padded to the type's minimum.
    #[test]
    fn uninvolved_pool_is_charged_nothing_unless_a_bundle_is_required() {
        let step = step_with_notes(vec![]);
        for bundle_type in [BundleType::DEFAULT, BundleType::UNPADDED] {
            assert_eq!(
                step.orchard_action_count(bundle_type, BundleVersion::orchard_v3()),
                Ok(0)
            );
            assert_eq!(
                step.ironwood_action_count(bundle_type, BundleVersion::ironwood_v3()),
                Ok(0)
            );
        }

        // `bundle_required` guarantees a bundle exists, padded to the type's minimum: two
        // all-dummy actions by default, or one when the type opts out of the default padding.
        let required = BundleType::Transactional {
            bundle_required: true,
            pad_to_minimum: None,
        };
        assert_eq!(
            step.orchard_action_count(required, BundleVersion::orchard_v3()),
            Ok(2)
        );
        let required_unpadded = BundleType::Transactional {
            bundle_required: true,
            pad_to_minimum: Some(1),
        };
        assert_eq!(
            step.orchard_action_count(required_unpadded, BundleVersion::orchard_v3()),
            Ok(1)
        );

        // A zero floor cannot suppress a required bundle: a bundle must contain at least one
        // action to exist at all, so the required-but-unpadded-to-zero case still yields one.
        let required_zero_floor = BundleType::Transactional {
            bundle_required: true,
            pad_to_minimum: Some(0),
        };
        assert_eq!(
            step.orchard_action_count(required_zero_floor, BundleVersion::orchard_v3()),
            Ok(1)
        );

        // Without `bundle_required`, a zero floor leaves an uninvolved pool with no bundle.
        let zero_floor = BundleType::Transactional {
            bundle_required: false,
            pad_to_minimum: Some(0),
        };
        assert_eq!(
            step.orchard_action_count(zero_floor, BundleVersion::orchard_v3()),
            Ok(0)
        );
    }

    // The documented error path. A coinbase bundle has spends disabled, so every spend in it must
    // be a dummy; a step that spends notes in a pool therefore cannot be built as a coinbase
    // bundle of that pool, and the count is reported as an error rather than as a wrong number.
    // This is the only error a step can currently provoke: `BundleVersion::default_flags` always
    // enables both spends and outputs, so no transactional bundle type can reject a step's counts.
    #[test]
    fn spends_cannot_be_charged_to_a_coinbase_bundle() {
        let step = step_with_notes(orchard_and_ironwood_notes((1, 10_000), (1, 20_000)));
        assert_matches!(
            step.orchard_action_count(BundleType::Coinbase, BundleVersion::orchard_v3()),
            Err(_)
        );
        assert_matches!(
            step.ironwood_action_count(BundleType::Coinbase, BundleVersion::ironwood_v3()),
            Err(_)
        );

        // A step that spends nothing in the pool is accepted: coinbase bundles create outputs,
        // and are never padded.
        let step = step_with_notes_and_change(
            vec![],
            vec![shielded_change(ShieldedPool::Ironwood, 10_000)],
        );
        assert_eq!(
            step.ironwood_action_count(BundleType::Coinbase, BundleVersion::ironwood_v3()),
            Ok(1)
        );
    }

    // What NU6.3 costs a large transaction depends on its shape, and a wallet estimating fees at
    // scale has to get the difference right.
    #[test]
    fn nu6_3_action_growth_at_scale_depends_on_step_shape() {
        let balanced = |n| {
            step_with_notes_and_change(
                orchard_and_ironwood_notes((n, 10_000), (0, 0)),
                std::iter::repeat_n(shielded_change(ShieldedPool::Orchard, 10_000), n).collect(),
            )
        };

        // A consolidation -- sweeping many notes into a single change output -- pays for that
        // output's fabricated spend and nothing else: one extra action, however large it is.
        let consolidation = step_with_notes_and_change(
            orchard_and_ironwood_notes((MAX_ACTIONS_PER_BUNDLE, 10_000), (0, 0)),
            vec![shielded_change(ShieldedPool::Orchard, 10_000)],
        );
        // 2439 actions: the change output rides along in a spend's action, exactly filling a block.
        assert_eq!(
            consolidation.orchard_action_count(BundleType::UNPADDED, BundleVersion::orchard_v2()),
            Ok(MAX_ACTIONS_PER_BUNDLE)
        );
        // 2440 from NU6.3: one action over the ceiling, so the same sweep no longer fits.
        assert_eq!(
            consolidation.orchard_action_count(BundleType::UNPADDED, BundleVersion::orchard_v3()),
            Ok(MAX_ACTIONS_PER_BUNDLE + 1)
        );

        // A balanced step -- as many outputs as spends -- doubles instead, so the largest one that
        // fits in a block halves at NU6.3: 2439 spends paired with 2439 outputs before, 1219 of
        // each after. This is why `arb_note_count` caps each side at half the ceiling.
        let half = MAX_ACTIONS_PER_BUNDLE / 2;
        assert_eq!(
            balanced(MAX_ACTIONS_PER_BUNDLE)
                .orchard_action_count(BundleType::UNPADDED, BundleVersion::orchard_v2()),
            Ok(MAX_ACTIONS_PER_BUNDLE)
        );
        // 2438: the largest balanced step that still fits.
        assert_eq!(
            balanced(half).orchard_action_count(BundleType::UNPADDED, BundleVersion::orchard_v3()),
            Ok(2 * half)
        );
        // 2440: one note more on each side and it does not.
        assert_eq!(
            balanced(half + 1)
                .orchard_action_count(BundleType::UNPADDED, BundleVersion::orchard_v3()),
            Ok(2 * half + 2)
        );
    }

    // A `Step` does not necessarily come from this wallet's own input selection: a proposal crosses
    // a trust boundary as a serialized message (see `proposal.proto` and
    // `Proposal::try_into_standard_proposal`), so a step's output and change counts are
    // attacker-influenced. A step claiming far more outputs than could ever fit on-chain must still
    // be counted exactly, so that the fee rule is handed an unaffordable action count and rejects
    // it, rather than a small wrapped-around one it would accept.
    //
    // The counts themselves cannot overflow `usize`: each is the length of an in-memory collection,
    // so reaching `usize::MAX` would require more notes than could be addressed.
    #[test]
    fn counts_beyond_the_block_limit_are_counted_exactly() {
        let spends = 4 * MAX_ACTIONS_PER_BUNDLE;
        let change = 4 * MAX_ACTIONS_PER_BUNDLE;
        let step = step_with_notes_and_change(
            orchard_and_ironwood_notes((spends, 10_000), (0, 0)),
            std::iter::repeat_n(shielded_change(ShieldedPool::Orchard, 10_000), change).collect(),
        );

        // Roughly eight times what a block can hold, reported exactly.
        assert!(spends + change > 8 * MAX_ACTIONS_PER_BUNDLE - 1);
        assert_eq!(
            step.orchard_action_count(BundleType::UNPADDED, BundleVersion::orchard_v3()),
            Ok(spends + change)
        );

        // Pre-NU6.3 the same step pairs, so it is charged half as much -- still far past the
        // ceiling, and still counted exactly.
        assert_eq!(
            step.orchard_action_count(BundleType::UNPADDED, BundleVersion::orchard_v2()),
            Ok(spends.max(change))
        );

        // Padding a step this size cannot reduce it, and the ZIP 317 floor is irrelevant here.
        assert_eq!(
            step.orchard_action_count(BundleType::DEFAULT, BundleVersion::orchard_v3()),
            Ok(spends + change)
        );
    }

    // A payment output counts towards the action count of the pool it is directed to, exactly as
    // a change output does. `orchard_payment_step` spends one Orchard note to make one payment.
    #[test]
    fn action_count_includes_payment_outputs() {
        // Pre-activation, the payment is an Orchard-pool output: one spend and one output share
        // an action, because the pre-NU6.3 Orchard bundle version permits cross-address transfers.
        let step = orchard_payment_step(PoolType::ORCHARD, false).unwrap();
        assert_eq!(
            step.orchard_action_count(BundleType::UNPADDED, BundleVersion::orchard_v2()),
            Ok(1)
        );
        assert_eq!(
            step.ironwood_action_count(BundleType::UNPADDED, BundleVersion::ironwood_v3()),
            Ok(0)
        );

        // Post-activation, the payment is routed to the Ironwood pool: the Orchard note spend is
        // charged to the Orchard bundle and the payment output to the Ironwood bundle, so neither
        // pool can pair them into one action.
        let step = orchard_payment_step(PoolType::IRONWOOD, true).unwrap();
        assert_eq!(
            step.orchard_action_count(BundleType::UNPADDED, BundleVersion::orchard_v3()),
            Ok(1)
        );
        assert_eq!(
            step.ironwood_action_count(BundleType::UNPADDED, BundleVersion::ironwood_v3()),
            Ok(1)
        );
    }

    proptest! {
        // The number of actions a step's Orchard-pool bundle requires depends upon the bundle
        // version: the pre-NU6.3 versions permit cross-address transfers, so a spend and an
        // output may share an action (`max(spends, outputs)`), while from NU6.3 onwards the
        // Orchard pool disables them, so each spend and output is paired with a fabricated
        // counterpart and occupies its own action (`spends + outputs`). The Ironwood pool
        // permits cross-address transfers at every version, so it always pairs.
        #[test]
        fn action_count_pairs_spends_and_outputs_only_when_cross_address_is_permitted(
            orchard_spends in arb_note_count(),
            ironwood_spends in arb_note_count(),
            orchard_change in arb_note_count(),
            ironwood_change in arb_note_count(),
            orchard_value in arb_note_value(),
            ironwood_value in arb_note_value(),
            change_value in arb_note_value(),
        ) {
            let change = std::iter::repeat_n(ShieldedPool::Orchard, orchard_change)
                .chain(std::iter::repeat_n(ShieldedPool::Ironwood, ironwood_change))
                .map(|pool| shielded_change(pool, change_value))
                .collect();
            let step = step_with_notes_and_change(
                orchard_and_ironwood_notes((orchard_spends, orchard_value), (ironwood_spends, ironwood_value)),
                change,
            );

            // `UNPADDED` pads only to the one-action consensus minimum, so for a non-empty
            // bundle its action count is exactly the number of requested actions.
            for version in [BundleVersion::orchard_insecure_v1(), BundleVersion::orchard_v2()] {
                prop_assert_eq!(
                    step.orchard_action_count(BundleType::UNPADDED, version),
                    Ok(orchard_spends.max(orchard_change))
                );
            }
            prop_assert_eq!(
                step.orchard_action_count(BundleType::UNPADDED, BundleVersion::orchard_v3()),
                Ok(orchard_spends + orchard_change)
            );
            prop_assert_eq!(
                step.ironwood_action_count(BundleType::UNPADDED, BundleVersion::ironwood_v3()),
                Ok(ironwood_spends.max(ironwood_change))
            );

            // The bundle type governs padding on top of that count: `DEFAULT` pads a non-empty
            // bundle up to the ZIP 317 two-action floor, and produces no bundle at all when the
            // step requires no actions in that pool.
            let pad = |requested: usize| if requested == 0 { 0 } else { requested.max(2) };
            prop_assert_eq!(
                step.orchard_action_count(BundleType::DEFAULT, BundleVersion::orchard_v3()),
                Ok(pad(orchard_spends + orchard_change))
            );
            prop_assert_eq!(
                step.ironwood_action_count(BundleType::DEFAULT, BundleVersion::ironwood_v3()),
                Ok(pad(ironwood_spends.max(ironwood_change)))
            );
        }

        // The action count a caller obtains for a real target height, resolving the bundle
        // version the way the fee and builder paths do: height -> consensus branch ->
        // `BundleVersion`. This is the scenario the legacy hardcoded `max(spends, outputs)`
        // formula got wrong: at a post-NU6.3 height it understated the Orchard action count
        // whenever a step had both spends and outputs, and so understated the ZIP 317 fee.
        #[test]
        fn orchard_action_count_grows_at_nu6_3_activation_height(
            spends in arb_note_count(),
            change in arb_note_count(),
            note_value in arb_note_value(),
            change_value in arb_note_value(),
            pre_nu6_3 in arb_pre_nu6_3_upgrade(),
            nu6_3_or_later in arb_nu6_3_or_later_upgrade(),
        ) {
            let orchard_step = step_with_notes_and_change(
                orchard_and_ironwood_notes((spends, note_value), (0, 0)),
                std::iter::repeat_n(shielded_change(ShieldedPool::Orchard, change_value), change)
                    .collect(),
            );

            // Pre-NU6.3, each change output shares an action with a spend: max(spends, change).
            prop_assert_eq!(
                orchard_step.orchard_action_count(
                    BundleType::UNPADDED,
                    bundle_version_at(pre_nu6_3, ValuePool::Orchard),
                ),
                Ok(spends.max(change))
            );

            // From NU6.3, the Orchard pool disables cross-address transfers: a change output's
            // corresponding dummy input must be signed with the spending key for the internal
            // IVK the change is sent to, so it cannot share an action with a spend of a note
            // belonging to a different address. Hence spends + change actions.
            prop_assert_eq!(
                orchard_step.orchard_action_count(
                    BundleType::UNPADDED,
                    bundle_version_at(nu6_3_or_later, ValuePool::Orchard),
                ),
                Ok(spends + change)
            );

            // The Ironwood pool retains cross-address transfers, so an equivalent Ironwood step
            // still pairs at a post-NU6.3 height.
            let ironwood_step = step_with_notes_and_change(
                orchard_and_ironwood_notes((0, 0), (spends, note_value)),
                std::iter::repeat_n(shielded_change(ShieldedPool::Ironwood, change_value), change)
                    .collect(),
            );
            prop_assert_eq!(
                ironwood_step.ironwood_action_count(
                    BundleType::UNPADDED,
                    bundle_version_at(nu6_3_or_later, ValuePool::Ironwood),
                ),
                Ok(spends.max(change))
            );
        }

        // A non-empty bundle is charged the greater of the actions it requests and the bundle
        // type's padding floor: padding never reduces the count, and the floor is never
        // undershot. A bundle that requests nothing is not produced at all, so it is charged
        // nothing however high the floor. `DEFAULT` (floor 2) and `UNPADDED` (floor 1) are the
        // floors the wallet itself uses; the whole `u8` range is covered here, including the
        // degenerate zero floor, since the bundle type is the caller's to choose.
        #[test]
        fn action_count_is_never_below_the_bundle_types_padding_floor(
            spends in arb_note_count(),
            change in arb_note_count(),
            note_value in arb_note_value(),
            change_value in arb_note_value(),
            pad_to_minimum in 0u8..=u8::MAX,
        ) {
            let step = step_with_notes_and_change(
                orchard_and_ironwood_notes((spends, note_value), (0, 0)),
                std::iter::repeat_n(shielded_change(ShieldedPool::Orchard, change_value), change)
                    .collect(),
            );
            let bundle_type = BundleType::Transactional {
                bundle_required: false,
                pad_to_minimum: Some(pad_to_minimum),
            };

            // Post-NU6.3, so the requested count is `spends + change`.
            let requested = spends + change;
            let expected = if requested == 0 {
                0
            } else {
                requested.max(usize::from(pad_to_minimum))
            };
            prop_assert_eq!(
                step.orchard_action_count(bundle_type, BundleVersion::orchard_v3()),
                Ok(expected)
            );
        }

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
            let step1 = step_with_notes(orchard_and_ironwood_notes((n_orchard, 10_000), (n_ironwood, 20_000)));
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

            let step2 = step_with_notes(orchard_and_ironwood_notes((m_orchard, 10_000), (m_ironwood, 20_000)));
            let proposal = Proposal::<(), u32> {
                fee_rule: (),
                min_target_height: TargetHeight::from(100u32),
                confirmations_policy: ConfirmationsPolicy::default(),
                proposed_version: None,
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

#[cfg(all(test, feature = "transparent-inputs"))]
mod transparent_tests {
    use std::collections::BTreeMap;

    use ::transparent::{
        address::TransparentAddress,
        bundle::{OutPoint, TxOut},
    };
    use zcash_protocol::value::Zatoshis;
    use zip321::TransactionRequest;

    use super::{ProposalError, ShieldedInputs, Step};
    use crate::{
        fees::{ChangeValue, TransactionBalance},
        wallet::WalletTransparentOutput,
    };

    /// A transparent change output carrying an explicit recipient address (e.g. to return
    /// change to the P2SH address that funded a step's transparent inputs) may only name an
    /// address that actually funds one of that step's transparent inputs. This is a safety
    /// property: proposals may arrive via untrusted deserialization, and change must never be
    /// redirected to an arbitrary address.
    #[test]
    fn transparent_change_recipient_must_fund_step_inputs() {
        let funding_addr = TransparentAddress::ScriptHash([7u8; 20]);
        let other_addr = TransparentAddress::ScriptHash([9u8; 20]);

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

        // Negative case: the change recipient does not match the funding address of any
        // transparent input of the step.
        assert_matches!(
            Step::from_parts(
                &[],
                TransactionRequest::empty(),
                BTreeMap::new(),
                vec![input.clone()],
                None::<ShieldedInputs<u32>>,
                None,
                vec![],
                TransactionBalance::new(
                    vec![ChangeValue::transparent_to_address(
                        Zatoshis::const_from_u64(50_000),
                        other_addr,
                    )],
                    Zatoshis::const_from_u64(10_000),
                )
                .unwrap(),
                false,
                #[cfg(feature = "orchard")]
                false,
            ),
            Err(ProposalError::TransparentChangeRecipientMismatch(a)) if a == other_addr
        );

        // Positive case: the same setup, but the change recipient matches the funding
        // address of the step's transparent input, so construction succeeds.
        assert_matches!(
            Step::from_parts(
                &[],
                TransactionRequest::empty(),
                BTreeMap::new(),
                vec![input],
                None::<ShieldedInputs<u32>>,
                None,
                vec![],
                TransactionBalance::new(
                    vec![ChangeValue::transparent_to_address(
                        Zatoshis::const_from_u64(50_000),
                        funding_addr,
                    )],
                    Zatoshis::const_from_u64(10_000),
                )
                .unwrap(),
                false,
                #[cfg(feature = "orchard")]
                false,
            ),
            Ok(_)
        );
    }
}
