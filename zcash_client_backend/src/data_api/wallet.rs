//! # Functions for creating Zcash transactions that spend funds belonging to the wallet
//!
//!
//! This module contains several different ways of creating Zcash transactions. This module is
//! designed around the idea that a Zcash wallet holds its funds in notes in either the Orchard
//! or Sapling shielded pool. In order to better preserve users' privacy, it does not provide any
//! functionality that allows users to directly spend transparent funds except by sending them to a
//! shielded internal address belonging to their wallet.
//!
//! The important high-level operations provided by this module are [`propose_transfer`],
//! and [`create_proposed_transactions`].
//!
//! [`propose_transfer`] takes a [`TransactionRequest`] object, selects inputs notes and
//! computes the fees required to satisfy that request, and returns a [`Proposal`] object that
//! describes the transaction to be made.
//!
//! [`create_proposed_transactions`] constructs one or more Zcash [`Transaction`]s based upon a
//! provided [`Proposal`], stores them to the wallet database, and returns the [`TxId`] for each
//! constructed transaction to the caller. The caller can then use the
//! [`WalletRead::get_transaction`] method to retrieve the newly constructed transactions. It is
//! the responsibility of the caller to retrieve and serialize the transactions and submit them for
//! inclusion into the Zcash blockchain.
//!
#![cfg_attr(
    feature = "transparent-inputs",
    doc = "
Another important high-level operation provided by this module is [`propose_shielding`], which
takes a set of transparent source addresses, and constructs a [`Proposal`] to send those funds
to a wallet-internal shielded address, as described in [ZIP 316](https://zips.z.cash/zip-0316).

[`propose_shielding`]: crate::data_api::wallet::propose_shielding
"
)]
//! [`TransactionRequest`]: crate::zip321::TransactionRequest
//! [`propose_transfer`]: crate::data_api::wallet::propose_transfer

use nonempty::NonEmpty;
use rand_core::OsRng;
use std::{
    num::NonZeroU32,
    ops::{Add, Sub},
};

use shardtree::error::{QueryError, ShardTreeError};

use super::InputSource;
use crate::{
    data_api::{
        Account, MaxSpendMode, SentTransaction, SentTransactionOutput, WalletCommitmentTrees,
        WalletRead, WalletWrite, error::Error, wallet::input_selection::propose_send_max,
    },
    decrypt_transaction,
    fees::{
        ChangeStrategy, DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy,
    },
    proposal::{Proposal, ProposalError, Step, StepOutputIndex},
    wallet::{Note, OvkPolicy, Recipient},
};
use sapling::{
    note_encryption::{PreparedIncomingViewingKey, try_sapling_note_decryption},
    prover::{OutputProver, SpendProver},
};
use transparent::{address::TransparentAddress, builder::TransparentSigningSet, bundle::OutPoint};
use zcash_address::ZcashAddress;
use zcash_keys::{
    address::Address,
    keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_primitives::transaction::{
    Transaction, TxId,
    builder::{BuildConfig, BuildResult, Builder},
    components::sapling::zip212_enforcement,
    fees::FeeRule,
};
use zcash_protocol::{
    PoolType, ShieldedProtocol,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    value::{BalanceError, Zatoshis},
};
use zip32::Scope;
use zip321::Payment;

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        fees::ChangeValue,
        proposal::StepOutput,
        wallet::{TransparentAddressMetadata, TransparentAddressSource},
    },
    core::convert::Infallible,
    input_selection::ShieldingSelector,
    std::collections::HashMap,
    transparent::bundle::TxOut,
};

#[cfg(feature = "pczt")]
use {
    crate::data_api::error::PcztError,
    bip32::ChildNumber,
    orchard::note_encryption::OrchardDomain,
    pczt::roles::{
        creator::Creator, io_finalizer::IoFinalizer, spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor, updater::Updater,
    },
    sapling::note_encryption::SaplingDomain,
    serde::{Deserialize, Serialize},
    transparent::pczt::Bip32Derivation,
    zcash_note_encryption::try_output_recovery_with_pkd_esk,
    zcash_protocol::consensus::NetworkConstants,
};

pub mod input_selection;
use input_selection::{GreedyInputSelector, InputSelector, InputSelectorError};

#[cfg(feature = "pczt")]
const PROPRIETARY_PROPOSAL_INFO: &str = "zcash_client_backend:proposal_info";
#[cfg(feature = "pczt")]
const PROPRIETARY_OUTPUT_INFO: &str = "zcash_client_backend:output_info";

#[cfg(feature = "pczt")]
fn serialize_target_height<S>(
    target_height: &TargetHeight,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let u: u32 = BlockHeight::from(*target_height).into();
    u.serialize(serializer)
}

#[cfg(feature = "pczt")]
fn deserialize_target_height<'de, D>(deserializer: D) -> Result<TargetHeight, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let u = u32::deserialize(deserializer)?;
    Ok(BlockHeight::from_u32(u).into())
}

/// Information about the proposal from which a PCZT was created.
///
/// Stored under the proprietary field `PROPRIETARY_PROPOSAL_INFO`.
#[cfg(feature = "pczt")]
#[derive(Serialize, Deserialize)]
struct ProposalInfo<AccountId> {
    from_account: AccountId,
    #[serde(
        serialize_with = "serialize_target_height",
        deserialize_with = "deserialize_target_height"
    )]
    target_height: TargetHeight,
}

/// Reduced version of [`Recipient`] stored inside a PCZT.
///
/// Stored under the proprietary field `PROPRIETARY_OUTPUT_INFO`.
#[cfg(feature = "pczt")]
#[derive(Serialize, Deserialize)]
enum PcztRecipient<AccountId> {
    External,
    #[cfg(feature = "transparent-inputs")]
    EphemeralTransparent {
        receiving_account: AccountId,
    },
    InternalAccount {
        receiving_account: AccountId,
    },
}

#[cfg(feature = "pczt")]
impl<AccountId: Copy> PcztRecipient<AccountId> {
    fn from_recipient(recipient: BuildRecipient<AccountId>) -> (Self, Option<ZcashAddress>) {
        match recipient {
            BuildRecipient::External {
                recipient_address, ..
            } => (PcztRecipient::External, Some(recipient_address)),
            #[cfg(feature = "transparent-inputs")]
            BuildRecipient::EphemeralTransparent {
                receiving_account, ..
            } => (
                PcztRecipient::EphemeralTransparent { receiving_account },
                None,
            ),
            BuildRecipient::InternalAccount {
                receiving_account,
                external_address,
            } => (
                PcztRecipient::InternalAccount { receiving_account },
                external_address,
            ),
        }
    }
}

/// Scans a [`Transaction`] for any information that can be decrypted by the accounts in
/// the wallet, and saves it to the wallet.
pub fn decrypt_and_store_transaction<ParamsT, DbT>(
    params: &ParamsT,
    data: &mut DbT,
    tx: &Transaction,
    mined_height: Option<BlockHeight>,
) -> Result<(), DbT::Error>
where
    ParamsT: consensus::Parameters,
    DbT: WalletWrite,
{
    // Fetch the UnifiedFullViewingKeys we are tracking
    let ufvks = data.get_unified_full_viewing_keys()?;

    data.store_decrypted_tx(decrypt_transaction(
        params,
        mined_height.map_or_else(|| data.get_tx_height(tx.txid()), |h| Ok(Some(h)))?,
        data.chain_height()?,
        tx,
        &ufvks,
    ))?;

    Ok(())
}

/// Errors that may be generated in construction of proposals for shielded->shielded or
/// shielded->transparent transfers.
pub type ProposeTransferErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    CommitmentTreeErrT,
    <InputsT as InputSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    <<InputsT as InputSelector>::InputSource as InputSource>::NoteRef,
>;

/// Errors that may be generated in construction of proposals for shielded->shielded or
/// shielded->transparent transactions that transfer the maximum value available within an account
/// and do not produce change outputs.
pub type ProposeSendMaxErrT<DbT, CommitmentTreeErrT, FeeRuleT> = Error<
    <DbT as WalletRead>::Error,
    CommitmentTreeErrT,
    BalanceError,
    <FeeRuleT as FeeRule>::Error,
    <FeeRuleT as FeeRule>::Error,
    <DbT as InputSource>::NoteRef,
>;

/// Errors that may be generated in construction of proposals for transparent->shielded
/// wallet-internal transfers.
#[cfg(feature = "transparent-inputs")]
pub type ProposeShieldingErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    CommitmentTreeErrT,
    <InputsT as ShieldingSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    Infallible,
>;

/// Errors that may be generated in combined creation and execution of transaction proposals.
pub type CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    InputsErrT,
    <FeeRuleT as FeeRule>::Error,
    ChangeErrT,
    N,
>;

/// Errors that may be generated in the execution of proposals that may send shielded inputs.
pub type TransferErrT<DbT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    <InputsT as InputSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    <<InputsT as InputSelector>::InputSource as InputSource>::NoteRef,
>;

/// Errors that may be generated in the execution of shielding proposals.
#[cfg(feature = "transparent-inputs")]
pub type ShieldErrT<DbT, InputsT, ChangeT> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    <InputsT as ShieldingSelector>::Error,
    <<ChangeT as ChangeStrategy>::FeeRule as FeeRule>::Error,
    <ChangeT as ChangeStrategy>::Error,
    Infallible,
>;

/// Errors that may be generated when extracting a transaction from a PCZT.
#[cfg(feature = "pczt")]
pub type ExtractErrT<DbT, N> = Error<
    <DbT as WalletRead>::Error,
    <DbT as WalletCommitmentTrees>::Error,
    Infallible,
    Infallible,
    Infallible,
    N,
>;

/// A wrapper type around [`BlockHeight`] that represents the _next_ chain tip.
///
/// Addition and subtraction are provided by proxying to [`BlockHeight`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetHeight(BlockHeight);

impl TargetHeight {
    /// Subtracts the provided value from this height, returning [`zcash_protocol::consensus::H0`]
    /// if this would result in underflow of the wrapped `u32`.
    pub fn saturating_sub(self, value: u32) -> BlockHeight {
        self.0.saturating_sub(value)
    }
}

impl From<BlockHeight> for TargetHeight {
    fn from(value: BlockHeight) -> Self {
        TargetHeight(value)
    }
}

impl From<TargetHeight> for BlockHeight {
    fn from(value: TargetHeight) -> Self {
        value.0
    }
}

impl From<TargetHeight> for u32 {
    fn from(value: TargetHeight) -> Self {
        u32::from(value.0)
    }
}

impl From<u32> for TargetHeight {
    fn from(value: u32) -> Self {
        TargetHeight(BlockHeight::from_u32(value))
    }
}

impl<I> Add<I> for TargetHeight
where
    BlockHeight: Add<I>,
{
    type Output = <BlockHeight as Add<I>>::Output;

    fn add(self, rhs: I) -> Self::Output {
        self.0 + rhs
    }
}

impl<I> Sub<I> for TargetHeight
where
    BlockHeight: Sub<I>,
{
    type Output = <BlockHeight as Sub<I>>::Output;

    fn sub(self, rhs: I) -> Self::Output {
        self.0 - rhs
    }
}

/// A description of the policy that is used to determine what notes are available for spending,
/// based upon the number of confirmations (the number of blocks in the chain since and including
/// the block in which a note was produced.)
///
/// See [`ZIP 315`] for details including the definitions of "trusted" and "untrusted" notes.
///
/// [`ZIP 315`]: https://zips.z.cash/zip-0315
#[derive(Clone, Copy, Debug)]
pub struct ConfirmationsPolicy {
    trusted: NonZeroU32,
    untrusted: NonZeroU32,
    #[cfg(feature = "transparent-inputs")]
    allow_zero_conf_shielding: bool,
}

/// The default confirmations policy according to [`ZIP 315`].
///
/// * Require 3 confirmations for "trusted" transaction outputs (outputs produced by the wallet)
/// * Require 10 confirmations for "untrusted" outputs (those sent to the wallet by external/third
///   parties)
/// * Allow zero-conf shielding of transparent UTXOs irrespective of their origin, but treat the
///   resulting shielding transaction's outputs as though the original transparent UTXOs had
///   instead been received as untrusted shielded outputs.
///
/// [`ZIP 315`]: https://zips.z.cash/zip-0315
impl Default for ConfirmationsPolicy {
    fn default() -> Self {
        ConfirmationsPolicy {
            // 3
            trusted: NonZeroU32::MIN.saturating_add(2),
            // 10
            untrusted: NonZeroU32::MIN.saturating_add(9),
            #[cfg(feature = "transparent-inputs")]
            allow_zero_conf_shielding: true,
        }
    }
}

impl ConfirmationsPolicy {
    /// A policy to use the minimum number of confirmations possible: 1 confirmation for shielded
    /// notes irrespective of origin, and 0 confirmations for spends of transparent UTXOs in
    /// wallet-internal shielding transactions.
    pub const MIN: Self = ConfirmationsPolicy {
        trusted: NonZeroU32::MIN,
        untrusted: NonZeroU32::MIN,
        #[cfg(feature = "transparent-inputs")]
        allow_zero_conf_shielding: true,
    };

    /// Constructs a new `ConfirmationsPolicy` with `trusted` and `untrusted` fields set to the
    /// provided values.
    ///
    /// The number of confirmations required for trusted notes must be less than or equal to the
    /// number of confirmations required for untrusted notes; this returns `Err(())` if this
    /// invariant is violated.
    ///
    /// WARNING: This should only be used with great care to avoid problems of transaction
    /// distinguishability; prefer [`ConfirmationsPolicy::default()`] instead.
    pub fn new(
        trusted: NonZeroU32,
        untrusted: NonZeroU32,
        #[cfg(feature = "transparent-inputs")] allow_zero_conf_shielding: bool,
    ) -> Result<Self, ()> {
        if trusted > untrusted {
            Err(())
        } else {
            Ok(Self {
                trusted,
                untrusted,
                #[cfg(feature = "transparent-inputs")]
                allow_zero_conf_shielding,
            })
        }
    }

    /// Constructs a new `ConfirmationsPolicy` with `trusted` and `untrusted` fields both
    /// set to `min_confirmations`.
    ///
    /// WARNING: This should only be used with great care to avoid problems of transaction
    /// distinguishability; prefer [`ConfirmationsPolicy::default()`] instead.
    pub fn new_symmetrical(
        min_confirmations: NonZeroU32,
        #[cfg(feature = "transparent-inputs")] allow_zero_conf_shielding: bool,
    ) -> Self {
        Self {
            trusted: min_confirmations,
            untrusted: min_confirmations,
            #[cfg(feature = "transparent-inputs")]
            allow_zero_conf_shielding,
        }
    }

    /// Constructs a new `ConfirmationsPolicy` with `trusted` and `untrusted` fields set to the
    /// provided values, which must both be nonzero. The number of trusted confirmations required
    /// must be less than or equal to the number of untrusted confirmations required.
    ///
    /// # Panics
    /// Panics if `trusted > untrusted` or either argument value is zero.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn new_unchecked(
        trusted: u32,
        untrusted: u32,
        #[cfg(feature = "transparent-inputs")] allow_zero_conf_shielding: bool,
    ) -> Self {
        Self::new(
            NonZeroU32::new(trusted).expect("trusted must be nonzero"),
            NonZeroU32::new(untrusted).expect("untrusted must be nonzero"),
            #[cfg(feature = "transparent-inputs")]
            allow_zero_conf_shielding,
        )
        .expect("trusted must be <= untrusted")
    }

    /// Constructs a new `ConfirmationsPolicy` with `trusted` and `untrusted` fields both
    /// set to `min_confirmations`.
    ///
    /// # Panics
    /// Panics if `min_confirmations == 0`
    #[cfg(any(test, feature = "test-dependencies"))]
    pub fn new_symmetrical_unchecked(
        min_confirmations: u32,
        #[cfg(feature = "transparent-inputs")] allow_zero_conf_shielding: bool,
    ) -> Self {
        Self::new_symmetrical(
            NonZeroU32::new(min_confirmations).expect("min_confirmations must be nonzero"),
            #[cfg(feature = "transparent-inputs")]
            allow_zero_conf_shielding,
        )
    }

    /// Returns the number of confirmations required before trusted notes may be spent.
    ///
    /// See [`ZIP 315`] for details.
    ///
    /// [`ZIP 315`]: https://zips.z.cash/zip-0315#trusted-and-untrusted-txos
    pub fn trusted(&self) -> NonZeroU32 {
        self.trusted
    }

    /// Returns the number of confirmations required before untrusted notes may be spent.
    ///
    /// See [`ZIP 315`] for details.
    ///
    /// [`ZIP 315`]: https://zips.z.cash/zip-0315#trusted-and-untrusted-txos
    pub fn untrusted(&self) -> NonZeroU32 {
        self.untrusted
    }

    /// Returns whether or not transparent inputs may be spent with zero confirmations in shielding
    /// transactions.
    #[cfg(feature = "transparent-inputs")]
    pub fn allow_zero_conf_shielding(&self) -> bool {
        self.allow_zero_conf_shielding
    }

    /// Returns the number of confirmations until a transaction output is considered spendable,
    /// given information about the output and the inputs to the transaction that produced it.
    ///
    /// # Parameters
    /// - `target_height`: The minimum height at which the output will be potentially spent.
    /// - `pool_type`: The Zcash pool that the output was received into.
    /// - `receiving_key_scope`: The ZIP 32 [`Scope`] of the key that received the output,
    ///   or `None` if the scope is unknown or corresponds to the ephemeral transparent
    ///   key scope.
    /// - `mined_height`: The block height at which the transaction that produced the output was
    ///   mined, if any.
    /// - `tx_trusted`: A boolean flag indicating whether the received transaction has been
    ///   explicitly marked as trusted by the user.
    /// - `max_shielding_input_height`: For outputs that are the result of wallet-internal
    ///   shielding transactions, the maximum height at which any transparent input to that
    ///   transaction was received.
    /// - `tx_shielding_inputs_trusted`: For outputs that are the result of wallet-internal
    ///   shielding transactions, a flag indicating whether all transparent inputs to that
    ///   transaction have been explicitly marked as trusted by the user.
    #[allow(clippy::too_many_arguments)]
    pub fn confirmations_until_spendable(
        &self,
        target_height: TargetHeight,
        pool_type: PoolType,
        receiving_key_scope: Option<Scope>,
        mined_height: Option<BlockHeight>,
        tx_trusted: bool,
        max_shielding_input_height: Option<BlockHeight>,
        tx_shielding_inputs_trusted: bool,
    ) -> u32 {
        // Trusted outputs of transactions mined at heights greater than `trusted_height` will not
        // be treated as spendable.
        let trusted_height = target_height.saturating_sub(u32::from(self.trusted));
        // Untrusted outputs of transactions mined at heights greater than `untrusted_height` will
        // not be treated as spendable.
        let untrusted_height = target_height.saturating_sub(u32::from(self.untrusted));

        // Calculate the possible options for confirmations.
        // - If the output's tx is unmined, we are constantly waiting for the maximum number of
        //   confirmations.
        // - If the output's tx is mined, the required number of confirmations decreases to a floor
        //   of zero.
        let confs_for_trusted =
            mined_height.map_or(u32::from(self.trusted), |h| h - trusted_height);
        let confs_for_untrusted =
            mined_height.map_or(u32::from(self.untrusted), |h| h - untrusted_height);
        match pool_type {
            PoolType::Transparent => {
                #[cfg(feature = "transparent-inputs")]
                let zc_shielding = self.allow_zero_conf_shielding;
                #[cfg(not(feature = "transparent-inputs"))]
                let zc_shielding = false;

                if zc_shielding {
                    0
                } else if tx_trusted || receiving_key_scope == Some(Scope::Internal) {
                    confs_for_trusted
                } else {
                    confs_for_untrusted
                }
            }
            PoolType::Shielded(_) => {
                if tx_trusted {
                    confs_for_trusted
                } else if receiving_key_scope == Some(Scope::Internal) {
                    // If the note was the output of a shielding transaction, we use the mined
                    // height of the transparent source funds & their trust status instead of the
                    // height at which the shielding transaction was mined.
                    if let Some(h) = max_shielding_input_height {
                        if tx_shielding_inputs_trusted {
                            h - trusted_height
                        } else {
                            h - untrusted_height
                        }
                    } else {
                        confs_for_trusted
                    }
                } else {
                    confs_for_untrusted
                }
            }
        }
    }
}

/// Select transaction inputs, compute fees, and construct a proposal for a transaction or series
/// of transactions that can then be authorized and made ready for submission to the network with
/// [`create_proposed_transactions`].
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_transfer<DbT, ParamsT, InputsT, ChangeT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_from_account: <DbT as InputSource>::AccountId,
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    request: zip321::TransactionRequest,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<
    Proposal<ChangeT::FeeRule, <DbT as InputSource>::NoteRef>,
    ProposeTransferErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT>,
>
where
    DbT: WalletRead + InputSource<Error = <DbT as WalletRead>::Error>,
    <DbT as InputSource>::NoteRef: Copy + Eq + Ord,
    ParamsT: consensus::Parameters + Clone,
    InputsT: InputSelector<InputSource = DbT>,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
{
    // Using the trusted confirmations results in an anchor_height that will
    // include the maximum number of notes being selected, and we can filter
    // later based on the input source (whether it's trusted or not) and the
    // number of confirmations
    let maybe_intial_heights = wallet_db
        .get_target_and_anchor_heights(confirmations_policy.trusted)
        .map_err(InputSelectorError::DataSource)?;
    let (target_height, anchor_height) =
        maybe_intial_heights.ok_or_else(|| InputSelectorError::SyncRequired)?;

    let proposal = input_selector.propose_transaction(
        params,
        wallet_db,
        target_height,
        anchor_height,
        confirmations_policy,
        spend_from_account,
        request,
        change_strategy,
    )?;
    Ok(proposal)
}

/// Proposes making a payment to the specified address from the given account.
///
/// Returns the proposal, which may then be executed using [`create_proposed_transactions`].
/// Depending upon the recipient address, more than one transaction may be constructed
/// in the execution of the returned proposal.
///
/// This method uses the basic [`GreedyInputSelector`] for input selection.
///
/// Parameters:
/// * `wallet_db`: A read/write reference to the wallet database.
/// * `params`: Consensus parameters.
/// * `fee_rule`: The fee rule to use in creating the transaction.
/// * `spend_from_account`: The unified account that controls the funds that will be spent
///   in the resulting transaction. This procedure will return an error if the
///   account ID does not correspond to an account known to the wallet.
/// * `confirmations_policy`: The minimum number of confirmations that a previously
///   received note must have in the blockchain in order to be considered for being
///   spent. A value of 10 confirmations is recommended and 0-conf transactions are
///   not supported.
/// * `to`: The address to which `amount` will be paid.
/// * `amount`: The amount to send.
/// * `memo`: A memo to be included in the output to the recipient.
/// * `change_memo`: A memo to be included in any change output that is created.
/// * `fallback_change_pool`: The shielded pool to which change should be sent if
///   automatic change pool determination fails.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_standard_transfer_to_address<DbT, ParamsT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    fee_rule: StandardFeeRule,
    spend_from_account: <DbT as InputSource>::AccountId,
    confirmations_policy: ConfirmationsPolicy,
    to: &Address,
    amount: Zatoshis,
    memo: Option<MemoBytes>,
    change_memo: Option<MemoBytes>,
    fallback_change_pool: ShieldedProtocol,
) -> Result<
    Proposal<StandardFeeRule, DbT::NoteRef>,
    ProposeTransferErrT<
        DbT,
        CommitmentTreeErrT,
        GreedyInputSelector<DbT>,
        SingleOutputChangeStrategy<DbT>,
    >,
>
where
    ParamsT: consensus::Parameters + Clone,
    DbT: InputSource,
    DbT: WalletRead<Error = <DbT as InputSource>::Error, AccountId = <DbT as InputSource>::AccountId>,
    DbT::NoteRef: Copy + Eq + Ord,
{
    let request = zip321::TransactionRequest::new(vec![
        Payment::new(
            to.to_zcash_address(params),
            Some(amount),
            memo,
            None,
            None,
            vec![],
        )
        .ok_or(Error::MemoForbidden)?,
    ])
    .expect(
        "It should not be possible for this to violate ZIP 321 request construction invariants.",
    );

    let input_selector = GreedyInputSelector::<DbT>::new();
    let change_strategy = SingleOutputChangeStrategy::<DbT>::new(
        fee_rule,
        change_memo,
        fallback_change_pool,
        DustOutputPolicy::default(),
    );

    propose_transfer(
        wallet_db,
        params,
        spend_from_account,
        &input_selector,
        &change_strategy,
        request,
        confirmations_policy,
    )
}

/// Select transaction inputs, compute fees, and construct a proposal for a transaction or series
/// of transactions that would spend all available funds from the given `spend_pool`s that can then
/// be authorized and made ready for submission to the network with [`create_proposed_transactions`].
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_send_max_transfer<DbT, ParamsT, FeeRuleT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_from_account: <DbT as InputSource>::AccountId,
    spend_pools: &[ShieldedProtocol],
    fee_rule: &FeeRuleT,
    recipient: ZcashAddress,
    memo: Option<MemoBytes>,
    mode: MaxSpendMode,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<
    Proposal<FeeRuleT, <DbT as InputSource>::NoteRef>,
    ProposeSendMaxErrT<DbT, CommitmentTreeErrT, FeeRuleT>,
>
where
    DbT: WalletRead + InputSource<Error = <DbT as WalletRead>::Error>,
    <DbT as InputSource>::NoteRef: Copy + Eq + Ord,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule + Clone,
{
    let (target_height, anchor_height) = wallet_db
        .get_target_and_anchor_heights(confirmations_policy.trusted())
        .map_err(|e| Error::from(InputSelectorError::DataSource(e)))?
        .ok_or_else(|| Error::from(InputSelectorError::SyncRequired))?;

    if memo.is_some() && !recipient.can_receive_memo() {
        return Err(Error::MemoForbidden);
    }

    let proposal = propose_send_max(
        params,
        wallet_db,
        fee_rule,
        spend_from_account,
        spend_pools,
        target_height,
        anchor_height,
        mode,
        confirmations_policy,
        recipient,
        memo,
    )?;

    Ok(proposal)
}

/// Constructs a proposal to shield all of the funds belonging to the provided set of
/// addresses.
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn propose_shielding<DbT, ParamsT, InputsT, ChangeT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    shielding_threshold: Zatoshis,
    from_addrs: &[TransparentAddress],
    to_account: <DbT as InputSource>::AccountId,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<
    Proposal<ChangeT::FeeRule, Infallible>,
    ProposeShieldingErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT>,
>
where
    ParamsT: consensus::Parameters,
    DbT: WalletRead + InputSource<Error = <DbT as WalletRead>::Error>,
    InputsT: ShieldingSelector<InputSource = DbT>,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
{
    let chain_tip_height = wallet_db
        .chain_height()
        .map_err(|e| Error::from(InputSelectorError::DataSource(e)))?
        .ok_or_else(|| Error::from(InputSelectorError::SyncRequired))?;

    input_selector
        .propose_shielding(
            params,
            wallet_db,
            change_strategy,
            shielding_threshold,
            from_addrs,
            to_account,
            (chain_tip_height + 1).into(),
            confirmations_policy,
        )
        .map_err(Error::from)
}

struct StepResult<AccountId> {
    build_result: BuildResult,
    outputs: Vec<SentTransactionOutput<AccountId>>,
    fee_amount: Zatoshis,
    #[cfg(feature = "transparent-inputs")]
    utxos_spent: Vec<OutPoint>,
}

/// A set of spending keys for an account, for use in execution of transaction proposals.
///
/// This consists of a [`UnifiedSpendingKey`], plus (if the `transparent-key-import` feature is
/// enabled) a set of standalone transparent spending keys corresponding to inputs being spent in a
/// transaction under construction.
pub struct SpendingKeys {
    usk: UnifiedSpendingKey,
    #[cfg(feature = "transparent-key-import")]
    standalone_transparent_keys: HashMap<TransparentAddress, secp256k1::SecretKey>,
}

impl SpendingKeys {
    /// Constructs a new [`SpendingKeys`] value from its constituent parts.
    pub fn new(
        usk: UnifiedSpendingKey,
        #[cfg(feature = "transparent-key-import")] standalone_transparent_keys: HashMap<
            TransparentAddress,
            secp256k1::SecretKey,
        >,
    ) -> Self {
        Self {
            usk,
            #[cfg(feature = "transparent-key-import")]
            standalone_transparent_keys,
        }
    }

    /// Constructs a new [`SpendingKeys`] value from a [`UnifiedSpendingKey`],
    /// without standalone spending keys.
    pub fn from_unified_spending_key(usk: UnifiedSpendingKey) -> Self {
        Self {
            usk,
            #[cfg(feature = "transparent-key-import")]
            standalone_transparent_keys: HashMap::new(),
        }
    }
}

/// Construct, prove, and sign a transaction or series of transactions using the inputs supplied by
/// the given proposal, and persist it to the wallet database.
///
/// Returns the database identifier for each newly constructed transaction, or an error if
/// an error occurs in transaction construction, proving, or signing.
///
/// When evaluating multi-step proposals, only transparent outputs of any given step may be spent
/// in later steps; attempting to spend a shielded note (including change) output by an earlier
/// step is not supported, because the ultimate positions of those notes in the global note
/// commitment tree cannot be known until the transaction that produces those notes is mined,
/// and therefore the required spend proofs for such notes cannot be constructed.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn create_proposed_transactions<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    spending_keys: &SpendingKeys,
    ovk_policy: OvkPolicy,
    proposal: &Proposal<FeeRuleT, N>,
) -> Result<NonEmpty<TxId>, CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
{
    // The set of transparent `StepOutput`s available and unused from prior steps.
    // When a transparent `StepOutput` is created, it is added to the map. When it
    // is consumed, it is removed from the map.
    #[cfg(feature = "transparent-inputs")]
    let mut unused_transparent_outputs = HashMap::new();

    let account_id = wallet_db
        .get_account_for_ufvk(&spending_keys.usk.to_unified_full_viewing_key())
        .map_err(Error::DataSource)?
        .ok_or(Error::KeyNotRecognized)?
        .id();

    let mut step_results = Vec::with_capacity(proposal.steps().len());
    for step in proposal.steps() {
        let step_result: StepResult<_> = create_proposed_transaction(
            wallet_db,
            params,
            spend_prover,
            output_prover,
            spending_keys,
            account_id,
            ovk_policy.clone(),
            proposal.fee_rule(),
            proposal.min_target_height(),
            &step_results,
            step,
            #[cfg(feature = "transparent-inputs")]
            &mut unused_transparent_outputs,
        )?;
        step_results.push((step, step_result));
    }

    // Ephemeral outputs must be referenced exactly once.
    #[cfg(feature = "transparent-inputs")]
    for so in unused_transparent_outputs.into_keys() {
        if let StepOutputIndex::Change(i) = so.output_index() {
            // references have already been checked
            if step_results[so.step_index()].0.balance().proposed_change()[i].is_ephemeral() {
                return Err(ProposalError::EphemeralOutputLeftUnspent(so).into());
            }
        }
    }

    // TODO: This should be provided by a `Clock`
    let created = time::OffsetDateTime::now_utc();

    // Store the transactions only after creating all of them. This avoids undesired
    // retransmissions in case a transaction is stored and the creation of a subsequent
    // transaction fails.
    let mut transactions = Vec::with_capacity(step_results.len());
    let mut txids = Vec::with_capacity(step_results.len());
    #[allow(unused_variables)]
    for (_, step_result) in step_results.iter() {
        let tx = step_result.build_result.transaction();
        transactions.push(SentTransaction::new(
            tx,
            created,
            proposal.min_target_height(),
            account_id,
            &step_result.outputs,
            step_result.fee_amount,
            #[cfg(feature = "transparent-inputs")]
            &step_result.utxos_spent,
        ));
        txids.push(tx.txid());
    }

    wallet_db
        .store_transactions_to_be_sent(&transactions)
        .map_err(Error::DataSource)?;

    Ok(NonEmpty::from_vec(txids).expect("proposal.steps is NonEmpty"))
}

#[derive(Debug, Clone)]
enum BuildRecipient<AccountId> {
    External {
        recipient_address: ZcashAddress,
        output_pool: PoolType,
    },
    #[cfg(feature = "transparent-inputs")]
    EphemeralTransparent {
        receiving_account: AccountId,
        ephemeral_address: TransparentAddress,
    },
    InternalAccount {
        receiving_account: AccountId,
        external_address: Option<ZcashAddress>,
    },
}

impl<AccountId> BuildRecipient<AccountId> {
    fn into_recipient_with_note(self, note: impl FnOnce() -> Note) -> Recipient<AccountId> {
        match self {
            BuildRecipient::External {
                recipient_address,
                output_pool,
            } => Recipient::External {
                recipient_address,
                output_pool,
            },
            #[cfg(feature = "transparent-inputs")]
            BuildRecipient::EphemeralTransparent { .. } => unreachable!(),
            BuildRecipient::InternalAccount {
                receiving_account,
                external_address,
            } => Recipient::InternalAccount {
                receiving_account,
                external_address,
                note: Box::new(note()),
            },
        }
    }

    fn into_recipient_with_outpoint(
        self,
        #[cfg(feature = "transparent-inputs")] outpoint: OutPoint,
    ) -> Recipient<AccountId> {
        match self {
            BuildRecipient::External {
                recipient_address,
                output_pool,
            } => Recipient::External {
                recipient_address,
                output_pool,
            },
            #[cfg(feature = "transparent-inputs")]
            BuildRecipient::EphemeralTransparent {
                receiving_account,
                ephemeral_address,
            } => Recipient::EphemeralTransparent {
                receiving_account,
                ephemeral_address,
                outpoint,
            },
            BuildRecipient::InternalAccount { .. } => unreachable!(),
        }
    }
}

#[allow(clippy::type_complexity)]
struct BuildState<'a, P, AccountId> {
    #[cfg(feature = "transparent-inputs")]
    step_index: usize,
    builder: Builder<'a, P, ()>,
    #[cfg(feature = "transparent-inputs")]
    transparent_input_addresses: HashMap<TransparentAddress, TransparentAddressMetadata>,
    #[cfg(feature = "orchard")]
    orchard_output_meta: Vec<(BuildRecipient<AccountId>, Zatoshis, Option<MemoBytes>)>,
    sapling_output_meta: Vec<(BuildRecipient<AccountId>, Zatoshis, Option<MemoBytes>)>,
    transparent_output_meta: Vec<(
        BuildRecipient<AccountId>,
        TransparentAddress,
        Zatoshis,
        StepOutputIndex,
    )>,
    #[cfg(feature = "transparent-inputs")]
    utxos_spent: Vec<OutPoint>,
}

// `unused_transparent_outputs` maps `StepOutput`s for transparent outputs
// that have not been consumed so far, to the corresponding pair of
// `TransparentAddress` and `Outpoint`.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn build_proposed_transaction<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    ufvk: &UnifiedFullViewingKey,
    account_id: <DbT as WalletRead>::AccountId,
    ovk_policy: OvkPolicy,
    min_target_height: TargetHeight,
    prior_step_results: &[(&Step<N>, StepResult<<DbT as WalletRead>::AccountId>)],
    proposal_step: &Step<N>,
    #[cfg(feature = "transparent-inputs")] unused_transparent_outputs: &mut HashMap<
        StepOutput,
        (TransparentAddress, OutPoint),
    >,
) -> Result<
    BuildState<'static, ParamsT, DbT::AccountId>,
    CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>,
>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
{
    #[cfg(feature = "transparent-inputs")]
    let step_index = prior_step_results.len();

    // We only support spending transparent payments or transparent ephemeral outputs from a
    // prior step (when "transparent-inputs" is enabled).
    #[allow(clippy::never_loop)]
    for input_ref in proposal_step.prior_step_inputs() {
        let (prior_step, _) = prior_step_results
            .get(input_ref.step_index())
            .ok_or(ProposalError::ReferenceError(*input_ref))?;

        #[allow(unused_variables)]
        let output_pool = match input_ref.output_index() {
            StepOutputIndex::Payment(i) => prior_step.payment_pools().get(&i).cloned(),
            StepOutputIndex::Change(i) => match prior_step.balance().proposed_change().get(i) {
                Some(change) if !change.is_ephemeral() => {
                    return Err(ProposalError::SpendsChange(*input_ref).into());
                }
                other => other.map(|change| change.output_pool()),
            },
        }
        .ok_or(ProposalError::ReferenceError(*input_ref))?;

        // Return an error on trying to spend a prior output that is not supported.
        #[cfg(feature = "transparent-inputs")]
        if output_pool != PoolType::TRANSPARENT {
            return Err(Error::ProposalNotSupported);
        }
        #[cfg(not(feature = "transparent-inputs"))]
        return Err(Error::ProposalNotSupported);
    }

    let (sapling_anchor, sapling_inputs) = if proposal_step
        .involves(PoolType::Shielded(ShieldedProtocol::Sapling))
    {
        proposal_step.shielded_inputs().map_or_else(
            || Ok((Some(sapling::Anchor::empty_tree()), vec![])),
            |inputs| {
                wallet_db.with_sapling_tree_mut::<_, _, Error<_, _, _, _, _, _>>(|sapling_tree| {
                    let anchor = sapling_tree
                        .root_at_checkpoint_id(&inputs.anchor_height())?
                        .ok_or(ProposalError::AnchorNotFound(inputs.anchor_height()))?
                        .into();

                    let sapling_inputs = inputs
                        .notes()
                        .iter()
                        .filter_map(|selected| match selected.note() {
                            Note::Sapling(note) => sapling_tree
                                .witness_at_checkpoint_id_caching(
                                    selected.note_commitment_tree_position(),
                                    &inputs.anchor_height(),
                                )
                                .and_then(|witness| {
                                    witness
                                        .ok_or(ShardTreeError::Query(QueryError::CheckpointPruned))
                                })
                                .map(|merkle_path| {
                                    Some((selected.spending_key_scope(), note, merkle_path))
                                })
                                .map_err(Error::from)
                                .transpose(),
                            #[cfg(feature = "orchard")]
                            Note::Orchard(_) => None,
                        })
                        .collect::<Result<Vec<_>, Error<_, _, _, _, _, _>>>()?;

                    Ok((Some(anchor), sapling_inputs))
                })
            },
        )?
    } else {
        (None, vec![])
    };

    #[cfg(feature = "orchard")]
    let (orchard_anchor, orchard_inputs) = if proposal_step
        .involves(PoolType::Shielded(ShieldedProtocol::Orchard))
    {
        proposal_step.shielded_inputs().map_or_else(
            || Ok((Some(orchard::Anchor::empty_tree()), vec![])),
            |inputs| {
                wallet_db.with_orchard_tree_mut::<_, _, Error<_, _, _, _, _, _>>(|orchard_tree| {
                    let anchor = orchard_tree
                        .root_at_checkpoint_id(&inputs.anchor_height())?
                        .ok_or(ProposalError::AnchorNotFound(inputs.anchor_height()))?
                        .into();

                    let orchard_inputs = inputs
                        .notes()
                        .iter()
                        .filter_map(|selected| match selected.note() {
                            #[cfg(feature = "orchard")]
                            Note::Orchard(note) => orchard_tree
                                .witness_at_checkpoint_id_caching(
                                    selected.note_commitment_tree_position(),
                                    &inputs.anchor_height(),
                                )
                                .and_then(|witness| {
                                    witness
                                        .ok_or(ShardTreeError::Query(QueryError::CheckpointPruned))
                                })
                                .map(|merkle_path| Some((note, merkle_path)))
                                .map_err(Error::from)
                                .transpose(),
                            Note::Sapling(_) => None,
                        })
                        .collect::<Result<Vec<_>, Error<_, _, _, _, _, _>>>()?;

                    Ok((Some(anchor), orchard_inputs))
                })
            },
        )?
    } else {
        (None, vec![])
    };
    #[cfg(not(feature = "orchard"))]
    let orchard_anchor = None;

    // Create the transaction. The type of the proposal ensures that there
    // are no possible transparent inputs, so we ignore those here.
    let mut builder = Builder::new(
        params.clone(),
        BlockHeight::from(min_target_height),
        BuildConfig::Standard {
            sapling_anchor,
            orchard_anchor,
        },
    );

    #[cfg(all(feature = "transparent-inputs", not(feature = "orchard")))]
    let has_shielded_inputs = !sapling_inputs.is_empty();
    #[cfg(all(feature = "transparent-inputs", feature = "orchard"))]
    let has_shielded_inputs = !(sapling_inputs.is_empty() && orchard_inputs.is_empty());

    let input_sources = NonEmpty::from_vec({
        let mut sources = vec![];
        if !sapling_inputs.is_empty() {
            sources.push(PoolType::SAPLING);
        }
        #[cfg(feature = "orchard")]
        if !orchard_inputs.is_empty() {
            sources.push(PoolType::ORCHARD);
        }
        // We assume here that prior step outputs cannot be shielded, due to checks above (and the
        // fact that the witness required to spend such outputs could not be computed.)
        #[cfg(feature = "transparent-inputs")]
        if !(proposal_step.transparent_inputs().is_empty()
            && proposal_step.prior_step_inputs().is_empty())
        {
            sources.push(PoolType::Transparent);
        }
        sources
    })
    .ok_or(Error::ProposalNotSupported)?;

    for (_sapling_key_scope, sapling_note, merkle_path) in sapling_inputs.into_iter() {
        let key = match _sapling_key_scope {
            Scope::External => ufvk.sapling().map(|k| k.fvk().clone()),
            Scope::Internal => ufvk.sapling().map(|k| k.to_internal_fvk()),
        };

        builder.add_sapling_spend(
            key.ok_or(Error::KeyNotAvailable(PoolType::SAPLING))?,
            sapling_note.clone(),
            merkle_path,
        )?;
    }

    #[cfg(feature = "orchard")]
    for (orchard_note, merkle_path) in orchard_inputs.into_iter() {
        builder.add_orchard_spend(
            ufvk.orchard()
                .cloned()
                .ok_or(Error::KeyNotAvailable(PoolType::ORCHARD))?,
            *orchard_note,
            merkle_path.into(),
        )?;
    }

    #[cfg(feature = "transparent-inputs")]
    let mut transparent_input_addresses =
        HashMap::<TransparentAddress, TransparentAddressMetadata>::new();

    #[cfg(feature = "transparent-inputs")]
    let mut metadata_from_address = |addr: &TransparentAddress| -> Result<
        TransparentAddressMetadata,
        CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>,
    > {
        match transparent_input_addresses.get(addr) {
            Some(result) => Ok(result.clone()),
            None => {
                // `wallet_db.get_transparent_address_metadata` includes reserved ephemeral
                // addresses in its lookup. We don't need to include these in order to be
                // able to construct ZIP 320 transactions, because in that case the ephemeral
                // output is represented via a "change" reference to a previous step. However,
                // we do need them in order to create a transaction from a proposal that
                // explicitly spends an output from an ephemeral address (only for outputs
                // already detected by this wallet instance).

                let result = wallet_db
                    .get_transparent_address_metadata(account_id, addr)
                    .map_err(InputSelectorError::DataSource)?
                    .ok_or(Error::AddressNotRecognized(*addr))?;

                transparent_input_addresses.insert(*addr, result.clone());
                Ok(result)
            }
        }
    };

    #[cfg(feature = "transparent-inputs")]
    let utxos_spent = {
        let mut utxos_spent: Vec<OutPoint> = vec![];
        let mut add_transparent_p2pkh_input =
            |builder: &mut Builder<_, _>,
             utxos_spent: &mut Vec<_>,
             recipient_address: &TransparentAddress,
             outpoint: OutPoint,
             txout: TxOut|
             -> Result<(), CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>> {
                let pubkey = match metadata_from_address(recipient_address)?.source() {
                    TransparentAddressSource::Derived {
                        scope,
                        address_index,
                    } => ufvk
                        .transparent()
                        .ok_or(Error::KeyNotAvailable(PoolType::Transparent))?
                        .derive_address_pubkey(*scope, *address_index)
                        .expect("spending key derivation should not fail"),
                    #[cfg(feature = "transparent-key-import")]
                    TransparentAddressSource::Standalone(pubkey) => *pubkey,
                };

                utxos_spent.push(outpoint.clone());
                builder.add_transparent_p2pkh_input(pubkey, outpoint, txout)?;

                Ok(())
            };

        for utxo in proposal_step.transparent_inputs() {
            add_transparent_p2pkh_input(
                &mut builder,
                &mut utxos_spent,
                utxo.recipient_address(),
                utxo.outpoint().clone(),
                utxo.txout().clone(),
            )?;
        }
        for input_ref in proposal_step.prior_step_inputs() {
            // A referenced transparent step output must exist and be referenced *at most* once.
            // (Exactly once in the case of ephemeral outputs.)
            let (address, outpoint) = unused_transparent_outputs
                .remove(input_ref)
                .ok_or(Error::Proposal(ProposalError::ReferenceError(*input_ref)))?;

            let txout = &prior_step_results[input_ref.step_index()]
                .1
                .build_result
                .transaction()
                .transparent_bundle()
                .ok_or(ProposalError::ReferenceError(*input_ref))?
                .vout[outpoint.n() as usize];

            add_transparent_p2pkh_input(
                &mut builder,
                &mut utxos_spent,
                &address,
                outpoint,
                txout.clone(),
            )?;
        }
        utxos_spent
    };

    let (external_ovk, internal_ovk) = match ovk_policy {
        OvkPolicy::Sender => (
            Some(
                ufvk.select_ovk(zip32::Scope::External, &input_sources)
                    .ok_or(Error::KeyNotAvailable(input_sources.head))?,
            ),
            None,
        ),
        OvkPolicy::Custom {
            external_ovk,
            internal_ovk,
        } => (Some(external_ovk), internal_ovk),
        OvkPolicy::Discard => (None, None),
    };

    #[cfg(feature = "orchard")]
    let mut orchard_output_meta: Vec<(BuildRecipient<_>, Zatoshis, Option<MemoBytes>)> = vec![];
    let mut sapling_output_meta: Vec<(BuildRecipient<_>, Zatoshis, Option<MemoBytes>)> = vec![];
    let mut transparent_output_meta: Vec<(
        BuildRecipient<_>,
        TransparentAddress,
        Zatoshis,
        StepOutputIndex,
    )> = vec![];

    for (&payment_index, output_pool) in proposal_step.payment_pools() {
        let payment = proposal_step
            .transaction_request()
            .payments()
            .get(&payment_index)
            .expect(
                "The mapping between payment index and payment is checked in step construction",
            );
        let payment_amount = payment
            .amount()
            .ok_or(ProposalError::PaymentAmountMissing(payment_index))?;
        let recipient_address = payment.recipient_address();

        let add_sapling_output =
            |builder: &mut Builder<_, _>,
             sapling_output_meta: &mut Vec<_>,
             to: sapling::PaymentAddress|
             -> Result<(), CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>> {
                let memo = payment.memo().map_or_else(MemoBytes::empty, |m| m.clone());
                builder.add_sapling_output(
                    external_ovk.map(|k| k.into()),
                    to,
                    payment_amount,
                    memo.clone(),
                )?;
                sapling_output_meta.push((
                    BuildRecipient::External {
                        recipient_address: recipient_address.clone(),
                        output_pool: PoolType::SAPLING,
                    },
                    payment_amount,
                    Some(memo),
                ));
                Ok(())
            };

        #[cfg(feature = "orchard")]
        let add_orchard_output =
            |builder: &mut Builder<_, _>,
             orchard_output_meta: &mut Vec<_>,
             to: orchard::Address|
             -> Result<(), CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>> {
                let memo = payment.memo().map_or_else(MemoBytes::empty, |m| m.clone());
                builder.add_orchard_output(
                    external_ovk.map(|k| k.into()),
                    to,
                    payment_amount,
                    memo.clone(),
                )?;
                orchard_output_meta.push((
                    BuildRecipient::External {
                        recipient_address: recipient_address.clone(),
                        output_pool: PoolType::ORCHARD,
                    },
                    payment_amount,
                    Some(memo),
                ));
                Ok(())
            };

        let add_transparent_output =
            |builder: &mut Builder<_, _>,
             transparent_output_meta: &mut Vec<_>,
             to: TransparentAddress|
             -> Result<(), CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>> {
                if payment.memo().is_some() {
                    return Err(Error::MemoForbidden);
                }
                builder.add_transparent_output(&to, payment_amount)?;
                transparent_output_meta.push((
                    BuildRecipient::External {
                        recipient_address: recipient_address.clone(),
                        output_pool: PoolType::TRANSPARENT,
                    },
                    to,
                    payment_amount,
                    StepOutputIndex::Payment(payment_index),
                ));
                Ok(())
            };

        match recipient_address
            .clone()
            .convert_if_network(params.network_type())?
        {
            Address::Unified(ua) => match output_pool {
                #[cfg(not(feature = "orchard"))]
                PoolType::Shielded(ShieldedProtocol::Orchard) => {
                    return Err(Error::ProposalNotSupported);
                }
                #[cfg(feature = "orchard")]
                PoolType::Shielded(ShieldedProtocol::Orchard) => {
                    let to = *ua.orchard().expect("The mapping between payment pool and receiver is checked in step construction");
                    add_orchard_output(&mut builder, &mut orchard_output_meta, to)?;
                }
                PoolType::Shielded(ShieldedProtocol::Sapling) => {
                    let to = *ua.sapling().expect("The mapping between payment pool and receiver is checked in step construction");
                    add_sapling_output(&mut builder, &mut sapling_output_meta, to)?;
                }
                PoolType::Transparent => {
                    let to = *ua.transparent().expect("The mapping between payment pool and receiver is checked in step construction");
                    add_transparent_output(&mut builder, &mut transparent_output_meta, to)?;
                }
            },
            Address::Sapling(to) => {
                add_sapling_output(&mut builder, &mut sapling_output_meta, to)?;
            }
            Address::Transparent(to) => {
                add_transparent_output(&mut builder, &mut transparent_output_meta, to)?;
            }
            #[cfg(not(feature = "transparent-inputs"))]
            Address::Tex(_) => {
                return Err(Error::ProposalNotSupported);
            }
            #[cfg(feature = "transparent-inputs")]
            Address::Tex(data) => {
                if has_shielded_inputs {
                    return Err(ProposalError::PaysTexFromShielded.into());
                }
                let to = TransparentAddress::PublicKeyHash(data);
                add_transparent_output(&mut builder, &mut transparent_output_meta, to)?;
            }
        }
    }

    for change_value in proposal_step.balance().proposed_change() {
        let memo = change_value
            .memo()
            .map_or_else(MemoBytes::empty, |m| m.clone());
        let output_pool = change_value.output_pool();
        match output_pool {
            PoolType::Shielded(ShieldedProtocol::Sapling) => {
                builder.add_sapling_output(
                    internal_ovk.map(|k| k.into()),
                    ufvk.sapling()
                        .ok_or(Error::KeyNotAvailable(PoolType::SAPLING))?
                        .change_address()
                        .1,
                    change_value.value(),
                    memo.clone(),
                )?;
                sapling_output_meta.push((
                    BuildRecipient::InternalAccount {
                        receiving_account: account_id,
                        external_address: None,
                    },
                    change_value.value(),
                    Some(memo),
                ))
            }
            PoolType::Shielded(ShieldedProtocol::Orchard) => {
                #[cfg(not(feature = "orchard"))]
                return Err(Error::UnsupportedChangeType(output_pool));

                #[cfg(feature = "orchard")]
                {
                    builder.add_orchard_output(
                        internal_ovk.map(|k| k.into()),
                        ufvk.orchard()
                            .ok_or(Error::KeyNotAvailable(PoolType::ORCHARD))?
                            .address_at(0u32, orchard::keys::Scope::Internal),
                        change_value.value(),
                        memo.clone(),
                    )?;
                    orchard_output_meta.push((
                        BuildRecipient::InternalAccount {
                            receiving_account: account_id,
                            external_address: None,
                        },
                        change_value.value(),
                        Some(memo),
                    ))
                }
            }
            PoolType::Transparent => {
                #[cfg(not(feature = "transparent-inputs"))]
                return Err(Error::UnsupportedChangeType(output_pool));
            }
        }
    }

    // This reserves the ephemeral addresses even if transaction construction fails.
    // It is not worth the complexity of being able to unreserve them, because there
    // are few failure modes after this point that would allow us to do so.
    #[cfg(feature = "transparent-inputs")]
    {
        let ephemeral_outputs: Vec<(usize, &ChangeValue)> = proposal_step
            .balance()
            .proposed_change()
            .iter()
            .enumerate()
            .filter(|(_, change_value)| {
                change_value.is_ephemeral() && change_value.output_pool() == PoolType::Transparent
            })
            .collect();

        let addresses_and_metadata = wallet_db
            .reserve_next_n_ephemeral_addresses(account_id, ephemeral_outputs.len())
            .map_err(Error::DataSource)?;
        assert_eq!(addresses_and_metadata.len(), ephemeral_outputs.len());

        // We don't need the TransparentAddressSource here; we can look it up from the data source later.
        for ((change_index, change_value), (ephemeral_address, _)) in
            ephemeral_outputs.iter().zip(addresses_and_metadata)
        {
            // This output is ephemeral; we will report an error in `create_proposed_transactions`
            // if a later step does not consume it.
            builder.add_transparent_output(&ephemeral_address, change_value.value())?;
            transparent_output_meta.push((
                BuildRecipient::EphemeralTransparent {
                    receiving_account: account_id,
                    ephemeral_address,
                },
                ephemeral_address,
                change_value.value(),
                StepOutputIndex::Change(*change_index),
            ))
        }
    }

    Ok(BuildState {
        #[cfg(feature = "transparent-inputs")]
        step_index,
        builder,
        #[cfg(feature = "transparent-inputs")]
        transparent_input_addresses,
        #[cfg(feature = "orchard")]
        orchard_output_meta,
        sapling_output_meta,
        transparent_output_meta,
        #[cfg(feature = "transparent-inputs")]
        utxos_spent,
    })
}

// `unused_transparent_outputs` maps `StepOutput`s for transparent outputs
// that have not been consumed so far, to the corresponding pair of
// `TransparentAddress` and `Outpoint`.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn create_proposed_transaction<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    spending_keys: &SpendingKeys,
    account_id: <DbT as WalletRead>::AccountId,
    ovk_policy: OvkPolicy,
    fee_rule: &FeeRuleT,
    min_target_height: TargetHeight,
    prior_step_results: &[(&Step<N>, StepResult<<DbT as WalletRead>::AccountId>)],
    proposal_step: &Step<N>,
    #[cfg(feature = "transparent-inputs")] unused_transparent_outputs: &mut HashMap<
        StepOutput,
        (TransparentAddress, OutPoint),
    >,
) -> Result<
    StepResult<<DbT as WalletRead>::AccountId>,
    CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>,
>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
{
    let build_state = build_proposed_transaction::<_, _, _, FeeRuleT, _, _>(
        wallet_db,
        params,
        &spending_keys.usk.to_unified_full_viewing_key(),
        account_id,
        ovk_policy,
        min_target_height,
        prior_step_results,
        proposal_step,
        #[cfg(feature = "transparent-inputs")]
        unused_transparent_outputs,
    )?;

    // Build the transaction with the specified fee rule
    #[cfg_attr(not(feature = "transparent-inputs"), allow(unused_mut))]
    let mut transparent_signing_set = TransparentSigningSet::new();
    #[cfg(feature = "transparent-inputs")]
    for (_address, address_metadata) in build_state.transparent_input_addresses {
        transparent_signing_set.add_key(match address_metadata.source() {
            TransparentAddressSource::Derived {
                scope,
                address_index,
            } => spending_keys
                .usk
                .transparent()
                .derive_secret_key(*scope, *address_index)
                .expect("spending key derivation should not fail"),
            #[cfg(feature = "transparent-key-import")]
            TransparentAddressSource::Standalone(_) => *spending_keys
                .standalone_transparent_keys
                .get(&_address)
                .ok_or(Error::AddressNotRecognized(_address))?,
        });
    }
    let sapling_extsks = &[
        spending_keys.usk.sapling().clone(),
        spending_keys.usk.sapling().derive_internal(),
    ];
    #[cfg(feature = "orchard")]
    let orchard_saks = &[spending_keys.usk.orchard().into()];
    #[cfg(not(feature = "orchard"))]
    let orchard_saks = &[];
    let build_result = build_state.builder.build(
        &transparent_signing_set,
        sapling_extsks,
        orchard_saks,
        OsRng,
        spend_prover,
        output_prover,
        fee_rule,
    )?;

    #[cfg(feature = "orchard")]
    let orchard_fvk: orchard::keys::FullViewingKey = spending_keys.usk.orchard().into();
    #[cfg(feature = "orchard")]
    let orchard_internal_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::Internal);
    #[cfg(feature = "orchard")]
    let orchard_outputs = build_state.orchard_output_meta.into_iter().enumerate().map(
        |(i, (recipient, value, memo))| {
            let output_index = build_result
                .orchard_meta()
                .output_action_index(i)
                .expect("An action should exist in the transaction for each Orchard output.");

            let recipient = recipient.into_recipient_with_note(|| {
                build_result
                    .transaction()
                    .orchard_bundle()
                    .and_then(|bundle| {
                        bundle
                            .decrypt_output_with_key(output_index, &orchard_internal_ivk)
                            .map(|(note, _, _)| Note::Orchard(note))
                    })
                    .expect("Wallet-internal outputs must be decryptable with the wallet's IVK")
            });

            SentTransactionOutput::from_parts(output_index, recipient, value, memo)
        },
    );

    let sapling_dfvk = spending_keys
        .usk
        .sapling()
        .to_diversifiable_full_viewing_key();
    let sapling_internal_ivk =
        PreparedIncomingViewingKey::new(&sapling_dfvk.to_ivk(Scope::Internal));
    let sapling_outputs = build_state.sapling_output_meta.into_iter().enumerate().map(
        |(i, (recipient, value, memo))| {
            let output_index = build_result
                .sapling_meta()
                .output_index(i)
                .expect("An output should exist in the transaction for each Sapling payment.");

            let recipient = recipient.into_recipient_with_note(|| {
                build_result
                    .transaction()
                    .sapling_bundle()
                    .and_then(|bundle| {
                        try_sapling_note_decryption(
                            &sapling_internal_ivk,
                            &bundle.shielded_outputs()[output_index],
                            zip212_enforcement(params, min_target_height.into()),
                        )
                        .map(|(note, _, _)| Note::Sapling(note))
                    })
                    .expect("Wallet-internal outputs must be decryptable with the wallet's IVK")
            });

            SentTransactionOutput::from_parts(output_index, recipient, value, memo)
        },
    );

    let txid: [u8; 32] = build_result.transaction().txid().into();
    assert_eq!(
        build_state.transparent_output_meta.len(),
        build_result
            .transaction()
            .transparent_bundle()
            .map_or(0, |b| b.vout.len()),
    );

    #[allow(unused_variables)]
    let transparent_outputs = build_state
        .transparent_output_meta
        .into_iter()
        .enumerate()
        .map(|(n, (recipient, address, value, step_output_index))| {
            // This assumes that transparent outputs are pushed onto `transparent_output_meta`
            // with the same indices they have in the transaction's transparent outputs.
            // We do not reorder transparent outputs; there is no reason to do so because it
            // would not usefully improve privacy.
            let outpoint = OutPoint::new(txid, n as u32);

            let recipient = recipient.into_recipient_with_outpoint(
                #[cfg(feature = "transparent-inputs")]
                outpoint.clone(),
            );

            #[cfg(feature = "transparent-inputs")]
            unused_transparent_outputs.insert(
                StepOutput::new(build_state.step_index, step_output_index),
                (address, outpoint),
            );
            SentTransactionOutput::from_parts(n, recipient, value, None)
        });

    let mut outputs: Vec<SentTransactionOutput<_>> = vec![];
    #[cfg(feature = "orchard")]
    outputs.extend(orchard_outputs);
    outputs.extend(sapling_outputs);
    outputs.extend(transparent_outputs);

    Ok(StepResult {
        build_result,
        outputs,
        fee_amount: proposal_step.balance().fee_required(),
        #[cfg(feature = "transparent-inputs")]
        utxos_spent: build_state.utxos_spent,
    })
}

/// Constructs a transaction using the inputs supplied by the given proposal.
///
/// Only single-step proposals are currently supported.
///
/// Returns a partially-created Zcash transaction (PCZT) that is ready to be authorized.
/// You can use the following roles for this:
/// - [`pczt::roles::prover::Prover`]
/// - [`pczt::roles::signer::Signer`] (if you have local access to the spend authorizing
///   keys)
/// - [`pczt::roles::combiner::Combiner`] (if you create proofs and apply signatures in
///   parallel)
///
/// Once the PCZT fully authorized, call [`extract_and_store_transaction_from_pczt`] to
/// finish transaction creation.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
#[cfg(feature = "pczt")]
pub fn create_pczt_from_proposal<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    account_id: <DbT as WalletRead>::AccountId,
    ovk_policy: OvkPolicy,
    proposal: &Proposal<FeeRuleT, N>,
) -> Result<pczt::Pczt, CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
    DbT::AccountId: serde::Serialize,
{
    use std::collections::HashSet;

    let account = wallet_db
        .get_account(account_id)
        .map_err(Error::DataSource)?
        .ok_or(Error::AccountIdNotRecognized)?;
    let ufvk = account.ufvk().ok_or(Error::AccountCannotSpend)?;
    let account_derivation = account.source().key_derivation();

    // For now we only support turning single-step proposals into PCZTs.
    if proposal.steps().len() > 1 {
        return Err(Error::ProposalNotSupported);
    }
    let fee_rule = proposal.fee_rule();
    let min_target_height = proposal.min_target_height();
    let prior_step_results = &[];
    let proposal_step = proposal.steps().first();
    let unused_transparent_outputs = &mut HashMap::new();

    let build_state = build_proposed_transaction::<_, _, _, FeeRuleT, _, _>(
        wallet_db,
        params,
        ufvk,
        account_id,
        ovk_policy,
        min_target_height,
        prior_step_results,
        proposal_step,
        #[cfg(feature = "transparent-inputs")]
        unused_transparent_outputs,
    )?;

    // Build the transaction with the specified fee rule
    let build_result = build_state.builder.build_for_pczt(OsRng, fee_rule)?;

    let created = Creator::build_from_parts(build_result.pczt_parts).ok_or(PcztError::Build)?;

    let io_finalized = IoFinalizer::new(created).finalize_io()?;

    #[cfg(feature = "orchard")]
    let orchard_outputs = build_state
        .orchard_output_meta
        .into_iter()
        .enumerate()
        .map(|(i, (recipient, _, _))| {
            let output_index = build_result
                .orchard_meta
                .output_action_index(i)
                .expect("An action should exist in the transaction for each Orchard output.");

            (output_index, PcztRecipient::from_recipient(recipient))
        })
        .collect::<HashMap<_, _>>();

    #[cfg(feature = "orchard")]
    let orchard_spends = (0..)
        .map(|i| build_result.orchard_meta.spend_action_index(i))
        .take_while(|item| item.is_some())
        .flatten()
        .collect::<HashSet<_>>();

    let sapling_outputs = build_state
        .sapling_output_meta
        .into_iter()
        .enumerate()
        .map(|(i, (recipient, _, _))| {
            let output_index = build_result
                .sapling_meta
                .output_index(i)
                .expect("An output should exist in the transaction for each Sapling output.");

            (output_index, PcztRecipient::from_recipient(recipient))
        })
        .collect::<HashMap<_, _>>();

    let pczt = Updater::new(io_finalized)
        .update_global_with(|mut updater| {
            updater.set_proprietary(
                PROPRIETARY_PROPOSAL_INFO.into(),
                postcard::to_allocvec(&ProposalInfo::<DbT::AccountId> {
                    from_account: account_id,
                    target_height: proposal.min_target_height(),
                })
                .expect("postcard encoding of PCZT proposal metadata should not fail"),
            )
        })
        .update_orchard_with(|mut updater| {
            for index in 0..updater.bundle().actions().len() {
                updater.update_action_with(index, |mut action_updater| {
                    // If the account has a known derivation, add the Orchard key path to the PCZT.
                    if let Some(derivation) = account_derivation {
                        // orchard_spends will only contain action indices for the real spends, and
                        // not the dummy inputs
                        if orchard_spends.contains(&index) {
                            // All spent notes are from the same account.
                            action_updater.set_spend_zip32_derivation(
                                orchard::pczt::Zip32Derivation::parse(
                                    derivation.seed_fingerprint().to_bytes(),
                                    vec![
                                        zip32::ChildIndex::hardened(32).index(),
                                        zip32::ChildIndex::hardened(
                                            params.network_type().coin_type(),
                                        )
                                        .index(),
                                        zip32::ChildIndex::hardened(u32::from(
                                            derivation.account_index(),
                                        ))
                                        .index(),
                                    ],
                                )
                                .expect("valid"),
                            );
                        }
                    }

                    if let Some((pczt_recipient, external_address)) = orchard_outputs.get(&index) {
                        if let Some(user_address) = external_address {
                            action_updater.set_output_user_address(user_address.encode());
                        }
                        action_updater.set_output_proprietary(
                            PROPRIETARY_OUTPUT_INFO.into(),
                            postcard::to_allocvec(pczt_recipient).expect(
                                "postcard encoding of PCZT recipient metadata should not fail",
                            ),
                        );
                    }

                    Ok(())
                })?;
            }
            Ok(())
        })?
        .update_sapling_with(|mut updater| {
            // If the account has a known derivation, add the Sapling key path to the PCZT.
            if let Some(derivation) = account_derivation {
                let non_dummy_spends = updater
                    .bundle()
                    .spends()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, spend)| {
                        // Dummy spends will already have a proof generation key.
                        spend.proof_generation_key().is_none().then_some(index)
                    })
                    .collect::<Vec<_>>();

                for index in non_dummy_spends {
                    updater.update_spend_with(index, |mut spend_updater| {
                        // All non-dummy spent notes are from the same account.
                        spend_updater.set_zip32_derivation(
                            sapling::pczt::Zip32Derivation::parse(
                                derivation.seed_fingerprint().to_bytes(),
                                vec![
                                    zip32::ChildIndex::hardened(32).index(),
                                    zip32::ChildIndex::hardened(params.network_type().coin_type())
                                        .index(),
                                    zip32::ChildIndex::hardened(u32::from(
                                        derivation.account_index(),
                                    ))
                                    .index(),
                                ],
                            )
                            .expect("valid"),
                        );
                        Ok(())
                    })?;
                }
            }

            for index in 0..updater.bundle().outputs().len() {
                if let Some((pczt_recipient, external_address)) = sapling_outputs.get(&index) {
                    updater.update_output_with(index, |mut output_updater| {
                        if let Some(user_address) = external_address {
                            output_updater.set_user_address(user_address.encode());
                        }
                        output_updater.set_proprietary(
                            PROPRIETARY_OUTPUT_INFO.into(),
                            postcard::to_allocvec(pczt_recipient).expect(
                                "postcard encoding of PCZT recipient metadata should not fail",
                            ),
                        );
                        Ok(())
                    })?;
                }
            }

            Ok(())
        })?
        .update_transparent_with(|mut updater| {
            // If the account has a known derivation, add the transparent key paths to the PCZT.
            if let Some(derivation) = account_derivation {
                // Match address metadata to the inputs that spend from those addresses.
                let inputs_to_update = updater
                    .bundle()
                    .inputs()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, input)| {
                        build_state
                            .transparent_input_addresses
                            .get(
                                &TransparentAddress::from_script_from_chain(input.script_pubkey())
                                    .expect("we created this with a supported transparent address"),
                            )
                            .and_then(|address_metadata| match address_metadata.source() {
                                TransparentAddressSource::Derived {
                                    scope,
                                    address_index,
                                } => Some((index, *scope, *address_index)),
                                #[cfg(feature = "transparent-key-import")]
                                TransparentAddressSource::Standalone(_) => None,
                            })
                    })
                    .collect::<Vec<_>>();

                for (index, scope, address_index) in inputs_to_update {
                    updater.update_input_with(index, |mut input_updater| {
                        let pubkey = ufvk
                            .transparent()
                            .expect("we derived this successfully in build_proposed_transaction")
                            .derive_address_pubkey(scope, address_index)
                            .expect("spending key derivation should not fail");

                        input_updater.set_bip32_derivation(
                            pubkey.serialize(),
                            Bip32Derivation::parse(
                                derivation.seed_fingerprint().to_bytes(),
                                vec![
                                    // Transparent uses BIP 44 derivation.
                                    44 | ChildNumber::HARDENED_FLAG,
                                    params.network_type().coin_type() | ChildNumber::HARDENED_FLAG,
                                    u32::from(derivation.account_index())
                                        | ChildNumber::HARDENED_FLAG,
                                    ChildNumber::from(scope).into(),
                                    ChildNumber::from(address_index).into(),
                                ],
                            )
                            .expect("valid"),
                        );
                        Ok(())
                    })?;
                }
            }

            assert_eq!(
                build_state.transparent_output_meta.len(),
                updater.bundle().outputs().len(),
            );
            for (index, (recipient, _, _, _)) in
                build_state.transparent_output_meta.into_iter().enumerate()
            {
                updater.update_output_with(index, |mut output_updater| {
                    let (pczt_recipient, external_address) =
                        PcztRecipient::from_recipient(recipient);
                    if let Some(user_address) = external_address {
                        output_updater.set_user_address(user_address.encode());
                    }
                    output_updater.set_proprietary(
                        PROPRIETARY_OUTPUT_INFO.into(),
                        postcard::to_allocvec(&pczt_recipient)
                            .expect("postcard encoding of pczt recipient metadata should not fail"),
                    );
                    Ok(())
                })?;
            }

            Ok(())
        })?
        .finish();

    Ok(pczt)
}

/// Finalizes the given PCZT, and persists the transaction to the wallet database.
///
/// The PCZT should have been created via [`create_pczt_from_proposal`], which adds
/// metadata necessary for the wallet backend.
///
/// Returns the transaction ID for the resulting transaction.
///
/// - `sapling_vk` is optional to allow the caller to check whether a PCZT has Sapling
///   with [`pczt::roles::prover::Prover::requires_sapling_proofs`], and avoid downloading
///   the Sapling parameters if they are not needed. If `sapling_vk` is `None`, and the
///   PCZT has a Sapling bundle, this function will return an error.
/// - `orchard_vk` is optional to allow the caller to control where the Orchard verifying
///   key is generated or cached. If `orchard_vk` is `None`, and the PCZT has an Orchard
///   bundle, an Orchard verifying key will be generated on the fly.
#[cfg(feature = "pczt")]
pub fn extract_and_store_transaction_from_pczt<DbT, N>(
    wallet_db: &mut DbT,
    pczt: pczt::Pczt,
    sapling_vk: Option<(
        &sapling::circuit::SpendVerifyingKey,
        &sapling::circuit::OutputVerifyingKey,
    )>,
    #[cfg(feature = "orchard")] orchard_vk: Option<&orchard::circuit::VerifyingKey>,
) -> Result<TxId, ExtractErrT<DbT, N>>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    DbT::AccountId: serde::de::DeserializeOwned,
{
    use std::collections::BTreeMap;
    use zcash_note_encryption::{Domain, ENC_CIPHERTEXT_SIZE, ShieldedOutput};

    let finalized = SpendFinalizer::new(pczt).finalize_spends()?;

    let proposal_info = finalized
        .global()
        .proprietary()
        .get(PROPRIETARY_PROPOSAL_INFO)
        .ok_or_else(|| PcztError::Invalid("PCZT missing proprietary proposal info field".into()))
        .and_then(|v| {
            postcard::from_bytes::<ProposalInfo<DbT::AccountId>>(v).map_err(|e| {
                PcztError::Invalid(format!(
                    "Postcard decoding of proprietary proposal info failed: {e}"
                ))
            })
        })?;

    let orchard_output_info = finalized
        .orchard()
        .actions()
        .iter()
        .map(|act| {
            let note = || {
                let recipient =
                    act.output().recipient().as_ref().and_then(|b| {
                        ::orchard::Address::from_raw_address_bytes(b).into_option()
                    })?;
                let value = act
                    .output()
                    .value()
                    .map(orchard::value::NoteValue::from_raw)?;
                let rho = orchard::note::Rho::from_bytes(act.spend().nullifier()).into_option()?;
                let rseed = act.output().rseed().as_ref().and_then(|rseed| {
                    orchard::note::RandomSeed::from_bytes(*rseed, &rho).into_option()
                })?;

                orchard::Note::from_parts(recipient, value, rho, rseed).into_option()
            };

            let external_address = act
                .output()
                .user_address()
                .as_deref()
                .map(ZcashAddress::try_from_encoded)
                .transpose()
                .map_err(|e| PcztError::Invalid(format!("Invalid user_address: {e}")))?;

            let pczt_recipient = act
                .output()
                .proprietary()
                .get(PROPRIETARY_OUTPUT_INFO)
                .map(|v| postcard::from_bytes::<PcztRecipient<DbT::AccountId>>(v))
                .transpose()
                .map_err(|e: postcard::Error| {
                    PcztError::Invalid(format!(
                        "Postcard decoding of proprietary output info failed: {e}"
                    ))
                })?
                .map(|pczt_recipient| (pczt_recipient, external_address));

            // If the pczt recipient is not present, this is a dummy note; if the note is not
            // present, then the PCZT has been pruned to make this output unrecoverable and so we
            // also ignore it.
            Ok(pczt_recipient.zip(note()))
        })
        .collect::<Result<Vec<_>, PcztError>>()?;

    let sapling_output_info = finalized
        .sapling()
        .outputs()
        .iter()
        .map(|out| {
            let note = || {
                let recipient = out
                    .recipient()
                    .as_ref()
                    .and_then(::sapling::PaymentAddress::from_bytes)?;
                let value = out.value().map(::sapling::value::NoteValue::from_raw)?;
                let rseed = out
                    .rseed()
                    .as_ref()
                    .cloned()
                    .map(::sapling::note::Rseed::AfterZip212)?;

                Some(::sapling::Note::from_parts(recipient, value, rseed))
            };

            let external_address = out
                .user_address()
                .as_deref()
                .map(ZcashAddress::try_from_encoded)
                .transpose()
                .map_err(|e| PcztError::Invalid(format!("Invalid user_address: {e}")))?;

            let pczt_recipient = out
                .proprietary()
                .get(PROPRIETARY_OUTPUT_INFO)
                .map(|v| postcard::from_bytes::<PcztRecipient<DbT::AccountId>>(v))
                .transpose()
                .map_err(|e: postcard::Error| {
                    PcztError::Invalid(format!(
                        "Postcard decoding of proprietary output info failed: {e}"
                    ))
                })?
                .map(|pczt_recipient| (pczt_recipient, external_address));

            // If the pczt recipient is not present, this is a dummy note; if the note is not
            // present, then the PCZT has been pruned to make this output unrecoverable and so we
            // also ignore it.
            Ok(pczt_recipient.zip(note()))
        })
        .collect::<Result<Vec<_>, PcztError>>()?;

    let transparent_output_info = finalized
        .transparent()
        .outputs()
        .iter()
        .map(|out| {
            let external_address = out
                .user_address()
                .as_deref()
                .map(ZcashAddress::try_from_encoded)
                .transpose()
                .map_err(|e| PcztError::Invalid(format!("Invalid user_address: {e}")))?;

            let pczt_recipient = out
                .proprietary()
                .get(PROPRIETARY_OUTPUT_INFO)
                .map(|v| postcard::from_bytes::<PcztRecipient<DbT::AccountId>>(v))
                .transpose()
                .map_err(|e: postcard::Error| {
                    PcztError::Invalid(format!(
                        "Postcard decoding of proprietary output info failed: {e}"
                    ))
                })?
                .map(|pczt_recipient| (pczt_recipient, external_address));

            Ok(pczt_recipient)
        })
        .collect::<Result<Vec<_>, PcztError>>()?;

    let utxos_map = finalized
        .transparent()
        .inputs()
        .iter()
        .map(|input| {
            Zatoshis::from_u64(*input.value()).map(|value| {
                (
                    OutPoint::new(*input.prevout_txid(), *input.prevout_index()),
                    value,
                )
            })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    let mut tx_extractor = TransactionExtractor::new(finalized);
    if let Some((spend_vk, output_vk)) = sapling_vk {
        tx_extractor = tx_extractor.with_sapling(spend_vk, output_vk);
    }
    if let Some(orchard_vk) = orchard_vk {
        tx_extractor = tx_extractor.with_orchard(orchard_vk);
    }
    let transaction = tx_extractor.extract()?;
    let txid = transaction.txid();

    #[allow(clippy::too_many_arguments)]
    fn to_sent_transaction_output<
        AccountId: Copy,
        D: Domain,
        O: ShieldedOutput<D, { ENC_CIPHERTEXT_SIZE }>,
        DbT: WalletRead + WalletCommitmentTrees,
        N,
    >(
        domain: D,
        note: D::Note,
        output: &O,
        output_pool: ShieldedProtocol,
        output_index: usize,
        pczt_recipient: PcztRecipient<AccountId>,
        external_address: Option<ZcashAddress>,
        note_value: impl Fn(&D::Note) -> u64,
        memo_bytes: impl Fn(&D::Memo) -> &[u8; 512],
        wallet_note: impl Fn(D::Note) -> Note,
    ) -> Result<SentTransactionOutput<AccountId>, ExtractErrT<DbT, N>> {
        let pk_d = D::get_pk_d(&note);
        let esk = D::derive_esk(&note).expect("notes are post-ZIP 212");
        let memo = try_output_recovery_with_pkd_esk(&domain, pk_d, esk, output).map(|(_, _, m)| {
            MemoBytes::from_bytes(memo_bytes(&m)).expect("Memo is the correct length.")
        });

        let note_value = Zatoshis::try_from(note_value(&note))?;
        let recipient = match (pczt_recipient, external_address) {
            (PcztRecipient::External, Some(addr)) => Ok(Recipient::External {
                recipient_address: addr,
                output_pool: PoolType::Shielded(output_pool),
            }),
            (PcztRecipient::External, None) => Err(PcztError::Invalid(
                "external recipient needs to have its user_address field set".into(),
            )),
            #[cfg(feature = "transparent-inputs")]
            (PcztRecipient::EphemeralTransparent { .. }, _) => Err(PcztError::Invalid(
                "shielded output cannot be EphemeralTransparent".into(),
            )),
            (PcztRecipient::InternalAccount { receiving_account }, external_address) => {
                Ok(Recipient::InternalAccount {
                    receiving_account,
                    external_address,
                    note: Box::new(wallet_note(note)),
                })
            }
        }?;

        Ok(SentTransactionOutput::from_parts(
            output_index,
            recipient,
            note_value,
            memo,
        ))
    }

    #[cfg(feature = "orchard")]
    let orchard_outputs = transaction
        .orchard_bundle()
        .map(|bundle| {
            assert_eq!(bundle.actions().len(), orchard_output_info.len());
            bundle
                .actions()
                .iter()
                .zip(orchard_output_info)
                .enumerate()
                .filter_map(|(output_index, (action, output_info))| {
                    output_info.map(|((pczt_recipient, external_address), note)| {
                        let domain = OrchardDomain::for_action(action);
                        to_sent_transaction_output::<_, _, _, DbT, _>(
                            domain,
                            note,
                            action,
                            ShieldedProtocol::Orchard,
                            output_index,
                            pczt_recipient,
                            external_address,
                            |note| note.value().inner(),
                            |memo| memo,
                            Note::Orchard,
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let sapling_outputs = transaction
        .sapling_bundle()
        .map(|bundle| {
            assert_eq!(bundle.shielded_outputs().len(), sapling_output_info.len());
            bundle
                .shielded_outputs()
                .iter()
                .zip(sapling_output_info)
                .enumerate()
                .filter_map(|(output_index, (action, output_info))| {
                    output_info.map(|((pczt_recipient, external_address), note)| {
                        let domain =
                            SaplingDomain::new(sapling::note_encryption::Zip212Enforcement::On);
                        to_sent_transaction_output::<_, _, _, DbT, _>(
                            domain,
                            note,
                            action,
                            ShieldedProtocol::Sapling,
                            output_index,
                            pczt_recipient,
                            external_address,
                            |note| note.value().inner(),
                            |memo| memo,
                            Note::Sapling,
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    #[allow(unused_variables)]
    let transparent_outputs = transaction
        .transparent_bundle()
        .map(|bundle| {
            assert_eq!(bundle.vout.len(), transparent_output_info.len());
            bundle
                .vout
                .iter()
                .zip(transparent_output_info)
                .enumerate()
                .filter_map(|(output_index, (output, output_info))| {
                    output_info.map(|(pczt_recipient, external_address)| {
                        // This assumes that transparent outputs are pushed onto `transparent_output_meta`
                        // with the same indices they have in the transaction's transparent outputs.
                        // We do not reorder transparent outputs; there is no reason to do so because it
                        // would not usefully improve privacy.
                        let outpoint = OutPoint::new(txid.into(), output_index as u32);

                        let recipient = match (pczt_recipient, external_address) {
                            (PcztRecipient::External, Some(addr)) => {
                                Ok(Recipient::External {
                                    recipient_address: addr,
                                    output_pool: PoolType::Transparent,
                                })
                            }
                            (PcztRecipient::External, None) => Err(PcztError::Invalid(
                                "external recipient needs to have its user_address field set".into(),
                            )),
                            #[cfg(feature = "transparent-inputs")]
                            (PcztRecipient::EphemeralTransparent { receiving_account }, _) => output
                                .recipient_address()
                                .ok_or(PcztError::Invalid(
                                    "Ephemeral outputs cannot have a non-standard script_pubkey"
                                        .into(),
                                ))
                                .map(|ephemeral_address| Recipient::EphemeralTransparent {
                                    receiving_account,
                                    ephemeral_address,
                                    outpoint,
                                }),
                            (
                                PcztRecipient::InternalAccount {
                                    receiving_account,
                                },
                                _,
                            ) => Err(PcztError::Invalid(
                                "Transparent output cannot be InternalAccount".into(),
                            )),
                        }?;

                        Ok(SentTransactionOutput::from_parts(
                            output_index,
                            recipient,
                            output.value(),
                            None,
                        ))
                    })
                })
                .collect::<Result<Vec<_>, ExtractErrT<DbT, _>>>()
        })
        .transpose()?;

    let mut outputs: Vec<SentTransactionOutput<_>> = vec![];
    #[cfg(feature = "orchard")]
    outputs.extend(orchard_outputs.into_iter().flatten());
    outputs.extend(sapling_outputs.into_iter().flatten());
    outputs.extend(transparent_outputs.into_iter().flatten());

    let fee_amount = transaction
        .fee_paid(|outpoint| Ok::<_, BalanceError>(utxos_map.get(outpoint).copied()))?
        // We should never obtain a `None` result because we constructed the UTXOs map and the
        // transaction from the same PCZT.
        .expect("input map was constructed correctly");

    // We don't need the spent UTXOs to be in transaction order.
    let utxos_spent = utxos_map.into_keys().collect::<Vec<_>>();

    let created = time::OffsetDateTime::now_utc();

    let transactions = vec![SentTransaction::new(
        &transaction,
        created,
        proposal_info.target_height,
        proposal_info.from_account,
        &outputs,
        fee_amount,
        #[cfg(feature = "transparent-inputs")]
        &utxos_spent,
    )];

    wallet_db
        .store_transactions_to_be_sent(&transactions)
        .map_err(Error::DataSource)?;

    Ok(txid)
}

/// Constructs a transaction that consumes available transparent UTXOs belonging to the specified
/// secret key, and sends them to the most-preferred receiver of the default internal address for
/// the provided Unified Spending Key.
///
/// This procedure will not attempt to shield transparent funds if the total amount being shielded
/// is less than the default fee to send the transaction. Fees will be paid only from the
/// transparent UTXOs being consumed.
///
/// Parameters:
/// * `wallet_db`: A read/write reference to the wallet database
/// * `params`: Consensus parameters
/// * `spend_prover`: The [`sapling::SpendProver`] to use in constructing the shielded
///   transaction.
/// * `output_prover`: The [`sapling::OutputProver`] to use in constructing the shielded
///   transaction.
/// * `input_selector`: The [`InputSelector`] to for note selection and change and fee
///   determination
/// * `usk`: The unified spending key that will be used to detect and spend transparent UTXOs,
///   and that will provide the shielded address to which funds will be sent. Funds will be
///   shielded to the internal (change) address associated with the most preferred shielded
///   receiver corresponding to this account, or if no shielded receiver can be used for this
///   account, this function will return an error. This procedure will return an error if the
///   USK does not correspond to an account known to the wallet.
/// * `from_addrs`: The list of transparent addresses that will be used to filter transaparent
///   UTXOs received by the wallet. Only UTXOs received at one of the provided addresses will
///   be selected to be shielded.
/// * `min_confirmations`: The minimum number of confirmations that a previously
///   received note must have in the blockchain in order to be considered for being
///   spent. A value of 10 confirmations is recommended and 0-conf transactions are
///   not supported.
///
/// [`sapling::SpendProver`]: sapling::prover::SpendProver
/// [`sapling::OutputProver`]: sapling::prover::OutputProver
#[cfg(feature = "transparent-inputs")]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn shield_transparent_funds<DbT, ParamsT, InputsT, ChangeT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    shielding_threshold: Zatoshis,
    spending_keys: &SpendingKeys,
    from_addrs: &[TransparentAddress],
    to_account: <DbT as InputSource>::AccountId,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<NonEmpty<TxId>, ShieldErrT<DbT, InputsT, ChangeT>>
where
    ParamsT: consensus::Parameters,
    DbT: WalletWrite + WalletCommitmentTrees + InputSource<Error = <DbT as WalletRead>::Error>,
    InputsT: ShieldingSelector<InputSource = DbT>,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
{
    let proposal = propose_shielding(
        wallet_db,
        params,
        input_selector,
        change_strategy,
        shielding_threshold,
        from_addrs,
        to_account,
        confirmations_policy,
    )?;

    create_proposed_transactions(
        wallet_db,
        params,
        spend_prover,
        output_prover,
        spending_keys,
        OvkPolicy::Sender,
        &proposal,
    )
}
