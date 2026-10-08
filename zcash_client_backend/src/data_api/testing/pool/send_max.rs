//! The shared, backend-agnostic tests of send-max proposals under the transaction size bound.
//!
//! Every scenario here is generic over one or two [`ShieldedPoolTester`]s and is instantiated
//! per pool by the concrete backends (see `zcash_client_sqlite`). Rather than funding the
//! hundreds or thousands of notes needed to reach the real bound, each scenario measures the
//! size of a proposal spending a small number of notes and uses it as the size limit.

use std::convert::Infallible;

use assert_matches::assert_matches;
use zcash_keys::address::Address;
use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;
use zcash_protocol::{
    ShieldedPool, constants::MAX_BLOCK_BYTES, local_consensus::LocalNetwork, value::Zatoshis,
};

use crate::{
    data_api::{
        Account as _, InputSource, MaxSpendMode, WalletRead, WalletTest, WalletWrite,
        error::Error,
        testing::{DataStoreFactory, TestCache, TestState},
        wallet::{
            ConfirmationsPolicy, LockRequest, ProposeSendMaxErrT, SendMaxProposal,
            input_selection::LockedInputPolicy, propose_send_max_transfer_within_size_limit,
        },
    },
    fees::StandardFeeRule,
    proposal::{Proposal, ProposalError},
    wallet::LockOwner,
};

use super::{ShieldedPoolTester, dsl::TestDsl};

#[cfg(feature = "orchard")]
use crate::data_api::testing::AddressType;

#[cfg(feature = "transparent-inputs")]
use {crate::proposal::StepOutputIndex, std::collections::BTreeMap, zcash_protocol::PoolType};

/// The values of the notes funded before the size limit is measured, as multiples of the ZIP 317
/// marginal fee. The size limit admits exactly this many notes.
const EARLY_NOTE_FEE_MULTIPLES: [u64; 5] = [2, 9, 3, 8, 7];

/// The values of the notes funded after the size limit is measured, as multiples of the ZIP 317
/// marginal fee. Together with the early notes, the five largest are `[9, 8, 7, 6, 5]`, so that
/// the notes a size-bounded send-max spends are neither the oldest nor the newest.
const LATE_NOTE_FEE_MULTIPLES: [u64; 3] = [6, 5, 4];

/// The fee multiples of the notes a size-bounded send-max spends, from largest to smallest.
const FITTING_NOTE_FEE_MULTIPLES: [u64; 5] = [9, 8, 7, 6, 5];

/// The fee multiples of the notes a size-bounded send-max leaves unspent.
const REMAINING_NOTE_FEE_MULTIPLES: [u64; 3] = [4, 3, 2];

/// The number of blocks for which the tests lock the inputs of a proposal.
const LOCK_BLOCKS: u32 = 10;

/// Returns `multiple` times the ZIP 317 marginal fee.
fn fee_multiple(multiple: u64) -> Zatoshis {
    (MARGINAL_FEE * multiple).unwrap()
}

/// Returns the total of the given multiples of the ZIP 317 marginal fee.
fn total_of(multiples: &[u64]) -> Zatoshis {
    fee_multiple(multiples.iter().sum())
}

/// Returns the estimated serialized size of the first step of `proposal`, which is the size
/// that the transaction size bound applies to.
fn first_step_size<NoteRef>(proposal: &Proposal<StandardFeeRule, NoteRef>) -> usize {
    proposal
        .steps()
        .first()
        .estimated_serialized_size(&|_| unreachable!("the first step spends no prior outputs"))
}

/// Returns the values of the shielded notes spent by the first step of `proposal`, from largest
/// to smallest, each with its pool.
fn spent_notes<NoteRef>(
    proposal: &Proposal<StandardFeeRule, NoteRef>,
) -> Vec<(Zatoshis, ShieldedPool)> {
    let mut notes = proposal
        .steps()
        .first()
        .shielded_inputs()
        .map(|inputs| {
            inputs
                .notes()
                .iter()
                .map(|n| (n.note().value(), n.note().pool()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    notes.sort_by(|a, b| b.cmp(a));
    notes
}

/// Proposes a ZIP 317 send-max transfer of the Sapling and Orchard funds of `account_id` to `to`,
/// with the minimum confirmations and the transaction size bound set to `size_limit` bytes.
#[allow(clippy::type_complexity)]
fn propose_send_max<Cache, DbT>(
    st: &mut TestState<Cache, DbT, LocalNetwork>,
    account_id: <DbT as InputSource>::AccountId,
    to: &Address,
    mode: MaxSpendMode,
    lock_inputs: Option<LockRequest>,
    size_limit: usize,
) -> Result<
    SendMaxProposal<StandardFeeRule, <DbT as InputSource>::NoteRef>,
    ProposeSendMaxErrT<DbT, Infallible, StandardFeeRule>,
>
where
    DbT: WalletTest + WalletWrite + InputSource<Error = <DbT as WalletRead>::Error>,
{
    let network = *st.network();
    propose_send_max_transfer_within_size_limit::<_, _, _, Infallible>(
        st.wallet_mut(),
        &network,
        account_id,
        &[ShieldedPool::Sapling, ShieldedPool::Orchard],
        &StandardFeeRule::Zip317,
        to.to_zcash_address(&network),
        None,
        mode,
        ConfirmationsPolicy::MIN,
        &LockedInputPolicy::Exclude,
        lock_inputs,
        size_limit,
    )
}

/// Funds the test account with the early notes in one block, measures the size of a send-max
/// proposal to `to` spending exactly those notes, then funds the late notes in a second block.
///
/// Returns the measured size, which admits exactly as many notes as there are early notes.
fn fund_notes_and_measure_limit<T, Cache, Dsf>(
    st: &mut TestDsl<super::dsl::TestScenario<T, Cache, Dsf>>,
    to: &Address,
) -> usize
where
    T: ShieldedPoolTester,
    Cache: TestCache,
    Dsf: DataStoreFactory,
{
    let account_id = st.get_account().id();
    st.add_notes_checking_balance([EARLY_NOTE_FEE_MULTIPLES.map(fee_multiple)]);
    let measured = propose_send_max(
        &mut **st,
        account_id,
        to,
        MaxSpendMode::MaxSpendable,
        None,
        MAX_BLOCK_BYTES,
    )
    .unwrap();
    assert_eq!(
        measured
            .proposal()
            .steps()
            .first()
            .shielded_inputs()
            .map(|i| i.notes().len()),
        Some(EARLY_NOTE_FEE_MULTIPLES.len())
    );
    st.add_notes_checking_balance([LATE_NOTE_FEE_MULTIPLES.map(fee_multiple)]);
    first_step_size(measured.proposal())
}

/// Tests that a size-bounded send-max proposal spends the largest-value notes that fit within the
/// size bound, and reports the notes left unspent as its remainder.
///
/// The test:
/// - Funds the wallet with more notes than the size limit admits, where the largest notes are
///   neither the oldest nor the newest.
/// - Proposes a send-max transfer with `MaxSpendMode::WithinSizeBound`.
/// - Verifies that the proposal spends exactly the largest notes that fit, pays their value less
///   the fee to the recipient, and reports the value and count of the other notes as the
///   remainder.
/// - Builds the transaction.
pub fn send_max_within_size_bound_spends_largest_notes_that_fit<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    let account_id = st.get_account().id();
    let to: Address = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let size_limit = fund_notes_and_measure_limit(&mut st, &to);

    let send_max = propose_send_max(
        &mut st,
        account_id,
        &to,
        MaxSpendMode::WithinSizeBound,
        None,
        size_limit,
    )
    .unwrap();
    let (proposal, remainder) = send_max.into_parts();

    assert_eq!(
        spent_notes(&proposal),
        FITTING_NOTE_FEE_MULTIPLES
            .map(|m| (fee_multiple(m), T::SHIELDED_PROTOCOL))
            .to_vec()
    );
    assert!(first_step_size(&proposal) <= size_limit);

    let step = proposal.steps().first();
    let expected_payment =
        (total_of(&FITTING_NOTE_FEE_MULTIPLES) - step.balance().fee_required()).unwrap();
    assert_matches!(
        step.transaction_request().payments().get(&0),
        Some(payment) if payment.amount() == Some(expected_payment)
    );

    assert_eq!(remainder.value(), total_of(&REMAINING_NOTE_FEE_MULTIPLES));
    assert_eq!(remainder.note_count(), REMAINING_NOTE_FEE_MULTIPLES.len());
    assert_eq!(
        remainder.note_count_in_pool(T::SHIELDED_PROTOCOL),
        REMAINING_NOTE_FEE_MULTIPLES.len()
    );
    assert!(!remainder.is_zero());

    st.create_proposed_expecting(&proposal, 1);
}

/// Tests that a size-bounded send-max proposal whose notes all fit within the size bound is the
/// proposal that `MaxSpendMode::MaxSpendable` produces, with a zero remainder.
pub fn send_max_within_size_bound_is_max_spendable_when_everything_fits<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    let account_id = st.get_account().id();
    let to: Address = T::sk_default_address(&T::sk(&[0xf5; 32]));
    st.add_notes_checking_balance([EARLY_NOTE_FEE_MULTIPLES.map(fee_multiple)]);

    let within = propose_send_max(
        &mut st,
        account_id,
        &to,
        MaxSpendMode::WithinSizeBound,
        None,
        MAX_BLOCK_BYTES,
    )
    .unwrap();
    let max_spendable = propose_send_max(
        &mut st,
        account_id,
        &to,
        MaxSpendMode::MaxSpendable,
        None,
        MAX_BLOCK_BYTES,
    )
    .unwrap();

    assert!(within.remainder().is_zero());
    assert_eq!(within.remainder().value(), Zatoshis::ZERO);
    assert_eq!(within, max_spendable);
}

/// Tests that the send-max modes other than `MaxSpendMode::WithinSizeBound` never leave notes
/// unspent to fit within the size bound, and instead reject an oversized proposal when it is
/// proposed.
pub fn send_max_without_size_bound_rejects_oversized<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    let account_id = st.get_account().id();
    let to: Address = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let size_limit = fund_notes_and_measure_limit(&mut st, &to);
    let funded_count = EARLY_NOTE_FEE_MULTIPLES.len() + LATE_NOTE_FEE_MULTIPLES.len();

    for mode in [MaxSpendMode::MaxSpendable, MaxSpendMode::Everything] {
        let result = propose_send_max(&mut st, account_id, &to, mode, None, size_limit);
        assert_matches!(
            result,
            Err(Error::Proposal(ProposalError::TransactionTooLarge { estimated_size, limit, .. }))
                if limit == size_limit && estimated_size > size_limit,
            "{mode:?}"
        );
    }

    // Nothing was locked or spent: a proposal without the bound spends every note.
    let unbounded = propose_send_max(
        &mut st,
        account_id,
        &to,
        MaxSpendMode::Everything,
        None,
        MAX_BLOCK_BYTES,
    )
    .unwrap();
    assert_eq!(spent_notes(unbounded.proposal()).len(), funded_count);
}

/// Tests that the notes a size-bounded send-max proposal leaves unspent are spent by a subsequent
/// size-bounded send-max proposal, once the first transaction has been mined.
pub fn send_max_within_size_bound_remainder_is_spendable_afterwards<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    let account_id = st.get_account().id();
    let to: Address = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let size_limit = fund_notes_and_measure_limit(&mut st, &to);

    let (first, remainder) = propose_send_max(
        &mut st,
        account_id,
        &to,
        MaxSpendMode::WithinSizeBound,
        None,
        size_limit,
    )
    .unwrap()
    .into_parts();
    let txids = st.create_proposed_expecting(&first, 1);
    let (h, _) = st.generate_next_block_including(txids.head);
    st.scan_cached_blocks(h, 1);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        remainder.value()
    );

    let (second, second_remainder) = propose_send_max(
        &mut st,
        account_id,
        &to,
        MaxSpendMode::WithinSizeBound,
        None,
        size_limit,
    )
    .unwrap()
    .into_parts();
    assert_eq!(
        spent_notes(&second),
        REMAINING_NOTE_FEE_MULTIPLES
            .map(|m| (fee_multiple(m), T::SHIELDED_PROTOCOL))
            .to_vec()
    );
    assert!(second_remainder.is_zero());

    let txids = st.create_proposed_expecting(&second, 1);
    let (h, _) = st.generate_next_block_including(txids.head);
    st.scan_cached_blocks(h, 1);
    assert_eq!(st.get_total_balance(account_id), Zatoshis::ZERO);
}

/// Tests that requesting input locks for a size-bounded send-max proposal locks only the notes
/// the proposal spends, leaving the remainder available to other proposals.
pub fn send_max_within_size_bound_locks_only_selected_notes<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    let account_id = st.get_account().id();
    let to: Address = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let size_limit = fund_notes_and_measure_limit(&mut st, &to);

    let owner = LockOwner::new([1; 32]);
    let locked = propose_send_max(
        &mut st,
        account_id,
        &to,
        MaxSpendMode::WithinSizeBound,
        Some(LockRequest::new(owner, LOCK_BLOCKS)),
        size_limit,
    )
    .unwrap();
    assert_eq!(
        spent_notes(locked.proposal()).len(),
        FITTING_NOTE_FEE_MULTIPLES.len()
    );

    // A second proposal, which excludes locked notes, can spend exactly the remainder.
    let (proposal, remainder) = propose_send_max(
        &mut st,
        account_id,
        &to,
        MaxSpendMode::WithinSizeBound,
        None,
        size_limit,
    )
    .unwrap()
    .into_parts();
    assert_eq!(
        spent_notes(&proposal),
        REMAINING_NOTE_FEE_MULTIPLES
            .map(|m| (fee_multiple(m), T::SHIELDED_PROTOCOL))
            .to_vec()
    );
    assert!(remainder.is_zero());
}

/// Tests that a size-bounded send-max proposal to a TEX recipient bounds the size of its first
/// step, which spends the shielded notes, and pays the recipient from its second step as usual.
#[cfg(feature = "transparent-inputs")]
pub fn send_max_within_size_bound_to_tex_bounds_the_first_step<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    let account_id = st.get_account().id();
    let to = Address::Tex([0x4; 20]);
    let size_limit = fund_notes_and_measure_limit(&mut st, &to);

    let (proposal, remainder) = propose_send_max(
        &mut st,
        account_id,
        &to,
        MaxSpendMode::WithinSizeBound,
        None,
        size_limit,
    )
    .unwrap()
    .into_parts();

    let steps = proposal.steps();
    assert_eq!(steps.len(), 2);
    assert_eq!(
        spent_notes(&proposal),
        FITTING_NOTE_FEE_MULTIPLES
            .map(|m| (fee_multiple(m), T::SHIELDED_PROTOCOL))
            .to_vec()
    );
    assert_eq!(remainder.value(), total_of(&REMAINING_NOTE_FEE_MULTIPLES));

    // The second step spends the ephemeral output of the first and pays the recipient its
    // value less the second step's fee.
    let ephemeral_value = steps[0]
        .balance()
        .proposed_change()
        .iter()
        .find(|c| c.is_ephemeral())
        .expect("the first step has an ephemeral output")
        .value();
    assert_matches!(
        steps[1].prior_step_inputs(),
        [input] if input.step_index() == 0
            && matches!(input.output_index(), StepOutputIndex::Change(_))
    );
    assert_eq!(
        steps[1].payment_pools(),
        &BTreeMap::from([(0, PoolType::Transparent)])
    );
    assert_matches!(
        steps[1].transaction_request().payments().get(&0),
        Some(payment) if payment.amount()
            == Some((ephemeral_value - steps[1].balance().fee_required()).unwrap())
    );
}

/// Tests that a size-bounded send-max proposal drawing on two pools orders notes by value across
/// pools, rather than preferring either pool.
///
/// The test:
/// - Funds `P0` notes with fee multiples `[9, 7, 4]` and `P1` notes with `[8, 6]`, and measures
///   the size of a proposal spending exactly those five notes.
/// - Funds a further `P1` note of multiple `3` and `P0` note of multiple `2`.
/// - Verifies that a size-bounded proposal spends the first five notes, leaving one note in each
///   pool as the remainder.
#[cfg(feature = "orchard")]
pub fn send_max_within_size_bound_drops_by_value_across_pools<
    P0: ShieldedPoolTester,
    P1: ShieldedPoolTester,
>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    /// The fee multiples of the `P0` and `P1` notes funded before the size limit is measured.
    const EARLY: ([u64; 3], [u64; 2]) = ([9, 7, 4], [8, 6]);
    /// The fee multiples of the `P0` and `P1` notes funded after the size limit is measured.
    const LATE: ([u64; 1], [u64; 1]) = ([2], [3]);

    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<P0>();
    let account = st.test_account().cloned().unwrap();
    let to: Address = P1::sk_default_address(&P1::sk(&[0xf5; 32]));
    let p0_fvk = P0::test_account_fvk(&st);
    let p1_fvk = P1::test_account_fvk(&st);

    // Funds each note in its own block, and scans those blocks.
    let fund = |st: &mut TestState<_, _, LocalNetwork>, p0: &[u64], p1: &[u64]| {
        let mut heights = vec![];
        for m in p0 {
            let (h, _, _) =
                st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, fee_multiple(*m));
            heights.push(h);
        }
        for m in p1 {
            let (h, _, _) =
                st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, fee_multiple(*m));
            heights.push(h);
        }
        st.scan_cached_blocks(heights[0], heights.len());
    };

    fund(&mut st, &EARLY.0, &EARLY.1);
    let size_limit = first_step_size(
        propose_send_max(
            &mut st,
            account.id(),
            &to,
            MaxSpendMode::MaxSpendable,
            None,
            MAX_BLOCK_BYTES,
        )
        .unwrap()
        .proposal(),
    );
    fund(&mut st, &LATE.0, &LATE.1);

    let (proposal, remainder) = propose_send_max(
        &mut st,
        account.id(),
        &to,
        MaxSpendMode::WithinSizeBound,
        None,
        size_limit,
    )
    .unwrap()
    .into_parts();

    let mut expected = EARLY
        .0
        .iter()
        .map(|m| (fee_multiple(*m), P0::SHIELDED_PROTOCOL))
        .chain(
            EARLY
                .1
                .iter()
                .map(|m| (fee_multiple(*m), P1::SHIELDED_PROTOCOL)),
        )
        .collect::<Vec<_>>();
    expected.sort_by(|a, b| b.cmp(a));
    assert_eq!(spent_notes(&proposal), expected);

    assert_eq!(remainder.value(), total_of(&[LATE.0[0], LATE.1[0]]));
    assert_eq!(
        remainder.note_count_in_pool(P0::SHIELDED_PROTOCOL),
        LATE.0.len()
    );
    assert_eq!(
        remainder.note_count_in_pool(P1::SHIELDED_PROTOCOL),
        LATE.1.len()
    );
    assert_eq!(remainder.note_count(), LATE.0.len() + LATE.1.len());
}
