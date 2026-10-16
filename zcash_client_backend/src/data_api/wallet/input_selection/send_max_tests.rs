//! Unit tests of the selection of notes for size-bounded send-max proposals.

use std::convert::Infallible;

use ::sapling::{Rseed, value::NoteValue, zip32::ExtendedSpendingKey};
use assert_matches::assert_matches;
use incrementalmerkletree::Position;
use proptest::prelude::*;
use transparent::address::TransparentAddress;
use zcash_keys::address::Address;
use zcash_primitives::transaction::{TxId, fees::zip317::MARGINAL_FEE};
use zcash_protocol::{
    ShieldedPool,
    consensus::{MainNetwork, NetworkUpgrade, Parameters},
    value::Zatoshis,
};
use zip32::Scope;

use super::{
    SendMaxErrT, SizeBoundOrder, largest_fitting_prefix, propose_largest_fitting_send_max,
    propose_send_max_from_notes,
};
use crate::{
    data_api::{
        ReceivedNotes,
        wallet::{ConfirmationsPolicy, SendMaxRemainder, TargetHeight},
    },
    fees::StandardFeeRule,
    proposal::{Proposal, ProposalError, SizeBoundViolation, Step, TransactionSizeBound},
    wallet::ReceivedNote,
};

#[cfg(feature = "orchard")]
use ::orchard::{
    keys::{FullViewingKey, SpendingKey},
    note::{Note as OrchardNote, NoteVersion, RandomSeed, Rho},
    value::NoteValue as OrchardNoteValue,
};

/// The values of the notes the proposal tests fund, as multiples of the ZIP 317 marginal fee.
const NOTE_FEE_MULTIPLES: [u64; 8] = [2, 9, 3, 8, 7, 6, 5, 4];

/// The number of the largest of those notes that the proposal tests' size limit admits.
const FITTING_NOTE_COUNT: usize = 5;

/// Returns `multiple` times the ZIP 317 marginal fee.
fn fee_multiple(multiple: u64) -> Zatoshis {
    (MARGINAL_FEE * multiple).unwrap()
}

/// Wraps `note` as a received note at the given note commitment tree position, received in an
/// output whose index is that position, so that distinct notes have distinct outputs.
fn received<NoteT>(note: NoteT, position: u64) -> ReceivedNote<u64, NoteT> {
    ReceivedNote::from_parts(
        position,
        TxId::from_bytes([0; 32]),
        u16::try_from(position).expect("test positions are small"),
        note,
        Scope::External,
        Position::from(position),
        None,
        None,
    )
}

/// Returns received Sapling notes of the given values, at successive tree positions.
fn sapling_notes(values: &[Zatoshis]) -> Vec<ReceivedNote<u64, ::sapling::Note>> {
    let (_, recipient) = ExtendedSpendingKey::master(&[])
        .expect("the derivation path yields a valid key")
        .default_address();
    values
        .iter()
        .zip(0u64..)
        .map(|(value, position)| {
            received(
                ::sapling::Note::from_parts(
                    recipient,
                    NoteValue::from_raw(u64::from(*value)),
                    Rseed::AfterZip212([0; 32]),
                ),
                position,
            )
        })
        .collect()
}

/// Returns received Orchard-shaped notes of the given values and note version, at successive
/// tree positions.
#[cfg(feature = "orchard")]
fn orchard_notes(values: &[Zatoshis], version: NoteVersion) -> Vec<ReceivedNote<u64, OrchardNote>> {
    let sk = SpendingKey::from_bytes([0x2a; 32]).unwrap();
    let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
    let rho = Rho::from_bytes(&[0; 32]).unwrap();
    let rseed = RandomSeed::from_bytes([0x1b; 32], &rho).unwrap();
    values
        .iter()
        .zip(0u64..)
        .map(|(value, position)| {
            let note = OrchardNote::from_parts(
                recipient,
                OrchardNoteValue::from_raw(u64::from(*value)),
                rho,
                rseed,
                version,
            )
            .unwrap();
            received(note, position)
        })
        .collect()
}

/// Returns the given Sapling notes as a [`ReceivedNotes`].
fn sapling_only(sapling: Vec<ReceivedNote<u64, ::sapling::Note>>) -> ReceivedNotes<u64> {
    ReceivedNotes::new(
        sapling,
        #[cfg(feature = "orchard")]
        vec![],
        #[cfg(feature = "orchard")]
        vec![],
    )
}

/// Returns the value, pool, and position of every note in `notes`, sorted in
/// [`SizeBoundOrder`].
fn order_keys(notes: &ReceivedNotes<u64>) -> Vec<(Zatoshis, ShieldedPool, Position)> {
    let keys = notes.sapling().iter().map(|n| {
        (
            n.note_value().unwrap(),
            ShieldedPool::Sapling,
            n.note_commitment_tree_position(),
        )
    });
    #[cfg(feature = "orchard")]
    let keys = keys
        .chain(notes.orchard().iter().map(|n| {
            (
                n.note_value().unwrap(),
                ShieldedPool::Orchard,
                n.note_commitment_tree_position(),
            )
        }))
        .chain(notes.ironwood().iter().map(|n| {
            (
                n.note_value().unwrap(),
                ShieldedPool::Ironwood,
                n.note_commitment_tree_position(),
            )
        }));
    let mut keys = keys.collect::<Vec<_>>();
    keys.sort_by(|(av, ap, apos), (bv, bp, bpos)| bv.cmp(av).then(ap.cmp(bp)).then(apos.cmp(bpos)));
    keys
}

/// The result of proposing a send-max transfer in these tests.
type ProposalResult =
    Result<Proposal<StandardFeeRule, u64>, SendMaxErrT<Infallible, StandardFeeRule, u64>>;

/// Proposes a ZIP 317 send-max transfer of `notes` to a Sapling address on mainnet at the NU5
/// activation height.
fn propose(notes: ReceivedNotes<u64>) -> ProposalResult {
    let (_, recipient) = ExtendedSpendingKey::master(&[0x5a])
        .expect("the derivation path yields a valid key")
        .default_address();
    propose_to(notes, &Address::from(recipient))
}

/// Proposes a ZIP 317 send-max transfer of `notes` to a transparent P2PKH address.
fn propose_to_transparent(notes: ReceivedNotes<u64>) -> ProposalResult {
    propose_to(
        notes,
        &Address::Transparent(TransparentAddress::PublicKeyHash([0x7; 20])),
    )
}

/// Proposes a ZIP 317 send-max transfer of `notes` to `recipient` on mainnet at the NU5
/// activation height.
fn propose_to(notes: ReceivedNotes<u64>, recipient: &Address) -> ProposalResult {
    let params = MainNetwork;
    let target_height = params.activation_height(NetworkUpgrade::Nu5).unwrap();
    propose_send_max_from_notes(
        &params,
        &StandardFeeRule::Zip317,
        notes,
        TargetHeight::from(target_height),
        target_height - 1,
        ConfirmationsPolicy::MIN,
        recipient.to_zcash_address(&params),
        None,
    )
}

/// Returns the number of actions the first step of `proposal` is estimated to carry in `pool`.
fn first_step_actions(proposal: &Proposal<StandardFeeRule, u64>, pool: ShieldedPool) -> usize {
    first_step(proposal).estimated_pool_actions(pool, &|_| {
        unreachable!("the first step spends no prior outputs")
    })
}

/// Returns the first step of `proposal`.
fn first_step(proposal: &Proposal<StandardFeeRule, u64>) -> &Step<u64> {
    proposal.steps().first()
}

/// Returns the funded notes, all Sapling notes of the [`NOTE_FEE_MULTIPLES`].
fn funded() -> ReceivedNotes<u64> {
    sapling_only(sapling_notes(&NOTE_FEE_MULTIPLES.map(fee_multiple)))
}

/// Returns the values of the `count` largest funded notes, from largest to smallest.
fn largest(count: usize) -> Vec<Zatoshis> {
    let mut sorted = NOTE_FEE_MULTIPLES.map(fee_multiple).to_vec();
    sorted.sort_by(|a, b| b.cmp(a));
    sorted.truncate(count);
    sorted
}

/// Returns a send-max proposal spending the `count` largest funded notes.
fn proposal_of_largest(count: usize) -> Proposal<StandardFeeRule, u64> {
    propose(sapling_only(sapling_notes(&largest(count)))).unwrap()
}

/// Returns the values of the notes spent by `proposal`, from largest to smallest.
fn spent_values(proposal: &Proposal<StandardFeeRule, u64>) -> Vec<Zatoshis> {
    let mut values = proposal
        .steps()
        .first()
        .shielded_inputs()
        .unwrap()
        .notes()
        .iter()
        .map(|n| n.note().value())
        .collect::<Vec<_>>();
    values.sort_by(|a, b| b.cmp(a));
    values
}

proptest! {
    #[test]
    fn largest_fitting_prefix_finds_the_threshold(
        (len, fitting) in (1usize..10_000).prop_flat_map(|len| (Just(len), 0..len)),
    ) {
        let mut probes = 0u32;
        let found = largest_fitting_prefix(len, |count| {
            probes += 1;
            assert!(count > 0 && count < len, "probed out of range: {count}");
            count > fitting
        });
        prop_assert_eq!(found, fitting);
        prop_assert!(probes <= len.ilog2() + 1);
    }
}

#[test]
fn largest_fitting_prefix_of_nothing_is_empty() {
    assert_eq!(largest_fitting_prefix(0, |_| unreachable!()), 0);
    assert_eq!(largest_fitting_prefix(1, |_| unreachable!()), 0);
}

#[test]
fn size_bound_order_is_value_descending_then_pool_then_position() {
    // Equal values within and across pools exercise both tie-breaks.
    let sapling = sapling_notes(&[3, 9, 3, 5].map(fee_multiple));
    #[cfg(feature = "orchard")]
    let notes = ReceivedNotes::new(
        sapling,
        orchard_notes(&[5, 9, 2].map(fee_multiple), NoteVersion::V2),
        orchard_notes(&[3, 7].map(fee_multiple), NoteVersion::V3),
    );
    #[cfg(not(feature = "orchard"))]
    let notes = sapling_only(sapling);

    let expected = order_keys(&notes);
    let ordered = SizeBoundOrder::new(&notes).unwrap();
    assert_eq!(ordered.len(), expected.len());
    for count in 0..=ordered.len() {
        assert_eq!(order_keys(&ordered.prefix(count)), expected[..count]);
        assert_eq!(order_keys(&ordered.suffix(count)), expected[count..]);
    }
}

#[test]
fn check_transaction_size_within_consensus_is_check_transaction_size() {
    let proposal = propose(sapling_only(sapling_notes(
        &NOTE_FEE_MULTIPLES.map(fee_multiple),
    )))
    .unwrap();
    let size = proposal.estimated_serialized_size();

    assert!(proposal.check_transaction_size().is_ok());
    assert!(
        proposal
            .check_transaction_size_within(&TransactionSizeBound::CONSENSUS)
            .is_ok()
    );
    assert!(
        proposal
            .check_transaction_size_within(&TransactionSizeBound::default())
            .is_ok()
    );
    let bytes = |n| TransactionSizeBound::CONSENSUS.with_max_bytes(n);
    assert!(proposal.check_transaction_size_within(&bytes(size)).is_ok());
    assert_matches!(
        proposal.check_transaction_size_within(&bytes(size - 1)),
        Err(ProposalError::TransactionTooLarge { estimated_size, limit, .. })
            if estimated_size == size && limit == size - 1
    );
}

#[test]
fn check_transaction_size_within_checks_each_count_limit() {
    let proposal = propose(sapling_only(sapling_notes(
        &NOTE_FEE_MULTIPLES.map(fee_multiple),
    )))
    .unwrap();
    let actions = first_step_actions(&proposal, ShieldedPool::Sapling);
    assert!(actions >= NOTE_FEE_MULTIPLES.len());
    let check = |bound: TransactionSizeBound| proposal.check_transaction_size_within(&bound);
    let violation = |violation| {
        move |result: Result<(), ProposalError>| {
            matches!(
                result,
                Err(ProposalError::ExceedsSizeBound { step_index: 0, violation: v }) if v == violation
            )
        }
    };
    let consensus = TransactionSizeBound::CONSENSUS;

    assert!(check(consensus.with_max_shielded_actions(actions)).is_ok());
    assert!(violation(SizeBoundViolation::ShieldedActions {
        count: actions,
        limit: actions - 1
    })(check(
        consensus.with_max_shielded_actions(actions - 1)
    )));

    assert!(check(consensus.with_max_pool_actions(ShieldedPool::Sapling, actions)).is_ok());
    assert!(violation(SizeBoundViolation::PoolActions {
        pool: ShieldedPool::Sapling,
        count: actions,
        limit: actions - 1
    })(check(
        consensus.with_max_pool_actions(ShieldedPool::Sapling, actions - 1)
    )));
    // The proposal has no bundle in the other pools.
    for pool in [ShieldedPool::Orchard, ShieldedPool::Ironwood] {
        assert!(check(consensus.with_max_pool_actions(pool, 0)).is_ok());
    }

    // The proposal pays one shielded output and has no transparent inputs or outputs.
    assert!(check(consensus.with_max_shielded_payment_outputs(1)).is_ok());
    assert!(violation(SizeBoundViolation::ShieldedPaymentOutputs {
        count: 1,
        limit: 0
    })(check(
        consensus.with_max_shielded_payment_outputs(0)
    )));
    assert!(
        check(
            consensus
                .with_max_transparent_inputs(0)
                .with_max_transparent_outputs(0)
        )
        .is_ok()
    );
}

#[test]
fn check_transaction_size_within_checks_transparent_outputs() {
    let proposal = propose_to_transparent(sapling_only(sapling_notes(
        &NOTE_FEE_MULTIPLES.map(fee_multiple),
    )))
    .unwrap();
    let consensus = TransactionSizeBound::CONSENSUS;
    assert!(
        proposal
            .check_transaction_size_within(
                &consensus
                    .with_max_transparent_outputs(1)
                    .with_max_shielded_payment_outputs(0)
            )
            .is_ok()
    );
    assert_matches!(
        proposal.check_transaction_size_within(&consensus.with_max_transparent_outputs(0)),
        Err(ProposalError::ExceedsSizeBound {
            step_index: 0,
            violation: SizeBoundViolation::TransparentOutputs { count: 1, limit: 0 },
        })
    );
}

#[cfg(feature = "transparent-inputs")]
#[test]
fn check_transaction_size_within_checks_prior_step_transparent_inputs() {
    let proposal = propose_to(
        sapling_only(sapling_notes(&NOTE_FEE_MULTIPLES.map(fee_multiple))),
        &Address::Tex([0x4; 20]),
    )
    .unwrap();
    assert_eq!(proposal.steps().len(), 2);
    let consensus = TransactionSizeBound::CONSENSUS;
    assert!(
        proposal
            .check_transaction_size_within(&consensus.with_max_transparent_inputs(1))
            .is_ok()
    );
    // The second step spends the ephemeral output of the first.
    assert_matches!(
        proposal.check_transaction_size_within(&consensus.with_max_transparent_inputs(0)),
        Err(ProposalError::ExceedsSizeBound {
            step_index: 1,
            violation: SizeBoundViolation::TransparentInputs { count: 1, limit: 0 },
        })
    );
}

#[test]
fn propose_largest_fitting_send_max_spends_the_largest_notes_that_fit() {
    let values = NOTE_FEE_MULTIPLES.map(fee_multiple);
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| b.cmp(a));
    let (fitting, remaining) = sorted.split_at(FITTING_NOTE_COUNT);

    // A send-max proposal's size depends only on how many notes it spends from each pool.
    let size_limit = propose(sapling_only(sapling_notes(fitting)))
        .unwrap()
        .estimated_serialized_size();

    let bound = TransactionSizeBound::CONSENSUS.with_max_bytes(size_limit);
    let send_max =
        propose_largest_fitting_send_max(sapling_only(sapling_notes(&values)), &bound, propose)
            .unwrap();
    assert_eq!(spent_values(send_max.proposal()), fitting);
    assert!(
        send_max
            .proposal()
            .check_transaction_size_within(&bound)
            .is_ok()
    );

    let remainder = send_max.remainder();
    assert_eq!(
        remainder.value(),
        remaining
            .iter()
            .try_fold(Zatoshis::ZERO, |acc, v| acc + *v)
            .unwrap()
    );
    assert_eq!(remainder.note_count(), remaining.len());
    assert_eq!(
        remainder.note_count_in_pool(ShieldedPool::Sapling),
        remaining.len()
    );
}

#[test]
fn propose_largest_fitting_send_max_spends_everything_that_fits() {
    let notes = sapling_only(sapling_notes(&NOTE_FEE_MULTIPLES.map(fee_multiple)));
    let send_max =
        propose_largest_fitting_send_max(notes, &TransactionSizeBound::CONSENSUS, propose).unwrap();
    assert_eq!(*send_max.remainder(), SendMaxRemainder::ZERO);
    assert_eq!(
        send_max,
        crate::data_api::wallet::SendMaxProposal::from_parts(
            propose(sapling_only(sapling_notes(
                &NOTE_FEE_MULTIPLES.map(fee_multiple)
            )))
            .unwrap(),
            SendMaxRemainder::ZERO,
        )
    );
}

/// Returns the notes that a size-bounded send-max of `notes` under `bound` spends, from largest
/// to smallest, and its remainder's note count.
fn spent_within(notes: ReceivedNotes<u64>, bound: &TransactionSizeBound) -> (Vec<Zatoshis>, usize) {
    let send_max = propose_largest_fitting_send_max(notes, bound, propose).unwrap();
    assert!(
        send_max
            .proposal()
            .check_transaction_size_within(bound)
            .is_ok()
    );
    (
        spent_values(send_max.proposal()),
        send_max.remainder().note_count(),
    )
}

#[test]
fn propose_largest_fitting_send_max_honours_action_limits() {
    let actions = first_step_actions(
        &proposal_of_largest(FITTING_NOTE_COUNT),
        ShieldedPool::Sapling,
    );
    let leftover = NOTE_FEE_MULTIPLES.len() - FITTING_NOTE_COUNT;

    for bound in [
        TransactionSizeBound::CONSENSUS.with_max_shielded_actions(actions),
        TransactionSizeBound::CONSENSUS.with_max_pool_actions(ShieldedPool::Sapling, actions),
    ] {
        assert_eq!(
            spent_within(funded(), &bound),
            (largest(FITTING_NOTE_COUNT), leftover)
        );
    }
}

#[test]
fn propose_largest_fitting_send_max_honours_the_intersection() {
    let leftover = NOTE_FEE_MULTIPLES.len() - FITTING_NOTE_COUNT;

    // A byte limit that admits one note more than the fitting notes, and an action limit that
    // admits exactly the fitting notes: the intersection admits exactly the fitting notes,
    // whichever way round it is taken.
    let bytes = TransactionSizeBound::CONSENSUS
        .with_max_bytes(proposal_of_largest(FITTING_NOTE_COUNT + 1).estimated_serialized_size());
    let actions = TransactionSizeBound::CONSENSUS.with_max_shielded_actions(first_step_actions(
        &proposal_of_largest(FITTING_NOTE_COUNT),
        ShieldedPool::Sapling,
    ));
    assert_eq!(
        spent_within(funded(), &bytes),
        (largest(FITTING_NOTE_COUNT + 1), leftover - 1)
    );
    for bound in [bytes.intersect(&actions), actions.intersect(&bytes)] {
        assert_eq!(
            spent_within(funded(), &bound),
            (largest(FITTING_NOTE_COUNT), leftover)
        );
    }
}

#[test]
fn propose_largest_fitting_send_max_honours_transparent_limits() {
    let consensus = TransactionSizeBound::CONSENSUS;

    // A limit that the recipient's output satisfies leaves nothing unspent.
    let send_max = propose_largest_fitting_send_max(
        funded(),
        &consensus.with_max_transparent_outputs(1),
        propose_to_transparent,
    )
    .unwrap();
    assert_eq!(*send_max.remainder(), SendMaxRemainder::ZERO);
    assert_eq!(
        spent_values(send_max.proposal()).len(),
        NOTE_FEE_MULTIPLES.len()
    );

    // A limit that the recipient's output exceeds does not depend on the number of notes
    // spent, so no number of notes satisfies it.
    assert!(
        propose_largest_fitting_send_max(
            funded(),
            &consensus.with_max_transparent_outputs(0),
            propose_to_transparent,
        )
        .is_err()
    );
}

/// A zero limit on a pool's actions keeps a size-bounded send-max from spending any note of
/// that pool, stopping at the first such note in [`SizeBoundOrder`].
#[cfg(feature = "orchard")]
#[test]
fn propose_largest_fitting_send_max_honours_a_zero_pool_limit() {
    /// The fee multiples of the Sapling notes, all larger than the Orchard notes.
    const SAPLING: [u64; 3] = [9, 8, 7];
    /// The fee multiples of the Orchard notes.
    const ORCHARD: [u64; 2] = [4, 3];
    let notes = || {
        ReceivedNotes::new(
            sapling_notes(&SAPLING.map(fee_multiple)),
            orchard_notes(&ORCHARD.map(fee_multiple), NoteVersion::V2),
            vec![],
        )
    };

    let unbounded = propose(notes()).unwrap();
    assert!(first_step_actions(&unbounded, ShieldedPool::Orchard) > 0);

    let bound = TransactionSizeBound::CONSENSUS.with_max_pool_actions(ShieldedPool::Orchard, 0);
    let send_max = propose_largest_fitting_send_max(notes(), &bound, propose).unwrap();
    assert_eq!(
        spent_values(send_max.proposal()),
        SAPLING.map(fee_multiple).to_vec()
    );
    assert_eq!(
        first_step_actions(send_max.proposal(), ShieldedPool::Orchard),
        0
    );
    let remainder = send_max.remainder();
    assert_eq!(
        remainder.note_count_in_pool(ShieldedPool::Orchard),
        ORCHARD.len()
    );
    assert_eq!(remainder.note_count(), ORCHARD.len());
}
