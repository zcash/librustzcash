//! Unit tests of the selection of notes for size-bounded send-max proposals.

use std::convert::Infallible;

use ::sapling::{Rseed, value::NoteValue, zip32::ExtendedSpendingKey};
use incrementalmerkletree::Position;
use proptest::prelude::*;
use zcash_keys::address::Address;
use zcash_primitives::transaction::{TxId, fees::zip317::MARGINAL_FEE};
use zcash_protocol::{
    ShieldedPool,
    consensus::{MainNetwork, NetworkUpgrade, Parameters},
    constants::MAX_BLOCK_BYTES,
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
    proposal::Proposal,
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

/// Wraps `note` as a received note at the given note commitment tree position.
fn received<NoteT>(note: NoteT, position: u64) -> ReceivedNote<u64, NoteT> {
    ReceivedNote::from_parts(
        position,
        TxId::from_bytes([0; 32]),
        0,
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

/// Proposes a ZIP 317 send-max transfer of `notes` to a Sapling address on mainnet at the NU5
/// activation height.
fn propose(
    notes: ReceivedNotes<u64>,
) -> Result<Proposal<StandardFeeRule, u64>, SendMaxErrT<Infallible, StandardFeeRule, u64>> {
    let params = MainNetwork;
    let target_height = params.activation_height(NetworkUpgrade::Nu5).unwrap();
    let (_, recipient) = ExtendedSpendingKey::master(&[0x5a])
        .expect("the derivation path yields a valid key")
        .default_address();
    propose_send_max_from_notes(
        &params,
        &StandardFeeRule::Zip317,
        notes,
        TargetHeight::from(target_height),
        target_height - 1,
        ConfirmationsPolicy::MIN,
        Address::from(recipient).to_zcash_address(&params),
        None,
    )
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
fn check_transaction_size_within_max_block_bytes_is_check_transaction_size() {
    let proposal = propose(sapling_only(sapling_notes(
        &NOTE_FEE_MULTIPLES.map(fee_multiple),
    )))
    .unwrap();
    let size = proposal.estimated_serialized_size();

    assert!(proposal.check_transaction_size().is_ok());
    assert!(
        proposal
            .check_transaction_size_within(MAX_BLOCK_BYTES)
            .is_ok()
    );
    assert!(proposal.check_transaction_size_within(size).is_ok());
    assert!(proposal.check_transaction_size_within(size - 1).is_err());
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

    let send_max =
        propose_largest_fitting_send_max(sapling_only(sapling_notes(&values)), size_limit, propose)
            .unwrap();
    assert_eq!(spent_values(send_max.proposal()), fitting);
    assert!(
        send_max
            .proposal()
            .check_transaction_size_within(size_limit)
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
    let send_max = propose_largest_fitting_send_max(notes, MAX_BLOCK_BYTES, propose).unwrap();
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
