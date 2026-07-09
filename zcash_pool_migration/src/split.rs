// Ported (in part) from the zodl_ironwood_migration prototype's `src/split.rs`.

//! Direct transaction building for the migration's note split, on the public
//! `zcash_primitives::transaction::builder::Builder`.
//!
//! Post-NU6.3 the `OrchardPostNu6_3` protocol disables cross-address transfers on the Orchard
//! bundle — payment outputs to a different address are rejected — but the orchard builder still
//! sanctions any number of wallet-controlled **change** outputs, each paired with a fabricated
//! zero-value spend at the change's own address. The high-level `create_pczt_from_proposal` path
//! (used for migration transfers, wired up in a later task) routes every V6 Orchard-protocol
//! output — payment AND change alike — to Ironwood, so it cannot express a same-pool note split;
//! this module builds the split transaction directly instead.
//!
//! Only the note-split half of the prototype's `split.rs` is ported here. Its
//! `build_transfer_pczt` (and the migration-transfer path generally) is intentionally **not**
//! ported: a later task replaces it with the high-level `create_pczt_from_proposal` path, which
//! *can* express a migration transfer (unlike the split).

use std::collections::BTreeSet;

use rand::rngs::OsRng;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{InputSource, WalletCommitmentTrees, WalletRead};
use zcash_client_backend::wallet::ReceivedNote;
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId};
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use crate::error::MigrationError;
use crate::reserved_source::ReservedInputSource;

/// ZIP-317 marginal fee per logical action (zatoshi).
const MARGINAL_FEE_ZATOSHI: u64 = 5_000;
/// ZIP-317 grace floor on the action count.
const GRACE_ACTIONS: u64 = 2;

/// The concrete wallet-database type this crate builds PCZTs against.
///
/// Defined here so this module is self-contained; `backend.rs` (Task 10) re-uses this alias
/// rather than redefining it.
pub(crate) type Db<P> = zcash_client_sqlite::WalletDb<
    rusqlite::Connection,
    P,
    zcash_client_sqlite::util::SystemClock,
    rand::rngs::OsRng,
>;

/// Exact ZIP-317 fee for the split transaction. The bundle disables cross-address transfers, so
/// each spend and each change output occupies its own action: `actions = n_spends + n_changes`
/// (floored at the grace count). No sapling, ironwood, or transparent components exist in a split.
pub(crate) fn split_fee(n_spends: usize, n_changes: usize) -> u64 {
    let actions = (n_spends as u64).saturating_add(n_changes as u64);
    MARGINAL_FEE_ZATOSHI * actions.max(GRACE_ACTIONS)
}

/// The note-split's resolved outputs, each already mapped to its real (post-shuffle) action index:
/// the self-funding migration notes (to be migration-locked) and, if the real balance left
/// anything over, one plain Orchard-pool change output holding exactly the leftover. `change` is
/// never migration-locked — it is ordinary spendable balance, left for the user to spend normally
/// or migrate manually later (per spec: values too small to plan a denomination for are left in
/// the wallet, not forced into a migration note).
pub(crate) struct SplitOutputs {
    pub(crate) migration_notes: Vec<(u32, u64)>,
    // Not yet read outside this module: surfacing the leftover amount to the platform (so it can
    // offer the sub-1-ZEC "also migrate this" opt-in) is follow-up work.
    #[allow(dead_code)]
    pub(crate) change: Option<(u32, u64)>,
}

/// Resolve the transaction's real balance against the planned migration-note values, deciding
/// whether the split needs an extra plain Orchard-pool change output for the leftover.
///
/// The migration notes always keep their exact planned values. The denomination plan was made
/// against an estimated fee and a balance snapshot that can drift from the real fee computed here
/// (which depends on the real spend count); drifting a migration note's value to absorb that
/// difference would leak the drift amount when the note is later spent in a migration transfer,
/// breaking the "clean power-of-ten crossing value" the self-funding note exists to provide. Any
/// leftover — fee-estimate drift plus genuine dust — becomes its own plain change output instead,
/// sized to whatever remains once *that* output's own marginal fee is paid.
///
/// If the leftover is smaller than one marginal action fee (so a dedicated change output would
/// cost more to include than it is worth), it is paid into the transaction fee instead — the only
/// case in which a leftover is absorbed rather than surfaced, and always for less than
/// [`MARGINAL_FEE_ZATOSHI`].
///
/// Returns `(fee, change)`: the exact fee to build with, and the change output's value if one is
/// needed.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if there are no planned outputs, or if the real fee is
/// higher than planned by more than the selected total (net of the planned migration outputs) can
/// cover — the split must be re-planned with a fee estimate that reserves enough headroom (see
/// [`crate::context::MigrationContext::prepare_note_split`]) rather than shrinking a migration
/// note to make up the difference.
pub(crate) fn finalize_split_outputs(
    n_spends: usize,
    selected_total: u64,
    outputs: &[u64],
) -> Result<(u64, Option<u64>), MigrationError> {
    if outputs.is_empty() {
        return Err(MigrationError::Pipeline(
            "note split: no outputs to adjust".into(),
        ));
    }
    let planned: u64 = outputs.iter().sum();
    let fee_without_change = split_fee(n_spends, outputs.len());
    let required = selected_total
        .checked_sub(fee_without_change)
        .ok_or_else(|| {
            MigrationError::Pipeline(format!(
                "note split: fee {fee_without_change} exceeds selected total {selected_total}"
            ))
        })?;
    let leftover = required.checked_sub(planned).ok_or_else(|| {
        MigrationError::Pipeline(format!(
            "note split: real fee exceeds the plan by more than the selected total can cover \
             (required {required} zatoshi, planned migration outputs {planned} zatoshi)"
        ))
    })?;
    if leftover == 0 {
        return Ok((fee_without_change, None));
    }
    let fee_with_change = split_fee(n_spends, outputs.len() + 1);
    let extra_action_cost = fee_with_change - fee_without_change;
    if leftover <= extra_action_cost {
        // Cheaper to pay the leftover into the fee than to mint a change output for it.
        return Ok((fee_without_change + leftover, None));
    }
    Ok((fee_with_change, Some(leftover - extra_action_cost)))
}

/// All spendable Orchard **V2** notes for `account`, excluding migration-locked notes. Selection
/// goes through [`ReservedInputSource`] so its (txid, output_index) lock filtering applies.
///
/// Upstream now tracks Ironwood as a value pool distinct from Orchard — both share the
/// `orchard::note::Note` plaintext shape, but the wallet backend accounts for them under separate
/// `ShieldedPool` variants — so selecting from `ShieldedPool::Orchard` already excludes V3
/// (Ironwood) notes. The explicit version filter below is kept anyway, defensively: at split time
/// no V3 note should exist in the Orchard-pool result in the first place.
pub(crate) fn select_spendable_orchard_notes<P: Parameters>(
    db: &Db<P>,
    account: AccountUuid,
    migration_locks: &BTreeSet<(String, u32)>,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, orchard::note::Note>>, MigrationError> {
    let (target, _anchor) = db
        .get_target_and_anchor_heights(ConfirmationsPolicy::default().trusted())?
        .ok_or(MigrationError::NotSynced)?;
    let reserved: BTreeSet<ReceivedNoteId> = BTreeSet::new();
    let source = ReservedInputSource::new(db, &reserved, migration_locks);
    let notes = source
        .select_unspent_notes(account, &[ShieldedPool::Orchard], target, &[])
        .map_err(|e| MigrationError::Pipeline(format!("note split: select notes: {e:?}")))?
        .take_orchard();
    Ok(notes
        .into_iter()
        .filter(|n| n.note().version() == orchard::note::NoteVersion::V2)
        .collect())
}

/// Build the note-split transaction as an unproven PCZT: spend every spendable Orchard V2 note and
/// fan the value into one same-address change output per planned denomination, plus (see
/// [`finalize_split_outputs`]) one further plain change output if the real balance leaves anything
/// over the plan. Runs entirely on public upstream APIs (the high-level `create_pczt_from_proposal`
/// path cannot keep V6 Orchard-protocol outputs in the Orchard pool).
///
/// Change outputs are sanctioned under the post-NU6.3 cross-address restriction: the orchard
/// builder pairs each with a fabricated zero-value spend at the change's own address, signed by
/// the normal signing flow with the wallet's spend-authorizing key (on the external-signer path,
/// the device must therefore sign those zero-value wallet-owned actions along with the real
/// spends).
///
/// Building needs only the Orchard full viewing key — the USK path derives it from the spending
/// key, the external-signer path reads it from the wallet database.
///
/// # Errors
///
/// Returns [`MigrationError::NotSynced`] if the wallet has no synced block data yet;
/// [`MigrationError::Pipeline`] if there are no spendable notes, if the requested outputs cannot
/// be balanced against the selected total (see [`finalize_split_outputs`]), if the note
/// commitment tree is missing the anchor/witness data needed to spend a selected note, or if the
/// transaction-builder/PCZT-assembly pipeline itself fails.
pub(crate) fn build_split_pczt<P: Parameters + Clone>(
    db: &mut Db<P>,
    network: &P,
    account: AccountUuid,
    orchard_fvk: &orchard::keys::FullViewingKey,
    migration_locks: &BTreeSet<(String, u32)>,
    outputs: &[u64],
) -> Result<(pczt::Pczt, SplitOutputs), MigrationError> {
    // --- immutable phase: select the notes to consolidate ---
    let notes = select_spendable_orchard_notes(db, account, migration_locks)?;
    if notes.is_empty() {
        return Err(MigrationError::Pipeline(
            "note split: no spendable Orchard notes".into(),
        ));
    }
    let selected_total: u64 = notes.iter().map(|n| n.note().value().inner()).sum();
    let (_fee, change) = finalize_split_outputs(notes.len(), selected_total, outputs)?;
    let mut requested: Vec<u64> = outputs.to_vec();
    if let Some(change_value) = change {
        requested.push(change_value);
    }

    let (target, anchor_height) = db
        .get_target_and_anchor_heights(ConfirmationsPolicy::default().trusted())?
        .ok_or(MigrationError::NotSynced)?;

    // --- mutable phase: anchor root + witness per spent note ---
    let (anchor, spends) = db.with_orchard_tree_mut::<_, _, MigrationError>(|tree| {
        let anchor: orchard::Anchor = tree
            .root_at_checkpoint_id(&anchor_height)?
            .ok_or_else(|| {
                MigrationError::Pipeline(format!(
                    "note split: anchor not found at height {anchor_height}"
                ))
            })?
            .into();
        let mut spends: Vec<(orchard::note::Note, orchard::tree::MerklePath)> = Vec::new();
        for received in &notes {
            let merkle_path = tree
                .witness_at_checkpoint_id_caching(
                    received.note_commitment_tree_position(),
                    &anchor_height,
                )?
                .ok_or_else(|| {
                    MigrationError::Pipeline(format!(
                        "note split: witness checkpoint pruned at {anchor_height}"
                    ))
                })?;
            spends.push((*received.note(), merkle_path.into()));
        }
        Ok((anchor, spends))
    })?;

    // --- build: n spends + k same-address change outputs, exact balance ---
    let mut builder = Builder::new(
        network.clone(),
        BlockHeight::from(target),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            // The padded default preserves the pre-configurability behavior; the note split's
            // action count (and thus `split_fee`) depends on it.
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    for (note, merkle_path) in spends {
        builder
            .add_orchard_spend::<std::convert::Infallible>(orchard_fvk.clone(), note, merkle_path)
            .map_err(|e| MigrationError::Pipeline(format!("note split: add spend: {e:?}")))?;
    }
    let change_address = orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal);
    let internal_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::Internal);
    for value in &requested {
        builder
            .add_orchard_change_output::<std::convert::Infallible>(
                orchard_fvk.clone(),
                Some(internal_ovk.clone()),
                change_address,
                Zatoshis::const_from_u64(*value),
                MemoBytes::empty(),
            )
            .map_err(|e| MigrationError::Pipeline(format!("note split: add change: {e:?}")))?;
    }

    let build_result = builder
        .build_for_pczt(OsRng, &Zip317FeeRule::standard())
        .map_err(|e| MigrationError::Pipeline(format!("note split: build: {e:?}")))?;

    // The orchard builder SHUFFLES action positions; the wallet scanner stores each received note
    // under its action index within the transaction. Map every change output (request order) to
    // its real action index via the build metadata — persisting request-order indices would make
    // the stored (txid, output_index) refs point at the wrong notes.
    let placed: Vec<(u32, u64)> = requested
        .iter()
        .enumerate()
        .map(|(i, &value)| {
            build_result
                .orchard_meta
                .output_action_index(i)
                .map(|action_index| (action_index as u32, value))
                .ok_or_else(|| {
                    MigrationError::Pipeline(format!(
                        "note split: no action index for change output {i}"
                    ))
                })
        })
        .collect::<Result<_, _>>()?;
    // `requested` is the migration outputs (request order) with the optional plain-change value
    // appended last — split `placed` the same way so the caller knows which resolved notes to
    // migration-lock and which (the leftover) to leave ordinary, unlocked Orchard balance.
    let (migration_notes, change) = if change.is_some() {
        let (notes, change_slice) = placed.split_at(outputs.len());
        (notes.to_vec(), change_slice.first().copied())
    } else {
        (placed, None)
    };

    // --- assemble the PCZT (Creator -> IoFinalizer) ---
    let created = pczt::roles::creator::Creator::build_from_parts(build_result.pczt_parts)
        .ok_or_else(|| MigrationError::Pipeline("note split: pczt creation failed".into()))?;
    let finalized = pczt::roles::io_finalizer::IoFinalizer::new(created)
        .finalize_io()
        .map_err(|e| MigrationError::Pipeline(format!("note split: io finalize: {e:?}")))?;

    Ok((
        finalized,
        SplitOutputs {
            migration_notes,
            change,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_fee_is_marginal_fee_times_actions() {
        // Cross-address disabled: actions = spends + changes; ZIP-317 marginal fee 5000.
        assert_eq!(split_fee(1, 2), 15_000);
        assert_eq!(split_fee(1, 9), 50_000);
        assert_eq!(split_fee(2, 3), 25_000);
    }

    #[test]
    fn split_fee_applies_the_two_action_grace_floor() {
        assert_eq!(split_fee(1, 0), 10_000);
        assert_eq!(split_fee(0, 1), 10_000);
    }

    #[test]
    fn finalize_reports_no_change_when_balance_is_exact() {
        // 1 spend, 2 planned outputs: fee = split_fee(1, 2) = 15_000. Selected total leaves
        // exactly the planned outputs once that fee is paid.
        let (fee, change) = finalize_split_outputs(1, 1_000_000, &[500_000, 485_000]).unwrap();
        assert_eq!(fee, 15_000);
        assert_eq!(change, None);
    }

    #[test]
    fn finalize_never_folds_leftover_into_a_migration_note() {
        // Same inputs as the exact-balance case, but the plan undershot: outputs sum to 900_000
        // instead of 985_000, leaving an 85_000 zatoshi leftover once the (now 3-action) fee is
        // paid. The migration outputs must come back byte-for-byte unchanged; the leftover must
        // surface as a separate change value, never added to `outputs[1]`.
        let (fee, change) = finalize_split_outputs(1, 1_000_000, &[500_000, 400_000]).unwrap();
        // fee_without_change = split_fee(1, 2) = 15_000; leftover = 1_000_000 - 15_000 - 900_000
        // = 85_000. fee_with_change = split_fee(1, 3) = 20_000; extra_action_cost = 5_000.
        // leftover (85_000) > extra_action_cost, so a change output is minted.
        assert_eq!(fee, 20_000);
        assert_eq!(change, Some(80_000));
    }

    #[test]
    fn finalize_folds_sub_marginal_leftover_into_fee_not_a_note() {
        // Leftover (2_000) is smaller than the marginal cost of adding a change action (5_000):
        // cheaper to pay it into the fee than to mint a dust output for it. Still never touches a
        // migration note's value.
        let (fee, change) = finalize_split_outputs(1, 1_012_000, &[500_000, 495_000]).unwrap();
        assert_eq!(fee, 17_000);
        assert_eq!(change, None);
    }

    #[test]
    fn finalize_rejects_a_plan_the_real_fee_cannot_cover() {
        // fee_without_change = split_fee(1, 2) = 15_000; required = 1_010_000 - 15_000 = 995_000,
        // which is less than the planned outputs (1_000_000) — the plan under-reserved for the
        // real fee. Must error rather than shrink a migration note to make up the difference.
        assert!(finalize_split_outputs(1, 1_010_000, &[500_000, 500_000]).is_err());
    }

    #[test]
    fn finalize_rejects_fee_exceeding_total_and_empty_outputs() {
        assert!(finalize_split_outputs(1, 9_000, &[5_000]).is_err());
        assert!(finalize_split_outputs(1, 1_000_000, &[]).is_err());
    }
}
