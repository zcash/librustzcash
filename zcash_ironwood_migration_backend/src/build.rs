//! Pure PCZT construction: assembling the migration transactions from plain-data ingredients.
//!
//! Given the cryptographic ingredients a wallet backend supplies (the spendable notes and their
//! witnesses, the Orchard anchor, the full viewing key, the destination-pool recipient), these
//! functions build the two kinds of migration transaction as unproven [`pczt::Pczt`]s:
//!
//! - [`build_split_pczt`]: the note-split (Phase 1), a same-pool send-to-self that fans the
//!   spendable balance into one self-funding note per planned denomination (plus a plain change
//!   output for any leftover).
//! - [`build_transfer_pczt`]: a migration transfer (Phase 2), which spends one self-funding note and
//!   outputs its crossing value into the destination pool.
//!
//! Both run purely on the transaction [`Builder`]: they do no database or wallet-backend access.
//! Selecting the notes to spend, resolving their witnesses and the anchor, and resolving the
//! recipient address are the wallet backend's job, done separately; here they are inputs. The output
//! is an unproven PCZT for the pipeline to prove, sign, and finalize.

use std::convert::Infallible;

use rand::rngs::OsRng;

use orchard::keys::{FullViewingKey, Scope};
use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer};
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::zip317::{
    FeeRule as Zip317FeeRule, GRACE_ACTIONS, MARGINAL_FEE,
};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use crate::error::MigrationError;
use crate::wallet::SplitOutputs;

/// The internal-scope diversifier index used for the wallet's own change/split outputs.
const INTERNAL_ADDRESS_INDEX: u32 = 0;

/// The ZIP-317 marginal fee (zatoshi) per logical action.
fn marginal_fee_zatoshi() -> u64 {
    MARGINAL_FEE.into_u64()
}

/// Exact ZIP-317 fee (zatoshi) for a note-split transaction. The bundle disables cross-address
/// transfers, so each spend and each change output occupies its own action:
/// `actions = n_spends + n_changes`, floored at the ZIP-317 grace count.
fn split_fee(n_spends: usize, n_changes: usize) -> u64 {
    let actions = (n_spends as u64).saturating_add(n_changes as u64);
    marginal_fee_zatoshi() * actions.max(GRACE_ACTIONS as u64)
}

/// Resolve the transaction's real balance against the planned migration-note values, deciding
/// whether the split needs an extra plain change output for the leftover, and returning
/// `(fee, change)`.
///
/// The migration notes always keep their exact planned values; drifting one to absorb the
/// fee-estimate difference would leak that drift when the note is later spent. Any leftover
/// (fee-estimate drift plus genuine dust) becomes its own plain change output, unless the leftover
/// is smaller than one marginal action fee, in which case it is cheaper to pay it into the fee.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if there are no outputs, if the real fee exceeds the
/// selected total, or if the real fee exceeds the plan by more than the selected total (net of the
/// planned outputs) can cover.
fn finalize_split_outputs(
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
        return Ok((fee_without_change + leftover, None));
    }
    Ok((fee_with_change, Some(leftover - extra_action_cost)))
}

/// Build the note-split transaction as an unproven PCZT: spend every supplied Orchard note and fan
/// the value into one same-address change output per planned denomination in `output_values`, plus
/// one further plain change output if the real balance leaves anything over the plan.
///
/// The ingredients (which the wallet backend resolves from its note-commitment tree) are: the
/// Orchard `anchor` and, per spent note, the `(Note, MerklePath)` witness in `spends`; plus the
/// `orchard_fvk` (change outputs and their fabricated zero-value wallet-owned spends are derived
/// from it). `output_values` are the self-funding note values (`NoteSplitPlan::migration_outputs`).
///
/// Returns the finalized PCZT and the [`SplitOutputs`] mapping each requested output (migration
/// notes first, then any change) to its real post-shuffle Orchard action index.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if there are no spends, if the outputs cannot be balanced
/// against the selected total (fee versus planned outputs), or if the builder/PCZT pipeline fails.
pub fn build_split_pczt<P: Parameters + Clone>(
    params: &P,
    target_height: u32,
    orchard_fvk: &FullViewingKey,
    anchor: orchard::Anchor,
    spends: Vec<(orchard::note::Note, orchard::tree::MerklePath)>,
    output_values: &[u64],
) -> Result<(pczt::Pczt, SplitOutputs), MigrationError> {
    if spends.is_empty() {
        return Err(MigrationError::Pipeline(
            "note split: no spendable notes".into(),
        ));
    }
    let selected_total: u64 = spends.iter().map(|(note, _)| note.value().inner()).sum();
    let (_fee, change) = finalize_split_outputs(spends.len(), selected_total, output_values)?;
    let mut requested: Vec<u64> = output_values.to_vec();
    if let Some(change_value) = change {
        requested.push(change_value);
    }

    let mut builder = Builder::new(
        params.clone(),
        BlockHeight::from_u32(target_height),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_bundle_type: orchard::builder::BundleType::DEFAULT,
            ironwood_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    for (note, merkle_path) in spends {
        builder
            .add_orchard_spend::<Infallible>(orchard_fvk.clone(), note, merkle_path)
            .map_err(|e| MigrationError::Pipeline(format!("note split: add spend: {e:?}")))?;
    }
    let change_address = orchard_fvk.address_at(INTERNAL_ADDRESS_INDEX, Scope::Internal);
    let internal_ovk = orchard_fvk.to_ovk(Scope::Internal);
    for value in &requested {
        builder
            .add_orchard_change_output::<Infallible>(
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

    // The Orchard builder shuffles action positions; map each requested output (request order) to
    // its real action index so the caller stores the right (action_index, value) references.
    let placed: Vec<(u32, u64)> = requested
        .iter()
        .enumerate()
        .map(|(i, &value)| {
            build_result
                .orchard_meta
                .output_action_index(i)
                .map(|action_index| (action_index as u32, value))
                .ok_or_else(|| {
                    MigrationError::Pipeline(format!("note split: no action index for output {i}"))
                })
        })
        .collect::<Result<_, _>>()?;
    let (migration_notes, change_out) = if change.is_some() {
        let (notes, change_slice) = placed.split_at(output_values.len());
        (notes.to_vec(), change_slice.first().copied())
    } else {
        (placed, None)
    };

    let created = Creator::build_from_parts(build_result.pczt_parts)
        .ok_or_else(|| MigrationError::Pipeline("note split: pczt creation failed".into()))?;
    let finalized = IoFinalizer::new(created)
        .finalize_io()
        .map_err(|e| MigrationError::Pipeline(format!("note split: io finalize: {e:?}")))?;

    Ok((
        finalized,
        SplitOutputs::from_parts(migration_notes, change_out),
    ))
}

/// Build a migration transfer as an unproven PCZT: spend the one supplied self-funding `note` and
/// output its `crossing_value` into the destination pool (the Ironwood bundle is output-only, so it
/// is anchored against the empty tree).
///
/// The ingredients (which the wallet backend resolves) are: the Orchard `anchor` and the note's
/// `merkle_path`; the `note` itself (a self-funding note the split minted, worth
/// `crossing_value + fee buffer`); the `orchard_fvk` (to authorize the spend and derive the output
/// viewing key); and the destination-pool `recipient` (the account's own receiver). `target_height`
/// and `expiry_height` bound the transaction.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if the builder or PCZT pipeline fails.
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_pczt<P: Parameters + Clone>(
    params: &P,
    target_height: u32,
    expiry_height: u32,
    orchard_fvk: &FullViewingKey,
    anchor: orchard::Anchor,
    note: orchard::note::Note,
    merkle_path: orchard::tree::MerklePath,
    recipient: orchard::Address,
    crossing_value: u64,
) -> Result<pczt::Pczt, MigrationError> {
    let mut builder = Builder::new(
        params.clone(),
        BlockHeight::from_u32(target_height),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            // The Ironwood bundle is output-only (no spend to anchor against), but the builder still
            // needs some anchor to construct it; the empty tree is the output-only convention.
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_bundle_type: orchard::builder::BundleType::DEFAULT,
            ironwood_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    )
    .with_expiry_height(BlockHeight::from_u32(expiry_height));

    builder
        .add_orchard_spend::<Infallible>(orchard_fvk.clone(), note, merkle_path)
        .map_err(|e| MigrationError::Pipeline(format!("transfer: add spend: {e:?}")))?;
    let external_ovk = orchard_fvk.to_ovk(Scope::External);
    builder
        .add_ironwood_output::<Infallible>(
            Some(external_ovk),
            recipient,
            Zatoshis::const_from_u64(crossing_value),
            MemoBytes::empty(),
        )
        .map_err(|e| MigrationError::Pipeline(format!("transfer: add ironwood output: {e:?}")))?;

    let build_result = builder
        .build_for_pczt(OsRng, &Zip317FeeRule::standard())
        .map_err(|e| MigrationError::Pipeline(format!("transfer: build: {e:?}")))?;

    let created = Creator::build_from_parts(build_result.pczt_parts)
        .ok_or_else(|| MigrationError::Pipeline("transfer: pczt creation failed".into()))?;
    let finalized = IoFinalizer::new(created)
        .finalize_io()
        .map_err(|e| MigrationError::Pipeline(format!("transfer: io finalize: {e:?}")))?;

    Ok(finalized)
}
