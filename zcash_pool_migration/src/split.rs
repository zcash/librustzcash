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

/// Make the planned outputs balance exactly: `Σ(outputs) = selected_total − fee`, with the last
/// output absorbing the residual (the denomination plan was made against an estimated fee and the
/// wallet's balance snapshot; the builder requires an exact balance). Errors when the fee exceeds
/// the selected total, when there are no outputs, or when absorption would make the last output
/// non-positive.
pub(crate) fn adjust_outputs_for_exact_balance(
    selected_total: u64,
    fee: u64,
    outputs: &[u64],
) -> Result<Vec<u64>, MigrationError> {
    let required: u64 = selected_total.checked_sub(fee).ok_or_else(|| {
        MigrationError::Pipeline(format!(
            "note split: fee {fee} exceeds selected total {selected_total}"
        ))
    })?;
    let mut adjusted = outputs.to_vec();
    let current: u64 = adjusted.iter().sum();
    let last = adjusted
        .last_mut()
        .ok_or_else(|| MigrationError::Pipeline("note split: no outputs to adjust".into()))?;
    let new_last = (*last as i128) + (required as i128) - (current as i128);
    if new_last <= 0 {
        return Err(MigrationError::Pipeline(format!(
            "note split: residual absorption drives the last output to {new_last} zatoshi"
        )));
    }
    *last = new_last as u64;
    Ok(adjusted)
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
/// fan the value into one same-address change output per planned denomination. Runs entirely on
/// public upstream APIs (the high-level `create_pczt_from_proposal` path cannot keep V6
/// Orchard-protocol outputs in the Orchard pool). Returns the PCZT plus, per requested change
/// output, its `(action_index, value)` — the residual-adjusted value at the output's real
/// (post-shuffle) action position within the transaction.
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
/// be balanced against the selected total (see [`adjust_outputs_for_exact_balance`]), if the note
/// commitment tree is missing the anchor/witness data needed to spend a selected note, or if the
/// transaction-builder/PCZT-assembly pipeline itself fails.
pub(crate) fn build_split_pczt<P: Parameters + Clone>(
    db: &mut Db<P>,
    network: &P,
    account: AccountUuid,
    orchard_fvk: &orchard::keys::FullViewingKey,
    migration_locks: &BTreeSet<(String, u32)>,
    outputs: &[u64],
) -> Result<(pczt::Pczt, Vec<(u32, u64)>), MigrationError> {
    // --- immutable phase: select the notes to consolidate ---
    let notes = select_spendable_orchard_notes(db, account, migration_locks)?;
    if notes.is_empty() {
        return Err(MigrationError::Pipeline(
            "note split: no spendable Orchard notes".into(),
        ));
    }
    let selected_total: u64 = notes.iter().map(|n| n.note().value().inner()).sum();
    let fee = split_fee(notes.len(), outputs.len());
    let adjusted = adjust_outputs_for_exact_balance(selected_total, fee, outputs)?;

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
    for value in &adjusted {
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
    let placed: Vec<(u32, u64)> = adjusted
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

    // --- assemble the PCZT (Creator -> IoFinalizer) ---
    let created = pczt::roles::creator::Creator::build_from_parts(build_result.pczt_parts)
        .ok_or_else(|| MigrationError::Pipeline("note split: pczt creation failed".into()))?;
    let finalized = pczt::roles::io_finalizer::IoFinalizer::new(created)
        .finalize_io()
        .map_err(|e| MigrationError::Pipeline(format!("note split: io finalize: {e:?}")))?;

    Ok((finalized, placed))
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
    fn adjust_keeps_outputs_when_balance_is_exact() {
        let adjusted =
            adjust_outputs_for_exact_balance(1_000_000, 15_000, &[500_000, 485_000]).unwrap();
        assert_eq!(adjusted, vec![500_000, 485_000]);
    }

    #[test]
    fn adjust_absorbs_the_residual_in_the_last_output() {
        // Planned against an estimated fee; the exact fee differs → last output absorbs the delta.
        let adjusted =
            adjust_outputs_for_exact_balance(1_000_000, 15_000, &[500_000, 400_000]).unwrap();
        assert_eq!(adjusted, vec![500_000, 485_000]);
        let adjusted =
            adjust_outputs_for_exact_balance(1_000_000, 15_000, &[500_000, 500_000]).unwrap();
        assert_eq!(adjusted, vec![500_000, 485_000]);
    }

    #[test]
    fn adjust_rejects_a_nonpositive_last_output() {
        assert!(adjust_outputs_for_exact_balance(1_000_000, 15_000, &[985_000, 10_000]).is_err());
    }

    #[test]
    fn adjust_rejects_fee_exceeding_total_and_empty_outputs() {
        assert!(adjust_outputs_for_exact_balance(10_000, 15_000, &[5_000]).is_err());
        assert!(adjust_outputs_for_exact_balance(1_000_000, 15_000, &[]).is_err());
    }
}
