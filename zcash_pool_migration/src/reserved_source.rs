// Ported from vizor-wallet `rust/src/wallet/sync/send.rs`
// (origin/adam/qleak-pr73-orchard-librustzcash), © Chainapsis, Apache-2.0.

//! `ReservedInputSource`: an [`InputSource`] adapter that excludes notes reserved in the current
//! batch and migration-locked notes. This is the portable note-reservation technique that lets
//! each migration transfer be proposed against a distinct pre-split note. Generic over the inner
//! `InputSource` so it need not name `WalletDb`'s params.
//!
//! Adapted from the zodl_ironwood_migration prototype onto the upstream `InputSource` shape as it
//! stands today: `ShieldedProtocol` was renamed to [`ShieldedPool`], and [`ReceivedNotes`] gained a
//! third, `ironwood` pool (Ironwood notes are `orchard::note::Note` values but are tracked
//! separately from Orchard). Only the `orchard` pool is post-filtered by migration lock below,
//! matching the prototype: prepared notes awaiting a migration transfer are Orchard notes, so
//! Sapling and Ironwood notes pass through untouched. The trait's transparent-output methods
//! (`#[cfg(feature = "transparent-inputs")]` upstream) delegate to the wrapped source 1:1 with no
//! filtering, also matching the prototype: their upstream defaults panic, and reservation
//! filtering is only meaningful for shielded notes. They are implemented unconditionally — this
//! crate's own dependency declarations always unify `zcash_client_backend`'s `transparent-inputs`
//! feature on (via its `zcash_client_sqlite` dependency), so the methods exist in every build of
//! this crate, and a local `#[cfg(feature = "transparent-inputs")]` (a feature this crate does not
//! declare) would never be true and would silently compile the delegations away.

use std::collections::BTreeSet;

use transparent::address::TransparentAddress;
use transparent::bundle::OutPoint;
use zcash_client_backend::data_api::wallet::{ConfirmationsPolicy, TargetHeight};
use zcash_client_backend::data_api::{
    AccountMeta, CoinbaseFilter, InputSource, NoteFilter, ReceivedNotes, TargetValue,
};
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::wallet::{Note, ReceivedNote, WalletTransparentOutput};
use zcash_protocol::{ShieldedPool, TxId};

/// An [`InputSource`] adapter that excludes reserved and migration-locked notes.
pub(crate) struct ReservedInputSource<'a, DbT: InputSource> {
    inner: &'a DbT,
    reserved: &'a BTreeSet<DbT::NoteRef>,
    /// (lowercased txid hex, output index) pairs of migration-locked notes.
    migration_locks: &'a BTreeSet<(String, u32)>,
}

impl<'a, DbT: InputSource> ReservedInputSource<'a, DbT> {
    /// Constructs a new [`ReservedInputSource`] from its constituent parts.
    pub(crate) fn new(
        inner: &'a DbT,
        reserved: &'a BTreeSet<DbT::NoteRef>,
        migration_locks: &'a BTreeSet<(String, u32)>,
    ) -> Self {
        Self {
            inner,
            reserved,
            migration_locks,
        }
    }

    fn merged_excludes(&self, exclude: &[DbT::NoteRef]) -> Vec<DbT::NoteRef> {
        merge_excludes(exclude, self.reserved)
    }

    fn note_is_locked<N>(&self, note: &ReceivedNote<DbT::NoteRef, N>) -> bool {
        is_locked(
            self.migration_locks,
            &format!("{}", note.txid()),
            note.output_index() as u32,
        )
    }
}

impl<DbT: InputSource> InputSource for ReservedInputSource<'_, DbT> {
    type Error = DbT::Error;
    type AccountId = DbT::AccountId;
    type NoteRef = DbT::NoteRef;

    fn get_spendable_note(
        &self,
        txid: &TxId,
        protocol: ShieldedPool,
        index: u32,
        target_height: TargetHeight,
    ) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error> {
        Ok(self
            .inner
            .get_spendable_note(txid, protocol, index, target_height)?
            .filter(|note| !self.reserved.contains(note.internal_note_id()))
            .filter(|note| !self.note_is_locked(note)))
    }

    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: TargetValue,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[Self::NoteRef],
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        let selected = self.inner.select_spendable_notes(
            account,
            target_value,
            sources,
            target_height,
            confirmations_policy,
            &self.merged_excludes(exclude),
        )?;
        Ok(ReceivedNotes::new(
            selected.sapling().to_vec(),
            selected
                .orchard()
                .iter()
                .filter(|note| !self.note_is_locked(note))
                .cloned()
                .collect(),
            selected.ironwood().to_vec(),
        ))
    }

    fn select_unspent_notes(
        &self,
        account: Self::AccountId,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        let selected = self.inner.select_unspent_notes(
            account,
            sources,
            target_height,
            &self.merged_excludes(exclude),
        )?;
        Ok(ReceivedNotes::new(
            selected.sapling().to_vec(),
            selected
                .orchard()
                .iter()
                .filter(|note| !self.note_is_locked(note))
                .cloned()
                .collect(),
            selected.ironwood().to_vec(),
        ))
    }

    fn get_account_metadata(
        &self,
        account: Self::AccountId,
        selector: &NoteFilter,
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<AccountMeta, Self::Error> {
        self.inner.get_account_metadata(
            account,
            selector,
            target_height,
            &self.merged_excludes(exclude),
        )
    }

    fn get_unspent_transparent_output(
        &self,
        outpoint: &OutPoint,
        target_height: TargetHeight,
    ) -> Result<Option<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.inner
            .get_unspent_transparent_output(outpoint, target_height)
    }

    fn get_spendable_transparent_outputs(
        &self,
        address: &TransparentAddress,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        output_filter: CoinbaseFilter,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.inner.get_spendable_transparent_outputs(
            address,
            target_height,
            confirmations_policy,
            output_filter,
        )
    }

    fn get_spendable_transparent_outputs_for_addresses(
        &self,
        addresses: &[TransparentAddress],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        output_filter: CoinbaseFilter,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.inner.get_spendable_transparent_outputs_for_addresses(
            addresses,
            target_height,
            confirmations_policy,
            output_filter,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn select_spendable_transparent_outputs(
        &self,
        account: Self::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        output_filter: CoinbaseFilter,
        address_allow_list: Option<&[TransparentAddress]>,
        target_value: TargetValue,
        max_inputs: usize,
        fee_rule: &StandardFeeRule,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.inner.select_spendable_transparent_outputs(
            account,
            target_height,
            confirmations_policy,
            output_filter,
            address_allow_list,
            target_value,
            max_inputs,
            fee_rule,
        )
    }
}

/// Merge a caller-supplied exclude list with the reserved set (sorted, de-duplicated).
fn merge_excludes<T: Ord + Copy>(exclude: &[T], reserved: &BTreeSet<T>) -> Vec<T> {
    let mut merged = exclude.to_vec();
    merged.extend(reserved.iter().copied());
    merged.sort_unstable();
    merged.dedup();
    merged
}

/// Whether a note (identified by its txid display string and output index) is migration-locked.
/// The key is the lowercased txid string paired with the output index, matching the store.
fn is_locked(locks: &BTreeSet<(String, u32)>, txid_display: &str, output_index: u32) -> bool {
    locks.contains(&(txid_display.to_lowercase(), output_index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_excludes_unions_sorts_dedups() {
        let reserved: BTreeSet<u32> = [3, 1].into_iter().collect();
        assert_eq!(merge_excludes(&[2, 1, 2], &reserved), vec![1, 2, 3]);
    }

    #[test]
    fn merge_excludes_with_empty_reserved_is_sorted_dedup_excludes() {
        let reserved: BTreeSet<u32> = BTreeSet::new();
        assert_eq!(merge_excludes(&[5, 5, 4], &reserved), vec![4, 5]);
    }

    #[test]
    fn is_locked_matches_lowercased_txid_and_index() {
        let mut locks = BTreeSet::new();
        locks.insert(("aabb".to_string(), 0u32));
        assert!(is_locked(&locks, "AABB", 0));
        assert!(is_locked(&locks, "aabb", 0));
        assert!(!is_locked(&locks, "AABB", 1));
        assert!(!is_locked(&locks, "CCDD", 0));
    }
}
