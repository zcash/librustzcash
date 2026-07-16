//! Building a migration transfer transaction: spending one self-funding note and crossing its value
//! into the Ironwood pool.
//!
//! [`build_transfer_pczt`] spends a single self-funding note (one the note split minted, worth its
//! crossing value plus a fee buffer) and outputs that crossing value into the destination Ironwood
//! pool. It has no change output: the self-funding note's buffer funds the transfer's fee exactly
//! (the Orchard spend and the Ironwood output each pad to the two-action minimum, so the transfer is
//! four logical actions, matching the buffer of `2 source + 2 destination` actions). The transfer
//! only exists post-NU6.3, when the Ironwood pool is live.

use core::convert::Infallible;

use rand_core::{CryptoRng, RngCore};

use orchard::keys::{FullViewingKey, Scope};
use zcash_primitives::transaction::builder::Builder;
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use super::{BuildError, build_config, finalize_pczt};

/// Build a migration transfer as an unproven PCZT: spend the supplied self-funding `note` and output
/// its `crossing_value` into the Ironwood pool (which is output-only here, so it is anchored against
/// the empty tree). The transfer's fee is funded entirely by the note's buffer, so there is no change
/// output; a build that balances proves the buffer matches the fee.
///
/// The ingredients (which the wallet backend resolves) are: the Orchard `anchor` and the note's
/// `merkle_path`; the `note` itself (a self-funding note the split minted, worth
/// `crossing_value` plus the fee buffer); the `orchard_fvk` (authorizes the spend and derives the
/// output viewing key); and the destination-pool `recipient` (the account's own Ironwood receiver).
/// `target_height` and `expiry_height` bound the transaction. It mirrors the note split's
/// [`crossing_values`](crate::note_splitting::NoteSplitPlan::crossing_values): one transfer per
/// self-funding note.
///
/// The caller supplies `rng` (a cryptographically secure RNG in production, e.g. `OsRng`; tests can
/// pass a seeded one), keeping this builder pure.
///
/// # Errors
///
/// Returns [`BuildError::Build`] if the builder or PCZT pipeline fails (including when the note's
/// buffer does not cover the transfer fee, which unbalances the transaction).
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_pczt<P, R>(
    params: &P,
    target_height: u32,
    expiry_height: u32,
    orchard_fvk: &FullViewingKey,
    anchor: orchard::Anchor,
    note: orchard::note::Note,
    merkle_path: orchard::tree::MerklePath,
    recipient: orchard::Address,
    crossing_value: u64,
    rng: R,
) -> Result<pczt::Pczt, BuildError>
where
    P: Parameters + Clone,
    R: RngCore + CryptoRng,
{
    let target = BlockHeight::from_u32(target_height);
    let expiry = BlockHeight::from_u32(expiry_height);
    // The Ironwood bundle is output-only (no spend to anchor against); the empty tree is the
    // output-only anchor convention.
    let config = build_config(anchor, Some(orchard::Anchor::empty_tree()));
    let mut builder = Builder::new(params.clone(), target, config).with_expiry_height(expiry);

    builder
        .add_orchard_spend::<Infallible>(orchard_fvk.clone(), note, merkle_path)
        .map_err(|e| BuildError::Build(format!("transfer: add spend: {e:?}")))?;

    let external_ovk = orchard_fvk.to_ovk(Scope::External);
    let crossing = Zatoshis::const_from_u64(crossing_value);
    let memo = MemoBytes::empty();
    builder
        .add_ironwood_output::<Infallible>(Some(external_ovk), recipient, crossing, memo)
        .map_err(|e| BuildError::Build(format!("transfer: add ironwood output: {e:?}")))?;

    let build_result = builder
        .build_for_pczt(rng, &Zip317FeeRule::standard())
        .map_err(|e| BuildError::Build(format!("transfer: build: {e:?}")))?;

    finalize_pczt(build_result.pczt_parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::value::COIN;

    use crate::build::test_util::{account, regtest_network, single_note_witness};
    use crate::note_splitting::{FeePolicy, RESIDUAL_MIGRATION_MIN_ZATOSHI, Zip317FeePolicy};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Every self-funding note the split can mint (a crossing value plus the fee buffer, from
        /// sub-ZEC up) builds into a balanced transfer post-NU6.3. A build that succeeds proves the
        /// buffer funds the transfer fee exactly, since the transfer has no change output.
        #[test]
        fn self_funding_notes_build_balanced_transfers(
            crossing_value in RESIDUAL_MIGRATION_MIN_ZATOSHI..=(1_000 * COIN),
        ) {
            let fvk = account();
            let buffer = Zip317FeePolicy.transfer_fee_buffer_zatoshi();
            let note_value = crossing_value + buffer;
            let (note, path, anchor) = single_note_witness(&fvk, note_value);
            let recipient = fvk.address_at(0u32, Scope::External);

            let params = regtest_network(true);
            let target_height = 100;
            let expiry_height = 140;
            let rng = ChaCha8Rng::seed_from_u64(crossing_value);
            let result = build_transfer_pczt(
                &params,
                target_height,
                expiry_height,
                &fvk,
                anchor,
                note,
                path,
                recipient,
                crossing_value,
                rng,
            );

            let pczt = result.expect("a self-funding note should build a balanced transfer");
            let orchard_bundle = pczt.orchard();
            let actions = orchard_bundle.actions();
            prop_assert!(!actions.is_empty());
        }
    }
}
