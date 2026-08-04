//! Building a migration transfer transaction: spending one self-funding note and crossing its value
//! into the Ironwood pool.
//!
//! [`build_transfer_pczt`] spends a single self-funding note (one the denomination plan minted, worth its
//! crossing value plus a fee buffer) and outputs that crossing value into the destination Ironwood
//! pool, to the account's own internal (change) address as ZIP 318 requires. It has no change output:
//! the self-funding note's buffer funds the transfer's fee exactly. The Orchard spend pads to the
//! two-action minimum, but the Ironwood side is a SINGLE unpadded action (the builder permits it,
//! and it saves proving bandwidth on hardware signers), so the transfer is three logical actions,
//! matching the buffer of `2 source + 1 destination` actions. The transfer only exists post-NU6.3,
//! when the Ironwood pool is live.
//!
//! Both bundle ANCHORS — and the spent note's Merkle witness — are DEFERRED to proving time
//! ([ZIP 374]): a transfer is pre-signed long before it is proven and broadcast, against a bucketed
//! boundary anchor drawn near its future broadcast height (see
//! [`draw_anchor_boundary`](crate::scheduling::draw_anchor_boundary)), whose tree state does not
//! exist at build time. The V6 txid and sighash exclude shielded anchors, so the PCZT is built and
//! signed with ABSENT anchor and witness fields, and the consumer installs the drawn boundary
//! anchor and the funding note's witness against it through the PCZT `Updater` role immediately
//! before proving.
//!
//! [ZIP 374]: https://zips.z.cash/zip-0374

use rand_core::{CryptoRng, RngCore};

use orchard::keys::{FullViewingKey, Scope};
use zcash_primitives::transaction::builder::{BundlePadding, DeferredPcztBuilder};
use zcash_primitives::transaction::fees::zip317::{
    FeeError as Zip317FeeError, FeeRule as Zip317FeeRule,
};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use super::{AccountDerivation, BuildError, finalize_pczt};

/// The transfer's destination-pool bundle padding: a SINGLE unpadded Ironwood action. The canonical
/// transfer carries exactly one Ironwood output, and since every migration transfer shares this
/// canonical shape the one-action bundle reveals nothing extra, while saving proving bandwidth on
/// hardware signers.
const IRONWOOD_TRANSFER_PADDING: BundlePadding = BundlePadding {
    bundle_required: false,
    pad_to_minimum: Some(1),
};

/// Build a migration transfer as an unproven PCZT: spend the supplied self-funding `note` and output
/// its `crossing_value` into the Ironwood pool. The transfer's fee is funded entirely by the note's
/// buffer, so there is no change output; a build that balances proves the buffer matches the fee.
///
/// No anchor and no witness is supplied: both bundles' anchors, and the spend's Merkle witness, are
/// DEFERRED to proving time (ZIP 374; see the module docs). The wallet backend resolves only the
/// `note` itself (a self-funding note the split minted, worth `crossing_value` plus the fee buffer);
/// the `orchard_fvk` authorizes the spend, derives the output viewing key, and derives the
/// destination: per ZIP 318 the crossing is sent to the account's own internal Ironwood change
/// address. `target_height` and `expiry_height` bound the transaction; the pre-signature commits to
/// the expiry, so the caller passes the canonical expiry for the transfer's drawn broadcast
/// schedule. It mirrors the denomination plan's
/// [`crossing_values`](crate::denomination::DenominationPlan::crossing_values): one transfer per
/// self-funding note.
///
/// `account_derivation` is the ZIP 32 account the funding note belongs to. When supplied, every
/// spend the transfer still needs a signature for is stamped with the account's Orchard key path,
/// so an EXTERNAL Signer can identify it as the account's. Pass `None` only when the account has
/// no known derivation; a PCZT built without it can be signed in process (see
/// [`sign_pczt`](super::sign_pczt), which matches by key rather than by path) but not by a
/// derivation-matching Signer.
///
/// The caller supplies `rng` (a cryptographically secure RNG in production, e.g. `OsRng`; tests can
/// pass a seeded one), keeping this builder pure.
///
/// # Errors
///
/// Returns [`BuildError::Build`] if the builder or PCZT pipeline fails (including when the note's
/// buffer does not cover the transfer fee, which unbalances the transaction, and when
/// `target_height` precedes NU6.3, whose V6 format is what permits deferring the anchors).
#[allow(clippy::too_many_arguments)]
pub fn build_transfer_pczt<P, R>(
    params: &P,
    target_height: u32,
    expiry_height: u32,
    orchard_fvk: &FullViewingKey,
    note: orchard::note::Note,
    crossing_value: Zatoshis,
    account_derivation: Option<&AccountDerivation>,
    rng: R,
) -> Result<pczt::Pczt, BuildError>
where
    P: Parameters + Clone,
    R: RngCore + CryptoRng,
{
    let mut builder = DeferredPcztBuilder::new::<Zip317FeeError>(
        params.clone(),
        BlockHeight::from_u32(target_height),
        BundlePadding::DEFAULT,
        IRONWOOD_TRANSFER_PADDING,
    )
    .map_err(|e| BuildError::Build(format!("transfer: builder: {e}")))?
    .with_expiry_height(BlockHeight::from_u32(expiry_height));

    builder
        .add_orchard_spend::<Zip317FeeError>(orchard_fvk.clone(), note)
        .map_err(|e| BuildError::Build(format!("transfer: add spend: {e}")))?;

    // ZIP 318: the destination MUST be the account's own internal (change) Ironwood address, sent with
    // the internal outgoing viewing key so the wallet can recover the note. Derived here so a caller
    // cannot misdirect the crossing.
    let internal_ovk = orchard_fvk.to_ovk(Scope::Internal);
    let recipient = orchard_fvk.address_at(0u32, Scope::Internal);
    builder
        .add_ironwood_output::<Zip317FeeError>(
            Some(internal_ovk),
            recipient,
            crossing_value,
            MemoBytes::empty(),
        )
        .map_err(|e| BuildError::Build(format!("transfer: add ironwood output: {e}")))?;

    let build_result = builder
        .build_for_pczt(rng, &Zip317FeeRule::standard())
        .map_err(|e| BuildError::Build(format!("transfer: build: {e}")))?;

    finalize_pczt(params, build_result.pczt_parts, account_derivation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::value::COIN;
    use zcash_protocol::zip318::{CROSSING_DESTINATION_ACTIONS, CROSSING_SOURCE_ACTIONS};

    use crate::build::test_util::{
        account, account_derivation, assert_every_spend_is_identifiable, regtest_network,
        single_note_witness,
    };
    use zcash_primitives::transaction::fees::zip317::MARGINAL_FEE;

    use crate::denomination::{MAX_RESIDUAL_VALUE, zat};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Every self-funding note the split can mint (a crossing value plus the fee buffer, from
        /// sub-ZEC up) builds into a balanced transfer post-NU6.3, with no anchor and no witness
        /// supplied: the emitted PCZT carries ABSENT anchors and an absent witness for the real
        /// spend (ZIP 374 deferral), to be installed at proving time. A build that succeeds proves
        /// the buffer funds the transfer fee exactly, since the transfer has no change output.
        #[test]
        fn self_funding_notes_build_balanced_transfers(
            crossing_value in u64::from(MAX_RESIDUAL_VALUE)..=(1_000 * COIN),
            account_seed in any::<u64>(),
            note_seed in any::<u64>(),
        ) {
            let fvk = account(account_seed);
            let buffer = (CROSSING_SOURCE_ACTIONS + CROSSING_DESTINATION_ACTIONS)
                as u64
                * MARGINAL_FEE.into_u64();
            let note_value = crossing_value + buffer;
            // Only the note itself is needed; its witness and anchor are deferred.
            let (note, _path, _anchor) = single_note_witness(&fvk, note_value, note_seed);

            let params = regtest_network(true);
            let target_height = 100;
            let expiry_height = 140;
            let rng = ChaCha8Rng::seed_from_u64(crossing_value);
            let result = build_transfer_pczt(
                &params,
                target_height,
                expiry_height,
                &fvk,
                note,
                zat(crossing_value),
                None,
                rng,
            );

            let pczt = result.expect("a self-funding note should build a balanced transfer");
            let orchard_bundle = pczt.orchard();
            let actions = orchard_bundle.actions();
            prop_assert!(!actions.is_empty());

            // ZIP 374 deferral: both anchors are ABSENT, and exactly the one real spend carries
            // no witness (the padding dummy keeps its arbitrary witness for the prover).
            prop_assert!(orchard_bundle.anchor().is_none());
            prop_assert!(pczt.ironwood().anchor().is_none());
            let unwitnessed = actions
                .iter()
                .filter(|a| a.spend().witness().is_none())
                .count();
            prop_assert_eq!(unwitnessed, 1);
        }
    }

    /// Given the account's derivation, the transfer's real Orchard spend carries ZIP 32
    /// derivation metadata, so an external Signer can identify and sign it. The Orchard padding
    /// dummy and the Ironwood bundle's own dummy spend are pre-signed by the IO Finalizer and are
    /// correctly left without it.
    #[test]
    fn stamps_derivation_on_the_spend_needing_a_signature() {
        let fvk = account(13);
        let derivation = account_derivation(13);
        let buffer = (CROSSING_SOURCE_ACTIONS + CROSSING_DESTINATION_ACTIONS) as u64
            * MARGINAL_FEE.into_u64();
        let crossing_value = 5 * COIN;
        let (note, _path, _anchor) = single_note_witness(&fvk, crossing_value + buffer, 13);

        let pczt = build_transfer_pczt(
            &regtest_network(true),
            100,
            140,
            &fvk,
            note,
            zat(crossing_value),
            Some(&derivation),
            ChaCha8Rng::seed_from_u64(13),
        )
        .expect("a self-funding note builds a balanced transfer");

        // Exactly the one real Orchard spend still needs a signature.
        assert_eq!(assert_every_spend_is_identifiable(&pczt), 1);
    }
}
