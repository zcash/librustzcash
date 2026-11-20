//! Building a migration transfer transaction: spending one self-funding note and crossing its value
//! into the Ironwood pool.
//!
//! [`build_transfer_pczt`] spends a single self-funding note (one the denomination plan minted, worth its
//! crossing value plus a fee buffer) and outputs that crossing value into the destination Ironwood
//! pool, to the account's own internal (change) address as ZIP 318 requires. It pays the ZIP 317
//! fee in effect at its target height; the self-funding note's buffer is expected to fund that fee
//! exactly; any surplus is otherwise returned as one Orchard change output.
//! The Orchard spend pads to the two-action minimum, but the Ironwood side is a SINGLE unpadded
//! action (the builder permits it, and it saves proving bandwidth on hardware signers), so the
//! transfer is three logical actions, matching the buffer of `2 source + 1 destination` actions.
//! The transfer only exists post-NU6.3, when the Ironwood pool is live.
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

use rand_core::{CryptoRng, Rng};

use orchard::keys::{FullViewingKey, Scope};
use zcash_primitives::transaction::builder::{BundlePadding, DeferredPcztBuilder};
use zcash_primitives::transaction::fees::zip317::{
    FeeError as Zip317FeeError, FeeRule as Zip317FeeRule,
};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use super::{AccountDerivation, BuildError, finalize_pczt};
use crate::engine::canonical_transfer_fee;

/// The transfer's destination-pool bundle padding: a SINGLE unpadded Ironwood action. The canonical
/// transfer carries exactly one Ironwood output, and since every migration transfer shares this
/// canonical shape the one-action bundle reveals nothing extra, while saving proving bandwidth on
/// hardware signers.
const IRONWOOD_TRANSFER_PADDING: BundlePadding = BundlePadding {
    bundle_required: false,
    pad_to_minimum: Some(1),
};

/// How a transfer disposes of value its funding note leaves over the crossing plus the fee.
#[derive(Clone, Copy, Debug)]
pub(crate) enum TransferChange {
    /// Fail the build ([`BuildError::Build`]).
    Forbid,
    /// Return it to the account's internal Orchard address as one change output.
    ReturnToOrchard,
}

/// Build a migration transfer as an unproven PCZT: spend the supplied self-funding `note` and output
/// its `crossing_value` into the Ironwood pool. The transfer pays the ZIP 317 fee in effect at
/// `target_height`, funded entirely by the note's buffer: there is no change output, so a build
/// that balances proves the buffer matches that fee.
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
/// The caller supplies `rng`, which provides the randomness for building the transaction and for
/// signing its dummy spends. It must be a cryptographically secure RNG in production; tests can
/// pass a seeded one. This keeps the builder pure.
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
    R: Rng + CryptoRng,
{
    build_transfer_pczt_with_change(
        params,
        BlockHeight::from_u32(target_height),
        BlockHeight::from_u32(expiry_height),
        orchard_fvk,
        note,
        crossing_value,
        account_derivation,
        TransferChange::Forbid,
        rng,
    )
    .map(|(pczt, _)| pczt)
}

/// [`build_transfer_pczt`] with `change` deciding the surplus of the note over the crossing plus
/// the fee; the second element is the Orchard change value when one was added.
///
/// # Errors
///
/// As [`build_transfer_pczt`]; under [`TransferChange::ReturnToOrchard`] a note that does not cover
/// the crossing plus the fee at `target_height` is [`BuildError::Balance`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_transfer_pczt_with_change<P, R>(
    params: &P,
    target_height: BlockHeight,
    expiry_height: BlockHeight,
    orchard_fvk: &FullViewingKey,
    note: orchard::note::Note,
    crossing_value: Zatoshis,
    account_derivation: Option<&AccountDerivation>,
    change: TransferChange,
    mut rng: R,
) -> Result<(pczt::Pczt, Option<Zatoshis>), BuildError>
where
    P: Parameters + Clone,
    R: Rng + CryptoRng,
{
    let mut builder = DeferredPcztBuilder::new::<Zip317FeeError>(
        params.clone(),
        target_height,
        BundlePadding::DEFAULT,
        IRONWOOD_TRANSFER_PADDING,
    )
    .map_err(|e| BuildError::Build(format!("transfer: builder: {e}")))?
    .with_expiry_height(expiry_height);

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
            Some(internal_ovk.clone()),
            recipient,
            crossing_value,
            MemoBytes::empty(),
        )
        .map_err(|e| BuildError::Build(format!("transfer: add ironwood output: {e}")))?;

    let orchard_change = match change {
        TransferChange::Forbid => None,
        TransferChange::ReturnToOrchard => {
            let fee = canonical_transfer_fee(params, target_height)
                .map_err(|e| BuildError::Build(format!("transfer: fee: {e}")))?;
            let note_value = Zatoshis::from_u64(note.value().inner()).map_err(|_| {
                BuildError::Balance("transfer: the note's value is not a valid amount".into())
            })?;
            let surplus = (note_value - crossing_value)
                .and_then(|v| v - fee)
                .ok_or_else(|| {
                    BuildError::Balance(format!(
                        "transfer: the funding note ({}) does not cover the crossing ({}) plus \
                         the fee ({}) at height {target_height}",
                        u64::from(note_value),
                        u64::from(crossing_value),
                        u64::from(fee),
                    ))
                })?;
            if surplus == Zatoshis::ZERO {
                None
            } else {
                // A change output pairs with a wallet-controlled zero-valued spend in one action,
                // keeping the Orchard side at the canonical two actions.
                builder
                    .add_orchard_change_output::<Zip317FeeError>(
                        orchard_fvk.clone(),
                        Some(internal_ovk),
                        recipient,
                        surplus,
                        MemoBytes::empty(),
                    )
                    .map_err(|e| BuildError::Build(format!("transfer: add change output: {e}")))?;
                Some(surplus)
            }
        }
    };

    let build_result = builder
        .build_for_pczt(&mut rng, &Zip317FeeRule::standard())
        .map_err(|e| BuildError::Build(format!("transfer: build: {e}")))?;

    let pczt = finalize_pczt(rng, params, build_result.pczt_parts, account_derivation)?;
    Ok((pczt, orchard_change))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::{
        local_consensus::LocalNetwork,
        value::COIN,
        zip318::{CROSSING_DESTINATION_ACTIONS, CROSSING_SOURCE_ACTIONS},
    };

    use crate::build::test_util::{
        TARGET_HEIGHT, account, account_derivation, assert_every_spend_is_identifiable,
        regtest_network, single_note_witness,
    };
    use crate::denomination::{MAX_RESIDUAL_VALUE, zat};

    /// The regtest height from which ZIP 317 Revision 2 applies (the NU7 activation height).
    const FEE_REDUCTION_HEIGHT: BlockHeight = BlockHeight::from_u32(1_000);
    /// Blocks between a test transfer's target height and its expiry height.
    const EXPIRY_WINDOW: u32 = 40;

    /// A regtest network with NU6.3 active and the fee reduction at [`FEE_REDUCTION_HEIGHT`].
    fn network() -> LocalNetwork {
        LocalNetwork {
            nu7: Some(FEE_REDUCTION_HEIGHT),
            ..regtest_network(true)
        }
    }

    /// Builds a transfer of `crossing_value` from a fresh note of `note_value` at `target_height`,
    /// disposing of any surplus per `change`.
    fn build(
        params: &LocalNetwork,
        target_height: BlockHeight,
        fvk: &FullViewingKey,
        note_value: u64,
        note_seed: u64,
        crossing_value: u64,
        change: TransferChange,
    ) -> Result<(pczt::Pczt, Option<Zatoshis>), BuildError> {
        // Only the note itself is needed; its witness and anchor are deferred.
        let (note, _path, _anchor) = single_note_witness(fvk, note_value, note_seed);
        build_transfer_pczt_with_change(
            params,
            target_height,
            target_height + EXPIRY_WINDOW,
            fvk,
            note,
            zat(crossing_value),
            Some(&account_derivation(note_seed)),
            change,
            ChaCha8Rng::seed_from_u64(note_seed),
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Every self-funding note the split can mint (a crossing value plus the fee buffer in
        /// effect at its target height, from sub-ZEC up) builds into a balanced transfer post-NU6.3
        /// on either side of the fee reduction, with no change and no anchor or witness supplied:
        /// the emitted PCZT carries ABSENT anchors and an absent witness for the real spend (ZIP 374
        /// deferral), and presents exactly that spend to sign. A note buffered for the earlier,
        /// higher fee and built at the reduced one returns the difference as ONE Orchard change
        /// output (paired with a zero-valued spend, so two spends to sign) when change is permitted,
        /// and fails to build when it is forbidden; a note buffered for the reduced fee does not
        /// cover the earlier one.
        #[test]
        fn self_funding_notes_build_balanced_transfers(
            crossing_value in u64::from(MAX_RESIDUAL_VALUE)..=(1_000 * COIN),
            account_seed in any::<u64>(),
            note_seed in any::<u64>(),
        ) {
            let fvk = account(account_seed);
            let params = network();
            let before = FEE_REDUCTION_HEIGHT - 1;
            let fee_before = canonical_transfer_fee(&params, before).expect("the fee computes");
            let fee_after = canonical_transfer_fee(&params, FEE_REDUCTION_HEIGHT)
                .expect("the fee computes");
            prop_assert!(fee_after < fee_before, "the fee is reduced at the reduction height");

            for (target_height, fee) in [(before, fee_before), (FEE_REDUCTION_HEIGHT, fee_after)] {
                let note_value = crossing_value + u64::from(fee);
                let (pczt, change) = build(
                    &params, target_height, &fvk, note_value, note_seed, crossing_value,
                    TransferChange::ReturnToOrchard,
                ).expect("a self-funding note should build a balanced transfer");
                prop_assert_eq!(change, None);
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
                prop_assert_eq!(assert_every_spend_is_identifiable(&pczt), 1);
            }

            // The earlier buffer at the reduced fee: the surplus returns as Orchard change.
            let over_buffered = crossing_value + u64::from(fee_before);
            let (pczt, change) = build(
                &params, FEE_REDUCTION_HEIGHT, &fvk, over_buffered, note_seed, crossing_value,
                TransferChange::ReturnToOrchard,
            ).expect("the surplus is returned as change");
            prop_assert_eq!(change, fee_before - fee_after);
            prop_assert_eq!(pczt.orchard().actions().len(), CROSSING_SOURCE_ACTIONS);
            prop_assert_eq!(pczt.ironwood().actions().len(), CROSSING_DESTINATION_ACTIONS);
            prop_assert_eq!(assert_every_spend_is_identifiable(&pczt), 2);
            prop_assert!(matches!(
                build(
                    &params, FEE_REDUCTION_HEIGHT, &fvk, over_buffered, note_seed, crossing_value,
                    TransferChange::Forbid,
                ),
                Err(BuildError::Build(_))
            ));

            // The reduced buffer before the reduction does not cover the fee.
            prop_assert!(matches!(
                build(
                    &params, before, &fvk, crossing_value + u64::from(fee_after), note_seed,
                    crossing_value, TransferChange::ReturnToOrchard,
                ),
                Err(BuildError::Balance(_))
            ));
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
        let params = regtest_network(true);
        let target_height = BlockHeight::from_u32(TARGET_HEIGHT);
        let buffer = canonical_transfer_fee(&params, target_height).expect("the fee computes");
        let crossing_value = 5 * COIN;
        let (note, _path, _anchor) =
            single_note_witness(&fvk, crossing_value + u64::from(buffer), 13);

        let pczt = build_transfer_pczt(
            &params,
            TARGET_HEIGHT,
            TARGET_HEIGHT + EXPIRY_WINDOW,
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
