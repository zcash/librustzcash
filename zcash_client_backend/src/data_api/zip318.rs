//! Assembling [ZIP 318] classification evidence from a decrypted transaction.
//!
//! This is the evidence source a wallet uses in production, and the only one that runs against a
//! transaction the wallet did not build. It lives here, in the backend-generic layer, rather than
//! in a store, because [`store_decrypted_tx`] is where the parsed transaction and the decrypted
//! outputs are in hand at the same moment; a store that re-derived the evidence from its own rows
//! would be a second implementation of the predicate to keep in step with this one.
//!
//! What it can observe is weaker than what the same predicate sees on an unproven transaction, for
//! a reason that is inherent rather than incidental: on chain, a zero-valued padding dummy and an
//! unrelated party's output are equally undecryptable, so no amount of work distinguishes them.
//! See [`Zip318Evidence::source_is_send_to_self`] for how the clause weakens, and [`classify`] for
//! why weakening it is sound: it admits more, never less.
//!
//! [ZIP 318]: https://zips.z.cash/zip-0318
//! [`store_decrypted_tx`]: crate::data_api::ll::wallet::store_decrypted_tx
//! [`classify`]: zcash_protocol::zip318::classify
//! [`Zip318Evidence::source_is_send_to_self`]: zcash_protocol::zip318::Zip318Evidence::source_is_send_to_self

use zcash_primitives::transaction::Transaction;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::zip318::{
    DestinationOutput, OutputOwner, PoolMigrationConstants, Zip318Classification, Zip318Evidence,
};

use crate::decrypt::{DecryptedOutput, TransferType};

/// Classifies a decrypted transaction against [ZIP 318].
///
/// `orchard_outputs` and `ironwood_outputs` are the outputs the wallet could decrypt, as
/// [`DecryptedTransaction`] reports them; an output absent from both is one the wallet cannot
/// attribute, which is not the same as one belonging to somebody else.
///
/// [ZIP 318]: https://zips.z.cash/zip-0318
/// [`DecryptedTransaction`]: crate::data_api::DecryptedTransaction
#[cfg(feature = "orchard")]
pub fn classify_decrypted_tx<AccountId, C>(
    tx: &Transaction,
    orchard_outputs: &[DecryptedOutput<(orchard::Note, orchard::ValuePool), AccountId>],
    ironwood_outputs: &[DecryptedOutput<(orchard::Note, orchard::ValuePool), AccountId>],
    constants: &C,
) -> Zip318Classification
where
    C: PoolMigrationConstants + ?Sized,
{
    zcash_protocol::zip318::classify(
        &evidence_from_decrypted_tx(tx, orchard_outputs, ironwood_outputs, constants),
        constants,
    )
}

/// The evidence behind [`classify_decrypted_tx`].
#[cfg(feature = "orchard")]
fn evidence_from_decrypted_tx<AccountId, C>(
    tx: &Transaction,
    orchard_outputs: &[DecryptedOutput<(orchard::Note, orchard::ValuePool), AccountId>],
    ironwood_outputs: &[DecryptedOutput<(orchard::Note, orchard::ValuePool), AccountId>],
    constants: &C,
) -> Zip318Evidence
where
    C: PoolMigrationConstants + ?Sized,
{
    Zip318Evidence {
        source_actions: Some(action_count(tx.orchard_bundle().map(|b| b.actions().len()))),
        destination_actions: Some(action_count(
            tx.ironwood_bundle().map(|b| b.actions().len()),
        )),
        other_bundles_present: Some(other_bundles_present(tx)),
        source_is_send_to_self: Some(is_send_to_self(orchard_outputs)),
        sole_destination_output: sole_destination_output(ironwood_outputs),
        // The height-independent form, deliberately. The reference-height form cannot be evaluated
        // before the transaction is mined, and judging it against the chain tip instead would let
        // the answer change once the transaction was mined in a later modulus period, contradicting
        // a decision already recorded.
        expiry_is_canonical: Some(constants.is_canonical_expiry_value(tx.expiry_height())),
        // Neither confirmatory clause is answerable here. Resolving the anchor to a height needs
        // the wallet's retained boundary checkpoints, and the fee needs the value of inputs the
        // wallet may not own; a store that has both may answer them and narrow the result.
        anchor_on_grid: None,
        fee_is_canonical: None,
    }
}

/// An absent bundle contributes no actions, which is what a preparation transaction's destination
/// pool looks like.
#[cfg(feature = "orchard")]
fn action_count(bundle_actions: Option<usize>) -> usize {
    bundle_actions.unwrap_or(0)
}

/// Whether the transaction carries a transparent or Sapling bundle. No ZIP 318 transaction carries
/// either, so this is a refutation on its own.
#[cfg(feature = "orchard")]
fn other_bundles_present(tx: &Transaction) -> bool {
    tx.transparent_bundle()
        .is_some_and(|b| !b.vin.is_empty() || !b.vout.is_empty())
        || tx
            .sapling_bundle()
            .is_some_and(|b| !b.shielded_spends().is_empty() || !b.shielded_outputs().is_empty())
}

/// Whether the source-pool outputs are consistent with a send-to-self.
///
/// This is the weakened clause described in the module documentation. It cannot be "every
/// value-carrying output is internal", because the outputs the wallet cannot decrypt are exactly
/// the ones it cannot classify, and a padding dummy is one of those. What it can say is that the
/// wallet received something on its own internal address here and received nothing on an external
/// one, which is the strongest sound reading available from chain data.
#[cfg(feature = "orchard")]
fn is_send_to_self<AccountId>(
    orchard_outputs: &[DecryptedOutput<(orchard::Note, orchard::ValuePool), AccountId>],
) -> bool {
    let mut any_internal = false;
    for output in orchard_outputs {
        match output.transfer_type() {
            TransferType::AccountInternal => any_internal = true,
            // An output on one of the account's own external addresses, or one the wallet sent to
            // somebody else, both mean this is not a send-to-self.
            TransferType::Incoming | TransferType::Outgoing | TransferType::WalletInternal => {
                return false;
            }
        }
    }
    any_internal
}

/// The sole destination-pool output, when the wallet can attribute exactly one.
///
/// A crossing the wallet cannot decrypt at all yields `None` (unknown), not a refutation: a
/// stranger's canonical crossing is invisible here, and claiming otherwise would be a judgement on
/// evidence we do not have.
#[cfg(feature = "orchard")]
fn sole_destination_output<AccountId>(
    ironwood_outputs: &[DecryptedOutput<(orchard::Note, orchard::ValuePool), AccountId>],
) -> Option<DestinationOutput> {
    let [output] = ironwood_outputs else {
        return None;
    };

    let (note, _pool) = output.note();

    Some(DestinationOutput {
        value: Zatoshis::from_u64(note.value().inner()).ok()?,
        owner: match output.transfer_type() {
            TransferType::AccountInternal => OutputOwner::OwnInternal,
            _ => OutputOwner::Other,
        },
    })
}
