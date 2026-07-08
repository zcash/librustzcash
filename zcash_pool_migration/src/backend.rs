// Portions ported from the zodl_ironwood_migration prototype's `src/backend.rs`
// (which in turn adapted vizor-wallet `rust/src/wallet/sync/send.rs`,
// origin/adam/qleak-pr73-orchard-librustzcash, © Chainapsis, Apache-2.0).

//! Wallet-backend integration for the migration engine: opening the wallet database, resolving
//! accounts and spending keys, reading Orchard/Ironwood balances and chain heights, proposing the
//! self-payment migration transfer at an explicit bucketed anchor, and driving the PCZT
//! prove/sign/finalize pipeline.
//!
//! Unlike the prototype, the migration **transfer** path is built with the upstream high-level
//! [`create_pczt_from_proposal`] (spec D4): input selection produces a [`Proposal`] restricted to
//! the Orchard pool, the proposal is realized as a version-6 PCZT with a per-transfer consensus
//! expiry, and that PCZT is proven, signed, and finalized here. The note **split** path still
//! builds directly on the transaction builder (see [`crate::split`]); this module only proves and
//! signs its already-assembled PCZT.
//!
//! Compile-verified against the current upstream APIs. Exercising the pipeline end to end against
//! live data (spec Task 13) is where the proving-key circuit-version pairing is confirmed at
//! runtime.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::path::Path;
use std::sync::OnceLock;

use rand::rngs::OsRng;
use rusqlite::Connection;
use zcash_address::ZcashAddress;
use zcash_client_backend::data_api::wallet::input_selection::{
    GreedyInputSelector, InputSelector, InputSelectorError, SpendPolicy,
};
use zcash_client_backend::data_api::wallet::{
    ConfirmationsPolicy, TargetHeight, create_pczt_from_proposal,
};
use zcash_client_backend::data_api::{Account as _, WalletCommitmentTrees, WalletRead};
use zcash_client_backend::fees::zip317::MultiOutputChangeStrategy;
use zcash_client_backend::fees::{DustOutputPolicy, SplitPolicy};
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId, WalletDb};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_primitives::transaction::TxVersion;
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{ShieldedPool, TxId};
use zip321::{Payment, TransactionRequest};

use crate::error::MigrationError;
use crate::reserved_source::ReservedInputSource;
use crate::split::Db;
use crate::store;
use crate::types::{MigrationSchedule, NoteSplitProposal, TransferProposal};

/// Spendable Orchard balance and total Ironwood balance (zatoshi) for an account.
pub(crate) struct PoolBalances {
    pub orchard_spendable: u64,
    pub ironwood_total: u64,
}

/// A proven, signed migration transaction, carried as a serialized PCZT ready for the platform to
/// extract and broadcast, alongside the finalized transaction id.
pub(crate) struct SignedPcztOutcome {
    pub txid: TxId,
    pub pczt_bytes: Vec<u8>,
}

/// Open the wallet database at `db_path` with consensus parameters `network` (any [`Parameters`]
/// impl: standard Mainnet/Testnet or a custom network). Passed straight through to [`WalletDb`].
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if the database cannot be opened.
pub(crate) fn open_wallet<P: Parameters + Clone>(
    db_path: &Path,
    network: P,
) -> Result<Db<P>, MigrationError> {
    WalletDb::for_path(db_path, network, SystemClock, OsRng)
        .map_err(|e| MigrationError::Pipeline(format!("open wallet: {e}")))
}

/// Read the account's Orchard full viewing key from the wallet database. The external-signer
/// (hardware wallet) flow builds PCZTs from the FVK alone, so this replaces the spending key on
/// that path.
///
/// # Errors
///
/// Returns [`MigrationError::InvalidState`] if the account is unknown or has no Orchard FVK, and
/// [`MigrationError::Backend`] on a database access error.
#[allow(dead_code)]
// Consumed by context (Task 12): the external-signer split/transfer PCZT builders read the
// account's Orchard FVK directly (there is no spending key on that path to derive it from).
pub(crate) fn account_orchard_fvk<P: Parameters>(
    db: &Db<P>,
    account: AccountUuid,
) -> Result<orchard::keys::FullViewingKey, MigrationError> {
    let account = db
        .get_account(account)?
        .ok_or(MigrationError::InvalidState(
            crate::error::InvalidStateError::NotApplicable("unknown account"),
        ))?;
    account
        .ufvk()
        .and_then(|ufvk| ufvk.orchard())
        .cloned()
        .ok_or(MigrationError::InvalidState(
            crate::error::InvalidStateError::NotApplicable(
                "account has no Orchard full viewing key",
            ),
        ))
}

/// Read the spendable Orchard and total Ironwood balances for `account`.
///
/// # Errors
///
/// Returns [`MigrationError::NotSynced`] if no wallet summary is available yet,
/// [`MigrationError::InvalidState`] if the account is unknown, and [`MigrationError::Backend`] on a
/// database access error.
pub(crate) fn pool_balances<P: Parameters>(
    db: &Db<P>,
    account: AccountUuid,
) -> Result<PoolBalances, MigrationError> {
    let summary = db
        .get_wallet_summary(ConfirmationsPolicy::default())?
        .ok_or(MigrationError::NotSynced)?;
    let balance = summary
        .account_balances()
        .get(&account)
        .ok_or(MigrationError::InvalidState(
            crate::error::InvalidStateError::NotApplicable("unknown account"),
        ))?;
    Ok(PoolBalances {
        orchard_spendable: u64::from(balance.orchard_balance().spendable_value()),
        ironwood_total: u64::from(balance.ironwood_balance().total()),
    })
}

/// Whether the wallet has mined the transaction with the given txid. Used to detect that the
/// denomination-split (prep) transaction has confirmed, so the migration can proceed.
///
/// # Errors
///
/// Returns [`MigrationError::Backend`] on a database access error.
pub(crate) fn is_tx_mined<P: Parameters>(db: &Db<P>, txid: TxId) -> Result<bool, MigrationError> {
    Ok(db.get_tx_height(txid)?.is_some())
}

/// Read the current target height and the wallet's natural (spendable) anchor height, as plain
/// heights.
///
/// # Errors
///
/// Returns [`MigrationError::NotSynced`] if the wallet has no scanned block data yet.
pub(crate) fn target_and_anchor<P: Parameters>(db: &Db<P>) -> Result<(u32, u32), MigrationError> {
    let (target, anchor) = native_target_and_anchor(db)?;
    Ok((u32::from(target), u32::from(anchor)))
}

/// [`target_and_anchor`] in the backend's native types, for callers that feed the proposal APIs
/// directly.
///
/// # Errors
///
/// Returns [`MigrationError::NotSynced`] if the wallet has no scanned block data yet.
pub(crate) fn native_target_and_anchor<P: Parameters>(
    db: &Db<P>,
) -> Result<(TargetHeight, BlockHeight), MigrationError> {
    db.get_target_and_anchor_heights(ConfirmationsPolicy::default().trusted())?
        .ok_or(MigrationError::NotSynced)
}

/// Build a zip321 request paying `amount` zatoshi to `address`. Pure (no DB/network access) so it
/// is directly unit-tested; the migration is a self-send, so `address` is the account's own
/// unified address resolved by [`self_payment_request`].
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if the amount is out of range or the request cannot be
/// constructed.
fn build_self_payment(
    address: &ZcashAddress,
    amount: u64,
) -> Result<TransactionRequest, MigrationError> {
    let value = Zatoshis::from_u64(amount)
        .map_err(|e| MigrationError::Pipeline(format!("invalid migration amount: {e:?}")))?;
    let payment = Payment::without_memo(address.clone(), value);
    TransactionRequest::new(vec![payment])
        .map_err(|e| MigrationError::Pipeline(format!("construct self-payment request: {e:?}")))
}

/// Build a zip321 request paying `value` to the account's own current unified address (Ironwood
/// addresses equal the existing unified address, so the migration is a self-send).
///
/// # Errors
///
/// Returns [`MigrationError::InvalidState`] if the account has no current unified address, and
/// [`MigrationError::Backend`] on a database access error.
pub(crate) fn self_payment_request<P: Parameters>(
    db: &Db<P>,
    network: &P,
    account: AccountUuid,
    value: Zatoshis,
) -> Result<TransactionRequest, MigrationError> {
    let address = db
        .get_last_generated_address_matching(account, UnifiedAddressRequest::AllAvailableKeys)?
        .ok_or(MigrationError::InvalidState(
            crate::error::InvalidStateError::NotApplicable(
                "account has no current unified address",
            ),
        ))?
        .to_zcash_address(network.network_type());
    build_self_payment(&address, u64::from(value))
}

/// Propose a single migration transfer: spend reserved Orchard notes (excluding locked ones) at
/// the bucket-aligned `anchor_height` and emit one Ironwood (version-6) output described by
/// `request`.
///
/// Selection is restricted to the Orchard shielded pool via [`SpendPolicy::shielded_pools`], so a
/// transfer never crosses another pool boundary; change falls back to the Orchard pool (the actual
/// change routing of a version-6 transfer is validated end to end in Task 13). The proposal is
/// pinned to transaction version 6 so the realized PCZT carries the Ironwood bundle.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if input selection fails (including insufficient funds).
#[allow(clippy::too_many_arguments)]
pub(crate) fn propose_migration_transfer<'a, P: Parameters + Clone>(
    db: &'a Db<P>,
    network: &P,
    account: AccountUuid,
    target_height: u32,
    anchor_height: u32,
    reserved: &'a BTreeSet<ReceivedNoteId>,
    locks: &'a BTreeSet<(String, u32)>,
    request: TransactionRequest,
) -> Result<Proposal<Zip317FeeRule, ReceivedNoteId>, MigrationError> {
    let reserved_source = ReservedInputSource::new(db, reserved, locks);
    let change_strategy =
        MultiOutputChangeStrategy::<Zip317FeeRule, ReservedInputSource<'a, Db<P>>>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
            SplitPolicy::single_output(),
        );
    let spend_policy = SpendPolicy::shielded_pools([ShieldedPool::Orchard]);
    let input_selector = GreedyInputSelector::<ReservedInputSource<'a, Db<P>>>::new();
    input_selector
        .propose_transaction(
            network,
            &reserved_source,
            TargetHeight::from(target_height),
            BlockHeight::from_u32(anchor_height),
            ConfirmationsPolicy::default(),
            account,
            request,
            &change_strategy,
            &spend_policy,
            Some(TxVersion::V6),
        )
        .map_err(|e| MigrationError::Pipeline(format!("propose migration transfer: {e:?}")))
}

/// The exact "migrate everything" crossing value for the immediate (single-transaction) path: the
/// whole spendable Orchard balance minus the fee to spend all of it into one Ironwood output.
///
/// There is no note split to self-fund the fee, so the single sweep transfer must account for the
/// fee up front. We let the input selector compute it rather than estimating: a request for the
/// *entire* balance forces every note to be selected and fails with
/// `InsufficientFunds { required = total + fee }`, so `fee = required - available` and the crossing
/// value is `total - fee`. Returns `None` when nothing is migratable (balance at or below the fee).
///
/// # Errors
///
/// Returns [`MigrationError::NotSynced`] if the wallet has no scanned block data yet, and
/// [`MigrationError::Pipeline`] if the probe proposal fails for a reason other than insufficient
/// funds.
pub(crate) fn sweep_crossing_value<P: Parameters + Clone>(
    db: &Db<P>,
    network: &P,
    account: AccountUuid,
) -> Result<Option<u64>, MigrationError> {
    let total = pool_balances(db, account)?.orchard_spendable;
    if total == 0 {
        return Ok(None);
    }
    let (target, anchor) = native_target_and_anchor(db)?;
    let value = Zatoshis::from_u64(total)
        .map_err(|e| MigrationError::Pipeline(format!("invalid sweep total: {e:?}")))?;
    let request = self_payment_request(db, network, account, value)?;

    let reserved: BTreeSet<ReceivedNoteId> = BTreeSet::new();
    let locks: BTreeSet<(String, u32)> = BTreeSet::new();
    let reserved_source = ReservedInputSource::new(db, &reserved, &locks);
    let change_strategy =
        MultiOutputChangeStrategy::<Zip317FeeRule, ReservedInputSource<'_, Db<P>>>::new(
            Zip317FeeRule::standard(),
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
            SplitPolicy::single_output(),
        );
    let spend_policy = SpendPolicy::shielded_pools([ShieldedPool::Orchard]);
    let input_selector = GreedyInputSelector::<ReservedInputSource<'_, Db<P>>>::new();

    let fee = match input_selector.propose_transaction(
        network,
        &reserved_source,
        target,
        anchor,
        ConfirmationsPolicy::default(),
        account,
        request,
        &change_strategy,
        &spend_policy,
        Some(TxVersion::V6),
    ) {
        // The whole balance is already proposable (fee somehow covered) — read the actual fee.
        Ok(proposal) => u64::from(proposal.steps().last().balance().fee_required()),
        // Expected: requesting the whole balance falls exactly `fee` short of covering itself.
        Err(InputSelectorError::InsufficientFunds {
            available,
            required,
        }) => u64::from(required).saturating_sub(u64::from(available)),
        Err(e) => {
            return Err(MigrationError::Pipeline(format!(
                "immediate sweep probe: {e:?}"
            )));
        }
    };

    Ok(total.checked_sub(fee).filter(|crossing| *crossing > 0))
}

// ======================== Proving key (spec §10.2) ========================
//
// Built once per process (lazily; no on-disk params). The migration transfer carries an Orchard
// (version-2 spend) bundle and an Ironwood (version-3 output) bundle; the note split carries only
// an Orchard bundle. In orchard 0.15 the pczt Prover builds every action circuit at the *proving
// key's own* circuit version (`Circuit::from_action_context(.., pk.circuit_version())`), and
// `Proof::create` rejects a key only when a `disableCrossAddress = 1` instance needs the
// post-NU6.3 capability. Post-NU6.3 — the only regime in which Ironwood exists — that capability
// is required, and `OrchardCircuitVersion::PostNu6_3` is the sole version that provides it and also
// covers the cross-address-enabled case. So one `PostNu6_3` proving key serves the Orchard bundle,
// the Ironwood bundle, and the note-split bundle alike: the prototype's two distinct
// `BundleProtocol`-derived keys collapse to this single key. The exact circuit-version pairing is
// re-confirmed at runtime against a synced wallet in Task 13.

/// The single shared Orchard-family proving key (`PostNu6_3`), used for both the Orchard and
/// Ironwood bundles of a migration PCZT.
fn shielded_proving_key() -> &'static orchard::circuit::ProvingKey {
    static PK: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
    PK.get_or_init(|| {
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3)
    })
}

/// Prove an assembled PCZT: the Orchard bundle, and (when the transaction carries one) the Ironwood
/// bundle. Both are proved with the same `PostNu6_3` key (see the module notes above).
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if proof generation fails.
pub(crate) fn prove_pczt(pczt: pczt::Pczt) -> Result<pczt::Pczt, MigrationError> {
    let mut prover = pczt::roles::prover::Prover::new(pczt);
    if prover.requires_orchard_proof() {
        prover = prover
            .create_orchard_proof(shielded_proving_key())
            .map_err(|e| MigrationError::Pipeline(format!("orchard proof: {e:?}")))?;
    }
    if prover.requires_ironwood_proof() {
        prover = prover
            .create_ironwood_proof(shielded_proving_key())
            .map_err(|e| MigrationError::Pipeline(format!("ironwood proof: {e:?}")))?;
    }
    Ok(prover.finish())
}

/// Sign every Orchard spend that belongs to the wallet. Action positions are randomized (qleak
/// decoys), so we try every index from 0 upward, terminating on `InvalidIndex` and ignoring
/// wrong-key actions (decoy/padding positions the wallet does not control).
///
/// The Ironwood bundle of a migration transfer is **output only** — value crosses *into* Ironwood,
/// so there are no Ironwood spends to authorize — hence `sign_ironwood` is deliberately never
/// called (spec §10).
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if the signer cannot be constructed or a spend fails to
/// sign for a reason other than a wrong key.
pub(crate) fn sign_all_orchard_spends(
    pczt: pczt::Pczt,
    usk: &UnifiedSpendingKey,
) -> Result<pczt::Pczt, MigrationError> {
    let mut signer = pczt::roles::signer::Signer::new(pczt)
        .map_err(|e| MigrationError::Pipeline(format!("pczt signer init: {e:?}")))?;
    let ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());
    for index in 0.. {
        match signer.sign_orchard(index, &ask) {
            Err(pczt::roles::signer::Error::InvalidIndex) => break,
            Ok(())
            | Err(pczt::roles::signer::Error::OrchardSign(
                orchard::pczt::SignerError::WrongSpendAuthorizingKey,
            )) => {}
            Err(e) => return Err(MigrationError::Pipeline(format!("sign orchard: {e:?}"))),
        }
    }
    Ok(signer.finish())
}

/// Prove, sign, finalize, and serialize an assembled PCZT, returning the serialized PCZT and the
/// finalized transaction id. Shared by the migration transfers and the note split.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if any of proving, signing, spend finalization,
/// serialization, or extraction fails.
pub(crate) fn prove_sign_finalize(
    pczt: pczt::Pczt,
    usk: &UnifiedSpendingKey,
) -> Result<SignedPcztOutcome, MigrationError> {
    let pczt = prove_pczt(pczt)?;
    let pczt = sign_all_orchard_spends(pczt, usk)?;
    let pczt = pczt::roles::spend_finalizer::SpendFinalizer::new(pczt)
        .finalize_spends()
        .map_err(|e| MigrationError::Pipeline(format!("finalize spends: {e:?}")))?;
    // `serialize` and `TransactionExtractor::new` both consume the PCZT, so clone before serializing
    // and extract from the original (the extractor verifies proofs, signatures, and the binding sig).
    let pczt_bytes = pczt
        .clone()
        .serialize()
        .map_err(|e| MigrationError::Pipeline(format!("serialize pczt: {e:?}")))?;
    let tx = pczt::roles::tx_extractor::TransactionExtractor::new(pczt)
        .extract()
        .map_err(|e| MigrationError::Pipeline(format!("extract tx: {e:?}")))?;
    Ok(SignedPcztOutcome {
        txid: tx.txid(),
        pczt_bytes,
    })
}

/// Merge an externally produced signature PCZT into the crate's staged (proven, unsigned) original,
/// finalize, and extract — the external-signer counterpart of the signing tail of
/// [`prove_sign_finalize`].
///
/// The combine step rejects any effecting-data mismatch between the two PCZTs, so a signed PCZT
/// that does not correspond to the staged original cannot be stored; extraction then verifies the
/// proofs and every signature before the broadcastable form is returned.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if either PCZT cannot be parsed, if combining or spend
/// finalization fails, or if serialization/extraction fails.
#[allow(dead_code)]
// Consumed by context (Task 12).
pub(crate) fn combine_signed_pczt(
    proven: &[u8],
    signed: &[u8],
) -> Result<SignedPcztOutcome, MigrationError> {
    let proven = pczt::Pczt::parse(proven)
        .map_err(|e| MigrationError::Pipeline(format!("parse staged pczt: {e:?}")))?;
    let signed = pczt::Pczt::parse(signed)
        .map_err(|e| MigrationError::Pipeline(format!("parse signed pczt: {e:?}")))?;
    let combined = pczt::roles::combiner::Combiner::new(vec![proven, signed])
        .combine()
        .map_err(|e| MigrationError::Pipeline(format!("combine signed pczt: {e:?}")))?;
    let finalized = pczt::roles::spend_finalizer::SpendFinalizer::new(combined)
        .finalize_spends()
        .map_err(|e| MigrationError::Pipeline(format!("finalize spends: {e:?}")))?;
    let pczt_bytes = finalized
        .clone()
        .serialize()
        .map_err(|e| MigrationError::Pipeline(format!("serialize pczt: {e:?}")))?;
    let tx = pczt::roles::tx_extractor::TransactionExtractor::new(finalized)
        .extract()
        .map_err(|e| MigrationError::Pipeline(format!("extract tx: {e:?}")))?;
    Ok(SignedPcztOutcome {
        txid: tx.txid(),
        pczt_bytes,
    })
}

/// Extract the broadcast-ready consensus transaction bytes from a serialized signed PCZT. The
/// platform calls this immediately before broadcasting.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if the PCZT cannot be parsed, extracted, or the transaction
/// cannot be encoded.
pub(crate) fn extract_broadcast_tx(pczt_bytes: &[u8]) -> Result<Vec<u8>, MigrationError> {
    let pczt = pczt::Pczt::parse(pczt_bytes)
        .map_err(|e| MigrationError::Pipeline(format!("parse pczt: {e:?}")))?;
    let tx = pczt::roles::tx_extractor::TransactionExtractor::new(pczt)
        .extract()
        .map_err(|e| MigrationError::Pipeline(format!("extract tx: {e:?}")))?;
    let mut bytes = Vec::new();
    tx.write(&mut bytes)
        .map_err(|e| MigrationError::Pipeline(format!("encode tx: {e}")))?;
    Ok(bytes)
}

/// Realize a migration-transfer proposal as an unsigned version-6 PCZT via the upstream high-level
/// path, overriding the consensus expiry with `expiry_height` so the pre-signed transfer stays
/// valid across its whole send window.
///
/// This is the piece that replaces the prototype's hand-built transfer transaction (spec D4): the
/// proposal's Ironwood-protocol outputs and Orchard-pool spends are assembled, I/O-finalized, and
/// returned ready for [`prove_sign_finalize`].
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if PCZT creation fails (including an expiry height below the
/// proposal's minimum target height).
pub(crate) fn create_transfer_pczt<P: Parameters + Clone>(
    db: &mut Db<P>,
    network: &P,
    account: AccountUuid,
    proposal: &Proposal<Zip317FeeRule, ReceivedNoteId>,
    expiry_height: u32,
) -> Result<pczt::Pczt, MigrationError> {
    // `InputsErrT` and `ChangeErrT` appear only in the discarded error type; `Infallible` matches
    // upstream's own callers (the proposal is already built, so neither error can occur here).
    create_pczt_from_proposal::<_, _, Infallible, _, Infallible, _>(
        db,
        network,
        account,
        OvkPolicy::Sender,
        proposal,
        Some(BlockHeight::from_u32(expiry_height)),
    )
    .map_err(|e| MigrationError::Pipeline(format!("create transfer pczt: {e:?}")))
}

/// Pin the note commitment trees' retained ("anchor") checkpoint at `anchor_height` on both the
/// Orchard and Ironwood trees for the duration of a signing loop (spec D5).
///
/// Pinning is hardening, not correctness: witnesses bake into the PCZT at sign time, so a failure
/// to pin is non-fatal and is intentionally swallowed. `ensure_retained` marks the checkpoint
/// exempt from ordinary pruning so a long-running schedule cannot lose its anchor mid-flight.
pub(crate) fn retain_anchor<P: Parameters>(
    db: &mut Db<P>,
    anchor_height: u32,
) -> Result<(), MigrationError> {
    let anchor = BlockHeight::from_u32(anchor_height);
    // Non-fatal: pinning failure does not compromise a PCZT whose witnesses are already baked.
    let _ = db.with_orchard_tree_mut::<_, (), MigrationError>(|tree| {
        tree.ensure_retained(anchor)?;
        Ok(())
    });
    let _ = db.with_ironwood_tree_mut::<_, (), MigrationError>(|tree| {
        tree.ensure_retained(anchor)?;
        Ok(())
    });
    Ok(())
}

/// Release the retained anchor checkpoints below `below`, allowing them to be pruned normally again
/// (spec D5). Called with `anchor + 1` after a signing loop to release exactly the pinned anchor.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if the commitment tree update fails.
pub(crate) fn release_retained_anchors<P: Parameters>(
    db: &mut Db<P>,
    below: u32,
) -> Result<(), MigrationError> {
    db.remove_retained_checkpoints_below(BlockHeight::from_u32(below))
        .map_err(|e| MigrationError::Pipeline(format!("release retained anchors: {e:?}")))
}

/// The internal note ids a proposal selected as inputs, so successive transfers can reserve them.
pub(crate) fn proposal_note_refs(
    proposal: &Proposal<Zip317FeeRule, ReceivedNoteId>,
) -> Vec<ReceivedNoteId> {
    proposal
        .steps()
        .iter()
        .flat_map(|step| step.shielded_inputs())
        .flat_map(|inputs| inputs.notes().iter())
        .map(|note| *note.internal_note_id())
        .collect()
}

/// Map a schedule transfer plus its proposal and finalized PCZT to the pending row the store
/// persists: the crossing value and heights come from the [`TransferProposal`], the fee from the
/// proposal's single step, and the selected-note triple from that step's first shielded input.
pub(crate) fn pending_row(
    t: &TransferProposal,
    proposal: &Proposal<Zip317FeeRule, ReceivedNoteId>,
    signed: &SignedPcztOutcome,
) -> store::PendingTxRow {
    let head_step = &proposal.steps().head;
    let fee = u64::from(head_step.balance().fee_required());
    let (selected_note_txid, selected_note_output_index, selected_note_value) =
        match head_step.shielded_inputs() {
            Some(inputs) => {
                let note = &inputs.notes().head;
                (
                    note.txid().to_string(),
                    note.output_index() as u32,
                    u64::from(note.note().value()),
                )
            }
            None => (String::new(), 0, 0),
        };
    store::PendingTxRow {
        txid_hex: signed.txid.to_string(),
        raw_pczt: signed.pczt_bytes.clone(),
        anchor_height: u32::from(t.anchor_height()),
        target_height: u32::from(t.next_executable_after_height()),
        next_executable_after_height: u32::from(t.next_executable_after_height()),
        expiry_height: u32::from(t.expiry_height()),
        value_zatoshi: u64::from(t.amount()),
        fee_zatoshi: fee,
        selected_note_txid,
        selected_note_output_index,
        selected_note_value,
        status: "scheduled".to_string(),
        metadata_json: "{}".to_string(),
    }
}

/// Build a signed PCZT for every scheduled transfer at the schedule's shared bucketed anchor and
/// persist each as a pending transaction.
///
/// The shared anchor is pinned for the duration of the loop (spec D5); each transfer is proposed
/// against the cumulative set of notes reserved by prior transfers (so no two transfers spend the
/// same note), realized as a version-6 PCZT with its own consensus expiry, proven, signed, and
/// finalized. The pin is released only after the whole loop succeeds.
///
/// # Errors
///
/// Returns [`MigrationError::NotSynced`] if the wallet has no scanned block data yet, and
/// [`MigrationError::Pipeline`]/[`MigrationError::Backend`] if any transfer fails to propose,
/// build, sign, or persist.
pub(crate) fn sign_schedule<P: Parameters + Clone>(
    db: &mut Db<P>,
    network: &P,
    account: AccountUuid,
    conn: &Connection,
    run_id: &str,
    schedule: &MigrationSchedule,
    usk: &UnifiedSpendingKey,
) -> Result<(), MigrationError> {
    let account_str = account.expose_uuid().to_string();
    // The natural target is shared by every transfer; each transfer's anchor is its own bucketed
    // anchor (identical across a schedule, per `TransferProposal::anchor_height`).
    let (target, _natural_anchor) = target_and_anchor(db)?;
    // Exclude the run's OWN prepared notes from the lock set — the transfers exist to spend them.
    let locks = store::locked_note_refs(conn, &account_str, Some(run_id))?;

    // Pin the schedule's shared anchor once for the whole signing loop.
    let pinned_anchor = schedule
        .transfers()
        .first()
        .map(|t| u32::from(t.anchor_height()));
    if let Some(anchor) = pinned_anchor {
        retain_anchor(db, anchor)?;
    }

    let mut reserved: BTreeSet<ReceivedNoteId> = BTreeSet::new();
    for t in schedule.transfers() {
        let request = self_payment_request(db, network, account, t.amount())?;
        let proposal = propose_migration_transfer(
            db,
            network,
            account,
            target,
            u32::from(t.anchor_height()),
            &reserved,
            &locks,
            request,
        )?;
        reserved.extend(proposal_note_refs(&proposal));
        let pczt = create_transfer_pczt(
            db,
            network,
            account,
            &proposal,
            u32::from(t.expiry_height()),
        )?;
        let signed = prove_sign_finalize(pczt, usk)?;
        store::insert_pending_txs(conn, run_id, &[pending_row(t, &proposal, &signed)])?;
    }

    // Release the pin only after a fully successful loop.
    if let Some(anchor) = pinned_anchor {
        release_retained_anchors(db, anchor + 1)?;
    }
    Ok(())
}

/// Build, sign (as a PCZT), and persist the note-split (denomination prep) transaction: spend the
/// wallet's version-2 notes and fan the value into one same-address change output per planned
/// denomination. Stored notes carry the residual-adjusted values at their real (shuffled) action
/// indices, so the `(txid, output_index)` refs match what the scanner records.
///
/// # Errors
///
/// Returns [`MigrationError::NotSynced`] if the wallet has no scanned block data yet, and
/// [`MigrationError::Pipeline`]/[`MigrationError::Backend`] if the split cannot be built, signed, or
/// persisted.
pub(crate) fn sign_split<P: Parameters + Clone>(
    db: &mut Db<P>,
    network: &P,
    account: AccountUuid,
    conn: &Connection,
    run_id: &str,
    proposal: &NoteSplitProposal,
    usk: &UnifiedSpendingKey,
) -> Result<SignedPcztOutcome, MigrationError> {
    let account_str = account.expose_uuid().to_string();
    // Exclude this run's own (not-yet-existing) notes for symmetry; other live runs' stay locked.
    let locks = store::locked_note_refs(conn, &account_str, Some(run_id))?;
    let orchard_fvk = orchard::keys::FullViewingKey::from(usk.orchard());
    let outputs: Vec<u64> = proposal
        .output_values()
        .iter()
        .map(|v| u64::from(*v))
        .collect();
    let (pczt, placed_outputs) =
        crate::split::build_split_pczt(db, network, account, &orchard_fvk, &locks, &outputs)?;
    let signed = prove_sign_finalize(pczt, usk)?;
    store::insert_prep_tx(
        conn,
        run_id,
        &signed.txid.to_string(),
        &signed.pczt_bytes,
        "pending",
    )?;
    let prepared: Vec<store::PreparedNote> = placed_outputs
        .iter()
        .map(|&(action_index, value_zatoshi)| store::PreparedNote {
            txid_hex: signed.txid.to_string(),
            output_index: action_index,
            value_zatoshi,
            note_version: 2,
            nullifier_hex: None,
            lock_state: "locked".to_string(),
        })
        .collect();
    store::insert_prepared_notes(conn, run_id, &prepared)?;
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_self_payment_creates_single_payment_for_amount() {
        let address: ZcashAddress =
            "ztestsapling1ctuamfer5xjnnrdr3xdazenljx0mu0gutcf9u9e74tr2d3jwjnt0qllzxaplu54hgc2tyjdc2p6"
                .parse()
                .expect("address parses");
        let req = build_self_payment(&address, 100_000_000).expect("request builds");
        assert_eq!(req.payments().len(), 1);
        let payment = req.payments().values().next().expect("one payment");
        assert_eq!(payment.amount().map(u64::from), Some(100_000_000));
    }
}
