// Portions ported from the zodl_ironwood_migration prototype's `src/backend.rs`
// (which in turn adapted vizor-wallet `rust/src/wallet/sync/send.rs`,
// origin/adam/qleak-pr73-orchard-librustzcash, © Chainapsis, Apache-2.0).

//! Wallet-backend integration for the migration engine: opening the wallet database, resolving
//! accounts and spending keys, reading Orchard/Ironwood balances and chain heights, proposing the
//! self-payment migration transfer at the wallet's natural anchor, and driving the PCZT
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
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
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
/// Uses the *untrusted* confirmation count (10, vs. 3 for trusted/wallet-produced outputs — see
/// [`ConfirmationsPolicy`]) to pick the anchor, not the trusted one: the anchor this returns is
/// later reused as a fixed, pinned height by [`propose_migration_transfer`] and
/// [`build_self_funding_transfer_pczt`] to actually select and spend notes, via the *full*
/// `ConfirmationsPolicy::default()` (both thresholds). An anchor picked only `trusted()` (3) blocks
/// back is not necessarily far enough back for an untrusted-origin note (e.g. externally received
/// funds, which need 10) to already satisfy its own confirmation requirement relative to that same
/// anchor — even though the same note reads as spendable against the *current* tip via
/// [`pool_balances`]/[`sweep_crossing_value`]'s own `ConfirmationsPolicy::default()` checks. Picking
/// the anchor at the more conservative `untrusted()` depth keeps it consistent with what the
/// spend-side selection actually requires for either kind of note.
///
/// # Errors
///
/// Returns [`MigrationError::NotSynced`] if the wallet has no scanned block data yet.
pub(crate) fn native_target_and_anchor<P: Parameters>(
    db: &Db<P>,
) -> Result<(TargetHeight, BlockHeight), MigrationError> {
    db.get_target_and_anchor_heights(ConfirmationsPolicy::default().untrusted())?
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

/// The outcome of [`build_self_funding_transfer_pczt`]: the unproven PCZT plus everything needed
/// to persist the pending row without re-querying the wallet.
pub(crate) struct SelfFundingTransferOutcome {
    pub(crate) pczt: pczt::Pczt,
    pub(crate) spent_note_id: ReceivedNoteId,
    pub(crate) spent_note_txid: String,
    pub(crate) spent_note_output_index: u32,
    pub(crate) spent_note_value: u64,
}

/// Attempt to build a migration-transfer PCZT directly on the transaction builder, the way the
/// note split already does (spec follow-up: transfers should not run through the wallet's
/// fee/change-selection logic — a self-funding note pays its own fee out of its own buffer, full
/// stop). Looks for exactly one spendable Orchard **V2** note worth `crossing_value +
/// TRANSFER_FEE_BUFFER_ZATOSHI` (the shape a note split always mints) among notes not already
/// `reserved` by an earlier transfer in this signing loop or migration-locked by another run, and
/// if found, spends it whole into a single Ironwood output of `crossing_value` — no Orchard change
/// output, since a self-funding note's value covers the crossing plus the transfer's own fee
/// exactly.
///
/// Returns `Ok(None)` when no such note exists — the immediate/sweep migration path has no note
/// split and must select from whatever notes make up an arbitrary-sized balance, so it always
/// falls back to the wallet's ordinary input-selection pipeline
/// ([`propose_migration_transfer`]/[`create_transfer_pczt`]) instead.
///
/// # Errors
///
/// Returns [`MigrationError::NotSynced`] if the wallet has no synced block data yet, and
/// [`MigrationError::Pipeline`]/[`MigrationError::InvalidState`] if the recipient address cannot be
/// resolved, the note commitment tree is missing the anchor/witness data needed to spend the
/// selected note, or the transaction-builder/PCZT-assembly pipeline itself fails.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_self_funding_transfer_pczt<P: Parameters + Clone>(
    db: &mut Db<P>,
    network: &P,
    account: AccountUuid,
    orchard_fvk: &orchard::keys::FullViewingKey,
    crossing_value: u64,
    reserved: &BTreeSet<ReceivedNoteId>,
    locks: &BTreeSet<(String, u32)>,
    target_height: u32,
    expiry_height: u32,
) -> Result<Option<SelfFundingTransferOutcome>, MigrationError> {
    let target_note_value =
        crossing_value.saturating_add(crate::denominations::TRANSFER_FEE_BUFFER_ZATOSHI);
    let candidates = crate::split::select_spendable_orchard_notes(db, account, reserved, locks)?;
    let Some(received) = candidates
        .into_iter()
        .find(|n| n.note().value().inner() == target_note_value)
    else {
        return Ok(None);
    };

    let recipient = db
        .get_last_generated_address_matching(account, UnifiedAddressRequest::AllAvailableKeys)?
        .and_then(|ua| ua.orchard().copied())
        .ok_or(MigrationError::InvalidState(
            crate::error::InvalidStateError::NotApplicable(
                "account has no current Orchard/Ironwood receiver",
            ),
        ))?;

    let (_target, anchor_height) = native_target_and_anchor(db)?;
    let (anchor, merkle_path) = db.with_orchard_tree_mut::<_, _, MigrationError>(|tree| {
        let anchor: orchard::Anchor = tree
            .root_at_checkpoint_id(&anchor_height)?
            .ok_or_else(|| {
                MigrationError::Pipeline(format!(
                    "transfer: anchor not found at height {anchor_height}"
                ))
            })?
            .into();
        let merkle_path = tree
            .witness_at_checkpoint_id_caching(
                received.note_commitment_tree_position(),
                &anchor_height,
            )?
            .ok_or_else(|| {
                MigrationError::Pipeline(format!(
                    "transfer: witness checkpoint pruned at {anchor_height}"
                ))
            })?;
        Ok((anchor, merkle_path.into()))
    })?;

    let mut builder = Builder::new(
        network.clone(),
        BlockHeight::from_u32(target_height),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            // No Ironwood spend exists in a migration transfer to anchor against (the bundle is
            // output-only), but the builder still needs *some* anchor to construct the Ironwood
            // bundle at all — the empty-tree placeholder is upstream's own convention for an
            // output-only bundle (see zcash_primitives::transaction::builder's own coinbase/test
            // fixtures).
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            // The padded default is what the self-funding buffer (TRANSFER_FEE_BUFFER_ZATOSHI)
            // is sized for: 2 Orchard + 2 Ironwood actions.
            orchard_bundle_type: orchard::builder::BundleType::DEFAULT,
            ironwood_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    )
    .with_expiry_height(BlockHeight::from_u32(expiry_height));

    builder
        .add_orchard_spend::<std::convert::Infallible>(
            orchard_fvk.clone(),
            *received.note(),
            merkle_path,
        )
        .map_err(|e| MigrationError::Pipeline(format!("transfer: add spend: {e:?}")))?;
    let external_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    builder
        .add_ironwood_output::<std::convert::Infallible>(
            Some(external_ovk),
            recipient,
            Zatoshis::const_from_u64(crossing_value),
            MemoBytes::empty(),
        )
        .map_err(|e| MigrationError::Pipeline(format!("transfer: add ironwood output: {e:?}")))?;

    let build_result = builder
        .build_for_pczt(OsRng, &Zip317FeeRule::standard())
        .map_err(|e| MigrationError::Pipeline(format!("transfer: build: {e:?}")))?;

    let created = pczt::roles::creator::Creator::build_from_parts(build_result.pczt_parts)
        .ok_or_else(|| MigrationError::Pipeline("transfer: pczt creation failed".into()))?;
    let finalized = pczt::roles::io_finalizer::IoFinalizer::new(created)
        .finalize_io()
        .map_err(|e| MigrationError::Pipeline(format!("transfer: io finalize: {e:?}")))?;

    Ok(Some(SelfFundingTransferOutcome {
        pczt: finalized,
        spent_note_id: *received.internal_note_id(),
        spent_note_txid: received.txid().to_string(),
        spent_note_output_index: received.output_index() as u32,
        spent_note_value: received.note().value().inner(),
    }))
}

/// Propose a single migration transfer: spend reserved Orchard notes (excluding locked ones) at
/// the schedule's shared `anchor_height` (the wallet's natural anchor) and emit one Ironwood
/// (version-6) output described by `request`.
///
/// Selection is restricted to the Orchard shielded pool via [`SpendPolicy::shielded_pools`], so a
/// transfer never crosses another pool boundary; change falls back to the Orchard pool (the actual
/// change routing of a version-6 transfer is validated end to end in Task 13). The proposal is
/// pinned to transaction version 6 so the realized PCZT carries the Ironwood bundle.
///
/// This is the **fallback** path for a transfer with no matching self-funding note (see
/// [`build_self_funding_transfer_pczt`]) — in practice, the immediate/sweep migration path, which
/// has no note split and must select from whatever notes make up an arbitrary-sized balance.
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
/// Ironwood bundles of a migration PCZT. Exposed to the crate so the external-signer round-trip
/// tests fabricate their PCZTs against the exact key the pipeline proves with.
pub(crate) fn shielded_proving_key() -> &'static orchard::circuit::ProvingKey {
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
        // The padded default preserves the pre-configurability behavior (matches upstream's
        // own callers); transfer fees assume the padded two-action Orchard bundle.
        orchard::builder::BundleType::DEFAULT,
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

/// Release retained ("anchor") checkpoints, allowing them to be pruned normally again (spec D5).
/// Called with `anchor + 1` after a signing loop.
///
/// The semantics are **bulk**: this delegates to the upstream `remove_retained_checkpoints_below`,
/// which releases *every* retained checkpoint at or below `below - 1` (i.e. strictly below `below`)
/// across both the Orchard and Ironwood commitment trees — not only the single checkpoint this
/// crate pinned via [`retain_anchor`]. The migration engine only ever pins one anchor at a time, so
/// in practice `anchor + 1` releases exactly that pin; but any other checkpoints a caller had
/// retained below `below` for unrelated reasons would be released too.
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

/// The [`pending_row`] counterpart for the direct-builder ([`build_self_funding_transfer_pczt`])
/// path: the fee is derived as `spent_note_value - crossing_value` (the note-matching predicate in
/// `build_self_funding_transfer_pczt` guarantees this always equals `TRANSFER_FEE_BUFFER_ZATOSHI`
/// exactly, but computing it from the actual spent/crossing values — rather than assuming the
/// constant — keeps this row self-consistent even if that invariant ever changes). The
/// selected-note triple is passed straight through rather than read from a `Proposal`'s shielded
/// inputs (the caller takes these fields by value out of a [`SelfFundingTransferOutcome`] before
/// consuming its `pczt`, which is not `Clone`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn self_funding_pending_row(
    t: &TransferProposal,
    spent_note_txid: &str,
    spent_note_output_index: u32,
    spent_note_value: u64,
    signed: &SignedPcztOutcome,
) -> store::PendingTxRow {
    let crossing_value = u64::from(t.amount());
    store::PendingTxRow {
        txid_hex: signed.txid.to_string(),
        raw_pczt: signed.pczt_bytes.clone(),
        anchor_height: u32::from(t.anchor_height()),
        target_height: u32::from(t.next_executable_after_height()),
        next_executable_after_height: u32::from(t.next_executable_after_height()),
        expiry_height: u32::from(t.expiry_height()),
        value_zatoshi: crossing_value,
        fee_zatoshi: spent_note_value.saturating_sub(crossing_value),
        selected_note_txid: spent_note_txid.to_string(),
        selected_note_output_index: spent_note_output_index,
        selected_note_value: spent_note_value,
        status: "scheduled".to_string(),
        metadata_json: "{}".to_string(),
    }
}

/// Build a signed PCZT for every scheduled transfer at the schedule's shared anchor and persist
/// each as a pending transaction.
///
/// `schedule` must come from one of this crate's `propose_*` methods: the pinned anchor is taken
/// from the schedule's shared anchor height (identical across every transfer, the wallet's natural
/// witnessable anchor), and pinning against a height the wallet never checkpointed would be a
/// no-op. That anchor's checkpoint is pinned for the duration of the loop (spec D5); each transfer
/// is proposed against the cumulative set of notes reserved by prior transfers (so no two
/// transfers spend the same note), realized as a version-6 PCZT with its own consensus expiry,
/// proven, signed, and finalized.
///
/// Failure containment: the loop inserts each signed transfer's pending row as it goes, so a
/// mid-loop failure can leave a *partial* schedule persisted. Because `next_due_transfer` has no
/// phase gate, those orphan rows would be handed out for broadcast; on any per-transfer failure
/// this therefore best-effort clears the run's still-`scheduled` rows before returning, and the
/// original error is always the one propagated. The anchor pin is likewise released on **both**
/// the success and the error path, and a release failure never masks the signing outcome (witnesses
/// are already baked into each signed PCZT, so a failed release is non-fatal). The release itself
/// is a bulk operation — see [`release_retained_anchors`].
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
    // The natural target and the schedule's shared anchor (identical across a schedule, per
    // `TransferProposal::anchor_height`) drive every transfer's proposal.
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

    // Sign every transfer as one self-contained step so the containment/release below runs on both
    // the success and the error path.
    let sign_all = |db: &mut Db<P>| -> Result<(), MigrationError> {
        let mut reserved: BTreeSet<ReceivedNoteId> = BTreeSet::new();
        let orchard_fvk = orchard::keys::FullViewingKey::from(usk.orchard());
        for t in schedule.transfers() {
            // Direct-builder path: a self-funding note pays its own fee, no wallet fee/change
            // logic needed. Falls back to the ordinary input-selection pipeline when no such note
            // exists (the immediate/sweep migration path).
            if let Some(outcome) = build_self_funding_transfer_pczt(
                db,
                network,
                account,
                &orchard_fvk,
                u64::from(t.amount()),
                &reserved,
                &locks,
                target,
                u32::from(t.expiry_height()),
            )? {
                let SelfFundingTransferOutcome {
                    pczt,
                    spent_note_id,
                    spent_note_txid,
                    spent_note_output_index,
                    spent_note_value,
                } = outcome;
                reserved.insert(spent_note_id);
                let signed = prove_sign_finalize(pczt, usk)?;
                store::insert_pending_txs(
                    conn,
                    run_id,
                    &[self_funding_pending_row(
                        t,
                        &spent_note_txid,
                        spent_note_output_index,
                        spent_note_value,
                        &signed,
                    )],
                )?;
                continue;
            }
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
        Ok(())
    };
    let result = sign_all(db);

    // On failure, drop any pending rows the loop managed to insert before it broke: a partial
    // schedule must not persist, since `next_due_transfer` would otherwise hand those orphan rows
    // out for broadcast. Best-effort — the signing error is what we report.
    if result.is_err() {
        let _ = store::clear_scheduled_pending(conn, run_id);
    }

    // Release the pin on both paths, and never let a release failure mask the signing outcome.
    if let Some(anchor) = pinned_anchor {
        let _ = release_retained_anchors(db, anchor + 1);
    }
    result
}

/// Build and sign (as a PCZT) the note-split (denomination prep) transaction: spend the wallet's
/// version-2 notes and fan the value into one same-address change output per planned denomination.
/// Returns the signed PCZT outcome together with each planned change output's residual-adjusted
/// `(action_index, value)` at its real (post-shuffle) action position, so the caller can persist
/// prepared-note refs whose `(txid, output_index)` match what the scanner records.
///
/// This performs **no** persistence: the caller records the run, prep transaction, and prepared
/// notes atomically only after signing has succeeded (mirroring the external-signer
/// `store_signed_note_split_pczt` storage shape), so a signing failure cannot strand a phantom
/// non-terminal run in the store.
///
/// # Errors
///
/// Returns [`MigrationError::NotSynced`] if the wallet has no scanned block data yet, and
/// [`MigrationError::Pipeline`]/[`MigrationError::Backend`] if the split cannot be built or signed.
pub(crate) fn sign_split<P: Parameters + Clone>(
    db: &mut Db<P>,
    network: &P,
    account: AccountUuid,
    conn: &Connection,
    run_id: &str,
    proposal: &NoteSplitProposal,
    usk: &UnifiedSpendingKey,
) -> Result<(SignedPcztOutcome, crate::split::SplitOutputs), MigrationError> {
    let account_str = account.expose_uuid().to_string();
    // Exclude this run's own (not-yet-existing) notes for symmetry; other live runs' stay locked.
    let locks = store::locked_note_refs(conn, &account_str, Some(run_id))?;
    let orchard_fvk = orchard::keys::FullViewingKey::from(usk.orchard());
    let outputs: Vec<u64> = proposal
        .output_values()
        .iter()
        .map(|v| u64::from(*v))
        .collect();
    let (pczt, split_outputs) =
        crate::split::build_split_pczt(db, network, account, &orchard_fvk, &locks, &outputs)?;
    let signed = prove_sign_finalize(pczt, usk)?;
    Ok((signed, split_outputs))
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
