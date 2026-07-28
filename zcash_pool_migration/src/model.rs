//! The persisted vocabulary of a pool migration: the types a store reads and writes, and the wire
//! codecs that carry them across that boundary.
//!
//! This module holds the sorts every other module talks in. It is deliberately the lowest layer
//! that mentions a migration at all: it knows how a migration is SHAPED (a status, a denomination
//! plan, a preparation plan, and a list of transactions each carrying a PCZT, a schedule, and a
//! lifecycle state) and how each piece is spelled when persisted, and nothing about how any of it
//! is planned, built, proved, or advanced.
//!
//! Keeping the vocabulary here rather than inside [`engine`](crate::engine) is what makes the
//! crate's module graph acyclic. Every other module needs these types; the engine additionally
//! needs every other module. With the vocabulary living in the engine, those two facts forced
//! `engine <-> state` and `engine <-> signing_rounds` cycles. The types are re-exported from
//! [`engine`](crate::engine), so the paths they have always had keep resolving.
//!
//! The behaviour that operates ON these types lives one layer up: the lifecycle queries and
//! transitions in [`state`](crate::state), and the driving operations in [`engine`](crate::engine).
//! What remains here reads a value out of the data, or reassembles it from stored parts, with no
//! notion of what step comes next.

use alloc::vec::Vec;
use core::fmt;

use corez::io;

use getset::{CopyGetters, Getters};
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::denomination::DenominationPlan;
use crate::preparation::PreparationPlan;

/// A stable ordinal identifier for a migration transaction within a migration. This is a ROW KEY
/// into the persisted migration (usable before a transaction is built, when no [`TxId`] exists yet:
/// deferred preparation layers and transfers are recorded as unbuilt placeholders); it is NOT a
/// Zcash transaction id. The real [`TxId`] becomes available once a transaction is built and signed
/// (it commits only effecting data), and is carried by [`MigrationTxState::Broadcast`].
///
/// The two identities are not interchangeable, and this one is the one to key on. A [`TxId`]
/// identifies a single broadcast ATTEMPT: [`rebuild_expired_transfer`](crate::engine::rebuild_expired_transfer) keeps this id while
/// producing a new transaction with a new [`TxId`], so a consumer that keyed its own records on
/// the [`TxId`] loses track of the transfer exactly when it most needs to follow it. Use the
/// [`TxId`] to talk to the network about a transaction, and this id to talk about the transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MigrationTransferId(pub(crate) u32);

impl MigrationTransferId {
    /// Wrap a stored ordinal as a migration-transaction row key (for a store reading a persisted
    /// migration back).
    pub const fn new(index: u32) -> Self {
        MigrationTransferId(index)
    }

    /// Writes this id as an unsigned 32-bit little-endian integer.
    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0.to_le_bytes())
    }

    /// Reads an id written by [`write`](Self::write).
    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        Ok(MigrationTransferId::new(u32::from_le_bytes(bytes)))
    }
}

impl From<MigrationTransferId> for u32 {
    fn from(id: MigrationTransferId) -> u32 {
        id.0
    }
}

/// What a migration transaction does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationTxKind {
    /// A note-preparation transaction: the `index`-th transaction of preparation `layer`.
    Preparation { layer: usize, index: usize },
    /// A phase-2 pool-crossing transfer of the `crossing`-th funding note.
    Transfer { crossing: usize },
}

impl AsRef<str> for MigrationTxKind {
    /// The stable lowercase wire name of this kind, as a store persists it (the queryable
    /// discriminant); the per-variant indices are stored alongside and reattached by
    /// [`from_stored`](Self::from_stored).
    fn as_ref(&self) -> &str {
        match self {
            MigrationTxKind::Preparation { .. } => "preparation",
            MigrationTxKind::Transfer { .. } => "transfer",
        }
    }
}

impl MigrationTxKind {
    /// The `(layer, index)` of a [`Preparation`](Self::Preparation) kind (its stored indices), or
    /// `None` for a [`Transfer`](Self::Transfer).
    pub fn preparation_indices(&self) -> Option<(usize, usize)> {
        match self {
            MigrationTxKind::Preparation { layer, index } => Some((*layer, *index)),
            MigrationTxKind::Transfer { .. } => None,
        }
    }

    /// The `crossing` of a [`Transfer`](Self::Transfer) kind (its stored index), or `None` for a
    /// [`Preparation`](Self::Preparation).
    pub fn transfer_crossing(&self) -> Option<usize> {
        match self {
            MigrationTxKind::Transfer { crossing } => Some(*crossing),
            MigrationTxKind::Preparation { .. } => None,
        }
    }

    /// Reconstruct a kind from the stored discriminant (the [`AsRef<str>`](AsRef) value) and the
    /// per-variant index columns (each `None` for the variant that does not carry it). Errors on an
    /// unrecognized discriminant, or a discriminant whose index columns are absent.
    pub fn from_stored(
        kind: &str,
        layer: Option<usize>,
        index: Option<usize>,
        crossing: Option<usize>,
    ) -> Result<Self, ParseMigrationTxKindError> {
        Ok(match kind {
            "preparation" => MigrationTxKind::Preparation {
                layer: layer.ok_or(ParseMigrationTxKindError)?,
                index: index.ok_or(ParseMigrationTxKindError)?,
            },
            "transfer" => MigrationTxKind::Transfer {
                crossing: crossing.ok_or(ParseMigrationTxKindError)?,
            },
            _ => return Err(ParseMigrationTxKindError),
        })
    }
}

/// The error returned when a stored `(kind, layer, index, crossing)` tuple does not reconstruct a
/// [`MigrationTxKind`] (its [`from_stored`](MigrationTxKind::from_stored) constructor): an
/// unrecognized discriminant, or a variant missing its index columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseMigrationTxKindError;

impl fmt::Display for ParseMigrationTxKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized or incomplete migration transaction kind")
    }
}

/// Where a migration transaction is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationTxState {
    /// Built and awaiting an EXTERNAL signature: its UNSIGNED PCZT is held in
    /// [`pczt`](MigrationTransaction::pczt), exported for a hardware or offline signer.
    /// [`apply_signature`](MigrationState::apply_signature) moves it to [`Signed`](Self::Signed) once the
    /// signed PCZT is returned. Only the external-signing path
    /// ([`build_preparation_unsigned`](crate::engine::build_preparation_unsigned)) produces this
    /// state; the in-process commit function signs
    /// immediately and goes straight to [`Signed`](Self::Signed).
    AwaitingSignature,
    /// Pre-signed (the account's spend authorization is attached), not yet proved.
    Signed,
    /// Proved against a real anchor, ready to broadcast.
    Proved,
    /// Broadcast to the network, with its transaction id.
    Broadcast { txid: TxId },
    /// Mined at the given height.
    Mined { height: BlockHeight },
}

/// One transaction of a committed migration: its pre-signed PCZT plus the metadata the consuming
/// application needs to prove it against a fresh anchor, wait for its dependencies, broadcast it at
/// its scheduled height, and track its state.
#[derive(Clone, Debug, PartialEq, Eq, Getters, CopyGetters)]
pub struct MigrationTransaction {
    /// This transaction's stable id.
    #[getset(get_copy = "pub")]
    pub(crate) id: MigrationTransferId,
    /// What it does (a preparation transaction or a transfer).
    #[getset(get_copy = "pub")]
    pub(crate) kind: MigrationTxKind,
    /// The unproven PCZT, serialized (`pczt::Pczt::serialize`): pre-signed, except while the
    /// transaction awaits an external signature
    /// ([`AwaitingSignature`](MigrationTxState::AwaitingSignature)), when these are the unsigned
    /// bytes the signed PCZT replaces. Every transaction is built when the migration is
    /// committed — one signing phase — so this is always present: the durable artifact the
    /// application proves (installing its anchor and witnesses at that point; ZIP 374) and
    /// broadcasts.
    #[getset(get = "pub")]
    pub(crate) pczt: Vec<u8>,
    /// The transactions that must be mined before this one may be broadcast (the preparation layer
    /// dependency graph; empty for an independent transaction).
    #[getset(get = "pub")]
    pub(crate) depends_on: Vec<MigrationTransferId>,
    /// The height at which to broadcast (for a transfer; a preparation transaction waits for its
    /// dependencies to mine and a boundary to pass rather than a fixed height).
    #[getset(get_copy = "pub")]
    pub(crate) scheduled_height: BlockHeight,
    /// The height after which the transaction can no longer be mined (ZIP 203) and its part must
    /// be carried by an entirely new, freshly signed transaction: a transfer via
    /// [`rebuild_expired_transfer`](crate::engine::rebuild_expired_transfer) /
    /// [`rebuild_expired_transfer_unsigned`](crate::engine::rebuild_expired_transfer_unsigned)
    /// (detection via
    /// [`MigrationState::expired_transactions`]); an expired preparation awaits its own
    /// remediation slice.
    #[getset(get_copy = "pub")]
    pub(crate) expiry_height: BlockHeight,
    /// The boundary height whose tree state the transaction proves against. For a transfer this is
    /// always present, drawn at SCHEDULING time: `plan_migration` floors the schedule so a
    /// candidate boundary exists for every transfer. `None` only for a preparation transaction
    /// (which waits on its dependencies rather than anchoring to a drawn boundary).
    #[getset(get_copy = "pub")]
    pub(crate) anchor_boundary: Option<BlockHeight>,
    /// The transaction's lifecycle state.
    #[getset(get_copy = "pub")]
    pub(crate) state: MigrationTxState,
    /// The opaque lock-owner token under which this transaction's input notes are locked, or
    /// `None` if it holds no lock. These are the raw bytes of a wallet's
    /// `zcash_client_backend::wallet::LockOwner` (its `LockOwner::as_bytes()` /
    /// `LockOwner::new()` round-trip) — carried here as an opaque `[u8; 32]` rather than the typed
    /// `LockOwner` because this `orchard`-gated engine module must not depend on
    /// `zcash_client_backend` (only `wallet`-feature code does); the conversion to/from `LockOwner`
    /// happens at that boundary, not here. The migration flow does not yet acquire locks, so every
    /// transaction the engine itself builds carries `None`; a store still round-trips whatever a
    /// caller sets.
    #[getset(get_copy = "pub")]
    pub(crate) lock_owner: Option<[u8; 32]>,
}

impl MigrationTransaction {
    /// Reassemble a stored migration transaction from its persisted parts, exactly as a store read
    /// them back (the inverse of the accessors). The caller is responsible for having persisted a
    /// consistent row.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: MigrationTransferId,
        kind: MigrationTxKind,
        pczt: Vec<u8>,
        depends_on: Vec<MigrationTransferId>,
        scheduled_height: BlockHeight,
        expiry_height: BlockHeight,
        anchor_boundary: Option<BlockHeight>,
        state: MigrationTxState,
        lock_owner: Option<[u8; 32]>,
    ) -> Self {
        Self {
            id,
            kind,
            pczt,
            depends_on,
            scheduled_height,
            expiry_height,
            anchor_boundary,
            state,
            lock_owner,
        }
    }
}

/// The overall status of a migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Planned and previewed, not yet committed (nothing built or signed).
    Planning,
    /// Built, pre-signed, and persisted; ready for the application to prove and broadcast.
    Committed,
    /// Some transactions have been broadcast or mined.
    InProgress,
    /// Every crossing has been mined.
    Complete,
    /// The migration failed and needs attention.
    Failed,
}

impl AsRef<str> for MigrationStatus {
    /// The stable lowercase wire name of the status, as stored by a backend and parsed back with
    /// [`TryFrom<&str>`](Self). Borrow-free: it returns a `&'static str`, so encoding a status
    /// allocates nothing.
    fn as_ref(&self) -> &str {
        match self {
            MigrationStatus::Planning => "planning",
            MigrationStatus::Committed => "committed",
            MigrationStatus::InProgress => "in_progress",
            MigrationStatus::Complete => "complete",
            MigrationStatus::Failed => "failed",
        }
    }
}

/// The error returned when a string does not name a [`MigrationStatus`] (its [`TryFrom<&str>`] impl).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseMigrationStatusError;

impl fmt::Display for ParseMigrationStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized migration status")
    }
}

impl TryFrom<&str> for MigrationStatus {
    type Error = ParseMigrationStatusError;

    /// Parses the lowercase wire name produced by [`AsRef<str>`](AsRef).
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(match s {
            "planning" => MigrationStatus::Planning,
            "committed" => MigrationStatus::Committed,
            "in_progress" => MigrationStatus::InProgress,
            "complete" => MigrationStatus::Complete,
            "failed" => MigrationStatus::Failed,
            _ => return Err(ParseMigrationStatusError),
        })
    }
}

impl AsRef<str> for MigrationTxState {
    /// The stable lowercase wire name of the lifecycle state, as a store persists it (the queryable
    /// discriminant); the `Broadcast` txid and `Mined` height are stored alongside and reattached by
    /// [`from_stored`](Self::from_stored).
    fn as_ref(&self) -> &str {
        match self {
            MigrationTxState::AwaitingSignature => "awaiting_signature",
            MigrationTxState::Signed => "signed",
            MigrationTxState::Proved => "proved",
            MigrationTxState::Broadcast { .. } => "broadcast",
            MigrationTxState::Mined { .. } => "mined",
        }
    }
}

/// The error returned when a stored `(state, txid, mined_height)` triple does not reconstruct a
/// [`MigrationTxState`] (its [`from_stored`](MigrationTxState::from_stored) constructor): an
/// unrecognized discriminant, or a `broadcast`/`mined` row missing its txid/height payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseMigrationTxStateError;

impl fmt::Display for ParseMigrationTxStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unrecognized or incomplete migration transaction state")
    }
}

impl MigrationTxState {
    /// The transaction id of a [`Broadcast`](Self::Broadcast) state (its stored payload), or `None`
    /// for any other state.
    pub fn broadcast_txid(&self) -> Option<[u8; 32]> {
        match self {
            MigrationTxState::Broadcast { txid } => Some(*txid.as_ref()),
            _ => None,
        }
    }

    /// The block height of a [`Mined`](Self::Mined) state (its stored payload), or `None` for any
    /// other state.
    pub fn mined_height(&self) -> Option<BlockHeight> {
        match self {
            MigrationTxState::Mined { height } => Some(*height),
            _ => None,
        }
    }

    /// Reconstruct a state from a store: the lowercase discriminant produced by
    /// [`AsRef<str>`](AsRef), plus the `broadcast` txid and `mined` height columns (each `None` for a
    /// state that does not carry it). Errors on an unrecognized discriminant, or a `broadcast`/`mined`
    /// discriminant whose payload column is absent.
    pub fn from_stored(
        state: &str,
        txid: Option<[u8; 32]>,
        mined_height: Option<BlockHeight>,
    ) -> Result<Self, ParseMigrationTxStateError> {
        Ok(match state {
            "awaiting_signature" => MigrationTxState::AwaitingSignature,
            "signed" => MigrationTxState::Signed,
            "proved" => MigrationTxState::Proved,
            "broadcast" => MigrationTxState::Broadcast {
                txid: TxId::from_bytes(txid.ok_or(ParseMigrationTxStateError)?),
            },
            "mined" => MigrationTxState::Mined {
                height: mined_height.ok_or(ParseMigrationTxStateError)?,
            },
            _ => return Err(ParseMigrationTxStateError),
        })
    }
}

/// The persisted state of a migration: the denomination plan (for the preview and residual accounting) and
/// every transaction, each as its pre-signed PCZT and metadata. A wallet resumes a migration entirely
/// from this state after being closed or restarted; this is what a
/// [`MigrationBackend`](crate::engine::MigrationBackend) stores.
#[derive(Clone, Debug, PartialEq, Eq, Getters, CopyGetters)]
pub struct MigrationState {
    /// The overall status.
    #[getset(get_copy = "pub")]
    pub(crate) status: MigrationStatus,
    /// The denomination decomposition (the denominations and residual).
    #[getset(get = "pub")]
    pub(crate) denominations: DenominationPlan,
    /// The preparation plan (its layers and direct-funding notes), retained for auditability and
    /// for rebuilding expired PREPARATION transactions (a follow-on slice). A
    /// `Preparation { layer, index }` transaction's spends resolve against
    /// `preparation.layers()[layer][index]`.
    #[getset(get = "pub")]
    pub(crate) preparation: PreparationPlan,
    /// Every migration transaction, in dependency order.
    #[getset(get = "pub")]
    pub(crate) transactions: Vec<MigrationTransaction>,
    /// The anchor bucket grid this migration was COMMITTED under, recorded so a later change to the
    /// wallet's anchor retention interval is caught as a typed error rather than surfacing as an
    /// unexplained missing checkpoint.
    ///
    /// Every transfer's [`anchor_boundary`](MigrationTransaction::anchor_boundary) lies on this
    /// grid. If the wallet is subsequently reconfigured, it stops retaining these boundaries'
    /// checkpoints and they are pruned, at which point the committed transfers become unprovable —
    /// so [`prove_transfer`](crate::engine::prove_transfer) and the rebuild path reject the
    /// mismatch up front.
    #[getset(get_copy = "pub")]
    pub(crate) anchor_bucket_interval: crate::scheduling::AnchorBucketInterval,
}

impl MigrationState {
    /// Reassemble a persisted migration from its stored parts, exactly as a store read them back
    /// (the inverse of the accessors).
    pub fn from_parts(
        status: MigrationStatus,
        denominations: DenominationPlan,
        preparation: PreparationPlan,
        transactions: Vec<MigrationTransaction>,
        anchor_bucket_interval: crate::scheduling::AnchorBucketInterval,
    ) -> Self {
        Self {
            status,
            denominations,
            preparation,
            transactions,
            anchor_bucket_interval,
        }
    }

    /// The self-funding note values (in zatoshi), one per crossing: a `Transfer { crossing }`
    /// transaction SPENDS `funding_notes()[crossing]`, of which the fee buffer pays that
    /// transaction's own fee and the remainder crosses into the destination pool. Derived from the
    /// denomination plan (each crossing value plus the fee buffer), so a store persists only that
    /// plan.
    ///
    /// This is a SPEND-side value: it is neither what arrives in the destination pool nor the round
    /// denomination the user consented to. To report what a transfer moves, use
    /// [`crossing_values`](Self::crossing_values), or
    /// [`transfer_crossing_value`](Self::transfer_crossing_value) for a single transaction.
    pub fn funding_notes(&self) -> Vec<Zatoshis> {
        self.denominations.migration_outputs()
    }

    /// The values (in zatoshi) that cross into the destination pool, one per crossing and
    /// index-aligned with [`funding_notes`](Self::funding_notes): each is its funding note less the
    /// fee buffer that funds the transfer's own fee, and so is one of the round denominations the
    /// user was shown at proposal time.
    ///
    /// This is the value to display for a transfer, and the one the receiving wallet's own
    /// accounting will agree with once the transfer mines.
    pub fn crossing_values(&self) -> &[Zatoshis] {
        self.denominations.crossing_values()
    }

    /// The value transaction `tx` crosses into the destination pool, or `None` when `tx` is not a
    /// transfer (a preparation transaction crosses nothing).
    ///
    /// Equivalent to indexing [`crossing_values`](Self::crossing_values) by the transaction's
    /// [`transfer_crossing`](MigrationTxKind::transfer_crossing) — the accessor to reach for when
    /// marshaling one stored transaction into a user-facing amount, so consumers do not re-derive
    /// the funding-note-minus-buffer arithmetic and get it wrong by a fee.
    pub fn transfer_crossing_value(&self, tx: &MigrationTransaction) -> Option<Zatoshis> {
        tx.kind()
            .transfer_crossing()
            .and_then(|crossing| self.crossing_values().get(crossing).copied())
    }

    /// Replace transfer `id`'s stored PCZT with its proven bytes and move it to
    /// [`Proved`](MigrationTxState::Proved). Called after
    /// [`prove_transfer`](crate::engine::prove_transfer) installs the drawn
    /// anchor and witnesses and proves the transaction, so the durable artifact becomes the proven,
    /// ready-to-broadcast PCZT.
    #[cfg(feature = "orchard")]
    pub fn set_transaction_proved(&mut self, id: MigrationTransferId, proven_pczt: Vec<u8>) {
        for tx in &mut self.transactions {
            if tx.id() == id {
                tx.pczt = proven_pczt;
                tx.state = MigrationTxState::Proved;
                break;
            }
        }
    }
}
