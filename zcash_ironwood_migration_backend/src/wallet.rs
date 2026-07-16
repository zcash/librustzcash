//! The [`WalletMigrationBackend`] trait: the wallet-side operations the migration engine needs, and
//! the plain-data types that cross that boundary.
//!
//! The engine (`MigrationContext`) is generic over an implementation of this trait, so the same
//! migration logic drives any wallet backend. A backend implements the wallet reads and the
//! PCZT-building operations here; the engine performs the pure PCZT prove/sign/finalize steps
//! itself. Note references cross the boundary as [`NoteRef`] pairs, and the build operations return
//! an unproven [`pczt::Pczt`] plus plain-data metadata, so no wallet-backend-specific type (a
//! database handle, an input-selection proposal, a note id) appears in this interface.

use zcash_protocol::TxId;

/// An account's migration-relevant pool balances, in zatoshi.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PoolBalances {
    orchard_spendable: u64,
    ironwood_total: u64,
}

impl PoolBalances {
    /// Constructs pool balances from their parts.
    pub fn from_parts(orchard_spendable: u64, ironwood_total: u64) -> Self {
        PoolBalances {
            orchard_spendable,
            ironwood_total,
        }
    }

    /// The spendable Orchard balance (zatoshi) available to migrate.
    pub fn orchard_spendable(&self) -> u64 {
        self.orchard_spendable
    }

    /// The total Ironwood balance (zatoshi) already migrated into the Ironwood pool.
    pub fn ironwood_total(&self) -> u64 {
        self.ironwood_total
    }
}

/// A reference to a wallet note, by the transaction that created it and its output index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NoteRef {
    txid: TxId,
    output_index: u32,
}

impl NoteRef {
    /// Constructs a note reference from its parts.
    pub fn from_parts(txid: TxId, output_index: u32) -> Self {
        NoteRef { txid, output_index }
    }

    /// The id of the transaction that created the note.
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// The note's output index within that transaction.
    pub fn output_index(&self) -> u32 {
        self.output_index
    }
}

/// The note a self-funding transfer spends: its location and value (zatoshi).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpentNote {
    txid: TxId,
    output_index: u32,
    value: u64,
}

impl SpentNote {
    /// Constructs a spent-note record from its parts.
    pub fn from_parts(txid: TxId, output_index: u32, value: u64) -> Self {
        SpentNote {
            txid,
            output_index,
            value,
        }
    }

    /// The id of the transaction that created the spent note.
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// The spent note's output index within that transaction.
    pub fn output_index(&self) -> u32 {
        self.output_index
    }

    /// The spent note's value in zatoshi.
    pub fn value(&self) -> u64 {
        self.value
    }
}

/// The output notes a note-split transaction creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitOutputs {
    migration_notes: Vec<(u32, u64)>,
    change: Option<(u32, u64)>,
}

impl SplitOutputs {
    /// Constructs the split outputs from their parts.
    pub fn from_parts(migration_notes: Vec<(u32, u64)>, change: Option<(u32, u64)>) -> Self {
        SplitOutputs {
            migration_notes,
            change,
        }
    }

    /// The `(output_index, value)` of each self-funding migration note the split creates.
    pub fn migration_notes(&self) -> &[(u32, u64)] {
        &self.migration_notes
    }

    /// The `(output_index, value)` of the Orchard change output, if the split produced one.
    pub fn change(&self) -> Option<(u32, u64)> {
        self.change
    }
}

/// The result of building a self-funding transfer: the unproven PCZT and the note it spends.
pub struct TransferBuild {
    pczt: pczt::Pczt,
    spent_note: SpentNote,
}

impl TransferBuild {
    /// Constructs a transfer build from its parts.
    pub fn from_parts(pczt: pczt::Pczt, spent_note: SpentNote) -> Self {
        TransferBuild { pczt, spent_note }
    }

    /// The note the transfer spends.
    pub fn spent_note(&self) -> &SpentNote {
        &self.spent_note
    }

    /// Consumes this build, returning the unproven PCZT and the spent-note record.
    pub fn into_parts(self) -> (pczt::Pczt, SpentNote) {
        (self.pczt, self.spent_note)
    }
}

/// The wallet-side operations the migration engine requires from a wallet backend.
///
/// An implementation reads the account's balances and chain heights, checks whether a transaction
/// has been mined, builds unproven migration PCZTs (doing its own note selection and
/// note-commitment-tree access), and pins/releases anchor checkpoints. The engine owns everything
/// else: planning, scheduling, persistence, and the pure PCZT prove/sign/finalize/extract steps.
///
/// Every note reference crosses this boundary as a [`NoteRef`], and every build method returns an
/// unproven [`pczt::Pczt`], so an implementation is free to use any wallet representation
/// internally without exposing it here.
pub trait WalletMigrationBackend {
    /// The wallet backend's error type.
    type Error: core::error::Error;

    /// The account's migration-relevant pool balances.
    fn pool_balances(&self) -> Result<PoolBalances, Self::Error>;

    /// The wallet's current target height and its witnessable note-commitment-tree anchor height.
    fn target_and_anchor_heights(&self) -> Result<(u32, u32), Self::Error>;

    /// Whether the transaction `txid` has been scanned as mined in a block.
    fn is_tx_mined(&self, txid: TxId) -> Result<bool, Self::Error>;

    /// Builds the unproven note-split PCZT that decomposes the spendable Orchard balance into the
    /// self-funding `target_values`, excluding the `reserved` notes from selection. Returns the
    /// PCZT and the output notes it creates.
    fn build_note_split_pczt(
        &mut self,
        target_values: &[u64],
        reserved: &[NoteRef],
    ) -> Result<(pczt::Pczt, SplitOutputs), Self::Error>;

    /// Builds the unproven self-funding transfer PCZT that spends one pre-split note to cross
    /// `crossing_value` from Orchard to Ironwood, excluding the `reserved` notes, anchored for the
    /// given target and expiry heights. Returns `None` if no suitable note is available.
    fn build_transfer_pczt(
        &mut self,
        crossing_value: u64,
        reserved: &[NoteRef],
        target_height: u32,
        expiry_height: u32,
    ) -> Result<Option<TransferBuild>, Self::Error>;

    /// The value (zatoshi) that would cross if the whole spendable Orchard balance were swept in a
    /// single transfer right now, net of the sweep fee, or `None` if nothing is sweepable.
    fn sweep_crossing_value(&self) -> Result<Option<u64>, Self::Error>;

    /// Pins the note-commitment-tree checkpoint at `height` on the Orchard and Ironwood trees, so
    /// ordinary checkpoint pruning cannot invalidate an anchor while a schedule is being signed.
    fn retain_anchor(&mut self, height: u32) -> Result<(), Self::Error>;

    /// Releases note-commitment-tree checkpoints pinned below `height`.
    fn release_retained_anchors_below(&mut self, height: u32) -> Result<(), Self::Error>;
}
