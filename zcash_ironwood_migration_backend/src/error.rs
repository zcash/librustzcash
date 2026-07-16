//! Error types for the migration engine: [`MigrationError`], returned by the engine's operations,
//! and [`InvalidStateError`], the payload of its [`MigrationError::InvalidState`] variant.
//!
//! These are backend-agnostic: a wallet-backend or storage failure is carried as an opaque message
//! ([`MigrationError::Backend`] / [`MigrationError::Store`]), so the error type names no
//! backend-specific type. A backend maps its own error into these at the trait boundary.

use core::fmt;

/// Why an operation was rejected because the migration was in the wrong state.
///
/// This is the payload of [`MigrationError::InvalidState`]; it exists as its own type so that
/// callers who only care about the "wrong state" case can match on it without also handling the
/// storage/backend/pipeline error variants.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidStateError {
    /// There is no active migration run for the account.
    NoActiveRun,
    /// A persisted run carried a phase string the engine does not recognise.
    ///
    /// This indicates the wallet database was written by a newer (or otherwise incompatible)
    /// version of this engine.
    UnknownPhase(String),
    /// The run is in a phase that does not permit this operation.
    WrongPhase {
        /// The phase (or set of phases, rendered as a single label) the operation requires.
        expected: &'static str,
        /// The phase the run was actually found in.
        found: String,
    },
    /// The migration has already completed.
    AlreadyComplete,
    /// The operation does not apply in the current state (short reason).
    NotApplicable(&'static str),
}

impl fmt::Display for InvalidStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidStateError::NoActiveRun => write!(f, "no active migration run"),
            InvalidStateError::UnknownPhase(p) => write!(f, "unknown migration phase: {p}"),
            InvalidStateError::WrongPhase { expected, found } => {
                write!(
                    f,
                    "wrong migration phase: expected {expected}, found {found}"
                )
            }
            InvalidStateError::AlreadyComplete => write!(f, "migration already complete"),
            InvalidStateError::NotApplicable(why) => write!(f, "operation not applicable: {why}"),
        }
    }
}

/// Errors returned by the migration engine.
///
/// Backend failures (from the wallet-backend and storage implementations) are carried as opaque
/// messages rather than a concrete error type, so this stays backend-agnostic. Intentionally
/// **not** `serde`-derivable;
/// the FFI/JNI glue marshals it via [`MigrationError::error_code`] plus the `Display` string.
///
/// Marked `#[non_exhaustive]` so new variants can be added later without a semver-breaking change
/// for downstream `match` expressions (they must already carry a wildcard arm).
#[derive(Debug)]
#[non_exhaustive]
pub enum MigrationError {
    /// The wallet must finish syncing before this operation can proceed.
    NotSynced,
    /// The migration is in a state that does not permit this operation.
    InvalidState(InvalidStateError),
    /// A failure in the engine's own persistence (the storage backend).
    Store(String),
    /// A failure in the wallet backend: balance/anchor/data access, or PCZT building.
    Backend(String),
    /// An error from the PCZT construction / proving / signing / extraction pipeline, whose
    /// sources are heterogeneous and share no single common type.
    Pipeline(String),
}

impl MigrationError {
    /// A stable numeric code for the FFI/JNI boundary.
    ///
    /// These codes are a stable ABI surface: once shipped, an existing variant's code must never
    /// be changed or reassigned to a different variant. Callers on the other side of an FFI
    /// boundary may switch on this value instead of (or in addition to) the `Display` string, so
    /// renumbering silently breaks them. A future variant added under this type's
    /// `#[non_exhaustive]` marker must be given a new, previously-unused code rather than reusing
    /// one of the codes below.
    ///
    /// Current codes: `NotSynced` = 1, `InvalidState` = 3, `Store` = 4, `Backend` = 5,
    /// `Pipeline` = 6. Code `2` is retired (it belonged to a `NotInitialized` variant that was
    /// removed before release) and must never be reassigned, so the remaining codes keep their
    /// original values rather than being compacted.
    pub fn error_code(&self) -> u32 {
        match self {
            MigrationError::NotSynced => 1,
            MigrationError::InvalidState(_) => 3,
            MigrationError::Store(_) => 4,
            MigrationError::Backend(_) => 5,
            MigrationError::Pipeline(_) => 6,
        }
    }
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationError::NotSynced => write!(f, "wallet must finish syncing first"),
            MigrationError::InvalidState(e) => write!(f, "invalid migration state: {e}"),
            MigrationError::Store(e) => write!(f, "storage error: {e}"),
            MigrationError::Backend(e) => write!(f, "wallet backend error: {e}"),
            MigrationError::Pipeline(e) => write!(f, "pczt pipeline error: {e}"),
        }
    }
}

impl core::error::Error for MigrationError {}
