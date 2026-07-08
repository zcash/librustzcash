//! Error types for the migration engine.
//!
//! Ported from the `zodl_ironwood_migration` prototype. Unlike the prototype — which used a
//! Cargo feature to dodge the cost of building its fork's wallet backend in some configurations —
//! this in-workspace crate always has the wallet backend available, so the [`MigrationError::Backend`]
//! and [`MigrationError::Pipeline`] variants (and their `From` conversions) are unconditional here.

use std::fmt;

use zcash_client_sqlite::error::SqliteClientError;

/// Why an operation was rejected because the migration was in the wrong state.
///
/// This is the payload of [`MigrationError::InvalidState`]; it exists as its own type so that
/// callers who only care about the "wrong state" case can match on it without also handling the
/// database/backend/pipeline error variants.
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
/// Wraps the underlying error types (`rusqlite::Error`, [`SqliteClientError`]) rather than
/// stringly-typed messages. Intentionally **not** `serde`-derivable; the FFI/JNI glue marshals it
/// via [`MigrationError::error_code`] plus the `Display` string.
///
/// Marked `#[non_exhaustive]` so new variants can be added later without a semver-breaking change
/// for downstream `match` expressions (they must already carry a wildcard arm).
#[derive(Debug)]
#[non_exhaustive]
pub enum MigrationError {
    /// The wallet must finish syncing before this operation can proceed.
    NotSynced,
    /// `initialize_post_upgrade` has not been called yet.
    NotInitialized,
    /// The migration is in a state that does not permit this operation.
    InvalidState(InvalidStateError),
    /// A database (SQLite) error from the engine's own tables.
    Db(rusqlite::Error),
    /// An error from the `zcash_client_sqlite` wallet backend (balance/anchor/data access).
    Backend(SqliteClientError),
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
    /// Current codes: `NotSynced` = 1, `NotInitialized` = 2, `InvalidState` = 3, `Db` = 4,
    /// `Backend` = 5, `Pipeline` = 6.
    pub fn error_code(&self) -> u32 {
        match self {
            MigrationError::NotSynced => 1,
            MigrationError::NotInitialized => 2,
            MigrationError::InvalidState(_) => 3,
            MigrationError::Db(_) => 4,
            MigrationError::Backend(_) => 5,
            MigrationError::Pipeline(_) => 6,
        }
    }
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationError::NotSynced => write!(f, "wallet must finish syncing first"),
            MigrationError::NotInitialized => {
                write!(
                    f,
                    "migration not initialized; call initialize_post_upgrade first"
                )
            }
            MigrationError::InvalidState(e) => write!(f, "invalid migration state: {e}"),
            MigrationError::Db(e) => write!(f, "database error: {e}"),
            MigrationError::Backend(e) => write!(f, "wallet backend error: {e}"),
            MigrationError::Pipeline(e) => write!(f, "pczt pipeline error: {e}"),
        }
    }
}

impl std::error::Error for MigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MigrationError::Db(e) => Some(e),
            MigrationError::Backend(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for MigrationError {
    fn from(e: rusqlite::Error) -> Self {
        MigrationError::Db(e)
    }
}

impl From<SqliteClientError> for MigrationError {
    fn from(e: SqliteClientError) -> Self {
        MigrationError::Backend(e)
    }
}

/// Commitment-tree access during the direct-builder note split.
impl<E: core::fmt::Debug> From<shardtree::error::ShardTreeError<E>> for MigrationError {
    fn from(e: shardtree::error::ShardTreeError<E>) -> Self {
        MigrationError::Pipeline(format!("commitment tree: {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable_and_display_readable() {
        assert_eq!(MigrationError::NotSynced.error_code(), 1);
        assert_eq!(MigrationError::NotInitialized.error_code(), 2);
        let e = MigrationError::InvalidState(InvalidStateError::NoActiveRun);
        assert_eq!(e.error_code(), 3);
        assert!(e.to_string().to_lowercase().contains("no active"));
        let db: MigrationError = rusqlite::Error::QueryReturnedNoRows.into();
        assert_eq!(db.error_code(), 4);
    }

    #[test]
    fn usable_as_std_error_with_source() {
        use std::error::Error;
        let e = MigrationError::Db(rusqlite::Error::QueryReturnedNoRows);
        fn takes_error(_: &dyn std::error::Error) {}
        takes_error(&e);
        assert!(e.source().is_some());
    }

    #[test]
    fn not_synced_and_not_initialized_display() {
        assert!(
            MigrationError::NotSynced
                .to_string()
                .to_lowercase()
                .contains("sync")
        );
        assert!(
            MigrationError::NotInitialized
                .to_string()
                .to_lowercase()
                .contains("initial")
        );
    }

    #[test]
    fn invalid_state_display_variants() {
        assert!(
            InvalidStateError::AlreadyComplete
                .to_string()
                .contains("complete")
        );
        assert_eq!(
            InvalidStateError::WrongPhase {
                expected: "ready",
                found: "broadcasting".to_string()
            }
            .to_string(),
            "wrong migration phase: expected ready, found broadcasting"
        );
    }
}
