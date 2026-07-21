//! The crate's single error type for the pool-migration store.

use std::fmt;

/// A failure reading or writing the pool-migration store.
#[derive(Debug)]
pub enum Error {
    /// A `rusqlite` (SQLite) error.
    Db(rusqlite::Error),
    /// A stored value could not be decoded back into the engine's types (a corrupt or truncated blob,
    /// or an unrecognized enum tag). The `&'static str` names the field.
    Corrupt(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Db(e) => write!(f, "pool-migration store database error: {e}"),
            Error::Corrupt(field) => {
                write!(f, "pool-migration store: corrupt stored value for {field}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Db(e) => Some(e),
            Error::Corrupt(_) => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e)
    }
}
