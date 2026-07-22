//! The pool-migration store's error type.

use std::fmt;

/// A failure reading or writing the pool-migration store.
#[derive(Debug)]
pub enum Error {
    /// A `rusqlite` (SQLite) error.
    Db(rusqlite::Error),
    /// A stored value could not be decoded back into the engine's types (an out-of-range amount, an
    /// unrecognized discriminant, or a missing column for the stored variant). The `&'static str`
    /// names the field.
    Corrupt(&'static str),
    /// The migration state to be written contains a preparation layer with no transactions, or a
    /// transaction with neither inputs nor outputs. The schema stores the layers/transactions grid
    /// only through the input and output rows, so such a state would read back with its grid
    /// coordinates silently renumbered; a plan produced by the engine never contains these. The
    /// `&'static str` names the offending structure.
    Unrepresentable(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Db(e) => write!(f, "pool-migration store database error: {e}"),
            Error::Corrupt(field) => {
                write!(f, "pool-migration store: corrupt stored value for {field}")
            }
            Error::Unrepresentable(what) => {
                write!(f, "pool-migration store: cannot represent {what}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Db(e) => Some(e),
            Error::Corrupt(_) | Error::Unrepresentable(_) => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e)
    }
}

impl From<zcash_protocol::value::BalanceError> for Error {
    /// A stored `INTEGER` amount outside the valid `Zatoshis` range (negative or above the money
    /// cap) is corrupt data.
    fn from(_: zcash_protocol::value::BalanceError) -> Self {
        Error::Corrupt("amount out of range")
    }
}
