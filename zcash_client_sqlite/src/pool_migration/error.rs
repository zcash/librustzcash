//! The pool-migration store's error type.

use std::fmt;

use zcash_pool_migration::engine::MigrationTransferId;

/// A failure reading or writing the pool-migration store.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A `rusqlite` (SQLite) error.
    Db(rusqlite::Error),
    /// The account a store was requested for (by [`AccountUuid`]) does not exist in the wallet's
    /// `accounts` table, so its migration cannot be scoped to an account row.
    ///
    /// [`AccountUuid`]: crate::AccountUuid
    AccountUnknown,
    /// A stored value could not be decoded back into the engine's types (an out-of-range amount, an
    /// unrecognized discriminant, or a missing column for the stored variant). The `&'static str`
    /// names the field.
    Corrupt(&'static str),
    /// The wallet has no fully-scanned height (nothing has been scanned yet, or an unscanned gap
    /// remains above the wallet birthday), so a satisfiability observation has no chain state to
    /// rest on. Not corruption: sync further and retry.
    ChainStateUnavailable,
    /// The migration state to be written contains a preparation layer with no transactions, or a
    /// transaction with neither inputs nor outputs. The schema stores the layers/transactions grid
    /// only through the input and output rows, so such a state would read back with its grid
    /// coordinates silently renumbered; a plan produced by the engine never contains these. The
    /// `&'static str` names the offending structure.
    Unrepresentable(&'static str),
    /// The migration state handed to `store_proved_transaction` contains no transaction with the
    /// given id, so there is nothing to finalize.
    UnknownTransaction(MigrationTransferId),
    /// The transaction handed to `store_proved_transaction` is not in the `Proved` lifecycle
    /// state, so its stored bytes are not a proven PCZT and no transaction can be finalized from
    /// them.
    NotProved(MigrationTransferId),
    /// The account holds no unified full viewing key, so a finalized migration transaction's
    /// outputs cannot be recovered for the wallet's sent-transaction record.
    ViewingKeyUnavailable,
    /// Finalizing the proven PCZT into a `Transaction` failed.
    #[cfg(feature = "orchard")]
    Finalize(FinalizeError),
    /// Persisting a finalized migration transaction to the wallet's own transaction tables failed.
    Wallet(Box<crate::error::SqliteClientError>),
}

/// Why a proven migration PCZT could not be finalized into the `Transaction` the wallet's
/// sent-transaction record stores.
#[cfg(feature = "orchard")]
#[derive(Debug)]
#[non_exhaustive]
pub enum FinalizeError {
    /// The stored PCZT could not be parsed.
    Parse(pczt::ParseError),
    /// Moving the spend authorizations into their final form (the PCZT Spend Finalizer role)
    /// failed: some spend lacks its signature.
    Spends(pczt::roles::spend_finalizer::Error),
    /// Extracting (and verifying) the final transaction failed: a proof or signature is missing
    /// or invalid, or a bundle is malformed.
    Extract(pczt::roles::tx_extractor::Error),
    /// The transaction's balance could not be computed (a value outside the valid `Zatoshis`
    /// range).
    Balance(zcash_protocol::value::BalanceError),
}

#[cfg(feature = "orchard")]
impl fmt::Display for FinalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FinalizeError::Parse(e) => write!(f, "parsing the stored proven PCZT failed: {e}"),
            FinalizeError::Spends(e) => write!(f, "finalizing the PCZT's spends failed: {e:?}"),
            FinalizeError::Extract(e) => {
                write!(f, "extracting the finalized transaction failed: {e:?}")
            }
            FinalizeError::Balance(e) => {
                write!(f, "computing the transaction's fee failed: {e:?}")
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Db(e) => write!(f, "pool-migration store database error: {e}"),
            Error::AccountUnknown => {
                write!(f, "pool-migration store: no such account in the wallet")
            }
            Error::Corrupt(field) => {
                write!(f, "pool-migration store: corrupt stored value for {field}")
            }
            Error::ChainStateUnavailable => {
                write!(
                    f,
                    "pool-migration store: the wallet has no fully-scanned height to observe from"
                )
            }
            Error::Unrepresentable(what) => {
                write!(f, "pool-migration store: cannot represent {what}")
            }
            Error::UnknownTransaction(id) => write!(
                f,
                "pool-migration store: the migration state holds no transaction {}",
                u32::from(*id)
            ),
            Error::NotProved(id) => write!(
                f,
                "pool-migration store: transaction {} is not proved, so it cannot be finalized",
                u32::from(*id)
            ),
            Error::ViewingKeyUnavailable => write!(
                f,
                "pool-migration store: the account has no unified full viewing key to recover \
                 the finalized transaction's outputs with"
            ),
            #[cfg(feature = "orchard")]
            Error::Finalize(e) => {
                write!(f, "pool-migration store: {e}")
            }
            Error::Wallet(e) => write!(
                f,
                "pool-migration store: persisting the finalized transaction failed: {e}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Db(e) => Some(e),
            Error::Wallet(e) => Some(e),
            Error::AccountUnknown
            | Error::Corrupt(_)
            | Error::ChainStateUnavailable
            | Error::Unrepresentable(_)
            | Error::UnknownTransaction(_)
            | Error::NotProved(_)
            | Error::ViewingKeyUnavailable => None,
            #[cfg(feature = "orchard")]
            Error::Finalize(_) => None,
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
