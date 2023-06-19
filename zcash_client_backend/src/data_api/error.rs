//! Types for wallet error handling.

use std::error;
use std::fmt::{self, Debug, Display};
use zcash_primitives::{
    transaction::{
        builder,
        components::{
            amount::{Amount, BalanceError},
            sapling, transparent,
        },
    },
    zip32::AccountId,
};

use crate::data_api::wallet::input_selection::InputSelectorError;

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::{legacy::TransparentAddress, zip32::DiversifierIndex};

/// Errors that can occur as a consequence of wallet operations.
#[derive(Debug)]
pub enum Error<DataSourceError, SelectionError, FeeError, NoteRef> {
    /// An error occurred retrieving data from the underlying data source
    DataSource(DataSourceError),

    /// An error in note selection
    NoteSelection(SelectionError),

    /// No account could be found corresponding to a provided spending key.
    KeyNotRecognized,

    /// No account with the given identifier was found in the wallet.
    AccountNotFound(AccountId),

    /// Zcash amount computation encountered an overflow or underflow.
    BalanceError(BalanceError),

    /// Unable to create a new spend because the wallet balance is not sufficient.
    InsufficientFunds { available: Amount, required: Amount },

    /// The wallet must first perform a scan of the blockchain before other
    /// operations can be performed.
    ScanRequired,

    /// An error occurred building a new transaction.
    Builder(builder::Error<FeeError>),

    /// It is forbidden to provide a memo when constructing a transparent output.
    MemoForbidden,

    /// A note being spent does not correspond to either the internal or external
    /// full viewing key for an account.
    NoteMismatch(NoteRef),

    #[cfg(feature = "transparent-inputs")]
    AddressNotRecognized(TransparentAddress),

    #[cfg(feature = "transparent-inputs")]
    ChildIndexOutOfRange(DiversifierIndex),
}

impl<DE, SE, FE, N> fmt::Display for Error<DE, SE, FE, N>
where
    DE: fmt::Display,
    SE: fmt::Display,
    FE: fmt::Display,
    N: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Error::DataSource(e) => {
                write!(
                    f,
                    "The underlying datasource produced the following error: {}",
                    e
                )
            }
            Error::NoteSelection(e) => {
                write!(f, "Note selection encountered the following error: {}", e)
            }
            Error::KeyNotRecognized => {
                write!(
                    f,
                    "Wallet does not contain an account corresponding to the provided spending key"
                )
            }
            Error::AccountNotFound(account) => {
                write!(f, "Wallet does not contain account {}", u32::from(*account))
            }
            Error::BalanceError(e) => write!(
                f,
                "The value lies outside the valid range of Zcash amounts: {:?}.",
                e
            ),
            Error::InsufficientFunds { available, required } => write!(
                f,
                "Insufficient balance (have {}, need {} including fee)",
                i64::from(*available),
                i64::from(*required)
            ),
            Error::ScanRequired => write!(f, "Must scan blocks first"),
            Error::Builder(e) => write!(f, "An error occurred building the transaction: {}", e),
            Error::MemoForbidden => write!(f, "It is not possible to send a memo to a transparent address."),
            Error::NoteMismatch(n) => write!(f, "A note being spent ({}) does not correspond to either the internal or external full viewing key for the provided spending key.", n),

            #[cfg(feature = "transparent-inputs")]
            Error::AddressNotRecognized(_) => {
                write!(f, "The specified transparent address was not recognized as belonging to the wallet.")
            }
            #[cfg(feature = "transparent-inputs")]
            Error::ChildIndexOutOfRange(i) => {
                write!(
                    f,
                    "The diversifier index {:?} is out of range for transparent addresses.",
                    i
                )
            }
        }
    }
}

impl<DE, SE, FE, N> error::Error for Error<DE, SE, FE, N>
where
    DE: Debug + Display + error::Error + 'static,
    SE: Debug + Display + error::Error + 'static,
    FE: Debug + Display + 'static,
    N: Debug + Display,
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::DataSource(e) => Some(e),
            Error::NoteSelection(e) => Some(e),
            Error::Builder(e) => Some(e),
            _ => None,
        }
    }
}

impl<DE, SE, FE, N> From<builder::Error<FE>> for Error<DE, SE, FE, N> {
    fn from(e: builder::Error<FE>) -> Self {
        Error::Builder(e)
    }
}

impl<DE, SE, FE, N> From<BalanceError> for Error<DE, SE, FE, N> {
    fn from(e: BalanceError) -> Self {
        Error::BalanceError(e)
    }
}

impl<DE, SE, FE, N> From<InputSelectorError<DE, SE>> for Error<DE, SE, FE, N> {
    fn from(e: InputSelectorError<DE, SE>) -> Self {
        match e {
            InputSelectorError::DataSource(e) => Error::DataSource(e),
            InputSelectorError::Selection(e) => Error::NoteSelection(e),
            InputSelectorError::InsufficientFunds {
                available,
                required,
            } => Error::InsufficientFunds {
                available,
                required,
            },
        }
    }
}

impl<DE, SE, FE, N> From<sapling::builder::Error> for Error<DE, SE, FE, N> {
    fn from(e: sapling::builder::Error) -> Self {
        Error::Builder(builder::Error::SaplingBuild(e))
    }
}

impl<DE, SE, FE, N> From<transparent::builder::Error> for Error<DE, SE, FE, N> {
    fn from(e: transparent::builder::Error) -> Self {
        Error::Builder(builder::Error::TransparentBuild(e))
    }
}
