//! Types for wallet error handling.

use std::error;
use std::fmt::{self, Debug, Display};

use shardtree::error::ShardTreeError;
use zcash_address::ConversionError;
use zcash_primitives::transaction::components::amount::NonNegativeAmount;
use zcash_primitives::transaction::{
    builder,
    components::{amount::BalanceError, transparent},
};

use crate::address::UnifiedAddress;
use crate::data_api::wallet::input_selection::InputSelectorError;
use crate::proposal::ProposalError;
use crate::PoolType;

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::legacy::TransparentAddress;

use crate::wallet::NoteId;

/// Errors that can occur as a consequence of wallet operations.
#[derive(Debug)]
pub enum Error<DataSourceError, CommitmentTreeError, SelectionError, FeeError> {
    /// An error occurred retrieving data from the underlying data source
    DataSource(DataSourceError),

    /// An error in computations involving the note commitment trees.
    CommitmentTree(ShardTreeError<CommitmentTreeError>),

    /// An error in note selection
    NoteSelection(SelectionError),

    /// An error in transaction proposal construction
    Proposal(ProposalError),

    /// The proposal was structurally valid, but spending shielded outputs of prior multi-step
    /// transaction steps is not yet supported.
    ProposalNotSupported,

    /// No account could be found corresponding to a provided spending key.
    KeyNotRecognized,

    /// Zcash amount computation encountered an overflow or underflow.
    BalanceError(BalanceError),

    /// Unable to create a new spend because the wallet balance is not sufficient.
    InsufficientFunds {
        available: NonNegativeAmount,
        required: NonNegativeAmount,
    },

    /// The wallet must first perform a scan of the blockchain before other
    /// operations can be performed.
    ScanRequired,

    /// An error occurred building a new transaction.
    Builder(builder::Error<FeeError>),

    /// It is forbidden to provide a memo when constructing a transparent output.
    MemoForbidden,

    /// Attempted to send change to an unsupported pool.
    ///
    /// This is indicative of a programming error; execution of a transaction proposal that
    /// presumes support for the specified pool was performed using an application that does not
    /// provide such support.
    UnsupportedChangeType(PoolType),

    /// Attempted to create a spend to an unsupported Unified Address receiver
    NoSupportedReceivers(Box<UnifiedAddress>),

    /// A proposed transaction cannot be built because it requires spending an input
    /// for which no spending key is available.
    ///
    /// The argument is the address of the note or UTXO being spent.
    NoSpendingKey(String),

    /// A note being spent does not correspond to either the internal or external
    /// full viewing key for an account.
    NoteMismatch(NoteId),

    /// An error occurred parsing the address from a payment request.
    Address(ConversionError<&'static str>),

    #[cfg(feature = "transparent-inputs")]
    AddressNotRecognized(TransparentAddress),
}

impl<DE, CE, SE, FE> fmt::Display for Error<DE, CE, SE, FE>
where
    DE: fmt::Display,
    CE: fmt::Display,
    SE: fmt::Display,
    FE: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::DataSource(e) => {
                write!(
                    f,
                    "The underlying datasource produced the following error: {}",
                    e
                )
            }
            Error::CommitmentTree(e) => {
                write!(f, "An error occurred in querying or updating a note commitment tree: {}", e)
            }
            Error::NoteSelection(e) => {
                write!(f, "Note selection encountered the following error: {}", e)
            }
            Error::Proposal(e) => {
                write!(f, "Input selection attempted to construct an invalid proposal: {}", e)
            }
            Error::ProposalNotSupported => {
                write!(
                    f,
                    "The proposal was valid, but spending shielded outputs of prior transaction steps is not yet supported."
                )
            }
            Error::KeyNotRecognized => {
                write!(
                    f,
                    "Wallet does not contain an account corresponding to the provided spending key"
                )
            }
            Error::BalanceError(e) => write!(
                f,
                "The value lies outside the valid range of Zcash amounts: {:?}.",
                e
            ),
            Error::InsufficientFunds { available, required } => write!(
                f,
                "Insufficient balance (have {}, need {} including fee)",
                u64::from(*available),
                u64::from(*required)
            ),
            Error::ScanRequired => write!(f, "Must scan blocks first"),
            Error::Builder(e) => write!(f, "An error occurred building the transaction: {}", e),
            Error::MemoForbidden => write!(f, "It is not possible to send a memo to a transparent address."),
            Error::UnsupportedChangeType(t) => write!(f, "Attempted to send change to an unsupported pool type: {}", t),
            Error::NoSupportedReceivers(ua) => write!(
                f,
                "A recipient's unified address does not contain any receivers to which the wallet can send funds; required one of {}",
                ua.receiver_types().iter().enumerate().map(|(i, tc)| format!("{}{:?}", if i > 0 { ", " } else { "" }, tc)).collect::<String>()
            ),
            Error::NoSpendingKey(addr) => write!(f, "No spending key available for address: {}", addr),
            Error::NoteMismatch(n) => write!(f, "A note being spent ({:?}) does not correspond to either the internal or external full viewing key for the provided spending key.", n),

            Error::Address(e) => {
                write!(f, "An error occurred decoding the address from a payment request: {}.", e)
            }
            #[cfg(feature = "transparent-inputs")]
            Error::AddressNotRecognized(_) => {
                write!(f, "The specified transparent address was not recognized as belonging to the wallet.")
            }
        }
    }
}

impl<DE, CE, SE, FE> error::Error for Error<DE, CE, SE, FE>
where
    DE: Debug + Display + error::Error + 'static,
    CE: Debug + Display + error::Error + 'static,
    SE: Debug + Display + error::Error + 'static,
    FE: Debug + Display + 'static,
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::DataSource(e) => Some(e),
            Error::CommitmentTree(e) => Some(e),
            Error::NoteSelection(e) => Some(e),
            Error::Proposal(e) => Some(e),
            Error::Builder(e) => Some(e),
            _ => None,
        }
    }
}

impl<DE, CE, SE, FE> From<builder::Error<FE>> for Error<DE, CE, SE, FE> {
    fn from(e: builder::Error<FE>) -> Self {
        Error::Builder(e)
    }
}

impl<DE, CE, SE, FE> From<BalanceError> for Error<DE, CE, SE, FE> {
    fn from(e: BalanceError) -> Self {
        Error::BalanceError(e)
    }
}

impl<DE, CE, SE, FE> From<ConversionError<&'static str>> for Error<DE, CE, SE, FE> {
    fn from(value: ConversionError<&'static str>) -> Self {
        Error::Address(value)
    }
}

impl<DE, CE, SE, FE> From<InputSelectorError<DE, SE>> for Error<DE, CE, SE, FE> {
    fn from(e: InputSelectorError<DE, SE>) -> Self {
        match e {
            InputSelectorError::DataSource(e) => Error::DataSource(e),
            InputSelectorError::Selection(e) => Error::NoteSelection(e),
            InputSelectorError::Proposal(e) => Error::Proposal(e),
            InputSelectorError::InsufficientFunds {
                available,
                required,
            } => Error::InsufficientFunds {
                available,
                required,
            },
            InputSelectorError::SyncRequired => Error::ScanRequired,
            InputSelectorError::Address(e) => Error::Address(e),
        }
    }
}

impl<DE, CE, SE, FE> From<sapling::builder::Error> for Error<DE, CE, SE, FE> {
    fn from(e: sapling::builder::Error) -> Self {
        Error::Builder(builder::Error::SaplingBuild(e))
    }
}

impl<DE, CE, SE, FE> From<transparent::builder::Error> for Error<DE, CE, SE, FE> {
    fn from(e: transparent::builder::Error) -> Self {
        Error::Builder(builder::Error::TransparentBuild(e))
    }
}

impl<DE, CE, SE, FE> From<ShardTreeError<CE>> for Error<DE, CE, SE, FE> {
    fn from(e: ShardTreeError<CE>) -> Self {
        Error::CommitmentTree(e)
    }
}
