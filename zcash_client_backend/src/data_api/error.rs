//! Types for wallet error handling.

use std::error;
use std::fmt::{self, Debug, Display};

use shardtree::error::ShardTreeError;
use zcash_address::ConversionError;
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::builder;
use zcash_protocol::{
    PoolType,
    value::{BalanceError, Zatoshis},
};

use crate::{
    data_api::wallet::input_selection::InputSelectorError, fees::ChangeError,
    proposal::ProposalError, wallet::NoteId,
};

#[cfg(feature = "transparent-inputs")]
use ::transparent::address::TransparentAddress;

/// Errors that can occur as a consequence of wallet operations.
#[derive(Debug)]
pub enum Error<DataSourceError, CommitmentTreeError, SelectionError, FeeError, ChangeErrT, NoteRefT>
{
    /// An error occurred retrieving data from the underlying data source
    DataSource(DataSourceError),

    /// An error in computations involving the note commitment trees.
    CommitmentTree(ShardTreeError<CommitmentTreeError>),

    /// An error in note selection
    NoteSelection(SelectionError),

    /// An error in change selection during transaction proposal construction
    Change(ChangeError<ChangeErrT, NoteRefT>),

    /// An error in transaction proposal construction
    Proposal(ProposalError),

    /// The proposal was structurally valid, but tried to do one of these unsupported things:
    /// * spend a prior shielded output;
    /// * pay to an output pool for which the corresponding feature is not enabled;
    /// * pay to a TEX address if the "transparent-inputs" feature is not enabled.
    /// * a proposal step has no inputs
    ProposalNotSupported,

    /// No account could be found corresponding to a provided ID.
    AccountIdNotRecognized,

    /// No account could be found corresponding to a provided spending key.
    KeyNotRecognized,

    /// The given account cannot be used for spending, because it is unable to maintain an
    /// accurate balance.
    AccountCannotSpend,

    /// Zcash amount computation encountered an overflow or underflow.
    BalanceError(BalanceError),

    /// Unable to create a new spend because the wallet balance is not sufficient.
    InsufficientFunds {
        available: Zatoshis,
        required: Zatoshis,
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

    /// A proposed transaction cannot be built because it requires spending an input of
    /// a type for which a key required to construct the transaction is not available.
    KeyNotAvailable(PoolType),

    /// A note being spent does not correspond to either the internal or external
    /// full viewing key for an account.
    NoteMismatch(NoteId),

    /// An error occurred parsing the address from a payment request.
    Address(ConversionError<&'static str>),

    /// The address associated with a record being inserted was not recognized as
    /// belonging to the wallet.
    #[cfg(feature = "transparent-inputs")]
    AddressNotRecognized(TransparentAddress),

    /// An error occurred while working with PCZTs.
    #[cfg(feature = "pczt")]
    Pczt(PcztError),
}

/// Errors that can occur while working with PCZTs.
#[cfg(feature = "pczt")]
#[derive(Debug)]
pub enum PcztError {
    /// An error occurred while building a PCZT.
    Build,

    /// An error occurred while finalizing the IO of a PCZT.
    IoFinalization(pczt::roles::io_finalizer::Error),

    /// An error occurred while updating the Orchard bundle of a PCZT.
    UpdateOrchard(pczt::roles::updater::OrchardError),

    /// An error occurred while updating the Sapling bundle of a PCZT.
    UpdateSapling(pczt::roles::updater::SaplingError),

    /// An error occurred while updating the transparent bundle of a PCZT.
    UpdateTransparent(pczt::roles::updater::TransparentError),

    /// An error occurred while finalizing the spends of a PCZT.
    SpendFinalization(pczt::roles::spend_finalizer::Error),

    /// An error occurred while extracting a transaction from a PCZT.
    Extraction(pczt::roles::tx_extractor::Error),

    /// PCZT parsing resulted in an invalid condition.
    Invalid(String),
}

impl<DE, TE, SE, FE, CE, N> fmt::Display for Error<DE, TE, SE, FE, CE, N>
where
    DE: fmt::Display,
    TE: fmt::Display,
    SE: fmt::Display,
    FE: fmt::Display,
    CE: fmt::Display,
    N: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write;

        match self {
            Error::DataSource(e) => {
                write!(
                    f,
                    "The underlying datasource produced the following error: {e}"
                )
            }
            Error::CommitmentTree(e) => {
                write!(
                    f,
                    "An error occurred in querying or updating a note commitment tree: {e}"
                )
            }
            Error::NoteSelection(e) => {
                write!(f, "Note selection encountered the following error: {e}")
            }
            Error::Change(e) => {
                write!(f, "Change output generation failed: {e}")
            }
            Error::Proposal(e) => {
                write!(
                    f,
                    "Input selection attempted to construct an invalid proposal: {e}"
                )
            }
            Error::ProposalNotSupported => write!(
                f,
                "The proposal was valid but tried to do something that is not supported \
                 (spend shielded outputs of prior transaction steps or use a feature that \
                 is not enabled).",
            ),
            Error::KeyNotRecognized => {
                write!(
                    f,
                    "Wallet does not contain an account corresponding to the provided spending key"
                )
            }
            Error::AccountCannotSpend => {
                write!(
                    f,
                    "The given account cannot be used for spending, because it is unable to maintain an accurate balance.",
                )
            }
            Error::AccountIdNotRecognized => {
                write!(
                    f,
                    "Wallet does not contain an account corresponding to the provided ID"
                )
            }
            Error::BalanceError(e) => write!(
                f,
                "The value lies outside the valid range of Zcash amounts: {e:?}."
            ),
            Error::InsufficientFunds {
                available,
                required,
            } => write!(
                f,
                "Insufficient balance (have {}, need {} including fee)",
                u64::from(*available),
                u64::from(*required)
            ),
            Error::ScanRequired => write!(f, "Must scan blocks first"),
            Error::Builder(e) => write!(f, "An error occurred building the transaction: {e}"),
            Error::MemoForbidden => write!(
                f,
                "It is not possible to send a memo to a transparent address."
            ),
            Error::UnsupportedChangeType(t) => write!(
                f,
                "Attempted to send change to an unsupported pool type: {t}"
            ),
            Error::NoSupportedReceivers(ua) => write!(
                f,
                "A recipient's unified address does not contain any receivers to which the wallet can send funds; required one of {}",
                ua.receiver_types()
                    .iter()
                    .enumerate()
                    .fold(String::new(), |mut acc, (i, tc)| {
                        let _ = write!(acc, "{}{:?}", if i > 0 { ", " } else { "" }, tc);
                        acc
                    })
            ),
            Error::KeyNotAvailable(pool) => write!(
                f,
                "A key required for transaction construction was not available for pool type {pool}"
            ),
            Error::NoteMismatch(n) => write!(
                f,
                "A note being spent ({n:?}) does not correspond to either the internal or external full viewing key for the provided spending key."
            ),

            Error::Address(e) => {
                write!(
                    f,
                    "An error occurred decoding the address from a payment request: {e}."
                )
            }
            #[cfg(feature = "transparent-inputs")]
            Error::AddressNotRecognized(_) => {
                write!(
                    f,
                    "The specified transparent address was not recognized as belonging to the wallet."
                )
            }
            #[cfg(feature = "pczt")]
            Error::Pczt(e) => write!(f, "PCZT error: {e}"),
        }
    }
}

#[cfg(feature = "pczt")]
impl fmt::Display for PcztError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PcztError::Build => {
                write!(
                    f,
                    "Failed to generate the PCZT prior to proving or signing."
                )
            }
            PcztError::IoFinalization(e) => {
                write!(f, "Failed to finalize IO: {e:?}.")
            }
            PcztError::UpdateOrchard(e) => {
                write!(f, "Failed to updating Orchard PCZT data: {e:?}.")
            }
            PcztError::UpdateSapling(e) => {
                write!(f, "Failed to updating Sapling PCZT data: {e:?}.")
            }
            PcztError::UpdateTransparent(e) => {
                write!(f, "Failed to updating transparent PCZT data: {e:?}.")
            }
            PcztError::SpendFinalization(e) => {
                write!(f, "Failed to finalize the PCZT spends: {e:?}.")
            }
            PcztError::Extraction(e) => {
                write!(f, "Failed to extract the final transaction: {e:?}.")
            }
            PcztError::Invalid(e) => {
                write!(f, "PCZT parsing resulted in an invalid condition: {e}.")
            }
        }
    }
}

impl<DE, TE, SE, FE, CE, N> error::Error for Error<DE, TE, SE, FE, CE, N>
where
    DE: Debug + Display + error::Error + 'static,
    TE: Debug + Display + error::Error + 'static,
    SE: Debug + Display + error::Error + 'static,
    FE: Debug + Display + 'static,
    CE: Debug + Display + error::Error + 'static,
    N: Debug + Display + 'static,
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::DataSource(e) => Some(e),
            Error::CommitmentTree(e) => Some(e),
            Error::NoteSelection(e) => Some(e),
            Error::Proposal(e) => Some(e),
            Error::Builder(e) => Some(e),
            #[cfg(feature = "pczt")]
            Error::Pczt(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "pczt")]
impl error::Error for PcztError {}

impl<DE, TE, SE, FE, CE, N> From<builder::Error<FE>> for Error<DE, TE, SE, FE, CE, N> {
    fn from(e: builder::Error<FE>) -> Self {
        Error::Builder(e)
    }
}

impl<DE, TE, SE, FE, CE, N> From<ProposalError> for Error<DE, TE, SE, FE, CE, N> {
    fn from(e: ProposalError) -> Self {
        Error::Proposal(e)
    }
}

impl<DE, TE, SE, FE, CE, N> From<BalanceError> for Error<DE, TE, SE, FE, CE, N> {
    fn from(e: BalanceError) -> Self {
        Error::BalanceError(e)
    }
}

impl<DE, TE, SE, FE, CE, N> From<ConversionError<&'static str>> for Error<DE, TE, SE, FE, CE, N> {
    fn from(value: ConversionError<&'static str>) -> Self {
        Error::Address(value)
    }
}

impl<DE, TE, SE, FE, CE, N> From<InputSelectorError<DE, SE, CE, N>>
    for Error<DE, TE, SE, FE, CE, N>
{
    fn from(e: InputSelectorError<DE, SE, CE, N>) -> Self {
        match e {
            InputSelectorError::DataSource(e) => Error::DataSource(e),
            InputSelectorError::Selection(e) => Error::NoteSelection(e),
            InputSelectorError::Change(e) => Error::Change(e),
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

impl<DE, TE, SE, FE, CE, N> From<sapling::builder::Error> for Error<DE, TE, SE, FE, CE, N> {
    fn from(e: sapling::builder::Error) -> Self {
        Error::Builder(builder::Error::SaplingBuild(e))
    }
}

impl<DE, TE, SE, FE, CE, N> From<transparent::builder::Error> for Error<DE, TE, SE, FE, CE, N> {
    fn from(e: ::transparent::builder::Error) -> Self {
        Error::Builder(builder::Error::TransparentBuild(e))
    }
}

impl<DE, TE, SE, FE, CE, N> From<ShardTreeError<TE>> for Error<DE, TE, SE, FE, CE, N> {
    fn from(e: ShardTreeError<TE>) -> Self {
        Error::CommitmentTree(e)
    }
}

#[cfg(feature = "pczt")]
impl<DE, TE, SE, FE, CE, N> From<PcztError> for Error<DE, TE, SE, FE, CE, N> {
    fn from(e: PcztError) -> Self {
        Error::Pczt(e)
    }
}

#[cfg(feature = "pczt")]
impl<DE, TE, SE, FE, CE, N> From<pczt::roles::io_finalizer::Error>
    for Error<DE, TE, SE, FE, CE, N>
{
    fn from(e: pczt::roles::io_finalizer::Error) -> Self {
        Error::Pczt(PcztError::IoFinalization(e))
    }
}

#[cfg(feature = "pczt")]
impl<DE, TE, SE, FE, CE, N> From<pczt::roles::updater::OrchardError>
    for Error<DE, TE, SE, FE, CE, N>
{
    fn from(e: pczt::roles::updater::OrchardError) -> Self {
        Error::Pczt(PcztError::UpdateOrchard(e))
    }
}

#[cfg(feature = "pczt")]
impl<DE, TE, SE, FE, CE, N> From<pczt::roles::updater::SaplingError>
    for Error<DE, TE, SE, FE, CE, N>
{
    fn from(e: pczt::roles::updater::SaplingError) -> Self {
        Error::Pczt(PcztError::UpdateSapling(e))
    }
}

#[cfg(feature = "pczt")]
impl<DE, TE, SE, FE, CE, N> From<pczt::roles::updater::TransparentError>
    for Error<DE, TE, SE, FE, CE, N>
{
    fn from(e: pczt::roles::updater::TransparentError) -> Self {
        Error::Pczt(PcztError::UpdateTransparent(e))
    }
}

#[cfg(feature = "pczt")]
impl<DE, TE, SE, FE, CE, N> From<pczt::roles::spend_finalizer::Error>
    for Error<DE, TE, SE, FE, CE, N>
{
    fn from(e: pczt::roles::spend_finalizer::Error) -> Self {
        Error::Pczt(PcztError::SpendFinalization(e))
    }
}

#[cfg(feature = "pczt")]
impl<DE, TE, SE, FE, CE, N> From<pczt::roles::tx_extractor::Error>
    for Error<DE, TE, SE, FE, CE, N>
{
    fn from(e: pczt::roles::tx_extractor::Error) -> Self {
        Error::Pczt(PcztError::Extraction(e))
    }
}
