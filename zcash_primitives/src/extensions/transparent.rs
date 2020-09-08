//! Core traits and structs for Transparent Zcash Extensions.

use crate::transaction::components::{Amount, OutPoint, TzeOut};
use std::fmt;

/// Binary parsing capability for TZE preconditions & witnesses.
///
/// Serialization formats interpreted by implementations of this
/// trait become consensus-critical upon activation of of the
/// extension that uses them.
pub trait FromPayload: Sized {
    type Error;

    /// Parses an extension type from a mode and payload.
    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error>;
}

/// Binary serialization capability for TZE preconditions & witnesses.
///
/// Serialization formats used by implementations of this
/// trait become consensus-critical upon activation of of the
/// extension that uses them.
pub trait ToPayload {
    /// Returns a serialized payload and its corresponding mode.
    fn to_payload(&self) -> (u32, Vec<u8>);
}

/// A condition that can be used to encumber transparent funds.
///
/// This struct is an intermediate representation between the 
/// serialized binary format which is used inside of a transaction
/// and extension-specific types. The payload field of this struct
/// is treated as opaque to all but extension corresponding to the
/// encapsulated extension_id value.
#[derive(Clone, Debug)]
pub struct Precondition {
    pub extension_id: u32,
    pub mode: u32,
    pub payload: Vec<u8>,
}

impl Precondition {
    /// Produce the intermediate format for an extension-specific precondition
    /// type.
    pub fn from<P: ToPayload>(extension_id: u32, value: &P) -> Precondition {
        let (mode, payload) = value.to_payload();
        Precondition {
            extension_id,
            mode,
            payload,
        }
    }

    /// Attempt to parse an extension-specific precondition value from the 
    /// intermediate representation.
    pub fn try_to<P: FromPayload>(&self) -> Result<P, P::Error> {
        P::from_payload(self.mode, &self.payload)
    }
}

/// Data that satisfies the precondition for prior encumbered funds, enabling them to be
/// spent.
///
/// This struct is an intermediate representation between the 
/// serialized binary format which is used inside of a transaction
/// and extension-specific types. The payload field of this struct
/// is treated as opaque to all but extension corresponding to the
/// encapsulated extension_id value.
#[derive(Clone, Debug)]
pub struct Witness {
    pub extension_id: u32,
    pub mode: u32,
    pub payload: Vec<u8>,
}

impl Witness {
    /// Produce the intermediate format for an extension-specific witness
    /// type.
    pub fn from<P: ToPayload>(extension_id: u32, value: &P) -> Witness {
        let (mode, payload) = value.to_payload();
        Witness {
            extension_id,
            mode,
            payload,
        }
    }

    /// Attempt to parse an extension-specific witness value from the 
    /// intermediate representation.
    pub fn try_to<P: FromPayload>(&self) -> Result<P, P::Error> {
        P::from_payload(self.mode, &self.payload)
    }
}

#[derive(Debug, PartialEq)]
pub enum Error<E> {
    InvalidExtensionId(u32),
    ProgramError(E),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidExtensionId(extension_id) => {
                write!(f, "Unrecognized program type id {}", extension_id)
            }

            Error::ProgramError(err) => write!(f, "Program error: {}", err),
        }
    }
}

pub trait Extension<C> {
    type P;
    type W;
    type Error;

    fn verify_inner(
        &self,
        precondition: &Self::P,
        witness: &Self::W,
        context: &C,
    ) -> Result<(), Self::Error>;

    fn verify(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        context: &C,
    ) -> Result<(), Self::Error>
    where
        Self::P: FromPayload<Error = Self::Error>,
        Self::W: FromPayload<Error = Self::Error>,
    {
        self.verify_inner(
            &Self::P::from_payload(precondition.mode, &precondition.payload)?,
            &Self::W::from_payload(witness.mode, &witness.payload)?,
            &context,
        )
    }
}

/// This extension trait is satisfied by [`transaction::builder::Builder`]. It provides a minimal
/// contract for interacting with the transaction builder, that extension library authors can use
/// to add extension-specific builder traits that may be used to interact with the transaction
/// builder. This may make it simpler for projects that include transaction-builder functionality
/// to integrate with third-party extensions without those extensions being coupled to a particular
/// transaction or builder representation.
///
/// [`transaction::builder::Builder`]: crate::transaction::builder::Builder
pub trait ExtensionTxBuilder<'a> {
    type BuildCtx;
    type BuildError;

    /// Add a TZE input to the transaction under construction by providing a witness
    /// to a precondition identified by a prior outpoint. 
    ///
    /// The `witness_builder` function allows the transaction builder to provide extra
    /// contextual information from the transaction under construction to be used 
    /// in the production of this witness (for example, so that the witness may
    /// internally make commitments based upon this information.) For the standard
    /// transaction builder, the value provided here is the transaction under
    /// construction.
    fn add_tze_input<WBuilder, W: ToPayload>(
        &mut self,
        extension_id: u32,
        prevout: (OutPoint, TzeOut),
        witness_builder: WBuilder,
    ) -> Result<(), Self::BuildError>
    where
        WBuilder: 'a + (FnOnce(&Self::BuildCtx) -> Result<W, Self::BuildError>);

    /// Add a TZE precondition to the transaction which must be satisfied by a future
    /// transaction's witness in order to spend the specified amount.
    fn add_tze_output<P: ToPayload>(
        &mut self,
        extension_id: u32,
        value: Amount,
        guarded_by: &P,
    ) -> Result<(), Self::BuildError>;
}

pub trait Epoch<VerifyCtx> {
    type VerifyError;

    /// Checks that the provided witness satisfies the specified precondition,
    /// given the context. This verification becomes part of the consensus rules.
    fn verify(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        ctx: &VerifyCtx,
    ) -> Result<(), Error<Self::VerifyError>>;
}
