//! Core traits and structs for Transparent Zcash Extensions.

use crate::transaction::components::{Amount, OutPoint, TzeOut};
use std::fmt;

pub trait FromPayload: Sized {
    type Error;

    /// Parses an extension type from a mode and payload.
    fn from_payload(mode: usize, payload: &[u8]) -> Result<Self, Self::Error>;
}

pub trait ToPayload {
    /// Returns a serialized payload and its corresponding mode.
    fn to_payload(&self) -> (usize, Vec<u8>);
}

/// A condition that can be used to encumber transparent funds.
#[derive(Clone, Debug)]
pub struct Precondition {
    pub extension_id: usize,
    pub mode: usize,
    pub payload: Vec<u8>,
}

impl Precondition {
    pub fn from<P: ToPayload>(extension_id: usize, value: &P) -> Precondition {
        let (mode, payload) = value.to_payload();
        Precondition {
            extension_id,
            mode,
            payload,
        }
    }

    pub fn try_to<P: FromPayload>(&self) -> Result<P, P::Error> {
        P::from_payload(self.mode, &self.payload)
    }
}

/// Data that satisfies the precondition for prior encumbered funds, enabling them to be
/// spent.
#[derive(Clone, Debug)]
pub struct Witness {
    pub extension_id: usize,
    pub mode: usize,
    pub payload: Vec<u8>,
}

impl Witness {
    pub fn from<P: ToPayload>(extension_id: usize, value: &P) -> Witness {
        let (mode, payload) = value.to_payload();
        Witness {
            extension_id,
            mode,
            payload,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Error<E> {
    InvalidForEpoch(u32, usize),
    InvalidExtensionId(usize),
    ProgramError(E),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidForEpoch(cid, ptype) => write!(
                f,
                "Program type {} is invalid for consensus branch id {}",
                ptype, cid
            ),

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

// This extension trait is satisfied by the transaction::builder::Builder type. It provides a
// minimal contract for interacting with the transaction builder, that extension library authors
// can use to add extension-specific builder traits that may be used to interact with the
// transaction builder.  This may make it simpler for projects that include transaction-builder
// functionality to integrate with third-party extensions without those extensions being coupled to
// a particular transaction or builder representation.
pub trait ExtensionTxBuilder<'a> {
    type BuildCtx;
    type BuildError;

    fn add_tze_input<WBuilder, W: ToPayload>(
        &mut self,
        extension_id: usize,
        prevout: (OutPoint, TzeOut),
        witness_builder: WBuilder,
    ) -> Result<(), Self::BuildError>
    where
        WBuilder: 'a + (FnOnce(&Self::BuildCtx) -> Result<W, Self::BuildError>);

    fn add_tze_output<P: ToPayload>(
        &mut self,
        extension_id: usize,
        value: Amount,
        guarded_by: &P,
    ) -> Result<(), Self::BuildError>;
}

pub trait Epoch<VerifyCtx> {
    type VerifyError;

    // Implementation of this method should check that the provided witness
    // satisfies the specified precondition, given the context. This verification
    // becomes part of the consensus rules.
    fn verify(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        ctx: &VerifyCtx,
    ) -> Result<(), Error<Self::VerifyError>>;
}
