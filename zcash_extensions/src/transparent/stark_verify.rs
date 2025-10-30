//! STARK proof verification TZE implementation.
//!
//! This extension enables verification of STARK proofs within Zcash transactions.
//! The extension validates STARK proofs embedded in transaction witnesses against
//! verification keys and public inputs specified in preconditions.
//!
//! For now, this is a minimal implementation that always succeeds, providing
//! the structural foundation for proper STARK verification.

use std::fmt;
use std::ops::{Deref, DerefMut};

// Stwo Cairo imports for STARK verification
use cairo_air::verifier::verify_cairo;
use cairo_air::{CairoProof, PreProcessedTraceVariant};
use stwo::core::channel::MerkleChannel;

use zcash_primitives::{
    extensions::transparent::{Extension, ExtensionTxBuilder, FromPayload, ToPayload},
    transaction::components::tze::OutPoint,
};
use zcash_protocol::value::Zatoshis;

/// Types and constants used for Mode 0 (verify STARK proof)
mod verify {
    pub const MODE: u32 = 0;

    /// Precondition for STARK verification.
    /// Currently empty, will later contain verification key and public inputs.
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct Precondition;

    /// Witness containing STARK proof.
    /// Currently empty, will later contain the actual proof data.
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct Witness;
}

/// The precondition type for the stark_verify extension.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Precondition {
    Verify(verify::Precondition),
}

impl Precondition {
    /// Convenience constructor for verify precondition values.
    pub fn verify() -> Self {
        Precondition::Verify(verify::Precondition)
    }
}

/// Errors that may be produced during parsing and verification of stark_verify
/// preconditions and witnesses.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Parse error indicating that the payload length was invalid.
    IllegalPayloadLength(usize),
    /// Verification error indicating that the specified mode was not recognized.
    ModeInvalid(u32),
    /// Verification error indicating that the witness being verified did not
    /// satisfy the precondition.
    VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IllegalPayloadLength(sz) => {
                write!(f, "Illegal payload length for stark_verify: {}", sz)
            }
            Error::ModeInvalid(m) => write!(f, "Invalid TZE mode for stark_verify: {}", m),
            Error::VerificationFailed => write!(f, "STARK verification failed"),
        }
    }
}

impl TryFrom<(u32, Precondition)> for Precondition {
    type Error = Error;

    fn try_from(from: (u32, Self)) -> Result<Self, Self::Error> {
        match from {
            (verify::MODE, Precondition::Verify(p)) => Ok(Precondition::Verify(p)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl FromPayload for Precondition {
    type Error = Error;

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            verify::MODE => {
                // For now, accept empty payload
                if payload.is_empty() {
                    Ok(Precondition::verify())
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Precondition {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Precondition::Verify(_) => (verify::MODE, vec![]),
        }
    }
}

/// The witness type for the stark_verify extension.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Witness {
    Verify(verify::Witness),
}

impl Witness {
    /// Convenience constructor for verify witness values.
    pub fn verify() -> Self {
        Witness::Verify(verify::Witness)
    }
}

impl TryFrom<(u32, Witness)> for Witness {
    type Error = Error;

    fn try_from(from: (u32, Self)) -> Result<Self, Self::Error> {
        match from {
            (verify::MODE, Witness::Verify(w)) => Ok(Witness::Verify(w)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl FromPayload for Witness {
    type Error = Error;

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            verify::MODE => {
                // For now, accept empty payload
                if payload.is_empty() {
                    Ok(Witness::verify())
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Witness::Verify(_) => (verify::MODE, vec![]),
        }
    }
}

/// This trait defines the context information that the stark_verify extension
/// requires from a consensus node integrating this extension.
///
/// Currently minimal; will be extended as STARK verification is implemented.
pub trait Context {}

/// Marker type for the stark_verify extension.
///
/// A value of this type will be used as the receiver for
/// `zcash_primitives::extensions::transparent::Extension` method invocations.
pub struct Program;

impl<C: Context> Extension<C> for Program {
    type Precondition = Precondition;
    type Witness = Witness;
    type Error = Error;

    /// Runs the program against the given precondition, witness, and context.
    ///
    /// For now, this always succeeds. Actual STARK verification logic will be
    /// implemented later.
    fn verify_inner(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        _context: &C,
    ) -> Result<(), Error> {
        match (precondition, witness) {
            (Precondition::Verify(_), Witness::Verify(_)) => {
                // TODO: Implement actual STARK proof verification
                // For now, always succeed
                Ok(())
            }
        }
    }
}

/// Wrapper for [`zcash_primitives::transaction::builder::Builder`] that simplifies
/// constructing transactions that utilize the stark_verify extension.
pub struct StarkVerifyBuilder<B> {
    /// The wrapped transaction builder.
    pub txn_builder: B,

    /// The assigned identifier for this extension.
    pub extension_id: u32,
}

impl<B> Deref for StarkVerifyBuilder<B> {
    type Target = B;

    fn deref(&self) -> &Self::Target {
        &self.txn_builder
    }
}

impl<B> DerefMut for StarkVerifyBuilder<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.txn_builder
    }
}

/// Errors that can occur in construction of transactions using `StarkVerifyBuilder`.
#[derive(Debug)]
pub enum StarkVerifyBuildError<E> {
    /// Wrapper for errors returned from the underlying `Builder`
    BaseBuilderError(E),
    /// Parse failure when reading precondition from previous output
    PrevoutParseFailure(Error),
}

/// Convenience methods for use with [`zcash_primitives::transaction::builder::Builder`]
/// for constructing transactions that utilize the stark_verify extension.
impl<'a, B: ExtensionTxBuilder<'a>> StarkVerifyBuilder<B> {
    /// Add a STARK verification precondition output to the transaction.
    pub fn add_stark_verify_output(
        &mut self,
        value: Zatoshis,
    ) -> Result<(), StarkVerifyBuildError<B::BuildError>> {
        self.txn_builder
            .add_tze_output(self.extension_id, value, &Precondition::verify())
            .map_err(StarkVerifyBuildError::BaseBuilderError)
    }

    /// Add a STARK verification witness input to the transaction.
    pub fn add_stark_verify_input(
        &mut self,
        prevout: (OutPoint, zcash_primitives::transaction::components::tze::TzeOut),
    ) -> Result<(), StarkVerifyBuildError<B::BuildError>> {
        // Validate that the previous output has a verify precondition
        match Precondition::from_payload(
            prevout.1.precondition.mode,
            &prevout.1.precondition.payload,
        ) {
            Err(parse_failure) => Err(StarkVerifyBuildError::PrevoutParseFailure(parse_failure)),
            Ok(Precondition::Verify(_)) => {
                self.txn_builder
                    .add_tze_input(self.extension_id, verify::MODE, prevout, |_| {
                        Ok(Witness::verify())
                    })
                    .map_err(StarkVerifyBuildError::BaseBuilderError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use zcash_primitives::{
        extensions::transparent::{self as tze, Extension, FromPayload, ToPayload},
        transaction::{
            TransactionData, TxVersion,
            components::tze::{Authorized, Bundle, OutPoint, TzeIn, TzeOut},
        },
    };
    use zcash_protocol::{consensus::BranchId, value::Zatoshis};

    use super::{Context, Precondition, Program, Witness, verify};

    #[test]
    fn precondition_verify_round_trip() {
        let data = vec![];
        let p = Precondition::from_payload(verify::MODE, &data).unwrap();
        assert_eq!(p, Precondition::Verify(verify::Precondition));
        assert_eq!(p.to_payload(), (verify::MODE, data));
    }

    #[test]
    fn precondition_rejects_invalid_mode() {
        let p = Precondition::from_payload(99, &[]);
        assert!(p.is_err());
    }

    #[test]
    fn precondition_rejects_non_empty_payload() {
        let p = Precondition::from_payload(verify::MODE, &[1, 2, 3]);
        assert!(p.is_err());
    }

    #[test]
    fn witness_verify_round_trip() {
        let data = vec![];
        let w = Witness::from_payload(verify::MODE, &data).unwrap();
        assert_eq!(w, Witness::verify());
        assert_eq!(w.to_payload(), (verify::MODE, data));
    }

    #[test]
    fn witness_rejects_invalid_mode() {
        let w = Witness::from_payload(99, &[]);
        assert!(w.is_err());
    }

    #[test]
    fn witness_rejects_non_empty_payload() {
        let w = Witness::from_payload(verify::MODE, &[1, 2, 3]);
        assert!(w.is_err());
    }

    /// Dummy context for testing
    struct Ctx;
    impl Context for Ctx {}

    #[test]
    fn stark_verify_program_succeeds() {
        // Create a simple transaction with STARK verify TZE
        let out = TzeOut {
            value: Zatoshis::from_u64(1).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::verify()),
        };

        let tx = TransactionData::from_parts_zfuture(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            #[cfg(feature = "zip-233")]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![],
                vout: vec![out],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        // Create spending transaction
        let in_witness = TzeIn {
            prevout: OutPoint::new(tx.txid(), 0),
            witness: tze::Witness::from(0, &Witness::verify()),
        };

        let tx_spend = TransactionData::from_parts_zfuture(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            #[cfg(feature = "zip-233")]
            Zatoshis::ZERO,
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![in_witness],
                vout: vec![],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        // Verify the spend
        let ctx = Ctx;
        assert_eq!(
            Program.verify(
                &tx.tze_bundle().unwrap().vout[0].precondition,
                &tx_spend.tze_bundle().unwrap().vin[0].witness,
                &ctx
            ),
            Ok(())
        );
    }
}
