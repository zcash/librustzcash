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
use stwo::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};

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
    /// Contains the serialized Cairo proof data and metadata for verification.
    #[derive(Debug, Clone)]
    pub struct Witness {
        /// Serialized Cairo proof (JSON format)
        pub proof_data: Vec<u8>,
        /// Whether the proof includes Pedersen builtin
        pub with_pedersen: bool,
    }

    // Manual PartialEq implementation since we need to compare the struct
    impl PartialEq for Witness {
        fn eq(&self, other: &Self) -> bool {
            self.proof_data == other.proof_data && self.with_pedersen == other.with_pedersen
        }
    }

    impl Eq for Witness {}
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
    pub fn verify(proof_data: Vec<u8>, with_pedersen: bool) -> Self {
        Witness::Verify(verify::Witness {
            proof_data,
            with_pedersen,
        })
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
                // Payload format: [with_pedersen (1 byte)] + [proof_data]
                if payload.is_empty() {
                    return Err(Error::IllegalPayloadLength(0));
                }

                let with_pedersen = payload[0] != 0;
                let proof_data = payload[1..].to_vec();

                Ok(Witness::verify(proof_data, with_pedersen))
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Witness::Verify(w) => {
                let mut payload = vec![if w.with_pedersen { 1 } else { 0 }];
                payload.extend_from_slice(&w.proof_data);
                (verify::MODE, payload)
            }
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
    /// Verifies a STARK proof embedded in the witness against the precondition.
    fn verify_inner(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        _context: &C,
    ) -> Result<(), Error> {
        match (precondition, witness) {
            (Precondition::Verify(_), Witness::Verify(w)) => {
                // Parse the Cairo proof from JSON
                let proof_str = std::str::from_utf8(&w.proof_data)
                    .map_err(|_| Error::VerificationFailed)?;

                let cairo_proof: CairoProof<Blake2sMerkleHasher> =
                    serde_json::from_str(proof_str).map_err(|_| Error::VerificationFailed)?;

                // Determine the preprocessed trace variant based on Pedersen flag
                let preprocessed_trace = if w.with_pedersen {
                    PreProcessedTraceVariant::Canonical
                } else {
                    PreProcessedTraceVariant::CanonicalWithoutPedersen
                };

                // Verify the STARK proof (matching cairo-prove CLI exactly)
                verify_cairo::<Blake2sMerkleChannel>(
                    cairo_proof,
                    preprocessed_trace,
                )
                .map_err(|_| Error::VerificationFailed)?;

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
        proof_data: Vec<u8>,
        with_pedersen: bool,
    ) -> Result<(), StarkVerifyBuildError<B::BuildError>> {
        // Validate that the previous output has a verify precondition
        match Precondition::from_payload(
            prevout.1.precondition.mode,
            &prevout.1.precondition.payload,
        ) {
            Err(parse_failure) => Err(StarkVerifyBuildError::PrevoutParseFailure(parse_failure)),
            Ok(Precondition::Verify(_)) => {
                self.txn_builder
                    .add_tze_input(self.extension_id, verify::MODE, prevout, move |_| {
                        Ok(Witness::verify(proof_data.clone(), with_pedersen))
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
        let proof_data = b"test proof data".to_vec();
        let with_pedersen = false;

        // Create payload: [with_pedersen flag] + [proof_data]
        let mut payload = vec![if with_pedersen { 1 } else { 0 }];
        payload.extend_from_slice(&proof_data);

        let w = Witness::from_payload(verify::MODE, &payload).unwrap();
        assert_eq!(w, Witness::verify(proof_data.clone(), with_pedersen));
        assert_eq!(w.to_payload(), (verify::MODE, payload));
    }

    #[test]
    fn witness_rejects_invalid_mode() {
        let w = Witness::from_payload(99, &[]);
        assert!(w.is_err());
    }

    #[test]
    fn witness_accepts_valid_payload() {
        // Valid payload with flag and data
        let w = Witness::from_payload(verify::MODE, &[0, 1, 2, 3]);
        assert!(w.is_ok());
    }

    #[test]
    fn witness_rejects_empty_payload() {
        // Empty payload should be rejected (needs at least the flag byte)
        let w = Witness::from_payload(verify::MODE, &[]);
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

        // Create spending transaction with a dummy witness (just for structural test)
        let in_witness = TzeIn {
            prevout: OutPoint::new(tx.txid(), 0),
            witness: tze::Witness::from(0, &Witness::verify(vec![1, 2, 3], false)),
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

        // Verify the spend - this should fail with dummy data
        let ctx = Ctx;
        let result = Program.verify(
            &tx.tze_bundle().unwrap().vout[0].precondition,
            &tx_spend.tze_bundle().unwrap().vin[0].witness,
            &ctx,
        );
        // Dummy proof data should fail verification
        assert!(result.is_err());
    }

    /// This test demonstrates the full STARK verification integration using actual transactions.
    #[test]
    fn verify_proof_all_opcode_components() {
        // Load the embedded proof from test fixtures
        //
        // Generated using this command inside stwo-cairo stwo_cairo_prover crate:
        // ./target/release/run_and_prove \
        //   --program ./test_data/test_prove_verify_all_opcode_components/compiled.json \
        //   --proof_path example_proof.json \
        //   --verify
        let proof_str = include_str!("../../tests/fixtures/all_opcode_components_proof.json");
        let proof_data = proof_str.as_bytes().to_vec();

        //
        // Create a transaction with a STARK verification precondition output
        //
        let out = TzeOut {
            value: Zatoshis::from_u64(100000).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::verify()),
        };

        let tx_a = TransactionData::from_parts_zfuture(
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

        //
        // Create a spending transaction with the STARK proof witness
        //
        let in_witness = TzeIn {
            prevout: OutPoint::new(tx_a.txid(), 0),
            witness: tze::Witness::from(0, &Witness::verify(proof_data, true)),
        };

        let tx_b = TransactionData::from_parts_zfuture(
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

        //
        // Verify the spending transaction using the full verification path
        //
        let ctx = Ctx;
        let result = Program.verify(
            &tx_a.tze_bundle().unwrap().vout[0].precondition,
            &tx_b.tze_bundle().unwrap().vin[0].witness,
            &ctx,
        );

        // The proof should verify successfully
        assert!(
            result.is_ok(),
            "STARK proof verification failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn verify_inner_basic_flow() {
        // This test demonstrates that the verify_inner function is properly wired up
        // and can parse/verify proofs. It expects failure with invalid proof data,
        // which confirms the verification logic is running.

        let ctx = Ctx;
        let precondition = Precondition::verify();

        // Test 1: Invalid JSON should fail at parsing stage
        let invalid_json = b"{invalid json}".to_vec();
        let witness = Witness::verify(invalid_json, false);
        let result = Program.verify_inner(&precondition, &witness, &ctx);
        assert!(
            result.is_err(),
            "Invalid JSON should fail verification"
        );

        // Test 2: Valid JSON but not a proof should fail
        let not_a_proof = br#"{"foo": "bar"}"#.to_vec();
        let witness = Witness::verify(not_a_proof, false);
        let result = Program.verify_inner(&precondition, &witness, &ctx);
        assert!(
            result.is_err(),
            "Non-proof JSON should fail verification"
        );

        // This confirms that:
        // 1. Witness data is being passed through correctly
        // 2. JSON parsing is attempted
        // 3. Verification logic is invoked
        // 4. Errors are properly propagated
    }
}
