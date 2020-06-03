//! Demo implementation of TZE consensus rules.
//!
//! The demo program implements a dual-hash-lock encumbrance with the following form:
//!
//! > `hash = BLAKE2b_256(preimage_1 || BLAKE2b_256(preimage_2))`
//!
//! The two preimages are revealed in sequential transactions, demonstrating how TZEs can
//! impose constraints on how program modes are chained together.
//!
//! The demo program has two modes:
//!
//! - Mode 0: `hash_1 = BLAKE2b_256(preimage_1 || hash_2)`
//! - Mode 1: `hash_2 = BLAKE2b_256(preimage_2)`
//!
//! and uses the following transaction formats:
//!
//! - `tx_a`: `[ [any input types...] ----> TzeOut(value, hash_1) ]`
//! - `tx_b`: `[ TzeIn(tx_a, preimage_1) -> TzeOut(value, hash_2) ]`
//! - `tx_c`: `[ TzeIn(tx_b, preimage_2) -> [any output types...] ]`

use blake2b_simd::Params;
use std::convert::TryFrom;
use std::fmt;

use zcash_primitives::extensions::transparent::{
    Extension, ExtensionTxBuilder, FromPayload, ToPayload,
};
use zcash_primitives::transaction::components::{amount::Amount, OutPoint, TzeOut};

mod open {
    pub const MODE: usize = 0;

    #[derive(Debug, PartialEq)]
    pub struct Precondition(pub [u8; 32]);

    #[derive(Debug, PartialEq)]
    pub struct Witness(pub [u8; 32]);
}

mod close {
    pub const MODE: usize = 1;

    #[derive(Debug, PartialEq)]
    pub struct Precondition(pub [u8; 32]);

    #[derive(Debug, PartialEq)]
    pub struct Witness(pub [u8; 32]);
}

#[derive(Debug, PartialEq)]
pub enum Precondition {
    Open(open::Precondition),
    Close(close::Precondition),
}

impl Precondition {
    pub fn open(hash: [u8; 32]) -> Self {
        Precondition::Open(open::Precondition(hash))
    }

    pub fn close(hash: [u8; 32]) -> Self {
        Precondition::Close(close::Precondition(hash))
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    IllegalPayloadLength(usize),
    ModeInvalid(usize),
    NonTzeTxn,
    HashMismatch, // include hashes?
    ModeMismatch,
    ExpectedClose,
    InvalidOutputQty(usize),
}

impl fmt::Display for Error {
    fn fmt<'a>(&self, f: &mut fmt::Formatter<'a>) -> fmt::Result {
        match self {
            Error::IllegalPayloadLength(sz) => write!(f, "Illegal payload length for demo: {}", sz),
            Error::ModeInvalid(m) => write!(f, "Invalid TZE mode for demo program: {}", m),
            Error::NonTzeTxn => write!(f, "Transaction has non-TZE inputs."),
            Error::HashMismatch => write!(f, "Hash mismatch"),
            Error::ModeMismatch => write!(f, "Extension operation mode mismatch."),
            Error::ExpectedClose => write!(f, "Got open, expected close."),
            Error::InvalidOutputQty(qty) => write!(f, "Incorrect number of outputs: {}", qty),
        }
    }
}

impl TryFrom<(usize, Precondition)> for Precondition {
    type Error = Error;

    fn try_from(from: (usize, Self)) -> Result<Self, Self::Error> {
        match from {
            (open::MODE, Precondition::Open(p)) => Ok(Precondition::Open(p)),
            (close::MODE, Precondition::Close(p)) => Ok(Precondition::Close(p)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl FromPayload for Precondition {
    type Error = Error;

    fn from_payload(mode: usize, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => {
                if payload.len() == 32 {
                    let mut hash = [0; 32];
                    hash.copy_from_slice(&payload);
                    Ok(Precondition::Open(open::Precondition(hash)))
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            close::MODE => {
                if payload.len() == 32 {
                    let mut hash = [0; 32];
                    hash.copy_from_slice(&payload);
                    Ok(Precondition::Close(close::Precondition(hash)))
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Precondition {
    fn to_payload(&self) -> (usize, Vec<u8>) {
        match self {
            Precondition::Open(p) => (open::MODE, p.0.to_vec()),
            Precondition::Close(p) => (close::MODE, p.0.to_vec()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Witness {
    Open(open::Witness),
    Close(close::Witness),
}

impl Witness {
    pub fn open(preimage: [u8; 32]) -> Self {
        Witness::Open(open::Witness(preimage))
    }

    pub fn close(preimage: [u8; 32]) -> Self {
        Witness::Close(close::Witness(preimage))
    }
}

impl TryFrom<(usize, Witness)> for Witness {
    type Error = Error;

    fn try_from(from: (usize, Self)) -> Result<Self, Self::Error> {
        match from {
            (open::MODE, Witness::Open(p)) => Ok(Witness::Open(p)),
            (close::MODE, Witness::Close(p)) => Ok(Witness::Close(p)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl FromPayload for Witness {
    type Error = Error;

    fn from_payload(mode: usize, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => {
                if payload.len() == 32 {
                    let mut preimage = [0; 32];
                    preimage.copy_from_slice(&payload);
                    Ok(Witness::Open(open::Witness(preimage)))
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            close::MODE => {
                if payload.len() == 32 {
                    let mut preimage = [0; 32];
                    preimage.copy_from_slice(&payload);
                    Ok(Witness::Close(close::Witness(preimage)))
                } else {
                    Err(Error::IllegalPayloadLength(payload.len()))
                }
            }
            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (usize, Vec<u8>) {
        match self {
            Witness::Open(w) => (open::MODE, w.0.to_vec()),
            Witness::Close(w) => (close::MODE, w.0.to_vec()),
        }
    }
}

pub trait Context {
    fn is_tze_only(&self) -> bool;
    fn tx_tze_outputs(&self) -> &[TzeOut];
}

pub struct Program;

impl<C: Context> Extension<C> for Program {
    type P = Precondition;
    type W = Witness;
    type Error = Error;

    /// Runs the program against the given precondition, witness, and context.
    ///
    /// At this point the precondition and witness have been parsed and validated
    /// non-contextually, and are guaranteed to both be for this program. All subsequent
    /// validation is this function's responsibility.
    fn verify_inner(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        context: &C,
    ) -> Result<(), Error> {
        // This match statement is selecting the mode that the program is operating in,
        // based on the enums defined in the parser.
        match (precondition, witness) {
            (Precondition::Open(p_open), Witness::Open(w_open)) => {
                // In OPEN mode, we enforce that the transaction must only contain inputs
                // and outputs from this program. The consensus rules enforce that if a
                // transaction contains both TZE inputs and TZE outputs, they must all be
                // of the same program type. Therefore we only need to check that the
                // transaction does not contain any other type of input or output.
                if !context.is_tze_only() {
                    return Err(Error::NonTzeTxn);
                }

                // Next, check that there is only a single TZE output of the correct type.
                let outputs = context.tx_tze_outputs();
                match outputs {
                    [tze_out] => match Precondition::from_payload(
                        tze_out.precondition.mode,
                        &tze_out.precondition.payload,
                    ) {
                        Ok(Precondition::Close(p_close)) => {
                            // Finally, check the precondition:
                            // precondition_open = BLAKE2b_256(witness_open || precondition_close)
                            let mut h = Params::new().hash_length(32).to_state();
                            h.update(&w_open.0);
                            h.update(&p_close.0);
                            let hash = h.finalize();
                            if hash.as_bytes() == p_open.0 {
                                Ok(())
                            } else {
                                Err(Error::HashMismatch)
                            }
                        }
                        Ok(Precondition::Open(_)) => Err(Error::ExpectedClose),
                        Err(e) => Err(e),
                    },
                    _ => Err(Error::InvalidOutputQty(outputs.len())),
                }
            }
            (Precondition::Close(p), Witness::Close(w)) => {
                // In CLOSE mode, we only require that the precondition is satisfied:
                // precondition_close = BLAKE2b_256(witness_close)
                let hash = Params::new().hash_length(32).hash(&w.0);
                if hash.as_bytes() == p.0 {
                    Ok(())
                } else {
                    Err(Error::HashMismatch)
                }
            }
            _ => Err(Error::ModeMismatch),
        }
    }
}

fn builder_hashes(preimage_1: &[u8; 32], preimage_2: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hash_2 = {
        let mut hash = [0; 32];
        hash.copy_from_slice(Params::new().hash_length(32).hash(preimage_2).as_bytes());
        hash
    };

    let hash_1 = {
        let mut hash = [0; 32];
        hash.copy_from_slice(
            Params::new()
                .hash_length(32)
                .to_state()
                .update(preimage_1)
                .update(&hash_2)
                .finalize()
                .as_bytes(),
        );
        hash
    };

    (hash_1, hash_2)
}

pub struct DemoBuilder<B> {
    pub txn_builder: B,
    pub extension_id: usize,
}

#[derive(Debug)]
pub enum DemoBuildError<E> {
    BaseBuilderError(E),
    ExpectedOpen,
    ExpectedClose,
    PrevoutParseFailure(Error),
    TransferMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    CloseMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

impl<'a, B: ExtensionTxBuilder<'a>> DemoBuilder<&mut B> {
    pub fn demo_open(
        &mut self,
        value: Amount,
        preimage_1: [u8; 32],
        preimage_2: [u8; 32],
    ) -> Result<(), DemoBuildError<B::BuildError>> {
        let (hash_1, _) = builder_hashes(&preimage_1, &preimage_2);

        // Call through to the generic builder.
        self.txn_builder
            .add_tze_output(self.extension_id, value, &Precondition::open(hash_1))
            .map_err(DemoBuildError::BaseBuilderError)
    }

    pub fn demo_transfer_to_close(
        &mut self,
        prevout: (OutPoint, TzeOut),
        transfer_amount: Amount,
        preimage_1: [u8; 32],
        preimage_2: [u8; 32],
    ) -> Result<(), DemoBuildError<B::BuildError>> {
        let (hash_1, hash_2) = builder_hashes(&preimage_1, &preimage_2);

        // eagerly validate the relationship between prevout.1 and preimage_1
        match Precondition::from_payload(
            prevout.1.precondition.mode,
            &prevout.1.precondition.payload,
        ) {
            Ok(Precondition::Open(hash)) => {
                if hash.0 != hash_1 {
                    Err(DemoBuildError::TransferMismatch {
                        expected: hash.0,
                        actual: hash_1,
                    })?
                }
            }
            Ok(Precondition::Close(_)) => Err(DemoBuildError::ExpectedOpen)?,
            Err(parse_failure) => Err(DemoBuildError::PrevoutParseFailure(parse_failure))?,
        }

        self.txn_builder
            .add_tze_input(self.extension_id, prevout, move |_| {
                Ok(Witness::open(preimage_1))
            })
            .map_err(DemoBuildError::BaseBuilderError)?;

        self.txn_builder
            .add_tze_output(
                self.extension_id,
                transfer_amount, // can this be > prevout.1.value?
                &Precondition::close(hash_2),
            )
            .map_err(DemoBuildError::BaseBuilderError)
    }

    pub fn demo_close(
        &mut self,
        prevout: (OutPoint, TzeOut),
        preimage_2: [u8; 32],
    ) -> Result<(), DemoBuildError<B::BuildError>> {
        let hash_2 = {
            let mut hash = [0; 32];
            hash.copy_from_slice(Params::new().hash_length(32).hash(&preimage_2).as_bytes());
            hash
        };

        // eagerly validate the relationship between prevout.1 and preimage_2
        match Precondition::from_payload(
            prevout.1.precondition.mode,
            &prevout.1.precondition.payload,
        ) {
            Ok(Precondition::Open(_)) => Err(DemoBuildError::ExpectedClose)?,
            Ok(Precondition::Close(hash)) => {
                if hash.0 != hash_2 {
                    Err(DemoBuildError::CloseMismatch {
                        expected: hash.0,
                        actual: hash_2,
                    })?
                }
            }
            Err(parse_failure) => Err(DemoBuildError::PrevoutParseFailure(parse_failure))?,
        }

        self.txn_builder
            .add_tze_input(self.extension_id, prevout, move |_| {
                Ok(Witness::close(preimage_2))
            })
            .map_err(DemoBuildError::BaseBuilderError)
    }
}

#[cfg(test)]
mod tests {
    use blake2b_simd::Params;
    use ff::PrimeField;

    use super::{close, open, Context, DemoBuilder, Precondition, Program, Witness};
    use zcash_primitives::{
        consensus::BranchId,
        extensions::transparent::{self as tze, Extension, FromPayload, ToPayload},
        jubjub::fs::Fs,
        legacy::TransparentAddress,
        merkle_tree::{CommitmentTree, IncrementalWitness},
        sapling::Node,
        transaction::{
            builder::Builder,
            components::{Amount, OutPoint, TzeIn, TzeOut},
            Transaction, TransactionData,
        },
        zip32::ExtendedSpendingKey,
        JUBJUB,
    };
    use zcash_proofs::prover::LocalTxProver;

    use ff::Field;
    use rand_core::OsRng;

    #[test]
    fn precondition_open_round_trip() {
        let data = vec![7; 32];
        let p = Precondition::from_payload(open::MODE, &data).unwrap();
        assert_eq!(p, Precondition::Open(open::Precondition([7; 32])));
        assert_eq!(p.to_payload(), (open::MODE, data));
    }

    #[test]
    fn precondition_close_round_trip() {
        let data = vec![7; 32];
        let p = Precondition::from_payload(close::MODE, &data).unwrap();
        assert_eq!(p, Precondition::Close(close::Precondition([7; 32])));
        assert_eq!(p.to_payload(), (close::MODE, data));
    }

    #[test]
    fn precondition_rejects_invalid_mode_or_length() {
        for mode in 0..3 {
            for len in &[31, 33] {
                let p = Precondition::from_payload(mode, &vec![7; *len]);
                assert!(p.is_err());
            }
        }
    }

    #[test]
    fn witness_open_round_trip() {
        let data = vec![7; 32];
        let w = Witness::from_payload(open::MODE, &data).unwrap();
        assert_eq!(w, Witness::Open(open::Witness([7; 32])));
        assert_eq!(w.to_payload(), (open::MODE, data));
    }

    #[test]
    fn witness_close_round_trip() {
        let data = vec![7; 32];
        let p = Witness::from_payload(close::MODE, &data).unwrap();
        assert_eq!(p, Witness::Close(close::Witness([7; 32])));
        assert_eq!(p.to_payload(), (close::MODE, data));
    }

    #[test]
    fn witness_rejects_invalid_mode_or_length() {
        for mode in 0..3 {
            for len in &[31, 33] {
                let p = Witness::from_payload(mode, &vec![7; *len]);
                assert!(p.is_err());
            }
        }
    }

    /// Dummy context
    pub struct Ctx<'a> {
        pub tx: &'a Transaction,
    }

    /// Implementation of required operations for the demo extension, as satisfied
    /// by the context.
    impl<'a> Context for Ctx<'a> {
        fn is_tze_only(&self) -> bool {
            self.tx.vin.is_empty()
                && self.tx.vout.is_empty()
                && self.tx.shielded_spends.is_empty()
                && self.tx.shielded_outputs.is_empty()
                && self.tx.joinsplits.is_empty()
        }

        fn tx_tze_outputs(&self) -> &[TzeOut] {
            &self.tx.tze_outputs
        }
    }

    #[test]
    fn demo_program() {
        let preimage_1 = [1; 32];
        let preimage_2 = [2; 32];

        let hash_2 = {
            let mut hash = [0; 32];
            hash.copy_from_slice(Params::new().hash_length(32).hash(&preimage_2).as_bytes());
            hash
        };

        let hash_1 = {
            let mut hash = [0; 32];
            hash.copy_from_slice(
                Params::new()
                    .hash_length(32)
                    .to_state()
                    .update(&preimage_1)
                    .update(&hash_2)
                    .finalize()
                    .as_bytes(),
            );
            hash
        };

        //
        // Opening transaction
        //

        let out_a = TzeOut {
            value: Amount::from_u64(1).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::open(hash_1)),
        };

        let mut mtx_a = TransactionData::nu4();
        mtx_a.tze_outputs.push(out_a);
        let tx_a = mtx_a.freeze().unwrap();

        //
        // Transfer
        //

        let in_b = TzeIn {
            prevout: OutPoint::new(tx_a.txid().0, 0),
            witness: tze::Witness::from(0, &Witness::open(preimage_1)),
        };
        let out_b = TzeOut {
            value: Amount::from_u64(1).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::close(hash_2)),
        };
        let mut mtx_b = TransactionData::nu4();
        mtx_b.tze_inputs.push(in_b);
        mtx_b.tze_outputs.push(out_b);
        let tx_b = mtx_b.freeze().unwrap();

        //
        // Closing transaction
        //

        let in_c = TzeIn {
            prevout: OutPoint::new(tx_b.txid().0, 0),
            witness: tze::Witness::from(0, &Witness::close(preimage_2)),
        };

        let mut mtx_c = TransactionData::nu4();
        mtx_c.tze_inputs.push(in_c);
        let tx_c = mtx_c.freeze().unwrap();

        // Verify tx_b
        {
            let ctx = Ctx { tx: &tx_b };
            assert_eq!(
                Program.verify(
                    &tx_a.tze_outputs[0].precondition,
                    &tx_b.tze_inputs[0].witness,
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_c
        {
            let ctx = Ctx { tx: &tx_b };
            assert_eq!(
                Program.verify(
                    &tx_b.tze_outputs[0].precondition,
                    &tx_c.tze_inputs[0].witness,
                    &ctx
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn demo_builder_program() {
        let preimage_1 = [1; 32];
        let preimage_2 = [2; 32];

        let prover = LocalTxProver::with_default_location().unwrap();

        //
        // Opening transaction
        //

        let mut rng = OsRng;
        let mut builder_a = Builder::new_nu4(0);

        // create some inputs to spend
        let extsk = ExtendedSpendingKey::master(&[]);
        let to = extsk.default_address().unwrap().1;
        let note1 = to
            .create_note(110000, Fs::random(&mut rng), &JUBJUB)
            .unwrap();
        let cm1 = Node::new(note1.cm(&JUBJUB).into_repr());
        let mut tree = CommitmentTree::new();
        // fake that the note appears in some previous
        // shielded output
        tree.append(cm1).unwrap();
        let witness1 = IncrementalWitness::from_tree(&tree);
        builder_a
            .add_sapling_spend(
                extsk.clone(),
                *to.diversifier(),
                note1.clone(),
                witness1.path().unwrap(),
            )
            .unwrap();

        let mut db_a = DemoBuilder {
            txn_builder: &mut builder_a,
            extension_id: 0,
        };

        let value = Amount::from_u64(100000).unwrap();
        db_a.demo_open(value, preimage_1, preimage_2)
            .map_err(|e| format!("open failure: {:?}", e))
            .unwrap();
        let (tx_a, _) = builder_a
            .build(BranchId::Canopy, &prover)
            .map_err(|e| format!("build failure: {:?}", e))
            .unwrap();

        //
        // Transfer
        //

        let mut builder_b = Builder::new_nu4(0);
        let mut db_b = DemoBuilder {
            txn_builder: &mut builder_b,
            extension_id: 0,
        };
        let prevout_a = (
            OutPoint::new(tx_a.txid().0, 0),
            tx_a.tze_outputs[0].clone(),
        );
        let value_xfr = Amount::from_u64(90000).unwrap();
        db_b.demo_transfer_to_close(prevout_a, value_xfr, preimage_1, preimage_2)
            .map_err(|e| format!("transfer failure: {:?}", e))
            .unwrap();
        let (tx_b, _) = builder_b
            .build(BranchId::Canopy, &prover)
            .map_err(|e| format!("build failure: {:?}", e))
            .unwrap();

        //
        // Closing transaction
        //

        let mut builder_c = Builder::new_nu4(0);
        let mut db_c = DemoBuilder {
            txn_builder: &mut builder_c,
            extension_id: 0,
        };
        let prevout_b = (
            OutPoint::new(tx_a.txid().0, 0),
            tx_b.tze_outputs[0].clone(),
        );
        db_c.demo_close(prevout_b, preimage_2)
            .map_err(|e| format!("close failure: {:?}", e))
            .unwrap();

        builder_c
            .add_transparent_output(
                &TransparentAddress::PublicKey([0; 20]),
                Amount::from_u64(80000).unwrap(),
            )
            .unwrap();

        let (tx_c, _) = builder_c
            .build(BranchId::Canopy, &prover)
            .map_err(|e| format!("build failure: {:?}", e))
            .unwrap();

        // Verify tx_b
        let ctx0 = Ctx { tx: &tx_b };
        assert_eq!(
            Program.verify(
                &tx_a.tze_outputs[0].precondition,
                &tx_b.tze_inputs[0].witness,
                &ctx0
            ),
            Ok(())
        );

        // Verify tx_c
        let ctx1 = Ctx { tx: &tx_b };
        assert_eq!(
            Program.verify(
                &tx_b.tze_outputs[0].precondition,
                &tx_c.tze_inputs[0].witness,
                &ctx1
            ),
            Ok(())
        );
    }
}
