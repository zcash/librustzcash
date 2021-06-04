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

use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::ops::{Deref, DerefMut};

use blake2b_simd::Params;

use zcash_primitives::{
    extensions::transparent::{Extension, ExtensionTxBuilder, FromPayload, ToPayload},
    transaction::components::{
        amount::Amount,
        tze::{OutPoint, TzeOut},
    },
};

/// Types and constants used for Mode 0 (open a channel)
mod open {
    pub const MODE: u32 = 0;

    #[derive(Debug, PartialEq)]
    pub struct Precondition(pub [u8; 32]);

    #[derive(Debug, PartialEq)]
    pub struct Witness(pub [u8; 32]);
}

/// Types and constants used for Mode 1 (close a channel)
mod close {
    pub const MODE: u32 = 1;

    #[derive(Debug, PartialEq)]
    pub struct Precondition(pub [u8; 32]);

    #[derive(Debug, PartialEq)]
    pub struct Witness(pub [u8; 32]);
}

/// The precondition type for the demo extension.
#[derive(Debug, PartialEq)]
pub enum Precondition {
    Open(open::Precondition),
    Close(close::Precondition),
}

impl Precondition {
    /// Convenience constructor for opening precondition values.
    pub fn open(hash: [u8; 32]) -> Self {
        Precondition::Open(open::Precondition(hash))
    }

    /// Convenience constructor for closing precondition values.
    pub fn close(hash: [u8; 32]) -> Self {
        Precondition::Close(close::Precondition(hash))
    }
}

/// Errors that may be produced during parsing and verification of demo preconditions and
/// witnesses.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Parse error indicating that the payload of the condition or the witness was
    /// not 32 bytes.
    IllegalPayloadLength(usize),
    /// Verification error indicating that the specified mode was not recognized by
    /// the extension.
    ModeInvalid(u32),
    /// Verification error indicating that the transaction provided in the verification
    /// context was missing required TZE inputs or outputs.
    NonTzeTxn,
    /// Verification error indicating that the witness being verified did not satisfy the
    /// precondition under inspection.
    HashMismatch,
    /// Verification error indicating that the mode requested by the witness value did not
    /// conform to that of the precondition under inspection.
    ModeMismatch,
    /// Verification error indicating that an `Open`-mode precondition was encountered
    /// when a `Close` was expected.
    ExpectedClose,
    /// Verification error indicating that an unexpected number of TZE outputs (more than
    /// one) was encountered in the transaction under inspection, in violation of
    /// the extension's invariants.
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

impl TryFrom<(u32, Precondition)> for Precondition {
    type Error = Error;

    fn try_from(from: (u32, Self)) -> Result<Self, Self::Error> {
        match from {
            (open::MODE, Precondition::Open(p)) => Ok(Precondition::Open(p)),
            (close::MODE, Precondition::Close(p)) => Ok(Precondition::Close(p)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl FromPayload for Precondition {
    type Error = Error;

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => payload
                .try_into()
                .map_err(|_| Error::IllegalPayloadLength(payload.len()))
                .map(Precondition::open),

            close::MODE => payload
                .try_into()
                .map_err(|_| Error::IllegalPayloadLength(payload.len()))
                .map(Precondition::close),

            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Precondition {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Precondition::Open(p) => (open::MODE, p.0.to_vec()),
            Precondition::Close(p) => (close::MODE, p.0.to_vec()),
        }
    }
}

/// The witness type for the demo extension.
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

impl TryFrom<(u32, Witness)> for Witness {
    type Error = Error;

    fn try_from(from: (u32, Self)) -> Result<Self, Self::Error> {
        match from {
            (open::MODE, Witness::Open(p)) => Ok(Witness::Open(p)),
            (close::MODE, Witness::Close(p)) => Ok(Witness::Close(p)),
            _ => Err(Error::ModeInvalid(from.0)),
        }
    }
}

impl FromPayload for Witness {
    type Error = Error;

    fn from_payload(mode: u32, payload: &[u8]) -> Result<Self, Self::Error> {
        match mode {
            open::MODE => payload
                .try_into()
                .map_err(|_| Error::IllegalPayloadLength(payload.len()))
                .map(Witness::open),

            close::MODE => payload
                .try_into()
                .map_err(|_| Error::IllegalPayloadLength(payload.len()))
                .map(Witness::close),

            _ => Err(Error::ModeInvalid(mode)),
        }
    }
}

impl ToPayload for Witness {
    fn to_payload(&self) -> (u32, Vec<u8>) {
        match self {
            Witness::Open(w) => (open::MODE, w.0.to_vec()),
            Witness::Close(w) => (close::MODE, w.0.to_vec()),
        }
    }
}

/// This trait defines the context information that the demo extension requires
/// be made available to it by a consensus node integrating this extension.
///
/// This context type provides accessors to information relevant to a single
/// transaction being validated by the extension.
pub trait Context {
    /// Predicate used to determine whether this transaction has only TZE
    /// inputs and outputs. The demo extension does not support verification
    /// of transactions which have either shielded or transparent inputs and
    /// outputs.
    fn is_tze_only(&self) -> bool;

    /// List of all TZE outputs in the transaction being validate by the extension.
    fn tx_tze_outputs(&self) -> &[TzeOut];
}

/// Marker type for the demo extension.
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
                            let hash = Params::new()
                                .hash_length(32)
                                .personal(b"demo_pc_h1_perso")
                                .to_state()
                                .update(&w_open.0)
                                .update(&p_close.0)
                                .finalize();
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
                let hash = Params::new()
                    .hash_length(32)
                    .personal(b"demo_pc_h2_perso")
                    .hash(&w.0);
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

fn hash_1(preimage_1: &[u8; 32], hash_2: &[u8; 32]) -> [u8; 32] {
    let mut hash = [0; 32];
    hash.copy_from_slice(
        Params::new()
            .hash_length(32)
            .personal(b"demo_pc_h1_perso")
            .to_state()
            .update(preimage_1)
            .update(hash_2)
            .finalize()
            .as_bytes(),
    );
    hash
}

/// Wrapper for [`zcash_primitives::transaction::builder::Builder`] that simplifies
/// constructing transactions that utilize the features of the demo extension.
pub struct DemoBuilder<B> {
    /// The wrapped transaction builder.
    pub txn_builder: B,

    /// The assigned identifier for this extension. This is necessary as the author
    /// of the demo extension will not know ahead of time what identifier will be
    /// assigned to it at the time of inclusion in the Zcash consensus rules.
    pub extension_id: u32,
}

impl<B> Deref for DemoBuilder<B> {
    type Target = B;

    fn deref(&self) -> &Self::Target {
        &self.txn_builder
    }
}

impl<B> DerefMut for DemoBuilder<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.txn_builder
    }
}

/// Errors that can occur in construction of transactions using `DemoBuilder`.
#[derive(Debug)]
pub enum DemoBuildError<E> {
    /// Wrapper for errors returned from the underlying `Builder`
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

/// Convenience methods for use with [`zcash_primitives::transaction::builder::Builder`]
/// for constructing transactions that utilize the features of the demo extension.
impl<'a, B: ExtensionTxBuilder<'a>> DemoBuilder<B> {
    /// Add a channel-opening precondition to the outputs of the transaction under
    /// construction.
    pub fn demo_open(
        &mut self,
        value: Amount,
        hash_1: [u8; 32],
    ) -> Result<(), DemoBuildError<B::BuildError>> {
        // Call through to the generic builder.
        self.txn_builder
            .add_tze_output(self.extension_id, value, &Precondition::open(hash_1))
            .map_err(DemoBuildError::BaseBuilderError)
    }

    /// Add a witness to a previous channel-opening precondition and a new channel-closing
    /// precondition to the transaction under construction.
    pub fn demo_transfer_to_close(
        &mut self,
        prevout: (OutPoint, TzeOut),
        transfer_amount: Amount,
        preimage_1: [u8; 32],
        hash_2: [u8; 32],
    ) -> Result<(), DemoBuildError<B::BuildError>> {
        let h1 = hash_1(&preimage_1, &hash_2);

        // eagerly validate the relationship between prevout.1 and preimage_1
        match Precondition::from_payload(
            prevout.1.precondition.mode,
            &prevout.1.precondition.payload,
        ) {
            Err(parse_failure) => Err(DemoBuildError::PrevoutParseFailure(parse_failure)),

            Ok(Precondition::Close(_)) => Err(DemoBuildError::ExpectedOpen),

            Ok(Precondition::Open(hash)) if hash.0 != h1 => Err(DemoBuildError::TransferMismatch {
                expected: hash.0,
                actual: h1,
            }),

            Ok(Precondition::Open(_)) => {
                self.txn_builder
                    .add_tze_input(self.extension_id, open::MODE, prevout, move |_| {
                        Ok(Witness::open(preimage_1))
                    })
                    .map_err(DemoBuildError::BaseBuilderError)?;

                self.txn_builder
                    .add_tze_output(
                        self.extension_id,
                        transfer_amount,
                        &Precondition::close(hash_2),
                    )
                    .map_err(DemoBuildError::BaseBuilderError)
            }
        }
    }

    /// Add a channel-closing witness to the transaction under construction.
    pub fn demo_close(
        &mut self,
        prevout: (OutPoint, TzeOut),
        preimage_2: [u8; 32],
    ) -> Result<(), DemoBuildError<B::BuildError>> {
        let hash_2 = {
            let mut hash = [0; 32];
            hash.copy_from_slice(
                Params::new()
                    .hash_length(32)
                    .personal(b"demo_pc_h2_perso")
                    .hash(&preimage_2)
                    .as_bytes(),
            );

            hash
        };

        // eagerly validate the relationship between prevout.1 and preimage_2
        match Precondition::from_payload(
            prevout.1.precondition.mode,
            &prevout.1.precondition.payload,
        ) {
            Err(parse_failure) => Err(DemoBuildError::PrevoutParseFailure(parse_failure)),

            Ok(Precondition::Open(_)) => Err(DemoBuildError::ExpectedClose),

            Ok(Precondition::Close(hash)) if hash.0 != hash_2 => {
                Err(DemoBuildError::CloseMismatch {
                    expected: hash.0,
                    actual: hash_2,
                })
            }

            Ok(Precondition::Close(_)) => self
                .txn_builder
                .add_tze_input(self.extension_id, close::MODE, prevout, move |_| {
                    Ok(Witness::close(preimage_2))
                })
                .map_err(DemoBuildError::BaseBuilderError),
        }
    }
}

#[cfg(test)]
mod tests {
    use blake2b_simd::Params;
    use ff::{Field, PrimeField};
    use rand_core::OsRng;

    use zcash_proofs::prover::LocalTxProver;

    use zcash_primitives::{
        consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters},
        constants,
        extensions::transparent::{self as tze, Extension, FromPayload, ToPayload},
        legacy::TransparentAddress,
        merkle_tree::{CommitmentTree, IncrementalWitness},
        sapling::{Node, Rseed},
        transaction::{
            builder::Builder,
            components::{
                amount::{Amount, DEFAULT_FEE},
                tze::{Authorized, Bundle, OutPoint, TzeIn, TzeOut},
            },
            Transaction, TransactionData, TxVersion,
        },
        zip32::ExtendedSpendingKey,
    };

    use super::{close, hash_1, open, Context, DemoBuilder, Precondition, Program, Witness};

    #[derive(PartialEq, Copy, Clone, Debug)]
    struct FutureNetwork;

    impl Parameters for FutureNetwork {
        fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
            match nu {
                NetworkUpgrade::Overwinter => Some(BlockHeight::from_u32(207_500)),
                NetworkUpgrade::Sapling => Some(BlockHeight::from_u32(280_000)),
                NetworkUpgrade::Blossom => Some(BlockHeight::from_u32(584_000)),
                NetworkUpgrade::Heartwood => Some(BlockHeight::from_u32(903_800)),
                NetworkUpgrade::Canopy => Some(BlockHeight::from_u32(1_028_500)),
                NetworkUpgrade::Nu5 => Some(BlockHeight::from_u32(1_200_000)),
                NetworkUpgrade::ZFuture => Some(BlockHeight::from_u32(1_400_000)),
            }
        }

        fn coin_type(&self) -> u32 {
            constants::testnet::COIN_TYPE
        }

        fn hrp_sapling_extended_spending_key(&self) -> &str {
            constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY
        }

        fn hrp_sapling_extended_full_viewing_key(&self) -> &str {
            constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY
        }

        fn hrp_sapling_payment_address(&self) -> &str {
            constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS
        }

        fn b58_pubkey_address_prefix(&self) -> [u8; 2] {
            constants::testnet::B58_PUBKEY_ADDRESS_PREFIX
        }

        fn b58_script_address_prefix(&self) -> [u8; 2] {
            constants::testnet::B58_SCRIPT_ADDRESS_PREFIX
        }
    }
    fn demo_hashes(preimage_1: &[u8; 32], preimage_2: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hash_2 = {
            let mut hash = [0; 32];
            hash.copy_from_slice(
                Params::new()
                    .hash_length(32)
                    .personal(b"demo_pc_h2_perso")
                    .hash(preimage_2)
                    .as_bytes(),
            );
            hash
        };

        (hash_1(preimage_1, &hash_2), hash_2)
    }

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
        assert_eq!(w, Witness::open([7; 32]));
        assert_eq!(w.to_payload(), (open::MODE, data));
    }

    #[test]
    fn witness_close_round_trip() {
        let data = vec![7; 32];
        let p = Witness::from_payload(close::MODE, &data).unwrap();
        assert_eq!(p, Witness::close([7; 32]));
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
            self.tx.transparent_bundle().is_none()
                && self.tx.sapling_bundle().is_none()
                && self.tx.sprout_bundle().is_none()
                && self.tx.orchard_bundle().is_none()
        }

        fn tx_tze_outputs(&self) -> &[TzeOut] {
            match self.tx.tze_bundle().as_ref() {
                Some(b) => &b.vout,
                None => &[],
            }
        }
    }

    fn demo_builder<'a>(height: BlockHeight) -> DemoBuilder<Builder<'a, FutureNetwork, OsRng>> {
        DemoBuilder {
            txn_builder: Builder::new(FutureNetwork, height),
            extension_id: 0,
        }
    }

    #[test]
    fn demo_program() {
        let preimage_1 = [1; 32];
        let preimage_2 = [2; 32];

        let hash_2 = {
            let mut hash = [0; 32];
            hash.copy_from_slice(
                Params::new()
                    .hash_length(32)
                    .personal(b"demo_pc_h2_perso")
                    .hash(&preimage_2)
                    .as_bytes(),
            );
            hash
        };

        let hash_1 = {
            let mut hash = [0; 32];
            hash.copy_from_slice(
                Params::new()
                    .hash_length(32)
                    .personal(b"demo_pc_h1_perso")
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

        let tx_a = TransactionData::from_parts(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![],
                vout: vec![out_a],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        //
        // Transfer
        //

        let in_b = TzeIn {
            prevout: OutPoint::new(tx_a.txid(), 0),
            witness: tze::Witness::from(0, &Witness::open(preimage_1)),
        };
        let out_b = TzeOut {
            value: Amount::from_u64(1).unwrap(),
            precondition: tze::Precondition::from(0, &Precondition::close(hash_2)),
        };

        let tx_b = TransactionData::from_parts(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![in_b],
                vout: vec![out_b],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        //
        // Closing transaction
        //

        let in_c = TzeIn {
            prevout: OutPoint::new(tx_b.txid(), 0),
            witness: tze::Witness::from(0, &Witness::close(preimage_2)),
        };

        let tx_c = TransactionData::from_parts(
            TxVersion::ZFuture,
            BranchId::ZFuture,
            0,
            0u32.into(),
            None,
            None,
            None,
            None,
            Some(Bundle {
                vin: vec![in_c],
                vout: vec![],
                authorization: Authorized,
            }),
        )
        .freeze()
        .unwrap();

        // Verify tx_b
        {
            let ctx = Ctx { tx: &tx_b };
            assert_eq!(
                Program.verify(
                    &tx_a.tze_bundle().as_ref().unwrap().vout[0].precondition,
                    &tx_b.tze_bundle().as_ref().unwrap().vin[0].witness,
                    &ctx
                ),
                Ok(())
            );
        }

        // Verify tx_c
        {
            let ctx = Ctx { tx: &tx_c };
            assert_eq!(
                Program.verify(
                    &tx_b.tze_bundle().as_ref().unwrap().vout[0].precondition,
                    &tx_c.tze_bundle().as_ref().unwrap().vin[0].witness,
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

        let tx_height = FutureNetwork
            .activation_height(NetworkUpgrade::ZFuture)
            .unwrap();

        // Only run the test if we have the prover parameters.
        let prover = match LocalTxProver::with_default_location() {
            Some(prover) => prover,
            None => return,
        };

        //
        // Opening transaction
        //

        let mut rng = OsRng;

        // create some inputs to spend
        let extsk = ExtendedSpendingKey::master(&[]);
        let to = extsk.default_address().unwrap().1;
        let note1 = to
            .create_note(110000, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cm1 = Node::new(note1.cmu().to_repr());
        let mut tree = CommitmentTree::empty();
        // fake that the note appears in some previous
        // shielded output
        tree.append(cm1).unwrap();
        let witness1 = IncrementalWitness::from_tree(&tree);

        let mut builder_a = demo_builder(tx_height);
        builder_a
            .add_sapling_spend(extsk, *to.diversifier(), note1, witness1.path().unwrap())
            .unwrap();

        let value = Amount::from_u64(100000).unwrap();
        let (h1, h2) = demo_hashes(&preimage_1, &preimage_2);
        builder_a
            .demo_open(value, h1)
            .map_err(|e| format!("open failure: {:?}", e))
            .unwrap();
        let (tx_a, _) = builder_a
            .txn_builder
            .build(&prover)
            .map_err(|e| format!("build failure: {:?}", e))
            .unwrap();
        let tze_a = tx_a.tze_bundle().unwrap();

        //
        // Transfer
        //

        let mut builder_b = demo_builder(tx_height + 1);
        let prevout_a = (OutPoint::new(tx_a.txid(), 0), tze_a.vout[0].clone());
        let value_xfr = (value - DEFAULT_FEE).unwrap();
        builder_b
            .demo_transfer_to_close(prevout_a, value_xfr, preimage_1, h2)
            .map_err(|e| format!("transfer failure: {:?}", e))
            .unwrap();
        let (tx_b, _) = builder_b
            .txn_builder
            .build(&prover)
            .map_err(|e| format!("build failure: {:?}", e))
            .unwrap();
        let tze_b = tx_b.tze_bundle().unwrap();

        //
        // Closing transaction
        //

        let mut builder_c = demo_builder(tx_height + 2);
        let prevout_b = (OutPoint::new(tx_a.txid(), 0), tze_b.vout[0].clone());
        builder_c
            .demo_close(prevout_b, preimage_2)
            .map_err(|e| format!("close failure: {:?}", e))
            .unwrap();

        builder_c
            .add_transparent_output(
                &TransparentAddress::PublicKey([0; 20]),
                (value_xfr - DEFAULT_FEE).unwrap(),
            )
            .unwrap();

        let (tx_c, _) = builder_c
            .txn_builder
            .build(&prover)
            .map_err(|e| format!("build failure: {:?}", e))
            .unwrap();
        let tze_c = tx_c.tze_bundle().unwrap();

        // Verify tx_b
        let ctx0 = Ctx { tx: &tx_b };
        assert_eq!(
            Program.verify(&tze_a.vout[0].precondition, &tze_b.vin[0].witness, &ctx0),
            Ok(())
        );

        // Verify tx_c
        let ctx1 = Ctx { tx: &tx_c };
        assert_eq!(
            Program.verify(&tze_b.vout[0].precondition, &tze_c.vin[0].witness, &ctx1),
            Ok(())
        );
    }
}
