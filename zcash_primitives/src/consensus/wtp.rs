//! Consensus logic for whitelisted transparent programs.

use std::fmt;

use crate::{
    transaction::Transaction,
    wtp::{Predicate, Witness},
};

mod demo;
mod bolt;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidEpoch,
    TypeMismatch,
    Program(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidEpoch => write!(f, "Program type is invalid for this epoch"),
            Error::TypeMismatch => write!(f, "Predicate and witness types do not match"),
            Error::Program(err) => write!(f, "Program error: {}", err),
        }
    }
}

mod context {
    use crate::transaction::{components::WtpOut, Transaction};

    pub(super) struct V1<'a> {
        height: i32,
        tx: &'a Transaction,
    }

    impl<'a> V1<'a> {
        pub(super) fn new(height: i32, tx: &'a Transaction) -> Self {
            V1 { height, tx }
        }

        pub(super) fn block_height(&self) -> i32 {
            self.height
        }

        pub(super) fn is_wtp_only(&self) -> bool {
            self.tx.vin.is_empty()
                && self.tx.vout.is_empty()
                && self.tx.shielded_spends.is_empty()
                && self.tx.shielded_outputs.is_empty()
                && self.tx.joinsplits.is_empty()
        }

        pub(super) fn tx_wtp_outputs(&self) -> &[WtpOut] {
            &self.tx.wtp_outputs
        }

    }
}

enum ContextVersion<'a> {
    V1(context::V1<'a>),
}

/// API for WTPs to access transaction and chain information.
///
/// Provides information to programs about the conditions under which a predicate and
/// witness are being verified. For a mined transaction, this would be in the context of
/// the block the transaction was mined in. For a transaction in the mempool, this would
/// be in the context of the next block height that would be mined.
pub struct Context<'a> {
    inner: ContextVersion<'a>,
}

impl<'a> Context<'a> {
    /// Generates a version 1 WTP context.
    pub fn v1(height: i32, tx: &'a Transaction) -> Self {
        Context {
            inner: ContextVersion::V1(context::V1::new(height, tx)),
        }
    }
}

/// A set of demo WTPs associated with the dummy network upgrade.
struct TestDummyPrograms;

impl TestDummyPrograms {
    fn verify(predicate: &Predicate, witness: &Witness, ctx: &context::V1) -> Result<(), Error> {
        // This epoch contains the following set of programs:
        match (predicate, witness) {
            // The demo program!
            (Predicate::Demo(p), Witness::Demo(w)) => {
                demo::Program::verify(p, w, ctx).map_err(Error::Program)
            }
            (Predicate::Demo(_), _) | (_, Witness::Demo(_)) => Err(Error::TypeMismatch),
            // The Bolt program
            (Predicate::Bolt(p), Witness::Bolt(w)) => {
                bolt::Program::verify(p, w, ctx).map_err(Error::Program)
            }
            (Predicate::Bolt(_), _) | (_, Witness::Bolt(_)) => Err(Error::TypeMismatch),
            // All other program types are invalid in this epoch.
            _ => Err(Error::InvalidEpoch),
        }
    }
}

/// Enumeration of all whitelisted transparent programs within the Zcash consensus rules.
pub enum Programs {
    TestDummy
}

impl Programs {
    pub fn for_epoch(consensus_branch_id: u32) -> Option<Self> {
        // Map from consensus branch IDs to epochs.
        match consensus_branch_id {
            0x7473_6554 => Some(Programs::TestDummy),
            _ => None,
        }
    }

    /// Verifies a given predicate and witness within the context of this epoch.
    pub fn verify(
        &self,
        predicate: &Predicate,
        witness: &Witness,
        ctx: &Context,
    ) -> Result<(), Error> {
        match (self, &ctx.inner) {
            (Programs::TestDummy, ContextVersion::V1(ctx)) => {
                TestDummyPrograms::verify(predicate, witness, ctx)
            }
        }
    }
}
