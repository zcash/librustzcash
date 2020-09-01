//! Consensus logic for Transparent Zcash Extensions.

use std::convert::TryFrom;
use zcash_primitives::extensions::transparent::{Error, Extension, Precondition, Witness};
use zcash_primitives::transaction::components::TzeOut;
use zcash_primitives::transaction::Transaction;

use crate::transparent::demo;

/// The set of programs that have assigned type IDs within the Zcash consensus rules.
#[derive(Debug, Clone, Copy)]
pub enum ExtensionId {
    Demo,
}

pub struct InvalidExtId(u32);

impl TryFrom<u32> for ExtensionId {
    type Error = InvalidExtId;

    fn try_from(t: u32) -> Result<Self, Self::Error> {
        match t {
            0 => Ok(ExtensionId::Demo),
            n => Err(InvalidExtId(n)),
        }
    }
}

impl From<ExtensionId> for u32 {
    fn from(type_id: ExtensionId) -> u32 {
        match type_id {
            ExtensionId::Demo => 0,
        }
    }
}

/// The complete set of context data that is available to any extension having
/// an assigned extension type ID.
pub struct Context<'a> {
    pub height: i32,
    pub tx: &'a Transaction,
}

impl<'a> Context<'a> {
    pub fn new(height: i32, tx: &'a Transaction) -> Self {
        Context { height, tx }
    }
}

pub trait Epoch {
    type Error;

    fn verify<'a>(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        ctx: &Context<'a>,
    ) -> Result<(), Error<Self::Error>>;
}

/// Implementation of required operations for the demo extension, as satisfied
/// by the context.
impl<'a> demo::Context for Context<'a> {
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

/// Wire identifier for the dummy network upgrade epoch.
pub const NEXT_BRANCH_ID: u32 = 0x7374f403;

/// A set of demo TZEs associated with the dummy network upgrade.
struct EpochV1;

impl Epoch for EpochV1 {
    type Error = String;

    fn verify<'a>(
        &self,
        precondition: &Precondition,
        witness: &Witness,
        ctx: &Context<'a>,
    ) -> Result<(), Error<Self::Error>> {
        // This epoch contains the following set of programs:
        let ext_id = ExtensionId::try_from(precondition.extension_id)
            .map_err(|InvalidExtId(id)| Error::InvalidExtensionId(id))?;
        match ext_id {
            ExtensionId::Demo => demo::Program
                .verify(precondition, witness, ctx)
                .map_err(|e| Error::ProgramError(format!("Epoch v1 program error: {}", e))),
        }
    }
}

pub fn epoch_for_branch(consensus_branch_id: u32) -> Option<Box<dyn Epoch<Error = String>>> {
    // Map from consensus branch IDs to epochs.
    let _tmp_branch_id = NEXT_BRANCH_ID;
    match consensus_branch_id {
        NEXT_BRANCH_ID => Some(Box::new(EpochV1)),
        _ => None,
    }
}
