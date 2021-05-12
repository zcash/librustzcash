//! Consensus logic for Transparent Zcash Extensions.

use std::convert::TryFrom;
use zcash_primitives::consensus::{BlockHeight, BranchId};
use zcash_primitives::extensions::transparent::{
    AuthData, Error, Extension, Precondition, Witness,
};
use zcash_primitives::transaction::{components::tze::TzeOut, Transaction};

use crate::transparent::demo;

/// Wire value for the demo extension identifier.
pub const EXTENSION_DEMO: u32 = 0;

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
            EXTENSION_DEMO => Ok(ExtensionId::Demo),
            n => Err(InvalidExtId(n)),
        }
    }
}

impl From<ExtensionId> for u32 {
    fn from(type_id: ExtensionId) -> u32 {
        match type_id {
            ExtensionId::Demo => EXTENSION_DEMO,
        }
    }
}

/// The complete set of context data that is available to any extension having
/// an assigned extension type ID. This type may be modified in the future if
/// additional context information is required by newly integrated TZEs.
pub struct Context<'a> {
    pub height: BlockHeight,
    pub tx: &'a Transaction,
}

impl<'a> Context<'a> {
    pub fn new(height: BlockHeight, tx: &'a Transaction) -> Self {
        Context { height, tx }
    }
}

/// Implementations of this trait provide complete extension validation rules
/// for a specific epoch, and handle dispatch of verification to individual
/// TZEs based upon extension ID and mode.
pub trait Epoch {
    type Error;

    /// For a specific epoch, if the extension ID and mode of the supplied
    /// witness matches that of the supplied precondition, these values will
    /// be passed to the associated extension for verification, along with
    /// whatever that extension requires of the provided [`Context`].
    ///
    /// Successful validation is indicated by the returned Result containing
    /// no errors.
    fn verify<'a>(
        &self,
        precondition: &Precondition,
        witness: &Witness<AuthData>,
        ctx: &Context<'a>,
    ) -> Result<(), Error<Self::Error>>;
}

/// Implementation of required operations for the demo extension, as satisfied
/// by the context.
impl<'a> demo::Context for Context<'a> {
    fn is_tze_only(&self) -> bool {
        self.tx.transparent_bundle().is_none()
            && self.tx.sapling_bundle().is_none()
            && self.tx.sprout_bundle().is_none()
            && self.tx.orchard_bundle().is_none()
    }

    fn tx_tze_outputs(&self) -> &[TzeOut] {
        if let Some(bundle) = &self.tx.tze_bundle() {
            &bundle.vout
        } else {
            &[]
        }
    }
}

/// Identifier for the set of TZEs associated with the ZFUTURE network upgrade.
/// This epoch is intended only for use on private test networks.
struct EpochVTest;

impl Epoch for EpochVTest {
    type Error = String;

    fn verify<'a>(
        &self,
        precondition: &Precondition,
        witness: &Witness<AuthData>,
        ctx: &Context<'a>,
    ) -> Result<(), Error<Self::Error>> {
        let ext_id = ExtensionId::try_from(precondition.extension_id)
            .map_err(|InvalidExtId(id)| Error::InvalidExtensionId(id))?;

        // This epoch recognizes the following set of extensions:
        match ext_id {
            ExtensionId::Demo => demo::Program
                .verify(precondition, witness, ctx)
                .map_err(|e| Error::ProgramError(format!("Epoch vTest program error: {}", e))),
        }
    }
}

pub fn epoch_for_branch(branch_id: BranchId) -> Option<Box<dyn Epoch<Error = String>>> {
    // Map from consensus branch IDs to epochs.
    match branch_id {
        BranchId::ZFuture => Some(Box::new(EpochVTest)),
        _ => None,
    }
}
