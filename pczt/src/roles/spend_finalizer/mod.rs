//! The Spend Finalizer role (anyone can execute).
//!
//! - Combines partial transparent signatures into `script_sig`s.

use ::transparent::sighash::{SighashPolicy, SighashType};

use crate::Pczt;

pub struct SpendFinalizer {
    pczt: Pczt,
    sighash_policy: SighashPolicy,
}

impl SpendFinalizer {
    /// Instantiates the Spend Finalizer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self {
            pczt,
            sighash_policy: SighashPolicy::ALL_ONLY,
        }
    }

    /// Sets the sighash policy that this Spend Finalizer applies to partial signatures.
    ///
    /// The default is [`SighashPolicy::ALL_ONLY`]; see [`SighashPolicy`] for why. Widen it
    /// only if the surrounding protocol genuinely calls for a narrower commitment, as this
    /// is the last point at which such a signature can be rejected before a broadcastable
    /// transaction exists.
    ///
    /// Note that this does not relax the separate requirement that `Global.tx_modifiable`
    /// record the parts of the transaction that each signature leaves uncommitted.
    pub fn with_sighash_policy(mut self, sighash_policy: SighashPolicy) -> Self {
        self.sighash_policy = sighash_policy;
        self
    }

    /// Finalizes the spends of the PCZT.
    pub fn finalize_spends(self) -> Result<Pczt, Error> {
        let Self {
            pczt,
            sighash_policy,
        } = self;

        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
        } = pczt;

        let mut transparent = transparent.into_parsed().map_err(Error::TransparentParse)?;

        transparent
            .finalize_spends_with_sighash_policy(sighash_policy)
            .map_err(Error::TransparentFinalize)?;

        Ok(Pczt {
            global,
            transparent: crate::transparent::Bundle::serialize_from(transparent),
            sapling,
            orchard,
        })
    }
}

/// Errors that can occur while finalizing the spends of a PCZT.
#[derive(Debug)]
pub enum Error {
    /// An input's sighash type leaves part of the transaction uncommitted, but
    /// `Global.tx_modifiable` does not record that part as still modifiable.
    InconsistentSighashType {
        index: usize,
        sighash_type: SighashType,
    },
    TransparentFinalize(transparent::pczt::SpendFinalizerError),
    TransparentParse(transparent::pczt::ParseError),
}
