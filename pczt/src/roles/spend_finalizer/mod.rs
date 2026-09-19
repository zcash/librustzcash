//! The Spend Finalizer role (anyone can execute).
//!
//! - Combines partial transparent signatures into `script_sig`s.

use ::transparent::sighash::SighashPolicy;

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
    /// The default is [`SighashPolicy::ALL_ONLY`]; see [`SighashPolicy`] for why.
    ///
    /// This policy governs which signatures are assembled into `script_sig`s; it does not
    /// protect whoever produced them. A partial signature that does not commit to the
    /// whole transaction can be lifted out of the PCZT and used directly, without this
    /// role ever running, so the decision that protects a signer is the Signer's own
    /// [`Signer::with_transparent_sighash_policy`].
    ///
    /// [`Signer::with_transparent_sighash_policy`]: crate::roles::signer::Signer::with_transparent_sighash_policy
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
            ironwood,
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
            ironwood,
        })
    }
}

/// Errors that can occur while finalizing the spends of a PCZT.
#[derive(Debug)]
pub enum Error {
    TransparentFinalize(transparent::pczt::SpendFinalizerError),
    TransparentParse(transparent::pczt::ParseError),
}
