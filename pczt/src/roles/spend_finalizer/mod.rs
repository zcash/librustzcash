//! The Spend Finalizer role (anyone can execute).
//!
//! - Combines partial transparent signatures into `script_sig`s.

use ::transparent::sighash::{
    SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE, SighashPolicy, SighashType,
};

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
            ironwood,
        } = pczt;

        let mut transparent = transparent.into_parsed().map_err(Error::TransparentParse)?;

        // A Signer that produces a signature leaving part of the transaction uncommitted
        // is required to record that in `Global.tx_modifiable`. If the flags say the
        // effects were already fixed, then the sighash type is not the product of a
        // deliberate multi-party flow, and finalizing would yield a signature that can be
        // lifted into a different transaction.
        //
        // This is a separate gate from the sighash policy, and is not relaxed by
        // `SpendFinalizer::with_sighash_policy`. Note that the IO Finalizer clears both
        // transparent modifiability flags whenever the transaction has shielded spends or
        // outputs, so such a transaction is `SIGHASH_ALL`-only here.
        for (index, input) in transparent.inputs().iter().enumerate() {
            let sighash_type = *input.sighash_type();
            let encoded = sighash_type.encode();
            let signed_outputs = encoded & !SIGHASH_ANYONECANPAY;

            let inconsistent =
                // Commits to no other input, so inputs must still be modifiable.
                (encoded & SIGHASH_ANYONECANPAY != 0 && !global.inputs_modifiable())
                // Commits to none of the outputs, so outputs must still be modifiable.
                || (signed_outputs == SIGHASH_NONE && !global.outputs_modifiable())
                // The input and output pairing must have been recorded as needing to be
                // preserved.
                || (signed_outputs == SIGHASH_SINGLE && !global.has_sighash_single());

            if inconsistent {
                return Err(Error::InconsistentSighashType {
                    index,
                    sighash_type,
                });
            }
        }

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
    /// An input's sighash type leaves part of the transaction uncommitted, but
    /// `Global.tx_modifiable` does not record that part as still modifiable.
    InconsistentSighashType {
        index: usize,
        sighash_type: SighashType,
    },
    TransparentFinalize(transparent::pczt::SpendFinalizerError),
    TransparentParse(transparent::pczt::ParseError),
}
