use alloc::vec::Vec;
use zcash_protocol::value::Zatoshis;

use crate::{
    address::Script,
    bundle::{Authorization, EffectsOnly, OutPoint, TxIn, TxOut},
    sighash::TransparentAuthorizingContext,
};

use super::Input;

impl super::Bundle {
    /// Extracts the effects of this PCZT bundle as a [regular `Bundle`].
    ///
    /// This is used by the Signer role to produce the transaction sighash.
    ///
    /// [regular `Bundle`]: super::Bundle
    pub fn extract_effects(
        &self,
    ) -> Result<Option<crate::bundle::Bundle<EffectsOnly>>, TxExtractorError> {
        self.to_tx_data(|_| Ok(()), |bundle| Ok(effects_only(bundle)))
    }

    /// Extracts a fully authorized [regular `Bundle`] from this PCZT bundle.
    ///
    /// This is used by the Transaction Extractor role to produce the final transaction.
    ///
    /// [regular `Bundle`]: super::Bundle
    pub fn extract(self) -> Result<Option<crate::bundle::Bundle<Unbound>>, TxExtractorError> {
        self.to_tx_data(
            |input| {
                input
                    .script_sig
                    .clone()
                    .ok_or(TxExtractorError::MissingScriptSig)
            },
            |bundle| Ok(Unbound(effects_only(bundle))),
        )
    }

    fn to_tx_data<A, E, F, G>(
        &self,
        script_sig: F,
        bundle_auth: G,
    ) -> Result<Option<crate::bundle::Bundle<A>>, E>
    where
        A: Authorization,
        E: From<TxExtractorError>,
        F: Fn(&Input) -> Result<<A as Authorization>::ScriptSig, E>,
        G: FnOnce(&Self) -> Result<A, E>,
    {
        let vin = self
            .inputs
            .iter()
            .map(|input| {
                let prevout = OutPoint::new(input.prevout_txid.into(), input.prevout_index);

                Ok(TxIn {
                    prevout,
                    script_sig: script_sig(input)?,
                    sequence: input.sequence.unwrap_or(u32::MAX),
                })
            })
            .collect::<Result<Vec<_>, E>>()?;

        let vout = self
            .outputs
            .iter()
            .map(|output| TxOut {
                value: output.value,
                script_pubkey: output.script_pubkey.clone(),
            })
            .collect::<Vec<_>>();

        Ok(if vin.is_empty() && vout.is_empty() {
            None
        } else {
            Some(crate::bundle::Bundle {
                vin,
                vout,
                authorization: bundle_auth(self)?,
            })
        })
    }
}

/// Errors that can occur while extracting a regular transparent bundle from a PCZT
/// bundle.
#[derive(Debug)]
pub enum TxExtractorError {
    /// The Transaction Extractor role requires all `script_sig` fields to be set.
    MissingScriptSig,
}

fn effects_only(bundle: &super::Bundle) -> EffectsOnly {
    let inputs = bundle
        .inputs
        .iter()
        .map(|input| TxOut {
            value: input.value,
            script_pubkey: input.script_pubkey.clone(),
        })
        .collect();

    EffectsOnly { inputs }
}

/// Authorizing data for a transparent bundle in a transaction that is just missing
/// binding signatures.
#[derive(Debug)]
pub struct Unbound(EffectsOnly);

impl Authorization for Unbound {
    type ScriptSig = Script;
}

impl TransparentAuthorizingContext for Unbound {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.0.input_amounts()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.0.input_scriptpubkeys()
    }
}
