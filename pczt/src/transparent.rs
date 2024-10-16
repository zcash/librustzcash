use std::collections::BTreeMap;

use crate::merge_optional;

#[cfg(feature = "transparent")]
use {
    zcash_primitives::{
        legacy::Script,
        transaction::components::{transparent, OutPoint},
    },
    zcash_protocol::value::Zatoshis,
};

/// PCZT fields that are specific to producing the transaction's transparent bundle (if
/// any).
#[derive(Clone)]
pub(crate) struct Bundle {
    pub(crate) inputs: Vec<Input>,
    pub(crate) outputs: Vec<Output>,
}

#[derive(Clone)]
pub(crate) struct Input {
    //
    // Transparent effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) prevout_txid: [u8; 32],
    pub(crate) prevout_index: u32,
    /// TODO: which role should set this?
    pub(crate) sequence: u32,

    /// A satisfying witness for the `script_pubkey` of the input being spent.
    ///
    /// This is set by the Spend Finalizer.
    pub(crate) script_sig: Option<Vec<u8>>,

    // These are required by the Transaction Extractor, to derive the shielded sighash
    // needed for computing the binding signatures.
    pub(crate) value: u64,
    pub(crate) script_pubkey: Vec<u8>,

    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone)]
pub(crate) struct Output {
    //
    // Transparent effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) value: u64,
    pub(crate) script_pubkey: Vec<u8>,

    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

impl Bundle {
    /// Merges this bundle with another.
    ///
    /// Returns `None` if the bundles have conflicting data.
    pub(crate) fn merge(mut self, other: Self) -> Option<Self> {
        // Destructure `other` to ensure we handle everything.
        let Self {
            mut inputs,
            mut outputs,
        } = other;

        // If the other bundle has more inputs or outputs than us, move them over; these
        // cannot conflict by construction.
        self.inputs.extend(inputs.drain(self.inputs.len()..));
        self.outputs.extend(outputs.drain(self.outputs.len()..));

        // Leverage the early-exit behaviour of zip to confirm that the remaining data in
        // the other bundle matches this one.
        for (lhs, rhs) in self.inputs.iter_mut().zip(inputs.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Input {
                prevout_txid,
                prevout_index,
                sequence,
                script_sig,
                value,
                script_pubkey,
                proprietary,
            } = rhs;

            if lhs.prevout_txid != prevout_txid
                || lhs.prevout_index != prevout_index
                || lhs.sequence != sequence
                || lhs.value != value
                || lhs.script_pubkey != script_pubkey
            {
                return None;
            }

            if !merge_optional(&mut lhs.script_sig, script_sig) {
                return None;
            }

            // TODO: Decide how to merge proprietary fields.
        }

        for (lhs, rhs) in self.outputs.iter_mut().zip(outputs.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Output {
                value,
                script_pubkey,
                proprietary,
            } = rhs;

            if lhs.value != value || lhs.script_pubkey != script_pubkey {
                return None;
            }

            // TODO: Decide how to merge proprietary fields.
        }

        Some(self)
    }
}

#[cfg(feature = "transparent")]
impl Bundle {
    pub(crate) fn to_tx_data<A, E, F, G>(
        &self,
        script_sig: F,
        bundle_auth: G,
    ) -> Result<Option<transparent::Bundle<A>>, E>
    where
        A: transparent::Authorization,
        E: From<Error>,
        F: Fn(&Input) -> Result<<A as transparent::Authorization>::ScriptSig, E>,
        G: FnOnce(&Self) -> Result<A, E>,
    {
        let vin = self
            .inputs
            .iter()
            .map(|input| {
                let prevout = OutPoint::new(input.prevout_txid, input.prevout_index);

                Ok(transparent::TxIn {
                    prevout,
                    script_sig: script_sig(input)?,
                    sequence: input.sequence,
                })
            })
            .collect::<Result<Vec<_>, E>>()?;

        let vout = self
            .outputs
            .iter()
            .map(|output| {
                let value = Zatoshis::from_u64(output.value).map_err(|_| Error::InvalidValue)?;
                let script_pubkey = Script(output.script_pubkey.clone());

                Ok(transparent::TxOut {
                    value,
                    script_pubkey,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(if vin.is_empty() && vout.is_empty() {
            None
        } else {
            Some(transparent::Bundle {
                vin,
                vout,
                authorization: bundle_auth(self)?,
            })
        })
    }
}

#[cfg(feature = "transparent")]
#[derive(Debug)]
pub enum Error {
    InvalidValue,
}
