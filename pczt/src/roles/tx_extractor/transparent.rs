use zcash_primitives::{
    legacy::Script,
    transaction::{
        components::transparent::{Authorization, Authorized, Bundle, MapAuth, TxOut},
        sighash::TransparentAuthorizingContext,
    },
};
use zcash_protocol::value::Zatoshis;

pub(super) fn extract_bundle(
    bundle: crate::transparent::Bundle,
) -> Result<Option<Bundle<Unbound>>, TransparentError> {
    bundle.to_tx_data(
        |input| {
            Ok(Script(
                input
                    .script_sig
                    .clone()
                    .ok_or(TransparentError::MissingScriptSig)?,
            ))
        },
        |bundle| {
            let inputs = bundle
                .inputs
                .iter()
                .map(|input| {
                    let value = Zatoshis::from_u64(input.value)
                        .map_err(|_| crate::transparent::Error::InvalidValue)?;
                    let script_pubkey = Script(input.script_pubkey.clone());

                    Ok(TxOut {
                        value,
                        script_pubkey,
                    })
                })
                .collect::<Result<_, TransparentError>>()?;

            Ok(Unbound { inputs })
        },
    )
}

#[derive(Debug)]
pub(super) struct Unbound {
    inputs: Vec<TxOut>,
}

impl Authorization for Unbound {
    type ScriptSig = Script;
}

impl TransparentAuthorizingContext for Unbound {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.inputs.iter().map(|input| input.value).collect()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.inputs
            .iter()
            .map(|input| input.script_pubkey.clone())
            .collect()
    }
}

pub(super) struct RemoveInputInfo;

impl MapAuth<Unbound, Authorized> for RemoveInputInfo {
    fn map_script_sig(
        &self,
        s: <Unbound as Authorization>::ScriptSig,
    ) -> <Authorized as Authorization>::ScriptSig {
        s
    }

    fn map_authorization(&self, _: Unbound) -> Authorized {
        Authorized
    }
}

#[derive(Debug)]
pub enum TransparentError {
    Data(crate::transparent::Error),
    MissingScriptSig,
}

impl From<crate::transparent::Error> for TransparentError {
    fn from(e: crate::transparent::Error) -> Self {
        Self::Data(e)
    }
}
