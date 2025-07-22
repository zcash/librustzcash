use transparent::{
    bundle::{Authorization, Authorized, Bundle, MapAuth},
    pczt::{ParseError, TxExtractorError, Unbound},
};
use zcash_script::{
    opcode::Opcode,
    script::{self, Parsable},
};

pub(super) fn extract_bundle(
    bundle: crate::transparent::Bundle,
) -> Result<Option<Bundle<Unbound>>, TransparentError> {
    bundle
        .into_parsed()
        .map_err(TransparentError::Parse)?
        .extract()
        .map_err(TransparentError::Extract)
}

pub(super) struct RemoveInputInfo;

impl MapAuth<Unbound, Authorized> for RemoveInputInfo {
    fn map_script_sig(
        &self,
        s: <Unbound as Authorization>::ScriptSig,
    ) -> <Authorized as Authorization>::ScriptSig {
        // TODO: This conversion is infallible, and should be provided by `zcash_script`.
        script::Sig::<Opcode>::from_bytes(&s.to_bytes())
            .expect("valid by construction")
            .0
    }

    fn map_authorization(&self, _: Unbound) -> Authorized {
        Authorized
    }
}

#[derive(Debug)]
pub enum TransparentError {
    Extract(TxExtractorError),
    Parse(ParseError),
}
