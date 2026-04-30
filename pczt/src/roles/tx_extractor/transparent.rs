use transparent::{
    bundle::{Authorization, Authorized, MapAuth},
    pczt::{TxExtractorError, Unbound},
};

pub(super) struct RemoveInputInfo;

impl MapAuth<Unbound, Authorized> for RemoveInputInfo {
    fn map_script_sig(
        &self,
        s: <Unbound as Authorization>::ScriptSig,
    ) -> <Authorized as Authorization>::ScriptSig {
        s.into()
    }

    fn map_authorization(&self, _: Unbound) -> Authorized {
        Authorized
    }
}

#[derive(Debug)]
pub enum TransparentError {
    Extract(TxExtractorError),
}
