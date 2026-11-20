use transparent::{
    bundle::{Authorization, Authorized, MapAuth},
    pczt::{TxExtractorError, Unbound},
};
use zcash_protocol::value::Zatoshis;

pub(super) struct RemoveInputInfo;

impl MapAuth<Unbound<Zatoshis>, Authorized> for RemoveInputInfo {
    fn map_script_sig(
        &self,
        s: <Unbound<Zatoshis> as Authorization>::ScriptSig,
    ) -> <Authorized as Authorization>::ScriptSig {
        s.into()
    }

    fn map_authorization(&self, _: Unbound<Zatoshis>) -> Authorized {
        Authorized
    }
}

#[derive(Debug)]
pub enum TransparentError {
    Extract(TxExtractorError),
}
