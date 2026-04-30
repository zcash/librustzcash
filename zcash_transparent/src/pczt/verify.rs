use zcash_script::script::Evaluable;

use crate::address::TransparentAddress;

impl super::Input {
    /// Verifies the consistency of this transparent input.
    ///
    /// If the `redeem_script` field is set, its validity will be checked.
    pub fn verify(&self) -> Result<(), VerifyError> {
        match TransparentAddress::from_script_from_chain(self.script_pubkey()) {
            Some(TransparentAddress::PublicKeyHash(_)) => {
                if self.redeem_script().is_some() {
                    return Err(VerifyError::NotP2sh);
                }
            }
            Some(TransparentAddress::ScriptHash(hash)) => {
                if let Some(redeem_script) = self.redeem_script() {
                    if hash[..] != crate::util::hash160::hash(&redeem_script.to_bytes())[..] {
                        return Err(VerifyError::WrongRedeemScript);
                    }
                }
            }
            None => return Err(VerifyError::UnsupportedScriptPubkey),
        }

        Ok(())
    }
}

impl super::Output {
    /// Verifies the consistency of this transparent output.
    ///
    /// If the `redeem_script` field is set, its validity will be checked.
    pub fn verify(&self) -> Result<(), VerifyError> {
        match TransparentAddress::from_script_pubkey(self.script_pubkey()) {
            Some(TransparentAddress::PublicKeyHash(_)) => {
                if self.redeem_script().is_some() {
                    return Err(VerifyError::NotP2sh);
                }
            }
            Some(TransparentAddress::ScriptHash(hash)) => {
                if let Some(redeem_script) = self.redeem_script() {
                    if hash[..] != crate::util::hash160::hash(&redeem_script.to_bytes())[..] {
                        return Err(VerifyError::WrongRedeemScript);
                    }
                }
            }
            None => return Err(VerifyError::UnsupportedScriptPubkey),
        }

        Ok(())
    }
}

/// Errors that can occur while verifying a PCZT bundle.
#[derive(Debug)]
pub enum VerifyError {
    /// A `redeem_script` can only be set on a P2SH coin.
    NotP2sh,
    /// The `script_pubkey` kind is unsupported.
    UnsupportedScriptPubkey,
    /// The provided `redeem_script` does not match the input's `script_pubkey`.
    WrongRedeemScript,
}
