//! Types related to computation of fees and change related to the transparent components
//! of a transaction.

use core::convert::Infallible;

use crate::transaction::{
    components::transparent::script_serialized_size, fees::zip317::P2PKH_STANDARD_INPUT_SIZE,
};
use transparent::{
    address::Script,
    bundle::{OutPoint, TxOut},
};
use zcash_protocol::value::Zatoshis;
use zcash_script::{script, solver};

#[cfg(feature = "transparent-inputs")]
use {
    core::iter,
    transparent::builder::{SpendInfo, TransparentInputInfo},
    zcash_encoding::CompactSize,
    zcash_script::{pattern::push_script, pv, script::Evaluable as _},
};

/// The size of a transparent input, or the outpoint corresponding to the input
/// if the size of the script required to spend that input is unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputSize {
    /// The txin size is known.
    Known(usize),
    /// The size of the script required to spend this input (and therefore the txin size)
    /// is unknown.
    Unknown(OutPoint),
}

impl InputSize {
    /// An `InputSize` corresponding to the upper bound on the size of a P2PKH input used by ZIP 317.
    pub const STANDARD_P2PKH: InputSize = InputSize::Known(P2PKH_STANDARD_INPUT_SIZE);
}

/// Maximum size of a DER-encoded ECDSA signature (72 bytes) plus one SIGHASH type byte.
#[cfg(feature = "transparent-inputs")]
const MAX_SIG_SIZE: usize = 72 + 1;

/// Size of a serialized outpoint: transaction hash (32 bytes) + output index (4 bytes).
#[cfg(feature = "transparent-inputs")]
const PREVOUT_SIZE: usize = 32 + 4;

/// Size of a serialized sequence number (u32).
#[cfg(feature = "transparent-inputs")]
const SEQUENCE_SIZE: usize = 4;

/// Returns an upper bound, in bytes, on the serialized size of a P2SH input that spends
/// via `redeem_script`, assuming signatures of the maximum length.
///
/// Returns `None` if the redeem script is not a recognized P2SH script kind (currently
/// only P2MS-in-P2SH is supported).
#[cfg(feature = "transparent-inputs")]
pub fn p2sh_input_serialized_len(redeem_script: &script::FromChain) -> Option<usize> {
    let fake_sig = pv::push_value(&[0; MAX_SIG_SIZE]).expect("short enough");

    let script_len = redeem_script
        .refine()
        .ok()
        .as_ref()
        .and_then(solver::standard)
        .and_then(|spend_info| match spend_info {
            solver::ScriptKind::MultiSig { required, .. } => Some(
                script::Component(
                    iter::empty()
                        .chain(Some(pv::_0))
                        .chain(iter::repeat_n(fake_sig, usize::from(required)))
                        .chain(push_script(redeem_script))
                        .collect(),
                )
                .byte_len(),
            ),
            _ => None,
        })?;

    let script_sig_len = CompactSize::serialized_size(script_len) + script_len;
    Some(PREVOUT_SIZE + script_sig_len + SEQUENCE_SIZE)
}

/// This trait provides a minimized view of a transparent input suitable for use in
/// fee and change computation.
pub trait InputView: core::fmt::Debug {
    /// The outpoint to which the input refers.
    fn outpoint(&self) -> &OutPoint;

    /// The previous output being spent.
    fn coin(&self) -> &TxOut;

    /// The size of this transparent input in a transaction, as used in [ZIP 317].
    ///
    /// [ZIP 317]: https://zips.z.cash/zip-0317#rationale-for-the-chosen-parameters
    fn serialized_size(&self) -> InputSize {
        match script::PubKey::parse(&self.coin().script_pubkey().0)
            .ok()
            .as_ref()
            .and_then(solver::standard)
        {
            Some(solver::ScriptKind::PubKeyHash { .. }) => InputSize::STANDARD_P2PKH,
            _ => InputSize::Unknown(self.outpoint().clone()),
        }
    }
}

#[cfg(feature = "transparent-inputs")]
impl InputView for TransparentInputInfo {
    fn outpoint(&self) -> &OutPoint {
        self.outpoint()
    }

    fn coin(&self) -> &TxOut {
        self.coin()
    }

    fn serialized_size(&self) -> InputSize {
        // For P2PKH inputs, return the ZIP 317 standard size (150 bytes) rather than the
        // exact serialized size (which is one byte smaller). The proposal layer accounts
        // for fees using the standard size; the builder must agree, otherwise a
        // shielding transaction with enough P2PKH inputs to cross a
        // `ceildiv(t_in_total_size, 150)` boundary will fail with `ChangeRequired`.
        match self.spend_info() {
            SpendInfo::P2pkh { .. } => InputSize::STANDARD_P2PKH,
            SpendInfo::P2sh { redeem_script } => p2sh_input_serialized_len(redeem_script).map_or(
                InputSize::Unknown(self.outpoint().clone()),
                InputSize::Known,
            ),
        }
    }
}

impl InputView for Infallible {
    fn outpoint(&self) -> &OutPoint {
        unreachable!()
    }
    fn coin(&self) -> &TxOut {
        unreachable!()
    }
}

/// This trait provides a minimized view of a transparent output suitable for use in
/// fee and change computation.
pub trait OutputView: core::fmt::Debug {
    /// Returns the value of the output being created.
    fn value(&self) -> Zatoshis;

    /// Returns the script corresponding to the newly created output.
    fn script_pubkey(&self) -> &Script;

    /// Returns the serialized size of the txout.
    fn serialized_size(&self) -> usize {
        // The serialized size of a transparent `TxOut` is the serialized size of an amount
        // plus the serialized size of the script pubkey.
        8 + script_serialized_size(self.script_pubkey())
    }
}

impl OutputView for TxOut {
    fn value(&self) -> Zatoshis {
        self.value()
    }

    fn script_pubkey(&self) -> &Script {
        self.script_pubkey()
    }
}

#[cfg(all(test, feature = "transparent-inputs"))]
mod tests {
    use secp256k1::{
        PublicKey, SecretKey,
        constants::{PUBLIC_KEY_SIZE, SECRET_KEY_SIZE},
    };
    use transparent::address::TransparentAddress;
    use zcash_script::{
        pattern::check_multisig,
        script::{Component, FromChain},
    };

    use super::{MAX_SIG_SIZE, PREVOUT_SIZE, SEQUENCE_SIZE, p2sh_input_serialized_len};

    /// The parts of a serialized input whose size does not depend on the script: the
    /// outpoint and the sequence number.
    const FIXED_INPUT_LEN: usize = PREVOUT_SIZE + SEQUENCE_SIZE;

    /// `OP_0`, the dummy element that `OP_CHECKMULTISIG` consumes.
    const DUMMY_LEN: usize = 1;

    /// The cost of pushing at most 75 bytes of data: one opcode byte that gives the length.
    const DIRECT_PUSH_OVERHEAD: usize = 1;

    /// The cost of pushing 76 to 255 bytes of data: `OP_PUSHDATA1` and one length byte.
    const PUSHDATA1_OVERHEAD: usize = 2;

    /// The length of the CompactSize encoding of a value of at most 252.
    const COMPACT_SIZE_ONE_BYTE_LEN: usize = 1;

    /// The length of the CompactSize encoding of a value from 253 to 65535.
    const COMPACT_SIZE_THREE_BYTE_LEN: usize = 3;

    /// A direct push of a signature placeholder of the maximum length.
    const SIG_PUSH_LEN: usize = DIRECT_PUSH_OVERHEAD + MAX_SIG_SIZE;

    /// A direct push of a compressed public key.
    const PUBKEY_PUSH_LEN: usize = DIRECT_PUSH_OVERHEAD + PUBLIC_KEY_SIZE;

    /// The threshold opcode, the key-count opcode, and `OP_CHECKMULTISIG`.
    const MULTISIG_OPCODES_LEN: usize = 3;

    fn pubkey(seed: u8) -> [u8; PUBLIC_KEY_SIZE] {
        let sk = SecretKey::from_secret_bytes([seed; SECRET_KEY_SIZE]).unwrap();
        PublicKey::from_secret_key(&sk).serialize()
    }

    #[test]
    fn p2sh_2_of_2_input_len() {
        let (k1, k2) = (pubkey(1), pubkey(2));
        let redeem_script: FromChain =
            Component(check_multisig(2, &[&k1, &k2], false).unwrap()).weaken();
        // The 71-byte redeem script fits a direct push (at most 75 bytes), and the
        // 221-byte scriptSig fits a 1-byte CompactSize (at most 252).
        let redeem_len = MULTISIG_OPCODES_LEN + 2 * PUBKEY_PUSH_LEN;
        let script_sig_len = DUMMY_LEN + 2 * SIG_PUSH_LEN + (DIRECT_PUSH_OVERHEAD + redeem_len);
        assert_eq!(
            p2sh_input_serialized_len(&redeem_script),
            Some(FIXED_INPUT_LEN + COMPACT_SIZE_ONE_BYTE_LEN + script_sig_len)
        );
    }

    #[test]
    fn p2sh_2_of_3_input_len() {
        let (k1, k2, k3) = (pubkey(1), pubkey(2), pubkey(3));
        let redeem_script: FromChain =
            Component(check_multisig(2, &[&k1, &k2, &k3], false).unwrap()).weaken();
        // The 105-byte redeem script needs OP_PUSHDATA1 (opcode plus length byte), and
        // the 256-byte scriptSig needs a 3-byte CompactSize.
        let redeem_len = MULTISIG_OPCODES_LEN + 3 * PUBKEY_PUSH_LEN;
        let script_sig_len = DUMMY_LEN + 2 * SIG_PUSH_LEN + (PUSHDATA1_OVERHEAD + redeem_len);
        assert_eq!(
            p2sh_input_serialized_len(&redeem_script),
            Some(FIXED_INPUT_LEN + COMPACT_SIZE_THREE_BYTE_LEN + script_sig_len)
        );
    }

    #[test]
    fn non_multisig_redeem_script_has_unknown_len() {
        let p2pkh = TransparentAddress::PublicKeyHash([0; 20]).script().weaken();
        assert_eq!(p2sh_input_serialized_len(&p2pkh), None);
    }
}
