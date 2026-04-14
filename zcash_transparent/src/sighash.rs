use alloc::vec::Vec;
use core::fmt;
use getset::Getters;
use zcash_protocol::value::Zatoshis;

use crate::{
    address::Script,
    bundle::{Authorization, Bundle},
};

pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_MASK: u8 = 0x1f;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// A [ZIP 244] sighash type.
///
/// [ZIP 244]: https://zips.z.cash/zip-0244#s-2a-hash-type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SighashType(u8);

impl SighashType {
    pub const ALL: Self = Self(SIGHASH_ALL);
    pub const NONE: Self = Self(SIGHASH_NONE);
    pub const SINGLE: Self = Self(SIGHASH_SINGLE);
    pub const ALL_ANYONECANPAY: Self = Self(SIGHASH_ALL | SIGHASH_ANYONECANPAY);
    pub const NONE_ANYONECANPAY: Self = Self(SIGHASH_NONE | SIGHASH_ANYONECANPAY);
    pub const SINGLE_ANYONECANPAY: Self = Self(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY);

    /// Parses the given `hash_type` using the [ZIP 244] rules.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244#s-2a-hash-type
    pub fn parse(hash_type: u8) -> Option<Self> {
        match hash_type & !SIGHASH_ANYONECANPAY {
            SIGHASH_ALL | SIGHASH_NONE | SIGHASH_SINGLE => Some(Self(hash_type)),
            _ => None,
        }
    }

    /// Encodes this `SighashType` using the [ZIP 244] rules.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244#s-2a-hash-type
    pub fn encode(&self) -> u8 {
        // Correct by construction.
        self.0
    }
}

/// Additional context that is needed to compute signature hashes
/// for transactions that include transparent inputs or outputs.
pub trait TransparentAuthorizingContext: Authorization {
    /// Returns the list of all transparent input amounts, provided
    /// so that wallets can commit to the transparent input breakdown
    /// without requiring the full data of the previous transactions
    /// providing these inputs.
    fn input_amounts(&self) -> Vec<Zatoshis>;
    /// Returns the list of all transparent input scriptPubKeys, provided
    /// so that wallets can commit to the transparent input breakdown
    /// without requiring the full data of the previous transactions
    /// providing these inputs.
    fn input_scriptpubkeys(&self) -> Vec<Script>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidInputIndex {
    pub index: usize,
    pub input_count: usize,
}

impl fmt::Display for InvalidInputIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "transparent input index {} is out of range for bundle with {} inputs",
            self.index, self.input_count
        )
    }
}

impl core::error::Error for InvalidInputIndex {}

/// A transparent input that is signable because we know its value and `script_pubkey`.
#[derive(Debug, Getters)]
#[getset(get = "pub")]
pub struct SignableInput<'a> {
    pub(crate) hash_type: SighashType,
    pub(crate) index: usize,
    pub(crate) script_code: &'a Script,
    pub(crate) script_pubkey: &'a Script,
    pub(crate) value: Zatoshis,
}

impl<'a> SignableInput<'a> {
    /// Constructs a signable input from its parts.
    pub fn from_parts<A: Authorization>(
        bundle: &Bundle<A>,
        hash_type: SighashType,
        index: usize,
        script_code: &'a Script,
        script_pubkey: &'a Script,
        value: Zatoshis,
    ) -> Result<Self, InvalidInputIndex> {
        if index >= bundle.vin.len() {
            return Err(InvalidInputIndex {
                index,
                input_count: bundle.vin.len(),
            });
        }

        Ok(Self {
            hash_type,
            index,
            script_code,
            script_pubkey,
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    use zcash_protocol::value::Zatoshis;

    use super::{InvalidInputIndex, SighashType, SignableInput};
    use crate::{
        address::Script,
        bundle::{Bundle, EffectsOnly, OutPoint, TxIn},
    };

    #[test]
    fn signable_input_rejects_out_of_range_index() {
        let bundle = Bundle {
            vin: vec![TxIn::from_parts(OutPoint::fake(), (), u32::MAX)],
            vout: vec![],
            authorization: EffectsOnly { inputs: vec![] },
        };
        let script = Script::default();

        let err = SignableInput::from_parts(
            &bundle,
            SighashType::ALL,
            1,
            &script,
            &script,
            Zatoshis::ZERO,
        )
        .unwrap_err();

        assert_eq!(
            err,
            InvalidInputIndex {
                index: 1,
                input_count: 1,
            }
        );
    }
}
