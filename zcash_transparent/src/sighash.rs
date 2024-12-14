use zcash_protocol::value::Zatoshis;

use crate::{address::Script, bundle::Authorization};

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
