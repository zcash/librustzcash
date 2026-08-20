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

    /// Constructs a `SighashType` from a raw pre-V5 `hash_type` byte
    /// without applying ZIP 244 strictness.
    pub fn from_raw(hash_type: u8) -> Self {
        Self(hash_type)
    }

    /// Encodes this `SighashType` using the [ZIP 244] rules.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244#s-2a-hash-type
    pub fn encode(&self) -> u8 {
        // Correct by construction.
        self.0
    }
}

/// A set of [ZIP 244] sighash types.
///
/// A signature that does not use [`SighashType::ALL`] does not commit to some part of the
/// transaction that it authorizes: a `SIGHASH_NONE` signature commits to none of the
/// outputs, and a `SIGHASH_ANYONECANPAY` signature commits to no other input. Such a
/// signature can be lifted out of the transaction it was created for and reused in a
/// different one, so an entity that signs or finalizes on a user’s behalf should only
/// produce or accept one when the surrounding protocol calls for it.
///
/// This type is how that decision is made explicit: the default is
/// [`SighashPolicy::ALL_ONLY`], and a wider policy has to be opted into.
///
/// [ZIP 244]: https://zips.z.cash/zip-0244#s-2a-hash-type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SighashPolicy(u8);

impl Default for SighashPolicy {
    fn default() -> Self {
        Self::ALL_ONLY
    }
}

impl SighashPolicy {
    /// The empty policy, permitting no sighash type at all.
    ///
    /// Use [`SighashPolicy::permitting`] to build up a policy from this.
    pub const EMPTY: Self = Self(0);

    /// Permits only [`SighashType::ALL`].
    ///
    /// This is the default policy, and the only one under which a signature is guaranteed
    /// to commit to every input and output of the transaction it authorizes.
    pub const ALL_ONLY: Self = Self::EMPTY.permitting(SighashType::ALL);

    /// Permits every [ZIP 244] sighash type.
    ///
    /// Only use this if the surrounding protocol needs signatures that do not commit to
    /// the whole transaction, and it is the protocol rather than the counterparty that
    /// decides which sighash type each input uses.
    ///
    /// [ZIP 244]: https://zips.z.cash/zip-0244#s-2a-hash-type
    pub const ANY: Self = Self::ALL_ONLY
        .permitting(SighashType::NONE)
        .permitting(SighashType::SINGLE)
        .permitting(SighashType::ALL_ANYONECANPAY)
        .permitting(SighashType::NONE_ANYONECANPAY)
        .permitting(SighashType::SINGLE_ANYONECANPAY);

    /// Returns the bit representing `hash_type` within the policy.
    const fn bit(hash_type: SighashType) -> u8 {
        // `SighashType` is correct by construction, so the masked value is always one of
        // `SIGHASH_ALL`, `SIGHASH_NONE`, or `SIGHASH_SINGLE`, i.e. 1, 2, or 3;
        // `SIGHASH_ANYONECANPAY` shifts it into the upper half of the mask.
        1 << ((hash_type.0 & !SIGHASH_ANYONECANPAY) - 1 + (hash_type.0 >> 7) * 3)
    }

    /// Returns a policy permitting everything this policy permits, and `hash_type`.
    pub const fn permitting(self, hash_type: SighashType) -> Self {
        Self(self.0 | Self::bit(hash_type))
    }

    /// Returns whether this policy permits `hash_type`.
    pub const fn permits(&self, hash_type: SighashType) -> bool {
        (self.0 & Self::bit(hash_type)) != 0
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

    use super::{InvalidInputIndex, SighashPolicy, SighashType, SignableInput};
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

    /// Every sighash type that [`SighashType::parse`] accepts.
    const EVERY_TYPE: [SighashType; 6] = [
        SighashType::ALL,
        SighashType::NONE,
        SighashType::SINGLE,
        SighashType::ALL_ANYONECANPAY,
        SighashType::NONE_ANYONECANPAY,
        SighashType::SINGLE_ANYONECANPAY,
    ];

    #[test]
    fn every_type_has_a_distinct_bit() {
        let mut seen = 0;
        for hash_type in EVERY_TYPE {
            let bit = SighashPolicy::bit(hash_type);
            assert_eq!(seen & bit, 0, "{hash_type:?} collides with an earlier type");
            seen |= bit;
        }
        assert_eq!(seen, SighashPolicy::ANY.0);
    }

    #[test]
    fn empty_permits_nothing() {
        for hash_type in EVERY_TYPE {
            assert!(!SighashPolicy::EMPTY.permits(hash_type));
        }
    }

    #[test]
    fn all_only_permits_only_all() {
        for hash_type in EVERY_TYPE {
            assert_eq!(
                SighashPolicy::ALL_ONLY.permits(hash_type),
                hash_type == SighashType::ALL,
            );
        }
    }

    #[test]
    fn any_permits_everything() {
        for hash_type in EVERY_TYPE {
            assert!(SighashPolicy::ANY.permits(hash_type));
        }
    }

    #[test]
    fn permitting_adds_exactly_one_type() {
        let policy = SighashPolicy::ALL_ONLY.permitting(SighashType::NONE_ANYONECANPAY);
        for hash_type in EVERY_TYPE {
            assert_eq!(
                policy.permits(hash_type),
                hash_type == SighashType::ALL || hash_type == SighashType::NONE_ANYONECANPAY,
            );
        }
    }

    #[test]
    fn default_is_all_only() {
        assert_eq!(SighashPolicy::default(), SighashPolicy::ALL_ONLY);
    }
}
