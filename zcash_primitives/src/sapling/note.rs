use group::{ff::Field, GroupEncoding};
use rand_core::{CryptoRng, RngCore};

use super::{value::NoteValue, Node, Nullifier, NullifierDerivingKey};
use crate::keys::prf_expand;

mod commitment;
pub use self::commitment::{ExtractedNoteCommitment, NoteCommitment};

pub(super) mod nullifier;

/// Enum for note randomness before and after [ZIP 212](https://zips.z.cash/zip-0212).
///
/// Before ZIP 212, the note commitment trapdoor `rcm` must be a scalar value.
/// After ZIP 212, the note randomness `rseed` is a 32-byte sequence, used to derive
/// both the note commitment trapdoor `rcm` and the ephemeral private key `esk`.
#[derive(Copy, Clone, Debug)]
pub enum Rseed {
    BeforeZip212(jubjub::Fr),
    AfterZip212([u8; 32]),
}

impl Rseed {
    /// Defined in [Zcash Protocol Spec § 4.7.2: Sending Notes (Sapling)][saplingsend].
    ///
    /// [saplingsend]: https://zips.z.cash/protocol/protocol.pdf#saplingsend
    pub(crate) fn rcm(&self) -> commitment::NoteCommitTrapdoor {
        commitment::NoteCommitTrapdoor(match self {
            Rseed::BeforeZip212(rcm) => *rcm,
            Rseed::AfterZip212(rseed) => {
                jubjub::Fr::from_bytes_wide(prf_expand(rseed, &[0x04]).as_array())
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct Note {
    /// The value of the note
    pub value: u64,
    /// The diversified base of the address, GH(d)
    pub g_d: jubjub::SubgroupPoint,
    /// The public key of the address, g_d^ivk
    pub pk_d: jubjub::SubgroupPoint,
    /// rseed
    pub rseed: Rseed,
}

impl PartialEq for Note {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
            && self.g_d == other.g_d
            && self.pk_d == other.pk_d
            && self.rcm() == other.rcm()
    }
}

impl Note {
    pub fn uncommitted() -> bls12_381::Scalar {
        // The smallest u-coordinate that is not on the curve
        // is one.
        bls12_381::Scalar::one()
    }

    /// Computes the note commitment, returning the full point.
    fn cm_full_point(&self) -> NoteCommitment {
        NoteCommitment::derive(
            self.g_d.to_bytes(),
            self.pk_d.to_bytes(),
            NoteValue::from_raw(self.value),
            self.rseed.rcm(),
        )
    }

    /// Computes the nullifier given the nullifier deriving key and
    /// note position
    pub fn nf(&self, nk: &NullifierDerivingKey, position: u64) -> Nullifier {
        Nullifier::derive(nk, self.cm_full_point(), position)
    }

    /// Computes the note commitment
    pub fn cmu(&self) -> ExtractedNoteCommitment {
        self.cm_full_point().into()
    }

    pub fn rcm(&self) -> jubjub::Fr {
        self.rseed.rcm().0
    }

    pub fn generate_or_derive_esk<R: RngCore + CryptoRng>(&self, rng: &mut R) -> jubjub::Fr {
        self.generate_or_derive_esk_internal(rng)
    }

    pub(crate) fn generate_or_derive_esk_internal<R: RngCore>(&self, rng: &mut R) -> jubjub::Fr {
        match self.derive_esk() {
            None => jubjub::Fr::random(rng),
            Some(esk) => esk,
        }
    }

    /// Returns the derived `esk` if this note was created after ZIP 212 activated.
    pub fn derive_esk(&self) -> Option<jubjub::Fr> {
        match self.rseed {
            Rseed::BeforeZip212(_) => None,
            Rseed::AfterZip212(rseed) => Some(jubjub::Fr::from_bytes_wide(
                prf_expand(&rseed, &[0x05]).as_array(),
            )),
        }
    }

    /// Returns [`self.cmu`] in the correct representation for inclusion in the Sapling
    /// note commitment tree.
    pub fn commitment(&self) -> Node {
        Node {
            repr: self.cmu().to_bytes(),
        }
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub(super) mod testing {
    use proptest::prelude::*;

    use super::{
        super::{testing::arb_payment_address, value::NoteValue},
        Note, Rseed,
    };

    prop_compose! {
        pub fn arb_note(value: NoteValue)(
            addr in arb_payment_address(),
            rseed in prop::array::uniform32(prop::num::u8::ANY).prop_map(Rseed::AfterZip212)
        ) -> Note {
            Note {
                value: value.inner(),
                g_d: addr.g_d().unwrap(), // this unwrap is safe because arb_payment_address always generates an address with a valid g_d
                pk_d: *addr.pk_d(),
                rseed
            }
        }
    }
}
