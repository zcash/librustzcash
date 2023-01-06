//! Sapling key components.
//!
//! Implements [section 4.2.2] of the Zcash Protocol Specification.
//!
//! [section 4.2.2]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents

use std::io::{self, Read, Write};

use super::{
    address::PaymentAddress,
    note_encryption::{
        PreparedEphemeralPublicKey, PreparedIncomingViewingKey, KDF_SAPLING_PERSONALIZATION,
    },
    spec::{
        crh_ivk, diversify_hash, ka_sapling_agree, ka_sapling_agree_prepared,
        ka_sapling_derive_public,
    },
};
use crate::{
    constants::{self, PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR},
    keys::prf_expand,
};

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use ff::PrimeField;
use group::{Curve, Group, GroupEncoding};
use subtle::{ConstantTimeEq, CtOption};
use zcash_note_encryption::EphemeralKeyBytes;

/// Errors that can occur in the decoding of Sapling spending keys.
pub enum DecodingError {
    /// The length of the byte slice provided for decoding was incorrect.
    LengthInvalid { expected: usize, actual: usize },
    /// Could not decode the `ask` bytes to a jubjub field element.
    InvalidAsk,
    /// Could not decode the `nsk` bytes to a jubjub field element.
    InvalidNsk,
}

/// An outgoing viewing key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutgoingViewingKey(pub [u8; 32]);

/// A Sapling expanded spending key
#[derive(Clone)]
pub struct ExpandedSpendingKey {
    pub ask: jubjub::Fr,
    pub nsk: jubjub::Fr,
    pub ovk: OutgoingViewingKey,
}

impl ExpandedSpendingKey {
    pub fn from_spending_key(sk: &[u8]) -> Self {
        let ask = jubjub::Fr::from_bytes_wide(prf_expand(sk, &[0x00]).as_array());
        let nsk = jubjub::Fr::from_bytes_wide(prf_expand(sk, &[0x01]).as_array());
        let mut ovk = OutgoingViewingKey([0u8; 32]);
        ovk.0
            .copy_from_slice(&prf_expand(sk, &[0x02]).as_bytes()[..32]);
        ExpandedSpendingKey { ask, nsk, ovk }
    }

    pub fn proof_generation_key(&self) -> ProofGenerationKey {
        ProofGenerationKey {
            ak: SPENDING_KEY_GENERATOR * self.ask,
            nsk: self.nsk,
        }
    }

    /// Decodes the expanded spending key from its serialized representation
    /// as part of the encoding of the extended spending key as defined in
    /// [ZIP 32](https://zips.z.cash/zip-0032)
    pub fn from_bytes(b: &[u8]) -> Result<Self, DecodingError> {
        if b.len() != 96 {
            return Err(DecodingError::LengthInvalid {
                expected: 96,
                actual: b.len(),
            });
        }

        let ask = Option::from(jubjub::Fr::from_repr(b[0..32].try_into().unwrap()))
            .ok_or(DecodingError::InvalidAsk)?;
        let nsk = Option::from(jubjub::Fr::from_repr(b[32..64].try_into().unwrap()))
            .ok_or(DecodingError::InvalidNsk)?;
        let ovk = OutgoingViewingKey(b[64..96].try_into().unwrap());

        Ok(ExpandedSpendingKey { ask, nsk, ovk })
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = [0u8; 96];
        reader.read_exact(repr.as_mut())?;
        Self::from_bytes(&repr).map_err(|e| match e {
            DecodingError::InvalidAsk => {
                io::Error::new(io::ErrorKind::InvalidData, "ask not in field")
            }
            DecodingError::InvalidNsk => {
                io::Error::new(io::ErrorKind::InvalidData, "nsk not in field")
            }
            DecodingError::LengthInvalid { .. } => unreachable!(),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.to_bytes())
    }

    /// Encodes the expanded spending key to the its seralized representation
    /// as part of the encoding of the extended spending key as defined in
    /// [ZIP 32](https://zips.z.cash/zip-0032)
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        result[0..32].copy_from_slice(&self.ask.to_repr());
        result[32..64].copy_from_slice(&self.nsk.to_repr());
        result[64..96].copy_from_slice(&self.ovk.0);
        result
    }
}

#[derive(Clone)]
pub struct ProofGenerationKey {
    pub ak: jubjub::SubgroupPoint,
    pub nsk: jubjub::Fr,
}

impl ProofGenerationKey {
    pub fn to_viewing_key(&self) -> ViewingKey {
        ViewingKey {
            ak: self.ak,
            nk: NullifierDerivingKey(constants::PROOF_GENERATION_KEY_GENERATOR * self.nsk),
        }
    }
}

/// A key used to derive the nullifier for a Sapling note.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NullifierDerivingKey(pub jubjub::SubgroupPoint);

#[derive(Debug, Clone)]
pub struct ViewingKey {
    pub ak: jubjub::SubgroupPoint,
    pub nk: NullifierDerivingKey,
}

impl ViewingKey {
    pub fn rk(&self, ar: jubjub::Fr) -> jubjub::SubgroupPoint {
        self.ak + constants::SPENDING_KEY_GENERATOR * ar
    }

    pub fn ivk(&self) -> SaplingIvk {
        SaplingIvk(crh_ivk(self.ak.to_bytes(), self.nk.0.to_bytes()))
    }

    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        self.ivk().to_payment_address(diversifier)
    }
}

/// A Sapling key that provides the capability to view incoming and outgoing transactions.
#[derive(Debug)]
pub struct FullViewingKey {
    pub vk: ViewingKey,
    pub ovk: OutgoingViewingKey,
}

impl Clone for FullViewingKey {
    fn clone(&self) -> Self {
        FullViewingKey {
            vk: ViewingKey {
                ak: self.vk.ak,
                nk: self.vk.nk,
            },
            ovk: self.ovk,
        }
    }
}

impl FullViewingKey {
    pub fn from_expanded_spending_key(expsk: &ExpandedSpendingKey) -> Self {
        FullViewingKey {
            vk: ViewingKey {
                ak: SPENDING_KEY_GENERATOR * expsk.ask,
                nk: NullifierDerivingKey(PROOF_GENERATION_KEY_GENERATOR * expsk.nsk),
            },
            ovk: expsk.ovk,
        }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let ak = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf).and_then(|p| CtOption::new(p, !p.is_identity()))
        };
        let nk = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf)
        };
        if ak.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ak not of prime order",
            ));
        }
        if nk.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nk not in prime-order subgroup",
            ));
        }
        let ak = ak.unwrap();
        let nk = NullifierDerivingKey(nk.unwrap());

        let mut ovk = [0u8; 32];
        reader.read_exact(&mut ovk)?;

        Ok(FullViewingKey {
            vk: ViewingKey { ak, nk },
            ovk: OutgoingViewingKey(ovk),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.vk.ak.to_bytes())?;
        writer.write_all(&self.vk.nk.0.to_bytes())?;
        writer.write_all(&self.ovk.0)?;

        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        self.write(&mut result[..])
            .expect("should be able to serialize a FullViewingKey");
        result
    }
}

#[derive(Debug, Clone)]
pub struct SaplingIvk(pub jubjub::Fr);

impl SaplingIvk {
    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        diversifier.g_d().and_then(|g_d| {
            let pk_d = g_d * self.0;

            PaymentAddress::from_parts(diversifier, pk_d)
        })
    }

    pub fn to_repr(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    pub fn g_d(&self) -> Option<jubjub::SubgroupPoint> {
        diversify_hash(&self.0)
    }
}

/// An ephemeral secret key used to encrypt an output note on-chain.
///
/// `esk` is "ephemeral" in the sense that each secret key is only used once. In
/// practice, `esk` is derived deterministically from the note that it is encrypting.
///
/// $\mathsf{KA}^\mathsf{Sapling}.\mathsf{Private} := \mathbb{F}_{r_J}$
///
/// Defined in [section 5.4.5.3: Sapling Key Agreement][concretesaplingkeyagreement].
///
/// [concretesaplingkeyagreement]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkeyagreement
#[derive(Debug)]
pub struct EphemeralSecretKey(pub(crate) jubjub::Scalar);

impl ConstantTimeEq for EphemeralSecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl EphemeralSecretKey {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        jubjub::Scalar::from_bytes(bytes).map(EphemeralSecretKey)
    }

    pub(crate) fn derive_public(&self, g_d: jubjub::ExtendedPoint) -> EphemeralPublicKey {
        EphemeralPublicKey(ka_sapling_derive_public(&self.0, &g_d))
    }

    pub(crate) fn agree(&self, pk_d: &jubjub::ExtendedPoint) -> SharedSecret {
        SharedSecret(ka_sapling_agree(&self.0, pk_d))
    }
}

/// An ephemeral public key used to encrypt an output note on-chain.
///
/// `epk` is "ephemeral" in the sense that each public key is only used once. In practice,
/// `epk` is derived deterministically from the note that it is encrypting.
///
/// $\mathsf{KA}^\mathsf{Sapling}.\mathsf{Public} := \mathbb{J}$
///
/// Defined in [section 5.4.5.3: Sapling Key Agreement][concretesaplingkeyagreement].
///
/// [concretesaplingkeyagreement]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkeyagreement
#[derive(Debug)]
pub struct EphemeralPublicKey(jubjub::ExtendedPoint);

impl EphemeralPublicKey {
    /// TODO: Remove once public API is changed.
    pub(crate) fn from_inner(epk: jubjub::ExtendedPoint) -> Self {
        EphemeralPublicKey(epk)
    }

    /// TODO: Remove once public API is changed.
    pub(crate) fn into_inner(self) -> jubjub::ExtendedPoint {
        self.0
    }

    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        jubjub::ExtendedPoint::from_bytes(bytes).map(EphemeralPublicKey)
    }

    pub(crate) fn to_bytes(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.0.to_bytes())
    }
}

impl PreparedEphemeralPublicKey {
    pub(crate) fn agree(&self, ivk: &PreparedIncomingViewingKey) -> SharedSecret {
        SharedSecret(ka_sapling_agree_prepared(ivk.inner(), self.inner()))
    }
}

/// $\mathsf{KA}^\mathsf{Sapling}.\mathsf{SharedSecret} := \mathbb{J}^{(r)}$
///
/// Defined in [section 5.4.5.3: Sapling Key Agreement][concretesaplingkeyagreement].
///
/// [concretesaplingkeyagreement]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkeyagreement
#[derive(Debug)]
pub struct SharedSecret(jubjub::SubgroupPoint);

impl SharedSecret {
    /// TODO: Remove once public API is changed.
    pub(crate) fn from_inner(epk: jubjub::SubgroupPoint) -> Self {
        SharedSecret(epk)
    }

    /// TODO: Remove once public API is changed.
    pub(crate) fn into_inner(self) -> jubjub::SubgroupPoint {
        self.0
    }

    /// For checking test vectors only.
    #[cfg(test)]
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Only for use in batched note encryption.
    pub(crate) fn batch_to_affine(
        shared_secrets: Vec<Option<Self>>,
    ) -> impl Iterator<Item = Option<jubjub::AffinePoint>> {
        // Filter out the positions for which ephemeral_key was not a valid encoding.
        let secrets: Vec<_> = shared_secrets
            .iter()
            .filter_map(|s| s.as_ref().map(|s| jubjub::ExtendedPoint::from(s.0)))
            .collect();

        // Batch-normalize the shared secrets.
        let mut secrets_affine = vec![jubjub::AffinePoint::identity(); secrets.len()];
        group::Curve::batch_normalize(&secrets, &mut secrets_affine);

        // Re-insert the invalid ephemeral_key positions.
        let mut secrets_affine = secrets_affine.into_iter();
        shared_secrets
            .into_iter()
            .map(move |s| s.and_then(|_| secrets_affine.next()))
    }

    /// Defined in [Zcash Protocol Spec § 5.4.5.4: Sapling Key Agreement][concretesaplingkdf].
    ///
    /// [concretesaplingkdf]: https://zips.z.cash/protocol/protocol.pdf#concretesaplingkdf
    pub(crate) fn kdf_sapling(self, ephemeral_key: &EphemeralKeyBytes) -> Blake2bHash {
        Self::kdf_sapling_inner(
            jubjub::ExtendedPoint::from(self.0).to_affine(),
            ephemeral_key,
        )
    }

    /// Only for direct use in batched note encryption.
    pub(crate) fn kdf_sapling_inner(
        secret: jubjub::AffinePoint,
        ephemeral_key: &EphemeralKeyBytes,
    ) -> Blake2bHash {
        Blake2bParams::new()
            .hash_length(32)
            .personal(KDF_SAPLING_PERSONALIZATION)
            .to_state()
            .update(&secret.to_bytes())
            .update(ephemeral_key.as_ref())
            .finalize()
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use std::fmt::{self, Debug, Formatter};

    use super::{ExpandedSpendingKey, FullViewingKey, SaplingIvk};

    impl Debug for ExpandedSpendingKey {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "Spending keys cannot be Debug-formatted.")
        }
    }

    prop_compose! {
        pub fn arb_expanded_spending_key()(v in vec(any::<u8>(), 32..252)) -> ExpandedSpendingKey {
            ExpandedSpendingKey::from_spending_key(&v)
        }
    }

    prop_compose! {
        pub fn arb_full_viewing_key()(sk in arb_expanded_spending_key()) -> FullViewingKey {
            FullViewingKey::from_expanded_spending_key(&sk)
        }
    }

    prop_compose! {
        pub fn arb_incoming_viewing_key()(fvk in arb_full_viewing_key()) -> SaplingIvk {
            fvk.vk.ivk()
        }
    }
}

#[cfg(test)]
mod tests {
    use group::{Group, GroupEncoding};

    use super::FullViewingKey;
    use crate::constants::SPENDING_KEY_GENERATOR;

    #[test]
    fn ak_must_be_prime_order() {
        let mut buf = [0; 96];
        let identity = jubjub::SubgroupPoint::identity();

        // Set both ak and nk to the identity.
        buf[0..32].copy_from_slice(&identity.to_bytes());
        buf[32..64].copy_from_slice(&identity.to_bytes());

        // ak is not allowed to be the identity.
        assert_eq!(
            FullViewingKey::read(&buf[..]).unwrap_err().to_string(),
            "ak not of prime order"
        );

        // Set ak to a basepoint.
        let basepoint = SPENDING_KEY_GENERATOR;
        buf[0..32].copy_from_slice(&basepoint.to_bytes());

        // nk is allowed to be the identity.
        assert!(FullViewingKey::read(&buf[..]).is_ok());
    }
}
