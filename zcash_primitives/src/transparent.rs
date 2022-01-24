use crate::{legacy::TransparentAddress, sapling::keys::prf_expand_vec};
use hdwallet::{traits::Deserialize, ExtendedPrivKey, ExtendedPubKey};
use sha2::{Digest, Sha256};
use std::convert::TryInto;

/// A type representing a private key at the BIP-44 external child
/// level `m/44'/<coin_type>'/<account>'/0/<child_index>
#[derive(Clone, Debug)]
pub struct ExternalPrivKey(pub ExtendedPrivKey);

impl ExternalPrivKey {
    /// Returns the external public key corresponding to this private key
    pub fn to_external_pubkey(&self) -> ExternalPubKey {
        ExternalPubKey(ExtendedPubKey::from_private_key(&self.0))
    }

    /// Extracts the secp256k1 secret key component
    pub fn secret_key(&self) -> &secp256k1::key::SecretKey {
        &self.0.private_key
    }
}

pub fn pubkey_to_address(pubkey: &secp256k1::key::PublicKey) -> TransparentAddress {
    let mut hash160 = ripemd160::Ripemd160::new();
    hash160.update(Sha256::digest(&pubkey.serialize()));
    TransparentAddress::PublicKey(*hash160.finalize().as_ref())
}

/// A type representing a public key at the BIP-44 external child
/// level `m/44'/<coin_type>'/<account>'/0/<child_index>
#[derive(Clone, Debug)]
pub struct ExternalPubKey(pub ExtendedPubKey);

impl std::convert::TryFrom<&[u8; 65]> for ExternalPubKey {
    type Error = hdwallet::error::Error;

    fn try_from(data: &[u8; 65]) -> Result<Self, Self::Error> {
        let ext_pub_key = ExtendedPubKey::deserialize(data)?;
        Ok(Self(ext_pub_key))
    }
}

impl ExternalPubKey {
    /// Returns the transparent address corresponding to
    /// this public key.
    pub fn to_address(&self) -> TransparentAddress {
        pubkey_to_address(&self.0.public_key)
    }

    /// Returns the secp256k1::key::PublicKey component of
    /// this public key.
    pub fn public_key(&self) -> &secp256k1::key::PublicKey {
        &self.0.public_key
    }

    /// Returns the chain code component of this public key.
    pub fn chain_code(&self) -> &[u8] {
        &self.0.chain_code
    }

    /// Derives the internal ovk and external ovk corresponding to this
    /// transparent fvk. As specified in [ZIP 316][transparent-ovk].
    ///
    /// [transparent-ovk]: https://zips.z.cash/zip-0316#deriving-internal-keys
    fn ovk_for_shielding(&self) -> (InternalOvk, ExternalOvk) {
        let i_ovk = prf_expand_vec(
            &self.chain_code(),
            &[&[0xd0], &self.public_key().serialize()],
        );
        let i_ovk = i_ovk.as_bytes();
        let ovk_internal = InternalOvk(i_ovk[..32].try_into().unwrap());
        let ovk_external = ExternalOvk(i_ovk[32..].try_into().unwrap());

        (ovk_internal, ovk_external)
    }

    /// Derives the internal ovk corresponding to this transparent fvk.
    pub fn internal_ovk(&self) -> InternalOvk {
        self.ovk_for_shielding().0
    }

    /// Derives the external ovk corresponding to this transparent fvk.
    pub fn external_ovk(&self) -> ExternalOvk {
        self.ovk_for_shielding().1
    }
}

/// Internal ovk used for autoshielding.
pub struct InternalOvk([u8; 32]);

impl InternalOvk {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// External ovk used by zcashd for transparent -> shielded spends to
/// external receivers.
pub struct ExternalOvk([u8; 32]);

impl ExternalOvk {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}
