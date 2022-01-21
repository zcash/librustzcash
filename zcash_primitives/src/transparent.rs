use crate::legacy::TransparentAddress;
use hdwallet::{ExtendedPrivKey, ExtendedPubKey};
use sha2::{Digest, Sha256};

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
}
