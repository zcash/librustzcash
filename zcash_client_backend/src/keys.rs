//! Helper functions for managing light client key material.
#![cfg(feature = "transparent-inputs")]

use zcash_primitives::{
    legacy::TransparentAddress,
    zip32::{ChildIndex, ExtendedSpendingKey},
};

use secp256k1::{key::PublicKey, Secp256k1};

use sha2::{Digest, Sha256};

/// Derives the ZIP 32 [`ExtendedSpendingKey`] for a given coin type and account from the
/// given seed.
///
/// # Panics
///
/// Panics if `seed` is shorter than 32 bytes.
///
/// # Examples
///
/// ```
/// use zcash_primitives::{constants::testnet::COIN_TYPE};
/// use zcash_client_backend::{keys::spending_key};
///
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, 0);
/// ```
/// [`ExtendedSpendingKey`]: zcash_primitives::zip32::ExtendedSpendingKey
pub fn spending_key(seed: &[u8], coin_type: u32, account: u32) -> ExtendedSpendingKey {
    if seed.len() < 32 {
        panic!("ZIP 32 seeds MUST be at least 32 bytes");
    }

    ExtendedSpendingKey::from_path(
        &ExtendedSpendingKey::master(&seed),
        &[
            ChildIndex::Hardened(32),
            ChildIndex::Hardened(coin_type),
            ChildIndex::Hardened(account),
        ],
    )
}

pub fn derive_transparent_address_from_secret_key(
    secret_key: secp256k1::key::SecretKey,
) -> TransparentAddress {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &secret_key);
    let mut hash160 = ripemd160::Ripemd160::new();
    hash160.update(Sha256::digest(&pk.serialize()[..].to_vec()));
    TransparentAddress::PublicKey(*hash160.finalize().as_ref())
}

#[cfg(test)]
mod tests {
    use super::spending_key;

    #[test]
    #[should_panic]
    fn spending_key_panics_on_short_seed() {
        let _ = spending_key(&[0; 31][..], 0, 0);
    }
}
