//! Helper functions for managing light client key material.

use zcash_primitives::zip32::{ChildIndex, ExtendedSpendingKey};

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::AccountId,
    bs58::decode::Error as Bs58Error,
    hdwallet::{ExtendedPrivKey, KeyIndex},
    secp256k1::{key::PublicKey, Secp256k1, SecretKey},
    sha2::{Digest, Sha256},
    std::convert::TryInto,
    zcash_primitives::{consensus, legacy::TransparentAddress},
};

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

#[cfg(feature = "transparent-inputs")]
pub fn derive_transparent_address_from_secret_key(
    secret_key: secp256k1::key::SecretKey,
) -> TransparentAddress {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &secret_key);
    let mut hash160 = ripemd160::Ripemd160::new();
    hash160.update(Sha256::digest(&pk.serialize()[..].to_vec()));
    TransparentAddress::PublicKey(*hash160.finalize().as_ref())
}

#[cfg(feature = "transparent-inputs")]
pub fn derive_secret_key_from_seed<P: consensus::Parameters>(
    params: &P,
    seed: &[u8],
    account: AccountId,
    index: u32,
) -> Result<SecretKey, hdwallet::error::Error> {
    let ext_t_key = ExtendedPrivKey::with_seed(&seed)?;
    let private_key = ext_t_key
        .derive_private_key(KeyIndex::hardened_from_normalize_index(44)?)?
        .derive_private_key(KeyIndex::hardened_from_normalize_index(params.coin_type())?)?
        .derive_private_key(KeyIndex::hardened_from_normalize_index(account.0)?)?
        .derive_private_key(KeyIndex::Normal(0))?
        .derive_private_key(KeyIndex::Normal(index))?
        .private_key;

    Ok(private_key)
}

#[cfg(feature = "transparent-inputs")]
pub struct Wif(pub String);

#[cfg(feature = "transparent-inputs")]
impl Wif {
    pub fn from_secret_key(sk: &SecretKey, compressed: bool) -> Self {
        let secret_key = sk.as_ref();
        let mut wif = [0u8; 34];
        wif[0] = 0x80;
        wif[1..33].copy_from_slice(secret_key);
        if compressed {
            wif[33] = 0x01;
            Wif(bs58::encode(&wif[..]).with_check().into_string())
        } else {
            Wif(bs58::encode(&wif[..]).with_check().into_string())
        }
    }
}

#[cfg(feature = "transparent-inputs")]
impl TryInto<SecretKey> for Wif {
    type Error = Bs58Error;

    fn try_into(self) -> Result<SecretKey, Self::Error> {
        bs58::decode(&self.0)
            .with_check(None)
            .into_vec()
            .map(|decoded| SecretKey::from_slice(&decoded[1..33]).expect("wrong size key"))
    }
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
