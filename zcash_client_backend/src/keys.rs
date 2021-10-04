//! Helper functions for managing light client key material.

use zcash_primitives::zip32::{ChildIndex, ExtendedSpendingKey};

use crate::wallet::AccountId;

use zcash_primitives::{legacy::TransparentAddress, zip32::ExtendedFullViewingKey};

#[cfg(feature = "transparent-inputs")]
use {
    bs58::{self, decode::Error as Bs58Error},
    hdwallet::{ExtendedPrivKey, ExtendedPubKey, KeyIndex},
    secp256k1::{key::PublicKey, key::SecretKey, Secp256k1},
    sha2::{Digest, Sha256},
    std::convert::TryInto,
    zcash_primitives::consensus,
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
/// use zcash_client_backend::{
///     keys::spending_key,
///     wallet::AccountId,
/// };
///
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, AccountId(0));
/// ```
/// [`ExtendedSpendingKey`]: zcash_primitives::zip32::ExtendedSpendingKey
pub fn spending_key(seed: &[u8], coin_type: u32, account: AccountId) -> ExtendedSpendingKey {
    if seed.len() < 32 {
        panic!("ZIP 32 seeds MUST be at least 32 bytes");
    }

    ExtendedSpendingKey::from_path(
        &ExtendedSpendingKey::master(&seed),
        &[
            ChildIndex::Hardened(32),
            ChildIndex::Hardened(coin_type),
            ChildIndex::Hardened(account.0),
        ],
    )
}

#[cfg(feature = "transparent-inputs")]
pub fn derive_transparent_address_from_secret_key(
    secret_key: &secp256k1::key::SecretKey,
) -> TransparentAddress {
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, secret_key);
    derive_transparent_address_from_public_key(&pk)
}

#[cfg(feature = "transparent-inputs")]
pub fn derive_transparent_address_from_public_key(
    public_key: &secp256k1::key::PublicKey,
) -> TransparentAddress {
    let mut hash160 = ripemd160::Ripemd160::new();
    hash160.update(Sha256::digest(&public_key.serialize()));
    TransparentAddress::PublicKey(*hash160.finalize().as_ref())
}

#[cfg(feature = "transparent-inputs")]
pub fn derive_secret_key_from_seed<P: consensus::Parameters>(
    params: &P,
    seed: &[u8],
    account: AccountId,
    index: u32,
) -> Result<SecretKey, hdwallet::error::Error> {
    let private_key =
        derive_extended_private_key_from_seed(params, seed, account, index)?.private_key;
    Ok(private_key)
}

#[cfg(feature = "transparent-inputs")]
pub fn derive_public_key_from_seed<P: consensus::Parameters>(
    params: &P,
    seed: &[u8],
    account: AccountId,
    index: u32,
) -> Result<PublicKey, hdwallet::error::Error> {
    let private_key = derive_extended_private_key_from_seed(params, seed, account, index)?;
    let pub_key = ExtendedPubKey::from_private_key(&private_key);
    Ok(pub_key.public_key)
}

#[cfg(feature = "transparent-inputs")]
pub fn derive_extended_private_key_from_seed<P: consensus::Parameters>(
    params: &P,
    seed: &[u8],
    account: AccountId,
    index: u32,
) -> Result<ExtendedPrivKey, hdwallet::error::Error> {
    let pk = ExtendedPrivKey::with_seed(&seed)?;
    let private_key = pk
        .derive_private_key(KeyIndex::hardened_from_normalize_index(44)?)?
        .derive_private_key(KeyIndex::hardened_from_normalize_index(params.coin_type())?)?
        .derive_private_key(KeyIndex::hardened_from_normalize_index(account.0)?)?
        .derive_private_key(KeyIndex::Normal(0))?
        .derive_private_key(KeyIndex::Normal(index))?;
    Ok(private_key)
}

#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Debug, Eq, PartialEq)]
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
impl<'a> TryInto<SecretKey> for &'a Wif {
    type Error = Bs58Error;

    fn try_into(self) -> Result<SecretKey, Self::Error> {
        bs58::decode(&self.0)
            .with_check(None)
            .into_vec()
            .map(|decoded| SecretKey::from_slice(&decoded[1..33]).expect("wrong size key"))
    }
}

/// A set of viewing keys that are all associated with a single
/// ZIP-0032 account identifier.
#[derive(Clone, Debug)]
pub struct UnifiedFullViewingKey {
    account: AccountId,
    transparent: Option<TransparentAddress>,
    sapling: Option<ExtendedFullViewingKey>,
}

impl UnifiedFullViewingKey {
    /// Construct a new unified full viewing key, if the required components are present.
    pub fn new(
        account: AccountId,
        transparent: Option<TransparentAddress>,
        sapling: Option<ExtendedFullViewingKey>,
    ) -> Option<UnifiedFullViewingKey> {
        if sapling.is_none() {
            None
        } else {
            Some(UnifiedFullViewingKey {
                account,
                transparent,
                sapling,
            })
        }
    }

    /// Returns the ZIP32 account identifier to which all component
    /// keys are related.
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the transparent component of the unified key.
    // TODO: make this the pubkey rather than the address to
    // permit child derivation
    pub fn transparent(&self) -> Option<&TransparentAddress> {
        self.transparent.as_ref()
    }

    /// Returns the Sapling extended full viewing key component of this
    /// unified key.
    pub fn sapling(&self) -> Option<&ExtendedFullViewingKey> {
        self.sapling.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::spending_key;
    use crate::wallet::AccountId;

    #[cfg(feature = "transparent-inputs")]
    use {
        super::{
            derive_public_key_from_seed, derive_secret_key_from_seed,
            derive_transparent_address_from_public_key, derive_transparent_address_from_secret_key,
            Wif,
        },
        crate::encoding::AddressCodec,
        secp256k1::key::SecretKey,
        std::convert::TryInto,
        zcash_primitives::consensus::MAIN_NETWORK,
    };

    #[cfg(feature = "transparent-inputs")]
    fn seed() -> Vec<u8> {
        let seed_hex = "6ef5f84def6f4b9d38f466586a8380a38593bd47c8cda77f091856176da47f26b5bd1c8d097486e5635df5a66e820d28e1d73346f499801c86228d43f390304f";
        hex::decode(&seed_hex).unwrap()
    }

    #[test]
    #[should_panic]
    fn spending_key_panics_on_short_seed() {
        let _ = spending_key(&[0; 31][..], 0, AccountId(0));
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn sk_to_wif() {
        let sk = derive_secret_key_from_seed(&MAIN_NETWORK, &seed(), AccountId(0), 0).unwrap();
        let wif = Wif::from_secret_key(&sk, true).0;
        assert_eq!(
            wif,
            "L4BvDC33yLjMRxipZvdiUmdYeRfZmR8viziwsVwe72zJdGbiJPv2".to_string()
        );
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn sk_to_taddr() {
        let sk = derive_secret_key_from_seed(&MAIN_NETWORK, &seed(), AccountId(0), 0).unwrap();
        let taddr = derive_transparent_address_from_secret_key(&sk).encode(&MAIN_NETWORK);
        assert_eq!(taddr, "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn sk_wif_to_taddr() {
        let sk_wif = Wif("L4BvDC33yLjMRxipZvdiUmdYeRfZmR8viziwsVwe72zJdGbiJPv2".to_string());
        let sk: SecretKey = (&sk_wif).try_into().expect("invalid wif");
        let taddr = derive_transparent_address_from_secret_key(&sk).encode(&MAIN_NETWORK);
        assert_eq!(taddr, "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn pk_from_seed() {
        let pk = derive_public_key_from_seed(&MAIN_NETWORK, &seed(), AccountId(0), 0).unwrap();
        let hex_value = hex::encode(&pk.serialize());
        assert_eq!(
            hex_value,
            "03b1d7fb28d17c125b504d06b1530097e0a3c76ada184237e3bc0925041230a5af".to_string()
        );
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn pk_to_taddr() {
        let pk = derive_public_key_from_seed(&MAIN_NETWORK, &seed(), AccountId(0), 0).unwrap();
        let taddr = derive_transparent_address_from_public_key(&pk).encode(&MAIN_NETWORK);
        assert_eq!(taddr, "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }
}
