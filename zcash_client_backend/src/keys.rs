//! Helper functions for managing light client key material.
use crate::wallet::AccountId;

pub mod sapling {
    pub use zcash_primitives::zip32::ExtendedFullViewingKey;
    use zcash_primitives::zip32::{ChildIndex, ExtendedSpendingKey};

    use crate::wallet::AccountId;

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
    ///     keys::sapling,
    ///     wallet::AccountId,
    /// };
    ///
    /// let extsk = sapling::spending_key(&[0; 32][..], COIN_TYPE, AccountId(0));
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
}

#[cfg(feature = "transparent-inputs")]
pub mod transparent {
    use bs58::{self, decode::Error as Bs58Error};
    use hdwallet::{ExtendedPrivKey, ExtendedPubKey, KeyIndex};
    use secp256k1::key::SecretKey;
    use sha2::{Digest, Sha256};

    use crate::wallet::AccountId;
    use zcash_primitives::{consensus, legacy::TransparentAddress};

    /// A type representing a BIP-44 private key at the account path level
    /// `m/44'/<coin_type>'/<account>'
    #[derive(Clone, Debug)]
    pub struct AccountPrivKey(ExtendedPrivKey);

    impl AccountPrivKey {
        /// Perform derivation of the extended private key for the BIP-44 path:
        /// `m/44'/<coin_type>'/<account>'
        ///
        /// This produces the extended private key for the external (non-change)
        /// address at the specified index for the provided account.
        pub fn from_seed<P: consensus::Parameters>(
            params: &P,
            seed: &[u8],
            account: AccountId,
        ) -> Result<AccountPrivKey, hdwallet::error::Error> {
            ExtendedPrivKey::with_seed(&seed)?
                .derive_private_key(KeyIndex::hardened_from_normalize_index(44)?)?
                .derive_private_key(KeyIndex::hardened_from_normalize_index(params.coin_type())?)?
                .derive_private_key(KeyIndex::hardened_from_normalize_index(account.0)?)
                .map(AccountPrivKey)
        }

        pub fn to_account_pubkey(&self) -> AccountPubKey {
            AccountPubKey(ExtendedPubKey::from_private_key(&self.0))
        }

        /// Derive BIP-44 private key at the external child path
        /// `m/44'/<coin_type>'/<account>'/0/<child_index>
        pub fn derive_external_secret_key(
            &self,
            child_index: u32,
        ) -> Result<ExternalPrivKey, hdwallet::error::Error> {
            self.0
                .derive_private_key(KeyIndex::Normal(0))?
                .derive_private_key(KeyIndex::Normal(child_index))
                .map(ExternalPrivKey)
        }
    }

    /// A type representing a BIP-44 public key at the account path level
    /// `m/44'/<coin_type>'/<account>'
    #[derive(Clone, Debug)]
    pub struct AccountPubKey(ExtendedPubKey);

    impl AccountPubKey {
        /// Derive BIP-44 public key at the external child path
        /// `m/44'/<coin_type>'/<account>'/0/<child_index>
        pub fn to_external_pubkey(
            &self,
            child_index: u32,
        ) -> Result<ExternalPubKey, hdwallet::error::Error> {
            self.0
                .derive_public_key(KeyIndex::Normal(0))?
                .derive_public_key(KeyIndex::Normal(child_index))
                .map(ExternalPubKey)
        }
    }

    /// A type representing a private key at the BIP-44 external child
    /// level `m/44'/<coin_type>'/<account>'/0/<child_index>
    #[derive(Clone, Debug)]
    pub struct ExternalPrivKey(ExtendedPrivKey);

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

    pub(crate) fn pubkey_to_address(pubkey: &secp256k1::key::PublicKey) -> TransparentAddress {
        let mut hash160 = ripemd::Ripemd160::new();
        hash160.update(Sha256::digest(pubkey.serialize()));
        TransparentAddress::PublicKey(*hash160.finalize().as_ref())
    }

    /// A type representing a public key at the BIP-44 external child
    /// level `m/44'/<coin_type>'/<account>'/0/<child_index>
    #[derive(Clone, Debug)]
    pub struct ExternalPubKey(ExtendedPubKey);

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

    /// Wallet Import Format encoded transparent private key.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Wif(pub String);

    /// Errors that may occur in WIF key decoding.
    #[derive(Debug)]
    pub enum WifError {
        Base58(Bs58Error),
        InvalidLeadByte(u8),
        InvalidTrailingByte(u8),
        Secp256k1(secp256k1::Error),
    }

    impl Wif {
        /// Encode the provided secret key in Wallet Import Format.
        pub fn from_secret_key<P: consensus::Parameters>(
            params: &P,
            sk: &SecretKey,
            compressed: bool,
        ) -> Self {
            let secret_key = sk.as_ref();
            let mut wif = [0u8; 34];
            wif[0] = params.wif_lead_byte();
            wif[1..33].copy_from_slice(secret_key);
            if compressed {
                wif[33] = 0x01;
                Wif(bs58::encode(&wif[..]).with_check().into_string())
            } else {
                Wif(bs58::encode(&wif[..]).with_check().into_string())
            }
        }

        /// Decode this Wif value to obtain the encoded secret key
        pub fn to_secret_key<P: consensus::Parameters>(
            &self,
            params: &P,
        ) -> Result<SecretKey, WifError> {
            bs58::decode(&self.0)
                .with_check(None)
                .into_vec()
                .map_err(WifError::Base58)
                .and_then(|decoded| {
                    if decoded[0] != params.wif_lead_byte() {
                        Err(WifError::InvalidLeadByte(decoded[0]))
                    } else if decoded[33] != 0x01 {
                        Err(WifError::InvalidTrailingByte(decoded[33]))
                    } else {
                        SecretKey::from_slice(&decoded[1..33]).map_err(WifError::Secp256k1)
                    }
                })
        }
    }
}

/// A set of viewing keys that are all associated with a single
/// ZIP-0032 account identifier.
#[derive(Clone, Debug)]
pub struct UnifiedFullViewingKey {
    account: AccountId,
    #[cfg(feature = "transparent-inputs")]
    transparent: Option<transparent::AccountPubKey>,
    sapling: Option<sapling::ExtendedFullViewingKey>,
}

impl UnifiedFullViewingKey {
    /// Construct a new unified full viewing key, if the required components are present.
    pub fn new(
        account: AccountId,
        #[cfg(feature = "transparent-inputs")] transparent: Option<transparent::AccountPubKey>,
        sapling: Option<sapling::ExtendedFullViewingKey>,
    ) -> Option<UnifiedFullViewingKey> {
        if sapling.is_none() {
            None
        } else {
            Some(UnifiedFullViewingKey {
                account,
                #[cfg(feature = "transparent-inputs")]
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

    #[cfg(feature = "transparent-inputs")]
    /// Returns the transparent component of the unified key at the
    /// BIP44 path `m/44'/<coin_type>'/<account>'`.
    pub fn transparent(&self) -> Option<&transparent::AccountPubKey> {
        self.transparent.as_ref()
    }

    /// Returns the Sapling extended full viewing key component of this
    /// unified key.
    pub fn sapling(&self) -> Option<&sapling::ExtendedFullViewingKey> {
        self.sapling.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::sapling;
    use crate::wallet::AccountId;

    #[cfg(feature = "transparent-inputs")]
    use {
        super::transparent, crate::encoding::AddressCodec, secp256k1::key::SecretKey,
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
        let _ = sapling::spending_key(&[0; 31][..], 0, AccountId(0));
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn sk_to_wif() {
        let sk = transparent::AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId(0))
            .unwrap()
            .derive_external_secret_key(0)
            .unwrap();
        let wif = transparent::Wif::from_secret_key(&MAIN_NETWORK, &sk.secret_key(), true).0;
        assert_eq!(
            wif,
            "L4BvDC33yLjMRxipZvdiUmdYeRfZmR8viziwsVwe72zJdGbiJPv2".to_string()
        );
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn sk_wif_to_taddr() {
        let sk_wif =
            transparent::Wif("L4BvDC33yLjMRxipZvdiUmdYeRfZmR8viziwsVwe72zJdGbiJPv2".to_string());
        let sk: SecretKey = (&sk_wif).to_secret_key(&MAIN_NETWORK).expect("invalid wif");
        let secp = secp256k1::Secp256k1::new();
        let pubkey = secp256k1::key::PublicKey::from_secret_key(&secp, &sk);
        let taddr = transparent::pubkey_to_address(&pubkey).encode(&MAIN_NETWORK);
        assert_eq!(taddr, "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn pk_from_seed() {
        let pk = transparent::AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId(0))
            .unwrap()
            .derive_external_secret_key(0)
            .unwrap()
            .to_external_pubkey();
        let hex_value = hex::encode(&pk.public_key().serialize());
        assert_eq!(
            hex_value,
            "03b1d7fb28d17c125b504d06b1530097e0a3c76ada184237e3bc0925041230a5af".to_string()
        );
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn pk_to_taddr() {
        let pk = transparent::AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId(0))
            .unwrap()
            .derive_external_secret_key(0)
            .unwrap()
            .to_external_pubkey();
        let taddr = pk.to_address().encode(&MAIN_NETWORK);
        assert_eq!(taddr, "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }
}
