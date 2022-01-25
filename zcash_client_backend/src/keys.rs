//! Helper functions for managing light client key material.
use zcash_primitives::{consensus, zip32::AccountId};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::legacy::keys as legacy;

pub mod sapling {
    use zcash_primitives::zip32::{AccountId, ChildIndex};
    pub use zcash_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};

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
    /// use zcash_primitives::{
    ///     constants::testnet::COIN_TYPE,
    ///     zip32::AccountId,
    /// };
    /// use zcash_client_backend::{
    ///     keys::sapling,
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
    use secp256k1::SecretKey;
    use zcash_primitives::consensus;

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

#[derive(Debug)]
pub enum DerivationError {
    #[cfg(feature = "transparent-inputs")]
    Transparent(hdwallet::error::Error),
}

/// A set of viewing keys that are all associated with a single
/// ZIP-0032 account identifier.
#[derive(Clone, Debug)]
pub struct UnifiedSpendingKey {
    account: AccountId,
    #[cfg(feature = "transparent-inputs")]
    transparent: legacy::AccountPrivKey,
    sapling: sapling::ExtendedSpendingKey,
}

impl UnifiedSpendingKey {
    pub fn from_seed<P: consensus::Parameters>(
        params: &P,
        seed: &[u8],
        account: AccountId,
    ) -> Result<UnifiedSpendingKey, DerivationError> {
        if seed.len() < 32 {
            panic!("ZIP 32 seeds MUST be at least 32 bytes");
        }

        #[cfg(feature = "transparent-inputs")]
        let transparent = legacy::AccountPrivKey::from_seed(params, seed, account)
            .map_err(DerivationError::Transparent)?;

        Ok(UnifiedSpendingKey {
            account,
            #[cfg(feature = "transparent-inputs")]
            transparent,
            sapling: sapling::spending_key(seed, params.coin_type(), account),
        })
    }

    pub fn to_unified_full_viewing_key(&self) -> UnifiedFullViewingKey {
        UnifiedFullViewingKey {
            account: self.account,
            #[cfg(feature = "transparent-inputs")]
            transparent: Some(self.transparent.to_account_pubkey()),
            sapling: Some(sapling::ExtendedFullViewingKey::from(&self.sapling)),
        }
    }

    pub fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the transparent component of the unified key at the
    /// BIP44 path `m/44'/<coin_type>'/<account>'`.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> &legacy::AccountPrivKey {
        &self.transparent
    }

    /// Returns the Sapling extended full viewing key component of this
    /// unified key.
    pub fn sapling(&self) -> &sapling::ExtendedSpendingKey {
        &self.sapling
    }
}

/// A set of viewing keys that are all associated with a single
/// ZIP-0032 account identifier.
#[derive(Clone, Debug)]
pub struct UnifiedFullViewingKey {
    account: AccountId,
    #[cfg(feature = "transparent-inputs")]
    transparent: Option<legacy::AccountPubKey>,
    sapling: Option<sapling::ExtendedFullViewingKey>,
}

impl UnifiedFullViewingKey {
    /// Construct a new unified full viewing key, if the required components are present.
    pub fn new(
        account: AccountId,
        #[cfg(feature = "transparent-inputs")] transparent: Option<legacy::AccountPubKey>,
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
    pub fn transparent(&self) -> Option<&legacy::AccountPubKey> {
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
    use zcash_primitives::zip32::AccountId;

    #[cfg(feature = "transparent-inputs")]
    use {
        super::transparent,
        crate::encoding::AddressCodec,
        secp256k1::key::SecretKey,
        zcash_primitives::{consensus::MAIN_NETWORK, legacy},
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
        let sk = legacy::keys::AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId(0))
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
        let taddr = legacy::keys::pubkey_to_address(&pubkey).encode(&MAIN_NETWORK);
        assert_eq!(taddr, "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn pk_from_seed() {
        let pk = legacy::keys::AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId(0))
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
        let pk = legacy::keys::AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId(0))
            .unwrap()
            .derive_external_secret_key(0)
            .unwrap()
            .to_external_pubkey();
        let taddr = pk.to_address().encode(&MAIN_NETWORK);
        assert_eq!(taddr, "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }
}
