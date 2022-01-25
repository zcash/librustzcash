use hdwallet::{ExtendedPrivKey, ExtendedPubKey, KeyIndex};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

use crate::{consensus, keys::prf_expand_vec, zip32::AccountId};

use super::TransparentAddress;

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

    pub fn from_extended_privkey(extprivkey: ExtendedPrivKey) -> Self {
        AccountPrivKey(extprivkey)
    }

    pub fn extended_privkey(&self) -> &ExtendedPrivKey {
        &self.0
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
    pub fn derive_external_pubkey(
        &self,
        child_index: u32,
    ) -> Result<ExternalPubKey, hdwallet::error::Error> {
        self.0
            .derive_public_key(KeyIndex::Normal(0))?
            .derive_public_key(KeyIndex::Normal(child_index))
            .map(ExternalPubKey)
    }

    pub fn from_extended_pubkey(extpubkey: ExtendedPubKey) -> Self {
        AccountPubKey(extpubkey)
    }

    pub fn extended_pubkey(&self) -> &ExtendedPubKey {
        &self.0
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

pub fn pubkey_to_address(pubkey: &secp256k1::key::PublicKey) -> TransparentAddress {
    let mut hash160 = ripemd160::Ripemd160::new();
    hash160.update(Sha256::digest(&pubkey.serialize()));
    TransparentAddress::PublicKey(*hash160.finalize().as_ref())
}

/// A type representing a public key at the BIP-44 external child
/// level `m/44'/<coin_type>'/<account>'/0/<child_index>
#[derive(Clone, Debug)]
pub struct ExternalPubKey(ExtendedPubKey);

impl std::convert::TryFrom<&[u8; 65]> for ExternalPubKey {
    type Error = hdwallet::error::Error;

    fn try_from(data: &[u8; 65]) -> Result<Self, Self::Error> {
        ExternalPubKey::deserialize(data)
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
    pub fn ovks_for_shielding(&self) -> (InternalOvk, ExternalOvk) {
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
        self.ovks_for_shielding().0
    }

    /// Derives the external ovk corresponding to this transparent fvk.
    pub fn external_ovk(&self) -> ExternalOvk {
        self.ovks_for_shielding().1
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = self.0.chain_code.clone();
        buf.extend(self.0.public_key.serialize().to_vec());
        buf
    }

    pub fn deserialize(data: &[u8; 65]) -> Result<Self, hdwallet::error::Error> {
        let chain_code = data[..32].to_vec();
        let public_key = PublicKey::from_slice(&data[32..])?;
        Ok(ExternalPubKey(ExtendedPubKey {
            public_key,
            chain_code,
        }))
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
