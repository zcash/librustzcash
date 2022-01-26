use hdwallet::{ExtendedPrivKey, ExtendedPubKey, KeyIndex};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

use crate::{consensus, keys::prf_expand_vec, zip32::AccountId};

use super::TransparentAddress;

const MAX_TRANSPARENT_CHILD_INDEX: u32 = 0x7FFFFFFF;

/// A type representing a BIP-44 private key at the account path level
/// `m/44'/<coin_type>'/<account>'
#[derive(Clone, Debug)]
pub struct AccountPrivKey(ExtendedPrivKey);

impl AccountPrivKey {
    /// Performs derivation of the extended private key for the BIP-44 path:
    /// `m/44'/<coin_type>'/<account>'`.
    ///
    /// This produces the root of the derivation tree for transparent
    /// viewing keys and addresses for the for the provided account.
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

    pub fn to_account_pubkey(&self) -> AccountPubKey {
        AccountPubKey(ExtendedPubKey::from_private_key(&self.0))
    }

    /// Derives the BIP-44 private spending key for the external (incoming payment) child path
    /// `m/44'/<coin_type>'/<account>'/0/<child_index>`.
    pub fn derive_external_secret_key(
        &self,
        child_index: u32,
    ) -> Result<secp256k1::key::SecretKey, hdwallet::error::Error> {
        self.0
            .derive_private_key(KeyIndex::Normal(0))?
            .derive_private_key(KeyIndex::Normal(child_index))
            .map(|k| k.private_key)
    }

    /// Derives the BIP-44 private spending key for the internal (change) child path
    /// `m/44'/<coin_type>'/<account>'/1/<child_index>`.
    pub fn derive_internal_secret_key(
        &self,
        child_index: u32,
    ) -> Result<secp256k1::key::SecretKey, hdwallet::error::Error> {
        self.0
            .derive_private_key(KeyIndex::Normal(1))?
            .derive_private_key(KeyIndex::Normal(child_index))
            .map(|k| k.private_key)
    }
}

/// A type representing a BIP-44 public key at the account path level
/// `m/44'/<coin_type>'/<account>'`.
///
/// This provides the necessary derivation capability for the for
/// the transparent component of a unified full viewing key.
#[derive(Clone, Debug)]
pub struct AccountPubKey(ExtendedPubKey);

impl AccountPubKey {
    /// Derives the BIP-44 public key at the external "change level" path
    /// `m/44'/<coin_type>'/<account>'/0`.
    pub fn derive_external_ivk(&self) -> Result<ExternalIvk, hdwallet::error::Error> {
        self.0
            .derive_public_key(KeyIndex::Normal(0))
            .map(ExternalIvk)
    }

    /// Derives the BIP-44 public key at the internal "change level" path
    /// `m/44'/<coin_type>'/<account>'/1`.
    pub fn derive_internal_ivk(&self) -> Result<InternalIvk, hdwallet::error::Error> {
        self.0
            .derive_public_key(KeyIndex::Normal(1))
            .map(InternalIvk)
    }

    /// Derives the internal ovk and external ovk corresponding to this
    /// transparent fvk. As specified in [ZIP 316][transparent-ovk].
    ///
    /// [transparent-ovk]: https://zips.z.cash/zip-0316#deriving-internal-keys
    pub fn ovks_for_shielding(&self) -> (InternalOvk, ExternalOvk) {
        let i_ovk = prf_expand_vec(
            &self.0.chain_code,
            &[&[0xd0], &self.0.public_key.serialize()],
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
        Ok(AccountPubKey(ExtendedPubKey {
            public_key,
            chain_code,
        }))
    }
}

/// Derives the P2PKH transparent address corresponding to the given pubkey.
#[deprecated(note = "This function will be removed from the public API in an upcoming refactor.")]
pub fn pubkey_to_address(pubkey: &secp256k1::key::PublicKey) -> TransparentAddress {
    let mut hash160 = ripemd160::Ripemd160::new();
    hash160.update(Sha256::digest(&pubkey.serialize()));
    TransparentAddress::PublicKey(*hash160.finalize().as_ref())
}

pub(crate) mod private {
    use hdwallet::ExtendedPubKey;
    pub trait SealedChangeLevelKey {
        fn extended_pubkey(&self) -> &ExtendedPubKey;
        fn from_extended_pubkey(key: ExtendedPubKey) -> Self;
    }
}

pub trait IncomingViewingKey: private::SealedChangeLevelKey + std::marker::Sized {
    /// Derives a transparent address at the provided child index.
    fn derive_address(
        &self,
        child_index: u32,
    ) -> Result<TransparentAddress, hdwallet::error::Error> {
        let child_key = self
            .extended_pubkey()
            .derive_public_key(KeyIndex::Normal(child_index))?;
        Ok(pubkey_to_address(&child_key.public_key))
    }

    /// Searches the space of child indexes for an index that will
    /// generate a valid transparent address, and returns the resulting
    /// address and the index at which it was generated.
    fn default_address(&self) -> (TransparentAddress, u32) {
        let mut child_index = 0;
        while child_index <= MAX_TRANSPARENT_CHILD_INDEX {
            match self.derive_address(child_index) {
                Ok(addr) => {
                    return (addr, child_index);
                }
                Err(_) => {
                    child_index += 1;
                }
            }
        }
        panic!("Exhausted child index space attempting to find a default address.");
    }

    fn serialize(&self) -> Vec<u8> {
        let extpubkey = self.extended_pubkey();
        let mut buf = extpubkey.chain_code.clone();
        buf.extend(extpubkey.public_key.serialize().to_vec());
        buf
    }

    fn deserialize(data: &[u8; 65]) -> Result<Self, hdwallet::error::Error> {
        let chain_code = data[..32].to_vec();
        let public_key = PublicKey::from_slice(&data[32..])?;
        Ok(Self::from_extended_pubkey(ExtendedPubKey {
            public_key,
            chain_code,
        }))
    }
}

/// A type representing an incoming viewing key at the BIP-44 "external"
/// path `m/44'/<coin_type>'/<account>'/0`. This allows derivation
/// of child addresses that may be provided to external parties.
#[derive(Clone, Debug)]
pub struct ExternalIvk(ExtendedPubKey);

impl private::SealedChangeLevelKey for ExternalIvk {
    fn extended_pubkey(&self) -> &ExtendedPubKey {
        &self.0
    }

    fn from_extended_pubkey(key: ExtendedPubKey) -> Self {
        ExternalIvk(key)
    }
}

impl IncomingViewingKey for ExternalIvk {}

/// A type representing an incoming viewing key at the BIP-44 "internal"
/// path `m/44'/<coin_type>'/<account>'/1`. This allows derivation
/// of change addresses for use within the wallet, but which should
/// not be shared with external parties.
#[derive(Clone, Debug)]
pub struct InternalIvk(ExtendedPubKey);

impl private::SealedChangeLevelKey for InternalIvk {
    fn extended_pubkey(&self) -> &ExtendedPubKey {
        &self.0
    }

    fn from_extended_pubkey(key: ExtendedPubKey) -> Self {
        InternalIvk(key)
    }
}

impl IncomingViewingKey for InternalIvk {}

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
