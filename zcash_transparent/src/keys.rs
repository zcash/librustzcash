//! Transparent key components.

use core::fmt;

use bip32::ChildNumber;
use subtle::{Choice, ConstantTimeEq};
use zip32::DiversifierIndex;

#[cfg(feature = "transparent-inputs")]
use {
    crate::address::TransparentAddress,
    alloc::string::ToString,
    alloc::vec::Vec,
    bip32::{ExtendedKey, ExtendedKeyAttrs, ExtendedPrivateKey, ExtendedPublicKey, Prefix},
    secp256k1::PublicKey,
    zcash_protocol::consensus::{self, NetworkConstants},
    zcash_spec::PrfExpand,
    zip32::AccountId,
};

/// The scope of a transparent key.
///
/// This type can represent [`zip32`] internal and external scopes, as well as custom scopes that
/// may be used in non-hardened derivation at the `change` level of the BIP 44 key path.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransparentKeyScope(u32);

impl TransparentKeyScope {
    /// Returns an arbitrary custom `TransparentKeyScope`.
    ///
    /// This should be used with care: funds associated with keys derived under a custom
    /// scope may not be recoverable if the wallet seed is restored in another wallet. It
    /// is usually preferable to use standardized key scopes.
    pub const fn custom(i: u32) -> Option<Self> {
        if i < (1 << 31) {
            Some(TransparentKeyScope(i))
        } else {
            None
        }
    }

    /// The scope used to derive keys for external transparent addresses,
    /// intended to be used to send funds to this wallet.
    pub const EXTERNAL: Self = TransparentKeyScope(0);

    /// The scope used to derive keys for internal wallet operations, e.g.
    /// change or UTXO management.
    pub const INTERNAL: Self = TransparentKeyScope(1);

    /// The scope used to derive keys for ephemeral transparent addresses.
    pub const EPHEMERAL: Self = TransparentKeyScope(2);
}

impl fmt::Debug for TransparentKeyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::EXTERNAL => f.write_str("TransparentKeyScope::EXTERNAL"),
            Self::INTERNAL => f.write_str("TransparentKeyScope::INTERNAL"),
            Self::EPHEMERAL => f.write_str("TransparentKeyScope::EPHEMERAL"),
            TransparentKeyScope(other) => f.write_str(&format!("TransparentKeyScope({other})")),
        }
    }
}

impl From<zip32::Scope> for TransparentKeyScope {
    fn from(value: zip32::Scope) -> Self {
        match value {
            zip32::Scope::External => TransparentKeyScope::EXTERNAL,
            zip32::Scope::Internal => TransparentKeyScope::INTERNAL,
        }
    }
}

impl From<TransparentKeyScope> for ChildNumber {
    fn from(value: TransparentKeyScope) -> Self {
        ChildNumber::new(value.0, false).expect("TransparentKeyScope is correct by construction")
    }
}

/// A child index for a derived transparent address.
///
/// Only NON-hardened derivation is supported.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NonHardenedChildIndex(u32);

impl core::fmt::Debug for NonHardenedChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("NonHardenedChildIndex({})", self.0))
    }
}

impl ConstantTimeEq for NonHardenedChildIndex {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl NonHardenedChildIndex {
    /// The minimum valid non-hardened child index.
    pub const ZERO: NonHardenedChildIndex = NonHardenedChildIndex(0);

    /// The maximum valid non-hardened child index.
    pub const MAX: NonHardenedChildIndex = NonHardenedChildIndex((1 << 31) - 1);

    /// Parses the given ZIP 32 child index.
    ///
    /// Returns `None` if the hardened bit is set.
    pub const fn from_index(i: u32) -> Option<Self> {
        if i <= Self::MAX.0 {
            Some(NonHardenedChildIndex(i))
        } else {
            None
        }
    }

    /// Constructs a [`NonHardenedChildIndex`] from a ZIP 32 child index.
    ///
    /// Panics: if the hardened bit is set.
    pub const fn const_from_index(i: u32) -> Self {
        assert!(i <= Self::MAX.0);
        NonHardenedChildIndex(i)
    }

    /// Returns the index as a 32-bit integer.
    pub const fn index(&self) -> u32 {
        self.0
    }

    /// Returns the successor to this index.
    pub const fn next(&self) -> Option<Self> {
        // overflow cannot happen because self.0 is 31 bits, and the next index is at most 32 bits
        // which in that case would lead from_index to return None.
        Self::from_index(self.0 + 1)
    }

    /// Subtracts the given delta from this index.
    pub const fn saturating_sub(&self, delta: u32) -> Self {
        NonHardenedChildIndex(self.0.saturating_sub(delta))
    }

    /// Adds the given delta to this index, returning a maximum possible value of
    /// [`NonHardenedChildIndex::MAX`].
    pub const fn saturating_add(&self, delta: u32) -> Self {
        let idx = self.0.saturating_add(delta);
        if idx > Self::MAX.0 {
            Self::MAX
        } else {
            NonHardenedChildIndex(idx)
        }
    }
}

impl TryFrom<ChildNumber> for NonHardenedChildIndex {
    type Error = ();

    fn try_from(value: ChildNumber) -> Result<Self, Self::Error> {
        if value.is_hardened() {
            Err(())
        } else {
            NonHardenedChildIndex::from_index(value.index()).ok_or(())
        }
    }
}

impl From<NonHardenedChildIndex> for ChildNumber {
    fn from(value: NonHardenedChildIndex) -> Self {
        Self::new(value.index(), false).expect("NonHardenedChildIndex is correct by construction")
    }
}

impl TryFrom<DiversifierIndex> for NonHardenedChildIndex {
    type Error = ();

    fn try_from(value: DiversifierIndex) -> Result<Self, Self::Error> {
        let idx = u32::try_from(value).map_err(|_| ())?;
        NonHardenedChildIndex::from_index(idx).ok_or(())
    }
}

impl From<NonHardenedChildIndex> for DiversifierIndex {
    fn from(value: NonHardenedChildIndex) -> Self {
        DiversifierIndex::from(value.0)
    }
}

/// An end-exclusive iterator over a range of non-hardened child indexes.
pub struct NonHardenedChildIter {
    next: Option<NonHardenedChildIndex>,
    end: NonHardenedChildIndex,
}

impl Iterator for NonHardenedChildIter {
    type Item = NonHardenedChildIndex;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.next;
        self.next = self
            .next
            .and_then(|i| i.next())
            .filter(|succ| succ < &self.end);
        cur
    }
}

/// An end-exclusive range of non-hardened child indexes.
pub struct NonHardenedChildRange(core::ops::Range<NonHardenedChildIndex>);

impl From<core::ops::Range<NonHardenedChildIndex>> for NonHardenedChildRange {
    fn from(value: core::ops::Range<NonHardenedChildIndex>) -> Self {
        Self(value)
    }
}

impl IntoIterator for NonHardenedChildRange {
    type Item = NonHardenedChildIndex;
    type IntoIter = NonHardenedChildIter;

    fn into_iter(self) -> Self::IntoIter {
        NonHardenedChildIter {
            next: Some(self.0.start),
            end: self.0.end,
        }
    }
}

/// A [BIP44] private key at the account path level `m/44'/<coin_type>'/<account>'`.
///
/// [BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[derive(Clone, Debug)]
#[cfg(feature = "transparent-inputs")]
pub struct AccountPrivKey(ExtendedPrivateKey<secp256k1::SecretKey>);

#[cfg(feature = "transparent-inputs")]
impl AccountPrivKey {
    /// Performs derivation of the extended private key for the BIP44 path:
    /// `m/44'/<coin_type>'/<account>'`.
    ///
    /// This produces the root of the derivation tree for transparent
    /// viewing keys and addresses for the provided account.
    pub fn from_seed<P: consensus::Parameters>(
        params: &P,
        seed: &[u8],
        account: AccountId,
    ) -> Result<AccountPrivKey, bip32::Error> {
        ExtendedPrivateKey::new(seed)?
            .derive_child(ChildNumber::new(44, true)?)?
            .derive_child(ChildNumber::new(params.coin_type(), true)?)?
            .derive_child(ChildNumber::new(account.into(), true)?)
            .map(AccountPrivKey)
    }

    pub fn from_extended_privkey(extprivkey: ExtendedPrivateKey<secp256k1::SecretKey>) -> Self {
        AccountPrivKey(extprivkey)
    }

    pub fn to_account_pubkey(&self) -> AccountPubKey {
        AccountPubKey(ExtendedPublicKey::from(&self.0))
    }

    /// Derives the BIP44 private spending key for the child path
    /// `m/44'/<coin_type>'/<account>'/<scope>/<address_index>`.
    pub fn derive_secret_key(
        &self,
        scope: TransparentKeyScope,
        address_index: NonHardenedChildIndex,
    ) -> Result<secp256k1::SecretKey, bip32::Error> {
        self.0
            .derive_child(scope.into())?
            .derive_child(address_index.into())
            .map(|k| *k.private_key())
    }

    /// Derives the BIP44 private spending key for the external (incoming payment) child path
    /// `m/44'/<coin_type>'/<account>'/0/<address_index>`.
    pub fn derive_external_secret_key(
        &self,
        address_index: NonHardenedChildIndex,
    ) -> Result<secp256k1::SecretKey, bip32::Error> {
        self.derive_secret_key(zip32::Scope::External.into(), address_index)
    }

    /// Derives the BIP44 private spending key for the internal (change) child path
    /// `m/44'/<coin_type>'/<account>'/1/<address_index>`.
    pub fn derive_internal_secret_key(
        &self,
        address_index: NonHardenedChildIndex,
    ) -> Result<secp256k1::SecretKey, bip32::Error> {
        self.derive_secret_key(zip32::Scope::Internal.into(), address_index)
    }

    /// Returns the `AccountPrivKey` serialized using the encoding for a
    /// [BIP 32](https://en.bitcoin.it/wiki/BIP_0032) ExtendedPrivateKey, excluding the
    /// 4 prefix bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Convert to `xprv` encoding.
        let xprv_encoded = self.0.to_extended_key(Prefix::XPRV).to_string();

        // Now decode it and return the bytes we want.
        bs58::decode(xprv_encoded)
            .with_check(None)
            .into_vec()
            .expect("correct")
            .split_off(Prefix::LENGTH)
    }

    /// Decodes the `AccountPrivKey` from the encoding specified for a
    /// [BIP 32](https://en.bitcoin.it/wiki/BIP_0032) ExtendedPrivateKey, excluding the
    /// 4 prefix bytes.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        // Convert to `xprv` encoding.
        let mut bytes = Prefix::XPRV.to_bytes().to_vec();
        bytes.extend_from_slice(b);
        let xprv_encoded = bs58::encode(bytes).with_check().into_string();

        // Now we can parse it.
        xprv_encoded
            .parse::<ExtendedKey>()
            .ok()
            .and_then(|k| ExtendedPrivateKey::try_from(k).ok())
            .map(AccountPrivKey::from_extended_privkey)
    }
}

/// A [BIP44] public key at the account path level `m/44'/<coin_type>'/<account>'`.
///
/// This provides the necessary derivation capability for the transparent component of a unified
/// full viewing key.
///
/// [BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Debug)]
pub struct AccountPubKey(ExtendedPublicKey<PublicKey>);

#[cfg(feature = "transparent-inputs")]
impl AccountPubKey {
    /// Derives the BIP44 public key at the external "change level" path
    /// `m/44'/<coin_type>'/<account>'/0`.
    pub fn derive_external_ivk(&self) -> Result<ExternalIvk, bip32::Error> {
        self.0
            .derive_child(ChildNumber::new(0, false)?)
            .map(ExternalIvk)
    }

    /// Derives the BIP44 public key at the internal "change level" path
    /// `m/44'/<coin_type>'/<account>'/1`.
    pub fn derive_internal_ivk(&self) -> Result<InternalIvk, bip32::Error> {
        self.0
            .derive_child(ChildNumber::new(1, false)?)
            .map(InternalIvk)
    }

    /// Derives the public key at the "ephemeral" path
    /// `m/44'/<coin_type>'/<account>'/2`.
    pub fn derive_ephemeral_ivk(&self) -> Result<EphemeralIvk, bip32::Error> {
        self.0
            .derive_child(ChildNumber::new(2, false)?)
            .map(EphemeralIvk)
    }

    /// Derives the BIP44 public key at the "address level" path corresponding to the given scope
    /// and address index.
    pub fn derive_address_pubkey(
        &self,
        scope: TransparentKeyScope,
        address_index: NonHardenedChildIndex,
    ) -> Result<secp256k1::PublicKey, bip32::Error> {
        Ok(*self
            .0
            .derive_child(scope.into())?
            .derive_child(address_index.into())?
            .public_key())
    }

    /// Derives the public key corresponding to the given full BIP 32 path.
    ///
    /// This enforces that the path has a prefix that could have been used to derive this
    /// `AccountPubKey`.
    pub fn derive_pubkey_at_bip32_path<P: consensus::Parameters>(
        &self,
        params: &P,
        expected_account_index: AccountId,
        path: &[ChildNumber],
    ) -> Result<secp256k1::PublicKey, bip32::Error> {
        if path.len() < 3 {
            Err(bip32::Error::ChildNumber)
        } else {
            match path.split_at(3) {
                ([purpose, coin_type, account_index], sub_path)
                    if purpose.is_hardened()
                        && purpose.index() == 44
                        && coin_type.is_hardened()
                        && coin_type.index() == params.network_type().coin_type()
                        && account_index.is_hardened()
                        && account_index.index() == expected_account_index.into() =>
                {
                    sub_path
                        .iter()
                        .try_fold(self.0.clone(), |acc, child_index| {
                            acc.derive_child(*child_index)
                        })
                        .map(|k| *k.public_key())
                }
                _ => Err(bip32::Error::ChildNumber),
            }
        }
    }

    /// Derives the internal ovk and external ovk corresponding to this
    /// transparent fvk. As specified in [ZIP 316][transparent-ovk].
    ///
    /// [transparent-ovk]: https://zips.z.cash/zip-0316#deriving-internal-keys
    pub fn ovks_for_shielding(&self) -> (InternalOvk, ExternalOvk) {
        let i_ovk = PrfExpand::TRANSPARENT_ZIP316_OVK
            .with(&self.0.attrs().chain_code, &self.0.public_key().serialize());
        let ovk_external = ExternalOvk(i_ovk[..32].try_into().unwrap());
        let ovk_internal = InternalOvk(i_ovk[32..].try_into().unwrap());

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
        let mut buf = self.0.attrs().chain_code.to_vec();
        buf.extend_from_slice(&self.0.public_key().serialize());
        buf
    }

    pub fn deserialize(data: &[u8; 65]) -> Result<Self, bip32::Error> {
        let chain_code = data[..32].try_into().expect("correct length");
        let public_key = PublicKey::from_slice(&data[32..])?;
        Ok(AccountPubKey(ExtendedPublicKey::new(
            public_key,
            ExtendedKeyAttrs {
                depth: 3,
                // We do not expose the inner `ExtendedPublicKey`, so we can use dummy
                // values for the fields that are not encoded in an `AccountPubKey`.
                parent_fingerprint: [0xff, 0xff, 0xff, 0xff],
                child_number: ChildNumber::new(0, true).expect("correct"),
                chain_code,
            },
        )))
    }
}

#[cfg(feature = "transparent-inputs")]
pub(crate) mod private {
    use super::TransparentKeyScope;
    use bip32::ExtendedPublicKey;
    use secp256k1::PublicKey;
    pub trait SealedChangeLevelKey {
        const SCOPE: TransparentKeyScope;
        fn extended_pubkey(&self) -> &ExtendedPublicKey<PublicKey>;
        fn from_extended_pubkey(key: ExtendedPublicKey<PublicKey>) -> Self;
    }
}

/// Trait representing a transparent "incoming viewing key".
///
/// Unlike the Sapling and Orchard shielded protocols (which have viewing keys built into
/// their key trees and bound to specific spending keys), the transparent protocol has no
/// "viewing key" concept. Transparent viewing keys are instead emulated by making two
/// observations:
///
/// - [BIP32] hierarchical derivation is structured as a tree.
/// - The [BIP44] key paths use non-hardened derivation below the account level.
///
/// A transparent viewing key for an account is thus defined as the root of a specific
/// non-hardened subtree underneath the account's path.
///
/// [BIP32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
/// [BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[cfg(feature = "transparent-inputs")]
pub trait IncomingViewingKey: private::SealedChangeLevelKey + core::marker::Sized {
    /// Derives a transparent address at the provided child index.
    #[allow(deprecated)]
    fn derive_address(
        &self,
        address_index: NonHardenedChildIndex,
    ) -> Result<TransparentAddress, bip32::Error> {
        let child_key = self.extended_pubkey().derive_child(address_index.into())?;
        Ok(TransparentAddress::from_pubkey(child_key.public_key()))
    }

    /// Searches the space of child indexes for an index that will
    /// generate a valid transparent address, and returns the resulting
    /// address and the index at which it was generated.
    fn default_address(&self) -> (TransparentAddress, NonHardenedChildIndex) {
        let mut address_index = NonHardenedChildIndex::ZERO;
        loop {
            match self.derive_address(address_index) {
                Ok(addr) => {
                    return (addr, address_index);
                }
                Err(_) => {
                    address_index = address_index.next().unwrap_or_else(|| {
                        panic!("Exhausted child index space attempting to find a default address.");
                    });
                }
            }
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let extpubkey = self.extended_pubkey();
        let mut buf = extpubkey.attrs().chain_code.to_vec();
        buf.extend_from_slice(&extpubkey.public_key().serialize());
        buf
    }

    fn deserialize(data: &[u8; 65]) -> Result<Self, bip32::Error> {
        let chain_code = data[..32].try_into().expect("correct length");
        let public_key = PublicKey::from_slice(&data[32..])?;
        Ok(Self::from_extended_pubkey(ExtendedPublicKey::new(
            public_key,
            ExtendedKeyAttrs {
                depth: 4,
                // We do not expose the inner `ExtendedPublicKey`, so we can use a dummy
                // value for the `parent_fingerprint` that is not encoded in an
                // `IncomingViewingKey`.
                parent_fingerprint: [0xff, 0xff, 0xff, 0xff],
                child_number: Self::SCOPE.into(),
                chain_code,
            },
        )))
    }
}

/// An incoming viewing key at the [BIP44] "external" path
/// `m/44'/<coin_type>'/<account>'/0`.
///
/// This allows derivation of child addresses that may be provided to external parties.
///
/// [BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Debug)]
pub struct ExternalIvk(ExtendedPublicKey<PublicKey>);

#[cfg(feature = "transparent-inputs")]
impl private::SealedChangeLevelKey for ExternalIvk {
    const SCOPE: TransparentKeyScope = TransparentKeyScope(0);

    fn extended_pubkey(&self) -> &ExtendedPublicKey<PublicKey> {
        &self.0
    }

    fn from_extended_pubkey(key: ExtendedPublicKey<PublicKey>) -> Self {
        ExternalIvk(key)
    }
}

#[cfg(feature = "transparent-inputs")]
impl IncomingViewingKey for ExternalIvk {}

/// An incoming viewing key at the [BIP44] "internal" path
/// `m/44'/<coin_type>'/<account>'/1`.
///
/// This allows derivation of change addresses for use within the wallet, but which should
/// not be shared with external parties.
///
/// [BIP44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Debug)]
pub struct InternalIvk(ExtendedPublicKey<PublicKey>);

#[cfg(feature = "transparent-inputs")]
impl private::SealedChangeLevelKey for InternalIvk {
    const SCOPE: TransparentKeyScope = TransparentKeyScope(1);

    fn extended_pubkey(&self) -> &ExtendedPublicKey<PublicKey> {
        &self.0
    }

    fn from_extended_pubkey(key: ExtendedPublicKey<PublicKey>) -> Self {
        InternalIvk(key)
    }
}

#[cfg(feature = "transparent-inputs")]
impl IncomingViewingKey for InternalIvk {}

/// An incoming viewing key at the "ephemeral" path
/// `m/44'/<coin_type>'/<account>'/2`.
///
/// This allows derivation of ephemeral addresses for use within the wallet.
#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Debug)]
pub struct EphemeralIvk(ExtendedPublicKey<PublicKey>);

#[cfg(feature = "transparent-inputs")]
impl EphemeralIvk {
    /// Derives a transparent address at the provided child index.
    pub fn derive_ephemeral_address(
        &self,
        address_index: NonHardenedChildIndex,
    ) -> Result<TransparentAddress, bip32::Error> {
        let child_key = self.0.derive_child(address_index.into())?;
        #[allow(deprecated)]
        Ok(TransparentAddress::from_pubkey(child_key.public_key()))
    }
}

/// Internal outgoing viewing key used for autoshielding.
pub struct InternalOvk([u8; 32]);

impl InternalOvk {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// External outgoing viewing key used by `zcashd` for transparent-to-shielded spends to
/// external receivers.
pub struct ExternalOvk([u8; 32]);

impl ExternalOvk {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use bip32::ChildNumber;
    use subtle::ConstantTimeEq;
    use zcash_protocol::consensus::{MAIN_NETWORK, NetworkConstants};

    use super::AccountPubKey;
    use super::NonHardenedChildIndex;
    #[allow(deprecated)]
    use crate::{
        address::TransparentAddress,
        keys::{AccountPrivKey, IncomingViewingKey, TransparentKeyScope},
        test_vectors,
    };

    #[test]
    #[allow(deprecated)]
    fn address_derivation() {
        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        for account_index in 0..5 {
            let account_index = zip32::AccountId::try_from(account_index).unwrap();
            let account_sk =
                AccountPrivKey::from_seed(&MAIN_NETWORK, &seed, account_index).unwrap();
            let account_pubkey = account_sk.to_account_pubkey();

            let external_ivk = account_pubkey.derive_external_ivk().unwrap();
            let (address, address_index) = external_ivk.default_address();

            let address_pubkey = account_pubkey
                .derive_address_pubkey(TransparentKeyScope::EXTERNAL, address_index)
                .unwrap();
            #[cfg(feature = "transparent-inputs")]
            assert_eq!(TransparentAddress::from_pubkey(&address_pubkey), address);

            let expected_path = [
                ChildNumber::new(44, true).unwrap(),
                ChildNumber::new(MAIN_NETWORK.coin_type(), true).unwrap(),
                ChildNumber::new(account_index.into(), true).unwrap(),
                TransparentKeyScope::EXTERNAL.into(),
                address_index.into(),
            ];

            // For short paths, we get an error.
            for i in 0..3 {
                assert_eq!(
                    account_pubkey.derive_pubkey_at_bip32_path(
                        &MAIN_NETWORK,
                        account_index,
                        &expected_path[..i]
                    ),
                    Err(bip32::Error::ChildNumber),
                );
            }

            // The truncated-by-one path gives the external IVK.
            assert_eq!(
                account_pubkey.derive_pubkey_at_bip32_path(
                    &MAIN_NETWORK,
                    account_index,
                    &expected_path[..4],
                ),
                Ok(*external_ivk.0.public_key()),
            );

            // The full path gives the correct pubkey.
            assert_eq!(
                account_pubkey.derive_pubkey_at_bip32_path(
                    &MAIN_NETWORK,
                    account_index,
                    &expected_path,
                ),
                Ok(address_pubkey),
            );
        }
    }

    #[test]
    #[allow(deprecated)]
    fn bip_32_test_vectors() {
        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        for tv in test_vectors::bip_32() {
            let account_sk = AccountPrivKey::from_seed(
                &MAIN_NETWORK,
                &seed,
                zip32::AccountId::try_from(tv.account).unwrap(),
            )
            .unwrap();
            let account_pubkey = account_sk.to_account_pubkey();

            let mut key_bytes = [0u8; 65];
            key_bytes[..32].copy_from_slice(&tv.c);
            key_bytes[32..].copy_from_slice(&tv.pk);
            assert_eq!(account_pubkey.serialize(), key_bytes);

            let (internal_ovk, external_ovk) = account_pubkey.ovks_for_shielding();
            assert_eq!(internal_ovk.as_bytes(), tv.internal_ovk);
            assert_eq!(external_ovk.as_bytes(), tv.external_ovk);

            // The test vectors are broken here: they should be deriving an address at the
            // address level, but instead use the account pubkey as an address.
            let address = TransparentAddress::PublicKeyHash(tv.address);

            #[cfg(feature = "transparent-inputs")]
            assert_eq!(
                TransparentAddress::from_pubkey(account_pubkey.0.public_key()),
                address
            );
        }
    }

    #[test]
    fn check_ovk_test_vectors() {
        for tv in test_vectors::transparent_ovk() {
            let mut key_bytes = [0u8; 65];
            key_bytes[..32].copy_from_slice(&tv.c);
            key_bytes[32..].copy_from_slice(&tv.pk);
            let account_key = AccountPubKey::deserialize(&key_bytes).unwrap();

            let (internal, external) = account_key.ovks_for_shielding();

            assert_eq!(tv.internal_ovk, internal.as_bytes());
            assert_eq!(tv.external_ovk, external.as_bytes());
        }
    }

    #[test]
    fn nonhardened_indexes_accepted() {
        assert_eq!(0, NonHardenedChildIndex::from_index(0).unwrap().index());
        assert_eq!(
            0x7fffffff,
            NonHardenedChildIndex::from_index(0x7fffffff)
                .unwrap()
                .index()
        );
    }

    #[test]
    fn hardened_indexes_rejected() {
        assert!(NonHardenedChildIndex::from_index(0x80000000).is_none());
        assert!(NonHardenedChildIndex::from_index(0xffffffff).is_none());
    }

    #[test]
    fn nonhardened_index_next() {
        assert_eq!(1, NonHardenedChildIndex::ZERO.next().unwrap().index());
        assert!(
            NonHardenedChildIndex::from_index(0x7fffffff)
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn nonhardened_index_ct_eq() {
        assert!(check(
            NonHardenedChildIndex::ZERO,
            NonHardenedChildIndex::ZERO
        ));
        assert!(!check(
            NonHardenedChildIndex::ZERO,
            NonHardenedChildIndex::ZERO.next().unwrap()
        ));

        fn check<T: ConstantTimeEq>(v1: T, v2: T) -> bool {
            v1.ct_eq(&v2).into()
        }
    }

    #[test]
    fn nonhardened_index_tryfrom_keyindex() {
        let nh: NonHardenedChildIndex = ChildNumber::new(0, false).unwrap().try_into().unwrap();
        assert_eq!(nh.index(), 0);

        assert!(NonHardenedChildIndex::try_from(ChildNumber::new(0, true).unwrap()).is_err());
    }
}
