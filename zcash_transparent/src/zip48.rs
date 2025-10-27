use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bip32::{ChildNumber, ExtendedPrivateKey, ExtendedPublicKey, Prefix};
use secp256k1::{PublicKey, SecretKey};
use zcash_protocol::consensus::{self, NetworkConstants};
use zcash_script::{
    descriptor::{self, KeyExpression, KeyOrigin, sh, sortedmulti},
    script,
};
use zip32::AccountId;

use crate::{
    address::TransparentAddress,
    keys::{NonHardenedChildIndex, TransparentKeyScope},
};

const BIP_48_PURPOSE: fn() -> ChildNumber = || ChildNumber::new(48, true).expect("valid");
const ZCASH_P2SH_SCRIPT_TYPE: fn() -> ChildNumber =
    || ChildNumber::new(133000, true).expect("valid");

fn pub_prefix<P: consensus::Parameters>(params: &P) -> Prefix {
    match params.network_type() {
        consensus::NetworkType::Main => Prefix::XPUB,
        consensus::NetworkType::Test => Prefix::TPUB,
        consensus::NetworkType::Regtest => Prefix::TPUB,
    }
}

/// A [ZIP 48] private key at the P2SH level `m/48'/<coin_type>'/<account>'/133000'`.
///
/// [ZIP 48]: https://zips.z.cash/zip-0048
#[derive(Clone, Debug)]
pub struct AccountPrivKey {
    origin: KeyOrigin,
    key: ExtendedPrivateKey<SecretKey>,
}

impl AccountPrivKey {
    /// Performs derivation of the extended private key for the ZIP 48 path:
    /// `m/48'/<coin_type>'/<account>'/133000'`.
    pub fn from_seed<P: consensus::Parameters>(
        params: &P,
        seed: &[u8],
        account: AccountId,
    ) -> Result<AccountPrivKey, bip32::Error> {
        let root = ExtendedPrivateKey::new(seed)?;
        let fingerprint = root.public_key().fingerprint();
        let derivation = vec![
            BIP_48_PURPOSE(),
            ChildNumber::new(params.coin_type(), true)?,
            ChildNumber::new(account.into(), true)?,
            ZCASH_P2SH_SCRIPT_TYPE(),
        ];

        let key = derivation
            .iter()
            .try_fold(root, |key, child_number| key.derive_child(*child_number))?;

        Ok(AccountPrivKey {
            origin: KeyOrigin::from_parts(fingerprint, derivation),
            key,
        })
    }

    /// Returns the public key corresponding to this private key.
    ///
    /// This is the public key that will be added to the key information vector for the
    /// corresponding [BIP 388] wallet policy.
    ///
    /// [BIP 388]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki
    pub fn to_account_pubkey(&self) -> AccountPubKey {
        AccountPubKey {
            origin: self.origin.clone(),
            key: ExtendedPublicKey::from(&self.key),
        }
    }

    /// Derives the signing key for this account's scoped address at the given index.
    pub fn derive_signing_key(
        &self,
        scope: zip32::Scope,
        address_index: NonHardenedChildIndex,
    ) -> SecretKey {
        *self
            .key
            .derive_child(TransparentKeyScope::from(scope).into())
            .expect("chance of failure is around 2^-127")
            .derive_child(address_index.into())
            .expect("chance of failure is around 2^-127")
            .private_key()
    }
}

/// A [ZIP 48] public key at the P2SH level `m/48'/<coin_type>'/<account>'/133000'`.
///
/// This provides the necessary derivation capability for a participant in a P2SH multisig
/// account.
///
/// [ZIP 48]: https://zips.z.cash/zip-0048
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPubKey {
    origin: KeyOrigin,
    key: ExtendedPublicKey<PublicKey>,
}

impl AccountPubKey {
    /// Attempts to parse a [BIP 388 `KEY_INFO` expression] as a ZIP 48 public key.
    ///
    /// Returns `None` if:
    /// - the string is not a valid `KEY_INFO` expresson.
    /// - the expression has no [`KeyOrigin`].
    /// - the key origin does not match ZIP 48.
    /// - the key is for the wrong network.
    ///
    /// [BIP 388 `KEY_INFO` expression]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki#key-information-vector
    pub fn parse_key_info_expression<P: consensus::Parameters>(
        s: &str,
        params: &P,
    ) -> Option<Self> {
        match s.parse::<KeyExpression>().ok()?.into_parts() {
            (Some(origin), descriptor::Key::Xpub { prefix, key, child })
                if prefix == pub_prefix(params) && child.is_empty() =>
            {
                // Verify that this `KEY_INFO` expression is for ZIP 48.
                match origin.derivation() {
                    [purpose, coin_type, account, script_type]
                        if purpose == &BIP_48_PURPOSE()
                            && coin_type.index() == params.coin_type()
                            && coin_type.is_hardened()
                            && account.is_hardened()
                            && script_type == &ZCASH_P2SH_SCRIPT_TYPE() =>
                    {
                        Some(Self { origin, key })
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Encodes this public key as a [BIP 388 `KEY_INFO` expression].
    ///
    /// [BIP 388 `KEY_INFO` expression]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki#key-information-vector
    pub fn key_info_expression<P: consensus::Parameters>(&self, params: &P) -> String {
        self.key_expression_inner(pub_prefix(params), vec![])
            .to_string()
    }

    /// Produces a [`KeyExpression`] from this public key corresponding to a specific
    /// address.
    pub fn key_expression_for_address(
        &self,
        prefix: Prefix,
        scope: zip32::Scope,
        address_index: NonHardenedChildIndex,
    ) -> KeyExpression {
        self.key_expression_inner(
            prefix,
            vec![
                TransparentKeyScope::from(scope).into(),
                address_index.into(),
            ],
        )
    }

    fn key_expression_inner(
        &self,
        prefix: Prefix,
        child: Vec<bip32::ChildNumber>,
    ) -> KeyExpression {
        KeyExpression::from_xpub(Some(self.origin.clone()), prefix, self.key.clone(), child)
            .expect("correct by construction")
    }
}

/// A [ZIP 48] P2SH multisig full viewing key.
///
/// This provides the necessary derivation capability to view all funds controlled by a
/// P2SH multisig account.
///
/// [ZIP 48]: https://zips.z.cash/zip-0048
pub struct FullViewingKey {
    threshold: u8,
    key_info: Vec<AccountPubKey>,
}

impl FullViewingKey {
    /// Constructs a full viewing key for a standard ZIP 48 account.
    ///
    /// This uses the standard wallet descriptor template. For example:
    /// - `threshold == 2`
    /// - `key_info.len() == 3`
    /// - Wallet descriptor template: `"sh(sortedmulti(2,@0/**,@1/**,@2/**))"`
    pub fn standard(
        threshold: u8,
        key_info: Vec<AccountPubKey>,
    ) -> Result<Self, FullViewingKeyError> {
        if key_info.is_empty() {
            Err(FullViewingKeyError::NoPubKeys)
        } else if key_info.len() > 15 {
            Err(FullViewingKeyError::TooManyPubKeys)
        } else if usize::from(threshold) > key_info.len() {
            Err(FullViewingKeyError::InvalidThreshold)
        } else {
            // Verify `key_info` in a scope so we can borrow from it.
            {
                // To be compatible with ZIP 48, all keys must have the same derivation
                // information. We check this by collecting into a set, and then checking
                // it contains one entry. We don't need to verify the derivation's
                // structure because `AccountPubKey` enforces it by construction.
                let derivations = key_info
                    .iter()
                    .map(|key| key.origin.derivation())
                    .collect::<BTreeSet<_>>();
                if derivations.len() != 1 {
                    return Err(FullViewingKeyError::IncompatiblePubKeys);
                }
            }

            // TODO: Decide whether `key_info` should be sorted (or checked to be sorted)
            // to ensure a canonical multipath descriptor.
            Ok(Self {
                threshold,
                key_info,
            })
        }
    }

    /// Returns the [BIP 388 wallet descriptor template] for this full viewing key.
    ///
    /// [BIP 388 wallet descriptor template]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki#wallet-descriptor-template
    pub fn wallet_descriptor_template(&self) -> String {
        self.standard_descriptor(|i, _| format!("@{i}/**"))
    }

    /// Returns the [BIP 389] multipath descriptor for this full viewing key.
    ///
    /// [BIP 389]: https://github.com/bitcoin/bips/blob/master/bip-0389.mediawiki
    pub fn multipath_descriptor<P: consensus::Parameters>(&self, params: &P) -> String {
        self.standard_descriptor(|_, key| format!("{}/<0;1>/*", key.key_info_expression(params)))
    }

    /// Because the only constructor for `FullViewingKey` forces a specific wallet
    /// descriptor template, we can fix it here.
    fn standard_descriptor(&self, key_encoder: impl Fn(usize, &AccountPubKey) -> String) -> String {
        let mut t = format!("sh(sortedmulti({}", self.threshold);
        for (i, key) in self.key_info.iter().enumerate() {
            t.push(',');
            t.push_str(&key_encoder(i, key));
        }
        t.push_str("))");
        t
    }

    /// Derives the scoped P2SH address for this account at the given index, along with
    /// the corresponding redeem script.
    pub fn derive_address(
        &self,
        scope: zip32::Scope,
        address_index: NonHardenedChildIndex,
    ) -> (TransparentAddress, script::Redeem) {
        // Produce the key expressions corresponding to the desired address.
        let keys = self
            .key_info
            .iter()
            .map(|pubkey| {
                pubkey.key_expression_for_address(
                    // Prefix doesn't matter, we aren't serializing the key expressions.
                    Prefix::XPUB,
                    scope,
                    address_index,
                )
            })
            .collect::<Vec<_>>();

        // Derive the P2SH script for the desired address. Because the only constructor
        // for `FullViewingKey` forces a specific wallet descriptor template, we can
        // fix it here.
        let redeem_script = sortedmulti(self.threshold, &keys)
            .expect("child numbers are non-hardened, chance of failure is around 2^-127");
        let script_pubkey = sh(&redeem_script);

        // Extract the address from the script.
        let addr = TransparentAddress::from_script_pubkey(&script_pubkey).expect("valid");

        (addr, redeem_script)
    }
}

/// Errors that can occur while constructing a [`FullViewingKey`].
#[derive(Clone, Debug)]
pub enum FullViewingKeyError {
    /// No pubkeys were provided.
    NoPubKeys,
    /// The script for a standard [`FullViewingKey`] can contain at most 15 pubkeys.
    TooManyPubKeys,
    /// The provided threshold was larger than the number of pubkeys.
    InvalidThreshold,
    /// The pubkeys were not all derived following ZIP 48.
    IncompatiblePubKeys,
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use bip32::Prefix;
    use zcash_protocol::consensus::{MainNetwork, Network, Parameters};
    use zip32::AccountId;

    use crate::{
        keys::NonHardenedChildIndex,
        test_vectors::zip_0048::TEST_VECTORS,
        zip48::{AccountPrivKey, AccountPubKey, FullViewingKey},
    };

    #[test]
    fn zip_48_example() {
        let params = MainNetwork;
        let seeds = [[1; 32], [2; 32], [3; 32]];

        let key_info = seeds
            .iter()
            .map(|seed| {
                AccountPrivKey::from_seed(&params, seed, AccountId::ZERO)
                    .unwrap()
                    .to_account_pubkey()
            })
            .collect();

        let fvk = FullViewingKey::standard(2, key_info).unwrap();

        assert_eq!(
            fvk.wallet_descriptor_template(),
            "sh(sortedmulti(2,@0/**,@1/**,@2/**))",
        );
        assert_eq!(
            fvk.multipath_descriptor(&params),
            "sh(sortedmulti(2,[4ba43603/48'/133'/0'/133000']xpub6E96VHgq8MKkYGuNLDjxLxH3LH93NGJX5xSufVjnh7zM8bKehGr3iekJLyc8WJiMemYWuXLPKwygt3j9nfJCapPkYRfCc5YFvzb3aMLsQdV/<0;1>/*,[8dfc9b34/48'/133'/0'/133000']xpub6EuQaJQHwbf2mbyHoYcyjcj9ByB8EeKp4zSKTT9EdxfaQJDgou3SR3oYtP7AYoHQtEUsnsjgdZD8n7c7G4Pv4iXMt98sCvdWNXs1bvhEu29/<0;1>/*,[56c4fac3/48'/133'/0'/133000']xpub6EVJBC6rV3qaNwfK3ChbjpEHnqhymSLmvqB1rKu7sRPH7szS9f4jDAiPyAF7PbnRH512uHhT4te6EJppbCWURtDKbiygGWphd5ej21oNqAx/<0;1>/*))",
        );
        for (i, addr) in [
            (0, "t3gDnw36YBC6SSmccqJYCsq6xtzGXamGxKd"),
            (1, "t3Tb7JHhVdVJ3vQPpji6pAHbFazTgVHhJZC"),
            (2, "t3gXpirdnRUdsXaeeMjMpTcXVFigQst5ekR"),
        ] {
            assert_eq!(
                fvk.derive_address(
                    zip32::Scope::External,
                    NonHardenedChildIndex::const_from_index(i)
                )
                .0
                .to_zcash_address(params.network_type())
                .to_string(),
                addr,
            );
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_vectors() {
        let seeds = (0..16)
            .map(|i| {
                [
                    i, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                    0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                    0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                ]
            })
            .collect::<Vec<_>>();

        for tv in TEST_VECTORS {
            let (params, xprv_prefix, xpub_prefix) = match tv.network {
                "mainnet" => (Network::MainNetwork, Prefix::XPRV, Prefix::XPUB),
                "testnet" => (Network::TestNetwork, Prefix::TPRV, Prefix::TPUB),
                _ => unreachable!(),
            };

            let privkeys = (0..tv.key_information_vector.len())
                .zip(&seeds)
                .map(|(_, seed)| {
                    AccountPrivKey::from_seed(
                        &params,
                        seed,
                        zip32::AccountId::try_from(tv.account).unwrap(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();

            for (actual, expected) in privkeys.iter().zip(tv.xprv_keys) {
                assert_eq!(actual.key.to_string(xprv_prefix).as_str(), *expected);
            }

            let key_info = privkeys
                .iter()
                .map(|privkey| privkey.to_account_pubkey())
                .collect::<Vec<_>>();

            for (actual, expected) in key_info.iter().zip(tv.xpub_keys) {
                assert_eq!(actual.key.to_string(xpub_prefix).as_str(), *expected);
            }

            let fvk = FullViewingKey::standard(tv.required, key_info).unwrap();

            assert_eq!(
                fvk.wallet_descriptor_template(),
                tv.wallet_descriptor_template,
            );

            for (key, expected) in fvk.key_info.iter().zip(tv.key_information_vector) {
                assert_eq!(
                    AccountPubKey::parse_key_info_expression(expected, &params).as_ref(),
                    Some(key),
                );
                assert_eq!(&key.key_info_expression(&params), expected);
            }

            for (i, address) in tv.external_addresses {
                assert_eq!(
                    &fvk.derive_address(
                        zip32::Scope::External,
                        NonHardenedChildIndex::const_from_index(*i)
                    )
                    .0
                    .to_zcash_address(params.network_type())
                    .to_string(),
                    address,
                )
            }

            for (i, address) in tv.change_addresses {
                assert_eq!(
                    &fvk.derive_address(
                        zip32::Scope::Internal,
                        NonHardenedChildIndex::const_from_index(*i)
                    )
                    .0
                    .to_zcash_address(params.network_type())
                    .to_string(),
                    address,
                )
            }
        }
    }
}
