use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::num::NonZeroU8;

use bip32::{ChildNumber, ExtendedKeyAttrs, ExtendedPrivateKey, ExtendedPublicKey, Prefix};
use nonempty::NonEmpty;
use secp256k1::{PublicKey, SecretKey};
use zcash_encoding::CompactSize;
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
#[derive(Clone)]
pub struct AccountPrivKey {
    origin: KeyOrigin,
    key: ExtendedPrivateKey<SecretKey>,
}

impl core::fmt::Debug for AccountPrivKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountPrivKey")
            .field("origin", &self.origin)
            .field("key", &"...")
            .finish()
    }
}

impl AccountPrivKey {
    /// Performs derivation of the extended private key for the ZIP 48 path:
    /// `m/48'/<coin_type>'/<account>'/133000'`.
    pub fn from_seed<P: consensus::Parameters>(
        params: &P,
        seed: &[u8],
        account: AccountId,
    ) -> Result<AccountPrivKey, bip32::Error> {
        Self::from_seed_with_coin_type(seed, params.coin_type(), account)
    }

    /// Internal helper constructor that doesn't depend on [`consensus::Parameters`].
    fn from_seed_with_coin_type(
        seed: &[u8],
        coin_type: u32,
        account: AccountId,
    ) -> Result<AccountPrivKey, bip32::Error> {
        let root = ExtendedPrivateKey::new(seed)?;
        let fingerprint = root.public_key().fingerprint();
        let derivation = vec![
            BIP_48_PURPOSE(),
            ChildNumber::new(coin_type, true)?,
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
            key: self.key.public_key(),
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

    /// Returns the ZIP 48 coin type and account ID for this public key.
    fn coin_type_and_account(&self) -> (u32, AccountId) {
        // By construction, the derivation is always a ZIP 48 path.
        let derivation = self.origin.derivation();
        (
            derivation
                .get(1)
                .expect("valid ZIP 48 derivation path")
                .index(),
            AccountId::try_from(
                derivation
                    .get(2)
                    .expect("valid ZIP 48 derivation path")
                    .index(),
            )
            .expect("valid"),
        )
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
    threshold: NonZeroU8,
    key_info: NonEmpty<AccountPubKey>,
}

impl FullViewingKey {
    /// Constructs a full viewing key for a standard ZIP 48 account.
    ///
    /// This uses the standard wallet descriptor template. For example:
    /// - `threshold == 2`
    /// - `key_info.len() == 3`
    /// - Wallet descriptor template: `"sh(sortedmulti(2,@0/**,@1/**,@2/**))"`
    pub fn standard(
        threshold: NonZeroU8,
        key_info: Vec<AccountPubKey>,
    ) -> Result<Self, FullViewingKeyError> {
        let key_info = NonEmpty::from_vec(key_info).ok_or(FullViewingKeyError::NoPubKeys)?;
        if key_info.len() > 15 {
            Err(FullViewingKeyError::TooManyPubKeys)
        } else if usize::from(threshold.get()) > key_info.len() {
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

    /// Returns the ZIP 48 coin type and account ID for this full viewing key.
    fn coin_type_and_account(&self) -> (u32, AccountId) {
        // By construction of `Self`, all keys in `key_info` have the same derivation
        // information, so we only need to look at the first.
        self.key_info.first().coin_type_and_account()
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

    /// Derives the [`AccountPrivKey`] from the given seed that matches this full viewing
    /// key.
    ///
    /// Returns `Ok(None)` if the given seed does not match any of the public keys.
    pub fn derive_matching_account_priv_key(
        &self,
        seed: &[u8],
    ) -> Result<Option<AccountPrivKey>, bip32::Error> {
        let (coin_type, account) = self.coin_type_and_account();
        let candiate_privkey = AccountPrivKey::from_seed_with_coin_type(seed, coin_type, account)?;
        let candiate_pubkey = candiate_privkey.to_account_pubkey();

        for key in &self.key_info {
            if key == &candiate_pubkey {
                return Ok(Some(candiate_privkey));
            }
        }

        // Nothing matched.
        Ok(None)
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
        let redeem_script = sortedmulti(self.threshold.get(), &keys)
            .expect("child numbers are non-hardened, chance of failure is around 2^-127");
        let script_pubkey = sh(&redeem_script);

        // Extract the address from the script.
        let addr = TransparentAddress::from_script_pubkey(&script_pubkey).expect("valid");

        (addr, redeem_script)
    }
}

/// The encoded length of one [`P2shKey`]: a 32-byte BIP 32 chain code followed by a
/// 33-byte SEC1 compressed public key.
const P2SH_KEY_ENCODING_LEN: usize = 65;

/// The multipath notation a key placeholder carries in a full viewing key item, which
/// derives both external and internal addresses.
const FVK_MULTIPATH: &str = "/**";

/// The multipath notation a key placeholder carries in an incoming viewing key item,
/// which derives external addresses only.
const IVK_MULTIPATH: &str = "/*";

/// The largest number of keys the standard descriptor template can carry, bounded by the
/// small integer opcodes the resulting script uses.
const MAX_KEYS: usize = 15;

/// A key of the key information vector of a [ZIP 316] Revision 2 P2SH viewing key item.
///
/// The item encoding carries a BIP 32 chain code and compressed public key, and no key
/// origin information, so an entry does not identify its own derivation path.
///
/// [ZIP 316]: https://zips.z.cash/zip-0316
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2shKey {
    chain_code: [u8; 32],
    public_key: PublicKey,
}

impl P2shKey {
    /// Constructs a key information vector entry from its parts.
    pub fn new(chain_code: [u8; 32], public_key: PublicKey) -> Self {
        Self {
            chain_code,
            public_key,
        }
    }

    /// Returns the BIP 32 chain code of this entry.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Returns the public key of this entry.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Parses a key information vector entry.
    ///
    /// Returns an error if the entry does not encode a valid compressed public key.
    pub fn from_bytes(data: &[u8; P2SH_KEY_ENCODING_LEN]) -> Result<Self, bip32::Error> {
        Ok(Self {
            chain_code: data[..32].try_into().expect("correct length"),
            public_key: PublicKey::from_slice(&data[32..])?,
        })
    }

    /// Returns the encoding of this entry.
    pub fn to_bytes(&self) -> [u8; P2SH_KEY_ENCODING_LEN] {
        let mut data = [0; P2SH_KEY_ENCODING_LEN];
        data[..32].copy_from_slice(&self.chain_code);
        data[32..].copy_from_slice(&self.public_key.serialize());
        data
    }

    fn extended_pubkey(&self) -> ExtendedPublicKey<PublicKey> {
        ExtendedPublicKey::new(
            self.public_key,
            ExtendedKeyAttrs {
                depth: 3,
                // The entry encoding carries neither of these, and this key is never
                // serialized as an extended key, so dummy values suffice.
                parent_fingerprint: [0xff, 0xff, 0xff, 0xff],
                child_number: ChildNumber::new(0, true).expect("valid"),
                chain_code: self.chain_code,
            },
        )
    }

    /// Derives the non-hardened child of this key at the given index.
    pub fn derive_child(&self, index: NonHardenedChildIndex) -> Result<Self, bip32::Error> {
        let child = self.extended_pubkey().derive_child(index.into())?;
        Ok(Self {
            chain_code: child.attrs().chain_code,
            public_key: *child.public_key(),
        })
    }

    fn key_expression(&self, child: Vec<ChildNumber>) -> KeyExpression {
        // Neither the prefix nor the absent origin is serialized: the expression exists
        // only to evaluate the descriptor to a script.
        KeyExpression::from_xpub(None, Prefix::XPUB, self.extended_pubkey(), child)
            .expect("correct by construction")
    }
}

impl Ord for P2shKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // ZIP 316 requires the key information vector of an item to be ordered
        // lexicographically by chain code and then public key, which is the order of the
        // entry encoding.
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl PartialOrd for P2shKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Renders the standard ZIP 48 descriptor template for the given shape.
fn render_template(threshold: NonZeroU8, n_keys: usize, multipath: &str) -> String {
    let mut t = format!("sh(sortedmulti({threshold}");
    for i in 0..n_keys {
        t.push(',');
        t.push_str(&format!("@{i}{multipath}"));
    }
    t.push_str("))");
    t
}

/// Checks the invariants shared by both viewing key item forms.
fn check_shape(
    threshold: NonZeroU8,
    key_info: Vec<P2shKey>,
) -> Result<(NonZeroU8, NonEmpty<P2shKey>), P2shViewingKeyError> {
    let key_info = NonEmpty::from_vec(key_info).ok_or(P2shViewingKeyError::NoPubKeys)?;
    if key_info.len() > MAX_KEYS {
        Err(P2shViewingKeyError::TooManyPubKeys)
    } else if usize::from(threshold.get()) > key_info.len() {
        Err(P2shViewingKeyError::InvalidThreshold)
    } else {
        Ok((threshold, key_info))
    }
}

/// Parses a P2SH viewing key item, requiring the standard template for `multipath`.
fn parse_item(
    bytes: &[u8],
    multipath: &str,
) -> Result<(NonZeroU8, NonEmpty<P2shKey>), P2shViewingKeyError> {
    let mut cursor = corez::io::Cursor::new(bytes);
    let template_len = CompactSize::read(&mut cursor)
        .ok()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(P2shViewingKeyError::Malformed)?;
    let template_start = usize::try_from(cursor.position()).expect("cursor fits in usize");
    let template_end = template_start
        .checked_add(template_len)
        .filter(|end| *end <= bytes.len())
        .ok_or(P2shViewingKeyError::Malformed)?;
    let template = core::str::from_utf8(&bytes[template_start..template_end])
        .map_err(|_| P2shViewingKeyError::Malformed)?;
    cursor.set_position(template_end as u64);

    let n_keys = CompactSize::read(&mut cursor)
        .ok()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(P2shViewingKeyError::Malformed)?;
    let keys_start = usize::try_from(cursor.position()).expect("cursor fits in usize");
    if n_keys
        .checked_mul(P2SH_KEY_ENCODING_LEN)
        .and_then(|len| keys_start.checked_add(len))
        != Some(bytes.len())
    {
        return Err(P2shViewingKeyError::Malformed);
    }

    let mut key_info = Vec::with_capacity(n_keys);
    for i in 0..n_keys {
        let entry: [u8; P2SH_KEY_ENCODING_LEN] = bytes
            [keys_start + i * P2SH_KEY_ENCODING_LEN..keys_start + (i + 1) * P2SH_KEY_ENCODING_LEN]
            .try_into()
            .expect("length checked above");
        key_info.push(P2shKey::from_bytes(&entry).map_err(P2shViewingKeyError::InvalidKey)?);
    }

    let threshold = parse_threshold(template).ok_or(P2shViewingKeyError::UnsupportedTemplate)?;
    let (threshold, key_info) = check_shape(threshold, key_info)?;

    // The template is rendered canonically on encoding, so only a template that is
    // already canonical can round-trip unchanged.
    if template != render_template(threshold, key_info.len(), multipath) {
        return Err(P2shViewingKeyError::UnsupportedTemplate);
    }

    Ok((threshold, key_info))
}

/// Extracts the multisig threshold from a standard descriptor template.
fn parse_threshold(template: &str) -> Option<NonZeroU8> {
    template
        .strip_prefix("sh(sortedmulti(")?
        .split(',')
        .next()?
        .parse()
        .ok()
}

/// Writes the canonical encoding of a P2SH viewing key item.
fn write_item<W: corez::io::Write>(
    threshold: NonZeroU8,
    key_info: &NonEmpty<P2shKey>,
    multipath: &str,
    mut writer: W,
) -> corez::io::Result<()> {
    let template = render_template(threshold, key_info.len(), multipath);
    CompactSize::write(&mut writer, template.len())?;
    writer.write_all(template.as_bytes())?;
    CompactSize::write(&mut writer, key_info.len())?;
    for key in key_info.iter() {
        writer.write_all(&key.to_bytes())?;
    }
    Ok(())
}

/// A [ZIP 316] Revision 2 P2SH viewing key item, in full viewing key form.
///
/// The item encodes a [BIP 388] wallet policy: a descriptor template together with the
/// key information vector its `@N` placeholders refer to. Only the standard ZIP 48
/// template is representable, so the descriptor of a value of this type is always one
/// this crate can evaluate.
///
/// [ZIP 316]: https://zips.z.cash/zip-0316
/// [BIP 388]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2shFullViewingKey {
    threshold: NonZeroU8,
    key_info: NonEmpty<P2shKey>,
}

impl P2shFullViewingKey {
    /// Constructs a P2SH viewing key item for a standard ZIP 48 account.
    ///
    /// Returns an error if no keys are given, if more than 15 are given, or if
    /// `threshold` exceeds the number of keys.
    pub fn new(threshold: NonZeroU8, key_info: Vec<P2shKey>) -> Result<Self, P2shViewingKeyError> {
        let (threshold, key_info) = check_shape(threshold, key_info)?;
        Ok(Self {
            threshold,
            key_info,
        })
    }

    /// Parses the canonical encoding of a P2SH viewing key item.
    ///
    /// Returns an error if the encoding is malformed, if a key information vector entry
    /// is not a valid public key, or if the descriptor template is not the standard ZIP 48
    /// template for a full viewing key.
    pub fn parse(bytes: &[u8]) -> Result<Self, P2shViewingKeyError> {
        let (threshold, key_info) = parse_item(bytes, FVK_MULTIPATH)?;
        Ok(Self {
            threshold,
            key_info,
        })
    }

    /// Returns the multisig threshold of this item's descriptor.
    pub fn threshold(&self) -> NonZeroU8 {
        self.threshold
    }

    /// Returns this item's key information vector.
    pub fn key_info(&self) -> &NonEmpty<P2shKey> {
        &self.key_info
    }

    /// Returns the [BIP 388 wallet descriptor template] of this item.
    ///
    /// [BIP 388 wallet descriptor template]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki#wallet-descriptor-template
    pub fn wallet_descriptor_template(&self) -> String {
        render_template(self.threshold, self.key_info.len(), FVK_MULTIPATH)
    }

    /// Writes the canonical encoding of this item.
    pub fn write<W: corez::io::Write>(&self, writer: W) -> corez::io::Result<()> {
        write_item(self.threshold, &self.key_info, FVK_MULTIPATH, writer)
    }

    /// Returns the canonical encoding of this item.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![];
        self.write(&mut result)
            .expect("writing to a Vec cannot fail");
        result
    }

    /// Derives the incoming viewing key form of this item.
    ///
    /// Each key is advanced to its external (index 0) non-hardened child, and the keys are
    /// re-sorted into the lexicographic order ZIP 316 requires of the encoding.
    pub fn to_incoming_viewing_key(&self) -> Result<P2shIncomingViewingKey, bip32::Error> {
        let mut key_info = self
            .key_info
            .iter()
            .map(|key| key.derive_child(NonHardenedChildIndex::ZERO))
            .collect::<Result<Vec<_>, _>>()?;
        key_info.sort_unstable();
        Ok(P2shIncomingViewingKey {
            threshold: self.threshold,
            key_info: NonEmpty::from_vec(key_info).expect("derived from a non-empty vector"),
        })
    }
}

/// A [ZIP 316] Revision 2 P2SH viewing key item, in incoming viewing key form.
///
/// This derives the P2SH receivers of an account without the ability to derive its
/// internal (change) addresses.
///
/// [ZIP 316]: https://zips.z.cash/zip-0316
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2shIncomingViewingKey {
    threshold: NonZeroU8,
    key_info: NonEmpty<P2shKey>,
}

impl P2shIncomingViewingKey {
    /// Constructs a P2SH incoming viewing key item for a standard ZIP 48 account.
    ///
    /// Returns an error if no keys are given, if more than 15 are given, or if
    /// `threshold` exceeds the number of keys.
    pub fn new(threshold: NonZeroU8, key_info: Vec<P2shKey>) -> Result<Self, P2shViewingKeyError> {
        let (threshold, key_info) = check_shape(threshold, key_info)?;
        Ok(Self {
            threshold,
            key_info,
        })
    }

    /// Parses the canonical encoding of a P2SH viewing key item.
    ///
    /// Returns an error if the encoding is malformed, if a key information vector entry
    /// is not a valid public key, or if the descriptor template is not the standard ZIP 48
    /// template for an incoming viewing key.
    pub fn parse(bytes: &[u8]) -> Result<Self, P2shViewingKeyError> {
        let (threshold, key_info) = parse_item(bytes, IVK_MULTIPATH)?;
        Ok(Self {
            threshold,
            key_info,
        })
    }

    /// Returns the multisig threshold of this item's descriptor.
    pub fn threshold(&self) -> NonZeroU8 {
        self.threshold
    }

    /// Returns this item's key information vector.
    pub fn key_info(&self) -> &NonEmpty<P2shKey> {
        &self.key_info
    }

    /// Returns the [BIP 388 wallet descriptor template] of this item.
    ///
    /// [BIP 388 wallet descriptor template]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki#wallet-descriptor-template
    pub fn wallet_descriptor_template(&self) -> String {
        render_template(self.threshold, self.key_info.len(), IVK_MULTIPATH)
    }

    /// Writes the canonical encoding of this item.
    pub fn write<W: corez::io::Write>(&self, writer: W) -> corez::io::Result<()> {
        write_item(self.threshold, &self.key_info, IVK_MULTIPATH, writer)
    }

    /// Returns the canonical encoding of this item.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![];
        self.write(&mut result)
            .expect("writing to a Vec cannot fail");
        result
    }

    /// Derives the P2SH address at the given address index, with the redeem script that
    /// spends from it.
    pub fn derive_address(
        &self,
        address_index: NonHardenedChildIndex,
    ) -> (TransparentAddress, script::Redeem) {
        let keys = self
            .key_info
            .iter()
            .map(|key| key.key_expression(vec![address_index.into()]))
            .collect::<Vec<_>>();

        // The only constructors for this type force the standard descriptor template, so
        // it can be fixed here.
        let redeem_script = sortedmulti(self.threshold.get(), &keys)
            .expect("child numbers are non-hardened, chance of failure is around 2^-127");
        let script_pubkey = sh(&redeem_script);

        (
            TransparentAddress::from_script_pubkey(&script_pubkey).expect("valid"),
            redeem_script,
        )
    }
}

/// Errors that can occur while constructing or parsing a P2SH viewing key item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum P2shViewingKeyError {
    /// No keys were provided.
    NoPubKeys,
    /// The standard descriptor template can carry at most 15 keys.
    TooManyPubKeys,
    /// The provided threshold was larger than the number of keys.
    InvalidThreshold,
    /// The item encoding was malformed.
    Malformed,
    /// The descriptor template is not the standard ZIP 48 template for this item's form.
    UnsupportedTemplate,
    /// A key information vector entry was not a valid public key.
    InvalidKey(bip32::Error),
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
    use core::num::NonZeroU8;

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

        let fvk = FullViewingKey::standard(NonZeroU8::new(2).unwrap(), key_info).unwrap();

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

            let fvk =
                FullViewingKey::standard(NonZeroU8::new(tv.required).unwrap(), key_info).unwrap();

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

            for (i, seed) in seeds.iter().enumerate() {
                if i < tv.key_information_vector.len() {
                    assert!(matches!(
                        fvk.derive_matching_account_priv_key(seed),
                        Ok(Some(_)),
                    ));
                } else {
                    assert!(matches!(
                        fvk.derive_matching_account_priv_key(seed),
                        Ok(None),
                    ));
                }
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
