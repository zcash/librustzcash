//! Encoding and decoding functions for Zcash key and address structs.
//!
//! Human-Readable Prefixes (HRPs) for Bech32 encodings are located in the [`zcash_primitives::constants`]
//! module.
//!
//! [`constants`]: zcash_primitives::constants

use bech32::{self, Error, FromBase32, ToBase32};
use bs58::{self, decode::Error as Bs58Error};
use std::convert::TryInto;
use std::io::{self, Write};
use zcash_primitives::{
    legacy::TransparentAddress,
    primitives::PaymentAddress,
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
};

fn bech32_encode<F>(hrp: &str, write: F) -> String
where
    F: Fn(&mut dyn Write) -> io::Result<()>,
{
    let mut data: Vec<u8> = vec![];
    write(&mut data).expect("Should be able to write to a Vec");
    bech32::encode(hrp, data.to_base32()).expect("hrp is invalid")
}

fn bech32_decode<T, F>(hrp: &str, s: &str, read: F) -> Result<Option<T>, Error>
where
    F: Fn(Vec<u8>) -> Option<T>,
{
    let (decoded_hrp, data) = bech32::decode(s)?;
    if decoded_hrp == hrp {
        Vec::<u8>::from_base32(&data).map(|data| read(data))
    } else {
        Ok(None)
    }
}

/// Writes an [`ExtendedSpendingKey`] as a Bech32-encoded string.
///
/// # Examples
///
/// ```
/// use zcash_primitives::{
///     constants::testnet::{COIN_TYPE, HRP_SAPLING_EXTENDED_SPENDING_KEY},
/// };
/// use zcash_client_backend::{
///     encoding::encode_extended_spending_key,
///     keys::spending_key,
/// };
///
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, 0);
/// let encoded = encode_extended_spending_key(HRP_SAPLING_EXTENDED_SPENDING_KEY, &extsk);
/// ```
pub fn encode_extended_spending_key(hrp: &str, extsk: &ExtendedSpendingKey) -> String {
    bech32_encode(hrp, |w| extsk.write(w))
}

/// Decodes an [`ExtendedSpendingKey`] from a Bech32-encoded string.
pub fn decode_extended_spending_key(
    hrp: &str,
    s: &str,
) -> Result<Option<ExtendedSpendingKey>, Error> {
    bech32_decode(hrp, s, |data| ExtendedSpendingKey::read(&data[..]).ok())
}

/// Writes an [`ExtendedFullViewingKey`] as a Bech32-encoded string.
///
/// # Examples
///
/// ```
/// use zcash_primitives::{
///     constants::testnet::{COIN_TYPE, HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY},
/// };
/// use zcash_client_backend::{
///     encoding::encode_extended_full_viewing_key,
///     keys::spending_key,
/// };
/// use zcash_primitives::zip32::ExtendedFullViewingKey;
///
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, 0);
/// let extfvk = ExtendedFullViewingKey::from(&extsk);
/// let encoded = encode_extended_full_viewing_key(HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, &extfvk);
/// ```
pub fn encode_extended_full_viewing_key(hrp: &str, extfvk: &ExtendedFullViewingKey) -> String {
    bech32_encode(hrp, |w| extfvk.write(w))
}

/// Decodes an [`ExtendedFullViewingKey`] from a Bech32-encoded string.
pub fn decode_extended_full_viewing_key(
    hrp: &str,
    s: &str,
) -> Result<Option<ExtendedFullViewingKey>, Error> {
    bech32_decode(hrp, s, |data| ExtendedFullViewingKey::read(&data[..]).ok())
}

/// Writes a [`PaymentAddress`] as a Bech32-encoded string.
///
/// # Examples
///
/// ```
/// use group::Group;
/// use jubjub::SubgroupPoint;
/// use rand_core::SeedableRng;
/// use rand_xorshift::XorShiftRng;
/// use zcash_client_backend::{
///     encoding::encode_payment_address,
/// };
/// use zcash_primitives::{
///     constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
///     primitives::{Diversifier, PaymentAddress},
/// };
///
/// let rng = &mut XorShiftRng::from_seed([
///     0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
///     0xbc, 0xe5,
/// ]);
///
/// let pa = PaymentAddress::from_parts(
///     Diversifier([0u8; 11]),
///     SubgroupPoint::random(rng),
/// )
/// .unwrap();
///
/// assert_eq!(
///     encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &pa),
///     "ztestsapling1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75ss7jnk",
/// );
/// ```
pub fn encode_payment_address(hrp: &str, addr: &PaymentAddress) -> String {
    bech32_encode(hrp, |w| w.write_all(&addr.to_bytes()))
}

/// Decodes a [`PaymentAddress`] from a Bech32-encoded string.
///
/// # Examples
///
/// ```
/// use group::Group;
/// use jubjub::SubgroupPoint;
/// use rand_core::SeedableRng;
/// use rand_xorshift::XorShiftRng;
/// use zcash_client_backend::{
///     encoding::decode_payment_address,
/// };
/// use zcash_primitives::{
///     constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
///     primitives::{Diversifier, PaymentAddress},
/// };
///
/// let rng = &mut XorShiftRng::from_seed([
///     0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
///     0xbc, 0xe5,
/// ]);
///
/// let pa = PaymentAddress::from_parts(
///     Diversifier([0u8; 11]),
///     SubgroupPoint::random(rng),
/// )
/// .unwrap();
///
/// assert_eq!(
///     decode_payment_address(
///         HRP_SAPLING_PAYMENT_ADDRESS,
///         "ztestsapling1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75ss7jnk",
///     ),
///     Ok(Some(pa)),
/// );
/// ```
pub fn decode_payment_address(hrp: &str, s: &str) -> Result<Option<PaymentAddress>, Error> {
    bech32_decode(hrp, s, |data| {
        if data.len() != 43 {
            return None;
        }

        let mut bytes = [0; 43];
        bytes.copy_from_slice(&data);
        PaymentAddress::from_bytes(&bytes)
    })
}

/// Writes a [`TransparentAddress`] as a Base58Check-encoded string.
///
/// # Examples
///
/// ```
/// use zcash_client_backend::{
///     encoding::encode_transparent_address,
/// };
/// use zcash_primitives::{
///     constants::testnet::{B58_PUBKEY_ADDRESS_PREFIX, B58_SCRIPT_ADDRESS_PREFIX},
///     legacy::TransparentAddress,
/// };
///
/// assert_eq!(
///     encode_transparent_address(
///         &B58_PUBKEY_ADDRESS_PREFIX,
///         &B58_SCRIPT_ADDRESS_PREFIX,
///         &TransparentAddress::PublicKey([0; 20]),
///     ),
///     "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma",
/// );
///
/// assert_eq!(
///     encode_transparent_address(
///         &B58_PUBKEY_ADDRESS_PREFIX,
///         &B58_SCRIPT_ADDRESS_PREFIX,
///         &TransparentAddress::Script([0; 20]),
///     ),
///     "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2",
/// );
/// ```
pub fn encode_transparent_address(
    pubkey_version: &[u8],
    script_version: &[u8],
    addr: &TransparentAddress,
) -> String {
    let decoded = match addr {
        TransparentAddress::PublicKey(key_id) => {
            let mut decoded = vec![0; pubkey_version.len() + 20];
            decoded[..pubkey_version.len()].copy_from_slice(pubkey_version);
            decoded[pubkey_version.len()..].copy_from_slice(key_id);
            decoded
        }
        TransparentAddress::Script(script_id) => {
            let mut decoded = vec![0; script_version.len() + 20];
            decoded[..script_version.len()].copy_from_slice(script_version);
            decoded[script_version.len()..].copy_from_slice(script_id);
            decoded
        }
    };
    bs58::encode(decoded).with_check().into_string()
}

/// Decodes a [`TransparentAddress`] from a Base58Check-encoded string.
///
/// # Examples
///
/// ```
/// use zcash_primitives::{
///     constants::testnet::{B58_PUBKEY_ADDRESS_PREFIX, B58_SCRIPT_ADDRESS_PREFIX},
/// };
/// use zcash_client_backend::{
///     encoding::decode_transparent_address,
/// };
/// use zcash_primitives::legacy::TransparentAddress;
///
/// assert_eq!(
///     decode_transparent_address(
///         &B58_PUBKEY_ADDRESS_PREFIX,
///         &B58_SCRIPT_ADDRESS_PREFIX,
///         "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma",
///     ),
///     Ok(Some(TransparentAddress::PublicKey([0; 20]))),
/// );
///
/// assert_eq!(
///     decode_transparent_address(
///         &B58_PUBKEY_ADDRESS_PREFIX,
///         &B58_SCRIPT_ADDRESS_PREFIX,
///         "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2",
///     ),
///     Ok(Some(TransparentAddress::Script([0; 20]))),
/// );
/// ```
pub fn decode_transparent_address(
    pubkey_version: &[u8],
    script_version: &[u8],
    s: &str,
) -> Result<Option<TransparentAddress>, Bs58Error> {
    bs58::decode(s).with_check(None).into_vec().map(|decoded| {
        if decoded.starts_with(pubkey_version) {
            decoded[pubkey_version.len()..]
                .try_into()
                .ok()
                .map(TransparentAddress::PublicKey)
        } else if decoded.starts_with(script_version) {
            decoded[script_version.len()..]
                .try_into()
                .ok()
                .map(TransparentAddress::Script)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use group::Group;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use zcash_primitives::{
        constants::{self},
        primitives::{Diversifier, PaymentAddress},
        zip32::ExtendedSpendingKey,
    };

    use super::{
        decode_extended_full_viewing_key, decode_extended_spending_key, decode_payment_address,
        encode_extended_full_viewing_key, encode_extended_spending_key, encode_payment_address,
    };

    #[test]
    fn extended_spending_key() {
        let extsk = ExtendedSpendingKey::master(&[0; 32][..]);

        let encoded_main = "secret-extended-key-main1qqqqqqqqqqqqqq8n3zjjmvhhr854uy3qhpda3ml34haf0x388z5r7h4st4kpsf6qysqws3xh6qmha7gna72fs2n4clnc9zgyd22s658f65pex4exe56qjk5pqj9vfdq7dfdhjc2rs9jdwq0zl99uwycyrxzp86705rk687spn44e2uhm7h0hsagfvkk4n7n6nfer6u57v9cac84t7nl2zth0xpyfeg0w2p2wv2yn6jn923aaz0vdaml07l60ahapk6efchyxwysrvjs87qvlj";
        let encoded_test = "secret-extended-key-test1qqqqqqqqqqqqqq8n3zjjmvhhr854uy3qhpda3ml34haf0x388z5r7h4st4kpsf6qysqws3xh6qmha7gna72fs2n4clnc9zgyd22s658f65pex4exe56qjk5pqj9vfdq7dfdhjc2rs9jdwq0zl99uwycyrxzp86705rk687spn44e2uhm7h0hsagfvkk4n7n6nfer6u57v9cac84t7nl2zth0xpyfeg0w2p2wv2yn6jn923aaz0vdaml07l60ahapk6efchyxwysrvjsvzyw8j";

        assert_eq!(
            encode_extended_spending_key(
                constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
                &extsk
            ),
            encoded_main
        );
        assert_eq!(
            decode_extended_spending_key(
                constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
                encoded_main
            )
            .unwrap(),
            Some(extsk.clone())
        );

        assert_eq!(
            encode_extended_spending_key(
                constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
                &extsk
            ),
            encoded_test
        );
        assert_eq!(
            decode_extended_spending_key(
                constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
                encoded_test
            )
            .unwrap(),
            Some(extsk)
        );
    }

    #[test]
    fn extended_full_viewing_key() {
        let extfvk = (&ExtendedSpendingKey::master(&[0; 32][..])).into();

        let encoded_main = "zxviews1qqqqqqqqqqqqqq8n3zjjmvhhr854uy3qhpda3ml34haf0x388z5r7h4st4kpsf6qy3zw4wc246aw9rlfyg5ndlwvne7mwdq0qe6vxl42pqmcf8pvmmd5slmjxduqa9evgej6wa3th2505xq4nggrxdm93rxk4rpdjt5nmq2vn44e2uhm7h0hsagfvkk4n7n6nfer6u57v9cac84t7nl2zth0xpyfeg0w2p2wv2yn6jn923aaz0vdaml07l60ahapk6efchyxwysrvjsxmansf";
        let encoded_test = "zxviewtestsapling1qqqqqqqqqqqqqq8n3zjjmvhhr854uy3qhpda3ml34haf0x388z5r7h4st4kpsf6qy3zw4wc246aw9rlfyg5ndlwvne7mwdq0qe6vxl42pqmcf8pvmmd5slmjxduqa9evgej6wa3th2505xq4nggrxdm93rxk4rpdjt5nmq2vn44e2uhm7h0hsagfvkk4n7n6nfer6u57v9cac84t7nl2zth0xpyfeg0w2p2wv2yn6jn923aaz0vdaml07l60ahapk6efchyxwysrvjs8evfkz";

        assert_eq!(
            encode_extended_full_viewing_key(
                constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
                &extfvk
            ),
            encoded_main
        );
        assert_eq!(
            decode_extended_full_viewing_key(
                constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
                encoded_main
            )
            .unwrap(),
            Some(extfvk.clone())
        );

        assert_eq!(
            encode_extended_full_viewing_key(
                constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
                &extfvk
            ),
            encoded_test
        );
        assert_eq!(
            decode_extended_full_viewing_key(
                constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
                encoded_test
            )
            .unwrap(),
            Some(extfvk)
        );
    }

    #[test]
    fn payment_address() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let addr =
            PaymentAddress::from_parts(Diversifier([0u8; 11]), jubjub::SubgroupPoint::random(rng))
                .unwrap();

        let encoded_main =
            "zs1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75c8v35z";
        let encoded_test =
            "ztestsapling1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75ss7jnk";

        assert_eq!(
            encode_payment_address(constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS, &addr),
            encoded_main
        );
        assert_eq!(
            decode_payment_address(
                constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
                encoded_main
            )
            .unwrap(),
            Some(addr.clone())
        );

        assert_eq!(
            encode_payment_address(constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS, &addr),
            encoded_test
        );
        assert_eq!(
            decode_payment_address(
                constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
                encoded_test
            )
            .unwrap(),
            Some(addr)
        );
    }

    #[test]
    fn invalid_diversifier() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        let addr =
            PaymentAddress::from_parts(Diversifier([1u8; 11]), jubjub::SubgroupPoint::random(rng))
                .unwrap();

        let encoded_main =
            encode_payment_address(constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS, &addr);

        assert_eq!(
            decode_payment_address(
                constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
                &encoded_main
            )
            .unwrap(),
            None
        );
    }
}
