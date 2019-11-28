//! Encoding and decoding functions for Zcash key and address structs.
//!
//! Human-Readable Prefixes (HRPs) for Bech32 encodings are located in the [`constants`]
//! module.
//!
//! [`constants`]: crate::constants

use bech32::{self, Error, FromBase32, ToBase32};
use pairing::bls12_381::Bls12;
use std::io::{self, Write};
use zcash_primitives::{
    primitives::PaymentAddress,
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    JUBJUB,
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
/// use zcash_client_backend::{
///     constants::testnet::{COIN_TYPE, HRP_SAPLING_EXTENDED_SPENDING_KEY},
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
/// use zcash_client_backend::{
///     constants::testnet::{COIN_TYPE, HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY},
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
/// use pairing::bls12_381::Bls12;
/// use rand_core::SeedableRng;
/// use rand_xorshift::XorShiftRng;
/// use zcash_client_backend::{
///     constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
///     encoding::encode_payment_address,
/// };
/// use zcash_primitives::{
///     jubjub::edwards,
///     primitives::{Diversifier, PaymentAddress},
///     JUBJUB,
/// };
///
/// let rng = &mut XorShiftRng::from_seed([
///     0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
///     0xbc, 0xe5,
/// ]);
///
/// let pa = PaymentAddress::from_parts(
///     Diversifier([0u8; 11]),
///     edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
/// )
/// .unwrap();
///
/// assert_eq!(
///     encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &pa),
///     "ztestsapling1qqqqqqqqqqqqqqqqqrjq05nyfku05msvu49mawhg6kr0wwljahypwyk2h88z6975u563j0ym7pe",
/// );
/// ```
pub fn encode_payment_address(hrp: &str, addr: &PaymentAddress<Bls12>) -> String {
    bech32_encode(hrp, |w| w.write_all(&addr.to_bytes()))
}

/// Decodes a [`PaymentAddress`] from a Bech32-encoded string.
///
/// # Examples
///
/// ```
/// use pairing::bls12_381::Bls12;
/// use rand_core::SeedableRng;
/// use rand_xorshift::XorShiftRng;
/// use zcash_client_backend::{
///     constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
///     encoding::decode_payment_address,
/// };
/// use zcash_primitives::{
///     jubjub::edwards,
///     primitives::{Diversifier, PaymentAddress},
///     JUBJUB,
/// };
///
/// let rng = &mut XorShiftRng::from_seed([
///     0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
///     0xbc, 0xe5,
/// ]);
///
/// let pa = PaymentAddress::from_parts(
///     Diversifier([0u8; 11]),
///     edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
/// )
/// .unwrap();
///
/// assert_eq!(
///     decode_payment_address(
///         HRP_SAPLING_PAYMENT_ADDRESS,
///         "ztestsapling1qqqqqqqqqqqqqqqqqrjq05nyfku05msvu49mawhg6kr0wwljahypwyk2h88z6975u563j0ym7pe",
///     ),
///     Ok(Some(pa)),
/// );
/// ```
pub fn decode_payment_address(hrp: &str, s: &str) -> Result<Option<PaymentAddress<Bls12>>, Error> {
    bech32_decode(hrp, s, |data| {
        if data.len() != 43 {
            return None;
        }

        let mut bytes = [0; 43];
        bytes.copy_from_slice(&data);
        PaymentAddress::<Bls12>::from_bytes(&bytes, &JUBJUB)
    })
}

#[cfg(test)]
mod tests {
    use pairing::bls12_381::Bls12;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use zcash_primitives::JUBJUB;
    use zcash_primitives::{
        jubjub::edwards,
        primitives::{Diversifier, PaymentAddress},
        zip32::ExtendedSpendingKey,
    };

    use super::{
        decode_extended_full_viewing_key, decode_extended_spending_key, decode_payment_address,
        encode_extended_full_viewing_key, encode_extended_spending_key, encode_payment_address,
    };
    use crate::constants;

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

        let addr = PaymentAddress::from_parts(
            Diversifier([0u8; 11]),
            edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
        )
        .unwrap();

        let encoded_main =
            "zs1qqqqqqqqqqqqqqqqqrjq05nyfku05msvu49mawhg6kr0wwljahypwyk2h88z6975u563j8nfaxd";
        let encoded_test =
            "ztestsapling1qqqqqqqqqqqqqqqqqrjq05nyfku05msvu49mawhg6kr0wwljahypwyk2h88z6975u563j0ym7pe";

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

        let addr = PaymentAddress::from_parts(
            Diversifier([1u8; 11]),
            edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
        )
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
