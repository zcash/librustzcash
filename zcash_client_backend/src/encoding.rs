//! Encoding and decoding functions for Zcash key and address structs.
//!
//! Human-Readable Prefixes (HRPs) for Bech32 encodings are located in the [`constants`]
//! module.

use bech32::{convert_bits, Bech32, Error};
use pairing::bls12_381::Bls12;
use sapling_crypto::{
    jubjub::edwards,
    primitives::{Diversifier, PaymentAddress},
};
use std::io::{self, Write};
use zcash_primitives::{
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    JUBJUB,
};

fn bech32_encode<F>(hrp: &str, write: F) -> String
where
    F: Fn(&mut dyn Write) -> io::Result<()>,
{
    let mut data: Vec<u8> = vec![];
    write(&mut data).expect("Should be able to write to a Vec");

    let converted =
        convert_bits(&data, 8, 5, true).expect("Should be able to convert Vec<u8> to Vec<u5>");
    let encoded = Bech32::new_check_data(hrp.into(), converted).expect("hrp is not empty");

    encoded.to_string()
}

fn bech32_decode<T, F>(hrp: &str, s: &str, read: F) -> Result<Option<T>, Error>
where
    F: Fn(Vec<u8>) -> Option<T>,
{
    let decoded = s.parse::<Bech32>()?;
    if decoded.hrp() == hrp {
        convert_bits(decoded.data(), 5, 8, false).map(|data| read(data))
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
/// use rand::{SeedableRng, XorShiftRng};
/// use sapling_crypto::{
///     jubjub::edwards,
///     primitives::{Diversifier, PaymentAddress},
/// };
/// use zcash_client_backend::{
///     constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
///     encoding::encode_payment_address,
/// };
/// use zcash_primitives::JUBJUB;
///
/// let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
///
/// let pa = PaymentAddress {
///     diversifier: Diversifier([0u8; 11]),
///     pk_d: edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
/// };
///
/// assert_eq!(
///     encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &pa),
///     "ztestsapling1qqqqqqqqqqqqqqqqqqxrrfaccydp867g6zg7ne5ht37z38jtfyw0ygmp0ja6hhf07twjq6awtaj",
/// );
/// ```
pub fn encode_payment_address(hrp: &str, addr: &PaymentAddress<Bls12>) -> String {
    bech32_encode(hrp, |w| {
        w.write_all(&addr.diversifier.0)?;
        addr.pk_d.write(w)
    })
}

/// Decodes a [`PaymentAddress`] from a Bech32-encoded string.
///
/// # Examples
///
/// ```
/// use pairing::bls12_381::Bls12;
/// use rand::{SeedableRng, XorShiftRng};
/// use sapling_crypto::{
///     jubjub::edwards,
///     primitives::{Diversifier, PaymentAddress},
/// };
/// use zcash_client_backend::{
///     constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
///     encoding::decode_payment_address,
/// };
/// use zcash_primitives::JUBJUB;
///
/// let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
///
/// let pa = PaymentAddress {
///     diversifier: Diversifier([0u8; 11]),
///     pk_d: edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
/// };
///
/// assert_eq!(
///     decode_payment_address(
///         HRP_SAPLING_PAYMENT_ADDRESS,
///         "ztestsapling1qqqqqqqqqqqqqqqqqqxrrfaccydp867g6zg7ne5ht37z38jtfyw0ygmp0ja6hhf07twjq6awtaj",
///     ),
///     Ok(Some(pa)),
/// );
/// ```
pub fn decode_payment_address(hrp: &str, s: &str) -> Result<Option<PaymentAddress<Bls12>>, Error> {
    bech32_decode(hrp, s, |data| {
        let mut diversifier = Diversifier([0; 11]);
        diversifier.0.copy_from_slice(&data[0..11]);
        // Check that the diversifier is valid
        if diversifier.g_d::<Bls12>(&JUBJUB).is_none() {
            return None;
        }

        edwards::Point::<Bls12, _>::read(&data[11..], &JUBJUB)
            .ok()?
            .as_prime_order(&JUBJUB)
            .map(|pk_d| PaymentAddress { pk_d, diversifier })
    })
}

#[cfg(test)]
mod tests {
    use pairing::bls12_381::Bls12;
    use rand::{SeedableRng, XorShiftRng};
    use sapling_crypto::{
        jubjub::edwards,
        primitives::{Diversifier, PaymentAddress},
    };
    use zcash_primitives::JUBJUB;

    use super::{decode_payment_address, encode_payment_address};
    use crate::constants;

    #[test]
    fn payment_address() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let addr = PaymentAddress {
            diversifier: Diversifier([0u8; 11]),
            pk_d: edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
        };

        let encoded_main =
            "zs1qqqqqqqqqqqqqqqqqqxrrfaccydp867g6zg7ne5ht37z38jtfyw0ygmp0ja6hhf07twjqj2ug6x";
        let encoded_test =
            "ztestsapling1qqqqqqqqqqqqqqqqqqxrrfaccydp867g6zg7ne5ht37z38jtfyw0ygmp0ja6hhf07twjq6awtaj";

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
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let addr = PaymentAddress {
            diversifier: Diversifier([1u8; 11]),
            pk_d: edwards::Point::<Bls12, _>::rand(rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
        };

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
