//! Types and encodings for standalone transparent spending keys.
//!
//! These types are provided for compatibility with encodings used in zcashd RPC APIs and
//! serialization formats.

use core::array::TryFromSliceError;

use bip32::{PrivateKey, PrivateKeyBytes};
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing};
use secrecy::{ExposeSecret, SecretString, SecretVec, Zeroize, zeroize::ZeroizeOnDrop};
use zcash_protocol::consensus::NetworkConstants;

/// Errors that can occur in the parsing of Bitcoin-style base58-encoded secret key material
#[derive(Debug)]
pub enum ParseError {
    /// The data being decoded had an incorrect length, an incorrect prefix, or has the correct
    /// length for a compressed encoding but has its final byte not equal to `1`.
    InvalidEncoding,
    /// Errors that occur in base58 decoding.
    Base58(bs58::decode::Error),
    /// Errors that occur when a decoded binary value does not correspond to a valid secp256k1 secret key.
    Bip32(bip32::Error),
}

impl From<bs58::decode::Error> for ParseError {
    fn from(value: bs58::decode::Error) -> Self {
        ParseError::Base58(value)
    }
}

impl From<TryFromSliceError> for ParseError {
    fn from(_: TryFromSliceError) -> Self {
        ParseError::InvalidEncoding
    }
}

impl From<bip32::Error> for ParseError {
    fn from(value: bip32::Error) -> Self {
        ParseError::Bip32(value)
    }
}

/// A secp256k1 secret key, along with a flag indicating whether a compressed encoding should be
/// used when performing DER serialization.
pub struct Key {
    secret: SecretKey,
    compressed: bool,
}

impl Key {
    /// Constructs a new key value from a secret key and a flag indicating whether
    /// the compressed encoding should be used when performing DER serialization.
    pub fn new(secret: SecretKey, compressed: bool) -> Self {
        Self { secret, compressed }
    }

    /// Decodes a base58-encoded secret key.
    ///
    /// This corresponds to <https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key_io.cpp#L282>
    pub fn decode_base58<N: NetworkConstants>(
        network: &N,
        encoded: &SecretString,
    ) -> Result<Self, ParseError> {
        let decoded = SecretVec::new(
            bs58::decode(encoded.expose_secret())
                .with_check(None)
                .into_vec()?,
        );
        let prefix = network.b58_secret_key_prefix();
        let decoded_len = decoded.expose_secret().len();
        let compressed =
            decoded_len == (33 + prefix.len()) && decoded.expose_secret().last() == Some(&1);
        if (decoded_len == 32 + prefix.len() || compressed)
            && decoded.expose_secret()[0..prefix.len()] == prefix
        {
            let key_end = decoded_len - if compressed { 1 } else { 0 };
            let bytes = PrivateKeyBytes::try_from(&decoded.expose_secret()[prefix.len()..key_end])?;
            Ok(Self {
                secret: SecretKey::from_bytes(&bytes)?,
                compressed,
            })
        } else {
            Err(ParseError::InvalidEncoding)
        }
    }

    /// Encodes a base58-encoded secret key.
    ///
    /// This corresponds to <https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key_io.cpp#L298>
    pub fn encode_base58<N: NetworkConstants>(&self, network: &N) -> SecretString {
        let input = SecretVec::new(
            network
                .b58_secret_key_prefix()
                .iter()
                .chain(self.secret.secret_bytes().iter())
                .chain(self.compressed.then_some(&1))
                .copied()
                .collect(),
        );

        SecretString::new(
            bs58::encode(input.expose_secret())
                .with_check()
                .into_string(),
        )
    }

    /// Returns the wrapped secp256k1 secret key.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Returns the value of the compressed flag.
    pub fn compressed(&self) -> bool {
        self.compressed
    }

    /// Derives the secp256k1 public key corresponding to the secret key.
    pub fn pubkey(&self) -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        self.pubkey_with_context(&secp)
    }

    /// Derives the secp256k1 public key corresponding to the secret key,
    /// using the provided secp context.
    pub fn pubkey_with_context<C: Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        self.secret.public_key(secp)
    }

    /// Generates the "openssh-inspired" DER encoding of the secret key used by zcashd.
    pub fn der_encode(&self) -> SecretVec<u8> {
        let secp = secp256k1::Secp256k1::new();
        self.der_encode_with_context(&secp)
    }

    /// Generates the "openssh-inspired" DER encoding of the secret key used by zcashd,
    /// using the provided secp context for pubkey encoding.
    pub fn der_encode_with_context<C: Signing>(&self, secp: &Secp256k1<C>) -> SecretVec<u8> {
        // Ported from https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key.cpp#L93
        // The original c++ code is retained as comments.

        //    secp256k1_pubkey pubkey;
        //    size_t pubkeylen = 0;
        //    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) {
        //        *seckeylen = 0;
        //        return 0;
        //    }
        let keypair = self.secret().keypair(secp);

        if self.compressed {
            let begin = [0x30, 0x81, 0xD3, 0x02, 0x01, 0x01, 0x04, 0x20];
            let middle = [
                0xA0, 0x81, 0x85, 0x30, 0x81, 0x82, 0x02, 0x01, 0x01, 0x30, 0x2C, 0x06, 0x07, 0x2A,
                0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01, 0x02, 0x21, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F, 0x30,
                0x06, 0x04, 0x01, 0x00, 0x04, 0x01, 0x07, 0x04, 0x21, 0x02, 0x79, 0xBE, 0x66, 0x7E,
                0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B,
                0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
                0x02, 0x21, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF,
                0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41, 0x02, 0x01, 0x01, 0xA1, 0x24, 0x03, 0x22,
                0x00,
            ];
            //        unsigned char *ptr = seckey;
            //        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
            //        memcpy(ptr, key32, 32); ptr += 32;
            //        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
            //        pubkeylen = CPubKey::COMPRESSED_PUBLIC_KEY_SIZE;
            //        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
            //        ptr += pubkeylen;
            //        *seckeylen = ptr - seckey;
            //        assert(*seckeylen == CKey::COMPRESSED_PRIVATE_KEY_SIZE);
            SecretVec::new(
                begin
                    .iter()
                    .chain(keypair.secret_bytes().iter())
                    .chain(middle.iter())
                    .chain(keypair.public_key().serialize().iter())
                    .copied()
                    .collect(),
            )
        } else {
            let begin = [0x30, 0x82, 0x01, 0x13, 0x02, 0x01, 0x01, 0x04, 0x20];
            let middle = [
                0xA0, 0x81, 0xA5, 0x30, 0x81, 0xA2, 0x02, 0x01, 0x01, 0x30, 0x2C, 0x06, 0x07, 0x2A,
                0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01, 0x02, 0x21, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F, 0x30,
                0x06, 0x04, 0x01, 0x00, 0x04, 0x01, 0x07, 0x04, 0x41, 0x04, 0x79, 0xBE, 0x66, 0x7E,
                0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B,
                0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
                0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11,
                0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F,
                0xFB, 0x10, 0xD4, 0xB8, 0x02, 0x21, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF,
                0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41, 0x02, 0x01, 0x01,
                0xA1, 0x44, 0x03, 0x42, 0x00,
            ];
            //        unsigned char *ptr = seckey;
            //        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
            //        memcpy(ptr, key32, 32); ptr += 32;
            //        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
            //        pubkeylen = CPubKey::PUBLIC_KEY_SIZE;
            //        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
            //        ptr += pubkeylen;
            //        *seckeylen = ptr - seckey;
            //        assert(*seckeylen == CKey::PRIVATE_KEY_SIZE);
            SecretVec::new(
                begin
                    .iter()
                    .chain(keypair.secret_bytes().iter())
                    .chain(middle.iter())
                    .chain(keypair.public_key().serialize_uncompressed().iter())
                    .copied()
                    .collect(),
            )
        }
    }

    // Decodes a secret key from the "openssl-inspired" DER encoding used by zcashd.
    pub fn der_decode(encoded: &SecretVec<u8>, compressed: bool) -> Result<Self, ()> {
        // Ported from https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key.cpp#L36
        // The original c++ code is retained as comments.

        let seckey = encoded.expose_secret();

        //    /* sequence header */
        //    if (end - seckey < 1 || *seckey != 0x30u) {
        //        return 0;
        //    }
        //    seckey++;
        let seckey = match seckey.split_first() {
            Some((&0x30, rest)) => Ok(rest),
            _ => Err(()),
        }?;

        //    /* sequence length constructor */
        //    if (end - seckey < 1 || !(*seckey & 0x80u)) {
        //        return 0;
        //    }
        //    size_t lenb = *seckey & ~0x80u; seckey++;
        //    if (lenb < 1 || lenb > 2) {
        //        return 0;
        //    }
        //    if (end - seckey < lenb) {
        //        return 0;
        //    }
        let (lenb, seckey) = match seckey.split_first() {
            Some((lenb, seckey)) if lenb & 0x80 != 0 => Ok((usize::from(lenb & !0x80), seckey)),
            _ => Err(()),
        }?;
        if !(1..=2).contains(&lenb) {
            return Err(());
        }
        if seckey.len() < lenb {
            return Err(());
        }

        //    /* sequence length */
        //    size_t len = seckey[lenb-1] | (lenb > 1 ? seckey[lenb-2] << 8 : 0u);
        //    seckey += lenb;
        //    if (end - seckey < len) {
        //        return 0;
        //    }
        let len_low_bits = usize::from(seckey[lenb - 1]);
        let len_high_bits = if lenb > 1 {
            usize::from(seckey[lenb - 2]) << 8
        } else {
            0
        };
        let len = len_low_bits | len_high_bits;
        let seckey = &seckey[lenb..];
        if seckey.len() < len {
            return Err(());
        }

        //    /* sequence element 0: version number (=1) */
        //    if (end - seckey < 3 || seckey[0] != 0x02u || seckey[1] != 0x01u || seckey[2] != 0x01u) {
        //        return 0;
        //    }
        //    seckey += 3;
        let seckey = match seckey.split_at(3) {
            (&[0x02, 0x01, 0x01], rest) => Ok(rest),
            _ => Err(()),
        }?;

        //    /* sequence element 1: octet string, up to 32 bytes */
        //    if (end - seckey < 2 || seckey[0] != 0x04u) {
        //        return 0;
        //    }
        //    size_t oslen = seckey[1];
        //    seckey += 2;
        //    if (oslen > 32 || end - seckey < oslen) {
        //        return 0;
        //    }
        //    memcpy(out32 + (32 - oslen), seckey, oslen);
        //    if (!secp256k1_ec_seckey_verify(ctx, out32)) {
        //        memset(out32, 0, 32);
        //        return 0;
        //    }
        //    return 1;
        //}
        if seckey.len() < 2 || seckey[0] != 0x04 {
            return Err(());
        }
        let oslen = usize::from(seckey[1]);
        let seckey = &seckey[2..];
        if oslen > 32 || seckey.len() < oslen {
            return Err(());
        }
        let mut secret_buf = [0u8; 32];
        secret_buf[(32 - oslen)..].copy_from_slice(&seckey[..oslen]);
        let secret_key = SecretKey::from_bytes(&secret_buf);
        secret_buf.zeroize();

        secret_key
            .map(|secret| Self { secret, compressed })
            .map_err(|_| ())
    }
}

impl Zeroize for Key {
    fn zeroize(&mut self) {
        self.secret.non_secure_erase();
    }
}

impl ZeroizeOnDrop for Key {}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod test_vectors;

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng as _};
    use rand_chacha::ChaChaRng;
    use secp256k1::{Secp256k1, SecretKey};
    use secrecy::SecretString;
    use transparent::address::TransparentAddress;
    use zcash_protocol::consensus::NetworkType;
    use zcash_script::script::Evaluable;

    use super::{
        Key,
        test_vectors::{INVALID, VALID, VectorKind},
    };

    #[test]
    fn der_encoding_roundtrip() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);
        let secp = Secp256k1::new();
        for _ in 0..100 {
            let secret = SecretKey::new(&mut rng);
            let compressed = rng.gen_bool(0.5);
            let key = Key { secret, compressed };

            let encoded = key.der_encode_with_context(&secp);
            let decoded = Key::der_decode(&encoded, compressed).unwrap();

            assert_eq!(key.secret(), decoded.secret());
        }
    }

    /// Checks that parsed keys match test payload.
    #[test]
    fn base58_keys_valid_parse() {
        for v in VALID {
            match v.kind {
                VectorKind::Privkey { is_compressed } => {
                    // Must be valid private key
                    let secret = &SecretString::new(v.base58_encoding.into());
                    let privkey = Key::decode_base58(&v.network, secret).unwrap();
                    assert_eq!(privkey.compressed, is_compressed);
                    assert_eq!(hex::encode(privkey.secret.as_ref()), v.raw_bytes_hex);

                    // Private key must be invalid public key
                    assert_eq!(
                        zcash_address::ZcashAddress::try_from_encoded(v.base58_encoding),
                        Err(zcash_address::ParseError::NotZcash),
                    );
                }
                VectorKind::Pubkey => {
                    // Must be valid public key
                    let destination: TransparentAddress =
                        zcash_address::ZcashAddress::try_from_encoded(v.base58_encoding)
                            .unwrap()
                            .convert_if_network(v.network)
                            .unwrap();
                    let script = destination.script();
                    assert_eq!(hex::encode(script.to_bytes()), v.raw_bytes_hex);

                    // Public key must be invalid private key
                    assert!(
                        Key::decode_base58(
                            &v.network,
                            &SecretString::new(v.base58_encoding.into())
                        )
                        .is_err()
                    );
                }
            }
        }
    }

    /// Checks that Base58 key parsing code is robust against a variety of corrupted data.
    #[test]
    fn base58_keys_invalid() {
        for &encoded in INVALID {
            assert!(
                Key::decode_base58(&NetworkType::Main, &SecretString::new(encoded.into())).is_err()
            );
            assert_eq!(
                zcash_address::ZcashAddress::try_from_encoded(encoded),
                Err(zcash_address::ParseError::NotZcash),
            );
        }
    }
}
