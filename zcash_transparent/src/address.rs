//! Support for legacy transparent addresses and scripts.

use core2::io::{self, Read, Write};
use zcash_address::TryFromAddress;
use zcash_protocol::consensus::NetworkType;

use zcash_encoding::Vector;
use zcash_script::{
    opcode::Opcode,
    pattern::IdentifiedScriptPubKey,
    script::{self, Parsable},
};

#[cfg(feature = "transparent-inputs")]
use sha2::{Digest, Sha256};

pub fn write_script_sig<T: Parsable, W: Write>(
    script_sig: &script::Sig<T>,
    writer: W,
) -> io::Result<()> {
    write_script_code(&script_sig.to_bytes(), writer)
}

pub fn read_script_sig<R: Read>(mut reader: R) -> io::Result<script::Sig<Opcode>> {
    let script = Vector::read(&mut reader, |r| {
        let mut bytes = [0; 1];
        r.read_exact(&mut bytes).map(|_| bytes[0])
    })?;
    script::Sig::<Opcode>::from_bytes(&script)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid script_sig"))
        .map(|(script, _)| script)
}

pub fn read_script_pubkey<R: Read>(mut reader: R) -> io::Result<script::PubKey> {
    let script = Vector::read(&mut reader, |r| {
        let mut bytes = [0; 1];
        r.read_exact(&mut bytes).map(|_| bytes[0])
    })?;
    script::PubKey::from_bytes(&script)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid script_pubkey"))
        .map(|(script, _)| script)
}

pub fn write_script_code<W: Write>(script_code: &[u8], mut writer: W) -> io::Result<()> {
    Vector::write(&mut writer, script_code, |w, e| w.write_all(&[*e]))
}

pub fn write_script_pubkey<W: Write>(script_pub_key: &script::PubKey, writer: W) -> io::Result<()> {
    write_script_code(&script_pub_key.to_bytes(), writer)
}

/// Returns the length of this script as encoded (including the initial CompactSize).
pub fn serialized_script_pubkey_size(script_pubkey: &script::PubKey) -> usize {
    Vector::serialized_size_of_u8_vec(&script_pubkey.to_bytes())
}

/// A transparent address corresponding to either a public key hash or a script hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransparentAddress {
    PublicKeyHash([u8; 20]),
    ScriptHash([u8; 20]),
}

impl TransparentAddress {
    /// Returns the address that this Script contains, if any.
    pub fn from_script_pubkey(script_pubkey: &script::PubKey) -> Option<Self> {
        IdentifiedScriptPubKey::identify(&script_pubkey.0).map(|identified| match identified {
            IdentifiedScriptPubKey::P2PKH(hash) => TransparentAddress::PublicKeyHash(hash),
            IdentifiedScriptPubKey::P2SH(hash) => TransparentAddress::ScriptHash(hash),
        })
    }

    /// Generate the `scriptPubKey` corresponding to this address.
    pub fn script(&self) -> script::PubKey {
        script::PubKey(
            match self {
                TransparentAddress::PublicKeyHash(key_id) => IdentifiedScriptPubKey::P2PKH(*key_id),

                TransparentAddress::ScriptHash(script_id) => {
                    IdentifiedScriptPubKey::P2SH(*script_id)
                }
            }
            .serialize(),
        )
    }

    /// Derives the P2PKH transparent address corresponding to the given pubkey.
    #[cfg(feature = "transparent-inputs")]
    pub fn from_pubkey(pubkey: &secp256k1::PublicKey) -> Self {
        TransparentAddress::PublicKeyHash(
            *ripemd::Ripemd160::digest(Sha256::digest(pubkey.serialize())).as_ref(),
        )
    }
}

impl TryFromAddress for TransparentAddress {
    type Error = ();

    fn try_from_transparent_p2pkh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        Ok(TransparentAddress::PublicKeyHash(data))
    }

    fn try_from_transparent_p2sh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, zcash_address::ConversionError<Self::Error>> {
        Ok(TransparentAddress::ScriptHash(data))
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::{any, prop_compose};

    use super::TransparentAddress;

    prop_compose! {
        pub fn arb_transparent_addr()(v in proptest::array::uniform20(any::<u8>())) -> TransparentAddress {
            TransparentAddress::PublicKeyHash(v)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TransparentAddress;
    use zcash_script::{pattern::IdentifiedScriptPubKey, script};

    #[test]
    fn p2pkh() {
        let addr = TransparentAddress::PublicKeyHash([4; 20]);
        assert_eq!(
            addr.script(),
            script::PubKey(
                IdentifiedScriptPubKey::P2PKH([
                    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                ])
                .serialize()
            )
        );
        assert_eq!(
            TransparentAddress::from_script_pubkey(&addr.script()),
            Some(addr)
        );
    }

    #[test]
    fn p2sh() {
        let addr = TransparentAddress::ScriptHash([7; 20]);
        assert_eq!(
            addr.script(),
            script::PubKey(
                IdentifiedScriptPubKey::P2SH([
                    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                ])
                .serialize()
            )
        );
        assert_eq!(
            TransparentAddress::from_script_pubkey(&addr.script()),
            Some(addr)
        );
    }
}
