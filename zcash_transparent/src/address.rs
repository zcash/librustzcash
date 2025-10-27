//! Support for legacy transparent addresses and scripts.

use core::fmt;
use core2::io::{self, Read, Write};

use zcash_address::{ToAddress, TryFromAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

use zcash_encoding::Vector;
use zcash_script::{
    op,
    script::{self, Evaluable},
    solver,
};

#[cfg(feature = "transparent-inputs")]
use sha2::{Digest, Sha256};

/// A serialized script, used inside transparent inputs and outputs of a transaction.
#[derive(Clone)]
pub struct Script(pub script::Code);

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct ScriptPrinter<'s>(&'s script::Code);
        impl fmt::Debug for ScriptPrinter<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut l = f.debug_list();
                for b in self.0.parse() {
                    l.entry(&b);
                }
                l.finish()
            }
        }

        if f.alternate() {
            f.debug_tuple("Script")
                .field(&ScriptPrinter(&self.0))
                .finish()
        } else {
            f.debug_tuple("Script")
                .field(&hex::encode(&self.0.0))
                .finish()
        }
    }
}

impl Default for Script {
    fn default() -> Self {
        Self(script::Code(vec![]))
    }
}

impl PartialEq for Script {
    fn eq(&self, other: &Self) -> bool {
        self.0.0 == other.0.0
    }
}

impl Eq for Script {}

impl Script {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let script = Vector::read(&mut reader, |r| {
            let mut bytes = [0; 1];
            r.read_exact(&mut bytes).map(|_| bytes[0])
        })?;
        Ok(Script(script::Code(script)))
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write(&mut writer, &self.0.0, |w, e| w.write_all(&[*e]))
    }

    /// Returns the length of this script as encoded (including the initial CompactSize).
    pub fn serialized_size(&self) -> usize {
        Vector::serialized_size_of_u8_vec(&self.0.0)
    }
}

impl From<script::FromChain> for Script {
    fn from(value: script::FromChain) -> Self {
        Self(script::Code(value.to_bytes()))
    }
}

impl From<&script::FromChain> for Script {
    fn from(value: &script::FromChain) -> Self {
        Self(script::Code(value.to_bytes()))
    }
}

impl From<script::PubKey> for Script {
    fn from(value: script::PubKey) -> Self {
        Self(script::Code(value.to_bytes()))
    }
}

impl From<&script::PubKey> for Script {
    fn from(value: &script::PubKey) -> Self {
        Self(script::Code(value.to_bytes()))
    }
}

impl From<script::Sig> for Script {
    fn from(value: script::Sig) -> Self {
        Self(script::Code(value.to_bytes()))
    }
}

impl From<&script::Sig> for Script {
    fn from(value: &script::Sig) -> Self {
        Self(script::Code(value.to_bytes()))
    }
}

/// A transparent address corresponding to either a public key hash or a script hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransparentAddress {
    PublicKeyHash([u8; 20]),
    ScriptHash([u8; 20]),
}

impl core::fmt::Debug for TransparentAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyHash(arg0) => f
                .debug_tuple("PublicKeyHash")
                .field(&hex::encode(arg0))
                .finish(),
            Self::ScriptHash(arg0) => f
                .debug_tuple("ScriptHash")
                .field(&hex::encode(arg0))
                .finish(),
        }
    }
}

impl TransparentAddress {
    /// Returns the address that this Script contains, if any.
    ///
    /// This is a helper method that handles the conversion between [`script::FromChain`]
    /// (which can contain opcodes that are invalid if executed but nevertheless valid to
    /// encode on chain) and [`script::PubKey`] (the subset of scripts that don't contain
    /// bad opcodes, which itself contains all scripts corresponding to transparent
    /// address encodings).
    pub fn from_script_from_chain(script: &script::FromChain) -> Option<Self> {
        Self::from_script_pubkey(&script.refine().ok()?)
    }

    /// Returns the address that this Script contains, if any.
    pub fn from_script_pubkey(script_pubkey: &script::PubKey) -> Option<Self> {
        solver::standard(script_pubkey).and_then(|script_kind| match script_kind {
            solver::ScriptKind::PubKeyHash { hash } => {
                Some(TransparentAddress::PublicKeyHash(hash))
            }
            solver::ScriptKind::ScriptHash { hash } => Some(TransparentAddress::ScriptHash(hash)),
            _ => None,
        })
    }

    /// Generate the `scriptPubKey` corresponding to this address.
    pub fn script(&self) -> script::PubKey {
        script::Component(match self {
            TransparentAddress::PublicKeyHash(key_id) => vec![
                // P2PKH script
                op::DUP,
                op::HASH160,
                op::push_value(&key_id[..]).expect("short enough"),
                op::EQUALVERIFY,
                op::CHECKSIG,
            ],

            TransparentAddress::ScriptHash(script_id) => vec![
                // P2SH script
                op::HASH160,
                op::push_value(&script_id[..]).expect("short enough"),
                op::EQUAL,
            ],
        })
    }

    /// Derives the P2PKH transparent address corresponding to the given pubkey.
    #[cfg(feature = "transparent-inputs")]
    pub fn from_pubkey(pubkey: &secp256k1::PublicKey) -> Self {
        Self::from_pubkey_bytes(&pubkey.serialize())
    }

    /// Derives the P2PKH transparent address corresponding to the given pubkey bytes.
    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn from_pubkey_bytes(pubkey: &[u8; 33]) -> Self {
        TransparentAddress::PublicKeyHash(
            *ripemd::Ripemd160::digest(Sha256::digest(pubkey)).as_ref(),
        )
    }

    /// Encodes this transparent address for the given network type.
    pub fn to_zcash_address(&self, net: NetworkType) -> ZcashAddress {
        match self {
            TransparentAddress::PublicKeyHash(data) => {
                ZcashAddress::from_transparent_p2pkh(net, *data)
            }
            TransparentAddress::ScriptHash(data) => ZcashAddress::from_transparent_p2sh(net, *data),
        }
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
    use zcash_script::script::Evaluable;

    #[test]
    fn p2pkh() {
        let addr = TransparentAddress::PublicKeyHash([4; 20]);
        assert_eq!(
            &addr.script().to_bytes(),
            &[
                0x76, 0xa9, 0x14, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x88, 0xac,
            ]
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
            addr.script().to_bytes(),
            &[
                0xa9, 0x14, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x87,
            ]
        );
        assert_eq!(
            TransparentAddress::from_script_pubkey(&addr.script()),
            Some(addr)
        );
    }
}
