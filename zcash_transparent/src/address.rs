//! Support for legacy transparent addresses and scripts.

use alloc::vec::Vec;
use core::fmt;
use core2::io::{self, Read, Write};

use zcash_address::TryFromAddress;
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
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Script(pub Vec<u8>);

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct ScriptPrinter<'s>(&'s [u8]);
        impl fmt::Debug for ScriptPrinter<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut l = f.debug_list();
                for b in script::Code(self.0).parse() {
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
                .field(&hex::encode(&self.0))
                .finish()
        }
    }
}

impl Script {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let script = Vector::read(&mut reader, |r| {
            let mut bytes = [0; 1];
            r.read_exact(&mut bytes).map(|_| bytes[0])
        })?;
        Ok(Script(script))
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Vector::write(&mut writer, &self.0, |w, e| w.write_all(&[*e]))
    }

    /// Returns the length of this script as encoded (including the initial CompactSize).
    pub fn serialized_size(&self) -> usize {
        Vector::serialized_size_of_u8_vec(&self.0)
    }
}

impl From<script::PubKey> for Script {
    fn from(value: script::PubKey) -> Self {
        Self(value.to_bytes())
    }
}

impl From<&script::PubKey> for Script {
    fn from(value: &script::PubKey) -> Self {
        Self(value.to_bytes())
    }
}

impl From<script::Sig> for Script {
    fn from(value: script::Sig) -> Self {
        Self(value.to_bytes())
    }
}

impl From<&script::Sig> for Script {
    fn from(value: &script::Sig) -> Self {
        Self(value.to_bytes())
    }
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
    use core::iter;

    use super::TransparentAddress;
    use zcash_script::{op, pattern, script};

    #[test]
    fn p2pkh() {
        let addr = TransparentAddress::PublicKeyHash([4; 20]);
        assert_eq!(
            addr.script(),
            script::Component(
                iter::empty()
                    .chain([op::DUP, op::HASH160])
                    .chain(pattern::equals(
                        pattern::push_160b_hash(&[
                            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                        ]),
                        true,
                    ))
                    .chain([op::CHECKSIG])
                    .collect()
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
            script::Component(
                iter::empty()
                    .chain([op::HASH160])
                    .chain(pattern::equals(
                        pattern::push_160b_hash(&[
                            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                        ]),
                        false,
                    ))
                    .collect()
            )
        );
        assert_eq!(
            TransparentAddress::from_script_pubkey(&addr.script()),
            Some(addr)
        );
    }
}
