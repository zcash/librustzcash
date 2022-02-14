//! Structs representing the components within Zcash transactions.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use std::fmt::Debug;
use std::io::{self, Read, Write};

use crate::legacy::Script;

use super::amount::Amount;

pub mod builder;

pub trait Authorization: Debug {
    type ScriptSig: Debug + Clone + PartialEq;
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Authorized;

impl Authorization for Authorized {
    type ScriptSig = Script;
}

pub trait MapAuth<A: Authorization, B: Authorization> {
    fn map_script_sig(&self, s: A::ScriptSig) -> B::ScriptSig;
    fn map_authorization(&self, s: A) -> B;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bundle<A: Authorization> {
    pub vin: Vec<TxIn<A>>,
    pub vout: Vec<TxOut>,
    pub authorization: A,
}

impl<A: Authorization> Bundle<A> {
    /// Returns `true` if this bundle matches the definition of a coinbase transaction.
    ///
    /// Note that this is defined purely in terms of the transparent transaction part. The
    /// consensus rules enforce additional rules on the shielded parts (namely, that they
    /// don't have any inputs) of transactions with a transparent part that matches this
    /// definition.
    pub fn is_coinbase(&self) -> bool {
        // From `CTransaction::IsCoinBase()` in zcashd:
        //   return (vin.size() == 1 && vin[0].prevout.IsNull());
        matches!(&self.vin[..], [input] if input.prevout.is_null())
    }

    pub fn map_authorization<B: Authorization, F: MapAuth<A, B>>(self, f: F) -> Bundle<B> {
        Bundle {
            vin: self
                .vin
                .into_iter()
                .map(|txin| TxIn {
                    prevout: txin.prevout,
                    script_sig: f.map_script_sig(txin.script_sig),
                    sequence: txin.sequence,
                })
                .collect(),
            vout: self.vout,
            authorization: f.map_authorization(self.authorization),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OutPoint {
    hash: [u8; 32],
    n: u32,
}

impl OutPoint {
    pub fn new(hash: [u8; 32], n: u32) -> Self {
        OutPoint { hash, n }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;
        let n = reader.read_u32::<LittleEndian>()?;
        Ok(OutPoint { hash, n })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.hash)?;
        writer.write_u32::<LittleEndian>(self.n)
    }

    /// Returns `true` if this `OutPoint` is "null" in the Bitcoin sense: it points to the
    /// `u32::MAX`th output of the transaction with the all-zeroes txid.
    fn is_null(&self) -> bool {
        // From `BaseOutPoint::IsNull()` in zcashd:
        //   return (hash.IsNull() && n == (uint32_t) -1);
        self.hash == [0; 32] && self.n == u32::MAX
    }

    pub fn n(&self) -> u32 {
        self.n
    }

    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TxIn<A: Authorization> {
    pub prevout: OutPoint,
    pub script_sig: A::ScriptSig,
    pub sequence: u32,
}

impl TxIn<Authorized> {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let prevout = OutPoint::read(&mut reader)?;
        let script_sig = Script::read(&mut reader)?;
        let sequence = reader.read_u32::<LittleEndian>()?;

        Ok(TxIn {
            prevout,
            script_sig,
            sequence,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.prevout.write(&mut writer)?;
        self.script_sig.write(&mut writer)?;
        writer.write_u32::<LittleEndian>(self.sequence)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TxOut {
    pub value: Amount,
    pub script_pubkey: Script,
}

impl TxOut {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let value = {
            let mut tmp = [0u8; 8];
            reader.read_exact(&mut tmp)?;
            Amount::from_nonnegative_i64_le_bytes(tmp)
        }
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "value out of range"))?;
        let script_pubkey = Script::read(&mut reader)?;

        Ok(TxOut {
            value,
            script_pubkey,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.value.to_i64_le_bytes())?;
        self.script_pubkey.write(&mut writer)
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::select;

    use crate::{legacy::Script, transaction::components::amount::testing::arb_nonnegative_amount};

    use super::{Authorized, Bundle, OutPoint, TxIn, TxOut};

    pub const VALID_OPCODES: [u8; 8] = [
        0x00, // OP_FALSE,
        0x51, // OP_1,
        0x52, // OP_2,
        0x53, // OP_3,
        0xac, // OP_CHECKSIG,
        0x63, // OP_IF,
        0x65, // OP_VERIF,
        0x6a, // OP_RETURN,
    ];

    prop_compose! {
        pub fn arb_outpoint()(hash in prop::array::uniform32(0u8..), n in 0..100u32) -> OutPoint {
            OutPoint::new(hash, n)
        }
    }

    prop_compose! {
        pub fn arb_script()(v in vec(select(&VALID_OPCODES[..]), 1..256)) -> Script {
            Script(v)
        }
    }

    prop_compose! {
        pub fn arb_txin()(
            prevout in arb_outpoint(),
            script_sig in arb_script(),
            sequence in any::<u32>()
        ) -> TxIn<Authorized> {
            TxIn { prevout, script_sig, sequence }
        }
    }

    prop_compose! {
        pub fn arb_txout()(value in arb_nonnegative_amount(), script_pubkey in arb_script()) -> TxOut {
            TxOut { value, script_pubkey }
        }
    }

    prop_compose! {
        pub fn arb_bundle()(
            vin in vec(arb_txin(), 0..10),
            vout in vec(arb_txout(), 0..10),
        ) -> Option<Bundle<Authorized>> {
            if vin.is_empty() && vout.is_empty() {
                None
            } else {
                Some(Bundle { vin, vout, authorization: Authorized })
            }
        }
    }
}
