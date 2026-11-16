//! Structs representing the components within Zcash transactions.

use alloc::vec::Vec;
use core::fmt::{self, Debug};
use zcash_script::{script, solver};

use zcash_protocol::value::Zatoshis;

use crate::{
    address::{Script, TransparentAddress},
    sighash::TransparentAuthorizingContext,
};

pub trait Authorization: Debug {
    type ScriptSig: Debug + Clone + PartialEq;
}

/// Marker type for a bundle that contains no authorizing data, and the necessary input
/// information for creating sighashes.
#[derive(Debug)]
pub struct EffectsOnly {
    pub(crate) inputs: Vec<TxOut>,
}

impl Authorization for EffectsOnly {
    type ScriptSig = ();
}

impl TransparentAuthorizingContext for EffectsOnly {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.inputs.iter().map(|input| input.value()).collect()
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.inputs
            .iter()
            .map(|input| input.script_pubkey().clone())
            .collect()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Authorized;

impl Authorization for Authorized {
    type ScriptSig = Script;
}

pub trait MapAuth<A: Authorization, B: Authorization> {
    fn map_script_sig(&self, s: A::ScriptSig) -> B::ScriptSig;
    fn map_authorization(&self, s: A) -> B;
}

/// The identity map.
impl MapAuth<Authorized, Authorized> for () {
    fn map_script_sig(
        &self,
        s: <Authorized as Authorization>::ScriptSig,
    ) -> <Authorized as Authorization>::ScriptSig {
        s
    }

    fn map_authorization(&self, s: Authorized) -> Authorized {
        s
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bundle<A: Authorization> {
    pub vin: Vec<TxIn<A>>,
    pub vout: Vec<TxOut>,
    pub authorization: A,
}

impl<A: Authorization> Bundle<A> {
    #[allow(deprecated)]
    pub fn map_authorization<B: Authorization, F: MapAuth<A, B>>(self, f: F) -> Bundle<B> {
        Bundle {
            vin: self
                .vin
                .into_iter()
                .map(|txin| {
                    TxIn::from_parts(
                        txin.prevout,
                        f.map_script_sig(txin.script_sig),
                        txin.sequence,
                    )
                })
                .collect(),
            vout: self.vout,
            authorization: f.map_authorization(self.authorization),
        }
    }
}

/// A pointer to a transparent Zcash transaction output.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    /// The txid of the transaction containing the output being pointed to.
    pub(crate) hash: [u8; 32],
    /// The index of the output being pointed to within its transaction.
    pub(crate) n: u32,
}

impl fmt::Debug for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The txid is shown as byte-reversed hex, which is the form that RPC methods and
        // block explorers use.
        let mut txid = self.hash;
        txid.reverse();
        f.debug_struct("OutPoint")
            .field("hash", &hex::encode(txid))
            .field("n", &self.n)
            .finish()
    }
}

impl OutPoint {
    /// Returns the null [`OutPoint`] in the Bitcoin sense:
    /// - the txid is set to all-zeroes, and
    /// - the output index is set to [`u32::MAX`].
    pub const NULL: OutPoint = OutPoint {
        hash: [0u8; 32],
        n: u32::MAX,
    };

    /// Constructs an `OutPoint` for the output at index `n` in the transaction
    /// with txid `hash`.
    ///
    /// `hash` is the txid in its internal byte order, as it appears in the transaction
    /// encoding. That is the reverse of the hex form that RPC methods and block explorers
    /// show.
    pub const fn new(hash: [u8; 32], n: u32) -> Self {
        OutPoint { hash, n }
    }

    /// Constructs a fake `OutPoint` for use in tests.
    #[cfg(any(test, feature = "test-dependencies"))]
    pub const fn fake() -> Self {
        OutPoint {
            hash: [1u8; 32],
            n: 1,
        }
    }

    /// Returns the output index of this `OutPoint`.
    pub fn n(&self) -> u32 {
        self.n
    }

    /// Returns the txid of the transaction containing this `OutPoint`, in internal byte
    /// order. That is the reverse of its displayed hex form.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TxIn<A: Authorization> {
    #[deprecated(since = "0.4.1", note = "use the prevout() accessor instead.")]
    pub prevout: OutPoint,
    #[deprecated(since = "0.4.1", note = "use the script_sig() accessor instead.")]
    pub script_sig: A::ScriptSig,
    #[deprecated(since = "0.4.1", note = "use the sequence() accessor instead.")]
    pub sequence: u32,
}

#[allow(deprecated)]
impl<A: Authorization> TxIn<A> {
    /// Constructs a new [`TxIn`] from its constituent parts.
    pub fn from_parts(prevout: OutPoint, script_sig: A::ScriptSig, sequence: u32) -> Self {
        Self {
            prevout,
            script_sig,
            sequence,
        }
    }

    /// Accessor for the previous transparent output that this input spends.
    pub fn prevout(&self) -> &OutPoint {
        &self.prevout
    }

    /// The signature being used to spend the input.
    pub fn script_sig(&self) -> &A::ScriptSig {
        &self.script_sig
    }

    /// The sequence number of the input (no Zcash protocol use as of NU6).
    pub fn sequence(&self) -> u32 {
        self.sequence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    #[deprecated(since = "0.4.1", note = "use the value() accessor instead.")]
    pub value: Zatoshis,
    #[deprecated(since = "0.4.1", note = "use the script_pubkey() accessor instead.")]
    pub script_pubkey: Script,
}

#[allow(deprecated)]
impl TxOut {
    // Constructs a new `TxOut` from its constituent parts.
    pub fn new(value: Zatoshis, script_pubkey: Script) -> Self {
        Self {
            value,
            script_pubkey,
        }
    }

    /// Returns the address to which the TxOut was sent, if this is a valid P2SH or P2PKH output.
    pub fn recipient_address(&self) -> Option<TransparentAddress> {
        self.script_kind()
            .as_ref()
            .and_then(TransparentAddress::from_script_kind)
    }

    pub fn value(&self) -> Zatoshis {
        self.value
    }

    pub fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }

    /// Returns the kind of script to which the TxOut was sent, if this is a valid output.
    pub fn script_kind(&self) -> Option<solver::ScriptKind> {
        script::PubKey::parse(&self.script_pubkey.0)
            .ok()
            .as_ref()
            .and_then(solver::standard)
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::select;
    use zcash_protocol::value::testing::arb_zatoshis;
    use zcash_script::script;

    use crate::address::Script;

    use super::{Authorized, Bundle, OutPoint, TxIn, TxOut};

    pub const VALID_OPCODES: [u8; 8] = [
        0x00, // OP_0,
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
        pub fn arb_script_sig()(v in vec(select(&VALID_OPCODES[..]), 1..256)) -> Script {
            Script(script::Code(v))
        }
    }

    prop_compose! {
        pub fn arb_script_pubkey()(v in vec(select(&VALID_OPCODES[..]), 1..256)) -> Script {
            Script(script::Code(v))
        }
    }

    prop_compose! {
        pub fn arb_txin()(
            prevout in arb_outpoint(),
            script_sig in arb_script_sig(),
            sequence in any::<u32>()
        ) -> TxIn<Authorized> {
            TxIn::from_parts(prevout, script_sig, sequence)
        }
    }

    prop_compose! {
        pub fn arb_txout()(value in arb_zatoshis(), script_pubkey in arb_script_pubkey()) -> TxOut {
            TxOut::new(value, script_pubkey)
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

#[cfg(test)]
mod tests {
    use super::OutPoint;

    /// The first byte of the txid in the test below. It is the last byte of the txid as
    /// displayed.
    const FIRST_TXID_BYTE: u8 = 0x01;

    /// The last byte of the txid in the test below. It is the first byte of the txid as
    /// displayed.
    const LAST_TXID_BYTE: u8 = 0xff;

    /// The output index in the test below.
    const OUTPUT_INDEX: u32 = 7;

    /// The number of zero bytes between the first and last bytes of the 32-byte txid.
    const MIDDLE_TXID_BYTES: usize = 30;

    #[test]
    fn outpoint_debug_shows_the_txid_as_byte_reversed_hex() {
        let mut hash = [0u8; 32];
        hash[0] = FIRST_TXID_BYTE;
        hash[hash.len() - 1] = LAST_TXID_BYTE;
        let outpoint = OutPoint::new(hash, OUTPUT_INDEX);

        assert_eq!(
            format!("{outpoint:?}"),
            format!(
                "OutPoint {{ hash: \"ff{}01\", n: {OUTPUT_INDEX} }}",
                "00".repeat(MIDDLE_TXID_BYTES)
            )
        );
    }
}
