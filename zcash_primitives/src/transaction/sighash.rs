use crate::legacy::Script;
use blake2b_simd::Hash as Blake2bHash;
use std::convert::TryInto;

use super::{
    components::{
        sapling::{self, GrothProofBytes},
        Amount,
    },
    sighash_v4::v4_signature_hash,
    sighash_v5::v5_signature_hash,
    Authorization, TransactionData, TxDigests, TxVersion,
};

#[cfg(feature = "zfuture")]
use crate::extensions::transparent::Precondition;

pub const SIGHASH_ALL: u32 = 1;
pub const SIGHASH_NONE: u32 = 2;
pub const SIGHASH_SINGLE: u32 = 3;
pub const SIGHASH_MASK: u32 = 0x1f;
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;

pub struct TransparentInput<'a> {
    index: usize,
    script_code: &'a Script,
    value: Amount,
}

impl<'a> TransparentInput<'a> {
    pub fn new(index: usize, script_code: &'a Script, value: Amount) -> Self {
        TransparentInput {
            index,
            script_code,
            value,
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn script_code(&self) -> &'a Script {
        self.script_code
    }

    pub fn value(&self) -> Amount {
        self.value
    }
}

#[cfg(feature = "zfuture")]
pub struct TzeInput<'a> {
    index: usize,
    precondition: &'a Precondition,
    value: Amount,
}

#[cfg(feature = "zfuture")]
impl<'a> TzeInput<'a> {
    pub fn new(index: usize, precondition: &'a Precondition, value: Amount) -> Self {
        TzeInput {
            index,
            precondition,
            value,
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn precondition(&self) -> &'a Precondition {
        self.precondition
    }

    pub fn value(&self) -> Amount {
        self.value
    }
}

pub enum SignableInput<'a> {
    Shielded,
    Transparent(TransparentInput<'a>),
    #[cfg(feature = "zfuture")]
    Tze(TzeInput<'a>),
}

impl<'a> SignableInput<'a> {
    pub fn transparent(index: usize, script_code: &'a Script, value: Amount) -> Self {
        SignableInput::Transparent(TransparentInput {
            index,
            script_code,
            value,
        })
    }

    #[cfg(feature = "zfuture")]
    pub fn tze(index: usize, precondition: &'a Precondition, value: Amount) -> Self {
        SignableInput::Tze(TzeInput {
            index,
            precondition,
            value,
        })
    }
}

pub struct SignatureHash(Blake2bHash);

impl AsRef<[u8; 32]> for SignatureHash {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref().try_into().unwrap()
    }
}

pub fn signature_hash<
    'a,
    SA: sapling::Authorization<Proof = GrothProofBytes>,
    A: Authorization<SaplingAuth = SA>,
>(
    tx: &TransactionData<A>,
    signable_input: SignableInput<'a>,
    txid_parts: &TxDigests<Blake2bHash>,
    hash_type: u32,
) -> SignatureHash {
    SignatureHash(match tx.version {
        TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => {
            v4_signature_hash(tx, signable_input, hash_type)
        }

        TxVersion::ZcashTxV5 => v5_signature_hash(tx, txid_parts, signable_input, hash_type),

        #[cfg(feature = "zfuture")]
        TxVersion::ZFuture => v5_signature_hash(tx, txid_parts, signable_input, hash_type),
    })
}
