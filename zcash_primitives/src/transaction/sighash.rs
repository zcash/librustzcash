use blake2b_simd::Hash as Blake2bHash;

use crate::{consensus::BranchId, legacy::Script};

#[cfg(feature = "zfuture")]
use crate::extensions::transparent::Precondition;

use super::{
    components::Amount, sighash_v4::v4_signature_hash, sighash_v5::SignatureHashDigester,
    txid::to_hash, TransactionData, TxDigests, TxId, TxVersion,
};

pub const SIGHASH_ALL: u32 = 1;
pub const SIGHASH_NONE: u32 = 2;
pub const SIGHASH_SINGLE: u32 = 3;
pub const SIGHASH_MASK: u32 = 0x1f;
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;

pub enum SignableInput<'a> {
    Shielded,
    Transparent {
        index: usize,
        script_code: &'a Script,
        value: Amount,
    },
    #[cfg(feature = "zfuture")]
    Tze {
        index: usize,
        precondition: &'a Precondition,
        value: Amount,
    },
}

impl<'a> SignableInput<'a> {
    pub fn transparent(index: usize, script_code: &'a Script, value: Amount) -> Self {
        SignableInput::Transparent {
            index,
            script_code,
            value,
        }
    }

    #[cfg(feature = "zfuture")]
    pub fn tze(index: usize, precondition: &'a Precondition, value: Amount) -> Self {
        SignableInput::Tze {
            index,
            precondition,
            value,
        }
    }
}

pub struct SignatureHash(Blake2bHash);

impl AsRef<[u8]> for SignatureHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub fn signature_hash<'a, F>(
    tx: &TransactionData,
    consensus_branch_id: BranchId,
    hash_type: u32,
    signable_input: SignableInput<'a>,
    txid_digest: &mut F,
) -> SignatureHash
where
    F: FnMut(&TransactionData) -> TxDigests<Blake2bHash, TxId>,
{
    // the accepted signature hashes are dependent upon
    SignatureHash(match tx.version {
        TxVersion::Sprout(_) | TxVersion::Overwinter | TxVersion::Sapling => {
            v4_signature_hash(tx, consensus_branch_id, hash_type, signable_input)
        }
        #[cfg(feature = "zfuture")]
        TxVersion::ZFuture => {
            let txid_parts = txid_digest(tx);
            let sig_parts = tx.digest(SignatureHashDigester {
                txid_parts,
                txversion: tx.version,
                hash_type,
                signable_input,
            });

            to_hash(&sig_parts, tx.version, consensus_branch_id)
        }
    })
}
