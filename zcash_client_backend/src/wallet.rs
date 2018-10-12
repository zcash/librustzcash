//! Structs representing transaction data scanned from the block chain by a wallet or
//! light client.

use pairing::bls12_381::{Bls12, Fr};
use zcash_primitives::{
    jubjub::{edwards, PrimeOrder},
    transaction::TxId,
};

pub struct EncCiphertextFrag(pub [u8; 52]);

/// A subset of a [`Transaction`] relevant to wallets and light clients.
///
/// [`Transaction`]: zcash_primitives::transaction::Transaction
pub struct WalletTx {
    pub txid: TxId,
    pub num_spends: usize,
    pub num_outputs: usize,
    pub shielded_outputs: Vec<WalletShieldedOutput>,
}

/// A subset of an [`OutputDescription`] relevant to wallets and light clients.
///
/// [`OutputDescription`]: zcash_primitives::transaction::components::OutputDescription
pub struct WalletShieldedOutput {
    pub index: usize,
    pub cmu: Fr,
    pub epk: edwards::Point<Bls12, PrimeOrder>,
    pub enc_ct: EncCiphertextFrag,
    pub account: usize,
    pub value: u64,
}
