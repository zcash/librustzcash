//! Structs representing transaction data scanned from the block chain by a wallet or
//! light client.

use pairing::bls12_381::{Bls12, Fr};
use zcash_primitives::{
    jubjub::{edwards, PrimeOrder},
    primitives::{Note, PaymentAddress},
    transaction::TxId,
};

/// A subset of a [`Transaction`] relevant to wallets and light clients.
///
/// [`Transaction`]: zcash_primitives::transaction::Transaction
pub struct WalletTx {
    pub txid: TxId,
    pub num_spends: usize,
    pub num_outputs: usize,
    pub shielded_spends: Vec<WalletShieldedSpend>,
    pub shielded_outputs: Vec<WalletShieldedOutput>,
}

/// A subset of a [`SpendDescription`] relevant to wallets and light clients.
///
/// [`SpendDescription`]: zcash_primitives::transaction::components::SpendDescription
pub struct WalletShieldedSpend {
    pub index: usize,
    pub nf: Vec<u8>,
}

/// A subset of an [`OutputDescription`] relevant to wallets and light clients.
///
/// [`OutputDescription`]: zcash_primitives::transaction::components::OutputDescription
pub struct WalletShieldedOutput {
    pub index: usize,
    pub cmu: Fr,
    pub epk: edwards::Point<Bls12, PrimeOrder>,
    pub account: usize,
    pub note: Note<Bls12>,
    pub to: PaymentAddress<Bls12>,
}
