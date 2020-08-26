//! Structs representing transaction data scanned from the block chain by a wallet or
//! light client.

use zcash_primitives::{
    keys::OutgoingViewingKey,
    merkle_tree::IncrementalWitness,
    primitives::{Diversifier, Note, PaymentAddress, Rseed},
    sapling::Node,
    transaction::{components::Amount, TxId},
};

/// A type-safe wrapper for account identifiers.
#[derive(Debug, Copy, Clone)]
pub struct AccountId(pub u32);

/// A subset of a [`Transaction`] relevant to wallets and light clients.
///
/// [`Transaction`]: zcash_primitives::transaction::Transaction
pub struct WalletTx {
    pub txid: TxId,
    pub index: usize,
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
    pub account: usize,
}

/// A subset of an [`OutputDescription`] relevant to wallets and light clients.
///
/// [`OutputDescription`]: zcash_primitives::transaction::components::OutputDescription
pub struct WalletShieldedOutput {
    pub index: usize,
    pub cmu: bls12_381::Scalar,
    pub epk: jubjub::ExtendedPoint,
    pub account: usize,
    pub note: Note,
    pub to: PaymentAddress,
    pub is_change: bool,
    pub witness: IncrementalWitness<Node>,
}

pub struct SpendableNote {
    pub diversifier: Diversifier,
    pub note_value: Amount,
    pub rseed: Rseed,
    pub witness: IncrementalWitness<Node>,
}

/// Describes a policy for which outgoing viewing key should be able to decrypt
/// transaction outputs.
///
/// For details on what transaction information is visible to the holder of an outgoing
/// viewing key, refer to [ZIP 310].
///
/// [ZIP 310]: https://zips.z.cash/zip-0310
pub enum OvkPolicy {
    /// Use the outgoing viewing key from the sender's [`ExtendedFullViewingKey`].
    ///
    /// Transaction outputs will be decryptable by the sender, in addition to the
    /// recipients.
    Sender,

    /// Use a custom outgoing viewing key. This might for instance be derived from a
    /// separate seed than the wallet's spending keys.
    ///
    /// Transaction outputs will be decryptable by the recipients, and whoever controls
    /// the provided outgoing viewing key.
    Custom(OutgoingViewingKey),

    /// Use no outgoing viewing key. Transaction outputs will be decryptable by their
    /// recipients, but not by the sender.
    Discard,
}
