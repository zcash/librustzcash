//! Structs representing transaction data scanned from the block chain by a wallet or
//! light client.

use subtle::{Choice, ConditionallySelectable};

use zcash_primitives::{
    merkle_tree::IncrementalWitness,
    sapling::{
        keys::OutgoingViewingKey, Diversifier, Node, Note, Nullifier, PaymentAddress, Rseed,
    },
    transaction::{components::Amount, TxId},
};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::{
    consensus::BlockHeight, legacy::TransparentAddress, transaction::components::OutPoint,
};

/// A type-safe wrapper for account identifiers.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct AccountId(pub u32);

impl Default for AccountId {
    fn default() -> Self {
        AccountId(0)
    }
}

impl ConditionallySelectable for AccountId {
    fn conditional_select(a0: &Self, a1: &Self, c: Choice) -> Self {
        AccountId(u32::conditional_select(&a0.0, &a1.0, c))
    }
}

/// A subset of a [`Transaction`] relevant to wallets and light clients.
///
/// [`Transaction`]: zcash_primitives::transaction::Transaction
pub struct WalletTx<N> {
    pub txid: TxId,
    pub index: usize,
    pub num_spends: usize,
    pub num_outputs: usize,
    pub shielded_spends: Vec<WalletShieldedSpend>,
    pub shielded_outputs: Vec<WalletShieldedOutput<N>>,
}

#[cfg(feature = "transparent-inputs")]
pub struct WalletTransparentOutput {
    pub address: TransparentAddress,
    pub outpoint: OutPoint,
    pub script: Vec<u8>,
    pub value: Amount,
    pub height: BlockHeight,
}

/// A subset of a [`SpendDescription`] relevant to wallets and light clients.
///
/// [`SpendDescription`]: zcash_primitives::transaction::components::SpendDescription
pub struct WalletShieldedSpend {
    pub index: usize,
    pub nf: Nullifier,
    pub account: AccountId,
}

/// A subset of an [`OutputDescription`] relevant to wallets and light clients.
///
/// [`OutputDescription`]: zcash_primitives::transaction::components::OutputDescription
pub struct WalletShieldedOutput<N> {
    pub index: usize,
    pub cmu: bls12_381::Scalar,
    pub epk: jubjub::ExtendedPoint,
    pub account: AccountId,
    pub note: Note,
    pub to: PaymentAddress,
    pub is_change: bool,
    pub witness: IncrementalWitness<Node>,
    pub nf: N,
}

/// Information about a note that is tracked by the wallet that is available for spending,
/// with sufficient information for use in note selection.
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
    ///
    /// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
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
