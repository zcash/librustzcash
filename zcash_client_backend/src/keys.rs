//! Helper functions for managing light client key material.

use zcash_primitives::zip32::{ChildIndex, ExtendedSpendingKey};

/// Derives the ZIP 32 [`ExtendedSpendingKey`] for a given coin type and account from the
/// given seed.
///
/// # Examples
///
/// ```
/// use zcash_client_backend::{constants::testnet::COIN_TYPE, keys::spending_key};
///
/// let extsk = spending_key(&[0; 32][..], COIN_TYPE, 0);
/// ```
pub fn spending_key(seed: &[u8], coin_type: u32, account: u32) -> ExtendedSpendingKey {
    ExtendedSpendingKey::from_path(
        &ExtendedSpendingKey::master(&seed),
        &[
            ChildIndex::Hardened(32),
            ChildIndex::Hardened(coin_type),
            ChildIndex::Hardened(account),
        ],
    )
}
