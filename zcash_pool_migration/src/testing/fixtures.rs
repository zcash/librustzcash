//! Fixtures for this crate's own unit tests.
//!
//! Most of these are re-exported from [`zcash_pool_migration_memory`], the test-support crate; see
//! [`account_derivation`] for the one that cannot be.

pub(crate) use zcash_pool_migration_memory::{
    TARGET_HEIGHT, account, assert_every_spend_is_identifiable, regtest_network,
    shared_anchor_witnesses, single_note_witness, spend_signability, spending_key,
};

/// The ZIP 32 account derivation a wallet seeded with `seed` would report for the account
/// [`account`] views.
///
/// Defined here rather than re-exported like its siblings, and it is the boundary case that shows
/// where that line falls. `zcash_pool_migration_memory` links this crate as a library, while these
/// tests are a second compilation of it, so the two `AccountDerivation` types are distinct: passing
/// the memory crate's value to this build's `build_prep_tx` is a type error. Every sibling above
/// returns a type owned by another crate, so none of them has the problem.
pub(crate) fn account_derivation(seed: u64) -> crate::build::AccountDerivation {
    let mut seed_fingerprint = [0u8; 32];
    seed_fingerprint[..8].copy_from_slice(&seed.to_le_bytes());
    crate::build::AccountDerivation::new(
        zip32::fingerprint::SeedFingerprint::from_bytes(seed_fingerprint),
        zip32::AccountId::ZERO,
    )
}
