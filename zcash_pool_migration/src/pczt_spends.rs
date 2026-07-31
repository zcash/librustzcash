//! Identification of a migration PCZT's REAL spends.
//!
//! Every Orchard action whose spend witness is still deferred is a real spend: the padded dummy
//! spends carry their (arbitrary) witnesses from build time, while ZIP 374 defers the real
//! spends' witnesses to proving. This is the single in-crate definition of that rule, used by the
//! wallet adapter's prover (which resolves the spends to tree positions) and by commit-time
//! extraction of [`MigrationTransaction::spend_nullifiers`]; the `zcash_client_sqlite` schema
//! migration that backfills the cache for pre-existing rows mirrors the same rule, anchored there
//! by a test against a builder-produced PCZT.
//!
//! [`MigrationTransaction::spend_nullifiers`]: crate::engine::MigrationTransaction::spend_nullifiers

use alloc::vec::Vec;

/// The `(action index, nullifier bytes)` of each real spend of `pczt`'s Orchard bundle, in action
/// order.
pub(crate) fn real_spend_nullifiers(pczt: &pczt::Pczt) -> Vec<(usize, [u8; 32])> {
    pczt.orchard()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, action)| action.spend().witness().is_none())
        .map(|(index, action)| (index, *action.spend().nullifier()))
        .collect()
}
