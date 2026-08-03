//! Identification of a migration PCZT's REAL spends.
//!
//! Every Orchard action whose spend witness is still deferred is a real spend: the padded dummy
//! spends carry their (arbitrary) witnesses from build time, while ZIP 374 defers the real
//! spends' witnesses to proving. This is the single in-crate definition of that rule, used by the
//! wallet adapter's prover (which resolves the spends to tree positions) and by commit-time
//! extraction of [`MigrationTransaction::spend_nullifiers`]; the `zcash_client_sqlite` schema
//! migration that backfills the cache for pre-existing rows mirrors the same rule, anchored there
//! by a test against a builder-produced PCZT. The rule identifies nothing in a PROVEN PCZT —
//! proving installs the deferred witnesses — so post-commit consumers read the persisted cache
//! and never re-derive the real spends from stored bytes.
//!
//! [`MigrationTransaction::spend_nullifiers`]: crate::engine::MigrationTransaction::spend_nullifiers

use alloc::vec::Vec;
use core::fmt;

use orchard::note::Nullifier;

/// A PCZT that does not present a well-formed set of real spends.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealSpendError {
    /// A deferred-witness spend's nullifier field is not a valid Orchard nullifier, so the action
    /// is not one this crate could have built.
    MalformedNullifier {
        /// The offending action's index in action order.
        action_index: usize,
        /// The bytes that are not a nullifier.
        bytes: [u8; 32],
    },
    /// The Orchard bundle carries no deferred-witness spend at all.
    ///
    /// Every migration transaction spends at least one real note — a transfer its one funding
    /// note, a preparation transaction one or more — so an UNPROVEN migration PCZT always has
    /// one. A PCZT with none is either already proven (proving installs the deferred witnesses,
    /// after which the rule identifies nothing) or not a migration transaction at all.
    NoRealSpends,
}

impl fmt::Display for RealSpendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RealSpendError::MalformedNullifier {
                action_index,
                bytes,
            } => write!(
                f,
                "the nullifier of the spend of action {action_index} is not a valid Orchard \
                 nullifier: {bytes:?}"
            ),
            RealSpendError::NoRealSpends => {
                f.write_str("the PCZT has no deferred-witness Orchard spend")
            }
        }
    }
}

impl core::error::Error for RealSpendError {}

/// The `(action index, nullifier)` of each real spend of `pczt`'s Orchard bundle, in action order;
/// never empty.
///
/// Actions whose spend already carries a witness are the builder's padding dummies, and skipping
/// them IS the rule rather than a failure. What cannot be skipped silently is a bundle the rule
/// leaves nothing of, or a spend whose nullifier field is not a nullifier: both are reported as a
/// [`RealSpendError`] instead of yielding an answer that would read as "this transaction spends
/// nothing".
pub fn real_spend_nullifiers(pczt: &pczt::Pczt) -> Result<Vec<(usize, Nullifier)>, RealSpendError> {
    let real_spends = pczt
        .orchard()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, action)| action.spend().witness().is_none())
        .map(|(action_index, action)| {
            let bytes = *action.spend().nullifier();
            Option::<Nullifier>::from(Nullifier::from_bytes(&bytes))
                .map(|nf| (action_index, nf))
                .ok_or(RealSpendError::MalformedNullifier {
                    action_index,
                    bytes,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if real_spends.is_empty() {
        Err(RealSpendError::NoRealSpends)
    } else {
        Ok(real_spends)
    }
}
