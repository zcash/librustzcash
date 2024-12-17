use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::Pczt;

pub struct Combiner {
    pczts: Vec<Pczt>,
}

impl Combiner {
    /// Instantiates the Combiner role with the given PCZTs.
    pub fn new(pczts: Vec<Pczt>) -> Self {
        Self { pczts }
    }

    /// Combines the PCZTs.
    pub fn combine(self) -> Result<Pczt, Error> {
        self.pczts
            .into_iter()
            .try_fold(None, |acc, pczt| match acc {
                None => Ok(Some(pczt)),
                Some(acc) => merge(acc, pczt).map(Some),
            })
            .transpose()
            .unwrap_or(Err(Error::NoPczts))
    }
}

fn merge(lhs: Pczt, rhs: Pczt) -> Result<Pczt, Error> {
    // Per-protocol bundles are merged first, because each is only interpretable in the
    // context of its own global.
    let transparent = lhs
        .transparent
        .merge(rhs.transparent, &lhs.global, &rhs.global)
        .ok_or(Error::DataMismatch)?;
    let sapling = lhs
        .sapling
        .merge(rhs.sapling, &lhs.global, &rhs.global)
        .ok_or(Error::DataMismatch)?;
    let orchard = lhs
        .orchard
        .merge(rhs.orchard, &lhs.global, &rhs.global)
        .ok_or(Error::DataMismatch)?;

    // Now that the per-protocol bundles are merged, merge the globals.
    let global = lhs.global.merge(rhs.global).ok_or(Error::DataMismatch)?;

    Ok(Pczt {
        global,
        transparent,
        sapling,
        orchard,
    })
}

/// Merges two values for an optional field together.
///
/// Returns `false` if the values cannot be merged.
pub(crate) fn merge_optional<T: PartialEq>(lhs: &mut Option<T>, rhs: Option<T>) -> bool {
    match (&lhs, rhs) {
        // If the RHS is not present, keep the LHS.
        (_, None) => (),
        // If the LHS is not present, set it to the RHS.
        (None, Some(rhs)) => *lhs = Some(rhs),
        // If both are present and are equal, nothing to do.
        (Some(lhs), Some(rhs)) if lhs == &rhs => (),
        // If both are present and are not equal, fail. Here we differ from BIP 174.
        (Some(_), Some(_)) => return false,
    }

    // Success!
    true
}

/// Merges two maps together.
///
/// Returns `false` if the values cannot be merged.
pub(crate) fn merge_map<K: Ord, V: PartialEq>(
    lhs: &mut BTreeMap<K, V>,
    rhs: BTreeMap<K, V>,
) -> bool {
    for (key, rhs_value) in rhs.into_iter() {
        if let Some(lhs_value) = lhs.get_mut(&key) {
            // If the key is present in both maps, and their values are not equal, fail.
            // Here we differ from BIP 174.
            if lhs_value != &rhs_value {
                return false;
            }
        } else {
            lhs.insert(key, rhs_value);
        }
    }

    // Success!
    true
}

/// Errors that can occur while combining PCZTs.
#[derive(Debug)]
pub enum Error {
    NoPczts,
    DataMismatch,
}
