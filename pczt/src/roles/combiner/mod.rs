//! The Combiner role (anyone can execute).
//!
//! - Combines several PCZTs that represent the same transaction into a single PCZT.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use zcash_protocol::constants::V5_TX_VERSION;

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
    // Whether the merge adds Sapling spends or outputs, or Orchard actions, to one of
    // the inputs. The Ironwood bundle is not present in v5 transactions.
    let adds_sapling = lhs.sapling.spends.len() != rhs.sapling.spends.len()
        || lhs.sapling.outputs.len() != rhs.sapling.outputs.len();
    let adds_orchard = lhs.orchard.actions.len() != rhs.orchard.actions.len();

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
    let ironwood = lhs
        .ironwood
        .merge(rhs.ironwood, &lhs.global, &rhs.global)
        .ok_or(Error::DataMismatch)?;

    // Now that the per-protocol bundles are merged, merge the globals.
    let global = lhs.global.merge(rhs.global).ok_or(Error::DataMismatch)?;

    // The anchors of a v5 transaction are transaction effecting data, so they cannot be
    // set after the PCZT is created, and a pool cannot gain spends, outputs or actions
    // without one.
    if global.tx_version == V5_TX_VERSION
        && ((adds_sapling && sapling.anchor.is_none())
            || (adds_orchard && orchard.anchor.is_none()))
    {
        return Err(Error::AnchorRequiredForV5);
    }

    Ok(Pczt {
        global,
        transparent,
        sapling,
        orchard,
        ironwood,
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
    /// The PCZTs describe a v5 transaction, and combining them would add Sapling spends
    /// or outputs, or Orchard actions, to a bundle whose anchor is absent. A v5
    /// transaction's anchors must be set by the Creator.
    AnchorRequiredForV5,
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::BranchId;

    use super::Combiner;
    use crate::{Pczt, roles::creator::Creator};

    fn create(
        branch_id: BranchId,
        sapling_anchor: Option<[u8; 32]>,
        orchard_anchor: Option<[u8; 32]>,
    ) -> Pczt {
        Creator::new(
            branch_id.into(),
            10_000_000,
            133,
            sapling_anchor,
            orchard_anchor,
        )
        .unwrap()
        .build()
        .unwrap()
    }

    #[test]
    fn v5_allows_absent_anchors_for_empty_bundles() {
        let pczt = create(BranchId::Nu6_2, None, None);
        let combined = Combiner::new(vec![pczt.clone(), pczt]).combine().unwrap();
        assert!(combined.sapling.anchor.is_none());
        assert!(combined.orchard.anchor.is_none());
    }

    #[cfg(feature = "sapling")]
    fn with_sapling_output(mut pczt: Pczt) -> Pczt {
        use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

        let recipient = sapling::zip32::ExtendedSpendingKey::master(&[0; 32])
            .expect("the derivation path yields a valid key")
            .to_diversifiable_full_viewing_key()
            .default_address()
            .1;
        let mut builder = sapling::builder::Builder::new(
            sapling::note_encryption::Zip212Enforcement::On,
            sapling::builder::BundleType::DEFAULT,
            sapling::Anchor::empty_tree(),
        );
        builder
            .add_output(
                None,
                recipient,
                sapling::value::NoteValue::from_raw(1),
                [0; 512],
            )
            .unwrap();
        let (bundle, _) = builder
            .build_for_pczt(ChaCha20Rng::from_seed([0; 32]))
            .unwrap();
        let bundle = crate::sapling::Bundle::serialize_from(bundle);
        pczt.sapling.outputs = bundle.outputs;
        pczt.sapling.value_sum = bundle.value_sum;
        pczt
    }

    #[cfg(feature = "sapling")]
    #[test]
    fn v5_rejects_sapling_additions_without_anchor() {
        let pczt = create(BranchId::Nu6_2, None, Some([0; 32]));
        let with_output = with_sapling_output(pczt.clone());
        assert!(matches!(
            Combiner::new(vec![pczt.clone(), with_output.clone()]).combine(),
            Err(super::Error::AnchorRequiredForV5)
        ));
        assert!(matches!(
            Combiner::new(vec![with_output, pczt]).combine(),
            Err(super::Error::AnchorRequiredForV5)
        ));
    }

    #[cfg(feature = "sapling")]
    #[test]
    fn sapling_additions_with_anchor_or_in_v6_are_allowed() {
        let anchor = sapling::Anchor::empty_tree().to_bytes();
        let pczt = create(BranchId::Nu6_2, Some(anchor), Some([0; 32]));
        let combined = Combiner::new(vec![pczt.clone(), with_sapling_output(pczt)])
            .combine()
            .unwrap();
        assert!(!combined.sapling.outputs.is_empty());
        assert_eq!(combined.sapling.anchor, Some(anchor));

        let pczt = create(BranchId::Nu6_3, None, None);
        let combined = Combiner::new(vec![pczt.clone(), with_sapling_output(pczt)])
            .combine()
            .unwrap();
        assert!(!combined.sapling.outputs.is_empty());
        assert!(combined.sapling.anchor.is_none());
    }

    #[cfg(all(
        feature = "orchard",
        any(feature = "prover", all(feature = "signer", feature = "io-finalizer"))
    ))]
    fn with_orchard_action(mut pczt: Pczt) -> Pczt {
        pczt.orchard
            .actions
            .push(crate::orchard::testing::dummy_action());
        pczt
    }

    #[cfg(all(
        feature = "orchard",
        any(feature = "prover", all(feature = "signer", feature = "io-finalizer"))
    ))]
    #[test]
    fn v5_rejects_orchard_additions_without_anchor() {
        let pczt = create(BranchId::Nu6_2, Some([0; 32]), None);
        assert!(matches!(
            Combiner::new(vec![pczt.clone(), with_orchard_action(pczt.clone())]).combine(),
            Err(super::Error::AnchorRequiredForV5)
        ));

        let pczt = create(BranchId::Nu6_2, Some([0; 32]), Some([0; 32]));
        let combined = Combiner::new(vec![pczt.clone(), with_orchard_action(pczt)])
            .combine()
            .unwrap();
        assert_eq!(combined.orchard.actions.len(), 1);

        let pczt = create(BranchId::Nu6_3, None, None);
        let combined = Combiner::new(vec![pczt.clone(), with_orchard_action(pczt)])
            .combine()
            .unwrap();
        assert_eq!(combined.orchard.actions.len(), 1);
        assert!(combined.orchard.anchor.is_none());
    }
}
