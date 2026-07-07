//! A low-level variant of the Signer role, for dependency-constrained environments.

use crate::Pczt;

pub struct Signer {
    pczt: Pczt,
}

impl Signer {
    /// Instantiates the low-level Signer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Exposes the capability to sign the Ironwood spends.
    ///
    /// The bundle is parsed with a preverified signing parse that skips deriving each
    /// spend's `FullViewingKey` (an expensive step the spend authorization signature
    /// does not depend on). Callers that rely on the wire `fvk` bytes MUST have
    /// already run the full Verifier checks over the identical PCZT bytes: they are
    /// not validated here, and the signing closure sees each spend's `fvk` as `None`.
    ///
    /// The signing closure must not add, remove, or reorder actions. A well-behaved
    /// closure leaves the returned PCZT's wire `fvk` bytes unchanged; a violating one
    /// is detected and returns [`OrchardParseError::SigningClosureModifiedActions`],
    /// leaving the PCZT unmodified.
    #[cfg(feature = "orchard")]
    pub fn sign_ironwood_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<OrchardParseError>,
        F: FnOnce(&Pczt, &mut orchard::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let anchor = pczt.ironwood.anchor;
        let fvk_snapshot = snapshot_spend_fvks(&pczt.ironwood);
        let mut bundle = pczt
            .ironwood
            .clone()
            .into_ironwood_parsed_preverified_for_signing_allowing_missing_anchor()
            .map_err(OrchardParseError::Parse)?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.ironwood = crate::orchard::Bundle::serialize_from_preserving_anchor(bundle, anchor);
        restore_spend_fvks(&mut pczt.ironwood, &fvk_snapshot).map_err(E::from)?;

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the Orchard spends.
    ///
    /// The bundle is parsed with a preverified signing parse that skips deriving each
    /// spend's `FullViewingKey` (an expensive step the spend authorization signature
    /// does not depend on). Callers that rely on the wire `fvk` bytes MUST have
    /// already run the full Verifier checks over the identical PCZT bytes: they are
    /// not validated here, and the signing closure sees each spend's `fvk` as `None`.
    ///
    /// The signing closure must not add, remove, or reorder actions. A well-behaved
    /// closure leaves the returned PCZT's wire `fvk` bytes unchanged; a violating one
    /// is detected and returns [`OrchardParseError::SigningClosureModifiedActions`],
    /// leaving the PCZT unmodified.
    #[cfg(feature = "orchard")]
    pub fn sign_orchard_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<OrchardParseError>,
        F: FnOnce(&Pczt, &mut orchard::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let bundle_version = crate::orchard::orchard_bundle_version(&pczt.global)
            .ok_or(OrchardParseError::UnsupportedConsensusBranchId)?;
        let anchor = pczt.orchard.anchor;
        let fvk_snapshot = snapshot_spend_fvks(&pczt.orchard);
        let mut bundle = pczt
            .orchard
            .clone()
            .into_parsed_with_version_preverified_for_signing_allowing_missing_anchor(
                bundle_version,
            )
            .map_err(OrchardParseError::Parse)?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.orchard = crate::orchard::Bundle::serialize_from_preserving_anchor(bundle, anchor);
        restore_spend_fvks(&mut pczt.orchard, &fvk_snapshot).map_err(E::from)?;

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the Sapling spends.
    #[cfg(feature = "sapling")]
    pub fn sign_sapling_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<sapling::pczt::ParseError>,
        F: FnOnce(&Pczt, &mut sapling::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let mut bundle = pczt.sapling.clone().into_parsed()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.sapling = crate::sapling::Bundle::serialize_from(bundle);

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the transparent spends.
    #[cfg(feature = "transparent")]
    pub fn sign_transparent_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<transparent::pczt::ParseError>,
        F: FnOnce(&Pczt, &mut transparent::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let mut bundle = pczt.transparent.clone().into_parsed()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.transparent = crate::transparent::Bundle::serialize_from(bundle);

        Ok(Self { pczt })
    }

    /// Finishes the low-level Signer role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}

/// A by-position snapshot of each spend's wire `(rk, fvk)` bytes: the `fvk` that the
/// preverified signing parse drops and must restore, paired with the `rk` used as a
/// per-position tamper check. See [`restore_spend_fvks`].
#[cfg(feature = "orchard")]
type SpendFvkSnapshot = alloc::vec::Vec<([u8; 32], Option<[u8; 96]>)>;

/// Snapshots each action's spend `(rk, fvk)` wire bytes, by position, for
/// [`restore_spend_fvks`] to restore after serialization.
#[cfg(feature = "orchard")]
fn snapshot_spend_fvks(bundle: &crate::orchard::Bundle) -> SpendFvkSnapshot {
    bundle
        .actions()
        .iter()
        .map(|action| (action.spend.rk, action.spend.fvk))
        .collect()
}

/// Restores the wire `fvk` bytes from [`snapshot_spend_fvks`] into each spend by
/// position, after checking the signing closure did not resize or reorder the action
/// list.
///
/// Positional restore is only sound if each position still holds its original action,
/// so this checks the action count and each position's wire `rk` — the one
/// always-present spend field that pins an action's identity, since a nullifier can
/// be shared — against the snapshot before writing any `fvk`. On a mismatch it writes
/// nothing and returns [`OrchardParseError::SigningClosureModifiedActions`].
#[cfg(feature = "orchard")]
fn restore_spend_fvks(
    bundle: &mut crate::orchard::Bundle,
    snapshot: &SpendFvkSnapshot,
) -> Result<(), OrchardParseError> {
    // Reject a resized or reordered list before writing: a count change misaligns
    // every later `fvk`, and a reorder moves `rk`s off their snapshotted positions.
    if bundle.actions.len() != snapshot.len() {
        return Err(OrchardParseError::SigningClosureModifiedActions);
    }
    for (action, (rk, _)) in bundle.actions.iter().zip(snapshot) {
        if action.spend.rk != *rk {
            return Err(OrchardParseError::SigningClosureModifiedActions);
        }
    }
    for (action, (_, fvk)) in bundle.actions.iter_mut().zip(snapshot) {
        action.spend.fvk = *fvk;
    }
    Ok(())
}

/// Errors that can occur while parsing an Orchard-protocol bundle of a PCZT for
/// signing.
#[cfg(feature = "orchard")]
#[derive(Debug)]
pub enum OrchardParseError {
    /// The bundle data was structurally invalid.
    Parse(orchard::pczt::ParseError),
    /// The PCZT's consensus branch ID is unrecognized, or predates NU5 (under which
    /// the Orchard protocol is not supported).
    UnsupportedConsensusBranchId,
    /// A signing closure passed to [`Signer::sign_orchard_with`] or
    /// [`Signer::sign_ironwood_with`] added, removed, or reordered actions, which
    /// those methods forbid. The PCZT is left unmodified.
    SigningClosureModifiedActions,
}

#[cfg(feature = "orchard")]
impl From<orchard::pczt::ParseError> for OrchardParseError {
    fn from(e: orchard::pczt::ParseError) -> Self {
        OrchardParseError::Parse(e)
    }
}

#[cfg(all(test, feature = "orchard"))]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec::Vec;

    use crate::orchard::{Action, Bundle, EncCiphertext, NoteVersion, Output, Spend};

    use super::{OrchardParseError, restore_spend_fvks, snapshot_spend_fvks};

    #[test]
    fn restore_spend_fvks_preserves_duplicate_nullifiers_by_position() {
        let first_fvk = Some([7u8; 96]);
        let second_fvk = Some([9u8; 96]);
        // Shared nullifier, distinct `rk`s: proves the restore keys on position, not
        // the (here ambiguous) nullifier.
        let mut bundle = bundle_with_duplicate_nullifier_fvks([first_fvk, second_fvk]);
        let snapshot = snapshot_spend_fvks(&bundle);

        bundle.actions[0].spend.fvk = None;
        bundle.actions[1].spend.fvk = None;

        restore_spend_fvks(&mut bundle, &snapshot).expect("actions were not modified");

        assert_eq!(bundle.actions[0].spend.fvk, first_fvk);
        assert_eq!(bundle.actions[1].spend.fvk, second_fvk);
    }

    #[test]
    fn restore_spend_fvks_rejects_reordered_actions() {
        let first_fvk = Some([7u8; 96]);
        let second_fvk = Some([9u8; 96]);
        let mut bundle = bundle_with_duplicate_nullifier_fvks([first_fvk, second_fvk]);
        let snapshot = snapshot_spend_fvks(&bundle);

        // A signing closure swaps the two actions; their distinct wire `rk`s move too.
        bundle.actions.swap(0, 1);

        assert!(matches!(
            restore_spend_fvks(&mut bundle, &snapshot),
            Err(OrchardParseError::SigningClosureModifiedActions)
        ));
        // Left as the closure left it: `fvk`s were not restored onto swapped actions.
        assert_eq!(bundle.actions[0].spend.fvk, second_fvk);
        assert_eq!(bundle.actions[1].spend.fvk, first_fvk);
    }

    /// Returns a two-action bundle whose spends share a nullifier but carry
    /// distinct wire `rk`s and the given distinct `fvk`s.
    fn bundle_with_duplicate_nullifier_fvks(fvks: [Option<[u8; 96]>; 2]) -> Bundle {
        Bundle {
            actions: fvks
                .into_iter()
                .enumerate()
                // Distinct `rk` per action (`[10; 32]`, `[11; 32]`), shared
                // nullifier `[3; 32]`.
                .map(|(i, fvk)| Action {
                    cv_net: Some([0; 32]),
                    spend: Spend {
                        nullifier: [3u8; 32],
                        rk: [10 + i as u8; 32],
                        spend_auth_sig: None,
                        recipient: None,
                        value: None,
                        rho: None,
                        rseed: None,
                        fvk,
                        witness: None,
                        alpha: None,
                        zip32_derivation: None,
                        dummy_sk: None,
                        proprietary: BTreeMap::new(),
                    },
                    output: Output {
                        cmx: [0; 32],
                        ephemeral_key: [0; 32],
                        enc_ciphertext: EncCiphertext::Encrypted(Vec::new()),
                        out_ciphertext: Vec::new(),
                        recipient: None,
                        value: None,
                        rseed: None,
                        ock: None,
                        zip32_derivation: None,
                        user_address: Option::<String>::None,
                        proprietary: BTreeMap::new(),
                    },
                    rcv: None,
                })
                .collect(),
            flags: 0,
            value_sum: (0, false),
            anchor: Some([0; 32]),
            note_version: NoteVersion::V2,
            zkproof: None,
            bsk: None,
        }
    }
}
