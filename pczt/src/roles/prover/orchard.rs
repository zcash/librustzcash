use orchard::circuit::ProvingKey;
use rand_core::OsRng;

use crate::{Pczt, common::AnchorRequirement};

impl super::Prover {
    pub fn create_orchard_proof(self, pk: &ProvingKey) -> Result<Self, OrchardError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        let mut parsed = orchard
            .into_parsed_with_version(
                crate::orchard::orchard_bundle_version(&global)
                    .ok_or(OrchardError::UnsupportedConsensusBranchId)?,
                AnchorRequirement::Required,
            )
            .map_err(OrchardError::Parser)?;

        crate::orchard::verify_witnesses_root_to_anchor(&parsed.bundle, *parsed.bundle.anchor())
            .map_err(OrchardError::InconsistentWitness)?;

        parsed
            .bundle
            .create_proof(pk, OsRng)
            .map_err(OrchardError::Prover)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard: parsed.reserialize(),
                ironwood,
            },
        })
    }

    pub fn create_ironwood_proof(self, pk: &ProvingKey) -> Result<Self, IronwoodError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        let mut parsed = ironwood
            .into_ironwood_parsed(AnchorRequirement::Required)
            .map_err(IronwoodError::Parser)?;

        crate::orchard::verify_witnesses_root_to_anchor(&parsed.bundle, *parsed.bundle.anchor())
            .map_err(IronwoodError::InconsistentWitness)?;

        parsed
            .bundle
            .create_proof(pk, OsRng)
            .map_err(IronwoodError::Prover)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
                ironwood: parsed.reserialize(),
            },
        })
    }
}

/// Errors that can occur while creating Orchard proofs for a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    /// A non-zero-valued spend's `witness` does not root to the bundle's anchor.
    InconsistentWitness(crate::orchard::AnchorConsistencyError),
    Parser(crate::orchard::ParseError),
    Prover(orchard::pczt::ProverError),
    /// The PCZT's consensus branch ID is unrecognized, or predates NU5 (under which
    /// the Orchard protocol is not supported).
    UnsupportedConsensusBranchId,
}

/// Errors that can occur while creating Ironwood proofs for a PCZT.
#[derive(Debug)]
pub enum IronwoodError {
    /// A non-zero-valued spend's `witness` does not root to the bundle's anchor.
    InconsistentWitness(crate::orchard::AnchorConsistencyError),
    Parser(crate::orchard::ParseError),
    Prover(orchard::pczt::ProverError),
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::OnceLock;

    use zcash_protocol::consensus::BranchId;

    use super::{IronwoodError, OrchardError};
    use crate::{orchard::testing::dummy_action, roles::creator::Creator, roles::prover::Prover};

    static PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

    fn proving_key() -> &'static orchard::circuit::ProvingKey {
        PROVING_KEY.get_or_init(|| {
            orchard::circuit::ProvingKey::build(
                orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2,
            )
        })
    }

    #[test]
    fn create_orchard_proof_fails_when_anchor_absent() {
        let mut pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build()
            .unwrap();
        pczt.orchard.actions.push(dummy_action());

        assert!(matches!(
            Prover::new(pczt).create_orchard_proof(proving_key()),
            Err(OrchardError::Parser(
                crate::orchard::ParseError::MissingAnchor
            ))
        ));
    }

    #[test]
    fn create_ironwood_proof_fails_when_anchor_absent() {
        let mut pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build()
            .unwrap();
        pczt.ironwood.actions.push(dummy_action());

        assert!(matches!(
            Prover::new(pczt).create_ironwood_proof(proving_key()),
            Err(IronwoodError::Parser(
                crate::orchard::ParseError::MissingAnchor
            ))
        ));
    }

    /// An untouched, empty Orchard bundle has no actions, so parsing substitutes a
    /// placeholder anchor even though the Prover requires the anchor to be set. Proving
    /// such a bundle is a no-op, but the wire anchor must stay absent afterwards.
    #[test]
    fn create_orchard_proof_preserves_absent_anchor_for_untouched_bundle() {
        let pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build()
            .unwrap();

        let pczt = Prover::new(pczt)
            .create_orchard_proof(proving_key())
            .unwrap()
            .finish();

        assert_eq!(pczt.orchard, crate::orchard::EMPTY_ORCHARD);

        let bytes = pczt.clone().serialize().unwrap();
        assert_eq!(
            crate::parse(&bytes).unwrap().orchard,
            crate::orchard::EMPTY_ORCHARD
        );
    }

    /// See [`create_orchard_proof_preserves_absent_anchor_for_untouched_bundle`].
    #[test]
    fn create_ironwood_proof_preserves_absent_anchor_for_untouched_bundle() {
        let pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build()
            .unwrap();

        let pczt = Prover::new(pczt)
            .create_ironwood_proof(proving_key())
            .unwrap()
            .finish();

        assert_eq!(pczt.ironwood, crate::orchard::EMPTY_IRONWOOD);

        let bytes = pczt.clone().serialize().unwrap();
        assert_eq!(
            crate::parse(&bytes).unwrap().ironwood,
            crate::orchard::EMPTY_IRONWOOD
        );
    }
}
