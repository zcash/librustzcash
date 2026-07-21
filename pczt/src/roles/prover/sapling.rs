use rand_core::OsRng;
use sapling::prover::{OutputProver, SpendProver};

use crate::{Pczt, common::AnchorRequirement};

impl super::Prover {
    pub fn create_sapling_proofs<S, O>(
        self,
        spend_prover: &S,
        output_prover: &O,
    ) -> Result<Self, SaplingError>
    where
        S: SpendProver,
        O: OutputProver,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        let mut parsed = sapling
            .into_parsed(AnchorRequirement::Required)
            .map_err(SaplingError::Parser)?;

        crate::sapling::verify_witnesses_root_to_anchor(&parsed.bundle, *parsed.bundle.anchor())
            .map_err(SaplingError::InconsistentWitness)?;

        parsed
            .bundle
            .create_proofs(spend_prover, output_prover, OsRng)
            .map_err(SaplingError::Prover)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling: parsed.reserialize(),
                orchard,
                ironwood,
            },
        })
    }
}

/// Errors that can occur while creating Sapling proofs for a PCZT.
#[derive(Debug)]
pub enum SaplingError {
    /// A non-zero-valued spend's `witness` does not root to the bundle's anchor.
    InconsistentWitness(crate::sapling::AnchorConsistencyError),
    Parser(crate::sapling::ParseError),
    Prover(sapling::pczt::ProverError),
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use zcash_proofs::prover::LocalTxProver;
    use zcash_protocol::consensus::BranchId;

    use super::SaplingError;
    use crate::{roles::creator::Creator, roles::prover::Prover, sapling::Spend};

    #[test]
    fn create_sapling_proofs_fails_when_anchor_absent() {
        let mut pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build()
            .unwrap();
        // A non-empty bundle whose anchor is absent MUST be rejected with a typed
        // error before proving is attempted, rather than panicking.
        pczt.sapling.spends.push(Spend {
            cv: [1; 32],
            nullifier: [2; 32],
            rk: [3; 32],
            zkproof: None,
            spend_auth_sig: None,
            recipient: None,
            value: None,
            rcm: None,
            rseed: None,
            rcv: None,
            proof_generation_key: None,
            witness: None,
            alpha: None,
            zip32_derivation: None,
            dummy_ask: None,
            proprietary: BTreeMap::new(),
        });

        let prover = LocalTxProver::bundled();
        assert!(matches!(
            Prover::new(pczt).create_sapling_proofs(&prover, &prover),
            Err(SaplingError::Parser(
                crate::sapling::ParseError::MissingAnchor
            ))
        ));
    }

    /// An untouched, empty Sapling bundle has no spends or outputs, so `into_parsed`
    /// substitutes a placeholder anchor for its absent one even though the Prover
    /// requires the anchor to be set. Proving such a bundle is a no-op, but the wire
    /// anchor MUST stay absent afterwards rather than picking up the placeholder, so
    /// that the bundle remains canonically empty.
    #[test]
    fn create_sapling_proofs_preserves_absent_anchor_for_untouched_bundle() {
        let pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build()
            .unwrap();

        let prover = LocalTxProver::bundled();
        let pczt = Prover::new(pczt)
            .create_sapling_proofs(&prover, &prover)
            .unwrap()
            .finish();

        assert_eq!(pczt.sapling, crate::sapling::EMPTY_BUNDLE);

        let bytes = pczt.clone().serialize().unwrap();
        assert_eq!(
            crate::parse(&bytes).unwrap().sapling,
            crate::sapling::EMPTY_BUNDLE
        );
    }
}
