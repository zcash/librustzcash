pub mod creator;

#[cfg(feature = "io-finalizer")]
pub mod io_finalizer;

pub mod verifier;

pub mod updater;

pub mod redactor;

#[cfg(feature = "prover")]
pub mod prover;

#[cfg(feature = "signer")]
pub mod signer;

pub mod low_level_signer;

pub mod combiner;

#[cfg(feature = "spend-finalizer")]
pub mod spend_finalizer;

#[cfg(feature = "tx-extractor")]
pub mod tx_extractor;

#[cfg(test)]
mod tests {
    #[cfg(feature = "tx-extractor")]
    #[test]
    fn extract_fails_on_empty() {
        use zcash_protocol::consensus::BranchId;

        use crate::roles::{
            creator::Creator,
            tx_extractor::{self, TransactionExtractor},
        };

        let pczt = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32]).build();

        // Extraction fails because we haven't run the IO Finalizer.
        // Extraction fails in Sapling because we happen to extract it before Orchard.
        assert!(matches!(
            TransactionExtractor::new(pczt).extract().unwrap_err(),
            tx_extractor::Error::Sapling(tx_extractor::SaplingError::Extract(
                sapling::pczt::TxExtractorError::MissingBindingSignatureSigningKey
            )),
        ));
    }

    #[cfg(feature = "io-finalizer")]
    #[test]
    fn io_finalizer_fails_on_empty() {
        use zcash_protocol::consensus::BranchId;

        use crate::roles::{
            creator::Creator,
            io_finalizer::{self, IoFinalizer},
        };

        let pczt = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32]).build();

        // IO finalization fails on spends because we happen to check them first.
        assert!(matches!(
            IoFinalizer::new(pczt).finalize_io().unwrap_err(),
            io_finalizer::Error::NoSpends,
        ));
    }
}
