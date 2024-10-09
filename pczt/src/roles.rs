pub mod creator;

pub mod combiner;

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

        // Extraction fails in Sapling because we happen to extract it before Orchard.
        assert!(matches!(
            TransactionExtractor::new(pczt).extract().unwrap_err(),
            tx_extractor::Error::Sapling(tx_extractor::SaplingError::MissingBsk),
        ));
    }
}
