//! Instantiates the backend-agnostic
//! [`WalletWrite::expire_unmined_transaction`](zcash_client_backend::data_api::WalletWrite::expire_unmined_transaction)
//! scenarios for each shielded pool.

mod sapling {
    use zcash_client_backend::data_api::testing::{pool, sapling::SaplingPoolTester};

    use crate::testing::{BlockCache, db::TestDbFactory};

    #[test]
    fn expire_unmined_transaction_releases_inputs() {
        pool::expire_unmined_transaction_releases_inputs::<SaplingPoolTester>(
            TestDbFactory::default(),
            BlockCache::new(),
        )
    }

    #[test]
    fn expired_unmined_transaction_mined_later_spends_inputs() {
        pool::expired_unmined_transaction_mined_later_spends_inputs::<SaplingPoolTester>(
            TestDbFactory::default(),
            BlockCache::new(),
        )
    }

    #[test]
    fn expire_unmined_transaction_ignores_mined_and_unknown() {
        pool::expire_unmined_transaction_ignores_mined_and_unknown::<SaplingPoolTester>(
            TestDbFactory::default(),
            BlockCache::new(),
        )
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn expire_unmined_transaction_releases_transparent_inputs() {
        pool::expire_unmined_transaction_releases_transparent_inputs::<SaplingPoolTester, _>(
            TestDbFactory::default(),
            BlockCache::new(),
        )
    }
}

#[cfg(feature = "orchard")]
mod orchard {
    use zcash_client_backend::data_api::testing::{orchard::OrchardPoolTester, pool};

    use crate::testing::{BlockCache, db::TestDbFactory};

    #[test]
    fn expire_unmined_transaction_releases_inputs() {
        pool::expire_unmined_transaction_releases_inputs::<OrchardPoolTester>(
            TestDbFactory::default(),
            BlockCache::new(),
        )
    }

    #[test]
    fn expired_unmined_transaction_mined_later_spends_inputs() {
        pool::expired_unmined_transaction_mined_later_spends_inputs::<OrchardPoolTester>(
            TestDbFactory::default(),
            BlockCache::new(),
        )
    }

    #[test]
    fn expire_unmined_transaction_ignores_mined_and_unknown() {
        pool::expire_unmined_transaction_ignores_mined_and_unknown::<OrchardPoolTester>(
            TestDbFactory::default(),
            BlockCache::new(),
        )
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn expire_unmined_transaction_releases_transparent_inputs() {
        pool::expire_unmined_transaction_releases_transparent_inputs::<OrchardPoolTester, _>(
            TestDbFactory::default(),
            BlockCache::new(),
        )
    }
}
