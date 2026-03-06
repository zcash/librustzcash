use crate::testing::{MemBlockCache, TestMemDbFactory};

#[test]
#[ignore] //FIXME
fn put_received_transparent_utxo() {
    zcash_client_backend::data_api::testing::transparent::put_received_transparent_utxo(
        TestMemDbFactory::new(),
        zcash_client_backend::data_api::testing::transparent::TransparentAccountType::Derived,
    );
}

#[test]
#[ignore] //FIXME
fn transparent_balance_across_shielding() {
    zcash_client_backend::data_api::testing::transparent::transparent_balance_across_shielding(
        TestMemDbFactory::new(),
        MemBlockCache::new(),
    );
}
