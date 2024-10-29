//! Sets the `is_change` flag on output notes received by an internal key when input value was
//! provided from the account corresponding to that key.
use std::collections::HashSet;

use rusqlite::named_params;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zip32::Scope;

use crate::{
    wallet::{
        init::{migrations::fix_broken_commitment_trees, WalletMigrationError},
        scope_code,
    },
    SAPLING_TABLES_PREFIX,
};

#[cfg(feature = "orchard")]
use crate::ORCHARD_TABLES_PREFIX;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x6d36656d_533b_4b65_ae91_dcb95c4ad289);

const DEPENDENCIES: &[Uuid] = &[fix_broken_commitment_trees::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Sets the `is_change` flag on output notes received by an internal key when input value was provided from the account corresponding to that key."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        let fix_change_flag = |table_prefix| {
            transaction.execute(
                &format!(
                    "UPDATE {table_prefix}_received_notes
                     SET is_change = 1
                     FROM sent_notes sn
                     WHERE sn.tx = {table_prefix}_received_notes.tx
                     AND sn.from_account_id = {table_prefix}_received_notes.account_id
                     AND {table_prefix}_received_notes.recipient_key_scope = :internal_scope"
                ),
                named_params! {":internal_scope": scope_code(Scope::Internal)},
            )
        };

        fix_change_flag(SAPLING_TABLES_PREFIX)?;
        #[cfg(feature = "orchard")]
        fix_change_flag(ORCHARD_TABLES_PREFIX)?;

        Ok(())
    }

    fn down(&self, _: &rusqlite::Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::{
            testing::{db::TestDbFactory, BlockCache},
            wallet::init::init_wallet_db,
        },
        zcash_client_backend::{
            data_api::{
                testing::{
                    pool::ShieldedPoolTester, sapling::SaplingPoolTester, AddressType, TestBuilder,
                },
                wallet::input_selection::GreedyInputSelector,
                Account as _, WalletRead as _, WalletWrite as _,
            },
            fees::{standard, DustOutputPolicy, StandardFeeRule},
            wallet::WalletTransparentOutput,
        },
        zcash_primitives::{
            block::BlockHash,
            transaction::components::{OutPoint, TxOut},
        },
        zcash_protocol::value::Zatoshis,
    };

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    #[cfg(feature = "transparent-inputs")]
    async fn shield_transparent<T: ShieldedPoolTester>() {
        let ds_factory = TestDbFactory::new(super::DEPENDENCIES.to_vec());
        let cache = BlockCache::new().await;
        let mut st = TestBuilder::new()
            .with_data_store_factory(ds_factory)
            .with_block_cache(cache)
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = T::test_account_fvk(&st);

        let uaddr = st
            .wallet()
            .get_current_address(account.id())
            .unwrap()
            .unwrap();
        let taddr = uaddr.transparent().unwrap();

        // Ensure that the wallet has at least one block
        let (h, _, _) = st
            .generate_next_block(
                &dfvk,
                AddressType::Internal,
                Zatoshis::const_from_u64(50000),
            )
            .await;
        st.scan_cached_blocks(h, 1).await;

        let utxo = WalletTransparentOutput::from_parts(
            OutPoint::fake(),
            TxOut {
                value: Zatoshis::const_from_u64(100000),
                script_pubkey: taddr.script(),
            },
            Some(h),
        )
        .unwrap();

        let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
        assert_matches!(res0, Ok(_));

        let fee_rule = StandardFeeRule::Zip317;

        let input_selector = GreedyInputSelector::new();
        let change_strategy = standard::SingleOutputChangeStrategy::new(
            fee_rule,
            None,
            T::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );

        let txids = st
            .shield_transparent_funds(
                &input_selector,
                &change_strategy,
                Zatoshis::from_u64(10000).unwrap(),
                account.usk(),
                &[*taddr],
                account.id(),
                1,
            )
            .unwrap();
        assert_eq!(txids.len(), 1);

        let tx = st.get_tx_from_history(*txids.first()).unwrap().unwrap();
        assert_eq!(tx.spent_note_count(), 1);
        assert!(tx.has_change());
        assert_eq!(tx.received_note_count(), 0);
        assert_eq!(tx.sent_note_count(), 0);
        assert!(tx.is_shielding());

        // Prior to the fix that removes the source of the error this migration is addressing,
        // this scanning will result in a state where `tx.is_shielding() == false`. However,
        // we can't validate that here, because after that fix, this test would fail.
        let (h, _) = st.generate_next_block_including(*txids.first()).await;
        st.scan_cached_blocks(h, 1).await;

        // Complete the migration to resolve the incorrect change flag value.
        init_wallet_db(st.wallet_mut().db_mut(), None).unwrap();

        let tx = st.get_tx_from_history(*txids.first()).unwrap().unwrap();
        assert_eq!(tx.spent_note_count(), 1);
        assert!(tx.has_change());
        assert_eq!(tx.received_note_count(), 0);
        assert_eq!(tx.sent_note_count(), 0);
        assert!(tx.is_shielding());
    }

    #[tokio::test]
    #[cfg(feature = "transparent-inputs")]
    async fn sapling_shield_transparent() {
        shield_transparent::<SaplingPoolTester>().await;
    }

    #[tokio::test]
    #[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
    async fn orchard_shield_transparent() {
        use zcash_client_backend::data_api::testing::orchard::OrchardPoolTester;

        shield_transparent::<OrchardPoolTester>().await;
    }
}
