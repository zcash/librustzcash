//! End-to-end, real-proving chain simulation of a whole migration over a genuine wallet.
//!
//! This drives a real (in-memory) `zcash_client_sqlite` `WalletDb` through the
//! `zcash_client_backend` testing framework, exercising the migration engine's proving path against
//! the wallet's OWN Orchard commitment tree instead of a hand-built one:
//!
//! 1. fund an account with a spendable Orchard note and commit a migration over the
//!    [`WalletMigration`] adapter (so the plan, the prep transactions, and the transfers all come
//!    from the real wallet);
//! 2. prove each PREPARATION transaction against the chain tip (installing the source anchor and its
//!    spends' witnesses through the PCZT `Updater` role), extract it, mine it, and scan it — so its
//!    minted funding notes become genuinely scanned received notes with real tree positions;
//! 3. advance the chain to each TRANSFER's drawn anchor boundary and prove it (resolving the funding
//!    note's witness from the wallet's tree by the nullifier its spend reveals), extract it, and
//!    assert both its Orchard and Ironwood bundles verify.
//!
//! [`WalletMigrationProver`] resolves every spend's tree position from the wallet's own note store
//! (no hand-supplied map), so this test also covers that production lookup path. It keeps each
//! transfer's boundary within `zcash_client_sqlite`'s checkpoint pruning window (100 blocks of the
//! tip), so it needs no migration anchor-checkpoint retention (issue #2700), which is a wallet
//! backend concern out of the migration crate's control.
//!
//! Run with `--features wallet,test-dependencies` (the latter exposes
//! [`commit_preparation_with_funding`], which hands the test each transfer's funding note).
#![cfg(all(feature = "wallet", feature = "test-dependencies"))]

use std::convert::Infallible;

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

use pczt::roles::tx_extractor::TransactionExtractor;

use shardtree::error::ShardTreeError;
use zcash_client_backend::data_api::testing::{
    AddressType, TestBuilder, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
};
use zcash_client_backend::data_api::{Account, WalletCommitmentTrees, WalletRead};
// The wallet, block cache, and DB factory come from `zcash_client_sqlite`'s own test harness,
// exposed under its `test-dependencies` feature — no hand-rolled equivalents.
use zcash_client_sqlite::testing::BlockCache;
use zcash_client_sqlite::testing::db::{TestDb, TestDbFactory};

use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::local_consensus::LocalNetwork;
use zcash_protocol::value::{COIN, Zatoshis};

use zcash_pool_migration_backend::engine::{
    self, MigrationState, MigrationTxId, MigrationTxKind, MigrationTxState, PoolMigrationRead,
    PoolMigrationWrite,
};
use zcash_pool_migration_backend::wallet::{WalletMigration, WalletMigrationProver};

/// Every network upgrade (through NU6.3, which activates the Ironwood pool) is active from this
/// height, so a migration built at or above it is post-NU6.3 and its transfers cross into Ironwood.
const ACTIVATION: u32 = 100_000;
/// The account is funded with this many ZEC in a single Orchard note; large enough that the
/// note-split planner produces at least one preparation transaction and one pool-crossing transfer.
const FUNDING_ZEC: u64 = 78;
/// Empty blocks scanned after a note is received so its commitment-tree shard completes and an
/// anchor at that height is available.
const SHARD_COMPLETION_BLOCKS: usize = 5;

/// The highest checkpoint at or below `from` whose Orchard tree root is available. The tip
/// checkpoint is not yet rooted right after scanning, so a spend anchors to the newest settled
/// checkpoint below it (every note mined at or before that height is still witnessable there).
fn highest_rooted_checkpoint(db: &mut TestDb, from: BlockHeight) -> BlockHeight {
    let mut height = u32::from(from);
    loop {
        let bh = BlockHeight::from_u32(height);
        let rooted = db
            .with_orchard_tree_mut::<_, _, ShardTreeError<<TestDb as WalletCommitmentTrees>::Error>>(
                |tree| Ok(tree.root_at_checkpoint_id(&bh)?.is_some()),
            )
            .expect("queries the Orchard tree");
        if rooted {
            return bh;
        }
        assert!(height > ACTIVATION, "no rooted Orchard checkpoint exists");
        height -= 1;
    }
}

/// A network with every upgrade through NU6.3 active at [`ACTIVATION`].
fn nu63_network() -> LocalNetwork {
    let h = BlockHeight::from_u32(ACTIVATION);
    LocalNetwork {
        nu6: Some(h),
        nu6_1: Some(h),
        nu6_2: Some(h),
        nu6_3: Some(h),
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    }
}

/// A trivial in-memory migration store for the [`WalletMigration`] adapter. The chain simulation
/// drives proving through the engine's free functions (which mutate the in-memory
/// [`MigrationState`] directly), so only `replace_migration` (used by commit) is exercised.
#[derive(Default)]
struct MigrationTestStore {
    state: Option<MigrationState>,
}

impl PoolMigrationRead for MigrationTestStore {
    type Error = Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.state.clone())
    }
}

impl PoolMigrationWrite for MigrationTestStore {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.state = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        _id: MigrationTxId,
        _state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        // Not exercised: the chain simulation advances proving state through the engine's
        // `prove_preparation` / `prove_transfer` on the in-memory `MigrationState`, not the store.
        Ok(())
    }
}

#[test]
fn migration_proves_end_to_end_against_a_funded_wallet() {
    let network = nu63_network();

    let mut st = TestBuilder::new()
        .with_network(network)
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();

    let account = st.test_account().cloned().expect("the test account exists");
    let account_id = account.id();
    let usk = account.usk().clone();
    let fvk = OrchardPoolTester::test_account_fvk(&st);

    // Fund the account with a single spendable Orchard note, then let its shard complete so an
    // anchor is available at the tip.
    let funding = Zatoshis::const_from_u64(FUNDING_ZEC * COIN);
    let (fund_height, _, _) = st.generate_next_block(&fvk, AddressType::DefaultExternal, funding);
    st.scan_cached_blocks(fund_height, 1);
    assert_eq!(st.get_total_balance(account_id), funding);
    for _ in 0..SHARD_COMPLETION_BLOCKS {
        let (h, _) = st.generate_empty_block();
        st.scan_cached_blocks(h, 1);
    }

    // Commit a migration over the wallet adapter: the plan, the preparation transactions, and the
    // transfers all come from the real wallet's spendable notes.
    let tip = st
        .wallet()
        .chain_height()
        .expect("reads the chain height")
        .expect("the wallet has a chain tip");
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let (mut state, _funding_notes) = {
        let adapter =
            WalletMigration::new(st.wallet(), account_id, usk, MigrationTestStore::default());
        let plan =
            engine::plan_migration(&network, &adapter, &mut rng).expect("plans the migration");
        let mut adapter = adapter;
        engine::commit_preparation_with_funding(&network, tip, &mut adapter, &plan, &mut rng)
            .expect("commits the migration")
    };

    // Every transaction is Signed with anchors and witnesses deferred.
    for tx in state.transactions() {
        assert!(matches!(tx.state(), MigrationTxState::Signed));
    }

    // Prove each preparation transaction against the current tip, extract it, mine it, and scan it,
    // so its minted funding notes become spendable received notes in the wallet.
    let prep_ids: Vec<MigrationTxId> = state
        .transactions()
        .iter()
        .filter(|t| matches!(t.kind(), MigrationTxKind::Preparation { .. }))
        .map(|t| t.id())
        .collect();
    assert!(
        !prep_ids.is_empty(),
        "the migration has preparation transactions"
    );

    for prep_id in prep_ids {
        let tip = st
            .wallet()
            .chain_height()
            .expect("reads the chain height")
            .expect("the wallet has a chain tip");
        let anchor = highest_rooted_checkpoint(st.wallet_mut(), tip);
        {
            let mut prover = WalletMigrationProver::new(st.wallet_mut(), account_id, fvk.clone());
            engine::prove_preparation(&mut prover, &mut state, prep_id, anchor)
                .expect("proves the preparation transaction");
        }
        let proven = state
            .transactions()
            .iter()
            .find(|t| t.id() == prep_id)
            .expect("the preparation transaction is present");
        assert!(matches!(proven.state(), MigrationTxState::Proved));
        let tx = TransactionExtractor::new(
            pczt::Pczt::parse(proven.pczt()).expect("parses the proven preparation PCZT"),
        )
        .extract()
        .expect("extracts and verifies the preparation transaction");
        // A preparation transaction is Orchard-only: no Ironwood bundle.
        assert!(
            tx.orchard_bundle().is_some(),
            "the preparation has an Orchard bundle"
        );
        assert!(
            tx.ironwood_bundle().is_none(),
            "the preparation has no Ironwood bundle"
        );

        let (prep_height, _) = st.generate_next_block_from_tx(1, &tx);
        st.scan_cached_blocks(prep_height, 1);
    }

    // Prove each transfer once the chain has reached its drawn anchor boundary (so that checkpoint
    // exists and holds the funding note), staying within the pruning window.
    let mut transfers: Vec<(MigrationTxId, BlockHeight)> = state
        .transactions()
        .iter()
        .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
        .map(|t| {
            (
                t.id(),
                t.anchor_boundary()
                    .expect("a transfer carries a drawn boundary"),
            )
        })
        .collect();
    transfers.sort_by_key(|(_, boundary)| *boundary);
    assert!(!transfers.is_empty(), "the migration has transfers");

    for (transfer_id, boundary) in transfers {
        // Advance (scanning empty blocks) until the tip is strictly past the transfer's boundary, so
        // the boundary checkpoint is settled and rooted (the tip checkpoint is not yet rooted).
        loop {
            let tip = st
                .wallet()
                .chain_height()
                .expect("reads the chain height")
                .expect("the wallet has a chain tip");
            if tip > boundary {
                break;
            }
            let (h, _) = st.generate_empty_block();
            st.scan_cached_blocks(h, 1);
        }

        {
            let mut prover = WalletMigrationProver::new(st.wallet_mut(), account_id, fvk.clone());
            engine::prove_transfer(&mut prover, &mut state, transfer_id)
                .expect("proves the transfer against its drawn boundary");
        }
        let proven = state
            .transactions()
            .iter()
            .find(|t| t.id() == transfer_id)
            .expect("the transfer is present");
        assert!(matches!(proven.state(), MigrationTxState::Proved));
        let tx = TransactionExtractor::new(
            pczt::Pczt::parse(proven.pczt()).expect("parses the proven transfer PCZT"),
        )
        .extract()
        .expect("extracts and verifies the transfer's Orchard and Ironwood proofs");
        assert!(
            tx.orchard_bundle().is_some(),
            "the transfer has an Orchard bundle"
        );
        assert!(
            tx.ironwood_bundle().is_some(),
            "the transfer has an Ironwood bundle"
        );
    }
}
