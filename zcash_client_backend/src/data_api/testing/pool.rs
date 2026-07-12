use std::{
    cmp::Eq,
    collections::HashSet,
    convert::Infallible,
    hash::Hash,
    num::{NonZeroU8, NonZeroU32, NonZeroU64, NonZeroUsize},
};

use assert_matches::assert_matches;
use incrementalmerkletree::{
    Address as TreeAddress, Level, Position, Retention,
    frontier::{Frontier, NonEmptyFrontier},
};
use rand::{Rng, RngCore};
use secrecy::Secret;
use shardtree::error::ShardTreeError;
use subtle::ConditionallySelectable;

use transparent::address::TransparentAddress;
use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_primitives::{
    block::BlockHash,
    transaction::{
        Transaction,
        fees::zip317::{FeeRule as Zip317FeeRule, MARGINAL_FEE, MINIMUM_FEE},
    },
};
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight, NetworkUpgrade, Parameters},
    local_consensus::LocalNetwork,
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zip32::Scope;
use zip321::{Payment, TransactionRequest};

use crate::{
    data_api::{
        self, Account as _, AccountBirthday, BoundedU8, DecryptedTransaction, InputSource,
        MaxSpendMode, NoteFilter, Ratio, TargetValue, WalletCommitmentTrees, WalletRead,
        WalletSummary, WalletTest, WalletWrite,
        chain::{self, BlockSource, ChainState, CommitmentTreeRoot, ScanSummary},
        error::Error,
        testing::{
            AddressType, CacheInsertionResult, FakeCompactOutput, InitialChainState, TestBuilder,
            single_output_change_strategy,
        },
        wallet::{
            ConfirmationsPolicy, TargetHeight, TransferErrT, decrypt_and_store_transaction,
            input_selection::GreedyInputSelector,
        },
    },
    decrypt_transaction,
    fees::{
        self, DustOutputPolicy, SplitPolicy, StandardFeeRule,
        standard::{self, SingleOutputChangeStrategy},
    },
    scanning::ScanError,
    wallet::{Note, NoteId, OvkPolicy, ReceivedNote},
};

use super::{DataStoreFactory, Reset, TestCache, TestFvk, TestState};

#[cfg(feature = "transparent-inputs")]
use {
    crate::{
        data_api::{CoinbaseFilter, TransactionDataRequest},
        fees::ChangeValue,
        proposal::{Proposal, ProposalError, StepOutput, StepOutputIndex},
        wallet::WalletTransparentOutput,
    },
    nonempty::NonEmpty,
    std::str::FromStr,
    transparent::{
        bundle::{OutPoint, TxOut},
        keys::{NonHardenedChildIndex, TransparentKeyScope},
    },
    zcash_primitives::transaction::fees::zip317,
    zcash_protocol::{TxId, value::ZatBalance},
};

#[cfg(feature = "orchard")]
use zcash_protocol::PoolType;

#[cfg(feature = "pczt")]
use {
    pczt::roles::{prover::Prover, signer::Signer},
    rand_core::OsRng,
    transparent::builder::TransparentSigningSet,
    zcash_primitives::transaction::builder::{BuildConfig, Builder},
    zcash_proofs::prover::LocalTxProver,
    zcash_script::opcode::PushValue,
};

pub mod dsl;
use dsl::{TestDsl, TestNoteConfig};

/// Value of the single wallet note placed in shard 1 by the
/// [`build_stable_shard_fixture`] and [`build_tip_shard_fixture`] fixtures.
pub(crate) const SHARD_1_NOTE_VALUE: Zatoshis = Zatoshis::const_from_u64(150_000);

/// Number of empty cached (but unscanned) blocks that
/// [`build_shard_1_note_fixture`] places *below* the account birthday, so
/// that a rewind which lowers the account birthday can recover by re-scanning
/// genuine cached blocks. Deliberately not aligned with any rewind target or
/// window boundary used by the tests, so boundary off-by-one errors cannot be
/// masked by coincidentally-matching fixture geometry.
pub(crate) const PRE_BIRTHDAY_BLOCKS: u32 = 55;

/// Value of account A's wallet note (placed in the interior of completed
/// shard 1) in the [`build_two_account_recovery_fixture`] fixture.
const RECOVERY_A_NOTE_VALUE: Zatoshis = Zatoshis::const_from_u64(150_000);

/// Value of account B's wallet note (placed in the chain-tip shard) in the
/// [`build_two_account_recovery_fixture`] fixture.
const RECOVERY_B_NOTE_VALUE: Zatoshis = Zatoshis::const_from_u64(80_000);

/// Shared construction for the stable- and tip-shard fixtures. Both fixtures
/// use the same initial chain state and two real blocks (Block A places a
/// wallet note in shard 1's interior, Block B's scan completes shard 1 via
/// real leaves and spills 9 leaves into shard 2). They differ only in how
/// many trailing filler blocks are scanned past Block B:
/// * [`build_stable_shard_fixture`] appends `PRUNING_DEPTH + 10` trailing
///   blocks, pushing the pruning floor above shard 1's `subtree_end_height`
///   so the note stabilizes against the completed-shard interpretation.
/// * [`build_tip_shard_fixture`] appends only 5 trailing blocks, leaving
///   the wallet's birthday inside the chain-tip pruning window so the note
///   stabilizes against the active-shard interpretation.
///
/// The block cache also holds [`PRE_BIRTHDAY_BLOCKS`] empty blocks *below*
/// the account birthday. These are never scanned during fixture setup —
/// mirroring production, where the chain always has (unscanned) history
/// below any account's birthday — but they give a rewind-then-rescan flow
/// real cached blocks to re-scan when a rewind lowers the account birthday.
/// To decouple the account birthday from the cache floor, the account is
/// imported mid-fixture (once the pre-birthday blocks exist) rather than
/// created by `TestBuilder`; its birthday frontier is the chain state of the
/// cached block at `birthday - 1`.
///
/// All block sizes here are well within plausible mainnet limits (the
/// 300-output-per-block ceiling we use as our model upper bound); no
/// `fake_advance_to` is used, so the block cache is contiguous from
/// `birthday - PRE_BIRTHDAY_BLOCKS` to `chain_tip` and any
/// rewind-then-rescan flow can drive a continuous re-scan.
///
/// In the diagram, `X` is the wallet's note commitment, `f` counts
/// non-wallet filler commitments, `P` is [`PRE_BIRTHDAY_BLOCKS`], and `N` is
/// `trailing_filler_blocks`. The shard 1/2 boundary falls inside Block B,
/// whose 30 leaves split 21/9 across it.
///
/// ```text
/// blocks:  |<-(faked state)->|<--P empty blk-->|<------A------>|<------B------>|<-----N blk----->|
///     birthday-P-1      birthday-P         birthday        birthday+1      birthday+2        chain_tip
/// leaves:  |<---(2^17-71)--->|<-------0------->|<----X+49f---->|<-----30f----->|<------N f------>|
/// shards:  |<shard 0>|<--------------------shard 1--------------------->|<-------shard 2------>|...
/// ```
///
/// Wallet notes placed by this fixture:
///
/// | height     | position | shard | value      |
/// |------------|----------|-------|------------|
/// | `birthday` | 131001   | 1     | 150 000    |
fn build_shard_1_note_fixture<T, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
    trailing_filler_blocks: u32,
) -> (
    TestState<impl TestCache, Dsf::DataStore, LocalNetwork>,
    <Dsf as DataStoreFactory>::AccountId,
    UnifiedSpendingKey,
)
where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::Account as _;

    const SHARD_HEIGHT: u32 = 16;
    const SHARD_POSITIONS: u32 = 1 << SHARD_HEIGHT;

    // Matches the hard-coded seed used by
    // `TestBuilder::with_account_having_current_birthday`, so the imported
    // account carries the keys that builder-created accounts would have.
    const TEST_SEED: [u8; 32] = [0u8; 32];

    // Initial frontier 71 positions short of shard 1's end (position
    // 131000). The frontier is unaligned with shard boundaries; a boundary-
    // aligned frontier would cause `prior_subtree_roots` to cache shard 1
    // and then `insert_frontier` would fail trying to reinstall its leaf
    // into the cached-leaf-form shard.
    let initial_tree_size: u32 = 2 * SHARD_POSITIONS - 71;

    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_initial_chain_state(|rng, network| {
            let birthday_height = network.activation_height(NetworkUpgrade::Nu5).unwrap() + 1000;

            let (prior_sapling_roots, sapling_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    initial_tree_size.into(),
                    NonZeroU8::new(SHARD_HEIGHT as u8).unwrap(),
                );
            let prior_sapling_roots = prior_sapling_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let (prior_orchard_roots, orchard_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    initial_tree_size.into(),
                    NonZeroU8::new(SHARD_HEIGHT as u8).unwrap(),
                );
            #[cfg(feature = "orchard")]
            let prior_orchard_roots = prior_orchard_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            // Ironwood is not active at these test heights, so its tree is empty.
            #[cfg(feature = "orchard")]
            let ironwood_initial_tree = Frontier::empty();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1 - PRE_BIRTHDAY_BLOCKS,
                    BlockHash([5; 32]),
                    sapling_initial_tree,
                    #[cfg(feature = "orchard")]
                    orchard_initial_tree,
                    #[cfg(feature = "orchard")]
                    ironwood_initial_tree,
                ),
                prior_sapling_roots,
                #[cfg(feature = "orchard")]
                prior_orchard_roots,
            }
        })
        .build();

    // Pre-birthday history: empty blocks at
    // `[birthday - PRE_BIRTHDAY_BLOCKS, birthday - 1]`, cached but never
    // scanned during fixture setup. Empty blocks leave the note commitment
    // trees untouched, so the chain state at `birthday - 1` carries the same
    // frontier the initial chain state installed.
    for _ in 0..PRE_BIRTHDAY_BLOCKS {
        st.generate_empty_block();
    }

    // Import the wallet account with birthday `birthday_height`, anchored on
    // the chain state of the cached block at `birthday - 1`. This decouples
    // the account birthday from the cache floor: the cache extends
    // `PRE_BIRTHDAY_BLOCKS` below the birthday.
    let usk = UnifiedSpendingKey::from_seed(st.network(), &TEST_SEED, zip32::AccountId::ZERO)
        .expect("account USK derivation from seed should succeed");
    let dfvk = T::sk_to_fvk(T::usk_to_sk(&usk));
    let birthday_prior_chain_state = st
        .latest_cached_block()
        .expect("pre-birthday blocks have been cached")
        .chain_state()
        .clone();
    let birthday = AccountBirthday::from_parts(birthday_prior_chain_state, None);
    let seed = Secret::new(TEST_SEED.to_vec());
    let (account, _) = st
        .wallet_mut()
        .import_account_hd("primary", &seed, zip32::AccountId::ZERO, &birthday, None)
        .expect("account import should succeed");
    let account_id = account.id();

    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let filler_value = Zatoshis::const_from_u64(1000);

    // Block A at `birthday`: 50 outputs at positions 131001..131050. The
    // first output is the wallet note (position 131001); outputs 2..50 are
    // non-wallet fillers. The note sits deep in shard 1's interior, well
    // away from any shard boundary.
    let mut block_a_outputs = Vec::with_capacity(50);
    block_a_outputs.push(FakeCompactOutput::new(
        dfvk.clone(),
        AddressType::DefaultExternal,
        SHARD_1_NOTE_VALUE,
    ));
    for _ in 1..50 {
        block_a_outputs.push(FakeCompactOutput::new(
            not_our_key.clone(),
            AddressType::DefaultExternal,
            filler_value,
        ));
    }
    let (block_a_height, _, _) = st.generate_next_block_multi(&block_a_outputs);
    st.scan_cached_blocks(block_a_height, 1);

    // Block B at `birthday + 1`: 30 outputs at positions 131051..131080.
    // Outputs 1..21 fill the remaining slots of shard 1 (positions
    // 131051..131071); outputs 22..30 land in shard 2 (positions
    // 131072..131080). Output 21 fills shard 1's last slot.
    let block_b_outputs: Vec<_> = (0..30)
        .map(|_| {
            FakeCompactOutput::new(
                not_our_key.clone(),
                AddressType::DefaultExternal,
                filler_value,
            )
        })
        .collect();
    let (block_b_height, _, _) = st.generate_next_block_multi(&block_b_outputs);
    st.scan_cached_blocks(block_b_height, 1);

    // Declare shard 1 complete at `block_b_height` (= `birthday + 1`).
    // Scanning Block B fills shard 1's last leaf, but the wallet's scanning
    // path does not on its own write `subtree_end_height` into the
    // `*_tree_shards` table; that's the caller's responsibility (modelling
    // the server-cap-sync path in production). Without this call,
    // `mark_stabilized_notes` would never see a non-NULL
    // `subtree_end_height` for shard 1 and the wallet note would never
    // stabilize.
    let shard_1_root = T::shard_root(&mut st, 1).unwrap();
    T::put_subtree_roots(
        &mut st,
        1,
        &[CommitmentTreeRoot::from_parts(block_b_height, shard_1_root)],
    )
    .unwrap();

    // Trailing filler blocks past Block B, each adding 1 non-wallet output to
    // shard 2.
    if trailing_filler_blocks > 0 {
        for _ in 0..trailing_filler_blocks {
            st.generate_next_block(&not_our_key, AddressType::DefaultExternal, filler_value);
        }
        st.scan_cached_blocks(block_b_height + 1, trailing_filler_blocks as usize);
    }

    (st, account_id, usk)
}

/// Builds a fixture in which the wallet's shard 1 contains a real wallet
/// note at position 131001, the shard completes via real scanning at
/// `birthday + 1`, and `PRUNING_DEPTH + 10` trailing filler blocks push the
/// pruning floor above shard 1's `subtree_end_height`. Under the corrected
/// spendability rule the note is stabilized with `witness_anchor_stable =
/// birthday + 1` (the completed-shard `subtree_end_height`).
///
/// Final state:
///   `chain_tip = birthday + PRUNING_DEPTH + 11`
///   `pruning_floor = birthday + 11`
///   shard 1: complete (positions 65536..131071), `subtree_end_height = birthday + 1`
///   shard 2: partial (positions 131072..131072 + 8 + PRUNING_DEPTH + 10)
pub(crate) fn build_stable_shard_fixture<T, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) -> (
    TestState<impl TestCache, Dsf::DataStore, LocalNetwork>,
    <Dsf as DataStoreFactory>::AccountId,
    UnifiedSpendingKey,
)
where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::ll::wallet::PRUNING_DEPTH;
    build_shard_1_note_fixture::<T, Dsf>(ds_factory, cache, PRUNING_DEPTH + 10)
}

/// Builds a fixture in which the wallet's shard 1 contains a real wallet
/// note at position 131001 and the shard completes via real scanning at
/// `birthday + 1`, but only 5 trailing filler blocks follow -- keeping the
/// chain tip close enough to the birthday that the birthday height sits
/// *inside* the chain-tip pruning window. Under the corrected spendability
/// rule the note is stabilized via the active-shard interpretation:
/// `witness_anchor_stable = birthday` (= `t.block`, Block A's height, not
/// the shard's `subtree_end_height`).
///
/// Final state:
///   `chain_tip = birthday + 6`
///   `pruning_floor = birthday - 94`  (chain_tip - PRUNING_DEPTH)
///   `lowest_window_checkpoint = birthday - 93`  (pruning_floor + 1)
///   birthday sits inside the pruning window; shard 1 is complete but its
///   `subtree_end_height` (= birthday + 1) is above the pruning floor.
pub(crate) fn build_tip_shard_fixture<T, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) -> (
    TestState<impl TestCache, Dsf::DataStore, LocalNetwork>,
    <Dsf as DataStoreFactory>::AccountId,
    UnifiedSpendingKey,
)
where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    build_shard_1_note_fixture::<T, Dsf>(ds_factory, cache, 5)
}

/// Builds a two-account fixture backed by a single contiguous run of real blocks, used by the
/// rewind-recovery tests that need genuine chain history on *both* sides of a wallet birthday.
///
/// Account A is the wallet's primary account (zip32 index 0 on seed `[0u8; 32]`, created by
/// `TestBuilder`); account B is derived from the same seed at zip32 index 1 and imported once the
/// chain has been scanned up to the block before B's birthday. Importing B mid-fixture is what
/// lets B's own note be created in a block that the fixture generates.
///
/// In the diagram, `A` is account A's note commitment, `B` is account B's note commitment, and `f`
/// counts non-wallet filler commitments. Heights are `b_A = Nu5 + 1000` (account A's birthday) and
/// `b_A + 5` (account B's birthday, also denoted `b_B`); the trailing `PRUNING_DEPTH + 10` blocks
/// push the pruning floor (`chain_tip - PRUNING_DEPTH`) above shard 1's `subtree_end_height`.
///
/// ```text
/// blocks:  |<-(faked state)->|<----A1----->|<----A2---->|<---3 blk--->|<----B----->|<---PD+10 blk--->|
///       nu5+999             b_A          b_A+1        b_A+2      (b_A+5;b_B)     b_B+4           chain_tip
/// leaves:  |<---2^17 - 71--->|<---A+34f--->|<----36f--->|<----3f----->|<---B+4f--->|<----PD+10 f---->|
/// shards:  |<shard 0>|<----------shard 1--------------->|<------------------shard 2------------------>..
/// ```
///
/// * Shard 1 is completed by Block A2's last leaf and declared at
///   `subtree_end_height = H_A + 1` via `put_subtree_roots`. Account A's note
///   sits in its interior (position 131001), clear of any shard boundary.
/// * Shard 2 is the partial chain-tip shard; account B's note (position
///   131075) sits in its interior.
/// * Blocks A1, A2, the three fillers, Block B, and the trailing fillers form
///   one gap-free cached run, so a rewind to any height above `H_A` can be
///   recovered by re-scanning real blocks rather than faked tree state.
///
/// Wallet notes placed by this fixture:
///
/// | account | height    | position | shard | value   |
/// |---------|-----------|----------|-------|---------|
/// | A       | `H_A`     | 131001   | 1     | 150 000 |
/// | B       | `H_A + 5` | 131075   | 2     |  80 000 |
fn build_two_account_recovery_fixture<T, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) -> (
    TestState<impl TestCache, Dsf::DataStore, LocalNetwork>,
    <Dsf as DataStoreFactory>::AccountId,
    UnifiedSpendingKey,
)
where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::{Account as _, ll::wallet::PRUNING_DEPTH};

    const SHARD_HEIGHT: u32 = 16;
    const SHARD_POSITIONS: u32 = 1 << SHARD_HEIGHT;

    // Matches the hard-coded seed used by
    // `TestBuilder::with_account_having_current_birthday`, so account B can
    // be derived from the same seed at zip32 index 1.
    const TEST_SEED: [u8; 32] = [0u8; 32];

    // Initial frontier 71 positions short of shard 1's end (position
    // 131000); see [`build_shard_1_note_fixture`] for why the frontier is
    // kept off the shard boundary.
    let initial_tree_size: u32 = 2 * SHARD_POSITIONS - 71;

    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_initial_chain_state(|rng, network| {
            let birthday_height = network.activation_height(NetworkUpgrade::Nu5).unwrap() + 1000;

            let (prior_sapling_roots, sapling_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    initial_tree_size.into(),
                    NonZeroU8::new(SHARD_HEIGHT as u8).unwrap(),
                );
            let prior_sapling_roots = prior_sapling_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let (prior_orchard_roots, orchard_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    initial_tree_size.into(),
                    NonZeroU8::new(SHARD_HEIGHT as u8).unwrap(),
                );
            #[cfg(feature = "orchard")]
            let prior_orchard_roots = prior_orchard_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            // Ironwood is not active at these test heights, so its tree is empty.
            #[cfg(feature = "orchard")]
            let ironwood_initial_tree = Frontier::empty();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    sapling_initial_tree,
                    #[cfg(feature = "orchard")]
                    orchard_initial_tree,
                    #[cfg(feature = "orchard")]
                    ironwood_initial_tree,
                ),
                prior_sapling_roots,
                #[cfg(feature = "orchard")]
                prior_orchard_roots,
            }
        })
        .with_account_having_current_birthday()
        .build();

    let dfvk_a = T::test_account_fvk(&st);
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let filler_value = Zatoshis::const_from_u64(1000);

    // Derive account B's viewing key ahead of any scanning so Block B can
    // carry a B-destined output.
    let zip32_index_b = zip32::AccountId::ZERO.next().unwrap();
    let usk_b = UnifiedSpendingKey::from_seed(st.network(), &TEST_SEED, zip32_index_b)
        .expect("account B USK derivation from seed should succeed");
    let fvk_b = T::sk_to_fvk(T::usk_to_sk(&usk_b));

    // Block A1 at `H_A`: 35 outputs at positions 131001..131035. Output #1 is
    // account A's wallet note (position 131001); the rest are non-wallet
    // fillers.
    let mut block_a1_outputs = Vec::with_capacity(35);
    block_a1_outputs.push(FakeCompactOutput::new(
        dfvk_a.clone(),
        AddressType::DefaultExternal,
        RECOVERY_A_NOTE_VALUE,
    ));
    for _ in 1..35 {
        block_a1_outputs.push(FakeCompactOutput::new(
            not_our_key.clone(),
            AddressType::DefaultExternal,
            filler_value,
        ));
    }
    let (block_a1_height, _, _) = st.generate_next_block_multi(&block_a1_outputs);

    // Block A2 at `H_A + 1`: 36 non-wallet outputs at positions
    // 131036..131071. Output #36 fills shard 1's last leaf.
    let block_a2_outputs: Vec<_> = (0..36)
        .map(|_| {
            FakeCompactOutput::new(
                not_our_key.clone(),
                AddressType::DefaultExternal,
                filler_value,
            )
        })
        .collect();
    let (block_a2_height, _, _) = st.generate_next_block_multi(&block_a2_outputs);
    st.scan_cached_blocks(block_a1_height, 2);

    // Declare shard 1 complete at `H_A + 1`; scanning alone does not write
    // `subtree_end_height` (see [`build_shard_1_note_fixture`]).
    let shard_1_root = T::shard_root(&mut st, 1).unwrap();
    T::put_subtree_roots(
        &mut st,
        1,
        &[CommitmentTreeRoot::from_parts(
            block_a2_height,
            shard_1_root,
        )],
    )
    .unwrap();

    // Three filler blocks at `H_A + 2 ..= H_A + 4`, one non-wallet output
    // each (positions 131072..131074, the start of shard 2).
    for _ in 0..3 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, filler_value);
    }
    st.scan_cached_blocks(block_a2_height + 1, 3);

    // Import account B with a birthday one block above the current tip
    // (`H_A + 5`). The prior chain state is taken from the latest cached
    // block so B's birthday frontier reflects real scanned history.
    let b_prior_chain_state = st
        .latest_cached_block()
        .expect("blocks have been scanned")
        .chain_state()
        .clone();
    let b_birthday = AccountBirthday::from_parts(b_prior_chain_state, None);
    let seed = Secret::new(TEST_SEED.to_vec());
    let (account_b, _) = st
        .wallet_mut()
        .import_account_hd("account B", &seed, zip32_index_b, &b_birthday, None)
        .expect("account B import should succeed");
    let account_b_id = account_b.id();

    // Block B at `H_A + 5`: 5 outputs at positions 131075..131079. Output #1
    // is account B's wallet note (position 131075); the rest are fillers.
    let mut block_b_outputs = Vec::with_capacity(5);
    block_b_outputs.push(FakeCompactOutput::new(
        fvk_b.clone(),
        AddressType::DefaultExternal,
        RECOVERY_B_NOTE_VALUE,
    ));
    for _ in 1..5 {
        block_b_outputs.push(FakeCompactOutput::new(
            not_our_key.clone(),
            AddressType::DefaultExternal,
            filler_value,
        ));
    }
    let (block_b_height, _, _) = st.generate_next_block_multi(&block_b_outputs);

    // `PRUNING_DEPTH + 10` trailing filler blocks push the pruning floor
    // above shard 1's `subtree_end_height`.
    let trailing_filler_blocks = PRUNING_DEPTH + 10;
    for _ in 0..trailing_filler_blocks {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, filler_value);
    }
    st.scan_cached_blocks(block_b_height, 1 + trailing_filler_blocks as usize);

    (st, account_b_id, usk_b)
}

/// Asserts that a send-max-spendable proposal for `account` consumes exactly
/// `expected_balance`: the proposal's output amounts plus its required fee
/// must sum to `expected_balance`. Catches the case where the spend path can
/// see fewer notes than the balance path reported.
pub(crate) fn assert_send_max_consumes_balance<T, Cache, DbT, ParamsT, AccountIdT, ErrT>(
    st: &mut TestState<Cache, DbT, ParamsT>,
    account_id: AccountIdT,
    expected_balance: Zatoshis,
) where
    T: ShieldedPoolTester,
    Cache: TestCache,
    <Cache::BlockSource as BlockSource>::Error: std::fmt::Debug,
    ParamsT: consensus::Parameters + Send + 'static,
    AccountIdT: std::fmt::Debug + std::cmp::Eq + std::hash::Hash,
    ErrT: std::fmt::Debug,
    DbT: InputSource<AccountId = AccountIdT, Error = ErrT>
        + WalletTest
        + WalletWrite<AccountId = AccountIdT, Error = ErrT>
        + WalletCommitmentTrees,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + 'static,
{
    let send_max_recipient = T::sk_default_address(&T::sk(&[0xdd; 32]));
    let proposal = st
        .propose_send_max_transfer(
            account_id,
            &Zip317FeeRule::standard(),
            send_max_recipient.to_zcash_address(st.network()),
            None,
            MaxSpendMode::MaxSpendable,
            ConfirmationsPolicy::MIN,
        )
        .expect("send-max proposal should succeed when spendable balance is non-zero");
    let step = proposal.steps().first();
    let total_payments: Zatoshis = step
        .transaction_request()
        .payments()
        .values()
        .map(|p| p.amount().expect("send-max proposal payments have amounts"))
        .sum::<Option<Zatoshis>>()
        .expect("send-max payments should not overflow");
    let fee = step.balance().fee_required();
    assert_eq!(
        (total_payments + fee).expect("payments + fee should not overflow"),
        expected_balance,
        "send-max proposal outputs + fee must equal the spendable balance",
    );
}

/// Trait that exposes the pool-specific types and operations necessary to run the
/// single-shielded-pool tests on a given pool.
///
/// You should not need to implement this yourself; instead use [`SaplingPoolTester`] or
/// [`OrchardPoolTester`] as appropriate.
///
/// [`SaplingPoolTester`]: super::sapling::SaplingPoolTester
#[cfg_attr(
    feature = "orchard",
    doc = "[`OrchardPoolTester`]: super::orchard::OrchardPoolTester"
)]
#[cfg_attr(
    not(feature = "orchard"),
    doc = "[`OrchardPoolTester`]: https://github.com/zcash/librustzcash/blob/0777cbc2def6ba6b99f96333eaf96c314c1f3a37/zcash_client_backend/src/data_api/testing/orchard.rs#L33"
)]
pub trait ShieldedPoolTester {
    const SHIELDED_PROTOCOL: ShieldedPool;

    /// The level of a shard root within this pool's note commitment tree (the
    /// number of leaves in a shard is `1 << SHARD_HEIGHT`).
    const SHARD_HEIGHT: u8;

    type Sk;
    type Fvk: TestFvk;
    type MerkleTreeHash: incrementalmerkletree::Hashable + Clone;
    type Note;

    fn test_account_fvk<Cache, DbT: WalletTest, P: consensus::Parameters>(
        st: &TestState<Cache, DbT, P>,
    ) -> Self::Fvk;
    fn usk_to_sk(usk: &UnifiedSpendingKey) -> &Self::Sk;
    fn sk(seed: &[u8]) -> Self::Sk;
    fn sk_to_fvk(sk: &Self::Sk) -> Self::Fvk;
    fn sk_default_address(sk: &Self::Sk) -> Address;
    fn fvk_default_address(fvk: &Self::Fvk) -> Address;
    fn fvks_equal(a: &Self::Fvk, b: &Self::Fvk) -> bool;

    fn random_fvk(mut rng: impl RngCore) -> Self::Fvk {
        let sk = {
            let mut sk_bytes = vec![0; 32];
            rng.fill_bytes(&mut sk_bytes);
            Self::sk(&sk_bytes)
        };

        Self::sk_to_fvk(&sk)
    }
    fn random_address(rng: impl RngCore) -> Address {
        Self::fvk_default_address(&Self::random_fvk(rng))
    }

    fn empty_tree_leaf() -> Self::MerkleTreeHash;
    fn empty_tree_root(level: Level) -> Self::MerkleTreeHash;

    fn put_subtree_roots<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        start_index: u64,
        roots: &[CommitmentTreeRoot<Self::MerkleTreeHash>],
    ) -> Result<(), ShardTreeError<<DbT as WalletCommitmentTrees>::Error>>;

    /// Computes the actual root of the `shard_index`-th shard from the wallet's local
    /// shardtree state, reading whatever leaves and cached annotations are currently
    /// stored. Used by tests that need to call [`Self::put_subtree_roots`] with a root
    /// that matches the shard's actual computed root — for example, when declaring a
    /// shard complete after filling its last position via `scan_cached_blocks`.
    fn shard_root<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        shard_index: u64,
    ) -> Result<Self::MerkleTreeHash, ShardTreeError<<DbT as WalletCommitmentTrees>::Error>>;

    /// Inserts a single subtree-root stub into the wallet's note commitment tree
    /// at the given address, treating `hash` as the opaque root of an otherwise
    /// unrealized subtree.
    ///
    /// Used by tests that need to construct realistic shard-boundary state
    /// without materializing every leaf within a shard. See
    /// [`super::shard_stub`] for the helper that decomposes a leaf range into
    /// the minimal set of stub addresses.
    fn insert_subtree_stub<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        addr: TreeAddress,
        hash: Self::MerkleTreeHash,
    ) -> Result<(), ShardTreeError<<DbT as WalletCommitmentTrees>::Error>>;

    /// Returns a fresh random hash suitable for use as an opaque subtree-root
    /// stub for this pool.
    fn random_subtree_hash(rng: impl RngCore) -> Self::MerkleTreeHash;

    /// Returns this pool's final-tree frontier from the given chain state.
    fn pool_frontier_in_chain_state(
        chain_state: &chain::ChainState,
    ) -> Frontier<Self::MerkleTreeHash, { super::shard_stub::NOTE_COMMITMENT_TREE_DEPTH }>;

    /// Builds a [`chain::ChainState`] in which this pool's final-tree frontier
    /// is `pool_frontier`, while the other pool's frontier is taken from
    /// `other_pools_chain_state`.
    fn build_chain_state_with_pool_frontier(
        block_height: BlockHeight,
        block_hash: BlockHash,
        pool_frontier: Frontier<
            Self::MerkleTreeHash,
            { super::shard_stub::NOTE_COMMITMENT_TREE_DEPTH },
        >,
        other_pools_chain_state: &chain::ChainState,
    ) -> chain::ChainState;

    /// Reads the root of the subtree at `addr` from the wallet's note
    /// commitment tree, treating positions strictly greater than `truncate_at`
    /// as empty.
    fn read_tree_root<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        addr: TreeAddress,
        truncate_at: Position,
    ) -> Result<Self::MerkleTreeHash, ShardTreeError<<DbT as WalletCommitmentTrees>::Error>>;

    /// Inserts the given non-empty frontier into the wallet's note commitment
    /// tree, with the given leaf retention.
    fn insert_frontier_into_tree<Cache, DbT: WalletTest + WalletCommitmentTrees, P>(
        st: &mut TestState<Cache, DbT, P>,
        frontier: NonEmptyFrontier<Self::MerkleTreeHash>,
        leaf_retention: Retention<BlockHeight>,
    ) -> Result<(), ShardTreeError<<DbT as WalletCommitmentTrees>::Error>>;

    fn next_subtree_index<A: Hash + Eq>(s: &WalletSummary<A>) -> u64;

    fn note_value(note: &Self::Note) -> Zatoshis;

    #[allow(clippy::type_complexity)]
    fn select_spendable_notes<Cache, DbT: InputSource + WalletTest, P>(
        st: &TestState<Cache, DbT, P>,
        account: <DbT as InputSource>::AccountId,
        target_value: TargetValue,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[DbT::NoteRef],
    ) -> Result<Vec<ReceivedNote<DbT::NoteRef, Self::Note>>, <DbT as InputSource>::Error>;

    #[allow(clippy::type_complexity)]
    fn select_unspent_notes<Cache, DbT: InputSource + WalletTest, P>(
        st: &TestState<Cache, DbT, P>,
        account: <DbT as InputSource>::AccountId,
        target_height: TargetHeight,
        exclude: &[DbT::NoteRef],
    ) -> Result<Vec<ReceivedNote<DbT::NoteRef, Self::Note>>, <DbT as InputSource>::Error>;

    fn decrypted_pool_outputs_count<A>(d_tx: &DecryptedTransaction<Transaction, A>) -> usize;

    fn with_decrypted_pool_memos<A>(
        d_tx: &DecryptedTransaction<Transaction, A>,
        f: impl FnMut(&MemoBytes),
    );

    fn try_output_recovery<P: consensus::Parameters>(
        params: &P,
        height: BlockHeight,
        tx: &Transaction,
        fvk: &Self::Fvk,
    ) -> Option<(Note, Address, MemoBytes)>;

    fn received_note_count(summary: &ScanSummary) -> usize;

    #[cfg(feature = "pczt")]
    fn add_proof_generation_keys(
        pczt: pczt::Pczt,
        usk: &UnifiedSpendingKey,
    ) -> Result<pczt::Pczt, pczt::roles::updater::SaplingError>;

    #[cfg(feature = "pczt")]
    fn apply_signatures_to_pczt(
        signer: &mut Signer,
        usk: &UnifiedSpendingKey,
    ) -> Result<(), pczt::roles::signer::Error>;
}

/// Tests sending funds within the given shielded pool in a single transaction.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Constructs a request to spend part of that balance to an external address in the
///   same pool.
/// - Builds the transaction.
/// - Checks that the transaction was stored, and that the outputs are decryptable and
///   have the expected details.
pub fn send_single_step_proposed_transfer<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    let (h, _, _) = st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10000),
    )])
    .unwrap();

    let fee_rule = StandardFeeRule::Zip317;

    let change_memo = "Test change memo".parse::<Memo>().unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        fee_rule,
        Some(change_memo.clone().into()),
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let account = st.get_account();
    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let sent_tx_id = create_proposed_result.unwrap()[0];

    // Verify that the sent transaction was stored and that we can decrypt the memos
    let tx = st
        .wallet()
        .get_transaction(sent_tx_id)
        .unwrap()
        .expect("Created transaction was stored.");
    let ufvks = [(account.id(), account.usk().to_unified_full_viewing_key())]
        .into_iter()
        .collect();
    let d_tx = decrypt_transaction(st.network(), None, Some(h), &tx, &ufvks);
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 2);

    let mut found_tx_change_memo = false;
    let mut found_tx_empty_memo = false;
    T::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == change_memo {
            found_tx_change_memo = true
        }
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_tx_change_memo);
    assert!(found_tx_empty_memo);

    // Verify that the stored sent notes match what we're expecting
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(sent_note_ids.len(), 2);

    // The sent memo should be the empty memo for the sent output, and the
    // change output's memo should be as specified.
    let mut found_sent_change_memo = false;
    let mut found_sent_empty_memo = false;
    for sent_note_id in sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Note id is valid")
            .as_ref()
        {
            Some(m) if m == &change_memo => {
                found_sent_change_memo = true;
            }
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }
    assert!(found_sent_change_memo);
    assert!(found_sent_empty_memo);

    // Check that querying for a nonexistent sent note returns None
    assert_matches!(
        st.wallet()
            .get_memo(NoteId::new(sent_tx_id, T::SHIELDED_PROTOCOL, 12345)),
        Ok(None)
    );

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 2);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(60000));
    }

    {
        let tx_1 = &tx_history[1];
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(60000));
        assert_eq!(tx_1.total_received(), Zatoshis::const_from_u64(40000));
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}

/// Builds a real transaction via the proposal/creation path, assembles it into a full
/// block, and verifies that [`decrypt_block`] followed by [`scan_block`] detects the
/// wallet output (the change note) that it contains.
///
/// [`decrypt_block`]: crate::scanning::full::decrypt_block
/// [`scan_block`]: crate::scanning::full::scan_block
pub fn scan_full_block_detects_outputs<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use incrementalmerkletree::Retention;
    use nonempty::NonEmpty;
    use zcash_primitives::block::{Block, BlockHeaderData};

    use crate::{
        data_api::BlockMetadata,
        scanning::{
            Nullifiers, ScanningKeys,
            full::{decrypt_block, scan_block},
        },
    };

    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note.
    let (h, _, _) = st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

    // Propose and create a transfer to an external recipient. The resulting transaction
    // has two shielded outputs: the payment, and the change returned to the wallet.
    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let request = TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10000),
    )])
    .unwrap();

    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let account = st.get_account();
    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let txids = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    assert_eq!(txids.len(), 1);

    let tx = st
        .wallet()
        .get_transaction(*txids.first())
        .unwrap()
        .expect("the created transaction was stored");

    // Build a `ScanningKeys` set for the wallet account. The account identifier used for
    // scanning is independent of the wallet database's account identifier.
    let ufvk = account.usk().to_unified_full_viewing_key();
    let scanning_keys = ScanningKeys::from_account_ufvks([(zip32::AccountId::ZERO, ufvk)]);

    // Assemble a single-transaction block containing the created transaction. The block
    // is scanned in isolation, so we treat the note commitment trees as empty as of the
    // immediately preceding block.
    let network = *st.network();
    let header = BlockHeaderData {
        version: 4,
        prev_block: BlockHash([0; 32]),
        merkle_root: [0; 32],
        final_sapling_root: [0; 32],
        time: 0,
        bits: 0,
        nonce: [0; 32],
        solution: vec![],
    }
    .freeze()
    .unwrap();
    let block = Block::from_parts(header, NonEmpty::singleton(tx), h);

    let prior_block_metadata = BlockMetadata::from_parts(
        h - 1,
        BlockHash([0; 32]),
        Some(0),
        #[cfg(feature = "orchard")]
        Some(0),
        #[cfg(feature = "orchard")]
        Some(0),
    );

    // Phase 1: decrypt the block's shielded outputs.
    let (header, vtx) = decrypt_block(&network, block, &scanning_keys);

    // Phase 2: scan the decrypted block.
    #[cfg(feature = "transparent-inputs")]
    let scanned = scan_block(
        &network,
        h,
        &header,
        vtx,
        &scanning_keys,
        &Nullifiers::empty(),
        Some(&prior_block_metadata),
        |_addr| Ok::<_, Infallible>(None),
    )
    .expect("scanning the block succeeds");
    #[cfg(not(feature = "transparent-inputs"))]
    let scanned = scan_block::<_, _, _, Infallible>(
        &network,
        h,
        &header,
        vtx,
        &scanning_keys,
        &Nullifiers::empty(),
        Some(&prior_block_metadata),
    )
    .expect("scanning the block succeeds");

    // The wallet should have detected exactly the change output returned to its internal
    // address; the payment output was sent to a recipient outside the wallet.
    assert_eq!(scanned.transactions().len(), 1);
    let received_outputs: usize = scanned
        .transactions()
        .iter()
        .map(|wtx| {
            let n = wtx.sapling_outputs().len();
            #[cfg(feature = "orchard")]
            let n = n + wtx.orchard_outputs().len();
            n
        })
        .sum();
    assert_eq!(received_outputs, 1);

    // The note commitment tree should have grown by exactly the two shielded outputs in
    // the block's single transaction (the payment and the change), starting from the
    // empty prior tree. The outputs all belong to the pool under test; the other pool (if
    // compiled in) sees no outputs.
    let total_commitments = scanned.sapling().commitments().len();
    #[cfg(feature = "orchard")]
    let total_commitments = total_commitments + scanned.orchard().commitments().len();
    assert_eq!(total_commitments, 2);

    let total_final_tree_size = scanned.sapling().final_tree_size();
    #[cfg(feature = "orchard")]
    let total_final_tree_size = total_final_tree_size + scanned.orchard().final_tree_size();
    assert_eq!(total_final_tree_size, 2);

    // The final note added in the block must be marked as a checkpoint at this block
    // height; this is what lets the wallet anchor witnesses to the block. Getting the
    // "last outputs in the block" boundary wrong is the most error-prone part of position
    // tracking, so we assert it explicitly.
    let last_retention = scanned.sapling().commitments().last().map(|(_, r)| *r);
    #[cfg(feature = "orchard")]
    let last_retention = scanned
        .orchard()
        .commitments()
        .last()
        .map(|(_, r)| *r)
        .or(last_retention);
    assert!(
        matches!(last_retention, Some(Retention::Checkpoint { id, .. }) if id == h),
        "final note commitment should be a checkpoint at height {h:?}, got {last_retention:?}",
    );
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ConfirmationStep {
    i: u32,
    confirmation_requirement: u32,
    number_of_confirmations: u32,
    pending_balance: Zatoshis,
    spendable_balance: Zatoshis,
    total_balance: Zatoshis,
}

/// An enumeration of mechanisms for generating transaction inputs for confirmations policy
/// testing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputTrust {
    /// Generate a wallet-internal output.
    Internal,
    /// Generate an output as if it was sent to the wallet by an untrusted counterparty.
    ExternalUntrusted,
    /// Generate an output as if it was sent to the wallet by a trusted counterparty.
    ExternalTrusted,
}

/// Tests that inputs from a source can be spent according to the default
/// `ConfirmationsPolicy`.
///
/// The test:
/// - Adds funds to the wallet in a single note from an certain source.
/// - Checks that the wallet balances are correct after N confirmations, according to
///   the policy.
pub fn zip_315_confirmations_test_steps<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
    input_trust: InputTrust,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    let account = st.test_account().cloned().unwrap();
    let starting_balance = Zatoshis::const_from_u64(60_000);

    // Add funds to the wallet in a single note, owned by the internal spending key,
    // which will have one confirmation.
    let confirmations_policy = ConfirmationsPolicy::default();
    let (address_type, min_confirmations) = match input_trust {
        InputTrust::Internal => (AddressType::Internal, confirmations_policy.trusted()),
        InputTrust::ExternalUntrusted => (
            AddressType::DefaultExternal,
            confirmations_policy.untrusted(),
        ),
        InputTrust::ExternalTrusted => {
            (AddressType::DefaultExternal, confirmations_policy.trusted())
        }
    };
    let min_confirmations = u32::from(min_confirmations);

    let (_, r, _) = st.add_a_single_note_checking_balance(
        TestNoteConfig::from(starting_balance).with_address_type(address_type),
    );
    let txid = r.txids()[0];

    // Mark the external input as explicitly trusted, if so requested
    let trusted = input_trust == InputTrust::ExternalTrusted;
    if trusted {
        st.wallet_mut().set_tx_trust(txid, true).unwrap();
    }

    let add_confirmation = |i: u32| {
        let (h, _) = st.generate_empty_block();
        st.scan_cached_blocks(h, 1);
        let outputs = st
            .wallet()
            .get_received_outputs(txid, TargetHeight::from(h + 1), confirmations_policy)
            .unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(
            outputs[0].confirmations_until_spendable(),
            u32::from(if trusted {
                confirmations_policy.trusted()
            } else {
                confirmations_policy.untrusted()
            })
            .saturating_sub(i + 1)
        );
        ConfirmationStep {
            i,
            confirmation_requirement: min_confirmations,
            number_of_confirmations: 1 + i,
            pending_balance: st.get_pending_shielded_balance(account.id(), confirmations_policy),
            spendable_balance: st.get_spendable_balance(account.id(), confirmations_policy),
            total_balance: st.get_total_balance(account.id()),
        }
    };

    // Generate N confirmations by mining blocks
    let steps = (1u32..min_confirmations)
        .map(add_confirmation)
        .collect::<Vec<_>>();

    assert!(
        steps
            .iter()
            .filter(|step| step.number_of_confirmations < min_confirmations)
            .all(|step| step.spendable_balance == Zatoshis::ZERO),
        "spendable balance is equal to starting balance until we have sufficient confirmations"
    );

    let to = T::random_address(st.rng_mut());
    // Now that the funds are spendable, propose a transaction
    let proposed = st.propose_standard_transfer::<Infallible>(
        account.id(),
        StandardFeeRule::Zip317,
        confirmations_policy,
        &to,
        Zatoshis::const_from_u64(10_000),
        None,
        None,
        T::SHIELDED_PROTOCOL,
    );
    assert!(
        proposed.is_ok(),
        "Could not spend funds by confirmation policy ({input_trust:?}): {proposed:#?}\n\
        steps: {steps:#?}",
    );
}

/// Tests max spendable funds within the given shielded pool in a
/// single transaction.
///
/// The test:
/// - Adds funds to the wallet in two notes with different confirmation heights
/// - Checks that the wallet balances are correct.
/// - Constructs a request to spend the whole balance to an external address in the
///   same pool.
/// - Builds the transaction.
/// - Checks that the transaction was stored, and that the outputs are decryptable and
///   have the expected details.
pub fn spend_max_spendable_single_step_proposed_transfer<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in two notes over 5 blocks
    let value = Zatoshis::const_from_u64(60000);
    let h = st
        .add_notes_checking_balance([Some(value), None, None, None, Some(value)])
        .block_height()
        .unwrap();

    // Spendable balance matches total balance
    let account = st.test_account().cloned().unwrap();
    let confirmation_policy = ConfirmationsPolicy::new_symmetrical(
        NonZeroU32::new(2).expect("2 is not zero"),
        #[cfg(feature = "transparent-inputs")]
        false,
    );
    assert_eq!(
        st.get_spendable_balance(account.id(), confirmation_policy),
        value
    );

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);

    let fee_rule = StandardFeeRule::Zip317;

    let send_max_memo = "Test Send Max memo".parse::<Memo>().unwrap();

    let addy = to.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            Some(MemoBytes::from(send_max_memo.clone())),
            MaxSpendMode::MaxSpendable,
            confirmation_policy,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let sent_tx_id = create_proposed_result.unwrap()[0];

    // Verify that the sent transaction was stored and that we can decrypt the memos
    let tx = st
        .wallet()
        .get_transaction(sent_tx_id)
        .unwrap()
        .expect("Created transaction was stored.");
    let ufvks = [(account.id(), account.usk().to_unified_full_viewing_key())]
        .into_iter()
        .collect();
    let d_tx = decrypt_transaction(st.network(), None, Some(h), &tx, &ufvks);
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 1);

    let mut found_send_max_memo = false;
    let mut found_tx_empty_memo = false;
    T::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == send_max_memo {
            found_send_max_memo = true
        }
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_send_max_memo);
    assert!(!found_tx_empty_memo); // there's no empty memo in this case

    // Verify that the stored sent notes match what we're expecting
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(sent_note_ids.len(), 1);

    // The sent memo should the specified memo for the sent output
    let mut found_sent_empty_memo = false;
    let mut found_sent_max_memo = false;
    for sent_note_id in sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Memo retrieval should succeed")
            .as_ref()
        {
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(m) if m == &send_max_memo => {
                found_sent_max_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }

    assert!(found_sent_max_memo);
    assert!(!found_sent_empty_memo);

    // Check that querying for a nonexistent sent note returns None
    assert_matches!(
        st.wallet()
            .get_memo(NoteId::new(sent_tx_id, T::SHIELDED_PROTOCOL, 12345)),
        Ok(None)
    );

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 3);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(60000));
    }
    {
        let tx_1 = &tx_history[1];
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_1.total_received(), Zatoshis::const_from_u64(60000));
    }
    {
        let tx_2 = &tx_history[2];
        assert_eq!(tx_2.total_spent(), Zatoshis::const_from_u64(60000));
        assert_eq!(tx_2.total_received(), Zatoshis::const_from_u64(0));
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}

/// Tests sending every piece of spendable funds within the given shielded pool in a
/// single transaction.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Constructs a request to spend the whole balance to an external address in the
///   same pool.
/// - Builds the transaction.
/// - Checks that the transaction was stored, and that the outputs are decryptable and
///   have the expected details.
pub fn spend_everything_single_step_proposed_transfer<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();

    // Add funds to the wallet in a single note
    let (h, _, _) = st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);

    let fee_rule = StandardFeeRule::Zip317;

    let send_max_memo = "Test Send Max memo".parse::<Memo>().unwrap();

    let addy = to.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            Some(MemoBytes::from(send_max_memo.clone())),
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let sent_tx_id = create_proposed_result.unwrap()[0];

    // Verify that the sent transaction was stored and that we can decrypt the memos
    let tx = st
        .wallet()
        .get_transaction(sent_tx_id)
        .unwrap()
        .expect("Created transaction was stored.");
    let ufvks = [(account.id(), account.usk().to_unified_full_viewing_key())]
        .into_iter()
        .collect();
    let d_tx = decrypt_transaction(st.network(), None, Some(h), &tx, &ufvks);
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 1);

    let mut found_send_max_memo = false;
    let mut found_tx_empty_memo = false;
    T::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == send_max_memo {
            found_send_max_memo = true
        }
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_send_max_memo);
    assert!(!found_tx_empty_memo); // there's no empty memo in this case

    // Verify that the stored sent notes match what we're expecting
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(sent_note_ids.len(), 1);

    // The sent memo should the specified memo for the sent output
    let mut found_sent_empty_memo = false;
    let mut found_sent_max_memo = false;
    for sent_note_id in sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Memo retrieval should succeed")
            .as_ref()
        {
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(m) if m == &send_max_memo => {
                found_sent_max_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }

    assert!(found_sent_max_memo);
    assert!(!found_sent_empty_memo);

    // Check that querying for a nonexistent sent note returns None
    assert_matches!(
        st.wallet()
            .get_memo(NoteId::new(sent_tx_id, T::SHIELDED_PROTOCOL, 12345)),
        Ok(None)
    );

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 2);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(60000));
    }

    {
        let tx_1 = &tx_history[1];
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(60000));
        assert_eq!(tx_1.total_received(), Zatoshis::const_from_u64(0));
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}

/// Tests that sending all the spendable funds within the given shielded pool in a
/// single transaction to a transparent address with a memo fails.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Tries to propose a send max transaction to a T-address with a memo
/// - Fails gracefully with Zip321Error.
#[cfg(feature = "transparent-inputs")]
pub fn fails_to_send_max_spendable_to_transparent_with_memo<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    use crate::data_api::MaxSpendMode;

    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60000));

    let account = st.test_account().cloned().unwrap();
    let (default_addr, _) = account.usk().default_transparent_address();

    let to: Address = Address::Transparent(default_addr);

    let fee_rule = StandardFeeRule::Zip317;

    let send_max_memo = "Test Send Max memo".parse::<Memo>().unwrap();

    let addy = to.to_zcash_address(st.network());
    assert_matches!(
        st.propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            Some(MemoBytes::from(send_max_memo.clone())),
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN
        ),
        Err(data_api::error::Error::Payment(
            zip321::PaymentError::TransparentMemo
        ))
    );
}

/// Tests that attempting to send all the spendable funds within the given shielded pool in a
/// single transaction fail if there are funds that are not yet confirmed.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Mine empty blocks
/// - Add more funds
/// - Attempts to construct a request to spend the whole balance to an external address in the
///   same pool.
/// - catches failure
/// - verifies the failure is the one expected
pub fn spend_everything_proposal_fails_when_unconfirmed_funds_present<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    st.add_notes_checking_balance([
        Some(Zatoshis::const_from_u64(60000)),
        None,
        None,
        Some(Zatoshis::const_from_u64(123456)),
    ]);

    // Spendable balance doesn't match total balance
    let account = st.test_account().cloned().unwrap();
    let total_balance = st.get_total_balance(account.id());
    let spendable_balance = st.get_spendable_balance(
        account.id(),
        ConfirmationsPolicy::new_symmetrical_unchecked(
            2,
            #[cfg(feature = "transparent-inputs")]
            true,
        ),
    );
    assert_ne!(total_balance, spendable_balance);

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);

    let fee_rule = StandardFeeRule::Zip317;

    let send_max_memo = "Test Send Max memo".parse::<Memo>().unwrap();

    let addy = to.to_zcash_address(st.network());
    assert_matches!(
        st.propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            Some(MemoBytes::from(send_max_memo.clone())),
            MaxSpendMode::Everything,
            ConfirmationsPolicy::new_symmetrical_unchecked(
                2,
                #[cfg(feature = "transparent-inputs")]
                true
            )
        ),
        Err(data_api::error::Error::DataSource(_))
    );
}

/// Tests that attempting to send `MaxSpendable` funds within the given shielded pool in a
/// single transaction succeeds if there are funds that are not yet confirmed.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Mine empty blocks
/// - Add more funds
/// - Attempts to construct a request to spend the whole balance to an external address in the
///   same pool.
/// - succeeds at doing so
pub fn send_max_spendable_proposal_succeeds_when_unconfirmed_funds_present<
    T: ShieldedPoolTester,
>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();
    let h = st
        .add_notes_checking_balance([
            Some(Zatoshis::const_from_u64(60000)),
            None,
            None,
            Some(Zatoshis::const_from_u64(123456)),
        ])
        .block_height()
        .unwrap();

    // Spendable balance doesn't match total balance
    let account = st.test_account().cloned().unwrap();
    let total_balance = st.get_total_balance(account.id());
    let spendable_balance = st.get_spendable_balance(
        account.id(),
        ConfirmationsPolicy::new_symmetrical_unchecked(
            2,
            #[cfg(feature = "transparent-inputs")]
            true,
        ),
    );
    assert_ne!(total_balance, spendable_balance);

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);

    let fee_rule = StandardFeeRule::Zip317;

    let send_max_memo = "Test Send Max memo".parse::<Memo>().unwrap();

    let addy = to.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account.id(),
            &fee_rule,
            addy,
            Some(MemoBytes::from(send_max_memo.clone())),
            MaxSpendMode::MaxSpendable,
            ConfirmationsPolicy::new_symmetrical_unchecked(
                2,
                #[cfg(feature = "transparent-inputs")]
                true,
            ),
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let sent_tx_id = create_proposed_result.unwrap()[0];

    // Verify that the sent transaction was stored and that we can decrypt the memos
    let tx = st
        .wallet()
        .get_transaction(sent_tx_id)
        .unwrap()
        .expect("Created transaction was stored.");
    let ufvks = [(account.id(), account.usk().to_unified_full_viewing_key())]
        .into_iter()
        .collect();
    let d_tx = decrypt_transaction(st.network(), None, Some(h), &tx, &ufvks);
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 1);

    let mut found_send_max_memo = false;
    let mut found_tx_empty_memo = false;
    T::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == send_max_memo {
            found_send_max_memo = true
        }
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_send_max_memo);
    assert!(!found_tx_empty_memo); // there's no empty memo in this case

    // Verify that the stored sent notes match what we're expecting
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(sent_note_ids.len(), 1);

    // The sent memo should the specified memo for the sent output
    let mut found_sent_empty_memo = false;
    let mut found_sent_max_memo = false;
    for sent_note_id in sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Memo retrieval should succeed")
            .as_ref()
        {
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(m) if m == &send_max_memo => {
                found_sent_max_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }

    assert!(found_sent_max_memo);
    assert!(!found_sent_empty_memo);

    // Check that querying for a nonexistent sent note returns None
    assert_matches!(
        st.wallet()
            .get_memo(NoteId::new(sent_tx_id, T::SHIELDED_PROTOCOL, 12345)),
        Ok(None)
    );

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 2);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(60000));
    }

    {
        let tx_1 = &tx_history[1];
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(60000));
        assert_eq!(tx_1.total_received(), Zatoshis::const_from_u64(0));
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}

/// This test attempts to send the max spendable funds to a TEX address recipient
/// checks that the transactions were stored and that the amounts involved are correct
#[cfg(feature = "transparent-inputs")]
pub fn spend_everything_multi_step_single_note_proposed_transfer<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::{MaxSpendMode, OutputOfSentTx};
    use zcash_keys::keys::transparent::gap_limits::GapLimits;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache)
        .map(|builder| builder.with_gap_limits(GapLimits::new(10, 5, 3)))
        .build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();

    let value = Zatoshis::const_from_u64(100000);

    // Add funds to the wallet.
    st.add_a_single_note_checking_balance(value);
    let initial_balance = value;
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        initial_balance
    );

    let expected_step0_fee = (zip317::MARGINAL_FEE * 3u64).unwrap();
    let expected_step1_fee = zip317::MINIMUM_FEE;
    let expected_ephemeral_spend = (value - expected_step0_fee - expected_step1_fee).unwrap();
    let expected_ephemeral_balance = (value - expected_step0_fee).unwrap();
    let expected_step0_change = (value - expected_step0_fee).unwrap();

    let total_sent = (expected_step0_fee + expected_step1_fee + expected_ephemeral_spend).unwrap();

    // check that the napkin math is Ok. Total value send should be the whole
    // value of the wallet
    assert_eq!(total_sent, value);

    // Generate a ZIP 320 proposal, sending to an external TEX address.
    let tex_addr = Address::Tex([0x4; 20]);

    // TODO: Do we want to allow shielded change memos in ephemeral transfers?
    //let change_memo = Memo::from_str("change").expect("valid memo").encode();
    let fee_rule = StandardFeeRule::Zip317;

    // We use `st.propose_standard_transfer` here in order to also test round-trip
    // serialization of the proposal.
    let addy = tex_addr.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account_id,
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let steps: Vec<_> = proposal.steps().iter().cloned().collect();
    assert_eq!(steps.len(), 2);

    assert_eq!(steps[0].balance().fee_required(), expected_step0_fee);
    assert_eq!(steps[1].balance().fee_required(), expected_step1_fee);
    assert_eq!(
        steps[0].balance().proposed_change(),
        [
            // TODO: Do we want to allow shielded change memos in ephemeral transfers?
            //ChangeValue::shielded(
            //    T::SHIELDED_PROTOCOL,
            //    expected_step0_change,
            //    Some(change_memo)
            //),
            ChangeValue::ephemeral_transparent(
                (total_sent - expected_step0_fee).expect("value is non-zero")
            ),
        ]
    );
    assert_eq!(steps[1].balance().proposed_change(), []);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 2);
    let txids = create_proposed_result.unwrap();

    // Mine the created transactions.
    for txid in txids.iter() {
        let (h, _) = st.generate_next_block_including(*txid);
        st.scan_cached_blocks(h, 1);
    }

    // Check that there are sent outputs with the correct values.
    let confirmed_sent: Vec<Vec<_>> = txids
        .iter()
        .map(|sent_txid| st.wallet().get_sent_outputs(sent_txid).unwrap())
        .collect();

    // Verify that a status request has been generated for the second transaction of
    // the ZIP 320 pair.
    let tx_data_requests = st.wallet().transaction_data_requests().unwrap();
    assert!(tx_data_requests.contains(&TransactionDataRequest::GetStatus(*txids.last())));

    assert!(expected_step0_change > expected_ephemeral_spend);
    assert_eq!(confirmed_sent.len(), 2);
    assert_eq!(confirmed_sent[0].len(), 1);
    assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
    let OutputOfSentTx {
        value: ephemeral_v, ..
    } = confirmed_sent[0][0].clone();
    assert_eq!(ephemeral_v, expected_ephemeral_balance);

    assert_eq!(confirmed_sent[1].len(), 1);
    assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &expected_ephemeral_spend && sent_to_addr == &Some(tex_addr));

    // Check that the transaction history matches what we expect.
    let tx_history = st.wallet().get_tx_history().unwrap();

    let tx_0 = tx_history
        .iter()
        .find(|tx| tx.txid() == *txids.first())
        .unwrap();
    let tx_1 = tx_history
        .iter()
        .find(|tx| tx.txid() == *txids.last())
        .unwrap();

    assert_eq!(tx_0.account_id(), &account_id);
    assert!(!tx_0.expired_unmined());
    assert_eq!(tx_0.has_change(), expected_step0_change.is_zero());
    assert!(!tx_0.is_shielding());
    assert_eq!(
        tx_0.account_value_delta(),
        -ZatBalance::from(expected_step0_fee),
    );

    assert_eq!(tx_1.account_id(), &account_id);
    assert!(!tx_1.expired_unmined());
    assert!(!tx_1.has_change());
    assert!(!tx_0.is_shielding());
    assert_eq!(
        tx_1.account_value_delta(),
        -ZatBalance::from(expected_ephemeral_balance),
    );

    let ending_balance = st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN);
    assert_eq!(initial_balance - total_sent, ending_balance.into());
}

/// This test attempts to send the max spendable funds to a TEX address recipient
/// checks that the transactions were stored and that the amounts involved are correct
#[cfg(feature = "transparent-inputs")]
pub fn spend_everything_multi_step_many_notes_proposed_transfer<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::OutputOfSentTx;
    use zcash_keys::keys::transparent::gap_limits::GapLimits;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache)
        .map(|builder| builder.with_gap_limits(GapLimits::new(10, 5, 3)))
        .build::<T>();

    let number_of_notes = 3u64;
    let note_value = Zatoshis::const_from_u64(100000);
    let value = (note_value * number_of_notes).unwrap();

    // Add funds to the wallet.
    for _ in 0..number_of_notes {
        st.add_a_single_note_checking_balance(note_value);
    }

    let initial_balance = value;
    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        initial_balance
    );

    let expected_step0_fee = (zip317::MARGINAL_FEE * 4u64).unwrap();
    let expected_step1_fee = zip317::MINIMUM_FEE;
    let expected_ephemeral_spend = (value - expected_step0_fee - expected_step1_fee).unwrap();
    let expected_ephemeral_balance = (value - expected_step0_fee).unwrap();
    let expected_step0_change = (value - expected_step0_fee).unwrap();

    let total_sent = (expected_step0_fee + expected_step1_fee + expected_ephemeral_spend).unwrap();

    // check that the napkin math is Ok. Total value send should be the whole
    // value of the wallet
    assert_eq!(total_sent, value);

    // Generate a ZIP 320 proposal, sending to an external TEX address.
    let tex_addr = Address::Tex([0x4; 20]);
    let fee_rule = StandardFeeRule::Zip317;

    // We use `st.propose_standard_transfer` here in order to also test round-trip
    // serialization of the proposal.
    let addy = tex_addr.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account_id,
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let steps: Vec<_> = proposal.steps().iter().cloned().collect();
    assert_eq!(steps.len(), 2);

    assert_eq!(steps[0].balance().fee_required(), expected_step0_fee);
    assert_eq!(steps[1].balance().fee_required(), expected_step1_fee);
    assert_eq!(
        steps[0].balance().proposed_change(),
        [ChangeValue::ephemeral_transparent(
            (total_sent - expected_step0_fee).expect("value is non-zero")
        ),]
    );
    assert_eq!(steps[1].balance().proposed_change(), []);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 2);
    let txids = create_proposed_result.unwrap();

    // Mine the created transactions.
    for txid in txids.iter() {
        let (h, _) = st.generate_next_block_including(*txid);
        st.scan_cached_blocks(h, 1);
    }

    // Check that there are sent outputs with the correct values.
    let confirmed_sent: Vec<Vec<_>> = txids
        .iter()
        .map(|sent_txid| st.wallet().get_sent_outputs(sent_txid).unwrap())
        .collect();

    // Verify that a status request has been generated for the second transaction of
    // the ZIP 320 pair.
    let tx_data_requests = st.wallet().transaction_data_requests().unwrap();
    assert!(tx_data_requests.contains(&TransactionDataRequest::GetStatus(*txids.last())));

    assert!(expected_step0_change > expected_ephemeral_spend);
    assert_eq!(confirmed_sent.len(), 2);
    assert_eq!(confirmed_sent[0].len(), 1);
    assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
    let OutputOfSentTx {
        value: ephemeral_v, ..
    } = confirmed_sent[0][0].clone();
    assert_eq!(ephemeral_v, expected_ephemeral_balance);

    assert_eq!(confirmed_sent[1].len(), 1);
    assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &expected_ephemeral_spend && sent_to_addr == &Some(tex_addr));

    // Check that the transaction history matches what we expect.
    let tx_history = st.wallet().get_tx_history().unwrap();

    let tx_0 = tx_history
        .iter()
        .find(|tx| tx.txid() == *txids.first())
        .unwrap();
    let tx_1 = tx_history
        .iter()
        .find(|tx| tx.txid() == *txids.last())
        .unwrap();

    assert_eq!(tx_0.account_id(), &account_id);
    assert!(!tx_0.expired_unmined());
    assert_eq!(tx_0.has_change(), expected_step0_change.is_zero());
    assert!(!tx_0.is_shielding());
    assert_eq!(
        tx_0.account_value_delta(),
        -ZatBalance::from(expected_step0_fee),
    );

    assert_eq!(tx_1.account_id(), &account_id);
    assert!(!tx_1.expired_unmined());
    assert!(!tx_1.has_change());
    assert!(!tx_0.is_shielding());
    assert_eq!(
        tx_1.account_value_delta(),
        -ZatBalance::from(expected_ephemeral_balance),
    );

    let ending_balance = st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN);
    assert_eq!(initial_balance - total_sent, ending_balance.into());
}

/// This test attempts to send the max spendable funds to a TEX address recipient.
/// The wallet contains many notes denominated with the marginal fee value.
/// Checks that the transactions were stored and that the amounts involved are correct
#[cfg(feature = "transparent-inputs")]
pub fn spend_everything_multi_step_with_marginal_notes_proposed_transfer<
    T: ShieldedPoolTester,
    Dsf,
>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::{MaxSpendMode, OutputOfSentTx};
    use zcash_keys::keys::transparent::gap_limits::GapLimits;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache)
        .map(|builder| builder.with_gap_limits(GapLimits::new(10, 5, 3)))
        .build::<T>();

    let number_of_notes = 10u64;
    let note_value = Zatoshis::const_from_u64(100000);
    let non_marginal_notes_value =
        (note_value * number_of_notes).expect("sum of notes should not fail.");

    for _ in 0..number_of_notes {
        st.add_a_single_note_checking_balance(note_value);
        st.add_a_single_note_checking_balance(zip317::MARGINAL_FEE);
    }

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        non_marginal_notes_value
    );

    let expected_step0_fee = (zip317::MARGINAL_FEE * (number_of_notes + 1)).unwrap();
    let expected_step1_fee = zip317::MINIMUM_FEE;
    let expected_ephemeral_spend =
        (non_marginal_notes_value - expected_step0_fee - expected_step1_fee).unwrap();
    let expected_ephemeral_balance = (non_marginal_notes_value - expected_step0_fee).unwrap();
    let expected_step0_change = (non_marginal_notes_value - expected_step0_fee).unwrap();

    let total_sent = (expected_step0_fee + expected_step1_fee + expected_ephemeral_spend).unwrap();

    // check that the napkin math is Ok. Total value send should be the whole
    // value of the wallet
    assert_eq!(total_sent, non_marginal_notes_value);

    // Generate a ZIP 320 proposal, sending to an external TEX address.
    let tex_addr = Address::Tex([0x4; 20]);

    let fee_rule = StandardFeeRule::Zip317;

    // We use `st.propose_standard_transfer` here in order to also test round-trip
    // serialization of the proposal.
    let addy = tex_addr.to_zcash_address(st.network());
    let proposal = st
        .propose_send_max_transfer(
            account_id,
            &fee_rule,
            addy,
            None,
            MaxSpendMode::Everything,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let steps: Vec<_> = proposal.steps().iter().cloned().collect();
    assert_eq!(steps.len(), 2);

    assert_eq!(
        steps[0].shielded_inputs().unwrap().notes().len() as u64,
        number_of_notes
    );
    assert_eq!(steps[0].balance().fee_required(), expected_step0_fee);
    assert_eq!(steps[1].balance().fee_required(), expected_step1_fee);
    assert_eq!(
        steps[0].balance().proposed_change(),
        [ChangeValue::ephemeral_transparent(
            (total_sent - expected_step0_fee).expect("value is non-zero")
        ),]
    );
    assert_eq!(steps[1].balance().proposed_change(), []);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 2);
    let txids = create_proposed_result.unwrap();

    // Mine the created transactions.
    for txid in txids.iter() {
        let (h, _) = st.generate_next_block_including(*txid);
        st.scan_cached_blocks(h, 1);
    }

    // Check that there are sent outputs with the correct values.
    let confirmed_sent: Vec<Vec<_>> = txids
        .iter()
        .map(|sent_txid| st.wallet().get_sent_outputs(sent_txid).unwrap())
        .collect();

    // Verify that a status request has been generated for the second transaction of
    // the ZIP 320 pair.
    let tx_data_requests = st.wallet().transaction_data_requests().unwrap();
    assert!(tx_data_requests.contains(&TransactionDataRequest::GetStatus(*txids.last())));

    assert!(expected_step0_change > expected_ephemeral_spend);
    assert_eq!(confirmed_sent.len(), 2);
    assert_eq!(confirmed_sent[0].len(), 1);
    assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
    let OutputOfSentTx {
        value: ephemeral_v, ..
    } = confirmed_sent[0][0].clone();
    assert_eq!(ephemeral_v, expected_ephemeral_balance);

    assert_eq!(confirmed_sent[1].len(), 1);
    assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &expected_ephemeral_spend && sent_to_addr == &Some(tex_addr));

    // Check that the transaction history matches what we expect.
    let tx_history = st.wallet().get_tx_history().unwrap();

    let tx_0 = tx_history
        .iter()
        .find(|tx| tx.txid() == *txids.first())
        .unwrap();
    let tx_1 = tx_history
        .iter()
        .find(|tx| tx.txid() == *txids.last())
        .unwrap();

    assert_eq!(tx_0.account_id(), &account_id);
    assert!(!tx_0.expired_unmined());
    assert_eq!(tx_0.has_change(), expected_step0_change.is_zero());
    assert!(!tx_0.is_shielding());
    assert_eq!(
        tx_0.account_value_delta(),
        -ZatBalance::from(expected_step0_fee),
    );

    assert_eq!(tx_1.account_id(), &account_id);
    assert!(!tx_1.expired_unmined());
    assert!(!tx_1.has_change());
    assert!(!tx_0.is_shielding());
    assert_eq!(
        tx_1.account_value_delta(),
        -ZatBalance::from(expected_ephemeral_balance),
    );

    let ending_balance = st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN);
    assert_eq!(ending_balance, Zatoshis::ZERO); // ending balance should be zero
}

pub fn send_with_multiple_change_outputs<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(650_0000);
    let (h, _, _) = st.add_a_single_note_checking_balance(value);

    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(100_0000),
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    let change_memo = "Test change memo".parse::<Memo>().unwrap();
    let change_strategy = fees::zip317::MultiOutputChangeStrategy::new(
        Zip317FeeRule::standard(),
        Some(change_memo.clone().into()),
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(2).unwrap(),
            Zatoshis::const_from_u64(100_0000),
        ),
    );

    let account = st.test_account().cloned().unwrap();
    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request.clone(),
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let step = &proposal.steps().head;
    assert_eq!(step.balance().proposed_change().len(), 2);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let sent_tx_id = create_proposed_result.unwrap()[0];

    // Verify that the sent transaction was stored and that we can decrypt the memos
    let tx = st
        .wallet()
        .get_transaction(sent_tx_id)
        .unwrap()
        .expect("Created transaction was stored.");
    let ufvks = [(account.id(), account.usk().to_unified_full_viewing_key())]
        .into_iter()
        .collect();
    let d_tx = decrypt_transaction(st.network(), None, Some(h), &tx, &ufvks);
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 3);

    let mut found_tx_change_memo = false;
    let mut found_tx_empty_memo = false;
    T::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == change_memo {
            found_tx_change_memo = true
        }
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_tx_change_memo);
    assert!(found_tx_empty_memo);

    // Verify that the stored sent notes match what we're expecting
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(sent_note_ids.len(), 3);

    // The sent memo should be the empty memo for the sent output, and each
    // change output's memo should be as specified.
    let mut change_memo_count = 0;
    let mut found_sent_empty_memo = false;
    for sent_note_id in sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Note id is valid")
            .as_ref()
        {
            Some(m) if m == &change_memo => {
                change_memo_count += 1;
            }
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }
    assert_eq!(change_memo_count, 2);
    assert!(found_sent_empty_memo);

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 2);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(650_0000));
    }

    {
        let tx_1 = &tx_history[1];
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(650_0000));
        assert_eq!(tx_1.total_received(), Zatoshis::const_from_u64(548_5000));
        assert_eq!(tx_1.fee_paid(), Some(Zatoshis::const_from_u64(15000)));
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );

    let (h, _) = st.generate_next_block_including(sent_tx_id);
    st.scan_cached_blocks(h, 1);

    // Now, create another proposal with more outputs requested. We have two change notes;
    // we'll spend one of them, and then we'll generate 7 splits.
    let change_strategy = fees::zip317::MultiOutputChangeStrategy::new(
        Zip317FeeRule::standard(),
        Some(change_memo.into()),
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(8).unwrap(),
            Zatoshis::const_from_u64(10_0000),
        ),
    );

    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let step = &proposal.steps().head;
    assert_eq!(step.balance().proposed_change().len(), 7);
}

#[cfg(feature = "transparent-inputs")]
pub fn send_multi_step_proposed_transfer<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
    is_reached_gap_limit: impl Fn(&<Dsf::DataStore as WalletRead>::Error, Dsf::AccountId, u32) -> bool,
) where
    Dsf: DataStoreFactory,
{
    use crate::{
        data_api::{OutputOfSentTx, TransactionStatus},
        wallet::{Exposure, TransparentAddressSource},
    };
    use zcash_keys::keys::transparent::gap_limits::GapLimits;

    let gap_limits = GapLimits::new(10, 5, 3);
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache)
        .map(|builder| builder.with_gap_limits(gap_limits))
        .build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);
    let tex_addr = Address::Tex([0x4; 20]);

    let add_funds = |st: &mut TestState<_, Dsf::DataStore, _>, value| {
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        assert_eq!(
            st.wallet()
                .block_max_scanned()
                .unwrap()
                .unwrap()
                .block_height(),
            h
        );
        h
    };

    let value = Zatoshis::const_from_u64(100000);
    let transfer_amount = Zatoshis::const_from_u64(50000);

    let run_test = |st: &mut TestState<_, Dsf::DataStore, _>, expected_index, prior_balance| {
        // Add funds to the wallet.
        add_funds(st, value);
        let initial_balance: Option<Zatoshis> = prior_balance + value;
        assert_eq!(
            st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
            initial_balance.unwrap()
        );

        let expected_step0_fee = (zip317::MARGINAL_FEE * 3u64).unwrap();
        let expected_step1_fee = zip317::MINIMUM_FEE;
        let expected_ephemeral = (transfer_amount + expected_step1_fee).unwrap();
        let expected_step0_change =
            (initial_balance - expected_ephemeral - expected_step0_fee).expect("sufficient funds");
        assert!(expected_step0_change.is_positive());

        let total_sent = (expected_step0_fee + expected_step1_fee + transfer_amount).unwrap();

        // Generate a ZIP 320 proposal, sending to another wallet's default transparent address
        // expressed as a TEX address.
        let change_memo = Some(Memo::from_str("change").expect("valid memo").encode());

        // We use `st.propose_standard_transfer` here in order to also test round-trip
        // serialization of the proposal.
        let proposal = st
            .propose_standard_transfer::<Infallible>(
                account_id,
                StandardFeeRule::Zip317,
                ConfirmationsPolicy::MIN,
                &tex_addr,
                transfer_amount,
                None,
                change_memo.clone(),
                T::SHIELDED_PROTOCOL,
            )
            .unwrap();

        let steps: Vec<_> = proposal.steps().iter().cloned().collect();
        assert_eq!(steps.len(), 2);

        assert_eq!(steps[0].balance().fee_required(), expected_step0_fee);
        assert_eq!(steps[1].balance().fee_required(), expected_step1_fee);
        assert_eq!(
            steps[0].balance().proposed_change(),
            [
                ChangeValue::shielded(T::SHIELDED_PROTOCOL, expected_step0_change, change_memo),
                ChangeValue::ephemeral_transparent(expected_ephemeral),
            ]
        );
        assert_eq!(steps[1].balance().proposed_change(), []);

        // There should be no ephemeral addresses exposed at the current chain height
        let exposed_at_tip = st
            .wallet()
            .get_ephemeral_transparent_receivers(account.account().id(), 1, false)
            .unwrap();
        assert_eq!(exposed_at_tip.len(), 0);

        let create_proposed_result = st
            .create_proposed_transactions::<Infallible, _, Infallible, _>(
                account.usk(),
                OvkPolicy::Sender,
                &proposal,
            );
        assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 2);
        let txids = create_proposed_result.unwrap();

        // After creation, there should be a new ephemeral address exposed.
        let exposed_at_tip = st
            .wallet()
            .get_ephemeral_transparent_receivers(account.account().id(), 1, false)
            .unwrap();
        assert_eq!(exposed_at_tip.len(), 1);
        let cur_height = st.wallet().chain_height().unwrap().unwrap();
        assert_matches!(
            exposed_at_tip.values().next().map(|m0| m0.exposure()),
            Some(Exposure::Exposed { at_height, .. }) if at_height == cur_height
        );

        // There should be no unused transparent receivers in this range
        let exposed_at_tip = st
            .wallet()
            .get_ephemeral_transparent_receivers(account.account().id(), 1, true)
            .unwrap();
        assert!(exposed_at_tip.is_empty());

        // Mine the created transactions.
        for txid in txids.iter() {
            let (h, _) = st.generate_next_block_including(*txid);
            st.scan_cached_blocks(h, 1);
        }

        // Check that there are sent outputs with the correct values.
        let confirmed_sent: Vec<Vec<_>> = txids
            .iter()
            .map(|sent_txid| st.wallet().get_sent_outputs(sent_txid).unwrap())
            .collect();

        // Verify that a status request has been generated for the second transaction of
        // the ZIP 320 pair.
        let tx_data_requests = st.wallet().transaction_data_requests().unwrap();
        assert!(tx_data_requests.contains(&TransactionDataRequest::GetStatus(*txids.last())));

        assert!(expected_step0_change < expected_ephemeral);
        assert_eq!(confirmed_sent.len(), 2);
        assert_eq!(confirmed_sent[0].len(), 2);
        assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
        let OutputOfSentTx {
            value: ephemeral_v,
            external_recipient: to_addr,
            ephemeral_address,
        } = confirmed_sent[0][1].clone();
        assert_eq!(ephemeral_v, expected_ephemeral);
        assert!(to_addr.is_some());
        assert_eq!(
            ephemeral_address,
            to_addr.map(|addr| (
                addr,
                NonHardenedChildIndex::const_from_index(expected_index)
            )),
        );

        assert_eq!(confirmed_sent[1].len(), 1);
        assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &transfer_amount && sent_to_addr.as_ref() == Some(&tex_addr));

        // Check that the transaction history matches what we expect.
        let tx_history = st.wallet().get_tx_history().unwrap();

        let tx_0 = tx_history
            .iter()
            .find(|tx| tx.txid() == *txids.first())
            .unwrap();
        let tx_1 = tx_history
            .iter()
            .find(|tx| tx.txid() == *txids.last())
            .unwrap();

        assert_eq!(tx_0.account_id(), &account_id);
        assert!(!tx_0.expired_unmined());
        assert_eq!(tx_0.has_change(), expected_step0_change.is_positive());
        assert!(!tx_0.is_shielding());
        assert_eq!(
            tx_0.account_value_delta(),
            -ZatBalance::from(expected_step0_fee),
        );

        assert_eq!(tx_1.account_id(), &account_id);
        assert!(!tx_1.expired_unmined());
        assert!(!tx_1.has_change());
        assert!(!tx_0.is_shielding());
        assert_eq!(
            tx_1.account_value_delta(),
            -ZatBalance::from(expected_ephemeral),
        );

        let ending_balance = st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN);
        assert_eq!(initial_balance - total_sent, ending_balance.into());

        (ephemeral_address.unwrap().0, txids, ending_balance)
    };

    // Each transfer should use a different ephemeral address.
    let (ephemeral0, _, bal_0) = run_test(&mut st, 0, Zatoshis::ZERO);
    let (ephemeral1, _, _) = run_test(&mut st, 1, bal_0);
    assert_ne!(ephemeral0, ephemeral1);

    add_funds(&mut st, value);

    assert_matches!(
        ephemeral0,
        Address::Transparent(TransparentAddress::PublicKeyHash(_))
    );

    // Simulate another wallet sending to an ephemeral address with an index
    // within the current gap limit.
    let known_addrs = st
        .wallet()
        .get_known_ephemeral_addresses(account_id, None)
        .unwrap();
    assert_eq!(
        known_addrs.len(),
        usize::try_from(gap_limits.ephemeral() + 2).unwrap()
    );

    // Check that the addresses are all distinct.
    let known_set: HashSet<_> = known_addrs.iter().map(|(addr, _)| addr).collect();
    assert_eq!(known_set.len(), known_addrs.len());
    // Check that the metadata is as expected.
    for (i, (_, meta)) in known_addrs.iter().enumerate() {
        assert_eq!(
            meta.source(),
            &TransparentAddressSource::Derived {
                scope: TransparentKeyScope::EPHEMERAL,
                address_index: NonHardenedChildIndex::from_index(i.try_into().unwrap()).unwrap(),
            }
        );
    }

    let (colliding_addr, _) = &known_addrs[usize::try_from(gap_limits.ephemeral() - 1).unwrap()];
    let utxo_value = (value - zip317::MINIMUM_FEE).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::MIN,
            &Address::from(*colliding_addr),
            utxo_value,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Create the transaction. This will cause the the gap start to move & a new
    // `gap_limits.ephemeral()` of addresses to be created.
    let txids = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();

    // Mine the transaction & update its status to advance the gap. We have to manually update the
    // status because scanning will not detect the transparent outputs.
    let (h, _) = st.generate_next_block_including(txids.head);
    st.scan_cached_blocks(h, 1);
    st.wallet_mut()
        .set_transaction_status(txids.head, TransactionStatus::Mined(h))
        .unwrap();

    // At this point the start of the gap should be at index `gap_limits.ephemeral()` and the new
    // size of the known address set should be `gap_limits.ephemeral() * 2`.
    let new_known_addrs = st
        .wallet()
        .get_known_ephemeral_addresses(account_id, None)
        .unwrap();
    assert_eq!(
        new_known_addrs.len(),
        usize::try_from(gap_limits.ephemeral() * 2).unwrap()
    );

    // check that known_addrs is a prefix of new_known_addrs; we have already checked their
    // lengths.
    assert!(
        new_known_addrs
            .iter()
            .map(|a| a.0)
            .zip(known_addrs.iter().map(|a| a.0))
            .all(|(a, b)| a == b),
        "new_known_addrs must have known_addrs as its prefix"
    );

    let reservation_should_succeed = |st: &mut TestState<_, Dsf::DataStore, _>, n: u32| {
        let reserved = st
            .wallet_mut()
            .reserve_next_n_ephemeral_addresses(account_id, n.try_into().unwrap())
            .unwrap();
        assert_eq!(reserved.len(), usize::try_from(n).unwrap());
        reserved
    };
    let reservation_should_fail =
        |st: &mut TestState<_, Dsf::DataStore, _>, n: u32, expected_bad_index| {
            assert_matches!(st
            .wallet_mut()
            .reserve_next_n_ephemeral_addresses(account_id, n.try_into().unwrap()),
            Err(e) if is_reached_gap_limit(&e, account_id, expected_bad_index));
        };

    assert_matches!(
        known_addrs[usize::try_from(gap_limits.ephemeral()).unwrap()]
            .1
            .exposure(),
        Exposure::Unknown
    );

    let next_reserved = reservation_should_succeed(&mut st, 1);

    // By reserving the address, its exposure has transitioned from "unknown" to "exposed".
    let gap_position = 0;
    let expected = &known_addrs[usize::try_from(gap_limits.ephemeral()).unwrap()];
    let actual = &next_reserved[usize::try_from(gap_position).unwrap()];
    assert_eq!(actual.0, expected.0);
    assert_eq!(actual.1.source(), expected.1.source());
    assert_eq!(expected.1.exposure(), Exposure::Unknown);
    assert_eq!(
        actual.1.exposure(),
        Exposure::Exposed {
            at_height: st.latest_block_height.unwrap(),
            gap_metadata: crate::wallet::GapMetadata::InGap {
                gap_position,
                gap_limit: gap_limits.ephemeral(),
            }
        }
    );

    // The range of address indices that are safe to reserve now is
    // 0..(gap_limits.ephemeral() * 2 - 1)`, and we have already reserved or used
    // `gap_limits.ephemeral() + 1`, addresses, so trying to reserve another
    // `gap_limits.ephemeral()` should fail.
    reservation_should_fail(&mut st, gap_limits.ephemeral(), gap_limits.ephemeral() * 2);
    reservation_should_succeed(&mut st, gap_limits.ephemeral() - 1);
    // Now we've reserved everything we can, we can't reserve one more
    reservation_should_fail(&mut st, 1, gap_limits.ephemeral() * 2);
}

/// Tests spending all funds within the given shielded pool in a single transaction.
///
/// The test:
/// - Adds funds to the wallet in a single note.
/// - Checks that the wallet balances are correct.
/// - Constructs a request to spend all of that balance to an external address in the
///   same pool.
/// - Builds the transaction.
/// - Checks that the transaction was stored, and that the outputs are decryptable and
///   have the expected details.
pub fn spend_all_funds_single_step_proposed_transfer<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(60000);
    let (h, _, _) = st.add_a_single_note_checking_balance(value);

    let spend_amount = Zatoshis::const_from_u64(50000);
    let to_extsk = T::sk(&[0xf5; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        spend_amount,
    )])
    .unwrap();

    let fee_rule = StandardFeeRule::Zip317;

    let change_memo = "Test change memo".parse::<Memo>().unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        fee_rule,
        Some(change_memo.clone().into()),
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let account = st.test_account().cloned().unwrap();
    let proposal = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let sent_tx_id = create_proposed_result.unwrap()[0];

    // Verify that the sent transaction was stored and that we can decrypt the memos
    let tx = st
        .wallet()
        .get_transaction(sent_tx_id)
        .unwrap()
        .expect("Created transaction was stored.");
    let ufvks = [(account.id(), account.usk().to_unified_full_viewing_key())]
        .into_iter()
        .collect();
    let d_tx = decrypt_transaction(st.network(), None, Some(h), &tx, &ufvks);
    assert_eq!(T::decrypted_pool_outputs_count(&d_tx), 2);

    let mut found_tx_change_memo = false;
    let mut found_tx_empty_memo = false;
    T::with_decrypted_pool_memos(&d_tx, |memo| {
        if Memo::try_from(memo).unwrap() == change_memo {
            found_tx_change_memo = true
        }
        if Memo::try_from(memo).unwrap() == Memo::Empty {
            found_tx_empty_memo = true
        }
    });
    assert!(found_tx_change_memo);
    assert!(found_tx_empty_memo);

    // Verify that the stored sent notes match what we're expecting
    let sent_note_ids = st
        .wallet()
        .get_sent_note_ids(&sent_tx_id, T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(sent_note_ids.len(), 2);

    // The sent memo should be the empty memo for the sent output, and the
    // change output's memo should be as specified.
    let mut found_sent_change_memo = false;
    let mut found_sent_empty_memo = false;
    for sent_note_id in sent_note_ids {
        match st
            .wallet()
            .get_memo(sent_note_id)
            .expect("Note id is valid")
            .as_ref()
        {
            Some(m) if m == &change_memo => {
                found_sent_change_memo = true;
            }
            Some(m) if m == &Memo::Empty => {
                found_sent_empty_memo = true;
            }
            Some(other) => panic!("Unexpected memo value: {other:?}"),
            None => panic!("Memo should not be stored as NULL"),
        }
    }
    assert!(found_sent_change_memo);
    assert!(found_sent_empty_memo);

    // Check that querying for a nonexistent sent note returns None
    assert_matches!(
        st.wallet()
            .get_memo(NoteId::new(sent_tx_id, T::SHIELDED_PROTOCOL, 12345)),
        Ok(None)
    );

    let tx_history = st.wallet().get_tx_history().unwrap();
    assert_eq!(tx_history.len(), 2);
    {
        let tx_0 = &tx_history[0];
        assert_eq!(tx_0.total_spent(), Zatoshis::const_from_u64(0));
        assert_eq!(tx_0.total_received(), Zatoshis::const_from_u64(60000));
    }

    {
        let tx_1 = &tx_history[1];
        assert_eq!(tx_1.total_spent(), Zatoshis::const_from_u64(60000));
        assert_eq!(tx_1.total_received(), Zatoshis::ZERO);
    }

    let network = *st.network();
    assert_matches!(
        decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, None),
        Ok(_)
    );
}
/// Test attempts to sweep a wallet into a TEX address
///
/// 1. funds wallet with 100000 Zatoshis
/// 2. sets that spend amount will be 75000 Zatoshi
/// 3. proposes a transaction to a TEX address spending 75000 Zatoshi
/// 4. attempts to perform the proposal
/// 5. proposes the transaction
/// 6. "mines" the transaction.
/// 7. checks that all funds have been spent by the two involved transactions
///
/// Desired effects:
/// - all funds are spent
/// - Fees are the least possible: in this case 15000 for tr0 and 10000 Zats for tr1
#[cfg(feature = "transparent-inputs")]
pub fn spend_all_funds_multi_step_proposed_transfer<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::OutputOfSentTx;
    use zcash_keys::keys::transparent::gap_limits::GapLimits;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache)
        .map(|builder| builder.with_gap_limits(GapLimits::new(10, 5, 3)))
        .build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    let value = Zatoshis::const_from_u64(100000);
    let transfer_amount = Zatoshis::const_from_u64(75000);

    // Add funds to the wallet.
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    let initial_balance = value;
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        initial_balance
    );

    let expected_step0_fee = (zip317::MARGINAL_FEE * 3u64).unwrap();
    let expected_step1_fee = zip317::MINIMUM_FEE;
    let expected_ephemeral = (transfer_amount + expected_step1_fee).unwrap();
    let expected_step0_change =
        (initial_balance - expected_ephemeral - expected_step0_fee).expect("sufficient funds");
    assert!(expected_step0_change.is_zero());

    let total_sent = (expected_step0_fee + expected_step1_fee + transfer_amount).unwrap();

    // Generate a ZIP 320 proposal, sending to an external TEX address.
    let tex_addr = Address::Tex([0x4; 20]);

    let change_memo: Option<MemoBytes> = None;
    // We use `st.propose_standard_transfer` here in order to also test round-trip
    // serialization of the proposal.
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::MIN,
            &tex_addr,
            transfer_amount,
            None,
            change_memo.clone(),
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    let steps: Vec<_> = proposal.steps().iter().cloned().collect();
    assert_eq!(steps.len(), 2);

    assert_eq!(steps[0].balance().fee_required(), expected_step0_fee);
    assert_eq!(steps[1].balance().fee_required(), expected_step1_fee);
    assert_eq!(
        steps[0].balance().proposed_change(),
        [
            ChangeValue::shielded(T::SHIELDED_PROTOCOL, expected_step0_change, change_memo),
            ChangeValue::ephemeral_transparent(expected_ephemeral),
        ]
    );
    assert_eq!(steps[1].balance().proposed_change(), []);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 2);
    let txids = create_proposed_result.unwrap();

    // Mine the created transactions.
    for txid in txids.iter() {
        let (h, _) = st.generate_next_block_including(*txid);
        st.scan_cached_blocks(h, 1);
    }

    // Check that there are sent outputs with the correct values.
    let confirmed_sent: Vec<Vec<_>> = txids
        .iter()
        .map(|sent_txid| st.wallet().get_sent_outputs(sent_txid).unwrap())
        .collect();

    // Verify that a status request has been generated for the second transaction of
    // the ZIP 320 pair.
    let tx_data_requests = st.wallet().transaction_data_requests().unwrap();
    assert!(tx_data_requests.contains(&TransactionDataRequest::GetStatus(*txids.last())));

    assert!(expected_step0_change < expected_ephemeral);
    assert_eq!(confirmed_sent.len(), 2);
    assert_eq!(confirmed_sent[0].len(), 2);
    assert_eq!(confirmed_sent[0][0].value, expected_step0_change);
    let OutputOfSentTx {
        value: ephemeral_v,
        external_recipient: to_addr,
        ephemeral_address: _,
    } = confirmed_sent[0][1].clone();
    assert_eq!(ephemeral_v, expected_ephemeral);
    assert!(to_addr.is_some());

    assert_eq!(confirmed_sent[1].len(), 1);
    assert_matches!(
            &confirmed_sent[1][0],
            OutputOfSentTx { value: sent_v, external_recipient: sent_to_addr, ephemeral_address: None }
            if sent_v == &transfer_amount && sent_to_addr == &Some(tex_addr));

    // Check that the transaction history matches what we expect.
    let tx_history = st.wallet().get_tx_history().unwrap();

    let tx_0 = tx_history
        .iter()
        .find(|tx| tx.txid() == *txids.first())
        .unwrap();
    let tx_1 = tx_history
        .iter()
        .find(|tx| tx.txid() == *txids.last())
        .unwrap();

    assert_eq!(tx_0.account_id(), &account_id);
    assert!(!tx_0.expired_unmined());
    assert_eq!(tx_0.has_change(), expected_step0_change.is_zero());
    assert!(!tx_0.is_shielding());
    assert_eq!(
        tx_0.account_value_delta(),
        -ZatBalance::from(expected_step0_fee),
    );

    assert_eq!(tx_1.account_id(), &account_id);
    assert!(!tx_1.expired_unmined());
    assert!(!tx_1.has_change());
    assert!(!tx_0.is_shielding());
    assert_eq!(
        tx_1.account_value_delta(),
        -ZatBalance::from(expected_ephemeral),
    );

    let ending_balance = st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN);
    assert_eq!(initial_balance - total_sent, ending_balance.into());
}

#[cfg(feature = "transparent-inputs")]
pub fn proposal_fails_if_not_all_ephemeral_outputs_consumed<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    let add_funds = |st: &mut TestState<_, Dsf::DataStore, _>, value| {
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        assert_eq!(
            st.wallet()
                .block_max_scanned()
                .unwrap()
                .unwrap()
                .block_height(),
            h
        );
        assert_eq!(
            st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
            value
        );
    };

    let value = Zatoshis::const_from_u64(100000);
    let transfer_amount = Zatoshis::const_from_u64(50000);

    // Add funds to the wallet.
    add_funds(&mut st, value);

    // Generate a ZIP 320 proposal, sending to an external TEX address.
    let tex_addr = Address::Tex([0x4; 20]);
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::MIN,
            &tex_addr,
            transfer_amount,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // This is somewhat redundant with `send_multi_step_proposed_transfer`,
    // but tests the case with no change memo and ensures we haven't messed
    // up the test setup.
    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(create_proposed_result, Ok(_));

    // Frobnicate the proposal to make it invalid because it does not consume
    // the ephemeral output, by truncating it to the first step.
    let frobbed_proposal = Proposal::multi_step(
        *proposal.fee_rule(),
        proposal.min_target_height(),
        proposal.confirmations_policy(),
        NonEmpty::singleton(proposal.steps().first().clone()),
    )
    .unwrap();

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &frobbed_proposal,
    );
    assert_matches!(
        create_proposed_result,
        Err(Error::Proposal(ProposalError::EphemeralOutputLeftUnspent(so)))
        if so == StepOutput::new(0, StepOutputIndex::Change(1))
    );
}

pub fn create_to_address_fails_on_incorrect_usk<T: ShieldedPoolTester, Dsf: DataStoreFactory>(
    ds_factory: Dsf,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, ()).build::<T>();
    let dfvk = T::test_account_fvk(&st);
    let to = T::fvk_default_address(&dfvk);

    // Create a USK that doesn't exist in the wallet
    let acct1 = zip32::AccountId::try_from(1).unwrap();
    let usk1 = UnifiedSpendingKey::from_seed(st.network(), &[1u8; 32], acct1).unwrap();

    let input_selector = GreedyInputSelector::<Dsf::DataStore>::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    let req = TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(1),
    )])
    .unwrap();

    // Attempting to spend with a USK that is not in the wallet results in an error
    assert_matches!(
        st.spend(
            &input_selector,
            &change_strategy,
            &usk1,
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        ),
        Err(data_api::error::Error::KeyNotRecognized)
    );
}

pub fn proposal_fails_with_no_blocks<T: ShieldedPoolTester, Dsf>(ds_factory: Dsf)
where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, ()).build::<T>();

    let account_id = st.test_account().unwrap().id();
    let dfvk = T::test_account_fvk(&st);
    let to = T::fvk_default_address(&dfvk);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(ConfirmationsPolicy::MIN), None);

    // We cannot do anything if we aren't synchronised
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(1),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::ScanRequired)
    );
}

pub fn spend_fails_on_unverified_notes<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    st.add_a_single_note_checking_balance(value);

    // Value is considered pending at 10 confirmations.
    assert_eq!(
        st.get_pending_shielded_balance(account_id, ConfirmationsPolicy::default()),
        value
    );
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::default()),
        Zatoshis::ZERO
    );

    // If none of the wallet's accounts have a recover-until height, then there
    // is no recovery phase for the wallet, and therefore the denominator in the
    // resulting ratio (the number of notes in the recovery range) is zero.
    let no_recovery = Some(Ratio::new(0, 0));

    // Wallet is fully scanned
    let summary = st.get_wallet_summary(ConfirmationsPolicy::MIN);
    assert_eq!(
        summary.as_ref().and_then(|s| s.progress().recovery()),
        no_recovery,
    );
    assert_eq!(summary.map(|s| s.progress().scan()), Some(Ratio::new(1, 1)));

    // Add more funds to the wallet in a second note
    let (h2, _, _) = st.add_a_single_note_checking_balance(value);

    // Verified balance does not include the second note
    let total = (value + value).unwrap();
    assert_eq!(
        st.get_spendable_balance(
            account_id,
            ConfirmationsPolicy::new_symmetrical_unchecked(
                2,
                #[cfg(feature = "transparent-inputs")]
                false
            )
        ),
        value
    );
    assert_eq!(
        st.get_pending_shielded_balance(
            account_id,
            ConfirmationsPolicy::new_symmetrical_unchecked(
                2,
                #[cfg(feature = "transparent-inputs")]
                false
            )
        ),
        value
    );
    assert_eq!(st.get_total_balance(account_id), total);

    // Wallet is still fully scanned
    let summary = st.get_wallet_summary(ConfirmationsPolicy::MIN);
    assert_eq!(
        summary.as_ref().and_then(|s| s.progress().recovery()),
        no_recovery
    );
    assert_eq!(summary.map(|s| s.progress().scan()), Some(Ratio::new(2, 2)));

    // Spend fails because there are insufficient verified notes
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::new_symmetrical_unchecked(
                2,
                #[cfg(feature = "transparent-inputs")]
                false
            ),
            &to,
            Zatoshis::const_from_u64(70000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == Zatoshis::const_from_u64(50000)
            && required == Zatoshis::const_from_u64(80000)
    );

    // Mine blocks SAPLING_ACTIVATION_HEIGHT + 2 to 9 until just before the second
    // note is verified
    for _ in 2..10 {
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    }
    st.scan_cached_blocks(h2 + 1, 8);

    // Total balance is value * number of blocks scanned (10).
    assert_eq!(st.get_total_balance(account_id), (value * 10u64).unwrap());

    // Spend still fails
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::default(),
            &to,
            Zatoshis::const_from_u64(70000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == Zatoshis::const_from_u64(50000)
            && required == Zatoshis::const_from_u64(80000)
    );

    // Mine block 11 so that the second note becomes verified
    let (h11, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h11, 1);

    // Total balance is value * number of blocks scanned (11).
    assert_eq!(st.get_total_balance(account_id), (value * 11u64).unwrap());
    // Spendable balance at 10 confirmations is value * 2.
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::default()),
        (value * 2u64).unwrap()
    );
    assert_eq!(
        st.get_pending_shielded_balance(account_id, ConfirmationsPolicy::default()),
        (value * 9u64).unwrap()
    );

    // Should now be able to generate a proposal
    let amount_sent = Zatoshis::from_u64(70000).unwrap();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::default(),
            &to,
            amount_sent,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    let txid = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    // TODO: send to an account so that we can check its balance.
    assert_eq!(
        st.get_total_balance(account_id),
        ((value * 11u64).unwrap() - (amount_sent + Zatoshis::from_u64(10000).unwrap()).unwrap())
            .unwrap()
    );
}

pub fn spend_fails_on_locked_notes<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let fee_rule = StandardFeeRule::Zip317;

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (h1, _, _) = st.add_a_single_note_checking_balance(value);

    // Send some of the funds to another address, but don't mine the tx.
    let extsk2 = T::sk(&[0xf5; 32]);
    let to = T::sk_default_address(&extsk2);
    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(15000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal,),
        Ok(txids) if txids.len() == 1
    );

    // A second proposal fails because there are no usable notes
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(2000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == Zatoshis::ZERO && required == Zatoshis::const_from_u64(12000)
    );

    // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 41 (that don't send us funds)
    // until just before the first transaction expires
    for i in 1..42 {
        st.generate_next_block(
            &T::sk_to_fvk(&T::sk(&[i as u8; 32])),
            AddressType::DefaultExternal,
            value,
        );
    }
    st.scan_cached_blocks(h1 + 1, 40);

    // Second proposal still fails
    assert_matches!(
        st.propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(2000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        ),
        Err(data_api::error::Error::InsufficientFunds {
            available,
            required
        })
        if available == Zatoshis::ZERO && required == Zatoshis::const_from_u64(12000)
    );

    // Mine block SAPLING_ACTIVATION_HEIGHT + 42 so that the first transaction expires
    let (h43, _, _) = st.generate_next_block(
        &T::sk_to_fvk(&T::sk(&[42; 32])),
        AddressType::DefaultExternal,
        value,
    );
    st.scan_cached_blocks(h43, 1);

    // Spendable balance matches total balance at 1 confirmation.
    assert_eq!(st.get_total_balance(account_id), value);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        value
    );

    // Second spend should now succeed
    let amount_sent2 = Zatoshis::const_from_u64(2000);
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            amount_sent2,
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    let txid2 = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid2);
    st.scan_cached_blocks(h, 1);

    // TODO: send to an account so that we can check its balance.
    assert_eq!(
        st.get_total_balance(account_id),
        (value - (amount_sent2 + Zatoshis::from_u64(10000).unwrap()).unwrap()).unwrap()
    );
}

pub fn ovk_policy_prevents_recovery_from_chain<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(50000);
    let (h1, _, _) = st.add_a_single_note_checking_balance(value);

    let extsk2 = T::sk(&[0xf5; 32]);
    let addr2 = T::sk_default_address(&extsk2);

    let fee_rule = StandardFeeRule::Zip317;

    #[allow(clippy::type_complexity)]
    let send_and_recover_with_policy = |st: &mut TestState<_, Dsf::DataStore, _>,
                                        ovk_policy|
     -> Result<
        Option<(Note, Address, MemoBytes)>,
        TransferErrT<
            Dsf::DataStore,
            GreedyInputSelector<Dsf::DataStore>,
            SingleOutputChangeStrategy<Dsf::DataStore>,
        >,
    > {
        let proposal = st.propose_standard_transfer(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &addr2,
            Zatoshis::const_from_u64(15000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )?;

        // Executing the proposal should succeed
        let txid = st.create_proposed_transactions(account.usk(), ovk_policy, &proposal)?[0];

        // Fetch the transaction from the database
        let tx = st
            .wallet()
            .get_transaction(txid)
            .map_err(Error::DataSource)?
            .unwrap();

        Ok(T::try_output_recovery(st.network(), h1, &tx, &dfvk))
    };

    // Send some of the funds to another address, keeping history.
    // The recipient output is decryptable by the sender.
    assert_matches!(
        send_and_recover_with_policy(&mut st, OvkPolicy::Sender),
        Ok(Some((_, recovered_to, _))) if recovered_to == addr2
    );

    // Mine blocks SAPLING_ACTIVATION_HEIGHT + 1 to 42 (that don't send us funds)
    // so that the first transaction expires
    for i in 1..=42 {
        st.generate_next_block(
            &T::sk_to_fvk(&T::sk(&[i as u8; 32])),
            AddressType::DefaultExternal,
            value,
        );
    }
    st.scan_cached_blocks(h1 + 1, 42);

    // Send the funds again, discarding history.
    // Neither transaction output is decryptable by the sender.
    assert_matches!(
        send_and_recover_with_policy(&mut st, OvkPolicy::Discard),
        Ok(None)
    );
}

pub fn spend_succeeds_to_t_addr_zero_change<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Add funds to the wallet in a single note
    let value = Zatoshis::const_from_u64(70000);
    st.add_a_single_note_checking_balance(value);

    let fee_rule = StandardFeeRule::Zip317;

    // TODO: generate_next_block_from_tx does not currently support transparent outputs.
    let to = TransparentAddress::PublicKeyHash([7; 20]).into();
    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(50000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal),
        Ok(txids) if txids.len() == 1
    );
}

pub fn change_note_spends_succeed<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Add funds to the wallet in a single note owned by the internal spending key
    let value = Zatoshis::const_from_u64(70000);
    st.add_a_single_note_checking_balance(
        TestNoteConfig::from(value).with_address_type(AddressType::Internal),
    );

    // Value is considered pending at 10 confirmations.
    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    assert_eq!(
        st.get_pending_shielded_balance(account_id, ConfirmationsPolicy::default()),
        value
    );
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::default()),
        Zatoshis::ZERO
    );

    let change_note_scope = st
        .wallet()
        .get_notes(T::SHIELDED_PROTOCOL)
        .unwrap()
        .iter()
        .find_map(|note| (note.note().value() == value).then_some(note.spending_key_scope()));
    assert_matches!(change_note_scope, Some(Scope::Internal));

    let fee_rule = StandardFeeRule::Zip317;

    // TODO: generate_next_block_from_tx does not currently support transparent outputs.
    let to = TransparentAddress::PublicKeyHash([7; 20]).into();
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            fee_rule,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(50000),
            None,
            None,
            T::SHIELDED_PROTOCOL,
        )
        .unwrap();

    // Executing the proposal should succeed
    assert_matches!(
        st.create_proposed_transactions::<Infallible, _, Infallible, _>(account.usk(), OvkPolicy::Sender, &proposal),
        Ok(txids) if txids.len() == 1
    );
}

pub fn account_deletion<T: ShieldedPoolTester, DSF>(ds_factory: DSF, cache: impl TestCache)
where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::DataStore: Reset,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .build();

    // Add two accounts to the wallet.
    let seed = Secret::new([0u8; 32].to_vec());
    let birthday = AccountBirthday::from_sapling_activation(st.network(), BlockHash([0; 32]));
    let (account1, usk) = st
        .wallet_mut()
        .create_account("account1", &seed, &birthday, None)
        .unwrap();
    let dfvk = T::sk_to_fvk(T::usk_to_sk(&usk));

    let (account2, usk2) = st
        .wallet_mut()
        .create_account("account2", &seed, &birthday, None)
        .unwrap();
    let dfvk2 = T::sk_to_fvk(T::usk_to_sk(&usk2));

    // Add funds to the account 0 in a single note
    let value = Zatoshis::from_u64(100000).unwrap();
    let (h, b0_result, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);
    let txid0 = *b0_result
        .txids()
        .first()
        .expect("A transaction was created.");

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account1), value);
    assert_eq!(
        st.get_spendable_balance(account1, ConfirmationsPolicy::MIN),
        value
    );
    assert_eq!(st.get_total_balance(account2), Zatoshis::ZERO);

    let bal_2 = Zatoshis::from_u64(50000).unwrap();
    let addr2 = T::fvk_default_address(&dfvk2);
    let req = TransactionRequest::new(vec![
        // payment to an account 2
        Payment::without_memo(addr2.to_zcash_address(st.network()), bal_2),
    ])
    .unwrap();

    let change_strategy = fees::standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let txid1 = st
        .spend(
            &input_selector,
            &change_strategy,
            &usk,
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    let bal_1 = (value - (bal_2 + MINIMUM_FEE).unwrap()).unwrap();
    assert_eq!(st.get_total_balance(account1), bal_1);

    let (h, _) = st.generate_next_block_including(txid1);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account2), bal_2);
    assert_eq!(st.get_total_balance(account1), bal_1);

    // txid0 should exist; we haven't enhanced it so we'll have the mined height, but not the raw
    // transaction data.
    assert_matches!(st.wallet_mut().get_tx_height(txid0), Ok(Some(_)));

    // delete account 1
    assert_matches!(st.wallet_mut().delete_account(account1), Ok(_));

    // txid0 should no longer exist in the wallet at all, because it only involved account1
    assert_matches!(st.wallet_mut().get_tx_height(txid0), Ok(None));

    // txid1 should exist in the wallet, as it involves account 2
    assert_matches!(st.wallet_mut().get_transaction(txid1), Ok(Some(_)));

    let summary = st
        .wallet()
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .unwrap()
        .unwrap();
    assert!(summary.account_balances().get(&account1).is_none());
    assert_eq!(
        summary.account_balances().get(&account2).unwrap().total(),
        bal_2
    );
    assert_eq!(
        summary
            .account_balances()
            .get(&account2)
            .unwrap()
            .spendable_value(),
        bal_2
    );

    // Create a third account
    let (account3, usk3) = st
        .wallet_mut()
        .create_account("account3", &seed, &birthday, None)
        .unwrap();
    let dfvk3 = T::sk_to_fvk(T::usk_to_sk(&usk3));

    // Creating a new account with the original birthday forces a rescan.
    st.scan_cached_blocks(birthday.height(), 2);

    let bal_3 = Zatoshis::from_u64(20000).unwrap();
    let addr3 = T::fvk_default_address(&dfvk3);
    let req = TransactionRequest::new(vec![
        // payment to an account 3
        Payment::without_memo(addr3.to_zcash_address(st.network()), bal_3),
    ])
    .unwrap();

    let txid2 = st
        .spend(
            &input_selector,
            &change_strategy,
            &usk2,
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    let bal_2_final = (bal_2 - (bal_3 + MINIMUM_FEE).unwrap()).unwrap();
    assert_eq!(st.get_total_balance(account2), bal_2_final);

    let (h, _) = st.generate_next_block_including(txid2);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account2), bal_2_final);
    assert_eq!(st.get_total_balance(account3), bal_3);

    // txid2 should exist; we haven't enhanced it so we'll have the mined height, but not the raw
    // transaction data.
    assert_matches!(st.wallet_mut().get_tx_height(txid2), Ok(Some(_)));

    // delete account 3
    assert_matches!(st.wallet_mut().delete_account(account3), Ok(_));

    // txid2 should still exist in the wallet, as it involves account 2
    assert_matches!(st.wallet_mut().get_transaction(txid2), Ok(Some(_)));

    let summary = st
        .wallet()
        .get_wallet_summary(ConfirmationsPolicy::default())
        .unwrap()
        .unwrap();
    assert!(summary.account_balances().get(&account3).is_none());
    assert_eq!(
        summary.account_balances().get(&account2).unwrap().total(),
        bal_2_final
    );
}

/// Regression test for a bug in which [`WalletWrite::delete_account`] failed with a
/// `rusqlite::Error::InvalidParameterName(":address")` panic when the account being
/// deleted was referenced by a `sent_notes` row via its `to_account_id` column.
///
/// The triggering state is reached when a transaction is sent from one account in the
/// wallet to an address belonging to a second account in the same wallet, and the
/// transaction is then decrypted via [`decrypt_and_store_transaction`] so that the
/// cross-account transfer is recorded with a non-null `to_account_id` and a received
/// output that has an associated address. Deleting the recipient account then exercises
/// the `sent_notes` update path inside `delete_account`.
///
/// [`WalletWrite::delete_account`]: crate::data_api::WalletWrite::delete_account
pub fn account_deletion_with_internal_transfer<T: ShieldedPoolTester, DSF>(
    ds_factory: DSF,
    cache: impl TestCache,
) where
    DSF: DataStoreFactory,
    <DSF as DataStoreFactory>::DataStore: Reset,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .build();

    // Add two accounts to the wallet, derived from the same seed.
    let seed = Secret::new([0u8; 32].to_vec());
    let birthday = AccountBirthday::from_sapling_activation(st.network(), BlockHash([0; 32]));
    let (account1, usk1) = st
        .wallet_mut()
        .create_account("account1", &seed, &birthday, None)
        .unwrap();
    let dfvk1 = T::sk_to_fvk(T::usk_to_sk(&usk1));

    let (account2, usk2) = st
        .wallet_mut()
        .create_account("account2", &seed, &birthday, None)
        .unwrap();
    let dfvk2 = T::sk_to_fvk(T::usk_to_sk(&usk2));

    // Add funds to account 1 in a single note.
    let value = Zatoshis::from_u64(100000).unwrap();
    let (h, _, _) = st.generate_next_block(&dfvk1, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account1), value);
    assert_eq!(st.get_total_balance(account2), Zatoshis::ZERO);

    // Send funds from account 1 to an address belonging to account 2.
    let bal_2 = Zatoshis::from_u64(50000).unwrap();
    let addr2 = T::fvk_default_address(&dfvk2);
    let req = TransactionRequest::new(vec![Payment::without_memo(
        addr2.to_zcash_address(st.network()),
        bal_2,
    )])
    .unwrap();

    let change_strategy = fees::standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let txid = st
        .spend(
            &input_selector,
            &change_strategy,
            &usk1,
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account2), bal_2);

    // Decrypt and store the transaction. Because the wallet owns the funding inputs
    // (account 1) and the output is received by account 2, this records the send as an
    // internal cross-account transfer, setting `sent_notes.to_account_id` to account 2
    // and associating the received output with account 2's address. This is the state
    // that triggers the `delete_account` bug.
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), &tx, Some(h)).unwrap();

    // Deleting account 2, the recipient of the internal transfer, must succeed. Prior to
    // the fix this failed with `rusqlite::Error::InvalidParameterName(":address")` because
    // the `sent_notes` update statement bound the wrong parameter name.
    assert_matches!(st.wallet_mut().delete_account(account2), Ok(_));

    // account 1 should still exist and retain its change balance.
    let summary = st
        .wallet()
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .unwrap()
        .unwrap();
    assert!(summary.account_balances().get(&account2).is_none());
    assert!(summary.account_balances().contains_key(&account1));
}

pub fn external_address_change_spends_detected_in_restore_from_seed<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::DataStore: Reset,
{
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .build();

    // Add two accounts to the wallet.
    let seed = Secret::new([0u8; 32].to_vec());
    let birthday = AccountBirthday::from_sapling_activation(st.network(), BlockHash([0; 32]));
    let (account1, usk) = st
        .wallet_mut()
        .create_account("account1", &seed, &birthday, None)
        .unwrap();
    let dfvk = T::sk_to_fvk(T::usk_to_sk(&usk));

    let (account2, usk2) = st
        .wallet_mut()
        .create_account("account2", &seed, &birthday, None)
        .unwrap();
    let dfvk2 = T::sk_to_fvk(T::usk_to_sk(&usk2));

    // Add funds to the wallet in a single note
    let value = Zatoshis::from_u64(100000).unwrap();
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h, 1);

    // Spendable balance matches total balance
    assert_eq!(st.get_total_balance(account1), value);
    assert_eq!(
        st.get_spendable_balance(account1, ConfirmationsPolicy::MIN),
        value
    );
    assert_eq!(st.get_total_balance(account2), Zatoshis::ZERO);

    let amount_sent = Zatoshis::from_u64(20000).unwrap();
    let amount_legacy_change = Zatoshis::from_u64(30000).unwrap();
    let addr = T::fvk_default_address(&dfvk);
    let addr2 = T::fvk_default_address(&dfvk2);
    let req = TransactionRequest::new(vec![
        // payment to an external recipient
        Payment::without_memo(addr2.to_zcash_address(st.network()), amount_sent),
        // payment back to the originating wallet, simulating legacy change
        Payment::without_memo(addr.to_zcash_address(st.network()), amount_legacy_change),
    ])
    .unwrap();

    let change_strategy = fees::standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let txid = st
        .spend(
            &input_selector,
            &change_strategy,
            &usk,
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    let amount_left = (value - (amount_sent + MINIMUM_FEE + MARGINAL_FEE).unwrap()).unwrap();
    let pending_change = (amount_left - amount_legacy_change).unwrap();

    // The "legacy change" is not counted by get_pending_change().
    assert_eq!(
        st.get_pending_change(account1, ConfirmationsPolicy::MIN),
        pending_change
    );
    // We spent the only note so we only have pending change.
    assert_eq!(st.get_total_balance(account1), pending_change);

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    assert_eq!(st.get_total_balance(account2), amount_sent,);
    assert_eq!(st.get_total_balance(account1), amount_left);

    st.reset();

    // Account creation and DFVK derivation should be deterministic.
    let (account1, restored_usk) = st
        .wallet_mut()
        .create_account("account1_restored", &seed, &birthday, None)
        .unwrap();
    assert!(T::fvks_equal(
        &T::sk_to_fvk(T::usk_to_sk(&restored_usk)),
        &dfvk,
    ));

    let (account2, restored_usk2) = st
        .wallet_mut()
        .create_account("account2_restored", &seed, &birthday, None)
        .unwrap();
    assert!(T::fvks_equal(
        &T::sk_to_fvk(T::usk_to_sk(&restored_usk2)),
        &dfvk2,
    ));

    st.scan_cached_blocks(st.sapling_activation_height(), 2);

    assert_eq!(st.get_total_balance(account2), amount_sent);
    assert_eq!(st.get_total_balance(account1), amount_left);
}

#[allow(dead_code)]
pub fn zip317_spend<T: ShieldedPoolTester, Dsf: DataStoreFactory>(
    ds_factory: Dsf,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let dfvk = T::test_account_fvk(&st);

    // Add funds to the wallet
    st.add_notes_checking_balance([Some(Zatoshis::const_from_u64(50000))]);

    // Add 10 uneconomic (dust) notes to the wallet
    for _ in 1..=10 {
        st.add_notes_checking_balance([Some(Zatoshis::const_from_u64(1000))]);
    }

    // Spendable balance matches total balance
    let total = Zatoshis::const_from_u64(60000);
    assert_eq!(st.get_total_balance(account_id), total);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        total
    );

    let input_selector = GreedyInputSelector::<Dsf::DataStore>::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    // This first request will fail due to insufficient non-dust funds
    let req = TransactionRequest::new(vec![Payment::without_memo(
        T::fvk_default_address(&dfvk).to_zcash_address(st.network()),
        Zatoshis::const_from_u64(50000),
    )])
    .unwrap();

    assert_matches!(
        st.spend(
            &input_selector,
            &change_strategy,
            account.usk(),
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        ),
        Err(Error::InsufficientFunds { available, required })
            if available == Zatoshis::const_from_u64(51000)
            && required == Zatoshis::const_from_u64(60000)
    );

    // This request will succeed, spending a single dust input to pay the 10000
    // ZAT fee in addition to the 41000 ZAT output to the recipient
    let req = TransactionRequest::new(vec![Payment::without_memo(
        T::fvk_default_address(&dfvk).to_zcash_address(st.network()),
        Zatoshis::const_from_u64(41000),
    )])
    .unwrap();

    let txid = st
        .spend(
            &input_selector,
            &change_strategy,
            account.usk(),
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap()[0];

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    // TODO: send to an account so that we can check its balance.
    // We sent back to the same account so the amount_sent should be included
    // in the total balance.
    assert_eq!(
        st.get_total_balance(account_id),
        (total - Zatoshis::const_from_u64(10000)).unwrap()
    );
}

#[cfg(feature = "transparent-inputs")]
pub fn shield_transparent<T: ShieldedPoolTester, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use zcash_keys::keys::UnifiedAddressRequest;
    use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    let uaddr = st
        .wallet()
        .get_last_generated_address_matching(account.id(), UnifiedAddressRequest::AllAvailableKeys)
        .unwrap()
        .unwrap();
    let taddr = uaddr.transparent().unwrap();

    // Ensure that the wallet has at least one block
    let (h, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::Internal,
        Zatoshis::const_from_u64(50000),
    );
    st.scan_cached_blocks(h, 1);

    let spent_outpoint = OutPoint::fake();
    let utxo = WalletTransparentOutput::from_parts(
        spent_outpoint.clone(),
        TxOut::new(Zatoshis::const_from_u64(100000), taddr.script().into()),
        Some(h),
        Some(account.id()),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();

    let res0 = st.wallet_mut().put_received_transparent_utxo(&utxo);
    assert_matches!(res0, Ok(_));

    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    let txids = st
        .shield_transparent_funds(
            &input_selector,
            &change_strategy,
            Zatoshis::from_u64(10000).unwrap(),
            account.usk(),
            &[*taddr],
            account.id(),
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    assert_eq!(txids.len(), 1);

    let tx_summary = st.get_tx_from_history(*txids.first()).unwrap().unwrap();
    assert_eq!(tx_summary.spent_note_count(), 1);
    assert!(tx_summary.has_change());
    assert_eq!(tx_summary.received_note_count(), 0);
    assert_eq!(tx_summary.sent_note_count(), 0);
    assert!(tx_summary.is_shielding());

    // Generate and scan the block including the transaction
    let (h, _) = st.generate_next_block_including(*txids.first());
    let scan_result = st.scan_cached_blocks(h, 1);

    // Ensure that the transaction metadata is still correct after the update produced by scanning.
    let tx_summary = st.get_tx_from_history(*txids.first()).unwrap().unwrap();
    assert_eq!(tx_summary.spent_note_count(), 1);
    assert!(tx_summary.has_change());
    assert_eq!(tx_summary.received_note_count(), 0);
    assert_eq!(tx_summary.sent_note_count(), 0);
    assert!(tx_summary.is_shielding());

    // Verify that a transaction enhancement request for the transaction containing the spent
    // outpoint does not yet exist.
    let requests = st.wallet().transaction_data_requests().unwrap();
    assert!(
        !requests
            .iter()
            .any(|req| req == &TransactionDataRequest::Enhancement(*spent_outpoint.txid()))
    );

    // Use `decrypt_and_store_transaction` for the side effect of creating enhancement requests for
    // the transparent inputs of the transaction.
    let tx = st
        .wallet()
        .get_transaction(*txids.first())
        .unwrap()
        .unwrap();
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), &tx, Some(h)).unwrap();

    // Verify that a transaction enhancement request for the received transaction was created
    let requests = st.wallet().transaction_data_requests().unwrap();
    assert!(
        requests
            .iter()
            .any(|req| req == &TransactionDataRequest::Enhancement(*spent_outpoint.txid()))
    );

    // Now advance the chain by 40 blocks; even though a record for the transaction that created
    // `spent_outpoint` exists in the wallet database, the transaction can't be enhanced because
    // the outpoint was fake. Advancing the chain will cause the request for enhancement to expire.
    for _ in 0..DEFAULT_TX_EXPIRY_DELTA {
        st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    st.scan_cached_blocks(
        scan_result.scanned_range().end,
        usize::try_from(DEFAULT_TX_EXPIRY_DELTA).unwrap(),
    );

    // Simulate the situation where the enhancement request results in `TxidNotRecognized`
    st.wallet_mut()
        .set_transaction_status(
            *spent_outpoint.txid(),
            data_api::TransactionStatus::TxidNotRecognized,
        )
        .unwrap();

    // Verify that the transaction enhancement request for the invalid txid has been deleted.
    let requests = st.wallet().transaction_data_requests().unwrap();
    assert!(
        !requests
            .iter()
            .any(|req| req == &TransactionDataRequest::Enhancement(*spent_outpoint.txid()))
    );
}

// FIXME: This requires fixes to the test framework.
#[allow(dead_code)]
pub fn birthday_in_anchor_shard<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // Set up the following situation:
    //
    //        |<------ 500 ------->|<--- 10 --->|<--- 10 --->|
    // last_shard_start   wallet_birthday  received_tx  anchor_height
    //
    // We set the Sapling and Orchard frontiers at the birthday block initial state to 1234
    // notes beyond the end of the first shard.
    let frontier_tree_size: u32 = (0x1 << 16) + 1234;
    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_initial_chain_state(|rng, network| {
            let birthday_height = network.activation_height(NetworkUpgrade::Nu5).unwrap() + 1000;

            // Construct a fake chain state for the end of the block with the given
            // birthday_offset from the Nu5 birthday.
            let (prior_sapling_roots, sapling_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    frontier_tree_size.into(),
                    NonZeroU8::new(16).unwrap(),
                );
            // There will only be one prior root
            let prior_sapling_roots = prior_sapling_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let (prior_orchard_roots, orchard_initial_tree) =
                Frontier::random_with_prior_subtree_roots(
                    rng,
                    frontier_tree_size.into(),
                    NonZeroU8::new(16).unwrap(),
                );
            // There will only be one prior root
            #[cfg(feature = "orchard")]
            let prior_orchard_roots = prior_orchard_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 500, root))
                .collect::<Vec<_>>();

            // Ironwood is not active at these test heights, so its tree is empty.
            #[cfg(feature = "orchard")]
            let ironwood_initial_tree = Frontier::empty();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    sapling_initial_tree,
                    #[cfg(feature = "orchard")]
                    orchard_initial_tree,
                    #[cfg(feature = "orchard")]
                    ironwood_initial_tree,
                ),
                prior_sapling_roots,
                #[cfg(feature = "orchard")]
                prior_orchard_roots,
            }
        })
        .with_account_having_current_birthday()
        .build();

    // Generate 9 blocks that have no value for us, starting at the birthday height.
    let not_our_value = Zatoshis::const_from_u64(10000);
    let not_our_key = T::random_fvk(st.rng_mut());
    let (initial_height, _, _) =
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    for _ in 1..9 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }

    // Now, generate a block that belongs to our wallet
    let (received_tx_height, _, _) = st.generate_next_block(
        &T::test_account_fvk(&st),
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(500000),
    );

    // Generate some more blocks to get above our anchor height
    for _ in 0..15 {
        st.generate_next_block(&not_our_key, AddressType::DefaultExternal, not_our_value);
    }

    // Scan a block range that includes our received note, but skips some blocks we need to
    // make it spendable.
    st.scan_cached_blocks(initial_height + 5, 20);

    // Verify that the received note is not considered spendable
    let account = st.test_account().unwrap();
    let account_id = account.id();
    let spendable = T::select_spendable_notes(
        &st,
        account_id,
        TargetValue::AtLeast(Zatoshis::const_from_u64(300000)),
        TargetHeight::from(received_tx_height + 10),
        ConfirmationsPolicy::default(),
        &[],
    )
    .unwrap();

    assert_eq!(spendable.len(), 0);

    // Scan the blocks we skipped
    st.scan_cached_blocks(initial_height, 5);

    // Verify that the received note is now considered spendable
    let spendable = T::select_spendable_notes(
        &st,
        account_id,
        TargetValue::AtLeast(Zatoshis::const_from_u64(300000)),
        TargetHeight::from(received_tx_height + 10),
        ConfirmationsPolicy::default(),
        &[],
    )
    .unwrap();

    assert_eq!(spendable.len(), 1);
}

pub fn checkpoint_gaps<T: ShieldedPoolTester, Dsf: DataStoreFactory>(
    ds_factory: Dsf,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Generate a block with funds belonging to our wallet.
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(500000));

    // Create a gap of 10 blocks having no shielded outputs, then add a block that doesn't
    // belong to us so that we can get a checkpoint in the tree.
    let account = st.test_account().cloned().unwrap();
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let not_our_value = Zatoshis::const_from_u64(10000);
    let sapling_end_size = st.latest_cached_block().unwrap().sapling_end_size();
    let orchard_end_size = st.latest_cached_block().unwrap().orchard_end_size();
    let ironwood_end_size = st.latest_cached_block().unwrap().ironwood_end_size();
    st.generate_block_at(
        account.birthday().height() + 10,
        BlockHash([0; 32]),
        &[FakeCompactOutput::new(
            &not_our_key,
            AddressType::DefaultExternal,
            not_our_value,
        )],
        sapling_end_size,
        orchard_end_size,
        ironwood_end_size,
        false,
    );

    // Scan the block
    st.scan_cached_blocks(account.birthday().height() + 10, 1);

    // Verify that our note is considered spendable
    let spendable = T::select_spendable_notes(
        &st,
        account.id(),
        TargetValue::AtLeast(Zatoshis::const_from_u64(300000)),
        TargetHeight::from(account.birthday().height() + 5),
        ConfirmationsPolicy::new_unchecked(
            1,
            5,
            #[cfg(feature = "transparent-inputs")]
            false,
        ),
        &[],
    )
    .unwrap();
    assert_eq!(spendable.len(), 1);

    let input_selector = GreedyInputSelector::<Dsf::DataStore>::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    let to = T::fvk_default_address(&not_our_key);
    let req = TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10000),
    )])
    .unwrap();

    // Attempt to spend the note with 5 confirmations
    assert_matches!(
        st.spend(
            &input_selector,
            &change_strategy,
            account.usk(),
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::new_symmetrical_unchecked(
                5,
                #[cfg(feature = "transparent-inputs")]
                false
            ),
        ),
        Ok(_)
    );
}

#[cfg(feature = "orchard")]
pub fn pool_crossing_required<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // TODO: Allow for Orchard activation after Sapling
    // Here we choose P0, but this has no effect since we supply the viewing keys
    // and generate the blocks directly on the state.
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);

    let p1_fvk = P1::test_account_fvk(&st);
    let p1_to = P1::fvk_default_address(&p1_fvk);

    let note_value = Zatoshis::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let initial_balance = note_value;
    assert_eq!(st.get_total_balance(account.id()), initial_balance);
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        initial_balance
    );

    let transfer_amount = Zatoshis::const_from_u64(200000);
    let p0_to_p1 = TransactionRequest::new(vec![Payment::without_memo(
        p1_to.to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, P1::SHIELDED_PROTOCOL);
    let proposal0 = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            p0_to_p1,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let _min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);
    let step0 = &proposal0.steps().head;

    // We expect 4 logical actions, two per pool (due to padding).
    let expected_fee = Zatoshis::const_from_u64(20000);
    assert_eq!(step0.balance().fee_required(), expected_fee);

    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    let proposed_change = step0.balance().proposed_change();
    assert_eq!(proposed_change.len(), 1);
    let change_output = proposed_change.first().unwrap();
    // Since this is a cross-pool transfer, change will be sent to the preferred pool.
    assert_eq!(
        change_output.output_pool(),
        PoolType::Shielded(std::cmp::max(ShieldedPool::Sapling, ShieldedPool::Orchard))
    );
    assert_eq!(change_output.value(), expected_change);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);

    assert_eq!(
        st.get_total_balance(account.id()),
        (initial_balance - expected_fee).unwrap()
    );
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (initial_balance - expected_fee).unwrap()
    );
}

#[cfg(feature = "orchard")]
pub fn fully_funded_fully_private<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // TODO: Allow for Orchard activation after Sapling
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);

    let p1_fvk = P1::test_account_fvk(&st);
    let p1_to = P1::fvk_default_address(&p1_fvk);

    let note_value = Zatoshis::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let initial_balance = (note_value * 2u64).unwrap();
    assert_eq!(st.get_total_balance(account.id()), initial_balance);
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        initial_balance
    );

    let transfer_amount = Zatoshis::const_from_u64(200000);
    let p0_to_p1 = TransactionRequest::new(vec![Payment::without_memo(
        p1_to.to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    // We set the default change output pool to P0, because we want to verify later that
    // change is actually sent to P1 (as the transaction is fully fundable from P1).
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, P0::SHIELDED_PROTOCOL);
    let proposal0 = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            p0_to_p1,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let _min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);
    let step0 = &proposal0.steps().head;

    // We expect 2 logical actions, since either pool can pay the full balance required
    // and note selection should choose the fully-private path.
    let expected_fee = Zatoshis::const_from_u64(10000);
    assert_eq!(step0.balance().fee_required(), expected_fee);

    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    let proposed_change = step0.balance().proposed_change();
    assert_eq!(proposed_change.len(), 1);
    let change_output = proposed_change.first().unwrap();
    // Since there are sufficient funds in either pool, change is kept in the same pool as
    // the source note (the target pool), and does not necessarily follow preference order.
    assert_eq!(
        change_output.output_pool(),
        PoolType::Shielded(P1::SHIELDED_PROTOCOL)
    );
    assert_eq!(change_output.value(), expected_change);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);

    assert_eq!(
        st.get_total_balance(account.id()),
        (initial_balance - expected_fee).unwrap()
    );
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (initial_balance - expected_fee).unwrap()
    );
}

#[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
pub fn fully_funded_send_to_t<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // TODO: Allow for Orchard activation after Sapling
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);
    let p1_fvk = P1::test_account_fvk(&st);
    let (p1_to, _) = account.usk().default_transparent_address();

    let note_value = Zatoshis::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 2);

    let initial_balance = (note_value * 2u64).unwrap();
    assert_eq!(st.get_total_balance(account.id()), initial_balance);
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        initial_balance
    );

    let transfer_amount = Zatoshis::const_from_u64(200000);
    let p0_to_p1 = TransactionRequest::new(vec![Payment::without_memo(
        Address::Transparent(p1_to).to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    // We set the default change output pool to P0, because we want to verify later that
    // change is actually sent to P1 (as the transaction is fully fundable from P1).
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, P0::SHIELDED_PROTOCOL);
    let proposal0 = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            p0_to_p1,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let _min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);
    let step0 = &proposal0.steps().head;

    // We expect 3 logical actions, one for the transparent output and two for the source pool.
    let expected_fee = Zatoshis::const_from_u64(15000);
    assert_eq!(step0.balance().fee_required(), expected_fee);

    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    let proposed_change = step0.balance().proposed_change();
    assert_eq!(proposed_change.len(), 1);
    let change_output = proposed_change.first().unwrap();
    // Since there are sufficient funds in either pool, change is kept in the same pool as
    // the source note (the target pool), and does not necessarily follow preference order.
    // The source note will always be sapling, as we spend Sapling funds preferentially.
    assert_eq!(change_output.output_pool(), PoolType::SAPLING);
    assert_eq!(change_output.value(), expected_change);

    let create_proposed_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal0,
    );
    assert_matches!(&create_proposed_result, Ok(txids) if txids.len() == 1);

    let (h, _) = st.generate_next_block_including(create_proposed_result.unwrap()[0]);
    st.scan_cached_blocks(h, 1);

    // Since the recipient address is in the same account, the total balance includes the transfer
    // amount.
    assert_eq!(
        st.get_total_balance(account.id()),
        (initial_balance - expected_fee).unwrap()
    );
    // The spendable balance doesn't include the transparent value, so it excludes the transfer
    // amount.
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (initial_balance - transfer_amount - expected_fee).unwrap()
    );
}

#[cfg(feature = "orchard")]
pub fn multi_pool_checkpoint<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // TODO: Allow for Orchard activation after Sapling
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();

    let account = st.test_account().cloned().unwrap();
    let acct_id = account.id();

    let p0_fvk = P0::test_account_fvk(&st);
    let p1_fvk = P1::test_account_fvk(&st);

    // Add some funds to the wallet; we add two notes to allow successive spends. Also,
    // we will generate a note in the P1 pool to ensure that we have some tree state.
    let note_value = Zatoshis::const_from_u64(500000);
    let (start_height, _, _) =
        st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    let scanned = st.scan_cached_blocks(start_height, 3);

    let next_to_scan = scanned.scanned_range().end;

    let initial_balance = (note_value * 3u64).unwrap();
    assert_eq!(st.get_total_balance(acct_id), initial_balance);
    assert_eq!(
        st.get_spendable_balance(acct_id, ConfirmationsPolicy::MIN),
        initial_balance
    );

    // Generate several empty blocks
    for _ in 0..10 {
        st.generate_empty_block();
    }

    // Scan into the middle of the empty range
    let scanned = st.scan_cached_blocks(next_to_scan, 5);
    let next_to_scan = scanned.scanned_range().end;

    // The initial balance should be unchanged.
    assert_eq!(st.get_total_balance(acct_id), initial_balance);
    assert_eq!(
        st.get_spendable_balance(acct_id, ConfirmationsPolicy::MIN),
        initial_balance
    );

    // Set up the fee rule and input selector we'll use for all the transfers.
    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, P1::SHIELDED_PROTOCOL);

    // First, send funds just to P0
    let transfer_amount = Zatoshis::const_from_u64(200000);
    let p0_transfer = TransactionRequest::new(vec![Payment::without_memo(
        P0::random_address(st.rng_mut()).to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();
    let res = st
        .spend(
            &input_selector,
            &change_strategy,
            account.usk(),
            p0_transfer,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    st.generate_next_block_including(*res.first());

    let expected_fee = Zatoshis::const_from_u64(10000);
    let expected_change = (note_value - transfer_amount - expected_fee).unwrap();
    assert_eq!(
        st.get_total_balance(acct_id),
        ((note_value * 2u64).unwrap() + expected_change).unwrap()
    );
    assert_eq!(
        st.get_pending_change(acct_id, ConfirmationsPolicy::MIN),
        expected_change
    );

    // In the next block, send funds to both P0 and P1
    let both_transfer = TransactionRequest::new(vec![
        Payment::without_memo(
            P0::random_address(st.rng_mut()).to_zcash_address(st.network()),
            transfer_amount,
        ),
        Payment::without_memo(
            P1::random_address(st.rng_mut()).to_zcash_address(st.network()),
            transfer_amount,
        ),
    ])
    .unwrap();
    let res = st
        .spend(
            &input_selector,
            &change_strategy,
            account.usk(),
            both_transfer,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();
    st.generate_next_block_including(*res.first());

    // Generate a few more empty blocks
    for _ in 0..5 {
        st.generate_empty_block();
    }

    // Generate another block with funds for us
    let (max_height, _, _) =
        st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);

    // Scan everything.
    st.scan_cached_blocks(
        next_to_scan,
        usize::try_from(u32::from(max_height) - u32::from(next_to_scan) + 1).unwrap(),
    );

    let expected_final = (initial_balance + note_value
        - (transfer_amount * 3u64).unwrap()
        - (expected_fee * 3u64).unwrap())
    .unwrap();
    assert_eq!(st.get_total_balance(acct_id), expected_final);

    let expected_checkpoints_p0: Vec<(BlockHeight, Option<Position>)> = [
        (99999, None),
        (100000, Some(0)),
        (100001, Some(1)),
        (100002, Some(1)),
        (100007, Some(1)), // synthetic checkpoint in empty span from scan start
        (100013, Some(3)),
        (100014, Some(5)),
        (100020, Some(6)),
    ]
    .into_iter()
    .map(|(h, pos)| (BlockHeight::from(h), pos.map(Position::from)))
    .collect();

    let expected_checkpoints_p1: Vec<(BlockHeight, Option<Position>)> = [
        (99999, None),
        (100000, None),
        (100001, None),
        (100002, Some(0)),
        (100007, Some(0)), // synthetic checkpoint in empty span from scan start
        (100013, Some(0)),
        (100014, Some(2)),
        (100020, Some(2)),
    ]
    .into_iter()
    .map(|(h, pos)| (BlockHeight::from(h), pos.map(Position::from)))
    .collect();

    let p0_checkpoints = st
        .wallet()
        .get_checkpoint_history(&P0::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(p0_checkpoints.to_vec(), expected_checkpoints_p0);

    let p1_checkpoints = st
        .wallet()
        .get_checkpoint_history(&P1::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(p1_checkpoints.to_vec(), expected_checkpoints_p1);
}

#[cfg(feature = "orchard")]
pub fn multi_pool_checkpoints_with_pruning<P0: ShieldedPoolTester, P1: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    // TODO: Allow for Orchard activation after Sapling
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<P0>();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::random_fvk(st.rng_mut());
    let p1_fvk = P1::random_fvk(st.rng_mut());

    let note_value = Zatoshis::const_from_u64(10000);
    // Generate 100 P0 blocks, then 100 P1 blocks, then another 100 P0 blocks.
    for _ in 0..10 {
        for _ in 0..10 {
            st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
        }
        for _ in 0..10 {
            st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
        }
    }
    st.scan_cached_blocks(account.birthday().height(), 200);
    for _ in 0..100 {
        st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
        st.generate_next_block(&p1_fvk, AddressType::DefaultExternal, note_value);
    }
    st.scan_cached_blocks(account.birthday().height() + 200, 200);
}

pub fn valid_chain_states<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let dfvk = T::test_account_fvk(&st);

    // Empty chain should return None
    assert_matches!(st.wallet().chain_height(), Ok(None));

    // Create a fake CompactBlock sending value to the address
    let (h1, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(5),
    );

    // Scan the cache
    st.scan_cached_blocks(h1, 1);

    // Create a second fake CompactBlock sending more value to the address
    let (h2, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(7),
    );

    // Scanning should detect no inconsistencies
    st.scan_cached_blocks(h2, 1);
}

// FIXME: This requires fixes to the test framework.
#[allow(dead_code)]
pub fn invalid_chain_cache_disconnected<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let dfvk = T::test_account_fvk(&st);

    // Create some fake CompactBlocks
    let (h, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(5),
    );
    let (last_contiguous_height, _, _) = st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(7),
    );

    // Scanning the cache should find no inconsistencies
    st.scan_cached_blocks(h, 2);

    // Create more fake CompactBlocks that don't connect to the scanned ones
    let disconnect_height = last_contiguous_height + 1;
    st.generate_block_at(
        disconnect_height,
        BlockHash([1; 32]),
        &[FakeCompactOutput::new(
            &dfvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(8),
        )],
        2,
        2,
        0,
        true,
    );
    st.generate_next_block(
        &dfvk,
        AddressType::DefaultExternal,
        Zatoshis::const_from_u64(3),
    );

    // Data+cache chain should be invalid at the data/cache boundary
    assert_matches!(
        st.try_scan_cached_blocks(
            disconnect_height,
            2
        ),
        Err(chain::error::Error::Scan(ScanError::PrevHashMismatch { at_height }))
            if at_height == disconnect_height
    );
}

pub fn data_db_truncation<T: ShieldedPoolTester, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(ConfirmationsPolicy::MIN), None);

    // Create fake CompactBlocks sending value to the address
    let value = Zatoshis::const_from_u64(50000);
    let value2 = Zatoshis::const_from_u64(70000);
    let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.generate_next_block(&dfvk, AddressType::DefaultExternal, value2);

    // Scan the cache
    st.scan_cached_blocks(h, 2);

    // Spendable balance should reflect both received notes
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (value + value2).unwrap()
    );

    // "Rewind" to height of last scanned block (this is a no-op)
    st.wallet_mut().truncate_to_height(h + 1).unwrap();

    // Spendable balance should be unaltered
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (value + value2).unwrap()
    );

    // Rewind so that one block is dropped
    st.wallet_mut().truncate_to_height(h).unwrap();

    // Spendable balance should only contain the first received note;
    // the rest should be pending.
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        value
    );
    assert_eq!(
        st.get_pending_shielded_balance(account.id(), ConfirmationsPolicy::MIN),
        value2
    );

    // Scan the cache again
    st.scan_cached_blocks(h, 2);

    // Account balance should again reflect both received notes
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        (value + value2).unwrap()
    );
}

pub fn truncate_to_chain_state<T: ShieldedPoolTester, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Test plan:
    // 1. Set up test environment with account
    // 2. Generate and scan initial blocks to populate the note commitment tree
    // 3. Capture the chain state at a specific height
    // 4. Generate and scan blocks beyond PRUNING_DEPTH to ensure early checkpoints are pruned
    // 5. Verify that normal truncate_to_height fails due to missing checkpoints
    // 6. Test that truncate_to_chain_state succeeds using the captured chain state
    // 7. Verify wallet state after truncation

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let sapling_activation = st
        .network()
        .activation_height(consensus::NetworkUpgrade::Sapling)
        .unwrap();

    // Step 2: Generate and scan initial blocks to populate the note commitment tree.
    // We use an "other" fvk so that notes won't be tracked by the wallet (keeping the
    // test focused on tree state rather than wallet balances).
    let seed = [1u8; 32];
    let other_sk = T::sk(&seed);
    let other_fvk = T::sk_to_fvk(&other_sk);

    let initial_block_count = 8u32;
    for _ in 0..initial_block_count {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    let scan_start = sapling_activation;
    st.scan_cached_blocks(scan_start, initial_block_count as usize);

    // Step 3: Capture the chain state at the current tip. The CachedBlock tracks the
    // exact frontier that corresponds to the end of each generated block.
    let capture_height = sapling_activation + initial_block_count - 1;
    let captured_chain_state = st
        .latest_cached_block()
        .expect("should have cached blocks")
        .chain_state()
        .clone();
    assert_eq!(captured_chain_state.block_height(), capture_height);

    // Step 4: Generate and scan blocks well beyond PRUNING_DEPTH so that the checkpoint
    // at capture_height is pruned from the note commitment tree.
    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5000),
        );
    }
    st.scan_cached_blocks(capture_height + 1, extra_blocks as usize);

    let tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should be set");
    assert!(
        tip >= capture_height + PRUNING_DEPTH,
        "tip should be beyond pruning depth from capture height"
    );

    // Step 5: Verify that truncate_to_height fails at capture_height because the
    // checkpoint has been pruned.
    let truncation_result = st.wallet_mut().truncate_to_height(capture_height);
    assert!(
        truncation_result.is_err(),
        "truncate_to_height should fail when checkpoint has been pruned"
    );

    // Step 6: truncate_to_chain_state should succeed because it inserts the frontier
    // as a checkpoint before truncating.
    st.wallet_mut()
        .truncate_to_chain_state(captured_chain_state.clone())
        .expect("truncate_to_chain_state should succeed");

    // Step 7: Verify wallet state after truncation.
    // The chain tip should now be at the capture height.
    let new_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after truncation");
    assert_eq!(new_tip, capture_height);

    // The block hash at capture_height should match what was in the captured chain state.
    let hash_at_capture = st
        .wallet()
        .get_block_hash(capture_height)
        .unwrap()
        .expect("block hash should exist at capture height");
    assert_eq!(hash_at_capture, captured_chain_state.block_hash());

    // Blocks above the capture height should have been removed.
    assert_eq!(
        st.wallet().get_block_hash(capture_height + 1).unwrap(),
        None,
        "blocks above capture height should be removed"
    );
}

pub fn truncate_to_chain_state_below_birthday<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Regression test: truncate_to_chain_state should succeed when truncating to a height
    // below the wallet birthday (where no entry exists in the blocks table). Previously,
    // this would fail with RequestedRewindInvalid because select_truncation_height requires
    // the target height to have an entry in the blocks table.

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_initial_chain_state(|rng, network| {
            let birthday_height = network.activation_height(NetworkUpgrade::Sapling).unwrap() + 200;

            let (prior_sapling_roots, sapling_initial_tree) =
                Frontier::random_with_prior_subtree_roots(rng, 1u64, NonZeroU8::new(16).unwrap());
            let prior_sapling_roots = prior_sapling_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 100, root))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let (prior_orchard_roots, orchard_initial_tree) =
                Frontier::random_with_prior_subtree_roots(rng, 1u64, NonZeroU8::new(16).unwrap());
            #[cfg(feature = "orchard")]
            let prior_orchard_roots = prior_orchard_roots
                .into_iter()
                .map(|root| CommitmentTreeRoot::from_parts(birthday_height - 100, root))
                .collect::<Vec<_>>();

            // Ironwood is not active at these test heights, so its tree is empty.
            #[cfg(feature = "orchard")]
            let ironwood_initial_tree = Frontier::empty();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    sapling_initial_tree,
                    #[cfg(feature = "orchard")]
                    orchard_initial_tree,
                    #[cfg(feature = "orchard")]
                    ironwood_initial_tree,
                ),
                prior_sapling_roots,
                #[cfg(feature = "orchard")]
                prior_orchard_roots,
            }
        })
        .with_account_having_current_birthday()
        .build();

    // Generate and scan a few initial blocks from the birthday height.
    let other_fvk = T::random_fvk(st.rng_mut());
    let birthday_height = st.test_account().unwrap().birthday().height();

    for _ in 0..5 {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    st.scan_cached_blocks(birthday_height, 5);

    // Generate and scan blocks well beyond PRUNING_DEPTH to ensure early checkpoints
    // are pruned from the note commitment tree.
    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5000),
        );
    }
    st.scan_cached_blocks(birthday_height + 5, extra_blocks as usize);

    // Get the prior chain state from the account birthday. This chain state is at
    // birthday_height - 1, which has valid tree frontiers but NO entry in the blocks
    // table (since the wallet never scanned a block at that height).
    let prior_chain_state = st
        .test_account()
        .unwrap()
        .birthday()
        .prior_chain_state()
        .clone();

    // This should succeed. On the buggy code, this fails with RequestedRewindInvalid
    // because select_truncation_height cannot find an entry in the blocks table at the
    // target height.
    let _target_height = prior_chain_state.block_height();
    st.wallet_mut()
        .truncate_to_chain_state(prior_chain_state)
        .expect("truncate_to_chain_state below birthday should succeed");

    // All blocks were above the target height, so they should have been removed.
    assert_eq!(
        st.wallet().get_block_hash(birthday_height).unwrap(),
        None,
        "blocks at birthday height should be removed after truncating below birthday"
    );
}

pub fn truncate_to_chain_state_above_scanned<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Regression test: when truncate_to_chain_state is called with a target height above
    // the max scanned height, the frontier insertion must be skipped (it would introduce
    // a subtree root discontinuity) but the scan queue must still be trimmed. Without the
    // fix, inserting a frontier in shard 2 when the wallet only has shard 0 fails because
    // shard 1's subtree root is unknown.

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let birthday_height = st.test_account().unwrap().birthday().height();

    // Generate and scan initial blocks, then scan beyond PRUNING_DEPTH to ensure
    // early checkpoints are pruned.
    let other_fvk = T::random_fvk(st.rng_mut());
    let initial_blocks = 5u32;
    for _ in 0..initial_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    st.scan_cached_blocks(birthday_height, initial_blocks as usize);

    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5000),
        );
    }
    st.scan_cached_blocks(birthday_height + initial_blocks, extra_blocks as usize);
    let max_scanned = birthday_height + initial_blocks + extra_blocks - 1;

    // Simulate downloading subtree roots from the network: add a known subtree root
    // for shard 0 only. This creates a state where shard 0 exists in the shard store
    // but shard 1 does not.
    T::put_subtree_roots(
        &mut st,
        0,
        &[CommitmentTreeRoot::from_parts(
            birthday_height,
            T::empty_tree_leaf(),
        )],
    )
    .unwrap();

    // Extend the scan queue beyond max_scanned.
    let chain_tip = max_scanned + 500;
    st.wallet_mut().update_chain_tip(chain_tip).unwrap();

    // Construct a ChainState above max_scanned with a frontier in shard 2. The wallet
    // has shard 0 (from put_subtree_roots above) but does NOT have shard 1. Inserting a
    // frontier in shard 2 introduces a discontinuity because shard 1's subtree root is
    // unknown.
    let target_height = max_scanned + 50;
    let shard_2_tree_size: u64 = (0x2 << 16) + 2;
    let (_, shard2_sapling_frontier) = Frontier::random_with_prior_subtree_roots(
        st.rng_mut(),
        shard_2_tree_size,
        NonZeroU8::new(16).unwrap(),
    );
    #[cfg(feature = "orchard")]
    let (_, shard2_orchard_frontier) = Frontier::random_with_prior_subtree_roots(
        st.rng_mut(),
        shard_2_tree_size,
        NonZeroU8::new(16).unwrap(),
    );
    // Ironwood is not active at these test heights, so its tree is empty.
    #[cfg(feature = "orchard")]
    let shard2_ironwood_frontier = Frontier::empty();

    let target_chain_state = ChainState::new(
        target_height,
        BlockHash([7; 32]),
        shard2_sapling_frontier,
        #[cfg(feature = "orchard")]
        shard2_orchard_frontier,
        #[cfg(feature = "orchard")]
        shard2_ironwood_frontier,
    );

    // Verify the scan queue extends beyond the target.
    let pre_truncation_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should be set");
    assert!(pre_truncation_tip > target_height);

    // Truncate to the target height, which is above max_scanned. With the fix, this
    // skips the frontier insertion (avoiding the discontinuity) and trims the scan queue.
    // Without the fix, this would fail because inserting a frontier in shard 2 requires
    // shard 1's subtree root, which is unknown.
    st.wallet_mut()
        .truncate_to_chain_state(target_chain_state)
        .expect("truncate_to_chain_state above max scanned should succeed");

    // The scan queue should have been trimmed to the target height.
    let post_truncation_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after truncation");
    assert_eq!(
        post_truncation_tip, target_height,
        "scan queue should be trimmed to target height, not extend to the old chain tip"
    );

    // Existing blocks below max_scanned should be preserved.
    assert!(
        st.wallet().get_block_hash(max_scanned).unwrap().is_some(),
        "blocks at max_scanned should be preserved"
    );
}

pub fn rewind_to_chain_state_deep<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Deep-rewind test plan:
    // 1. Set up a birthday-aligned account.
    // 2. Generate and scan initial blocks to populate the note commitment tree.
    // 3. Pick a rewind target well below the future prune floor.
    // 4. Generate and scan more than PRUNING_DEPTH extra blocks so that the checkpoint at the
    //    target is pruned AND the target lies below `tip - PRUNING_DEPTH` (the "deep" branch).
    // 5. Call `rewind_to_chain_state(target)` and verify:
    //    - the scan queue is rewound all the way to `target`;
    //    - blocks, transactions, tx_locator_map entries, and note commitment trees are
    //      only rewound to `tip - (PRUNING_DEPTH - 1)` (the oldest retained checkpoint).

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let sapling_activation = st
        .network()
        .activation_height(consensus::NetworkUpgrade::Sapling)
        .unwrap();

    // Generate and scan initial blocks using an "other" fvk so notes are not tracked
    // by the wallet.
    let seed = [1u8; 32];
    let other_fvk = T::sk_to_fvk(&T::sk(&seed));

    let initial_block_count = 8u32;
    for _ in 0..initial_block_count {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    st.scan_cached_blocks(sapling_activation, initial_block_count as usize);

    // The rewind target is the tip of the initial range.
    let rewind_target = sapling_activation + initial_block_count - 1;

    // Scan more than PRUNING_DEPTH extra blocks so that the checkpoint at rewind_target is pruned
    // AND rewind_target is below `tip - PRUNING_DEPTH`.
    let extra_blocks = PRUNING_DEPTH + 10;
    for _ in 0..extra_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5000),
        );
    }
    st.scan_cached_blocks(rewind_target + 1, extra_blocks as usize);

    let pre_rewind_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should be set");
    assert!(
        pre_rewind_tip > rewind_target + PRUNING_DEPTH,
        "tip should be strictly beyond pruning depth from the rewind target"
    );

    // Capture the block hash at the prune boundary so we can assert it survives the rewind
    // unchanged (rather than merely that something exists at that height).
    let prune_boundary = pre_rewind_tip - (PRUNING_DEPTH - 1);
    let boundary_hash_before = st
        .wallet()
        .get_block_hash(prune_boundary)
        .unwrap()
        .expect("block at prune boundary should be present before rewind");

    // `rewind_to_chain_state` must succeed at the same target.
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::new(),
        )
        .expect("rewind_to_chain_state should succeed for a deep target");

    // The chain tip (derived from scan_queue) should still report the pre-rewind tip:
    // `rewind_to_chain_state` overwrites the scan-queue range above the rewind target
    // with a `Historic` rescan range that extends up to the pre-rewind tip.
    let new_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after rewind");
    assert_eq!(new_tip, pre_rewind_tip);

    // A deep rewind preserves block, transaction, tx_locator_map, and note commitment tree
    // data only as far back as the oldest retained checkpoint at `tip - (PRUNING_DEPTH - 1)`.
    // Data at that boundary is kept (so stabilized notes remain spendable); data above it is
    // removed.
    let wallet = st.wallet();
    assert_eq!(
        wallet.get_block_hash(prune_boundary).unwrap(),
        Some(boundary_hash_before),
        "block hash at (tip - (PRUNING_DEPTH - 1)) should be preserved unchanged by a deep rewind"
    );
    assert!(
        wallet.get_block_hash(prune_boundary + 1).unwrap().is_none(),
        "block entries above (tip - (PRUNING_DEPTH - 1)) must be removed by a deep rewind"
    );
    assert!(
        wallet.get_block_hash(pre_rewind_tip).unwrap().is_none(),
        "block entries up to the pre-rewind tip must be removed by a deep rewind"
    );
    assert_eq!(
        wallet
            .block_max_scanned()
            .unwrap()
            .map(|m| m.block_height()),
        Some(prune_boundary),
        "block_max_scanned should equal (tip - (PRUNING_DEPTH - 1)) after a deep rewind"
    );
}

pub fn rewind_to_chain_state_shallow<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Shallow-rewind test plan:
    // 1. Set up a birthday-aligned account.
    // 2. Generate and scan initial blocks to populate the note commitment tree.
    // 3. Pick a rewind target.
    // 4. Generate and scan `PRUNING_DEPTH - 1` extra blocks so that the target sits at
    //    the shallow boundary (`target == tip - (PRUNING_DEPTH - 1)`, exactly the oldest
    //    retained checkpoint).
    // 5. Call `rewind_to_chain_state(target)` and verify all wallet data is rewound to the
    //    target: data at the target is preserved, anything above is removed.

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let sapling_activation = st
        .network()
        .activation_height(consensus::NetworkUpgrade::Sapling)
        .unwrap();

    let seed = [1u8; 32];
    let other_fvk = T::sk_to_fvk(&T::sk(&seed));

    let initial_block_count = 8u32;
    for _ in 0..initial_block_count {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10000),
        );
    }
    st.scan_cached_blocks(sapling_activation, initial_block_count as usize);

    let rewind_target = sapling_activation + initial_block_count - 1;

    // Scan `PRUNING_DEPTH - 1` extra blocks so the target sits at the shallow boundary
    // (`target == tip - (PRUNING_DEPTH - 1)`, exactly the oldest retained checkpoint
    // given the tree's `max_checkpoints = PRUNING_DEPTH`).
    let extra_blocks = PRUNING_DEPTH - 1;
    for _ in 0..extra_blocks {
        st.generate_next_block(
            &other_fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5000),
        );
    }
    st.scan_cached_blocks(rewind_target + 1, extra_blocks as usize);

    let tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should be set");
    assert_eq!(
        tip,
        rewind_target + (PRUNING_DEPTH - 1),
        "tip should be exactly at the shallow boundary from the rewind target"
    );

    let target_hash_before = st
        .wallet()
        .get_block_hash(rewind_target)
        .unwrap()
        .expect("block at the rewind target should be present before rewind");

    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::new(),
        )
        .expect("rewind_to_chain_state should succeed for a shallow target");

    // The chain tip (derived from scan_queue) should still report the pre-rewind tip:
    // `rewind_to_chain_state` overwrites the scan-queue range above the rewind target with
    // a `Historic` rescan range that extends up to the pre-rewind tip.
    let new_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after rewind");
    assert_eq!(new_tip, tip);

    // A shallow rewind truncates blocks, tx_locator_map, and note commitment trees
    // directly to the rewind target: data at the target is preserved (with the same
    // content it had before), anything above is removed.
    let wallet = st.wallet();
    assert_eq!(
        wallet.get_block_hash(rewind_target).unwrap(),
        Some(target_hash_before),
        "block hash at the rewind target should be preserved unchanged"
    );
    assert!(
        wallet.get_block_hash(rewind_target + 1).unwrap().is_none(),
        "block entries above the rewind target should be removed by a shallow rewind"
    );
    assert_eq!(
        wallet
            .block_max_scanned()
            .unwrap()
            .map(|m| m.block_height()),
        Some(rewind_target),
        "block_max_scanned should equal the rewind target after a shallow rewind"
    );
}

pub fn rewind_after_non_contiguous_scan<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    // Regression test: after the scan scheduler processes a `ChainTip` range before a
    // lower `Historic` range, `MAX(height) FROM blocks` points into one scanned region
    // while `last_scanned - (PRUNING_DEPTH - 1)` lands inside the unscanned gap between
    // the two regions. `rewind_to_chain_state` must still succeed: an implementation that
    // expected a checkpoint at exactly the PD floor would return `CorruptedData` via
    // `truncate_to_checkpoint`; clamping forward to the lowest checkpoint inside the
    // prune window keeps us aligned with a real checkpoint.

    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let sapling_activation = st
        .network()
        .activation_height(consensus::NetworkUpgrade::Sapling)
        .unwrap();

    // Scan is always sequential in cache order, but `scan_cached_blocks` is happy to be
    // invoked on subranges out of order. We pre-generate a contiguous chain of blocks
    // and scan it in two disjoint segments with a gap in between.
    let seed = [1u8; 32];
    let other_fvk = T::sk_to_fvk(&T::sk(&seed));
    let filler_value = Zatoshis::const_from_u64(10_000);

    let low_count: u32 = 10;
    let gap_size: u32 = PRUNING_DEPTH + 5; // must exceed PD so the PD floor lands in the gap
    let high_count: u32 = 10;
    let total_generated = low_count + gap_size + high_count;

    for _ in 0..total_generated {
        st.generate_next_block(&other_fvk, AddressType::DefaultExternal, filler_value);
    }

    let low_start = sapling_activation;
    let low_end_inclusive = low_start + low_count - 1;
    let high_start = low_end_inclusive + gap_size + 1;

    // Scan the low range first (simulating a historic range).
    st.scan_cached_blocks(low_start, low_count as usize);

    // Scan the high range next (simulating a chain-tip range), leaving `gap_size` blocks
    // in the middle unscanned. Because `high_start > low_end_inclusive + PRUNING_DEPTH`,
    // the PD floor after this scan (`high_end_inclusive - (PRUNING_DEPTH - 1)`) lands
    // inside the unscanned gap.
    st.scan_cached_blocks(high_start, high_count as usize);

    let max_scanned_height = st
        .wallet()
        .block_max_scanned()
        .unwrap()
        .map(|m| m.block_height())
        .expect("block_max_scanned should report the high-range tip");
    let high_end_inclusive = high_start + high_count - 1;
    assert_eq!(max_scanned_height, high_end_inclusive);
    let pd_floor = max_scanned_height - (PRUNING_DEPTH - 1);
    assert!(
        pd_floor > low_end_inclusive && pd_floor < high_start,
        "test invariant: PD floor must lie in the unscanned gap (got {pd_floor}, \
         gap is ({low_end_inclusive}, {high_start}))"
    );

    // `rewind_to_chain_state` must return `Ok(_)` rather than `CorruptedData`: clamping
    // forward to the lowest checkpoint inside the window (which sits at `high_start`)
    // keeps us aligned with a real checkpoint.
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(low_end_inclusive, BlockHash([0; 32])),
            HashSet::new(),
        )
        .expect("rewind_to_chain_state should succeed across a non-contiguous scan");
}

/// Helper: drive the value-conservation checks once a recovery sequence
/// claims the note is spendable again. Run a send-max proposal (consume
/// exactly the reported balance) and a real fixed-value spend that must
/// construct a transaction end-to-end.
fn assert_recovered_balance_spends<T, Cache, DbT, ParamsT, AccountIdT, ErrT>(
    st: &mut TestState<Cache, DbT, ParamsT>,
    account_id: AccountIdT,
    usk: &UnifiedSpendingKey,
    expected_balance: Zatoshis,
) where
    T: ShieldedPoolTester,
    Cache: TestCache,
    <Cache::BlockSource as BlockSource>::Error: std::fmt::Debug,
    ParamsT: consensus::Parameters + Send + 'static,
    AccountIdT: std::fmt::Debug + std::cmp::Eq + std::hash::Hash + Copy,
    ErrT: std::fmt::Debug,
    DbT: InputSource<AccountId = AccountIdT, Error = ErrT>
        + WalletTest
        + WalletWrite<AccountId = AccountIdT, Error = ErrT>
        + WalletCommitmentTrees,
    <DbT as WalletRead>::AccountId: ConditionallySelectable + Default + Send + Sync + 'static,
    <DbT as WalletRead>::Account: data_api::Account<AccountId = AccountIdT>,
{
    // Send-max consumes exactly the reported balance.
    assert_send_max_consumes_balance::<T, _, _, _, _, _>(st, account_id, expected_balance);

    // A small fixed-value spend must construct a transaction.
    let to_extsk = T::sk(&[0xcc; 32]);
    let to: Address = T::sk_default_address(&to_extsk);
    let send_value = Zatoshis::const_from_u64(10_000);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        send_value,
    )])
    .unwrap();
    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        T::SHIELDED_PROTOCOL,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();
    let proposal = st
        .propose_transfer(
            account_id,
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .expect("propose_transfer should succeed against stabilized notes after the recovery scan");
    let txids = st
        .create_proposed_transactions::<std::convert::Infallible, _, std::convert::Infallible, _>(
            usk,
            OvkPolicy::Sender,
            &proposal,
        )
        .expect("transaction construction should succeed");
    assert_eq!(
        txids.len(),
        1,
        "the spend should produce exactly one transaction",
    );
}

/// A note in the chain-tip shard stays recoverable across a rewind to below
/// its account's birthday, as long as the chain has real history there to
/// re-scan.
///
/// Uses [`build_two_account_recovery_fixture`]: account B's birthday is
/// `H_A + 5`, and account A contributes the real blocks `H_A ..= H_A + 4`.
/// The rewind targets `H_A + 2` -- below B's birthday but inside A's history
/// -- so the recovery re-scan covers genuine cached blocks rather than faked
/// tree state (the `CacheMiss` failure mode of an all-faked pre-birthday
/// fixture).
///
///   1. Baseline: both accounts' notes are spendable.
///   2. After the rewind: B's balance is zero (its chain-tip shard is
///      re-dirtied and the pruning window carries the `Anchor` stamp).
///   3. After re-scanning the dirty range: B's note is spendable again and
///      value conservation holds.
pub fn b_note_stable_across_rewind_below_birthday<T, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let (mut st, account_b_id, usk_b) =
        build_two_account_recovery_fixture::<T, Dsf>(ds_factory, cache);
    let account_a = st.test_account().unwrap().clone();
    let birthday_a = account_a.birthday().height();
    let birthday_b = birthday_a + 5;

    // (1) Baseline: both notes spendable.
    assert_eq!(
        st.get_spendable_balance(account_a.id(), ConfirmationsPolicy::MIN),
        RECOVERY_A_NOTE_VALUE,
        "account A's note must be spendable in the freshly-built fixture",
    );
    assert_eq!(
        st.get_spendable_balance(account_b_id, ConfirmationsPolicy::MIN),
        RECOVERY_B_NOTE_VALUE,
        "account B's note must be spendable in the freshly-built fixture",
    );

    // (2) Rewind to `H_A + 2`: below B's birthday (`H_A + 5`) but within the
    // run of real blocks contributed by account A.
    let rewind_target = birthday_a + 2;
    assert!(
        rewind_target < birthday_b,
        "the rewind target must sit below account B's birthday",
    );
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::from([account_b_id]),
        )
        .expect("rewind_to_chain_state should succeed");

    assert_eq!(
        st.get_spendable_balance(account_b_id, ConfirmationsPolicy::MIN),
        Zatoshis::ZERO,
        "immediately after the rewind account B's note must not be spendable",
    );

    // (3) Re-scan every dirtied block. `H_A + 3 ..= chain_tip` is a
    // contiguous run of real cached blocks, so the re-scan completes without
    // a `CacheMiss`.
    let chain_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after rewind");
    let rescan_from = rewind_target + 1;
    let rescan_count = u32::from(chain_tip) - u32::from(rescan_from) + 1;
    st.scan_cached_blocks(rescan_from, rescan_count as usize);

    assert_eq!(
        st.get_spendable_balance(account_b_id, ConfirmationsPolicy::MIN),
        RECOVERY_B_NOTE_VALUE,
        "after re-scanning the dirty range account B's note must be spendable again",
    );
    assert_eq!(
        st.get_spendable_balance(account_a.id(), ConfirmationsPolicy::MIN),
        RECOVERY_A_NOTE_VALUE,
        "account A's note is unaffected by a rewind that stays above its shard",
    );

    assert_recovered_balance_spends::<T, _, _, _, _, _>(
        &mut st,
        account_b_id,
        &usk_b,
        RECOVERY_B_NOTE_VALUE,
    );
}

/// Recovering a completed-shard note after a rewind re-dirties its shard
/// requires re-scanning the *entire* birthday shard -- not merely the block
/// that re-discovers the note -- plus the anchor range.
///
/// Uses [`build_two_account_recovery_fixture`]. Account A's note sits at the
/// start of shard 1, which Block A2 completes. The rewind targets `H_A - 1`,
/// re-dirtying shard 1; recovery then proceeds in stages:
///
///   1. Baseline: A's note is spendable.
///   2. After the rewind: A's balance is zero.
///   3. After re-scanning only Block A1 (which re-discovers A's note but
///      leaves shard 1's later leaves unscanned): still zero -- the witness
///      needs every leaf to the note's right within the shard.
///   4. After also re-scanning Block A2 (shard 1 complete and scan-clean)
///      but not the anchor range: still zero.
///   5. After re-scanning the anchor range (the chain-tip pruning window):
///      A's note is spendable again -- with the blocks between shard 1 and
///      the pruning window left unscanned, since the chain-tip shard's
///      frontier already suffices to build the witness.
pub fn a_note_requires_full_birthday_shard_scan<T, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let (mut st, account_b_id, _) = build_two_account_recovery_fixture::<T, Dsf>(ds_factory, cache);
    let account_a = st.test_account().unwrap().clone();
    let birthday_a = account_a.birthday().height();
    let block_a1_height = birthday_a;
    let block_a2_height = birthday_a + 1;

    // (1) Baseline.
    assert_eq!(
        st.get_spendable_balance(account_a.id(), ConfirmationsPolicy::MIN),
        RECOVERY_A_NOTE_VALUE,
        "account A's note must be spendable in the freshly-built fixture",
    );

    // (2) Rewind below A's birthday, re-dirtying shard 1. Both accounts'
    // birthdays sit above the target, so both are reset.
    let rewind_target = birthday_a - 1;
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::from([account_a.id(), account_b_id]),
        )
        .expect("rewind_to_chain_state should succeed");

    assert_eq!(
        st.get_spendable_balance(account_a.id(), ConfirmationsPolicy::MIN),
        Zatoshis::ZERO,
        "immediately after the rewind account A's note must not be spendable",
    );

    // (3) Re-scan only Block A1. A's note is re-discovered, but shard 1's
    // leaves at positions 131036..131071 (Block A2) are still unscanned.
    st.scan_cached_blocks(block_a1_height, 1);
    assert_eq!(
        st.get_spendable_balance(account_a.id(), ConfirmationsPolicy::MIN),
        Zatoshis::ZERO,
        "account A's note must stay non-spendable while its shard is only partially scanned",
    );

    // (4) Re-scan Block A2, completing shard 1. The shard is scan-clean
    // again, but the anchor range has not been rescanned.
    st.scan_cached_blocks(block_a2_height, 1);
    assert_eq!(
        st.get_spendable_balance(account_a.id(), ConfirmationsPolicy::MIN),
        Zatoshis::ZERO,
        "completing shard 1 is not enough while the anchor range is unscanned",
    );

    // (5) Re-scan the chain-tip pruning window (the anchor range), leaving
    // the blocks between shard 1 and the pruning window unscanned.
    let chain_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after rewind");
    let pruning_window_start = chain_tip - (PRUNING_DEPTH - 1);
    st.scan_cached_blocks(pruning_window_start, PRUNING_DEPTH as usize);

    assert_eq!(
        st.get_spendable_balance(account_a.id(), ConfirmationsPolicy::MIN),
        RECOVERY_A_NOTE_VALUE,
        "after shard 1 and the anchor range are rescanned account A's note is spendable again",
    );

    assert_recovered_balance_spends::<T, _, _, _, _, _>(
        &mut st,
        account_a.id(),
        account_a.usk(),
        RECOVERY_A_NOTE_VALUE,
    );
}

/// R2: rewind to a height above shard 1's end (stable-shard fixture).
///
/// The rewind target sits *above* `shard 1`'s `subtree_end_height`
/// (= `birthday + 1`). The force-rewrite covers
/// `(new_birthday = target + 1, chain_tip + 1]` as `Historic`; that range
/// starts above shard 1's end and therefore does *not* overlap shard 1's
/// extent. `mark_anchor_priority_window` upgrades the pruning window
/// portion of the rewrite to `Anchor`.
///
/// Class 2 (target between shard end and pruning floor) and Class 3 (target
/// inside pruning window) of the previous test suite collapse here: in both
/// cases the rewrite range starts above shard 1 and so leaves the shard's
/// scan-state untouched. We pick `birthday + 5` as a representative target.
///
/// Under the corrected spendability rule, shard 1 stays scan-clean across
/// the rewind, so only the chain-tip pruning window needs to be rescanned to
/// restore the note's `spendable` status.
pub fn stabilized_note_rewind_above_shard_end<T, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let (mut st, account_id, usk) = build_stable_shard_fixture::<T, Dsf>(ds_factory, cache);
    let birthday_height = st
        .wallet()
        .get_wallet_birthday()
        .unwrap()
        .expect("account birthday should be set");

    // Baseline.
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        SHARD_1_NOTE_VALUE,
        "fixture must report the stabilized note as spendable",
    );

    // Rewind to a height above shard 1's end (= birthday + 1). Picking
    // `birthday + 5` lands in the Historic territory below the pruning
    // window; any choice in `(birthday + 1, chain_tip]` would exercise the
    // same regime.
    let rewind_target = birthday_height + 5;
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::new(),
        )
        .expect("rewind_to_chain_state should succeed");

    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        Zatoshis::ZERO,
        "immediately after rewind the Anchor stamp on the pruning window blocks the balance",
    );

    // Rescan only the chain-tip pruning window. Shard 1's extent
    // `(shard_0_end, birthday + 1]` sits below the rewrite range, so the
    // shard is still scan-clean. The corrected rule should restore the note
    // to `spendable`.
    let chain_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip should still be set after rewind");
    let pruning_window_start = chain_tip - (PRUNING_DEPTH - 1);
    st.scan_cached_blocks(pruning_window_start, PRUNING_DEPTH as usize);

    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        SHARD_1_NOTE_VALUE,
        "shard 1's extent is below the rewrite range; pruning-window rescan must restore the note",
    );

    assert_recovered_balance_spends::<T, _, _, _, _, _>(
        &mut st,
        account_id,
        &usk,
        SHARD_1_NOTE_VALUE,
    );
}

/// R3: rewind un-mines the shard-completion block (tip-shard fixture).
///
/// The tip-shard fixture leaves the wallet's birthday inside the chain-tip
/// pruning window (`chain_tip = birthday + 6`,
/// `pruning_floor = birthday - 94`,
/// `lowest_window_checkpoint = birthday - 93`). A rewind target below the
/// birthday therefore drives `truncation_target` to
/// `max(target, birthday - 93)`; with `target = birthday - 50` the
/// truncation lands at the lowest checkpoint at or above `birthday - 50`,
/// which is the account's birthday-frontier checkpoint at `birthday - 1`
/// (the pre-birthday blocks are unscanned and so carry no checkpoints).
/// Truncation removes shardtree state strictly above `birthday - 1`, which
/// discards the leaves inserted by Blocks A and B (positions
/// 131001..131080). Shard 1's last leaf (position 131071) is among those
/// discarded, so shard 1 reverts from complete to partial.
///
/// Under the corrected spendability rule, the note must not be reported as
/// spendable while its containing shard is partial -- even though
/// `witness_anchor_stable` is still set. Recovery requires rescanning from
/// the lowered birthday through the chain tip — all genuine cached blocks —
/// so that shard 1's leaves are reinserted and the shard returns to
/// complete + scan-clean.
pub fn stabilized_note_rewind_un_mines_shard_completion<T, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let (mut st, account_id, usk) = build_tip_shard_fixture::<T, Dsf>(ds_factory, cache);
    let birthday_height = st
        .wallet()
        .get_wallet_birthday()
        .unwrap()
        .expect("account birthday should be set");

    // Baseline: the note is stabilized via the active-shard interpretation
    // (witness_anchor_stable = birthday = Block A's height), and the rule
    // accepts it because shard 1 is currently scan-clean.
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        SHARD_1_NOTE_VALUE,
        "tip-shard fixture must report the active-shard-stabilized note as spendable",
    );

    // Rewind to a height well below the birthday, acknowledging that this
    // lowers the account birthday to `rewind_target + 1`. Truncation lands at
    // the lowest tree checkpoint at or above the target — the account's
    // birthday-frontier checkpoint at `birthday - 1` — removing both Block
    // A's and Block B's leaves and reverting shard 1 to partial. The rewind
    // target sits above the cache floor
    // (`birthday - PRE_BIRTHDAY_BLOCKS`), so the whole post-rewind scan
    // range is backed by genuine cached blocks.
    let rewind_target = birthday_height - 50;
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::from([account_id]),
        )
        .expect("rewind_to_chain_state should succeed");

    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        Zatoshis::ZERO,
        "after rewind the Anchor stamp + the partial shard combine to withhold the note",
    );

    // Recover by re-scanning every cached block from the lowered birthday
    // (`rewind_target + 1`) through the chain tip: 49 pre-birthday empty
    // blocks, Block A, Block B, and the 5 trailing fillers. The block cache
    // is contiguous across the original birthday, so a single
    // `scan_cached_blocks` call drives the full re-scan. After this, shard 1
    // is complete and scan-clean again.
    let new_birthday = rewind_target + 1;
    let recovery_block_count = 49 + 1 + 1 + 5;
    st.scan_cached_blocks(new_birthday, recovery_block_count as usize);

    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        SHARD_1_NOTE_VALUE,
        "after re-scanning from the lowered birthday through the chain tip, shard 1 is \
         complete and the note is spendable again",
    );

    assert_recovered_balance_spends::<T, _, _, _, _, _>(
        &mut st,
        account_id,
        &usk,
        SHARD_1_NOTE_VALUE,
    );
}

/// A stabilized note must remain spendable across a chain-tip advance smaller than the
/// trusted anchor depth, and must stop being spendable once the advance reaches that
/// depth.
///
/// `update_chain_tip` stamps the unscanned extension `(max_scanned, new_tip]` with
/// `ChainTip` priority. The anchor the wallet will select for a spend is derived from
/// the *new* tip (`target - min_confirmations(trusted)`); while the tip has advanced by
/// fewer than `min_confirmations` blocks, that anchor still lies within scanned history:
/// the tree structure between the note's anchor-stable height and the anchor is fully
/// known and a witness against exactly that anchor's root is constructable, so the
/// unscanned extension — which lies entirely *above* the anchor and cannot participate
/// in the witness — must not veto spendability.
///
/// Once the advance reaches the anchor depth, the policy anchor lies in unscanned
/// territory. The only anchor the wallet could construct a witness against is a stale,
/// checkpoint-clamped one; spending against it would reveal the wallet's lagging view
/// of the chain to a network observer, so the wallet must instead report zero spendable
/// value until it has scanned forward.
pub fn stabilized_note_spendable_across_small_tip_advance<T, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let (mut st, account_id, _usk) = build_stable_shard_fixture::<T, Dsf>(ds_factory, cache);

    let policy = ConfirmationsPolicy::default();
    let anchor_depth = u32::from(policy.trusted());
    assert!(
        anchor_depth > 1,
        "this test requires a trusted anchor depth of at least 2 so that a nonzero tip \
         advance can stay below it",
    );

    // Baseline: the wallet is fully scanned and the stabilized note is spendable.
    assert_eq!(
        st.get_spendable_balance(account_id, policy),
        SHARD_1_NOTE_VALUE,
        "fixture must report the stabilized note as spendable under the default policy",
    );

    let scanned_tip = st
        .wallet()
        .chain_height()
        .unwrap()
        .expect("chain tip is known");

    // Advance the chain tip by one block fewer than the trusted anchor depth, without
    // scanning. The policy anchor against the new tip
    // (`new_tip + 1 - anchor_depth = scanned_tip - 1`) is still within scanned history,
    // so the note must remain spendable.
    st.wallet_mut()
        .update_chain_tip(scanned_tip + (anchor_depth - 1))
        .unwrap();
    assert_eq!(
        st.get_spendable_balance(account_id, policy),
        SHARD_1_NOTE_VALUE,
        "a tip advance smaller than the anchor depth must not suspend spendability",
    );

    // Advance the tip by exactly the anchor depth. The policy anchor
    // (`new_tip + 1 - anchor_depth = scanned_tip + 1`) now lies in the unscanned
    // extension, so nothing may be reported spendable until the wallet scans forward.
    st.wallet_mut()
        .update_chain_tip(scanned_tip + anchor_depth)
        .unwrap();
    assert_eq!(
        st.get_spendable_balance(account_id, policy),
        Zatoshis::ZERO,
        "a tip advance reaching the anchor depth must suspend spendability until the \
         wallet has scanned to the new anchor",
    );
}

/// A note's stored anchor floor (`witness_anchor_stable`) is a claim about the chain the
/// wallet was observing when the floor was written: every block bearing on the note's
/// witness context up to that height has been scanned, so the wallet's determination of
/// witness constructability is grounded in chain data it has verified. A rewind that
/// truncates wallet state below a stored floor discards the scanned blocks and tree data
/// backing that claim, so the claim must not survive the truncation.
///
/// This test drives the false positive that arises if it does. A change note is mined at
/// the chain tip and stabilizes with its floor at its own mined height. A reorg then
/// rewinds the wallet three blocks below that height, and the same transaction is
/// re-mined two blocks lower on the new chain, with a non-wallet output in the block
/// directly above it that the wallet does not (yet) scan. Once the new chain advances far
/// enough that the unscanned block falls below the chain-tip pruning window, the
/// window-scanned check no longer sees the gap, and the stale floor — sitting exactly at
/// the gap's upper boundary — vouches that the region between the note and the window is
/// durably scanned. Every spendability check then passes and the wallet reports the note
/// spendable, even though that determination rests on blocks that exist only on the
/// reorged-away chain: the unscanned gap on the new chain has been neither
/// hash-chain-verified nor checked for spends of the wallet's notes.
///
/// The truncation must instead invalidate the stored floor. The note then re-stabilizes
/// from new-chain data only once its shard is scan-clean, so the wallet reports zero
/// spendable value while the gap remains, and the note becomes spendable when the gap is
/// scanned.
pub fn stabilized_note_floor_invalidated_by_reorg<T, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    T: ShieldedPoolTester,
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    use crate::data_api::ll::wallet::PRUNING_DEPTH;

    let (mut st, account_id, usk) = build_stable_shard_fixture::<T, Dsf>(ds_factory, cache);
    let policy = ConfirmationsPolicy::default();

    // Baseline: the fixture note is stabilized and spendable.
    assert_eq!(
        st.get_spendable_balance(account_id, policy),
        SHARD_1_NOTE_VALUE,
        "fixture must report the stabilized note as spendable under the default policy",
    );

    // Spend the fixture note, producing a wallet transaction whose change note carries
    // the stability floor under test. (A received note cannot be used here: re-mining
    // the *same* transaction at a different height is what lets the note row keep its
    // stored floor across the reorg, and only wallet-created transactions can be mined
    // into the fake chain twice.) The proposal is created against the fixture chain
    // state, before the additional blocks below are generated, so input selection can
    // only see the fixture note.
    let to = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let request = TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10000),
    )])
    .unwrap();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);
    let input_selector = GreedyInputSelector::new();
    let proposal = st
        .propose_transfer(
            account_id,
            &input_selector,
            &change_strategy,
            request,
            policy,
        )
        .unwrap();
    let txid = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            &usk,
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap()[0];

    // Extend the old chain by three scanned blocks: a second wallet note, a non-wallet
    // filler, and the transaction created above. The second wallet note is structural:
    // it occupies the first note-commitment-tree position that the upcoming rewind
    // truncates away. A marked (wallet-note) leaf keeps its pruned sibling's hash stored
    // explicitly, so truncating at its boundary cleanly splits the pair; were the leaf a
    // pruned non-wallet commitment, truncation would leave behind a merged hash node
    // spanning the boundary, and re-scanning the divergent chain would hit a note
    // commitment tree insertion conflict instead of exercising the spendability rule.
    let dfvk = T::sk_to_fvk(T::usk_to_sk(&usk));
    let extra_note_value = Zatoshis::const_from_u64(25000);
    let (extra_height, _, _) =
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, extra_note_value);

    let not_our_fvk = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let filler_value = Zatoshis::const_from_u64(1000);
    st.generate_next_block(&not_our_fvk, AddressType::DefaultExternal, filler_value);

    let (tx_height, _) = st.generate_next_block_including(txid);

    // Scan all three blocks in a single batch. This matters for the tree surgery below:
    // scanning in one batch writes no batch-boundary frontier (and thus no cached
    // interior-node hash annotations) above the rewind target, so truncating there and
    // re-scanning the divergent chain does not conflict with stale annotations. The
    // change note lands in the open chain-tip shard, which is scan-clean after the
    // batch, so it stabilizes immediately with its floor at its own mined height (above
    // the pruning floor).
    st.scan_cached_blocks(extra_height, 3);

    // The wallet's whole balance is now the change note plus the second wallet note (the
    // fixture note is spent). The reorg below permanently un-mines the second note, so
    // the recovered balance at the end of the test is the change value alone.
    let change_value = (st.get_total_balance(account_id) - extra_note_value)
        .expect("balance covers the extra note value");
    assert!(change_value > Zatoshis::ZERO);

    // Reorg: rewind the wallet to three blocks below the transaction's mined height —
    // just below the second wallet note. This truncates the tree data above the rewind
    // target, including everything the change note's stored floor vouches for, and
    // un-mines both the transaction and the second note. The block cache is truncated
    // separately so that the chain regenerated below diverges from the reorged-away one.
    let rewind_target = tx_height - 3;
    st.wallet_mut()
        .rewind_to_chain_state(
            ChainState::empty(rewind_target, BlockHash([0; 32])),
            HashSet::new(),
        )
        .expect("rewind_to_chain_state should succeed");
    st.truncate_cache_to_height(rewind_target);

    // On the new chain, the same transaction is re-mined two blocks lower than before
    // (the second wallet note is not re-mined at all)...
    let (remine_height, _) = st.generate_next_block_including(txid);
    assert_eq!(remine_height, tx_height - 2);

    // ...with a non-wallet output in the block directly above it. The output makes the
    // gap material: the wallet can obtain that commitment's value only by scanning the
    // gap block or by trusting a server-supplied frontier, and until the block is
    // scanned it may conceal spends of the wallet's notes.
    let (gap_height, _, _) =
        st.generate_next_block(&not_our_fvk, AddressType::DefaultExternal, filler_value);
    assert_eq!(gap_height, tx_height - 1);

    // Extend the new chain with single-output filler blocks (empty blocks would leave
    // the note commitment tree without checkpoints at the new heights, clamping the
    // wallet's anchor selection below the region under test) until the gap block sits
    // just below the pruning window of the new tip
    // (`new_tip - PRUNING_DEPTH = gap_height + 1`).
    let mut new_tip = gap_height;
    for _ in 0..(PRUNING_DEPTH + 1) {
        new_tip = st
            .generate_next_block(&not_our_fvk, AddressType::DefaultExternal, filler_value)
            .0;
    }

    // Scan the re-mined transaction's block, then everything above the gap block, which
    // is deliberately left unscanned: it is the only hole in the wallet's view of the
    // new chain, and it lies below the pruning window, where only the note's stability
    // floor guards against it.
    st.scan_cached_blocks(remine_height, 1);
    st.wallet_mut().update_chain_tip(new_tip).unwrap();
    st.scan_cached_blocks(gap_height + 1, (PRUNING_DEPTH + 1) as usize);

    // The change note's old floor (its old-chain mined height) sits exactly at the top
    // of the unscanned gap; were it to survive the truncation, it would vouch that the
    // gap does not matter and the note would be reported spendable. The truncation must
    // instead have invalidated the floor, and the note — whose shard is not scan-clean
    // while the gap remains — must not have re-stabilized.
    assert_eq!(
        st.get_spendable_balance(account_id, policy),
        Zatoshis::ZERO,
        "a stability floor written on the reorged-away chain must not vouch for \
         spendability while the new chain has an unscanned gap below the pruning window",
    );

    // Scanning the gap block closes the hole: the change note re-stabilizes from
    // new-chain data and becomes spendable.
    st.scan_cached_blocks(gap_height, 1);
    assert_eq!(
        st.get_spendable_balance(account_id, policy),
        change_value,
        "closing the gap must restore spendability of the change note",
    );
}

pub fn reorg_to_checkpoint<T: ShieldedPoolTester, Dsf, C>(ds_factory: Dsf, cache: C)
where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
    C: TestCache,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();

    // Create a sequence of blocks to serve as the foundation of our chain state.
    let p0_fvk = T::random_fvk(st.rng_mut());
    let gen_random_block = |st: &mut TestState<C, Dsf::DataStore, LocalNetwork>,
                            output_count: usize| {
        let fake_outputs =
            std::iter::repeat_with(|| FakeCompactOutput::random(st.rng_mut(), p0_fvk.clone()))
                .take(output_count)
                .collect::<Vec<_>>();
        st.generate_next_block_multi(&fake_outputs[..]);
        output_count
    };

    // The stable portion of the tree will contain 20 notes.
    for _ in 0..10 {
        gen_random_block(&mut st, 4);
    }

    // We will reorg to this height.
    let reorg_height = account.birthday().height() + 4;
    let reorg_position = Position::from(19);

    // Scan the first 5 blocks. The last block in this sequence will be where we simulate a
    // reorg.
    st.scan_cached_blocks(account.birthday().height(), 5);
    assert_eq!(
        st.wallet()
            .block_max_scanned()
            .unwrap()
            .unwrap()
            .block_height(),
        reorg_height
    );

    // There will be 6 checkpoints: one for the prior block frontier, and then one for each scanned
    // block.
    let checkpoints = st
        .wallet()
        .get_checkpoint_history(&T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(checkpoints.len(), 6);
    assert_eq!(
        checkpoints.last(),
        Some(&(reorg_height, Some(reorg_position)))
    );

    // Scan another block, then simulate a reorg.
    st.scan_cached_blocks(reorg_height + 1, 1);
    assert_eq!(
        st.wallet()
            .block_max_scanned()
            .unwrap()
            .unwrap()
            .block_height(),
        reorg_height + 1
    );
    let checkpoints = st
        .wallet()
        .get_checkpoint_history(&T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(checkpoints.len(), 7);
    assert_eq!(
        checkpoints.last(),
        Some(&(reorg_height + 1, Some(reorg_position + 4)))
    );

    //        /\  /\  /\
    //  .... /\/\/\/\/\/\
    //          c   d   e

    // Truncate back to the reorg height, but retain the block cache.
    st.truncate_to_height_retaining_cache(reorg_height);

    // The following error-prone tree state is generated by the a previous (buggy) truncate
    // implementation:
    //        /\  /\
    //  .... /\/\/\/\
    //          c

    // We have pruned back to the original checkpoints & tree state.
    let checkpoints = st
        .wallet()
        .get_checkpoint_history(&T::SHIELDED_PROTOCOL)
        .unwrap();
    assert_eq!(checkpoints.len(), 6);
    assert_eq!(
        checkpoints.last(),
        Some(&(reorg_height, Some(reorg_position)))
    );

    // Skip two blocks, then (re) scan the same block.
    st.scan_cached_blocks(reorg_height + 2, 1);

    // Given the buggy truncation, this would result in this the following tree state:
    //        /\  /\   \  /\
    //  .... /\/\/\/\   \/\/\
    //          c       e   f

    let checkpoints = st
        .wallet()
        .get_checkpoint_history(&T::SHIELDED_PROTOCOL)
        .unwrap();
    // Even though we only scanned one block, we get a checkpoint at both the start and the end of
    // the block due to the insertion of the prior block frontier.
    assert_eq!(checkpoints.len(), 8);
    assert_eq!(
        checkpoints.last(),
        Some(&(reorg_height + 2, Some(reorg_position + 8)))
    );

    // Now, fully truncate back to the reorg height. This should leave the tree in a state
    // where it can be added to with arbitrary notes.
    st.truncate_to_height(reorg_height);

    // Generate some new random blocks
    for _ in 0..10 {
        let output_count = st.rng_mut().gen_range(2..10);
        gen_random_block(&mut st, output_count);
    }

    // The previous truncation retained the cache, so re-scanning the same blocks would have
    // resulted in the same note commitment tree state, and hence no conflicts; could occur. Now
    // that we have cleared the cache and generated a different sequence blocks, if truncation did
    // not completely clear the tree state this would generates a note commitment tree conflict.
    st.scan_cached_blocks(reorg_height + 1, 1);
}

pub fn scan_cached_blocks_allows_blocks_out_of_order<T: ShieldedPoolTester>(
    ds_factory: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    let value = Zatoshis::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    st.scan_cached_blocks(h1, 1);
    assert_eq!(st.get_total_balance(account.id()), value);

    // Create blocks to reach height + 2
    let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
    let (h3, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Scan the later block first
    st.scan_cached_blocks(h3, 1);

    // Now scan the block of height height + 1
    st.scan_cached_blocks(h2, 1);
    assert_eq!(
        st.get_total_balance(account.id()),
        Zatoshis::const_from_u64(150_000)
    );

    // We can spend the received notes
    let req = TransactionRequest::new(vec![Payment::without_memo(
        T::fvk_default_address(&dfvk).to_zcash_address(st.network()),
        Zatoshis::const_from_u64(110_000),
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);

    assert_matches!(
        st.spend(
            &input_selector,
            &change_strategy,
            account.usk(),
            req,
            OvkPolicy::Sender,
            ConfirmationsPolicy::MIN,
        ),
        Ok(_)
    );
}

pub fn scan_cached_blocks_finds_received_notes<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(ConfirmationsPolicy::MIN), None);

    // Create a fake CompactBlock sending value to the address
    let value = Zatoshis::const_from_u64(50000);
    let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Scan the cache
    let summary = st.scan_cached_blocks(h1, 1);
    assert_eq!(summary.scanned_range().start, h1);
    assert_eq!(summary.scanned_range().end, h1 + 1);
    assert_eq!(T::received_note_count(&summary), 1);

    // Account balance should reflect the received note
    assert_eq!(st.get_total_balance(account.id()), value);

    // Create a second fake CompactBlock sending more value to the address
    let value2 = Zatoshis::const_from_u64(70000);
    let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value2);

    // Scan the cache again
    let summary = st.scan_cached_blocks(h2, 1);
    assert_eq!(summary.scanned_range().start, h2);
    assert_eq!(summary.scanned_range().end, h2 + 1);
    assert_eq!(T::received_note_count(&summary), 1);

    // Account balance should reflect both received notes
    assert_eq!(
        st.get_total_balance(account.id()),
        (value + value2).unwrap()
    );
}

pub fn scan_cached_blocks_finds_change_notes<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(ConfirmationsPolicy::MIN), None);

    // Create a fake CompactBlock sending value to the address
    let value = Zatoshis::const_from_u64(50000);
    let (_, _, nf) = st.add_a_single_note_checking_balance(value);

    // Create a second fake CompactBlock spending value from the address
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let to2 = T::fvk_default_address(&not_our_key);
    let value2 = Zatoshis::const_from_u64(20000);
    let (spent_height, _) = st.generate_next_block_spending(&dfvk, (nf, value), to2, value2);

    // Scan the cache again
    st.scan_cached_blocks(spent_height, 1);

    // Account balance should equal the change
    assert_eq!(
        st.get_total_balance(account.id()),
        (value - value2).unwrap()
    );
}

pub fn scan_cached_blocks_detects_spends_out_of_order<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let account = st.test_account().cloned().unwrap();
    let dfvk = T::test_account_fvk(&st);

    // Wallet summary is not yet available
    assert_eq!(st.get_wallet_summary(ConfirmationsPolicy::MIN), None);

    // Create a fake CompactBlock sending value to the address
    let value = Zatoshis::const_from_u64(50000);
    let (received_height, _, nf) =
        st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);

    // Create a second fake CompactBlock spending value from the address
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let to2 = T::fvk_default_address(&not_our_key);
    let value2 = Zatoshis::const_from_u64(20000);
    let (spent_height, _) = st.generate_next_block_spending(&dfvk, (nf, value), to2, value2);

    // Scan the spending block first.
    st.scan_cached_blocks(spent_height, 1);

    // Account balance should equal the change
    assert_eq!(
        st.get_total_balance(account.id()),
        (value - value2).unwrap()
    );

    // Now scan the block in which we received the note that was spent.
    st.scan_cached_blocks(received_height, 1);

    // Account balance should be the same.
    assert_eq!(
        st.get_total_balance(account.id()),
        (value - value2).unwrap()
    );
}

pub fn metadata_queries_exclude_unwanted_notes<T: ShieldedPoolTester, Dsf, TC>(
    ds_factory: Dsf,
    cache: TC,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: std::fmt::Debug,
    TC: TestCache,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    // Create 10 blocks with successively increasing value
    let note_values = (1..=10)
        .map(|i| Zatoshis::const_from_u64(i * 100_0000))
        .collect::<Vec<_>>();
    let h0 = st
        .add_notes_checking_balance(note_values.clone().into_iter().map(Some))
        .first_block_height()
        .unwrap();

    let target_height = TargetHeight::from(h0 + 10);
    let account = st.test_account().cloned().unwrap();
    let test_meta = |st: &TestState<TC, Dsf::DataStore, LocalNetwork>, query, expected_count| {
        let metadata = st
            .wallet()
            .get_account_metadata(account.id(), &query, target_height, &[])
            .unwrap();

        assert_eq!(metadata.note_count(T::SHIELDED_PROTOCOL), expected_count);
    };

    test_meta(
        &st,
        NoteFilter::ExceedsMinValue(Zatoshis::const_from_u64(1000_0000)),
        Some(0),
    );
    test_meta(
        &st,
        NoteFilter::ExceedsMinValue(Zatoshis::const_from_u64(500_0000)),
        Some(5),
    );
    test_meta(
        &st,
        NoteFilter::ExceedsBalancePercentage(BoundedU8::new_const(10)),
        Some(5),
    );

    // We haven't sent any funds yet, so we can't evaluate this query
    test_meta(
        &st,
        NoteFilter::ExceedsPriorSendPercentile(BoundedU8::new_const(50)),
        None,
    );

    // Spend half of each one of our notes, so that we can get a distribution of sent note values.
    // FIXME: This test is currently excessively specialized to the `zcash_client_sqlite::WalletDb`
    // implmentation of the `InputSource` trait. A better approach would be to create a test input
    // source that can select a set of notes directly based upon their nullifiers.
    let not_our_key = T::sk_to_fvk(&T::sk(&[0xf5; 32]));
    let to = T::fvk_default_address(&not_our_key).to_zcash_address(st.network());
    let nz2 = NonZeroU64::new(2).unwrap();

    for value in &note_values {
        let txids = st
            .create_standard_transaction(&account, to.clone(), *value / nz2)
            .unwrap();
        st.generate_next_block_including(txids.head);
    }
    st.scan_cached_blocks(h0 + 10, 10);

    // Since we've spent half our notes, our remaining notes each have approximately half their
    // original value. The 50th percentile of our spends should be 250_0000 ZAT, and half of our
    // remaining notes should have value greater than that.
    test_meta(
        &st,
        NoteFilter::ExceedsPriorSendPercentile(BoundedU8::new_const(50)),
        Some(5),
    );
}

#[cfg(feature = "pczt")]
pub fn pczt_single_step<P0: ShieldedPoolTester, P1: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
    pin_expiry_above_target: Option<u32>,
) where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: serde::Serialize + serde::de::DeserializeOwned,
{
    use zcash_protocol::consensus::ZIP212_GRACE_PERIOD;

    let mut st = TestBuilder::new()
        .with_data_store_factory(ds_factory)
        .with_block_cache(cache)
        .with_initial_chain_state(|_, network| {
            // Initialize the chain state to after ZIP 212 became enforced.
            let birthday_height = std::cmp::max(
                network.activation_height(NetworkUpgrade::Nu5).unwrap(),
                network.activation_height(NetworkUpgrade::Canopy).unwrap() + ZIP212_GRACE_PERIOD,
            );

            // Ironwood is not active at these test heights, so its tree is empty.
            #[cfg(feature = "orchard")]
            let ironwood_initial_tree = Frontier::empty();

            InitialChainState {
                chain_state: ChainState::new(
                    birthday_height - 1,
                    BlockHash([5; 32]),
                    Frontier::empty(),
                    #[cfg(feature = "orchard")]
                    Frontier::empty(),
                    #[cfg(feature = "orchard")]
                    ironwood_initial_tree,
                ),
                prior_sapling_roots: vec![],
                #[cfg(feature = "orchard")]
                prior_orchard_roots: vec![],
            }
        })
        .with_account_having_current_birthday()
        .build();

    let account = st.test_account().cloned().unwrap();

    let p0_fvk = P0::test_account_fvk(&st);

    let p1_fvk = P1::test_account_fvk(&st);
    let p1_to = P1::fvk_default_address(&p1_fvk);

    // Only mine a block in P0 to ensure the transactions source is there.
    let note_value = Zatoshis::const_from_u64(350000);
    st.generate_next_block(&p0_fvk, AddressType::DefaultExternal, note_value);
    st.scan_cached_blocks(account.birthday().height(), 1);

    assert_eq!(st.get_total_balance(account.id()), note_value);
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        note_value
    );

    let transfer_amount = Zatoshis::const_from_u64(200000);
    let p0_to_p1 = TransactionRequest::new(vec![Payment::without_memo(
        p1_to.to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();

    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, P0::SHIELDED_PROTOCOL);
    let proposal0 = st
        .propose_transfer(
            account.id(),
            &input_selector,
            &change_strategy,
            p0_to_p1,
            ConfirmationsPolicy::MIN,
        )
        .unwrap();

    let min_target_height = proposal0.min_target_height();
    assert_eq!(proposal0.steps().len(), 1);

    let target_expiry_height =
        pin_expiry_above_target.map(|delta| BlockHeight::from(min_target_height) + delta);

    if target_expiry_height.is_some() {
        // This is rejected before transaction building, so the successful call below
        // can reuse the same proposal.
        assert_matches!(
            st.create_pczt_from_proposal::<Infallible, _, Infallible>(
                account.id(),
                OvkPolicy::Sender,
                &proposal0,
                Some(min_target_height.saturating_sub(1)),
            ),
            Err(Error::ExpiryHeightBelowTargetHeight { .. })
        );
    }

    let create_proposed_result = st.create_pczt_from_proposal::<Infallible, _, Infallible>(
        account.id(),
        OvkPolicy::Sender,
        &proposal0,
        target_expiry_height,
    );
    assert_matches!(&create_proposed_result, Ok(_));
    let pczt_created = create_proposed_result.unwrap();
    let pczt_branch_id =
        consensus::BranchId::try_from(*pczt_created.global().consensus_branch_id())
            .expect("the PCZT carries a valid consensus branch ID");

    // If we don't create proofs or signatures, we will fail to extract a transaction.
    assert_matches!(
        st.extract_and_store_transaction_from_pczt(pczt_created.clone()),
        Err(Error::Pczt(data_api::error::PcztError::Extraction(_)))
    );

    // Add proof generation keys to Sapling spends.
    let pczt_updated = P0::add_proof_generation_keys(pczt_created, account.usk()).unwrap();

    // Create proofs, using the circuit that governs the Orchard pool under the
    // consensus branch the PCZT was created for. (The test network's most recent
    // upgrade is NU5, so this is currently the historical pre-NU6.2 circuit;
    // modernizing the test network fixture is part of the broader Ironwood test
    // coverage work.)
    let sapling_prover = LocalTxProver::bundled();
    let orchard_pk = ::orchard::circuit::ProvingKey::build(
        zcash_primitives::transaction::components::orchard::bundle_version_for_branch(
            pczt_branch_id,
            ::orchard::ValuePool::Orchard,
        )
        .expect("the PCZT's consensus branch supports the Orchard pool")
        .circuit_version(),
    );
    let pczt_proven = Prover::new(pczt_updated)
        .create_orchard_proof(&orchard_pk)
        .unwrap()
        .create_sapling_proofs(&sapling_prover, &sapling_prover)
        .unwrap()
        .finish();

    // Apply signatures.
    let mut signer = Signer::new(pczt_proven).unwrap();
    P0::apply_signatures_to_pczt(&mut signer, account.usk()).unwrap();
    let pczt_authorized = signer.finish();

    // Now we can extract the transaction.
    let extract_and_store_result = st.extract_and_store_transaction_from_pczt(pczt_authorized);
    assert_matches!(&extract_and_store_result, Ok(_));
    let txid = extract_and_store_result.unwrap();

    if let Some(expiry_height) = target_expiry_height {
        let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
        assert_eq!(tx.expiry_height(), expiry_height);
    }

    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);
}

/// Ensure that wallet recovery recomputes fees.
///
/// Callers must provide an `intervene` function that deletes fee information for the specified
/// txid from the database. This deletion is checked and the test will fail if fee information is
/// not deleted.
#[cfg(feature = "transparent-inputs")]
pub fn wallet_recovery_computes_fees<T: ShieldedPoolTester, DsF: DataStoreFactory>(
    ds_factory: DsF,
    cache: impl TestCache,
    mut intervene: impl FnMut(&mut DsF::DataStore, TxId) -> Result<(), DsF::DsError>,
) {
    use secrecy::ExposeSecret;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();

    let seed = Secret::new(st.test_seed().unwrap().expose_secret().clone());
    let source_account = st.test_account().cloned().unwrap();
    let (dest_account_id, dest_usk) = st
        .wallet_mut()
        .create_account("dest", &seed, source_account.birthday(), None)
        .unwrap();

    let (to, _) = dest_usk.default_transparent_address();

    // Get some funds in the source account
    let note_value = Zatoshis::const_from_u64(350000);
    let _summary = st.add_notes_checking_balance([Some(note_value), Some(note_value)]);

    // Create two transactions sending from the source account to a transparent address in the
    // destination account.
    let input_selector = GreedyInputSelector::new();
    let change_strategy =
        single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL);
    let transfer_amount = Zatoshis::const_from_u64(200000);
    let request = TransactionRequest::new(vec![Payment::without_memo(
        Address::from(to).to_zcash_address(st.network()),
        transfer_amount,
    )])
    .unwrap();

    let mut send_transparent = || {
        let p0 = st
            .propose_transfer(
                source_account.id(),
                &input_selector,
                &change_strategy,
                request.clone(),
                ConfirmationsPolicy::MIN,
            )
            .unwrap();
        let result0 = st
            .create_proposed_transactions::<Infallible, _, Infallible, _>(
                source_account.usk(),
                OvkPolicy::Sender,
                &p0,
            )
            .unwrap();
        assert_eq!(result0.len(), 1);
        let txid = result0[0];
        let (h, _) = st.generate_next_block_including(txid);
        st.scan_cached_blocks(h, 1);

        // Make the destination account aware of the received UTXOs
        let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
        let t_bundle = tx.transparent_bundle().unwrap();
        assert_eq!(t_bundle.vout.len(), 1);

        let outpoint = OutPoint::new(*txid.as_ref(), 0);
        let utxo = WalletTransparentOutput::from_parts(
            outpoint,
            t_bundle.vout[0].clone(),
            Some(h),
            Some(dest_account_id),
            Some(TransparentKeyScope::EXTERNAL),
            None,
        )
        .unwrap();
        st.wallet_mut()
            .put_received_transparent_utxo(&utxo)
            .unwrap();

        (txid, h)
    };

    send_transparent();
    let (input_tx_1_txid, input_tx_1_height) = send_transparent();

    assert_eq!(
        st.get_total_balance(dest_account_id),
        (transfer_amount + transfer_amount).unwrap()
    );

    // Shield the funds in the destination account
    let p1 = st
        .propose_shielding(
            &input_selector,
            &change_strategy,
            Zatoshis::const_from_u64(10000),
            &[to],
            dest_account_id,
            ConfirmationsPolicy::MIN,
            CoinbaseFilter::AllTransparentOutputs,
        )
        .unwrap();
    let result1 = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            &dest_usk,
            OvkPolicy::Sender,
            &p1,
        )
        .unwrap();
    assert_eq!(result1.len(), 1);
    let txid = result1[0];
    let (h, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(h, 1);

    // Since our wallet constructed the transaction, we have the fee information;
    // we will need to wipe it out via a backend-level intervention in order to simulate
    // what happens in recovery.
    let shielding_tx = st.get_tx_from_history(txid).unwrap().unwrap();
    assert_matches!(shielding_tx.fee_paid, Some(_));
    let created_fee = shielding_tx.fee_paid.unwrap();

    intervene(st.wallet_mut(), txid).unwrap();

    // Verify that the intervention removed the fee information for the transaction.
    let shielding_tx = st.get_tx_from_history(txid).unwrap().unwrap();
    assert_matches!(shielding_tx.fee_paid, None);

    // Run `decrypt_and_store_transaction; this should restore the fee, since the wallet has all of
    // the necessary input and output data.
    let tx = st.wallet().get_transaction(txid).unwrap().unwrap();
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(h)).unwrap();

    // Verify that the fee information has been restored.
    let shielding_tx = st.get_tx_from_history(txid).unwrap().unwrap();
    assert_eq!(shielding_tx.fee_paid, Some(created_fee));

    // Wipe the fee information again; calling `decrypt_and_store_transaction` with the *input* tx
    // should also cause the fees to be restored.
    intervene(st.wallet_mut(), txid).unwrap();

    let shielding_tx = st.get_tx_from_history(txid).unwrap().unwrap();
    assert_matches!(shielding_tx.fee_paid, None);

    // Run `decrypt_and_store_transaction with one of the inputs; this should also restore the fee,
    // since the wallet has all of the necessary input and output data.
    let tx = st
        .wallet()
        .get_transaction(input_tx_1_txid)
        .unwrap()
        .unwrap();
    let network = *st.network();
    decrypt_and_store_transaction(&network, st.wallet_mut(), &tx, Some(input_tx_1_height)).unwrap();

    // Verify that the fee information has been restored.
    let shielding_tx = st.get_tx_from_history(txid).unwrap().unwrap();
    assert_eq!(shielding_tx.fee_paid, Some(created_fee));
}

/// Tests that the wallet correctly reports balance with two notes that are identical
/// other than their note randomness.
pub fn receive_two_notes_with_same_value<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Add funds to the wallet in two identical notes
    let value = Zatoshis::const_from_u64(60000);
    let h = st
        .add_notes_checking_balance([[value, value]])
        .block_height()
        .unwrap();

    // Spendable balance matches total balance.
    let account = st.test_account().cloned().unwrap();
    let total_value = (value + value).unwrap();
    assert_eq!(
        st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
        total_value
    );

    let target_height = (h + 1).into();

    // Both notes are unspent.
    let unspent_notes = T::select_unspent_notes(&st, account.id(), target_height, &[]).unwrap();
    assert_eq!(unspent_notes.len(), 2);
    for note in unspent_notes {
        assert_eq!(T::note_value(note.note()), value);
    }

    // Both notes are spendable with 1 confirmation.
    let spendable_notes = T::select_spendable_notes(
        &st,
        account.id(),
        TargetValue::AllFunds(MaxSpendMode::MaxSpendable),
        target_height,
        ConfirmationsPolicy::MIN,
        &[],
    )
    .unwrap();
    assert_eq!(spendable_notes.len(), 2);
    for note in spendable_notes {
        assert_eq!(T::note_value(note.note()), value);
    }
}

#[cfg(feature = "pczt")]
fn build_transparent_coinbase_tx(
    network: &LocalNetwork,
    target_height: TargetHeight,
    value: Zatoshis,
    recipient: TransparentAddress,
    miner_data: Option<PushValue>,
) -> zcash_primitives::transaction::builder::BuildResult {
    let build_config = BuildConfig::Coinbase { miner_data };
    let mut builder = Builder::new(*network, BlockHeight::from(target_height), build_config);

    // Add transparent output to recipient
    builder.add_transparent_output(&recipient, value).unwrap();

    // Build the transaction (coinbase transactions don't need provers)
    builder
        .build(
            // unused internally
            &TransparentSigningSet::new(),
            // unused internally
            &[],
            // unused internally
            &[],
            OsRng,
            &LocalTxProver::bundled(),
            &LocalTxProver::bundled(),
            // unused internally
            &StandardFeeRule::Zip317,
        )
        .unwrap()
}

#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
/// Tests that immature coinbase outputs are excluded from note selection.
pub fn immature_coinbase_outputs_are_excluded_from_note_selection<T: ShieldedPoolTester>(
    dsf: impl DataStoreFactory,
    cache: impl TestCache,
) {
    let mut st = TestDsl::with_sapling_birthday_account(dsf, cache).build::<T>();

    // Get the default transparent address
    let (t_addr, _) = st.get_account().usk().default_transparent_address();

    let coinbase_value = Zatoshis::const_from_u64(50000);

    // Get the height where the coinbase tx will be mined
    let coinbase_height = st.sapling_activation_height();

    // Construct the coinbase transaction and mine the block
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(coinbase_height),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);

    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();

    for i in 1..=99 {
        let latest_block_height = st.add_empty_blocks(1);

        // Verify the coinbase UTXO is **not** spendable
        let spendable_utxos = st
            .wallet()
            .get_spendable_transparent_outputs(
                &t_addr,
                TargetHeight::from(h + i),
                ConfirmationsPolicy::default(),
                CoinbaseFilter::AllTransparentOutputs,
            )
            .unwrap();
        let confirmations = latest_block_height - h;
        assert!(
            spendable_utxos.is_empty(),
            "{i}: Immature coinbase output is spendable at blockheight {latest_block_height} \
            with {confirmations} confirmations \
            (should only be spendable at 100):\n \
            {spendable_utxos:#?}"
        );
    }

    // Add the last block and ensure that the coinbase transaction is spendable
    let latest_height = st.add_empty_blocks(1);
    let confirmations = latest_height - h;
    let target_height = TargetHeight::from(latest_height + 1);
    let spendable_utxos = st
        .wallet()
        .get_spendable_transparent_outputs(
            &t_addr,
            target_height,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::AllTransparentOutputs,
        )
        .unwrap();
    assert!(
        !spendable_utxos.is_empty(),
        "Coinbase output should be spendable at blockheight {latest_height} \
        with {confirmations} confirmations since the coinbase tx was mined (at {h})\n \
        target_height {target_height:?} - coinbase_tx.mined_height {h} = {}",
        u32::from(target_height) - u32::from(h)
    );

    // Verify we can propose shielding the coinbase utxo
    let account = st.get_account().id();
    let _proposal = st
        .propose_shielding(
            &GreedyInputSelector::new(),
            &single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL),
            Zatoshis::from_u64(10000).unwrap(),
            &[t_addr],
            account,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::AllTransparentOutputs,
        )
        .unwrap();
}

#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
/// Tests that `CoinbaseFilter::CoinbaseOnly` excludes non-coinbase outputs and
/// `CoinbaseFilter::NonCoinbaseOnly` excludes coinbase outputs from UTXO selection and
/// shielding proposals, and that `CoinbaseOnly` still allows proposing shielding when only
/// coinbase UTXOs are available.
pub fn coinbase_only_filtering<T: ShieldedPoolTester, Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use std::collections::BTreeSet;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let account = st.get_account().id();

    // 1. Create a coinbase UTXO (50,000 zats)
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_height = st.sapling_activation_height();
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(coinbase_height),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    // The coinbase transaction has a single transparent output at index 0.
    let coinbase_outpoint = OutPoint::new(coinbase_tx.txid().into(), 0);
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();

    // 2. Create a non-coinbase UTXO (60,000 zats)
    // Inserted via put_received_transparent_utxo, which sets tx_index = NULL.
    // NULL tx_index is treated as non-coinbase by the filter.
    let non_coinbase_value = Zatoshis::const_from_u64(60000);
    let non_coinbase_outpoint = OutPoint::fake();
    let utxo = WalletTransparentOutput::from_parts(
        non_coinbase_outpoint.clone(),
        TxOut::new(non_coinbase_value, t_addr.script().into()),
        Some(h),
        Some(account),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    st.wallet_mut()
        .put_received_transparent_utxo(&utxo)
        .unwrap();

    // 3. Wait for coinbase maturity (100 confirmations)
    st.add_empty_blocks(100);
    let target_height = TargetHeight::from(h + 101);

    // 4. CoinbaseFilter::All returns both UTXOs
    let all_utxos = st
        .wallet()
        .get_spendable_transparent_outputs(
            &t_addr,
            target_height,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::AllTransparentOutputs,
        )
        .unwrap();
    assert_eq!(
        all_utxos.len(),
        2,
        "Expected both coinbase and non-coinbase UTXOs with CoinbaseFilter::AllTransparentOutputs"
    );
    let all_utxos_value = all_utxos
        .iter()
        .map(|utxo| utxo.value().into_u64())
        .sum::<u64>();
    assert_eq!(
        all_utxos_value,
        coinbase_value.into_u64() + non_coinbase_value.into_u64(),
        "Unexpected total UTXO value when querying for all transparent transactions"
    );

    // 5. CoinbaseFilter::CoinbaseOnly returns only the coinbase UTXO
    let coinbase_utxos = st
        .wallet()
        .get_spendable_transparent_outputs(
            &t_addr,
            target_height,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::CoinbaseOnly,
        )
        .unwrap();
    assert_eq!(
        coinbase_utxos.len(),
        1,
        "Expected only the coinbase UTXO with CoinbaseFilter::CoinbaseOnly"
    );
    assert_eq!(coinbase_utxos[0].value(), coinbase_value);
    assert_eq!(coinbase_utxos[0].outpoint(), &coinbase_outpoint);

    // 5b. CoinbaseFilter::NonCoinbaseOnly returns only the non-coinbase UTXO.
    // The non-coinbase UTXO was inserted with tx_index = NULL, which the filter treats as
    // non-coinbase, so it must be included here.
    let non_coinbase_utxos = st
        .wallet()
        .get_spendable_transparent_outputs(
            &t_addr,
            target_height,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::NonCoinbaseOnly,
        )
        .unwrap();
    assert_eq!(
        non_coinbase_utxos.len(),
        1,
        "Expected only the non-coinbase UTXO with CoinbaseFilter::NonCoinbaseOnly"
    );
    assert_eq!(non_coinbase_utxos[0].value(), non_coinbase_value);
    assert_eq!(non_coinbase_utxos[0].outpoint(), &non_coinbase_outpoint);

    // 6. propose_shielding with CoinbaseOnly includes only the coinbase input
    let proposal = st
        .propose_shielding(
            &GreedyInputSelector::new(),
            &single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL),
            Zatoshis::from_u64(10000).unwrap(),
            &[t_addr],
            account,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::CoinbaseOnly,
        )
        .unwrap();
    let coinbase_inputs = proposal.steps().first().transparent_inputs();
    assert_eq!(
        coinbase_inputs.len(),
        1,
        "CoinbaseOnly proposal should contain exactly one transparent input"
    );
    assert_eq!(coinbase_inputs[0].value(), coinbase_value);
    assert_eq!(coinbase_inputs[0].outpoint(), &coinbase_outpoint);

    // 6b. propose_shielding with NonCoinbaseOnly includes only the non-coinbase input
    let proposal_non_coinbase = st
        .propose_shielding(
            &GreedyInputSelector::new(),
            &single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL),
            Zatoshis::from_u64(10000).unwrap(),
            &[t_addr],
            account,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::NonCoinbaseOnly,
        )
        .unwrap();
    let non_coinbase_inputs = proposal_non_coinbase.steps().first().transparent_inputs();
    assert_eq!(
        non_coinbase_inputs.len(),
        1,
        "NonCoinbaseOnly proposal should contain exactly one transparent input"
    );
    assert_eq!(non_coinbase_inputs[0].value(), non_coinbase_value);
    assert_eq!(non_coinbase_inputs[0].outpoint(), &non_coinbase_outpoint);

    // 7. propose_shielding with All includes both inputs
    let proposal_all = st
        .propose_shielding(
            &GreedyInputSelector::new(),
            &single_output_change_strategy(StandardFeeRule::Zip317, None, T::SHIELDED_PROTOCOL),
            Zatoshis::from_u64(10000).unwrap(),
            &[t_addr],
            account,
            ConfirmationsPolicy::default(),
            CoinbaseFilter::AllTransparentOutputs,
        )
        .unwrap();
    let all_inputs = proposal_all.steps().first().transparent_inputs();
    assert_eq!(
        all_inputs.len(),
        2,
        "All proposal should contain both transparent inputs"
    );
    // Input ordering is not guaranteed, so compare the set of outpoints.
    let all_outpoints = all_inputs
        .iter()
        .map(|input| input.outpoint().clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        all_outpoints,
        BTreeSet::from([coinbase_outpoint, non_coinbase_outpoint]),
        "All proposal should contain both the coinbase and non-coinbase outpoints"
    );
}

/// Verifies that `propose_shielding_coinbase` with a shielded destination produces
/// a proposal containing a single ZIP-321 payment to the supplied address for the
/// full available value (input total minus fee), with no change.
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_shielding_coinbase_succeeds<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    // Coinbase outputs require 100 confirmations.
    st.add_empty_blocks(100);

    // The destination is a shielded address controlled by a separate spending key
    // (i.e. potentially in a different wallet).
    let to_extsk = T::sk(&[0xab; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address.clone(),
            None,
            None,
        )
        .expect("propose_shielding_coinbase with a shielded destination should succeed");

    let step = proposal.steps().first();
    assert_eq!(
        step.transparent_inputs().len(),
        1,
        "Expected exactly one coinbase transparent input"
    );
    let payments = step.transaction_request().payments();
    assert_eq!(
        payments.len(),
        1,
        "Expected exactly one payment in proposal"
    );
    let (idx, payment) = payments.iter().next().unwrap();
    assert_eq!(*idx, 0);
    assert_eq!(payment.recipient_address(), &to_address);
    assert_eq!(
        step.balance().proposed_change().len(),
        0,
        "Coinbase shielding must produce no change"
    );

    let fee = step.balance().fee_required();
    let payment_amount = payment.amount().expect("payment must have an amount");
    assert_eq!(
        (payment_amount + fee).unwrap(),
        coinbase_value,
        "payment_amount + fee must equal coinbase input value"
    );
}

/// A shielding proposal spends no shielded notes, so its step defers the choice of anchor and
/// serializes it as the zero sentinel. A proposal produced by an older library version also omits
/// the confirmations policy field entirely. Decoding such a proposal must interpret the zero anchor
/// as deferred and fall back to the default confirmations policy, and building it must resolve the
/// anchor from that policy rather than failing with `AnchorNotFound(0)`.
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn legacy_proposal_without_confirmations_policy_builds<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    // Coinbase outputs require 100 confirmations.
    st.add_empty_blocks(100);

    let to_extsk = T::sk(&[0xab; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address,
            None,
            None,
        )
        .expect("coinbase shielding proposal should succeed");

    // The shielding step spends no shielded notes, so it carries no explicit anchor.
    assert_eq!(
        proposal.steps().first().anchor_height(),
        None,
        "an input-less shielding step must defer its anchor",
    );

    // Serialize, then downgrade to a proposal as an older version would have produced it: drop the
    // confirmations policy field, and confirm the deferred anchor encodes as the zero sentinel.
    let mut proto = crate::proto::proposal::Proposal::from_standard_proposal(&proposal);
    proto.confirmations_policy = None;
    assert_eq!(
        proto.steps[0].anchor_height, 0,
        "a deferred anchor must encode as the zero sentinel",
    );

    // Decoding must fall back to the default policy and keep the anchor deferred.
    let decoded = proto
        .try_into_standard_proposal(&params, st.wallet())
        .expect("a legacy proposal without a confirmations policy must decode");
    assert_eq!(
        decoded.confirmations_policy(),
        ConfirmationsPolicy::default(),
        "a missing confirmations policy must decode as the default",
    );
    assert_eq!(decoded.steps().first().anchor_height(), None);

    // Building must resolve the deferred anchor from the default policy and target height rather
    // than looking up a checkpoint at height zero.
    let usk = st.get_account().usk().clone();
    st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        &usk,
        OvkPolicy::Sender,
        &decoded,
    )
    .expect("a legacy input-less proposal must build via the resolved anchor");
}

/// Verifies that `propose_shielding_coinbase` rejects a transparent destination
/// with [`ProposalError::ShieldingRequiresShieldedRecipient`].
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_shielding_coinbase_transparent_recipient_rejected<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    st.add_empty_blocks(100);

    let bad_to_address = Address::Transparent(TransparentAddress::PublicKeyHash([7; 20]))
        .to_zcash_address(st.network());

    let result = st.propose_shielding_coinbase(
        &GreedyInputSelector::new(),
        &StandardFeeRule::Zip317,
        Zatoshis::ZERO,
        &[t_addr],
        bad_to_address,
        None,
        None,
    );

    assert_matches!(
        result,
        Err(Error::Proposal(
            ProposalError::ShieldingRequiresShieldedRecipient
        ))
    );
}

/// Verifies that `propose_shielding_coinbase` propagates the supplied `memo`
/// into the resulting payment's memo field.
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_shielding_coinbase_with_memo_succeeds<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    st.add_empty_blocks(100);

    let to_extsk = T::sk(&[0xcd; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let memo_text = "shielding to external wallet";
    let memo_bytes = MemoBytes::from(memo_text.parse::<Memo>().unwrap());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address,
            Some(memo_bytes.clone()),
            None,
        )
        .expect("propose_shielding_coinbase with memo should succeed");

    let payments = proposal.steps().first().transaction_request().payments();
    let (_, payment) = payments.iter().next().unwrap();
    assert_eq!(payment.memo(), Some(&memo_bytes));
}

/// Verifies that `propose_shielding_coinbase` with `limit = Some(n)` selects at
/// most `n` UTXOs, preferring the highest-value coinbase outputs.
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_shielding_coinbase_with_limit_truncates_inputs<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();

    // Mine three coinbase transactions to the same recipient at successive heights,
    // with distinct values so we can verify the highest-value-first selection.
    let values = [
        Zatoshis::const_from_u64(30000),
        Zatoshis::const_from_u64(70000),
        Zatoshis::const_from_u64(50000),
    ];
    let mut first_h = None;
    for v in values {
        let coinbase_height = if let Some(h) = first_h {
            h + values.len() as u32 // arbitrary; only first_h matters for maturity
        } else {
            st.sapling_activation_height()
        };
        let build = build_transparent_coinbase_tx(
            st.network(),
            TargetHeight::from(coinbase_height),
            v,
            t_addr,
            None,
        );
        let tx = build.transaction();
        let (h, _) = st.generate_next_block_from_tx(0, tx);
        st.scan_cached_blocks(h, 1);
        let params = *st.network();
        decrypt_and_store_transaction(&params, st.wallet_mut(), tx, Some(h)).unwrap();
        if first_h.is_none() {
            first_h = Some(h);
        }
    }
    // Mature all three.
    st.add_empty_blocks(100);

    let to_extsk = T::sk(&[0x55; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address,
            None,
            Some(2),
        )
        .expect("propose_shielding_coinbase with limit=Some(2) should succeed");

    let inputs = proposal.steps().first().transparent_inputs();
    assert_eq!(
        inputs.len(),
        2,
        "limit=Some(2) should select exactly 2 inputs"
    );

    // The two highest-value coinbase UTXOs are 70000 and 50000.
    let mut selected_values: Vec<u64> = inputs.iter().map(|i| i.value().into_u64()).collect();
    selected_values.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(selected_values, vec![70000, 50000]);
}

/// Verifies that `propose_shielding_coinbase` with `limit = Some(0)` selects no
/// inputs, returning [`InputSelectorError::InsufficientFunds`].
///
/// [`InputSelectorError::InsufficientFunds`]: crate::data_api::wallet::input_selection::InputSelectorError::InsufficientFunds
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_shielding_coinbase_with_zero_limit_insufficient_funds<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let (t_addr, _) = st.get_account().usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    st.add_empty_blocks(100);

    let to_extsk = T::sk(&[0x66; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let shielding_threshold = Zatoshis::const_from_u64(10000);
    let result = st.propose_shielding_coinbase(
        &GreedyInputSelector::new(),
        &StandardFeeRule::Zip317,
        shielding_threshold,
        &[t_addr],
        to_address,
        None,
        Some(0),
    );

    // With no inputs selected, `payment_amount = input_total - fee` underflows
    // (input_total = 0, fee > 0), producing `Error::InsufficientFunds` with
    // `available: 0, required: fee`.
    assert_matches!(result, Err(Error::InsufficientFunds { .. }));
}

/// Regression test for the propose-fee/build-fee mismatch fixed in #2376.
///
/// Both `sapling::builder::BundleType::DEFAULT` and
/// `orchard::builder::BundleType::DEFAULT` pad up to a minimum of 2
/// outputs/actions (`MIN_SHIELDED_OUTPUTS` / `MIN_ACTIONS`). Before the fix,
/// `propose_shielding_coinbase` hardcoded `(1, 0)` / `(0, 1)` when asking the
/// fee rule what fee to charge, so the proposal underestimated the fee by
/// exactly one ZIP-317 marginal unit (5000 zat). The proposal succeeded, but
/// `create_proposed_transactions` then failed at build time with
/// `Insufficient funds for transaction construction; need an additional ZatBalance(5000) zatoshis`.
///
/// This test verifies the propose-and-build round trip succeeds for both
/// Sapling and Orchard destinations (parameterized by `T`).
#[cfg(all(feature = "pczt", feature = "transparent-inputs"))]
pub fn propose_and_build_shielding_coinbase_succeeds<T: ShieldedPoolTester, Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use zcash_protocol::consensus::COINBASE_MATURITY_BLOCKS;

    let mut st = TestDsl::with_sapling_birthday_account(ds_factory, cache).build::<T>();
    let account = st.get_account();
    let (t_addr, _) = account.usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(50000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    // Coinbase outputs require 100 confirmations.
    st.add_empty_blocks(COINBASE_MATURITY_BLOCKS as usize);

    // The destination is a shielded address controlled by a separate spending key.
    let to_extsk = T::sk(&[0xcd; 32]);
    let to_address = T::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address,
            None,
            None,
        )
        .expect("propose_shielding_coinbase should succeed");

    // Prior to #2376 this would fail at build time with `Insufficient funds for transaction
    // construction; need an additional ZatBalance(5000) zatoshis` because the proposal-stage fee
    // was computed assuming N output/action slots but the builder materializes N+1 (after `MIN_*`
    // padding).
    let build_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(
        &build_result,
        Ok(txids) if txids.len() == 1,
        "create_proposed_transactions must succeed for proposal {:?}",
        proposal,
    );
}

/// Verifies that once Ironwood is active, `propose_shielding_coinbase` resolves a destination
/// with an Orchard receiver to the Ironwood pool — the payment is delivered to the Orchard
/// receiver via the Ironwood bundle — and that the proposed transaction builds.
#[cfg(all(feature = "orchard", feature = "pczt", feature = "transparent-inputs"))]
pub fn shielding_coinbase_to_orchard_receiver_delivers_via_ironwood<Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
    <<Dsf as DataStoreFactory>::DataStore as WalletWrite>::UtxoRef: std::fmt::Debug,
{
    use super::orchard::OrchardPoolTester;
    use zcash_protocol::consensus::COINBASE_MATURITY_BLOCKS;

    // A network on which Ironwood (NU6.3) is active from the Sapling activation height.
    let ironwood_active_network = {
        let activation = BlockHeight::from_u32(100_000);
        LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        }
    };

    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_network(ironwood_active_network)
            .with_data_store_factory(ds_factory)
            .with_block_cache(cache)
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();
    let account = st.get_account();
    let (t_addr, _) = account.usk().default_transparent_address();
    let coinbase_value = Zatoshis::const_from_u64(100000);
    let coinbase_build_result = build_transparent_coinbase_tx(
        st.network(),
        TargetHeight::from(st.sapling_activation_height()),
        coinbase_value,
        t_addr,
        None,
    );
    let coinbase_tx = coinbase_build_result.transaction();
    let (h, _) = st.generate_next_block_from_tx(0, coinbase_tx);
    st.scan_cached_blocks(h, 1);
    let params = *st.network();
    decrypt_and_store_transaction(&params, st.wallet_mut(), coinbase_tx, Some(h)).unwrap();
    // Coinbase outputs require 100 confirmations.
    st.add_empty_blocks(COINBASE_MATURITY_BLOCKS as usize);

    // The destination has an Orchard receiver controlled by a separate spending key.
    let to_extsk = OrchardPoolTester::sk(&[0xcd; 32]);
    let to_address =
        OrchardPoolTester::sk_default_address(&to_extsk).to_zcash_address(st.network());

    let proposal = st
        .propose_shielding_coinbase(
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &[t_addr],
            to_address,
            None,
            None,
        )
        .expect("propose_shielding_coinbase to an Orchard receiver should succeed post-NU6.3");

    // The Orchard-receiver payment is represented as an Ironwood-pool output, matching the
    // bundle the builder will deliver it through; an Orchard-pool payment would violate the
    // Orchard turnstile.
    assert_eq!(
        proposal.steps().head.payment_pools().get(&0),
        Some(&PoolType::IRONWOOD),
    );

    let build_result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
        account.usk(),
        OvkPolicy::Sender,
        &proposal,
    );
    assert_matches!(
        &build_result,
        Ok(txids) if txids.len() == 1,
        "create_proposed_transactions must succeed for proposal {:?}",
        proposal,
    );
}

/// After NU6.3 activation, a payment to an Orchard receiver must be delivered through the
/// Ironwood pool, which requires a version 6 transaction. Explicitly requesting a version 5
/// transaction — which has no Ironwood bundle — for such a payment must be rejected at proposal
/// time with [`ProposalError::OrchardReceiverRequiresIronwood`], rather than producing a proposal
/// that could only fail later at build time.
#[cfg(feature = "orchard")]
pub fn propose_v5_payment_to_orchard_receiver_is_rejected<Dsf>(
    ds_factory: Dsf,
    cache: impl TestCache,
) where
    Dsf: DataStoreFactory,
{
    use super::orchard::OrchardPoolTester;
    use crate::data_api::wallet::{input_selection::SpendPolicy, propose_transfer};
    use crate::proposal::ProposalError;
    use zcash_primitives::transaction::TxVersion;

    // A network on which Ironwood (NU6.3) is active from the Sapling activation height.
    let ironwood_active_network = {
        let activation = BlockHeight::from_u32(100_000);
        LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        }
    };

    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_network(ironwood_active_network)
            .with_data_store_factory(ds_factory)
            .with_block_cache(cache)
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();

    // Fund the wallet with a single spendable Orchard note.
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60_000));

    // The destination has an Orchard receiver controlled by a separate spending key.
    let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
    let to = OrchardPoolTester::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10_000),
    )])
    .unwrap();

    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let account = st.get_account();
    let network = *st.network();
    let result = propose_transfer::<_, _, _, _, Infallible>(
        st.wallet_mut(),
        &network,
        account.id(),
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::MIN,
        &SpendPolicy::default(),
        Some(TxVersion::V5),
    );

    assert_matches!(
        result,
        Err(Error::Proposal(
            ProposalError::OrchardReceiverRequiresIronwood(TxVersion::V5)
        ))
    );
}

/// PCZT construction supports the version 6 transaction format, including its Ironwood bundle.
/// After NU6.3 a payment to an Orchard receiver is delivered through the Ironwood pool, so
/// `create_pczt_from_proposal` realizes such a proposal as a version 6 PCZT that carries a
/// populated Ironwood bundle.
#[cfg(all(feature = "orchard", feature = "pczt"))]
pub fn create_pczt_supports_ironwood_output<Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
    <Dsf as DataStoreFactory>::AccountId: serde::Serialize,
{
    use super::orchard::OrchardPoolTester;

    // A network on which NU6.3 — the version 6 transaction format — is active from height 100_000.
    let ironwood_active_network = {
        let activation = BlockHeight::from_u32(100_000);
        LocalNetwork {
            nu6: Some(activation),
            nu6_1: Some(activation),
            nu6_2: Some(activation),
            nu6_3: Some(activation),
            ..TestBuilder::<(), ()>::DEFAULT_NETWORK
        }
    };

    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_network(ironwood_active_network)
            .with_data_store_factory(ds_factory)
            .with_block_cache(cache)
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();

    // Fund the wallet with a single spendable Orchard note.
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60_000));

    // The destination has an Orchard receiver controlled by a separate spending key; post-NU6.3 the
    // payment is routed through the Ironwood pool.
    let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
    let to = OrchardPoolTester::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10_000),
    )])
    .unwrap();

    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let account_id = st.get_account().id();
    let proposal = st
        .propose_transfer(
            account_id,
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::MIN,
        )
        .expect("proposal construction succeeds; the Orchard-receiver payment routes to Ironwood");

    // The payment routes to the Ironwood pool, so the resulting PCZT must carry an Ironwood bundle.
    assert_eq!(
        proposal.steps().head.payment_pools().get(&0),
        Some(&PoolType::IRONWOOD),
    );

    let pczt = st
        .create_pczt_from_proposal::<Infallible, _, Infallible>(
            account_id,
            OvkPolicy::Sender,
            &proposal,
            None,
        )
        .expect("an Ironwood-routed payment builds as a version 6 PCZT");

    // The PCZT is a version 6 transaction carrying a populated Ironwood bundle.
    assert_eq!(
        *pczt.global().tx_version(),
        zcash_protocol::constants::V6_TX_VERSION,
    );
    assert!(
        !pczt.ironwood().actions().is_empty(),
        "the PCZT carries an Ironwood bundle for the Ironwood-routed payment",
    );

    // The Ironwood output carries the wallet's recipient metadata (the only proprietary field set
    // on Ironwood outputs), confirming the bundle is populated during construction rather than left
    // as an empty shell.
    assert!(
        pczt.ironwood()
            .actions()
            .iter()
            .any(|action| !action.output().proprietary().is_empty()),
        "the Ironwood output carries recipient metadata",
    );
}

/// The transaction version requested at proposal time is recorded on the proposal and preserved
/// across serialization, so that transaction building honors it. A proposal serialized without a
/// version request (as older serializers produced) decodes with no requested version and falls
/// back to the target-height version at build time.
#[cfg(feature = "orchard")]
pub fn proposal_records_and_serializes_proposed_version<Dsf>(ds_factory: Dsf, cache: impl TestCache)
where
    Dsf: DataStoreFactory,
{
    use super::orchard::OrchardPoolTester;
    use crate::data_api::wallet::{input_selection::SpendPolicy, propose_transfer};
    use zcash_primitives::transaction::TxVersion;

    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_data_store_factory(ds_factory)
            .with_block_cache(cache)
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();

    // Fund the wallet with a single spendable Orchard note.
    st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60_000));

    let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
    let to = OrchardPoolTester::sk_default_address(&to_extsk);
    let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
        to.to_zcash_address(st.network()),
        Zatoshis::const_from_u64(10_000),
    )])
    .unwrap();

    let change_strategy = standard::SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
    );
    let input_selector = GreedyInputSelector::new();

    let account_id = st.get_account().id();
    let network = *st.network();
    // The test network's most recent upgrade is NU5, so version 5 is a valid explicit request.
    let proposal = propose_transfer::<_, _, _, _, Infallible>(
        st.wallet_mut(),
        &network,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::MIN,
        &SpendPolicy::default(),
        Some(TxVersion::V5),
    )
    .expect("proposal construction succeeds");

    // The requested version is recorded on the proposal.
    assert_eq!(proposal.proposed_version(), Some(TxVersion::V5));

    // ... and is preserved across a round-trip through the proposal's serialized (proto) form.
    let proto = crate::proto::proposal::Proposal::from_standard_proposal(&proposal);
    let decoded = proto
        .try_into_standard_proposal(&network, st.wallet())
        .expect("the serialized proposal decodes");
    assert_eq!(decoded.proposed_version(), Some(TxVersion::V5));

    // A proposal serialized without the field (as an older serializer produced) decodes with no
    // requested version.
    let mut legacy_proto = crate::proto::proposal::Proposal::from_standard_proposal(&proposal);
    legacy_proto.proposed_version = None;
    let decoded_legacy = legacy_proto
        .try_into_standard_proposal(&network, st.wallet())
        .expect("a legacy proposal without a requested version must decode");
    assert_eq!(decoded_legacy.proposed_version(), None);
}
