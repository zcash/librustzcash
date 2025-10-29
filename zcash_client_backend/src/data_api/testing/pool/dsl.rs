//! A convenient DSL for writing wallet tests.

use std::{
    collections::VecDeque,
    ops::{Deref, DerefMut},
};

use subtle::ConditionallySelectable;
use zcash_primitives::block::BlockHash;
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};

use crate::data_api::{
    chain::ScanSummary,
    testing::{AddressType, DataStoreFactory, TestBuilder, TestCache, TestFvk, TestState},
    WalletCommitmentTrees, WalletRead, WalletTest, WalletWrite,
};

use super::ShieldedPoolTester;

/// A type-state wrapper struct that provides convenience methods.
pub struct TestDsl<T> {
    /// Either a `TestBuilder<Cache, DataStoreFactory>` or
    /// `TestState<Cache, DataStore, LocalNetwork>`.
    inner: T,
}

impl<T> Deref for TestDsl<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for TestDsl<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> From<T> for TestDsl<T> {
    fn from(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> TestDsl<T> {
    /// Perform a state transition that may change the inner type.
    pub fn map<X>(self, f: impl FnOnce(T) -> X) -> TestDsl<X> {
        f(self.inner).into()
    }
}

/// [`TestDsl`] provides convenience methods for common [`TestBuilder`] scenarios.
impl<Cache, Dsf> TestDsl<TestBuilder<Cache, Dsf>>
where
    Cache: TestCache,
    Dsf: DataStoreFactory,
{
    /// Equip the inner [`TestBuilder`] with the provided [`DataStoreFactory`]
    /// and [`TestCache`], as well as an account that has a birthday at Sapling
    /// activation.
    ///
    /// Shorthand for the following:
    /// ```rust,ignore
    /// let dsl: TestDsl<TestBuilder<_, _>> = TestBuilder::new()
    ///     .with_data_store_factory(dsf)
    ///     .with_block_cache(tc)
    ///     .with_account_from_sapling_activation(BlockHash([0; 32]))
    ///     .into();
    /// ```
    pub fn with_standard_sapling_account(dsf: Dsf, tc: Cache) -> Self {
        TestBuilder::new()
            .with_data_store_factory(dsf)
            .with_block_cache(tc)
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .into()
    }

    /// Build the builder, wrapping the resulting [`TestState`] in a [`TestDsl`] and [`TestScenario`].
    pub fn build<T: ShieldedPoolTester>(self) -> TestDsl<TestScenario<T, Cache, Dsf>> {
        let state = self.inner.build();
        TestScenario {
            steps: VecDeque::default(),
            state,
        }
        .into()
    }
}

/// Input parameters to run `TestState::generate_next_block`.
pub struct GenerateNextBlockInput<T: ShieldedPoolTester> {
    /// Diversified full viewing key, if specified.
    dfvk: Option<T::Fvk>,
    /// Type of address, if specified.
    address_type: AddressType,
    /// Value to add.
    value: Zatoshis,
}

/// Output of running `TestState::generate_next_block`.
pub struct GenerateNextBlockOutput<T: ShieldedPoolTester, Cache: TestCache> {
    current_block_height: BlockHeight,
    cache_insert_result: Cache::InsertResult,
    full_viewing_key_nullifier: <<T as ShieldedPoolTester>::Fvk as TestFvk>::Nullifier,
}

/// Output of running `TestState::generate_empty_block`.
pub struct GenerateEmptyBlockOutput<Cache: TestCache> {
    current_block_height: BlockHeight,
    cache_insert_result: Cache::InsertResult,
}

pub struct ScanCachedBlockInput {
    from_height: BlockHeight,
    limit: usize,
}

pub struct ScanCachedBlockOutput {
    scan_summary: ScanSummary,
}

/// An enumeration of all test scenario step inputs.
pub enum TestStepInput<T: ShieldedPoolTester> {
    GenerateNextBlock(GenerateNextBlockInput<T>),
    GenerateEmptyBlock,
    ScanCachedBlock(ScanCachedBlockInput),
}

// TODO(schell): block generation obfuscates some meaning
// * called to put funds in the wallet
// * called to advance the chain without giving our wallet notes
// * we want a higher-level semantic blocks

/// An enumeration of all test scenario step outputs.
pub enum TestStepOutput<T: ShieldedPoolTester, Cache: TestCache> {
    GenerateNextBlock(GenerateNextBlockOutput<T, Cache>),
    GenerateEmptyBlock(GenerateEmptyBlockOutput<Cache>),
    ScanCachedBlock(ScanCachedBlockOutput),
}

/// A collection of a test step name, input, and possible output.
pub struct TestStep<T: ShieldedPoolTester, Cache: TestCache> {
    name: Option<String>,
    input: TestStepInput<T>,
    output: Option<TestStepOutput<T, Cache>>,
}

pub struct TestScenario<T: ShieldedPoolTester, Cache: TestCache, Dsf: DataStoreFactory> {
    /// All the queued test steps.
    steps: VecDeque<TestStep<T, Cache>>,
    /// The current scenario state.
    state: TestState<Cache, Dsf::DataStore, LocalNetwork>,
}

impl<T, C, D> Deref for TestScenario<T, C, D>
where
    T: ShieldedPoolTester,
    C: TestCache,
    D: DataStoreFactory,
{
    type Target = TestState<C, D::DataStore, LocalNetwork>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<T, C, D> DerefMut for TestScenario<T, C, D>
where
    T: ShieldedPoolTester,
    C: TestCache,
    D: DataStoreFactory,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

/// Common basic operations.
impl<Cache, Dsf, T> TestScenario<T, Cache, Dsf>
where
    T: ShieldedPoolTester,
    Cache: TestCache,
    Dsf: DataStoreFactory,
{
    /// Add a named step.
    pub fn add_step(&mut self, name: impl AsRef<str>, input: TestStepInput<T>) -> &mut Self {
        let name = if name.as_ref().is_empty() {
            None
        } else {
            Some(name.as_ref().to_owned())
        };
        self.steps.push_back(TestStep {
            name,
            input,
            output: None,
        });
        self
    }

    /// Run the scenario, generating test step outputs.
    pub fn run(&mut self) {
        let TestScenario { steps, state: st } = self;
        for TestStep {
            name,
            input,
            output,
        } in steps.iter_mut()
        {
            *output = Some(match &input {
                TestStepInput::GenerateNextBlock(gen) => {
                    let dfvk = gen.dfvk.clone().unwrap_or(T::test_account_fvk(st));
                    let (current_block_height, cache_insert_result, full_viewing_key_nullifier) =
                        st.generate_next_block(&dfvk, gen.address_type, gen.value);
                    TestStepOutput::GenerateNextBlock(GenerateNextBlockOutput {
                        current_block_height,
                        cache_insert_result,
                        full_viewing_key_nullifier,
                    })
                }
                TestStepInput::GenerateEmptyBlock => {
                    let (current_block_height, cache_insert_result) = st.generate_empty_block();
                    TestStepOutput::GenerateEmptyBlock(GenerateEmptyBlockOutput {
                        current_block_height,
                        cache_insert_result,
                    })
                }
                TestStepInput::ScanCachedBlock(step) => {
                    let scan_summary = st.scan_cached_blocks(step.from_height, step.limit);
                    TestStepOutput::ScanCachedBlock(ScanCachedBlockOutput { scan_summary })
                }
            });
        }
    }
}

/// Add funds scenarios.
impl<Cache, Dsf, T> TestScenario<T, Cache, Dsf>
where
    T: ShieldedPoolTester,
    Cache: TestCache,
    Dsf: DataStoreFactory,
{
    /// Adds funds from a single note from an address of the given type.
    ///
    /// This is shorthand for:
    /// ```rust,ignore
    /// let dfvk = T::test_account_fvk(&st);
    /// let (h, _, _) = st.generate_next_block(&dfvk, address_type, zatoshis);
    /// st.scan_cached_blocks(h, 1);
    /// ```
    pub fn add_a_single_note_to(
        &mut self,
        address_type: AddressType,
        zatoshis: Zatoshis,
    ) -> &mut Self {
        let dfvk = T::test_account_fvk(self);
        let group = format!("add a single note of {zatoshis:?} to address {address_type:?}");
        self.add_step(
            format!("{group} - generate a block"),
            TestStepInput::GenerateNextBlock(GenerateNextBlockInput {
                dfvk: Some(dfvk),
                address_type,
                value: zatoshis,
            }),
        );
        self.add_step(
            format!("{group} - scan cached block"),
            TestStepInput::ScanCachedBlock(ScanCachedBlockInput {
                from_height: None,
                limit: 1,
            }),
        );
        self
    }

    /// Adds funds from a single note from a default external address.
    ///
    /// This is shorthand for:
    /// ```rust,ignore
    /// let dfvk = T::test_account_fvk(&st);
    /// let (h, _, _) = st.generate_next_block(&dfvk, AdressType::DefaultExternal, zatoshis);
    /// st.scan_cached_blocks(h, 1);
    /// ```
    pub fn add_a_single_note_of(&mut self, zatoshis: Zatoshis) -> &mut Self {
        self.add_a_single_note_to(AddressType::DefaultExternal, zatoshis)
    }

    /// Generates `N` empty blocks.
    pub fn with_empty_blocks(mut self, n: usize) -> Self {
        let group = format!("generate {n} empty blocks");
        for i in 0..n {
            self.add_step(
                format!("{group} - block {}", i + 1),
                TestStepInput::GenerateEmptyBlock,
            );
        }
        self
    }

    /// Fold over all the "add funds" steps.
    ///
    /// Returns the starting block hight and the current block height after adding funds.
    pub fn generate(&mut self) -> std::ops::RangeInclusive<(BlockHeight, BlockHeight)> {}

    /// Consume the funds builder, returning the range of block heights scanned and
    /// a summary of the scan.
    pub fn scan(mut self, limit: usize) -> ((BlockHeight, BlockHeight), ScanSummary) {
        let (from_height, current_height) = self.generate();
        let summary = self.scenario.scan_cached_blocks(from_height, limit);
        ((from_height, current_height), summary)
    }

    // /// Consume the funds builder, scanning cached blocks from the given height and
    // /// returning the current block height and a summary of the scan.
    // pub fn scan_from(mut self, from_height: BlockHeight, limit: usize) -> ScanSummary {
    //     let _h = self.generate();
    //     self.dsl.scan_cached_blocks(from_height, limit)
    // }
}

/// [`TestDsl`] provides convenience methods for common [`TestState`] operations.
impl<Cache, DataStore> TestDsl<TestState<Cache, DataStore, LocalNetwork>>
where
    DataStore: WalletTest,
    Cache: TestCache,
{
    pub fn add_funds<T: ShieldedPoolTester>(&mut self) -> FundsBuilder<'_, Cache, DataStore, T> {
        FundsBuilder {
            scenario: self,
            steps: vec![],
        }
    }
}
