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
    // TODO(schell): we shouldn't need to pass around Fvk as T has it on T::Fvk.
    pub fn build<T: ShieldedPoolTester>(self) -> TestDsl<TestScenario<T, Cache, Dsf, T::Fvk>> {
        let state = self.inner.build();
        TestScenario {
            steps: TestSteps::default(),
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
    full_viewing_key_nullifiers: Vec<<<T as ShieldedPoolTester>::Fvk as TestFvk>::Nullifier>,
}

/// Output of running `TestState::generate_empty_block`.
pub struct GenerateEmptyBlockOutput<Cache: TestCache> {
    current_block_height: BlockHeight,
    cache_insert_result: Cache::InsertResult,
}

pub struct ScanCachedBlockStep {
    from_height: Option<BlockHeight>,
    limit: usize,
}

/// An enumeration of all test scenario step inputs.
pub enum TestStepInput<T: ShieldedPoolTester> {
    GenerateNextBlock(GenerateNextBlockInput<T>),
    GenerateEmptyBlock,
}

// TODO(schell): block generation obfuscates some meaning
// * called to put funds in the wallet
// * called to advance the chain without giving our wallet notes
// * we want a higher-level semantic blocks

/// An enumeration of all test scenario step outputs.
pub enum TestStepOutput<T: ShieldedPoolTester, Cache: TestCache> {
    GenerateNextBlock(GenerateNextBlockOutput<T, Cache>),
    GenerateEmptyBlock(GenerateEmptyBlockOutput<Cache>),
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

impl<T, C, D> TestScenario<T, C, D>
where
    T: ShieldedPoolTester,
    C: TestCache,
    D: DataStoreFactory,
{
    /// Add a possibly named
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
        self.add_step(
            None,
            TestStepInput::GenerateNextBlock(GenerateNextBlockInput {
                dfvk: Some(dfvk),
                address_type,
                value: zatoshis,
            }),
        );
        // self.steps
        //     .push(FundsBuilderStep::ScanCachedBlocks(ScanCachedBlockStep {
        //         name: "single note block scan",
        //         from_height: None,
        //         limit: 1,
        //     }));
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
        self.steps
            .extend(std::iter::repeat_with(|| FundsBuilderStep::GenerateEmptyBlock).take(n));
        self
    }

    /// Fold over all the "add funds" steps.
    ///
    /// Returns the starting block hight and the current block height after adding funds.
    pub fn generate(&mut self) -> std::ops::RangeInclusive<(BlockHeight, BlockHeight)> {
        let mut height_range = BlockHeight::from_u32(0)..=BlockHeight::from_u32(0);
        for step in self.steps.drain(..) {
            match step {
                FundsBuilderStep::GenerateNextBlock(gen) => {
                    let dfvk = gen.dfvk.unwrap_or(T::test_account_fvk(self.scenario));
                    let (h, _, _) =
                        self.scenario
                            .generate_next_block(&dfvk, gen.address_type, gen.value);
                    if *height_range.start() < h {
                        height_range = h..=*height_range.end();
                    }
                }
                FundsBuilderStep::GenerateEmptyBlock => {
                    let (h, _) = self.scenario.generate_empty_block();
                    height_range = *height_range.start()..=h;
                } // FundsBuilderStep::ScanCachedBlocks(step) => {
                  //     if let Some(h) = step.from_height {
                  //         // Use the explicit height.
                  //         // TODO(schell): determine if we actually do this in practice
                  //         height = Some(h);
                  //     }
                  //     let h = height.as_ref().expect(&format!(
                  //         "Test step '{name}' missing `scan_cached_blocks` `from_height`,\
                  //          it's possible we missed a step",
                  //         name = step.name
                  //     ));
                  //     dsl.scan_cached_blocks(*h, step.limit);
                  // }
            }
        }

        (
            from_height.unwrap_or(BlockHeight::from_u32(0)),
            current_height,
        )
    }

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
