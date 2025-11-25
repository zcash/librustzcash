//! A convenient DSL for writing wallet tests.

use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use zcash_primitives::{block::BlockHash, transaction::fees::zip317};
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};

use crate::data_api::{
    Account, AccountBalance, WalletRead,
    chain::ScanSummary,
    testing::{
        AddressType, DataStoreFactory, FakeCompactOutput, TestAccount, TestBuilder, TestCache,
        TestFvk, TestState,
    },
    wallet::ConfirmationsPolicy,
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
    pub fn with_sapling_birthday_account(dsf: Dsf, tc: Cache) -> Self {
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
            state,
            _phantom: PhantomData,
        }
        .into()
    }
}

/// A proxy for `FakeCompactOutput` that allows test code to omit the `fvk` and
/// `address_type` fields, which can be derived from the `TestState` in most cases.
pub struct TestNoteConfig<T: ShieldedPoolTester> {
    /// The amount of the note.
    pub value: Zatoshis,
    /// Diversifiable full viewing key of the recipient.
    pub fvk: Option<T::Fvk>,
    /// Address type of the recipient.
    pub address_type: Option<AddressType>,
}

impl<T: ShieldedPoolTester> From<Zatoshis> for TestNoteConfig<T> {
    fn from(value: Zatoshis) -> Self {
        TestNoteConfig {
            value,
            fvk: None,
            address_type: None,
        }
    }
}

impl<T: ShieldedPoolTester> TestNoteConfig<T> {
    pub fn with_address_type(mut self, address_type: AddressType) -> Self {
        self.address_type = Some(address_type);
        self
    }

    pub fn with_fvk(mut self, fvk: T::Fvk) -> Self {
        self.fvk = Some(fvk);
        self
    }
}

pub struct AddFundsStepResult<T: ShieldedPoolTester, C: TestCache> {
    pub block_height: BlockHeight,
    pub insert_result: C::InsertResult,
    /// Empty when the step was to generate an empty block
    pub nullifiers: Vec<<T::Fvk as TestFvk>::Nullifier>,
}

/// The input and output of one "add funds" step.
pub struct AddFundsStep<T: ShieldedPoolTester, C: TestCache> {
    pub notes: Vec<TestNoteConfig<T>>,
    pub results: AddFundsStepResult<T, C>,
}

/// A collection of results from adding funds to a `TestState`.
pub struct AddFundsSummary<T: ShieldedPoolTester, C: TestCache> {
    pub steps: Vec<AddFundsStep<T, C>>,
    pub scan_summary: Option<ScanSummary>,
}

impl<T: ShieldedPoolTester, C: TestCache> Default for AddFundsSummary<T, C> {
    fn default() -> Self {
        Self {
            steps: Default::default(),
            scan_summary: None,
        }
    }
}

impl<T: ShieldedPoolTester, C: TestCache> AddFundsSummary<T, C> {
    /// Return the first block height.
    pub fn first_block_height(&self) -> Option<BlockHeight> {
        self.steps.first().map(|step| step.results.block_height)
    }

    /// Return the latest block height after generating the blocks
    /// that added funds.
    pub fn block_height(&self) -> Option<BlockHeight> {
        self.steps.last().map(|step| step.results.block_height)
    }
}

#[repr(transparent)]
pub struct TestScenario<T: ShieldedPoolTester, Cache, Dsf: DataStoreFactory> {
    /// The current scenario state.
    state: TestState<Cache, Dsf::DataStore, LocalNetwork>,
    _phantom: PhantomData<T>,
}

impl<T, C, D> Deref for TestScenario<T, C, D>
where
    T: ShieldedPoolTester,
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
    D: DataStoreFactory,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

/// Add funds scenarios.
impl<Cache, Dsf, T> TestScenario<T, Cache, Dsf>
where
    T: ShieldedPoolTester,
    Cache: TestCache,
    Dsf: DataStoreFactory,
{
    /// Return the current test account balance, if possible.
    ///
    /// Returns `None` when no account summary data is available, which is
    /// the case before the wallet has scanned any blocks.
    pub fn get_account_balance(
        &self,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Option<AccountBalance> {
        let account = self.get_account();
        let binding = self
            .wallet()
            .get_wallet_summary(confirmations_policy)
            .unwrap()?;
        let balance = binding.account_balances().get(&account.id())?;
        Some(*balance)
    }

    /// Adds funds from a single note from an address of the given type.
    ///
    /// Returns the current block height, cache insert result and test viewing key nullifier.
    ///
    /// This is shorthand for:
    /// ```rust,ignore
    /// {
    ///     let dfvk = T::test_account_fvk(&st);
    ///     let output@(h, _, _) = st.generate_next_block(&dfvk, address_type, zatoshis);
    ///     st.scan_cached_blocks(h, 1);
    ///     output
    /// }
    /// ```
    ///
    /// This also verifies that the test account contains the expected funds as
    /// part of the _total_, and that the funds are spendable with the minimum number
    /// of confirmations.
    pub fn add_a_single_note_checking_balance(
        &mut self,
        note: impl Into<TestNoteConfig<T>>,
    ) -> (
        BlockHeight,
        Cache::InsertResult,
        <T::Fvk as TestFvk>::Nullifier,
    ) {
        let mut summary = self.add_notes_checking_balance([[note]]);
        let res = summary.steps.pop().unwrap().results;
        (res.block_height, res.insert_result, res.nullifiers[0])
    }

    fn scanned_block_height(&self) -> BlockHeight {
        self.wallet()
            .block_max_scanned()
            .unwrap()
            .map(|meta| meta.block_height())
            .unwrap_or_else(|| BlockHeight::from_u32(0))
    }

    /// Generates `N` empty blocks.
    ///
    /// Returns the current block height.
    pub fn add_empty_blocks(&mut self, n: usize) -> BlockHeight {
        let mut out_height = self.scanned_block_height();
        for _ in 0..n {
            let (h, _) = self.generate_empty_block();
            out_height = h;
        }
        out_height
    }

    /// Returns the test account.
    pub fn get_account(&self) -> TestAccount<Dsf::Account> {
        self.test_account().expect("not configured").clone()
    }

    /// Creates a `FakeCompactOutput` from the given `TestNoteConfig`.
    fn make_fake_output(&self, note_config: &TestNoteConfig<T>) -> FakeCompactOutput<T::Fvk> {
        let TestNoteConfig {
            value,
            fvk,
            address_type,
        } = note_config;
        FakeCompactOutput::new(
            fvk.clone().unwrap_or_else(|| T::test_account_fvk(self)),
            address_type.unwrap_or(AddressType::DefaultExternal),
            *value,
        )
    }

    /// Add funds from multiple notes in one or more blocks, or generate empty blocks.
    ///
    /// This step also verifies that the test account contains the expected
    /// funds as part of the _total_. Keep in mind that these funds may not yet
    /// be _spendable_ due to the number of confirmations required.
    ///
    /// Returns a summary of steps.
    ///
    /// ## Parameters
    ///
    /// * `blocks` - A collection of "blocks", where each "block" is a collection of
    ///   "notes". More specifically, "notes" can be anything that can be converted
    ///   into a [`TestNoteConfig`]. This allows you to add multiple blocks that each
    ///   containing zero or more notes with one call to `add_notes`.
    ///
    /// ## Note
    /// Keep in mind:
    /// * Each block coalesces these notes into a single transaction.
    /// * Funds are added to the default test account.
    pub fn add_notes_checking_balance(
        &mut self,
        blocks: impl IntoIterator<Item = impl IntoIterator<Item = impl Into<TestNoteConfig<T>>>>,
    ) -> AddFundsSummary<T, Cache> {
        let mut from_height = None;
        let mut current_height = self.scanned_block_height();
        let mut limit = 0;
        let account = self.get_account();
        let starting_balance = self
            .get_account_balance(ConfirmationsPolicy::MIN)
            .map(|b| b.total())
            .unwrap_or(Zatoshis::ZERO);
        let mut expected_total = starting_balance;
        let mut summary = AddFundsSummary::default();
        for notes in blocks.into_iter() {
            // Collect the notes while also counting their value.
            let (fake_outputs, note_configs): (Vec<_>, Vec<_>) = notes
                .into_iter()
                .map(|into_note_config| {
                    let note_config = into_note_config.into();
                    if note_config.value > zip317::MARGINAL_FEE {
                        // Don't include uneconomic (dust) notes in the expected
                        // total, as the balance won't include them.
                        expected_total = (expected_total + note_config.value).unwrap();
                    }
                    (self.make_fake_output(&note_config), note_config)
                })
                .unzip();
            let step_result = if fake_outputs.is_empty() {
                let (h, r) = self.generate_empty_block();
                AddFundsStepResult {
                    block_height: h,
                    insert_result: r,
                    nullifiers: vec![],
                }
            } else {
                let (h, r, n) = self.generate_next_block_multi(&fake_outputs);
                AddFundsStepResult {
                    block_height: h,
                    insert_result: r,
                    nullifiers: n,
                }
            };
            current_height = step_result.block_height;
            if from_height.is_none() {
                from_height = Some(current_height);
            }
            summary.steps.push(AddFundsStep {
                notes: note_configs,
                results: step_result,
            });
            limit += 1;
        }
        if let Some(from_height) = from_height {
            summary.scan_summary = Some(self.scan_cached_blocks(from_height, limit));
        }

        // Do most of the assertions that we care about at the "add funds" callsites
        assert_eq!(
            self.get_total_balance(account.id()),
            expected_total,
            "Unexpected total balance"
        );
        assert_eq!(
            self.wallet()
                .block_max_scanned()
                .unwrap()
                .unwrap()
                .block_height(),
            current_height
        );
        assert_eq!(
            self.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
            expected_total
        );

        summary
    }
}
