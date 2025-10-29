//! A convenient DSL for writing wallet tests.

use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use zcash_primitives::block::BlockHash;
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, value::Zatoshis};

use crate::data_api::{
    testing::{AddressType, DataStoreFactory, TestAccount, TestBuilder, TestCache, TestState},
    wallet::ConfirmationsPolicy,
    Account, AccountBalance, WalletRead,
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
            state,
            _phantom: PhantomData,
        }
        .into()
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
        Some(balance.clone())
    }

    /// Adds funds from a single note from an address of the given type.
    ///
    /// Returns the current block height.
    ///
    /// This is shorthand for:
    /// ```rust,ignore
    /// {
    ///     let dfvk = T::test_account_fvk(&st);
    ///     let (h, _, _) = st.generate_next_block(&dfvk, address_type, zatoshis);
    ///     st.scan_cached_blocks(h, 1);
    ///     h
    /// }
    /// ```
    ///
    /// This also verifies that the test account contains the expected funds as
    /// part of the _total_, and that the funds are spendable with the minimum number
    /// of confirmations.
    pub fn add_a_single_note_to(
        &mut self,
        address_type: AddressType,
        zatoshis: Zatoshis,
    ) -> BlockHeight {
        let starting_balance = self
            .get_account_balance(ConfirmationsPolicy::MIN)
            .map(|balance| balance.total())
            .unwrap_or(Zatoshis::ZERO);
        let ending_balance =
            (starting_balance + zatoshis).expect("adding funds would overflow zatoshis");
        let dfvk = T::test_account_fvk(self);
        let (h, _, _) = self.generate_next_block(&dfvk, address_type, zatoshis);
        self.scan_cached_blocks(h, 1);

        // Spendable balance matches total balance at 1 confirmation.
        let account = self.test_account().unwrap().clone();
        assert_eq!(self.get_total_balance(account.id()), ending_balance);
        assert_eq!(
            self.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
            ending_balance
        );

        h
    }

    /// Adds funds from a single note to a default external address.
    ///
    /// Returns the current block height.
    ///
    /// This is shorthand for:
    /// ```rust,ignore
    /// {
    ///     let dfvk = T::test_account_fvk(&st);
    ///     let (h, _, _) = st.generate_next_block(&dfvk, AdressType::DefaultExternal, zatoshis);
    ///     st.scan_cached_blocks(h, 1);
    ///     h
    /// }
    /// ```
    ///
    /// This also verifies that the test account contains the expected funds as
    /// part of the _total_, and that the funds are spendable with the minimum number
    /// of confirmations.
    pub fn add_a_single_note_of(&mut self, zatoshis: Zatoshis) -> BlockHeight {
        self.add_a_single_note_to(AddressType::DefaultExternal, zatoshis)
    }

    /// Generates `N` empty blocks.
    ///
    /// Returns the current block height.
    pub fn add_empty_blocks(&mut self, n: usize) -> BlockHeight {
        let mut out_height = BlockHeight::from_u32(0);
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

    /// Add funds from multiple notes, or generate empty blocks.
    ///
    /// This step also verifies that the test account contains the expected
    /// funds as part of the _total_. Keep in mind that these funds may not yet
    /// be _spendable_ due to the number confirmations required.
    pub fn add_notes_to(
        &mut self,
        address_type: AddressType,
        notes: impl IntoIterator<Item = Option<Zatoshis>>,
    ) -> BlockHeight {
        let dfvk = T::test_account_fvk(self);
        let mut from_height = None;
        let mut current_height = BlockHeight::from_u32(0);
        let mut limit = 0;
        let account = self.get_account();
        let starting_balance = self
            .get_account_balance(ConfirmationsPolicy::MIN)
            .map(|b| b.total())
            .unwrap_or(Zatoshis::ZERO);
        let mut expected_total = starting_balance;
        for maybe_note in notes.into_iter() {
            if let Some(zatoshis) = maybe_note {
                expected_total = (expected_total + zatoshis).unwrap();
                let (h, _, _) = self.generate_next_block(&dfvk, address_type, zatoshis);
                current_height = h;
                if from_height.is_none() {
                    from_height = Some(current_height);
                }
            } else {
                self.generate_empty_block();
            }
            limit += 1;
        }
        if let Some(from_height) = from_height {
            self.scan_cached_blocks(from_height, limit);
        }

        assert_eq!(self.get_total_balance(account.id()), expected_total);
        assert_eq!(
            self.wallet()
                .block_max_scanned()
                .unwrap()
                .unwrap()
                .block_height(),
            current_height
        );

        current_height
    }

    /// Add funds from multiple notes, or generate empty blocks.
    pub fn add_notes(&mut self, notes: impl IntoIterator<Item = Option<Zatoshis>>) -> BlockHeight {
        self.add_notes_to(AddressType::DefaultExternal, notes)
    }
}
