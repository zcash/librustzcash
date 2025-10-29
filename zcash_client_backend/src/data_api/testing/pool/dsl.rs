//! A convenient DSL for writing wallet tests.

use std::{
    collections::VecDeque,
    marker::PhantomData,
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
    pub fn add_a_single_note_to(
        &mut self,
        address_type: AddressType,
        zatoshis: Zatoshis,
    ) -> BlockHeight {
        let dfvk = T::test_account_fvk(self);
        let (h, _, _) = self.generate_next_block(&dfvk, address_type, zatoshis);
        self.scan_cached_blocks(h, 1);
        h
    }

    /// Adds funds from a single note from a default external address.
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

    // pub fn add_notes_to(
    //     &mut self,
    //     address_type: AddressType,
    //     notes: impl IntoIterator<Item = Option<Zatoshis>>
    // )
}
