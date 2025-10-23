//! A convenient DSL for writing wallet tests.

use std::ops::{Deref, DerefMut};

use zcash_primitives::block::BlockHash;
use zcash_protocol::local_consensus::LocalNetwork;

use crate::data_api::{
    testing::{DataStoreFactory, TestBuilder, TestCache, TestState},
    WalletTest,
};

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

    /// Build the builder, wrapping the resulting [`TestState`] in a [`TestDsl`].
    pub fn build(self) -> TestDsl<TestState<Cache, Dsf::DataStore, LocalNetwork>> {
        self.map(TestBuilder::build)
    }
}

/// [`TestDsl`] provides convenience methods for common [`TestState`] operations.
impl<Cache, DataStore> TestDsl<TestState<Cache, DataStore, LocalNetwork>>
where
    DataStore: WalletTest,
    Cache: TestCache,
{
}
