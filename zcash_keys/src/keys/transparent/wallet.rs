use crate::address::Address;
use core::hash::Hash;
use std::vec::Vec;
use transparent::{
    address::TransparentAddress,
    keys::{NonHardenedChildIndex, TransparentKeyScope},
};
use zcash_protocol::{TxId, consensus::BlockHeight};

use super::gap_limits::GapLimits;

#[cfg(feature = "transparent-inputs")]
pub trait GapLimitsWalletAccess {
    /// The type of query error
    type Error;

    /// A wallet-internal account identifier
    type AccountRef: Copy + Eq + Hash;

    /// Returns the transparent address index at the start of the first gap of at least `gap_limit`
    /// indices in the given account, considering only addresses derived for the specified key scope.
    ///
    /// Returns `Ok(None)` if the gap would start at an index greater than the maximum valid
    /// non-hardened transparent child index.
    fn find_gap_start(
        &self,
        account_ref: Self::AccountRef,
        key_scope: TransparentKeyScope,
        gap_limit: u32,
    ) -> Result<Option<NonHardenedChildIndex>, Self::Error>;

    fn store_address_range(
        &self,
        account_id: Self::AccountRef,
        key_scope: TransparentKeyScope,
        list: Vec<(Address, TransparentAddress, NonHardenedChildIndex)>,
    ) -> Result<(), Self::Error>;

    fn update_gap_limits(
        &self,
        gap_limits: &GapLimits,
        txid: TxId,
        observation_height: BlockHeight,
    ) -> Result<(), Self::Error>;
}
