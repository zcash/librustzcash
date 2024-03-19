//! Allocator for ephemeral transparent addresses.

use std::{borrow::Borrow, cmp::max};

use rusqlite::Connection;

use zcash_client_backend::data_api::AddressTrackingError;
use zcash_primitives::{consensus::Parameters, legacy::TransparentAddress};

use crate::WalletDb;

// Consider making this larger from the start than in Bitcoin, say 100.
const GAP_LIMIT: u32 = 20;

pub(crate) struct AddressTracker {
    /// The ZIP 32 account for which this `AddressTracker` keeps track of ephemeral t-addresses.
    account: zip32::AccountId,

    /// Invariant: `gap_set` holds the ephemeral t-addresses for `account` at indices
    /// `first_unmined_index..(first_unmined_index + GAP_LIMIT)`.
    gap_set: Vec<TransparentAddress>,

    /// Invariant: `first_unused_index` is in `first_unmined_index..(first_unmined_index + GAP_LIMIT)`.
    first_unused_index: u32,

    /// Invariant: `first_unreserved_index` is in `first_unused_index..(first_unmined_index + GAP_LIMIT)`.
    first_unreserved_index: u32,

    /// Invariant: `first_unmined_index` is in `0..=(u32::MAX - GAP_LIMIT)`.
    first_unmined_index: u32,
}

impl AddressTracker {
    pub(crate) fn new<C: Borrow<Connection>, P: Parameters>(
        wallet: &WalletDb<C, P>,
        account: zip32::AccountId,
    ) -> Self {
        // TODO: read (first_unused_index, first_unmined_index) from database.
        let first_unused_index: u32 = todo!();
        let first_unmined_index: u32 = todo!();
        // TODO: fill in gap_set.
        AddressTracker {
            account,
            gap_set: todo!(),
            first_unused_index,
            first_unreserved_index: first_unused_index,
            first_unmined_index,
        }
    }

    pub(crate) fn reserve_next_address<C: Borrow<Connection>, P: Parameters>(
        &mut self,
        _wallet: &WalletDb<C, P>,
    ) -> Result<TransparentAddress, AddressTrackingError> {
        if self.first_unreserved_index >= self.first_unmined_index + GAP_LIMIT - 1 {
            return Err(AddressTrackingError::ReachedGapLimit);
        }
        let ephemeral_addr =
            self.gap_set[(self.first_unreserved_index - self.first_unmined_index) as usize];
        self.first_unreserved_index += 1;
        Ok(ephemeral_addr)
    }

    /// We can assume the particular pattern of use in `create_proposed_transaction`, i.e.
    /// the array will be in the same order the addresses were reserved.
    pub(crate) fn unreserve_addresses<C: Borrow<Connection>, P: Parameters>(
        &mut self,
        _wallet: &WalletDb<C, P>,
        addresses: &[TransparentAddress],
    ) -> Result<(), AddressTrackingError> {
        for &addr in addresses.iter().rev() {
            if self.first_unreserved_index > self.first_unmined_index
                && self.gap_set
                    [(self.first_unreserved_index - self.first_unmined_index - 1) as usize]
                    == addr
            {
                self.first_unreserved_index -= 1;
            }
        }
        Ok(())
    }

    /// We can assume the particular pattern of use in `create_proposed_transaction`, i.e.
    /// the array will be in the same order the addresses were reserved.
    pub(crate) fn mark_addresses_as_used<C: Borrow<Connection>, P: Parameters>(
        &mut self,
        wallet: &WalletDb<C, P>,
        used_addresses: &[TransparentAddress],
    ) -> Result<(), AddressTrackingError> {
        for &addr in used_addresses {
            if self.first_unused_index < self.first_unmined_index + GAP_LIMIT
                && self.gap_set[(self.first_unused_index - self.first_unmined_index) as usize]
                    == addr
            {
                self.first_unused_index += 1;
            }
        }
        Ok(())
    }

    /// Checks the set of ephemeral transparent addresses within the gap limit for the
    /// given mined t-addresses, in order to update the first unmined ephemeral t-address
    /// index if necessary.
    /// These addresses could be in any order.
    pub(crate) fn mark_addresses_as_mined<C: Borrow<Connection>, P: Parameters>(
        &mut self,
        _wallet: &WalletDb<C, P>,
        mined_addresses: &[TransparentAddress],
    ) -> Result<(), AddressTrackingError> {
        // Find the position of the *last* element of `gap_set`, if any, that matches some element of `mined_addresses`.
        if let Some(pos) = self
            .gap_set
            .iter()
            .enumerate()
            .rev()
            .find_map(|(pos, &gap_addr)| {
                mined_addresses
                    .iter()
                    .find(|&&mined_addr| mined_addr == gap_addr)
                    .map(|_| pos)
            })
        {
            if self.first_unmined_index + (pos as u32) + 1 > u32::MAX - GAP_LIMIT {
                return Err(AddressTrackingError::ReachedGapLimit);
            }
            self.first_unmined_index += (pos as u32) + 1;
            self.first_unreserved_index =
                max(self.first_unreserved_index, self.first_unmined_index);
            self.first_unused_index = max(self.first_unused_index, self.first_unmined_index);
            self.gap_set.copy_within(pos..(GAP_LIMIT as usize), 0);
            // TODO: re-fill the rest of `gap_set`.
        }
        Ok(())
    }
}
