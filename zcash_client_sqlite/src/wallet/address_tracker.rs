//! Allocator for ephemeral transparent addresses.

use std::borrow::Borrow;

use rusqlite::Connection;

use zcash_client_backend::data_api::AddressTrackingError;
use zcash_primitives::{consensus::Parameters, legacy::TransparentAddress};

use crate::WalletDb;

pub(crate) struct AddressTracker {
    gap_set: Vec<TransparentAddress>,
    first_unused_index: u32,
    first_unmined_index: u32,
}

impl AddressTracker {
    pub(crate) fn new<C: Borrow<Connection>, P: Parameters>(_conn: C, _params: &P) -> Self {
        AddressTracker {
            gap_set: vec![],
            first_unused_index: 0,
            first_unmined_index: 0,
        }
    }

    pub(crate) fn reserve_next_address<C: Borrow<Connection>, P: Parameters>(
        &mut self,
        _wallet: &WalletDb<C, P>,
        _account: zip32::AccountId,
    ) -> Result<TransparentAddress, AddressTrackingError> {
        Err(AddressTrackingError::ReachedGapLimit)
    }

    pub(crate) fn unreserve_addresses<C: Borrow<Connection>, P: Parameters>(
        &mut self,
        _wallet: &WalletDb<C, P>,
        addresses: &[TransparentAddress],
    ) -> Result<(), AddressTrackingError> {
        for _addr in addresses.iter().rev() {
            todo!()
        }
        Ok(())
    }

    pub(crate) fn mark_addresses_as_used<C: Borrow<Connection>, P: Parameters>(
        &mut self,
        _wallet: &WalletDb<C, P>,
        _addresses: &[TransparentAddress],
    ) -> Result<(), AddressTrackingError> {
        Ok(())
    }

    /// Checks the set of ephemeral transparent addresses within the gap limit for the
    /// given mined t-addresses, in order to update the first unmined ephemeral t-address
    /// index if necessary.
    pub(crate) fn mark_addresses_as_mined<C: Borrow<Connection>, P: Parameters>(
        &mut self,
        _wallet: &WalletDb<C, P>,
        _addresses: &[TransparentAddress],
    ) -> Result<(), AddressTrackingError> {
        Ok(())
    }
}
