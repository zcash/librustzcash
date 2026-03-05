//! Reference implementations of [`WalletRead`] and [`WalletWrite`] trait methods.
//!
//! This module provides standalone free functions that implement the canonical semantics of
//! selected trait methods in terms of other, more primitive operations. Wallet backend authors
//! who do not have a more efficient implementation available can delegate the corresponding
//! trait method to the function provided here; backends that can do better (e.g. via an
//! indexed database lookup) should implement the trait method directly.
//!
//! [`WalletRead`]: super::WalletRead
//! [`WalletWrite`]: super::WalletWrite

use zcash_keys::address::{Address, UnifiedAddress};
use zcash_protocol::consensus;

use super::{FindAccountForAddressError, WalletRead};

/// Returns `true` if `address` contains any receiver that matches one of the receivers of the
/// given [`UnifiedAddress`].
pub fn address_receiver_matches_ua<P: consensus::Parameters>(
    address: &Address,
    ua: &UnifiedAddress,
    params: &P,
) -> bool {
    let zcash_address = address.to_zcash_address(params);
    let ua_receivers = ua.as_understood_receivers();

    ua_receivers
        .iter()
        .any(|ua_receiver| ua_receiver.corresponds(&zcash_address))
}

/// Reference implementation of [`WalletRead::find_account_for_address`] that performs a linear
/// scan over all accounts and their tracked addresses, using only
/// [`WalletRead::get_account_ids`] and [`WalletRead::list_addresses`].
///
/// This is `O(accounts × addresses)` and is suitable for backends that do not maintain an
/// indexed address-to-account mapping. Backends that can answer this query more efficiently
/// (e.g. via an indexed database lookup) should implement
/// [`WalletRead::find_account_for_address`] directly rather than delegating to this function.
///
/// See [`WalletRead::find_account_for_address`] for the semantics of the return value and for
/// Unified Address conflict handling.
pub fn find_account_for_address<W: WalletRead, P: consensus::Parameters>(
    wallet: &W,
    params: &P,
    address: &Address,
) -> Result<Option<W::AccountId>, FindAccountForAddressError<W::Error>> {
    let mut found_acc_id: Option<W::AccountId> = None;

    if let Address::Unified(ua) = address {
        for acc_id in wallet.get_account_ids()? {
            for addr_info in wallet.list_addresses(acc_id)? {
                let stored = addr_info.address();
                if address_receiver_matches_ua(stored, ua, params) {
                    match found_acc_id {
                        None => found_acc_id = Some(acc_id),
                        Some(prev) if prev == acc_id => {}
                        Some(_) => {
                            return Err(FindAccountForAddressError::UnifiedAddressConflict);
                        }
                    }
                }
            }
        }
    } else {
        // Non-UA addresses have a single receiver, so no cross-account conflict is
        // possible; return the first match.
        for acc_id in wallet.get_account_ids()? {
            for addr_info in wallet.list_addresses(acc_id)? {
                let stored = addr_info.address();
                if stored == address {
                    return Ok(Some(acc_id));
                }
                if let Address::Unified(stored_ua) = stored {
                    if address_receiver_matches_ua(address, stored_ua, params) {
                        return Ok(Some(acc_id));
                    }
                }
            }
        }
    }

    Ok(found_acc_id)
}
