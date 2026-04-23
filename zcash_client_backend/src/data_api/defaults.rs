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

use super::{Account, FindAccountForAddressError, WalletRead};

/// Returns `true` if `address` contains any receiver that matches one of the receivers of the
/// given [`UnifiedAddress`].
pub fn address_receiver_matches_ua<P: consensus::Parameters>(
    address: &Address,
    ua: &UnifiedAddress,
    params: &P,
) -> bool {
    let zcash_address = address.to_zcash_address(params);
    ua.as_understood_receivers()
        .iter()
        .any(|r| r.corresponds(&zcash_address))
}

/// Reference implementation of [`WalletRead::find_account_for_address`].
///
/// For Unified Addresses this iterates the wallet's accounts and, for each, asks the account's
/// [`UnifiedIncomingViewingKey`] whether it derived any receiver of the address (see
/// [`UnifiedIncomingViewingKey::decrypt_diversifiers`]). An account matches if at least one of
/// the UA's shielded receivers is attributable to it. If more than one account matches, the
/// UA's receivers are inconsistent across accounts and `UnifiedAddressConflict` is returned.
///
/// For non-Unified Addresses this falls back to a linear scan over each account's tracked
/// addresses via [`WalletRead::list_addresses`], returning the first account that holds a
/// matching address (as an exact match, or as a receiver embedded in a stored UA).
///
/// Backends that can answer this query more efficiently (e.g. via an indexed database
/// lookup) should implement [`WalletRead::find_account_for_address`] directly rather than
/// delegating to this function.
///
/// See [`WalletRead::find_account_for_address`] for the semantics of the return value.
///
/// [`UnifiedIncomingViewingKey`]: zcash_keys::keys::UnifiedIncomingViewingKey
/// [`UnifiedIncomingViewingKey::decrypt_diversifiers`]: zcash_keys::keys::UnifiedIncomingViewingKey::decrypt_diversifiers
pub fn find_account_for_address<W: WalletRead, P: consensus::Parameters>(
    wallet: &W,
    params: &P,
    address: &Address,
) -> Result<Option<W::AccountId>, FindAccountForAddressError<W::Error>> {
    if let Address::Unified(ua) = address {
        let mut found_acc_id: Option<W::AccountId> = None;
        for acc_id in wallet.get_account_ids()? {
            let Some(account) = wallet.get_account(acc_id)? else {
                continue;
            };
            if !account.uivk().decrypt_diversifiers(ua).is_empty() {
                match found_acc_id {
                    None => found_acc_id = Some(acc_id),
                    Some(prev) if prev == acc_id => {}
                    Some(_) => return Err(FindAccountForAddressError::UnifiedAddressConflict),
                }
            }
        }
        Ok(found_acc_id)
    } else {
        // Non-UA addresses have a single receiver, so no cross-account conflict is
        // possible; return the first match.
        let zcash_address = address.to_zcash_address(params);
        for acc_id in wallet.get_account_ids()? {
            for addr_info in wallet.list_addresses(acc_id)? {
                let stored = addr_info.address();
                if stored == address {
                    return Ok(Some(acc_id));
                }
                if let Address::Unified(stored_ua) = stored {
                    if stored_ua
                        .as_understood_receivers()
                        .iter()
                        .any(|r| r.corresponds(&zcash_address))
                    {
                        return Ok(Some(acc_id));
                    }
                }
            }
        }
        Ok(None)
    }
}
