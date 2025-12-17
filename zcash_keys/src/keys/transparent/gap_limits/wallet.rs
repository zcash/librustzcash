use super::GapLimits;
use crate::address::Address;
use crate::keys::{
    AddressGenerationError, UnifiedAddressRequest, transparent::wallet::GapLimitsWalletAccess,
};
use crate::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use core::ops::Range;
use std::vec::Vec;
use transparent::address::TransparentAddress;
use transparent::keys::{
    IncomingViewingKey, NonHardenedChildIndex, NonHardenedChildRange, TransparentKeyScope,
};
use zcash_address::unified::Typecode;
use zip32::DiversifierIndex;

fn generate_external_address(
    uivk: &UnifiedIncomingViewingKey,
    ua_request: UnifiedAddressRequest,
    index: NonHardenedChildIndex,
) -> Result<(Address, TransparentAddress), AddressGenerationError> {
    let ua = uivk.address(index.into(), ua_request);
    let transparent_address = uivk
        .transparent()
        .as_ref()
        .ok_or(AddressGenerationError::KeyNotAvailable(Typecode::P2pkh))?
        .derive_address(index)
        .map_err(|_| {
            AddressGenerationError::InvalidTransparentChildIndex(DiversifierIndex::from(index))
        })?;
    Ok((
        ua.map_or_else(
            |e| {
                if matches!(e, AddressGenerationError::ShieldedReceiverRequired) {
                    // fall back to the transparent-only address
                    Ok(Address::from(transparent_address))
                } else {
                    // other address generation errors are allowed to propagate
                    Err(e)
                }
            },
            |addr| Ok(Address::from(addr)),
        )?,
        transparent_address,
    ))
}

pub fn generate_address_list(
    account_uivk: &UnifiedIncomingViewingKey,
    account_ufvk: Option<&UnifiedFullViewingKey>,
    key_scope: TransparentKeyScope,
    request: UnifiedAddressRequest,
    range_to_store: Range<NonHardenedChildIndex>,
    require_key: bool,
) -> Result<Vec<(Address, TransparentAddress, NonHardenedChildIndex)>, AddressGenerationError> {
    let mut address_list = Vec::<(Address, TransparentAddress, NonHardenedChildIndex)>::new();

    if !account_uivk.has_transparent() {
        if require_key {
            return Err(AddressGenerationError::KeyNotAvailable(Typecode::P2pkh));
        } else {
            // No addresses to generate
            return Ok(address_list);
        }
    }

    let gen_addrs = |key_scope: TransparentKeyScope, index: NonHardenedChildIndex| match key_scope {
        TransparentKeyScope::EXTERNAL => generate_external_address(account_uivk, request, index),
        TransparentKeyScope::INTERNAL => {
            let internal_address = account_ufvk
                .and_then(|k| k.transparent())
                .expect("presence of transparent key was checked above.")
                .derive_internal_ivk()?
                .derive_address(index)?;
            Ok((Address::from(internal_address), internal_address))
        }
        TransparentKeyScope::EPHEMERAL => {
            let ephemeral_address = account_ufvk
                .and_then(|k| k.transparent())
                .expect("presence of transparent key was checked above.")
                .derive_ephemeral_ivk()?
                .derive_ephemeral_address(index)?;
            Ok((Address::from(ephemeral_address), ephemeral_address))
        }
        _ => Err(AddressGenerationError::UnsupportedTransparentKeyScope(
            key_scope,
        )),
    };

    for transparent_child_index in NonHardenedChildRange::from(range_to_store) {
        let (address, transparent_address) = gen_addrs(key_scope, transparent_child_index)?;
        address_list.push((address, transparent_address, transparent_child_index));
    }

    Ok(address_list)
}

pub enum GapAddressesError<SE> {
    Storage(SE),
    AddressGeneration(AddressGenerationError),
    AccountUnknown,
}

pub fn generate_gap_addresses<DbT, SE>(
    wallet_db: &mut DbT,
    gap_limits: &GapLimits,
    account_id: DbT::AccountRef,
    account_uivk: &UnifiedIncomingViewingKey,
    account_ufvk: Option<&UnifiedFullViewingKey>,
    key_scope: TransparentKeyScope,
    request: UnifiedAddressRequest,
    require_key: bool,
) -> Result<(), GapAddressesError<SE>>
where
    DbT: GapLimitsWalletAccess<Error = SE>,
{
    let gap_limit = gap_limits
        .limit_for(key_scope)
        .ok_or(GapAddressesError::AddressGeneration(
            AddressGenerationError::UnsupportedTransparentKeyScope(key_scope),
        ))?;

    if let Some(gap_start) = wallet_db
        .find_gap_start(account_id, key_scope, gap_limit)
        .map_err(GapAddressesError::Storage)?
    {
        let address_list = generate_address_list(
            account_uivk,
            account_ufvk,
            key_scope,
            request,
            gap_start..gap_start.saturating_add(gap_limit),
            require_key,
        )
        .map_err(GapAddressesError::AddressGeneration)?;
        wallet_db
            .store_address_range(account_id, key_scope, address_list)
            .map_err(GapAddressesError::Storage)?;
    }

    Ok(())
}
