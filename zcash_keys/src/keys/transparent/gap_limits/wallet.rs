use super::GapLimits;
use crate::keys::{
    AddressGenerationError, UnifiedAddressRequest, transparent::wallet::GapLimitsWalletAccess,
};
use crate::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use transparent::keys::TransparentKeyScope;

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
        wallet_db
            .generate_address_range(
                account_id,
                account_uivk,
                account_ufvk,
                key_scope,
                request,
                gap_start..gap_start.saturating_add(gap_limit),
                require_key,
            )
            .map_err(GapAddressesError::Storage)?;
    }

    Ok(())
}
