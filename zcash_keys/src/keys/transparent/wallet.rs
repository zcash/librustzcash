use crate::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use core::{hash::Hash, ops::Range};
use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};

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

    #[allow(clippy::too_many_arguments)]
    fn generate_address_range(
        &self,
        account_id: Self::AccountRef,
        account_uivk: &UnifiedIncomingViewingKey,
        account_ufvk: Option<&UnifiedFullViewingKey>,
        key_scope: TransparentKeyScope,
        request: UnifiedAddressRequest,
        range_to_store: Range<NonHardenedChildIndex>,
        require_key: bool,
    ) -> Result<(), Self::Error>;
}
