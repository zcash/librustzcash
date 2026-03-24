//! Types and operations specific to generation of transparent addresses using a "gap limit"
//! strategy, as described by [`BIP 44`].
//!
//! [`BIP 44`]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

use alloc::vec::Vec;
use core::hash::Hash;
use core::ops::Range;

use crate::{
    address::Address,
    keys::{
        AddressGenerationError, UnifiedAddressRequest, UnifiedFullViewingKey,
        UnifiedIncomingViewingKey,
    },
};
use transparent::{
    address::TransparentAddress,
    keys::{IncomingViewingKey, NonHardenedChildIndex, NonHardenedChildRange, TransparentKeyScope},
};
use zcash_address::unified::Typecode;
use zip32::DiversifierIndex;

/// Configuration for gap limits used in transparent address management.
///
/// A "gap limit" is the number of consecutive unused addresses that the wallet will generate
/// before stopping. This concept comes from BIP-44 HD wallet standards: when scanning for
/// funds, the wallet generates addresses sequentially and stops when it encounters a "gap"
/// of unused addresses equal to this limit. In recovery, a wallet will discover funds
/// belonging to generated addresses. Note that order of operations matters; if a wallet scans
/// blocks for transparent outputs instead of querying the UTXO set, out-of-order scanning may
/// result in funds not being found; as a result, wallets should still fall back to making
/// temporally unlinkable, private queries to the UTXO set for each address controlled by the
/// wallet at any time that a gap in scanned blocks is introduced by out-of-order scanning.
///
/// In Zcash, we define individual gap limits for the following address types:
/// - **External addresses**: Addresses shared with external parties.
/// - **Internal (change) addresses**: Used for transparent change outputs.
/// - **Ephemeral addresses**: Used for single-use purposes like ZIP-320 TEX address transfers.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct GapLimits {
    external: u32,
    internal: u32,
    ephemeral: u32,
}

impl GapLimits {
    /// Constructs a new `GapLimits` value from its constituent parts.
    ///
    /// The gap limits recommended for use with this crate are supplied by the [`Default`]
    /// implementation for this type.
    ///
    /// This constructor is only available under the `unstable` feature, as it is not recommended
    /// for general use.
    #[cfg(any(test, feature = "test-dependencies", feature = "unstable"))]
    pub fn new(external: u32, internal: u32, ephemeral: u32) -> Self {
        Self {
            external,
            internal,
            ephemeral,
        }
    }

    /// Returns the gap limit for external-scoped addresses.
    pub fn external(&self) -> u32 {
        self.external
    }

    /// Returns the gap limit for internal-scoped addresses.
    pub fn internal(&self) -> u32 {
        self.internal
    }

    /// Returns the gap limit for ephemeral-scoped addresses.
    pub fn ephemeral(&self) -> u32 {
        self.ephemeral
    }

    /// Returns the gap limit for the given transparent key scope, or `None` if the key scope is
    /// one for which gap limits are not managed by this type.
    pub fn limit_for(&self, scope: TransparentKeyScope) -> Option<u32> {
        match scope {
            TransparentKeyScope::EXTERNAL => Some(self.external()),
            TransparentKeyScope::INTERNAL => Some(self.internal()),
            TransparentKeyScope::EPHEMERAL => Some(self.ephemeral()),
            _ => None,
        }
    }
}

/// The default gap limits supported by this implementation are:
///
/// - external addresses: 10
/// - transparent internal (change) addresses: 5
/// - ephemeral addresses: 10
///
/// These limits are chosen with the following rationale:
/// - At present, many wallets query light wallet servers with a set of addresses, because querying
///   for each address independently and in a fashion that is not susceptible to clustering via
///   timing correlation leads to undesirable delays in discovery of received funds. As such, it is
///   desirable to minimize the number of addresses that can be "linked", i.e. understood by the
///   light wallet server to all belong to the same wallet.
/// - For transparent change addresses it is always expected that an address will receive funds
///   immediately following its generation except in the case of wallet failure.
/// - For externally-scoped transparent addresses and ephemeral addresses, it is desirable to use a
///   slightly larger gap limit to account for addresses that were shared with counterparties never
///   having been used. However, we don't want to use the full 20-address gap limit space because
///   it's possible that in the future, changes to the light wallet protocol will obviate the need to
///   query for UTXOs in a fashion that links those addresses to one another. In such a
///   circumstance, the gap limit will be adjusted upward and address rotation should then choose
///   an address that is outside the current gap limit; after that change, newly generated
///   addresses will not be exposed as linked in the view of the light wallet server.
impl Default for GapLimits {
    fn default() -> Self {
        Self {
            external: 10,
            internal: 5,
            ephemeral: 10,
        }
    }
}

/// A trait providing wallet storage operations required for transparent address gap limit
/// management.
///
/// Implementations of this trait allow the gap limit logic in [`generate_gap_addresses`] to query
/// and update the wallet's transparent address state without being coupled to a specific storage
/// backend.
pub trait AddressStore {
    /// The type of errors produced by the wallet storage backend.
    type Error;

    /// A wallet-internal account identifier.
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

    /// Persists a range of derived transparent addresses to the wallet storage.
    ///
    /// Each entry in the list contains the wallet-level address, the raw transparent address,
    /// and the child index from which the address was derived.
    fn store_address_range(
        &mut self,
        account_id: Self::AccountRef,
        key_scope: TransparentKeyScope,
        list: Vec<(Address, TransparentAddress, NonHardenedChildIndex)>,
    ) -> Result<(), Self::Error>;
}

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

/// Generates a list of addresses for the given range of transparent child indices.
///
/// For external-scoped addresses, a unified address is generated using the provided
/// [`UnifiedAddressRequest`]; for internal and ephemeral scopes, the raw transparent address is
/// returned.
///
/// Returns an empty list if the account lacks a transparent key and `require_key` is `false`.
/// Returns an error if the key is required but unavailable, or if the key scope is unsupported.
pub fn generate_address_list(
    account_uivk: &UnifiedIncomingViewingKey,
    account_ufvk: Option<&UnifiedFullViewingKey>,
    key_scope: TransparentKeyScope,
    request: UnifiedAddressRequest,
    range_to_store: Range<NonHardenedChildIndex>,
    require_key: bool,
) -> Result<Vec<(Address, TransparentAddress, NonHardenedChildIndex)>, AddressGenerationError> {
    let account_pubkey = if let Some(k) = account_ufvk.and_then(|ufvk| ufvk.transparent()) {
        k
    } else if matches!(
        key_scope,
        TransparentKeyScope::INTERNAL | TransparentKeyScope::EPHEMERAL
    ) && require_key
    {
        return Err(AddressGenerationError::KeyNotAvailable(Typecode::P2pkh));
    } else {
        // No addresses to generate
        return Ok(vec![]);
    };

    let gen_addrs = |key_scope: TransparentKeyScope, index: NonHardenedChildIndex| match key_scope {
        TransparentKeyScope::EXTERNAL => generate_external_address(account_uivk, request, index),
        TransparentKeyScope::INTERNAL => {
            let internal_address = account_pubkey
                .derive_internal_ivk()?
                .derive_address(index)?;
            Ok((Address::from(internal_address), internal_address))
        }
        TransparentKeyScope::EPHEMERAL => {
            let ephemeral_address = account_pubkey
                .derive_ephemeral_ivk()?
                .derive_ephemeral_address(index)?;
            Ok((Address::from(ephemeral_address), ephemeral_address))
        }
        _ => Err(AddressGenerationError::UnsupportedTransparentKeyScope(
            key_scope,
        )),
    };

    NonHardenedChildRange::from(range_to_store)
        .into_iter()
        .map(|transparent_child_index| {
            let (address, transparent_address) = gen_addrs(key_scope, transparent_child_index)?;
            Ok((address, transparent_address, transparent_child_index))
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Errors that can occur when generating transparent gap addresses.
pub enum GapAddressesError<SE> {
    /// An error occurred in the underlying wallet storage backend.
    Storage(SE),
    /// An error occurred while deriving a transparent address.
    AddressGeneration(AddressGenerationError),
    /// The specified account was not found in the wallet database.
    AccountUnknown,
}

/// Generates transparent addresses to fill the gap for a given account and key scope.
///
/// This function queries the wallet backend (via [`AddressStore`]) to find the start
/// of the first gap of unused addresses, then generates enough addresses to maintain the
/// configured gap limit. If no gap exists (i.e., the address space is exhausted), this is a
/// no-op.
#[allow(clippy::too_many_arguments)]
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
    DbT: AddressStore<Error = SE>,
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
