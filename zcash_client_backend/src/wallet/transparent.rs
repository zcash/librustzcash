//! Types and operations specific to handling of transparent addresses and transparent outputs
//! received by the wallet.
use transparent::keys::TransparentKeyScope;

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
