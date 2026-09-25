//! Statements of the spend authority held by an application's key store.
//!
//! The wallet does not store which spending keys are available. Queries whose result depends
//! on spend authority, such as note selection and balance computation, instead take a
//! [`SpendCapability`] that states what the key store holds. The wallet evaluates it against
//! the receiving address of each output:
//!
//! | Receiver                                        | Authorized when                                |
//! | ----------------------------------------------- | ---------------------------------------------- |
//! | Derived from account `a`, in pool `p`           | the capability holds pool `p` of account `a`   |
//! | Standalone P2PKH with public key `pk`           | the capability holds `pk`                      |
//! | Standalone P2SH multisig at address `s`         | the capability names `s`                       |
//! | Standalone, imported by address only            | never                                          |
//!
//! A multisig output is authorized only by naming its script's address. Holding a member key
//! of the script does not authorize it: the capability asserts that the application can take
//! part in a multi-party signing of that specific script.
//!
//! Each of these conditions is monotone: a capability that holds more never authorizes less.
//! Consequently, the spendable value that the wallet reports for a capability never exceeds
//! the spendable value it reports for a larger one.

use std::{
    collections::{BTreeSet, HashMap},
    hash::Hash,
};

use zcash_protocol::PoolType;

#[cfg(feature = "transparent-inputs")]
use ::transparent::address::TransparentAddress;

/// The spend authority held by an application's key store.
///
/// A capability is an assertion by the caller: every output that it authorizes is one for
/// which the application can produce the required signatures, or, for a multisig output, can
/// contribute its share of them to a multi-party PCZT. Outputs that it does not authorize are
/// reported as watch-only value and are never selected for spending.
#[derive(Debug, Clone)]
pub struct SpendCapability<AccountId> {
    accounts: AccountAuthority<AccountId>,
    #[cfg(feature = "transparent-inputs")]
    standalone: StandaloneAuthority,
}

impl<AccountId: Eq + Hash> SpendCapability<AccountId> {
    /// Constructs a capability from its account and standalone components.
    #[cfg(feature = "transparent-inputs")]
    pub fn new(accounts: AccountAuthority<AccountId>, standalone: StandaloneAuthority) -> Self {
        Self {
            accounts,
            standalone,
        }
    }

    /// Constructs a capability that holds the given account authority and no standalone
    /// key material.
    pub fn for_accounts(accounts: AccountAuthority<AccountId>) -> Self {
        Self {
            accounts,
            #[cfg(feature = "transparent-inputs")]
            standalone: StandaloneAuthority::none(),
        }
    }

    /// A capability that holds nothing. Every output is watch-only under it.
    pub fn none() -> Self {
        Self::for_accounts(AccountAuthority::none())
    }

    /// Returns the authority over account-derived key material.
    pub fn accounts(&self) -> &AccountAuthority<AccountId> {
        &self.accounts
    }

    /// Returns the authority over standalone transparent key material.
    #[cfg(feature = "transparent-inputs")]
    pub fn standalone(&self) -> &StandaloneAuthority {
        &self.standalone
    }

    /// Returns whether outputs received in `pool` at addresses derived from `account`'s keys
    /// are authorized.
    pub fn authorizes_account_pool(&self, account: &AccountId, pool: PoolType) -> bool {
        self.accounts.authorizes(account, pool)
    }
}

/// Authority over the key material that is derived from each account's keys.
///
/// Authority is stated per account and per pool, because the key store may hold spending
/// keys for some of an account's pools but not for others.
#[derive(Debug, Clone)]
pub enum AccountAuthority<AccountId> {
    /// Every pool of every account.
    All,
    /// Only the listed pools of the listed accounts.
    Only(HashMap<AccountId, BTreeSet<PoolType>>),
}

impl<AccountId: Eq + Hash> AccountAuthority<AccountId> {
    /// Authority over no account.
    pub fn none() -> Self {
        AccountAuthority::Only(HashMap::new())
    }

    /// Returns whether this authority covers `pool` of `account`.
    pub fn authorizes(&self, account: &AccountId, pool: PoolType) -> bool {
        match self {
            AccountAuthority::All => true,
            AccountAuthority::Only(accounts) => {
                accounts.get(account).is_some_and(|p| p.contains(&pool))
            }
        }
    }
}

/// Authority over standalone transparent key material: public keys and redeem scripts
/// imported into an account independently of the account's own key derivation.
#[cfg(feature = "transparent-inputs")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandaloneAuthority {
    keys: StandaloneKeys,
    scripts: BTreeSet<TransparentAddress>,
}

#[cfg(feature = "transparent-inputs")]
impl StandaloneAuthority {
    /// Constructs a standalone authority from the held public keys and the P2SH addresses of
    /// the multisig scripts that the application can take part in signing. An address in
    /// `scripts` that is not a P2SH address authorizes nothing.
    pub fn new(keys: StandaloneKeys, scripts: BTreeSet<TransparentAddress>) -> Self {
        Self { keys, scripts }
    }

    /// Authority over no standalone key material.
    pub fn none() -> Self {
        Self::new(StandaloneKeys::Only(BTreeSet::new()), BTreeSet::new())
    }

    /// Returns the standalone public keys held.
    pub fn keys(&self) -> &StandaloneKeys {
        &self.keys
    }

    /// Returns the P2SH addresses of the multisig scripts named by this authority.
    pub fn scripts(&self) -> &BTreeSet<TransparentAddress> {
        &self.scripts
    }

    /// Returns whether an output received at the standalone P2PKH address of `pubkey` is
    /// authorized.
    pub fn authorizes_pubkey(&self, pubkey: &secp256k1::PublicKey) -> bool {
        self.keys.holds(pubkey)
    }

    /// Returns whether an output received at the standalone P2SH address `script_address` is
    /// authorized.
    pub fn authorizes_script(&self, script_address: &TransparentAddress) -> bool {
        matches!(script_address, TransparentAddress::ScriptHash(_))
            && self.scripts.contains(script_address)
    }
}

/// The standalone P2PKH public keys held by the key store.
#[cfg(feature = "transparent-inputs")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandaloneKeys {
    /// Every standalone public key imported into the wallet.
    AllImported,
    /// Only the listed public keys.
    Only(BTreeSet<secp256k1::PublicKey>),
}

#[cfg(feature = "transparent-inputs")]
impl StandaloneKeys {
    /// Returns whether `pubkey` is held.
    pub fn holds(&self, pubkey: &secp256k1::PublicKey) -> bool {
        match self {
            StandaloneKeys::AllImported => true,
            StandaloneKeys::Only(keys) => keys.contains(pubkey),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use zcash_protocol::{PoolType, ShieldedPool};

    use super::{AccountAuthority, SpendCapability};

    #[test]
    fn account_authority_is_per_account_and_pool() {
        let capability = SpendCapability::for_accounts(AccountAuthority::Only(HashMap::from([(
            0u32,
            BTreeSet::from([PoolType::Shielded(ShieldedPool::Orchard)]),
        )])));

        assert!(capability.authorizes_account_pool(&0, PoolType::Shielded(ShieldedPool::Orchard)));
        assert!(!capability.authorizes_account_pool(&0, PoolType::Shielded(ShieldedPool::Sapling)));
        assert!(!capability.authorizes_account_pool(&0, PoolType::Transparent));
        assert!(!capability.authorizes_account_pool(&1, PoolType::Shielded(ShieldedPool::Orchard)));
        let all = SpendCapability::for_accounts(AccountAuthority::All);
        assert!(all.authorizes_account_pool(&1, PoolType::Transparent));
        assert!(!SpendCapability::<u32>::none().authorizes_account_pool(&1, PoolType::Transparent));
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn scripts_are_authorized_only_by_name() {
        use ::transparent::address::TransparentAddress;

        use super::{StandaloneAuthority, StandaloneKeys};

        let named = TransparentAddress::ScriptHash([1; 20]);
        let unnamed = TransparentAddress::ScriptHash([2; 20]);
        let authority = StandaloneAuthority::new(
            StandaloneKeys::AllImported,
            BTreeSet::from([named, TransparentAddress::PublicKeyHash([3; 20])]),
        );

        assert!(authority.authorizes_script(&named));
        assert!(!authority.authorizes_script(&unnamed));
        assert!(!authority.authorizes_script(&TransparentAddress::PublicKeyHash([3; 20])));
    }
}
