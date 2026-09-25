//! Statements of the spend authority held by an application's key store.
//!
//! The wallet database does not record which spending keys are available. Queries whose result
//! depends on spend authority, such as note selection and balance computation, instead take a
//! [`SpendAuthority`] that states what the key store holds. Every key known to the wallet
//! belongs to an account, so authority is stated per account. The wallet evaluates it against
//! the receiving address of each output of account `a`:
//!
//! | Receiver                                        | Authorized when                                   |
//! | ----------------------------------------------- | ------------------------------------------------- |
//! | Derived from the keys of `a`, in pool `p`       | the authority for `a` holds pool `p`              |
//! | Standalone P2PKH with public key `pk`           | the authority for `a` holds `pk`                  |
//! | Standalone P2SH with redeem script address `s`  | the authority for `a` names `s`                   |
//! | Standalone, imported by address only            | never                                             |
//!
//! A P2SH output is authorized only by naming its script's address. Holding a key that the
//! script refers to does not authorize it: the authority asserts that the application can
//! satisfy that specific script, alone or as one party to a multi-party signing.
//!
//! Each of these conditions is monotone: an authority that holds more never authorizes less.
//! Consequently, the spendable value that the wallet reports for an authority never exceeds
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
/// A spend authority is an assertion by the caller: every output that it authorizes is one for
/// which the application can produce the required signatures, or, for a multi-party script, can
/// contribute its share of them to a PCZT. Outputs that it does not authorize are reported as
/// watch-only value and are never selected for spending.
#[derive(Debug, Clone)]
pub struct SpendAuthority<AccountId> {
    accounts: HashMap<AccountId, AccountSpendAuthority>,
}

impl<AccountId: Eq + Hash> SpendAuthority<AccountId> {
    /// Constructs a spend authority from the authority held for each account. An account that
    /// is absent from `accounts` has no authority.
    pub fn new(accounts: HashMap<AccountId, AccountSpendAuthority>) -> Self {
        Self { accounts }
    }

    /// A spend authority that holds nothing. Every output is watch-only under it.
    pub fn none() -> Self {
        Self::new(HashMap::new())
    }

    /// Returns the authority held for each account.
    pub fn accounts(&self) -> &HashMap<AccountId, AccountSpendAuthority> {
        &self.accounts
    }

    /// Returns the authority held for `account`, or `None` if it has none.
    pub fn account(&self, account: &AccountId) -> Option<&AccountSpendAuthority> {
        self.accounts.get(account)
    }

    /// Returns whether outputs received in `pool` at addresses derived from `account`'s keys
    /// are authorized.
    pub fn authorizes_account_pool(&self, account: &AccountId, pool: PoolType) -> bool {
        self.account(account)
            .is_some_and(|authority| authority.authorizes_pool(pool))
    }
}

/// The spend authority held for the key material of a single account.
///
/// Authority over key material derived from the account's keys is stated per pool, because the
/// key store may hold spending keys for some of an account's pools but not for others.
/// Authority over the account's standalone transparent key material is stated separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSpendAuthority {
    pools: BTreeSet<PoolType>,
    #[cfg(feature = "transparent-inputs")]
    standalone_pubkeys: StandalonePubkeys,
    #[cfg(feature = "transparent-inputs")]
    standalone_scripts: BTreeSet<TransparentAddress>,
}

impl AccountSpendAuthority {
    /// Constructs an account authority that holds the given pools of derived key material and
    /// no standalone key material.
    pub fn for_pools(pools: BTreeSet<PoolType>) -> Self {
        Self {
            pools,
            #[cfg(feature = "transparent-inputs")]
            standalone_pubkeys: StandalonePubkeys::Only(BTreeSet::new()),
            #[cfg(feature = "transparent-inputs")]
            standalone_scripts: BTreeSet::new(),
        }
    }

    /// Constructs an account authority from the held pools of derived key material, the held
    /// standalone public keys, and the P2SH addresses of the standalone redeem scripts that the
    /// application can satisfy. An address in `standalone_scripts` that is not a P2SH address
    /// authorizes nothing.
    #[cfg(feature = "transparent-inputs")]
    pub fn new(
        pools: BTreeSet<PoolType>,
        standalone_pubkeys: StandalonePubkeys,
        standalone_scripts: BTreeSet<TransparentAddress>,
    ) -> Self {
        Self {
            pools,
            standalone_pubkeys,
            standalone_scripts,
        }
    }

    /// Returns the pools in which outputs received at addresses derived from the account's
    /// keys are authorized.
    pub fn pools(&self) -> &BTreeSet<PoolType> {
        &self.pools
    }

    /// Returns the standalone public keys held.
    #[cfg(feature = "transparent-inputs")]
    pub fn standalone_pubkeys(&self) -> &StandalonePubkeys {
        &self.standalone_pubkeys
    }

    /// Returns the P2SH addresses of the standalone redeem scripts named by this authority.
    #[cfg(feature = "transparent-inputs")]
    pub fn standalone_scripts(&self) -> &BTreeSet<TransparentAddress> {
        &self.standalone_scripts
    }

    /// Returns whether outputs received in `pool` at addresses derived from the account's keys
    /// are authorized.
    pub fn authorizes_pool(&self, pool: PoolType) -> bool {
        self.pools.contains(&pool)
    }

    /// Returns whether an output received at the account's standalone P2SH address
    /// `script_address` is authorized.
    #[cfg(feature = "transparent-inputs")]
    pub fn authorizes_script(&self, script_address: &TransparentAddress) -> bool {
        matches!(script_address, TransparentAddress::ScriptHash(_))
            && self.standalone_scripts.contains(script_address)
    }
}

/// The standalone P2PKH public keys of an account that the key store holds.
#[cfg(feature = "transparent-inputs")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandalonePubkeys {
    /// Every standalone public key of the account.
    All,
    /// Only the listed public keys.
    Only(BTreeSet<secp256k1::PublicKey>),
}

#[cfg(feature = "transparent-inputs")]
impl StandalonePubkeys {
    /// Returns whether an output received at the standalone P2PKH address of `pubkey` is
    /// authorized.
    pub fn authorizes(&self, pubkey: &secp256k1::PublicKey) -> bool {
        match self {
            StandalonePubkeys::All => true,
            StandalonePubkeys::Only(pubkeys) => pubkeys.contains(pubkey),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use zcash_protocol::{PoolType, ShieldedPool};

    use super::{AccountSpendAuthority, SpendAuthority};

    #[test]
    fn account_authority_is_per_account_and_pool() {
        let authority = SpendAuthority::new(HashMap::from([(
            0u32,
            AccountSpendAuthority::for_pools(BTreeSet::from([PoolType::Shielded(
                ShieldedPool::Orchard,
            )])),
        )]));

        assert!(authority.authorizes_account_pool(&0, PoolType::Shielded(ShieldedPool::Orchard)));
        assert!(!authority.authorizes_account_pool(&0, PoolType::Shielded(ShieldedPool::Sapling)));
        assert!(!authority.authorizes_account_pool(&0, PoolType::Transparent));
        assert!(!authority.authorizes_account_pool(&1, PoolType::Shielded(ShieldedPool::Orchard)));
        assert!(!SpendAuthority::<u32>::none().authorizes_account_pool(&1, PoolType::Transparent));
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn scripts_are_authorized_only_by_name() {
        use ::transparent::address::TransparentAddress;

        use super::StandalonePubkeys;

        let named = TransparentAddress::ScriptHash([1; 20]);
        let unnamed = TransparentAddress::ScriptHash([2; 20]);
        let authority = AccountSpendAuthority::new(
            BTreeSet::new(),
            StandalonePubkeys::All,
            BTreeSet::from([named, TransparentAddress::PublicKeyHash([3; 20])]),
        );

        assert!(authority.authorizes_script(&named));
        assert!(!authority.authorizes_script(&unnamed));
        assert!(!authority.authorizes_script(&TransparentAddress::PublicKeyHash([3; 20])));
    }
}
