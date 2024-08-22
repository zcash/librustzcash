#![allow(unused)]
use incrementalmerkletree::{Address, Marking, Retention};
use sapling::NullifierDerivingKey;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    hash::Hash,
    num::NonZeroU32,
    ops::Deref,
};
use zcash_keys::keys::{AddressGenerationError, DerivationError, UnifiedIncomingViewingKey};
use zip32::{fingerprint::SeedFingerprint, DiversifierIndex, Scope};

use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, Network},
    transaction::{components::OutPoint, Transaction, TxId},
};
use zcash_protocol::{
    memo::{self, Memo, MemoBytes},
    value::Zatoshis,
    ShieldedProtocol::{Orchard, Sapling},
};

use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        chain::ChainState, Account as _, AccountPurpose, AccountSource, SeedRelevance,
        TransactionDataRequest, TransactionStatus,
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{NoteId, WalletSpend, WalletTransparentOutput, WalletTx},
};

use zcash_client_backend::data_api::{
    chain::CommitmentTreeRoot, scanning::ScanRange, AccountBirthday, BlockMetadata,
    DecryptedTransaction, NullifierQuery, ScannedBlock, SentTransaction, WalletCommitmentTrees,
    WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
};

#[cfg(feature = "transparent-inputs")]
use {
    zcash_client_backend::wallet::TransparentAddressMetadata,
    zcash_primitives::legacy::TransparentAddress,
};

#[cfg(feature = "orchard")]
use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;

use crate::error::Error;

mod wallet_commitment_trees;
mod wallet_read;
mod wallet_write;

struct MemoryWalletBlock {
    height: BlockHeight,
    hash: BlockHash,
    block_time: u32,
    // Just the transactions that involve an account in this wallet
    transactions: HashSet<TxId>,
    memos: HashMap<NoteId, MemoBytes>,
}

impl PartialEq for MemoryWalletBlock {
    fn eq(&self, other: &Self) -> bool {
        (self.height, self.block_time) == (other.height, other.block_time)
    }
}

impl Eq for MemoryWalletBlock {}

impl PartialOrd for MemoryWalletBlock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some((self.height, self.block_time).cmp(&(other.height, other.block_time)))
    }
}

impl Ord for MemoryWalletBlock {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.height, self.block_time).cmp(&(other.height, other.block_time))
    }
}

pub struct MemoryWalletDb {
    network: Network,
    accounts: Vec<Account>,
    blocks: BTreeMap<BlockHeight, MemoryWalletBlock>,
    tx_idx: HashMap<TxId, BlockHeight>,

    /// Tracks transactions relevant to this wallet indexed by their TxId
    tx_meta: HashMap<TxId, WalletTx<AccountId>>,

    /// Tracks transparent outputs received by this wallet indexed by their OutPoint which defines the
    /// transaction and index where the output was created
    transparent_received_outputs: HashMap<OutPoint, TransparentReceivedOutput>,

    /// Tracks spends of received outputs. In thix case the TxId is the spending transaction
    /// from this wallet.
    transparent_received_output_spends: HashMap<OutPoint, TxId>,

    sapling_spends: BTreeMap<sapling::Nullifier, (TxId, bool)>,
    #[cfg(feature = "orchard")]
    orchard_spends: BTreeMap<orchard::note::Nullifier, (TxId, bool)>,

    sapling_tree: ShardTree<
        MemoryShardStore<sapling::Node, BlockHeight>,
        { SAPLING_SHARD_HEIGHT * 2 },
        SAPLING_SHARD_HEIGHT,
    >,
    #[cfg(feature = "orchard")]
    orchard_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        { ORCHARD_SHARD_HEIGHT * 2 },
        ORCHARD_SHARD_HEIGHT,
    >,
}

impl MemoryWalletDb {
    pub fn new(network: Network, max_checkpoints: usize) -> Self {
        Self {
            network,
            accounts: Vec::new(),
            blocks: BTreeMap::new(),
            tx_idx: HashMap::new(),
            tx_meta: HashMap::new(),
            transparent_received_outputs: HashMap::new(),
            transparent_received_output_spends: HashMap::new(),
            sapling_spends: BTreeMap::new(),
            #[cfg(feature = "orchard")]
            orchard_spends: BTreeMap::new(),
            sapling_tree: ShardTree::new(MemoryShardStore::empty(), max_checkpoints),
            #[cfg(feature = "orchard")]
            orchard_tree: ShardTree::new(MemoryShardStore::empty(), max_checkpoints),
        }
    }

    fn max_zip32_account_index(
        &self,
        seed_fingerprint: &SeedFingerprint,
    ) -> Result<Option<zip32::AccountId>, Error> {
        Ok(self
            .accounts
            .iter()
            .filter_map(|a| match a.source() {
                AccountSource::Derived {
                    seed_fingerprint: sf,
                    account_index,
                } => {
                    if &sf == seed_fingerprint {
                        Some(account_index)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .max())
    }
}

/// The viewing key that an [`Account`] has available to it.
#[derive(Debug, Clone)]
pub(crate) enum ViewingKey {
    /// A full viewing key.
    ///
    /// This is available to derived accounts, as well as accounts directly imported as
    /// full viewing keys.
    Full(Box<UnifiedFullViewingKey>),

    /// An incoming viewing key.
    ///
    /// Accounts that have this kind of viewing key cannot be used in wallet contexts,
    /// because they are unable to maintain an accurate balance.
    Incoming(Box<UnifiedIncomingViewingKey>),
}

/// The ID type for accounts.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct AccountId(u32);

impl Deref for AccountId {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An account stored in a `zcash_client_sqlite` database.
#[derive(Debug, Clone)]
pub struct Account {
    account_id: AccountId,
    kind: AccountSource,
    viewing_key: ViewingKey,
    birthday: AccountBirthday,
    purpose: AccountPurpose,
    notes: HashSet<NoteId>,
}

impl Account {
    /// Returns the default Unified Address for the account,
    /// along with the diversifier index that generated it.
    ///
    /// The diversifier index may be non-zero if the Unified Address includes a Sapling
    /// receiver, and there was no valid Sapling receiver at diversifier index zero.
    pub(crate) fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.uivk().default_address(request)
    }
}

impl zcash_client_backend::data_api::Account<AccountId> for Account {
    fn id(&self) -> AccountId {
        self.account_id
    }

    fn source(&self) -> AccountSource {
        self.kind
    }

    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        self.viewing_key.ufvk()
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        self.viewing_key.uivk()
    }
}

impl ViewingKey {
    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        match self {
            ViewingKey::Full(ufvk) => Some(ufvk),
            ViewingKey::Incoming(_) => None,
        }
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        match self {
            ViewingKey::Full(ufvk) => ufvk.as_ref().to_unified_incoming_viewing_key(),
            ViewingKey::Incoming(uivk) => uivk.as_ref().clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct TransparentReceivedOutput {
    output: WalletTransparentOutput,
    account_id: AccountId,
    tx_id: TxId,
}
