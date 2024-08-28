use core::time;
use incrementalmerkletree::{Address, Marking, Retention};
use sapling::NullifierDerivingKey;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use std::{
    cmp::Ordering,
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet},
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
    transaction::{components::OutPoint, txid, Authorized, Transaction, TransactionData, TxId},
};
use zcash_protocol::{
    memo::{self, Memo, MemoBytes},
    value::{ZatBalance, Zatoshis},
    PoolType,
    ShieldedProtocol::{Orchard, Sapling},
};

use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        chain::ChainState, Account as _, AccountPurpose, AccountSource, SeedRelevance,
        TransactionDataRequest, TransactionStatus,
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    proto::service::ShieldedProtocol,
    wallet::{Note, NoteId, WalletSaplingOutput, WalletSpend, WalletTransparentOutput, WalletTx},
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
use zcash_client_backend::{data_api::ORCHARD_SHARD_HEIGHT, wallet::WalletOrchardOutput};

use crate::error::Error;

/// Internal wallet representation of a Block.
pub(crate) struct MemoryWalletBlock {
    pub(crate) height: BlockHeight,
    pub(crate) hash: BlockHash,
    pub(crate) block_time: u32,
    // Just the transactions that involve an account in this wallet
    pub(crate) transactions: HashSet<TxId>,
    pub(crate) memos: HashMap<NoteId, MemoBytes>,
    pub(crate) sapling_commitment_tree_size: Option<u32>,
    pub(crate) sapling_output_count: Option<u32>,
    #[cfg(feature = "orchard")]
    pub(crate) orchard_commitment_tree_size: Option<u32>,
    #[cfg(feature = "orchard")]
    pub(crate) orchard_action_count: Option<u32>,
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
