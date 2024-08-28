use core::time;
use incrementalmerkletree::{Address, Marking, Position, Retention};
use sapling::NullifierDerivingKey;
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::memory::MemoryShardStore, ShardTree};
use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet},
    convert::Infallible,
    hash::Hash,
    num::NonZeroU32,
    ops::Deref,
    rc::Rc,
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
    ShieldedProtocol::{self, Orchard, Sapling},
};

use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        chain::ChainState, Account as _, AccountPurpose, AccountSource, SeedRelevance,
        SentTransactionOutput, TransactionDataRequest, TransactionStatus,
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{
        Note, NoteId, Recipient, WalletSaplingOutput, WalletSpend, WalletTransparentOutput,
        WalletTx,
    },
};

use zcash_client_backend::data_api::{
    chain::CommitmentTreeRoot, scanning::ScanRange, AccountBirthday, BlockMetadata,
    DecryptedTransaction, NullifierQuery, ScannedBlock, SentTransaction, WalletCommitmentTrees,
    WalletRead, WalletSummary, WalletWrite, SAPLING_SHARD_HEIGHT,
};

/// Maps a block height and transaction (i.e. transaction locator) index to a nullifier.
pub(crate) struct NullifierMap(BTreeMap<Nullifier, (BlockHeight, u32)>);

impl NullifierMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
    pub fn insert(&mut self, height: BlockHeight, index: u32, nullifier: Nullifier) {
        self.0.insert(nullifier, (height, index));
    }

    pub fn get(&self, nullifier: &Nullifier) -> Option<&(BlockHeight, u32)> {
        self.0.get(nullifier)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Nullifier {
    #[cfg(feature = "orchard")]
    Orchard(orchard::note::Nullifier),
    Sapling(sapling::Nullifier),
}

impl Nullifier {
    pub(crate) fn pool(&self) -> PoolType {
        match self {
            #[cfg(feature = "orchard")]
            Nullifier::Orchard(_) => PoolType::ORCHARD,
            Nullifier::Sapling(_) => PoolType::SAPLING,
        }
    }
}
#[cfg(feature = "orchard")]
impl From<orchard::note::Nullifier> for Nullifier {
    fn from(n: orchard::note::Nullifier) -> Self {
        Nullifier::Orchard(n)
    }
}
impl From<sapling::Nullifier> for Nullifier {
    fn from(n: sapling::Nullifier) -> Self {
        Nullifier::Sapling(n)
    }
}
