//! *An SQLite-based Zcash light client.*
//!
//! `zcash_client_sqlite` contains complete SQLite-based implementations of the [`WalletRead`],
//! [`WalletWrite`], and [`BlockSource`] traits from the [`zcash_client_backend`] crate. In
//! combination with [`zcash_client_backend`], it provides a full implementation of a SQLite-backed
//! client for the Zcash network.
//!
//! # Design
//!
//! The light client is built around two SQLite databases:
//!
//! - A cache database, used to inform the light client about new [`CompactBlock`]s. It is
//!   read-only within all light client APIs *except* for [`init_cache_database`] which
//!   can be used to initialize the database.
//!
//! - A data database, where the light client's state is stored. It is read-write within
//!   the light client APIs, and **assumed to be read-only outside these APIs**. Callers
//!   **MUST NOT** write to the database without using these APIs. Callers **MAY** read
//!   the database directly in order to extract information for display to users.
//!
//! ## Feature flags
#![doc = document_features::document_features!()]
//!
//! [`WalletRead`]: zcash_client_backend::data_api::WalletRead
//! [`WalletWrite`]: zcash_client_backend::data_api::WalletWrite
//! [`BlockSource`]: zcash_client_backend::data_api::chain::BlockSource
//! [`CompactBlock`]: zcash_client_backend::proto::compact_formats::CompactBlock
//! [`init_cache_database`]: crate::chain::init::init_cache_database

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

use incrementalmerkletree::{Marking, Position, Retention};
use nonempty::NonEmpty;
use rusqlite::{self, Connection};
use secrecy::{ExposeSecret, SecretVec};
use shardtree::{error::ShardTreeError, store::ShardStore, ShardTree};
use std::{
    borrow::{Borrow, BorrowMut},
    cmp::{max, min},
    collections::HashMap,
    convert::AsRef,
    fmt,
    num::NonZeroU32,
    ops::Range,
    path::Path,
};
use subtle::ConditionallySelectable;
use tracing::{debug, trace, warn};
use util::Clock;
use uuid::Uuid;

use zcash_client_backend::{
    data_api::{
        self,
        chain::{BlockSource, ChainState, CommitmentTreeRoot},
        scanning::{ScanPriority, ScanRange},
        Account, AccountBirthday, AccountMeta, AccountPurpose, AccountSource, AddressInfo,
        BlockMetadata, DecryptedTransaction, InputSource, NoteFilter, NullifierQuery, ScannedBlock,
        SeedRelevance, SentTransaction, SpendableNotes, TransactionDataRequest,
        WalletCommitmentTrees, WalletRead, WalletSummary, WalletWrite, Zip32Derivation,
        SAPLING_SHARD_HEIGHT,
    },
    proto::compact_formats::CompactBlock,
    wallet::{Note, NoteId, ReceivedNote, WalletTransparentOutput},
    TransferType,
};
use zcash_keys::{
    address::UnifiedAddress,
    keys::{ReceiverRequirement, UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TxId},
};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    memo::Memo,
    value::{TargetValue, Zatoshis},
    ShieldedProtocol,
};
use zip32::{fingerprint::SeedFingerprint, DiversifierIndex};

use crate::{error::SqliteClientError, wallet::commitment_tree::SqliteShardStore};
use wallet::{
    commitment_tree::{self, put_shard_roots},
    common::spendable_notes_meta,
    scanning::replace_queue_entries,
    upsert_address, SubtreeProgressEstimator,
};

#[cfg(feature = "orchard")]
use {
    incrementalmerkletree::frontier::Frontier, shardtree::store::Checkpoint,
    std::collections::BTreeMap, zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::transparent::ephemeral::schedule_ephemeral_address_checks,
    ::transparent::{address::TransparentAddress, bundle::OutPoint, keys::NonHardenedChildIndex},
    std::collections::BTreeSet,
    zcash_client_backend::wallet::TransparentAddressMetadata,
    zcash_keys::encoding::AddressCodec,
};

#[cfg(feature = "multicore")]
use maybe_rayon::{
    prelude::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};

#[cfg(any(test, feature = "test-dependencies"))]
use {
    rusqlite::named_params,
    zcash_client_backend::data_api::{testing::TransactionSummary, OutputOfSentTx, WalletTest},
    zcash_keys::address::Address,
};

#[cfg(any(test, feature = "test-dependencies", feature = "transparent-inputs"))]
use crate::wallet::encoding::KeyScope;

#[cfg(any(test, feature = "test-dependencies", not(feature = "orchard")))]
use zcash_protocol::PoolType;

/// `maybe-rayon` doesn't provide this as a fallback, so we have to.
#[cfg(not(feature = "multicore"))]
trait ParallelSliceMut<T> {
    fn par_chunks_mut(&mut self, chunk_size: usize) -> std::slice::ChunksMut<'_, T>;
}
#[cfg(not(feature = "multicore"))]
impl<T> ParallelSliceMut<T> for [T] {
    fn par_chunks_mut(&mut self, chunk_size: usize) -> std::slice::ChunksMut<'_, T> {
        self.chunks_mut(chunk_size)
    }
}

#[cfg(feature = "unstable")]
use {
    crate::chain::{fsblockdb_with_blocks, BlockMeta},
    std::path::PathBuf,
    std::{fs, io},
};

pub mod chain;
pub mod error;
pub mod util;
pub mod wallet;

#[cfg(test)]
mod testing;

/// The maximum number of blocks the wallet is allowed to rewind. This is
/// consistent with the bound in zcashd, and allows block data deeper than
/// this delta from the chain tip to be pruned.
pub(crate) const PRUNING_DEPTH: u32 = 100;

/// The number of blocks to verify ahead when the chain tip is updated.
pub(crate) const VERIFY_LOOKAHEAD: u32 = 10;

pub(crate) const SAPLING_TABLES_PREFIX: &str = "sapling";

#[cfg(feature = "orchard")]
pub(crate) const ORCHARD_TABLES_PREFIX: &str = "orchard";

#[cfg(not(feature = "orchard"))]
pub(crate) const UA_ORCHARD: ReceiverRequirement = ReceiverRequirement::Omit;
#[cfg(feature = "orchard")]
pub(crate) const UA_ORCHARD: ReceiverRequirement = ReceiverRequirement::Require;

#[cfg(not(feature = "transparent-inputs"))]
pub(crate) const UA_TRANSPARENT: ReceiverRequirement = ReceiverRequirement::Omit;
#[cfg(feature = "transparent-inputs")]
pub(crate) const UA_TRANSPARENT: ReceiverRequirement = ReceiverRequirement::Require;

/// Unique identifier for a specific account tracked by a [`WalletDb`].
///
/// Account identifiers are "one-way stable": a given identifier always points to a
/// specific viewing key within a specific [`WalletDb`] instance, but the same viewing key
/// may have multiple account identifiers over time. In particular, this crate upholds the
/// following properties:
///
/// - When an account starts being tracked within a [`WalletDb`] instance (via APIs like
///   [`WalletWrite::create_account`], [`WalletWrite::import_account_hd`], or
///   [`WalletWrite::import_account_ufvk`]), a new `AccountUuid` is generated.
/// - If an `AccountUuid` is present within a [`WalletDb`], it always points to the same
///   account.
///
/// What this means is that account identifiers are not stable across "wallet recreation
/// events". Examples of these include:
/// - Restoring a wallet from a backed-up seed.
/// - Importing the same viewing key into two different wallet instances.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccountUuid(#[cfg_attr(feature = "serde", serde(with = "uuid::serde::compact"))] Uuid);

impl ConditionallySelectable for AccountUuid {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        AccountUuid(Uuid::from_u128(
            ConditionallySelectable::conditional_select(&a.0.as_u128(), &b.0.as_u128(), choice),
        ))
    }
}

impl AccountUuid {
    /// Constructs an `AccountUuid` from a bare [`Uuid`] value.
    ///
    /// The resulting identifier is not guaranteed to correspond to any account stored in
    /// a [`WalletDb`].
    pub fn from_uuid(value: Uuid) -> Self {
        AccountUuid(value)
    }

    /// Exposes the opaque account identifier from its typesafe wrapper.
    pub fn expose_uuid(&self) -> Uuid {
        self.0
    }
}

/// A typesafe wrapper for the primary key identifier for a row in the `accounts` table.
///
/// This is an ephemeral value for efficiently and generically working with accounts in a
/// [`WalletDb`]. To reference accounts in external contexts, use [`AccountUuid`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub(crate) struct AccountRef(u32);

/// This implementation is retained under `#[cfg(test)]` for pre-AccountUuid testing.
#[cfg(test)]
impl ConditionallySelectable for AccountRef {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        AccountRef(ConditionallySelectable::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

/// An opaque type for received note identifiers.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReceivedNoteId(pub(crate) ShieldedProtocol, pub(crate) i64);

impl fmt::Display for ReceivedNoteId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReceivedNoteId(protocol, id) => write!(f, "Received {:?} Note: {}", protocol, id),
        }
    }
}

/// A newtype wrapper for sqlite primary key values for the utxos table.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UtxoId(pub i64);

/// A newtype wrapper for sqlite primary key values for the transactions table.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TxRef(pub i64);

/// A newtype wrapper for sqlite primary key values for the addresses table.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct AddressRef(pub(crate) i64);

/// A data structure that can be used to configure custom gap limits for use in transparent address
/// rotation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg(feature = "transparent-inputs")]
pub struct GapLimits {
    external: u32,
    internal: u32,
    ephemeral: u32,
}

#[cfg(feature = "transparent-inputs")]
impl GapLimits {
    /// Constructs a new `GapLimits` value from its constituent parts.
    ///
    /// The gap limits recommended for use with this crate are supplied by the [`Default`]
    /// implementation for this type.
    ///
    /// This constructor is only available under the `unstable` feature, as it is not recommended
    /// for general use.
    #[cfg(any(test, feature = "test-dependencies", feature = "unstable"))]
    pub fn from_parts(external: u32, internal: u32, ephemeral: u32) -> Self {
        Self {
            external,
            internal,
            ephemeral,
        }
    }

    pub(crate) fn external(&self) -> u32 {
        self.external
    }

    pub(crate) fn internal(&self) -> u32 {
        self.internal
    }

    pub(crate) fn ephemeral(&self) -> u32 {
        self.ephemeral
    }
}

/// The default gap limits supported by this implementation are:
///
/// - external addresses: 10
/// - transparent internal (change) addresses: 5
/// - ephemeral addresses: 5
///
/// These limits are chosen with the following rationale:
/// - At present, many wallets query light wallet servers with a set of addresses, because querying
///   for each address independently and in a fashion that is not susceptible to clustering via
///   timing correlation leads to undesirable delays in discovery of received funds. As such, it is
///   desirable to minimize the number of addresses that can be "linked", i.e. understood by the
///   light wallet server to all belong to the same wallet.
/// - For transparent change addresses and ephemeral addresses, it is always expected that an
///   address will receive funds immediately following its generation except in the case of wallet
///   failure.
/// - For externally-scoped transparent addresses, it is desirable to use a slightly larger gap
///   limit to account for addresses that were shared with counterparties never having been used.
///   However, we don't want to use the full 20-address gap limit space because it's possible that
///   in the future, changes to the light wallet protocol will obviate the need to query for UTXOs
///   in a fashion that links those addresses. In such a circumstance, the gap limit will be
///   adjusted upward and address rotation should then choose an address that is outside the
///   current gap limit; after that change, newly generated addresses will not be exposed as
///   linked in the view of the light wallet server.
#[cfg(feature = "transparent-inputs")]
impl Default for GapLimits {
    fn default() -> Self {
        Self {
            external: 10,
            internal: 5,
            ephemeral: 5,
        }
    }
}

#[cfg(all(
    any(test, feature = "test-dependencies"),
    feature = "transparent-inputs"
))]
impl From<GapLimits> for zcash_client_backend::data_api::testing::transparent::GapLimits {
    fn from(value: GapLimits) -> Self {
        zcash_client_backend::data_api::testing::transparent::GapLimits::new(
            value.external,
            value.internal,
            value.ephemeral,
        )
    }
}

#[cfg(all(
    any(test, feature = "test-dependencies"),
    feature = "transparent-inputs"
))]
impl From<zcash_client_backend::data_api::testing::transparent::GapLimits> for GapLimits {
    fn from(value: zcash_client_backend::data_api::testing::transparent::GapLimits) -> Self {
        GapLimits::from_parts(value.external(), value.internal(), value.ephemeral())
    }
}

/// A wrapper for the SQLite connection to the wallet database, along with a capability to read the
/// system from the clock. A `WalletDb` encapsulates the full set of capabilities that are required
/// in order to implement the [`WalletRead`], [`WalletWrite`] and [`WalletCommitmentTrees`] traits.
pub struct WalletDb<C, P, CL, R> {
    conn: C,
    params: P,
    clock: CL,
    rng: R,
    #[cfg(feature = "transparent-inputs")]
    gap_limits: GapLimits,
}

/// A wrapper for a SQLite transaction affecting the wallet database.
pub struct SqlTransaction<'conn>(pub(crate) &'conn rusqlite::Transaction<'conn>);

impl Borrow<rusqlite::Connection> for SqlTransaction<'_> {
    fn borrow(&self) -> &rusqlite::Connection {
        self.0
    }
}

impl<P, CL, R> WalletDb<Connection, P, CL, R> {
    /// Construct a [`WalletDb`] instance that connects to the wallet database stored at the
    /// specified path.
    ///
    /// ## Parameters
    /// - `path`: The path to the SQLite database used to store wallet data.
    /// - `params`: Parameters associated with the Zcash network that the wallet will connect to.
    /// - `clock`: The clock to use in the case that the backend needs access to the system time.
    /// - `rng`: The random number generation capability to be exposed by the created `WalletDb`
    ///   instance.
    pub fn for_path<F: AsRef<Path>>(
        path: F,
        params: P,
        clock: CL,
        rng: R,
    ) -> Result<Self, rusqlite::Error> {
        Connection::open(path).and_then(move |conn| {
            rusqlite::vtab::array::load_module(&conn)?;
            Ok(WalletDb {
                conn,
                params,
                clock,
                rng,
                #[cfg(feature = "transparent-inputs")]
                gap_limits: GapLimits::default(),
            })
        })
    }
}

#[cfg(feature = "transparent-inputs")]
impl<C, P, CL, R> WalletDb<C, P, CL, R> {
    /// Sets the gap limits to be used by the wallet in transparent address generation.
    pub fn with_gap_limits(mut self, gap_limits: GapLimits) -> Self {
        self.gap_limits = gap_limits;
        self
    }
}

impl<C: Borrow<rusqlite::Connection>, P, CL, R> WalletDb<C, P, CL, R> {
    /// Constructs a new wrapper around the given connection.
    ///
    /// This is provided for use cases such as connection pooling, where `conn` may be an
    /// `&mut rusqlite::Connection`.
    ///
    /// The caller must ensure that [`rusqlite::vtab::array::load_module`] has been called
    /// on the connection.
    ///
    /// ## Parameters
    /// - `conn`: A connection to the wallet database.
    /// - `params`: Parameters associated with the Zcash network that the wallet will connect to.
    /// - `clock`: The clock to use in the case that the backend needs access to the system time.
    /// - `rng`: The random number generation capability to be exposed by the created `WalletDb`
    ///   instance.
    pub fn from_connection(conn: C, params: P, clock: CL, rng: R) -> Self {
        WalletDb {
            conn,
            params,
            clock,
            rng,
            #[cfg(feature = "transparent-inputs")]
            gap_limits: GapLimits::default(),
        }
    }
}

impl<C: BorrowMut<Connection>, P, CL, R> WalletDb<C, P, CL, R> {
    pub fn transactionally<F, A, E: From<rusqlite::Error>>(&mut self, f: F) -> Result<A, E>
    where
        F: FnOnce(&mut WalletDb<SqlTransaction<'_>, &P, &CL, &mut R>) -> Result<A, E>,
    {
        let tx = self.conn.borrow_mut().transaction()?;
        let mut wdb = WalletDb {
            conn: SqlTransaction(&tx),
            params: &self.params,
            clock: &self.clock,
            rng: &mut self.rng,
            #[cfg(feature = "transparent-inputs")]
            gap_limits: self.gap_limits,
        };
        let result = f(&mut wdb)?;
        tx.commit()?;
        Ok(result)
    }

    /// Attempts to construct a witness for each note belonging to the wallet that is believed by
    /// the wallet to currently be spendable, and returns a vector of the ranges that must be
    /// rescanned in order to correct missing witness data.
    ///
    /// This method is intended for repairing wallets that broke due to bugs in `shardtree`.
    pub fn check_witnesses(&mut self) -> Result<Vec<Range<BlockHeight>>, SqliteClientError> {
        self.transactionally(|wdb| wallet::commitment_tree::check_witnesses(wdb.conn.0))
    }

    /// Updates the scan queue by inserting scan ranges for the given range of block heights, with
    /// the specified scanning priority.
    pub fn queue_rescans(
        &mut self,
        rescan_ranges: NonEmpty<Range<BlockHeight>>,
        priority: ScanPriority,
    ) -> Result<(), SqliteClientError> {
        let query_range = rescan_ranges
            .iter()
            .fold(None, |acc: Option<Range<BlockHeight>>, scan_range| {
                if let Some(range) = acc {
                    Some(min(range.start, scan_range.start)..max(range.end, scan_range.end))
                } else {
                    Some(scan_range.clone())
                }
            })
            .expect("rescan_ranges is nonempty");

        self.transactionally::<_, _, SqliteClientError>(|wdb| {
            replace_queue_entries(
                wdb.conn.0,
                &query_range,
                rescan_ranges
                    .into_iter()
                    .map(|r| ScanRange::from_parts(r, priority)),
                true,
            )
        })?;

        Ok(())
    }
}

#[cfg(feature = "transparent-inputs")]
impl<C: BorrowMut<Connection>, P, CL: Clock, R: rand::RngCore> WalletDb<C, P, CL, R> {
    /// For each ephemeral address in the wallet, ensure that the transaction data request queue
    /// contains a request for the wallet to check for UTXOs belonging to that address at some time
    /// during the next 24-hour period.
    ///
    /// We use randomized scheduling of ephemeral address checks to ensure that a
    /// lightwalletd-compromising adversary cannot use temporal clustering to determine what
    /// ephemeral addresses belong to a given wallet.
    pub fn schedule_ephemeral_address_checks(&mut self) -> Result<(), SqliteClientError> {
        self.borrow_mut().transactionally(|wdb| {
            schedule_ephemeral_address_checks(wdb.conn.0, wdb.clock, &mut wdb.rng)
        })
    }
}

impl<C: Borrow<rusqlite::Connection>, P: consensus::Parameters, CL, R> InputSource
    for WalletDb<C, P, CL, R>
{
    type Error = SqliteClientError;
    type NoteRef = ReceivedNoteId;
    type AccountId = AccountUuid;

    fn get_spendable_note(
        &self,
        txid: &TxId,
        protocol: ShieldedProtocol,
        index: u32,
    ) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error> {
        match protocol {
            ShieldedProtocol::Sapling => wallet::sapling::get_spendable_sapling_note(
                self.conn.borrow(),
                &self.params,
                txid,
                index,
            )
            .map(|opt| opt.map(|n| n.map_note(Note::Sapling))),
            ShieldedProtocol::Orchard => {
                #[cfg(feature = "orchard")]
                return wallet::orchard::get_spendable_orchard_note(
                    self.conn.borrow(),
                    &self.params,
                    txid,
                    index,
                )
                .map(|opt| opt.map(|n| n.map_note(Note::Orchard)));

                #[cfg(not(feature = "orchard"))]
                return Err(SqliteClientError::UnsupportedPoolType(PoolType::ORCHARD));
            }
        }
    }

    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: TargetValue,
        sources: &[ShieldedProtocol],
        anchor_height: BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<SpendableNotes<Self::NoteRef>, Self::Error> {
        Ok(SpendableNotes::new(
            if sources.contains(&ShieldedProtocol::Sapling) {
                wallet::sapling::select_spendable_sapling_notes(
                    self.conn.borrow(),
                    &self.params,
                    account,
                    target_value,
                    anchor_height,
                    exclude,
                )?
            } else {
                vec![]
            },
            #[cfg(feature = "orchard")]
            if sources.contains(&ShieldedProtocol::Orchard) {
                wallet::orchard::select_spendable_orchard_notes(
                    self.conn.borrow(),
                    &self.params,
                    account,
                    target_value,
                    anchor_height,
                    exclude,
                )?
            } else {
                vec![]
            },
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_unspent_transparent_output(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<WalletTransparentOutput>, Self::Error> {
        wallet::transparent::get_wallet_transparent_output(self.conn.borrow(), outpoint, false)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_spendable_transparent_outputs(
        &self,
        address: &TransparentAddress,
        target_height: BlockHeight,
        min_confirmations: u32,
    ) -> Result<Vec<WalletTransparentOutput>, Self::Error> {
        wallet::transparent::get_spendable_transparent_outputs(
            self.conn.borrow(),
            &self.params,
            address,
            target_height,
            min_confirmations,
        )
    }

    /// Returns metadata for the spendable notes in the wallet.
    fn get_account_metadata(
        &self,
        account_id: Self::AccountId,
        selector: &NoteFilter,
        exclude: &[Self::NoteRef],
    ) -> Result<AccountMeta, Self::Error> {
        let chain_tip_height = wallet::chain_tip_height(self.conn.borrow())?
            .ok_or(SqliteClientError::ChainHeightUnknown)?;

        let sapling_pool_meta = spendable_notes_meta(
            self.conn.borrow(),
            ShieldedProtocol::Sapling,
            chain_tip_height,
            account_id,
            selector,
            exclude,
        )?;

        #[cfg(feature = "orchard")]
        let orchard_pool_meta = spendable_notes_meta(
            self.conn.borrow(),
            ShieldedProtocol::Orchard,
            chain_tip_height,
            account_id,
            selector,
            exclude,
        )?;
        #[cfg(not(feature = "orchard"))]
        let orchard_pool_meta = None;

        Ok(AccountMeta::new(sapling_pool_meta, orchard_pool_meta))
    }
}

impl<C: Borrow<rusqlite::Connection>, P: consensus::Parameters, CL, R> WalletRead
    for WalletDb<C, P, CL, R>
{
    type Error = SqliteClientError;
    type AccountId = AccountUuid;
    type Account = wallet::Account;

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        Ok(wallet::get_account_ids(self.conn.borrow())?)
    }

    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        wallet::get_account(self.conn.borrow(), &self.params, account_id)
    }

    fn get_derived_account(
        &self,
        seed: &SeedFingerprint,
        account_id: zip32::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        wallet::get_derived_account(self.conn.borrow(), &self.params, seed, account_id)
    }

    fn validate_seed(
        &self,
        account_id: Self::AccountId,
        seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        if let Some(account) = self.get_account(account_id)? {
            if let AccountSource::Derived { derivation, .. } = account.source() {
                wallet::seed_matches_derived_account(
                    &self.params,
                    seed,
                    derivation.seed_fingerprint(),
                    derivation.account_index(),
                    &account.uivk(),
                )
            } else {
                Err(SqliteClientError::UnknownZip32Derivation)
            }
        } else {
            // Missing account is documented to return false.
            Ok(false)
        }
    }

    fn seed_relevance_to_derived_accounts(
        &self,
        seed: &SecretVec<u8>,
    ) -> Result<SeedRelevance<Self::AccountId>, Self::Error> {
        let mut has_accounts = false;
        let mut has_derived = false;
        let mut relevant_account_ids = vec![];

        for account_id in self.get_account_ids()? {
            has_accounts = true;
            let account = self.get_account(account_id)?.expect("account ID exists");

            // If the account is imported, the seed _might_ be relevant, but the only
            // way we could determine that is by brute-forcing the ZIP 32 account
            // index space, which we're not going to do. The method name indicates to
            // the caller that we only check derived accounts.
            if let AccountSource::Derived { derivation, .. } = account.source() {
                has_derived = true;

                if wallet::seed_matches_derived_account(
                    &self.params,
                    seed,
                    derivation.seed_fingerprint(),
                    derivation.account_index(),
                    &account.uivk(),
                )? {
                    // The seed is relevant to this account.
                    relevant_account_ids.push(account_id);
                }
            }
        }

        Ok(
            if let Some(account_ids) = NonEmpty::from_vec(relevant_account_ids) {
                SeedRelevance::Relevant { account_ids }
            } else if has_derived {
                SeedRelevance::NotRelevant
            } else if has_accounts {
                SeedRelevance::NoDerivedAccounts
            } else {
                SeedRelevance::NoAccounts
            },
        )
    }

    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::Account>, Self::Error> {
        wallet::get_account_for_ufvk(self.conn.borrow(), &self.params, ufvk)
    }

    fn list_addresses(&self, account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> {
        wallet::list_addresses(self.conn.borrow(), &self.params, account)
    }

    fn get_last_generated_address_matching(
        &self,
        account: Self::AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        wallet::get_last_generated_address_matching(
            self.conn.borrow(),
            &self.params,
            account,
            request,
        )
        .map(|res| res.map(|(addr, _)| addr))
    }

    fn get_account_birthday(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        wallet::account_birthday(self.conn.borrow(), account)
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::wallet_birthday(self.conn.borrow()).map_err(SqliteClientError::from)
    }

    fn get_wallet_summary(
        &self,
        min_confirmations: u32,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        // This will return a runtime error if we call `get_wallet_summary` from two
        // threads at the same time, as transactions cannot nest.
        wallet::get_wallet_summary(
            &self.conn.borrow().unchecked_transaction()?,
            &self.params,
            min_confirmations,
            &SubtreeProgressEstimator,
        )
    }

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::chain_tip_height(self.conn.borrow()).map_err(SqliteClientError::from)
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        wallet::get_block_hash(self.conn.borrow(), block_height).map_err(SqliteClientError::from)
    }

    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        wallet::block_metadata(self.conn.borrow(), &self.params, height)
    }

    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        wallet::block_fully_scanned(self.conn.borrow(), &self.params)
    }

    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        wallet::get_max_height_hash(self.conn.borrow()).map_err(SqliteClientError::from)
    }

    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        wallet::block_max_scanned(self.conn.borrow(), &self.params)
    }

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        wallet::scanning::suggest_scan_ranges(self.conn.borrow(), ScanPriority::Historic)
    }

    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        wallet::get_target_and_anchor_heights(self.conn.borrow(), min_confirmations)
            .map_err(SqliteClientError::from)
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::get_tx_height(self.conn.borrow(), txid).map_err(SqliteClientError::from)
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        wallet::get_unified_full_viewing_keys(self.conn.borrow(), &self.params)
    }

    fn get_memo(&self, note_id: NoteId) -> Result<Option<Memo>, Self::Error> {
        let sent_memo = wallet::get_sent_memo(self.conn.borrow(), note_id)?;
        if sent_memo.is_some() {
            Ok(sent_memo)
        } else {
            wallet::get_received_memo(self.conn.borrow(), note_id)
        }
    }

    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        wallet::get_transaction(self.conn.borrow(), &self.params, txid)
            .map(|res| res.map(|(_, tx)| tx))
    }

    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        wallet::sapling::get_sapling_nullifiers(self.conn.borrow(), query)
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        wallet::orchard::get_orchard_nullifiers(self.conn.borrow(), query)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_receivers(
        &self,
        account: Self::AccountId,
        include_change: bool,
    ) -> Result<HashMap<TransparentAddress, Option<TransparentAddressMetadata>>, Self::Error> {
        let key_scopes: &[KeyScope] = if include_change {
            &[KeyScope::EXTERNAL, KeyScope::INTERNAL]
        } else {
            &[KeyScope::EXTERNAL]
        };

        wallet::transparent::get_transparent_receivers(
            self.conn.borrow(),
            &self.params,
            account,
            key_scopes,
        )
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_balances(
        &self,
        account: Self::AccountId,
        max_height: BlockHeight,
    ) -> Result<HashMap<TransparentAddress, Zatoshis>, Self::Error> {
        wallet::transparent::get_transparent_balances(
            self.conn.borrow(),
            &self.params,
            account,
            max_height,
        )
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_address_metadata(
        &self,
        account: Self::AccountId,
        address: &TransparentAddress,
    ) -> Result<Option<TransparentAddressMetadata>, Self::Error> {
        wallet::transparent::get_transparent_address_metadata(
            self.conn.borrow(),
            &self.params,
            account,
            address,
        )
    }

    #[cfg(feature = "transparent-inputs")]
    fn utxo_query_height(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        let account_ref = wallet::get_account_ref(self.conn.borrow(), account)?;
        wallet::transparent::utxo_query_height(self.conn.borrow(), account_ref, &self.gap_limits)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_known_ephemeral_addresses(
        &self,
        account: Self::AccountId,
        index_range: Option<Range<NonHardenedChildIndex>>,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Self::Error> {
        let account_id = wallet::get_account_ref(self.conn.borrow(), account)?;
        wallet::transparent::ephemeral::get_known_ephemeral_addresses(
            self.conn.borrow(),
            &self.params,
            account_id,
            index_range,
        )
    }

    #[cfg(feature = "transparent-inputs")]
    fn find_account_for_ephemeral_address(
        &self,
        address: &TransparentAddress,
    ) -> Result<Option<Self::AccountId>, Self::Error> {
        wallet::transparent::ephemeral::find_account_for_ephemeral_address_str(
            self.conn.borrow(),
            &address.encode(&self.params),
        )
    }

    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        let iter = wallet::transaction_data_requests(self.conn.borrow())?.into_iter();

        #[cfg(feature = "transparent-inputs")]
        let iter = iter.chain(wallet::transparent::transaction_data_requests(
            self.conn.borrow(),
            &self.params,
        )?);

        Ok(iter.collect())
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
impl<C: Borrow<rusqlite::Connection>, P: consensus::Parameters, CL, R> WalletTest
    for WalletDb<C, P, CL, R>
{
    fn get_tx_history(
        &self,
    ) -> Result<Vec<TransactionSummary<<Self as WalletRead>::AccountId>>, <Self as WalletRead>::Error>
    {
        wallet::testing::get_tx_history(self.conn.borrow())
    }

    fn get_sent_note_ids(
        &self,
        txid: &TxId,
        protocol: ShieldedProtocol,
    ) -> Result<Vec<NoteId>, <Self as WalletRead>::Error> {
        use crate::wallet::encoding::pool_code;

        let mut stmt_sent_notes = self.conn.borrow().prepare(
            "SELECT output_index
             FROM sent_notes
             JOIN transactions ON transactions.id_tx = sent_notes.tx
             WHERE transactions.txid = :txid
             AND sent_notes.output_pool = :pool_code",
        )?;

        let note_ids = stmt_sent_notes
            .query_map(
                named_params! {
                    ":txid": txid.as_ref(),
                    ":pool_code": pool_code(PoolType::Shielded(protocol)),
                },
                |row| Ok(NoteId::new(*txid, protocol, row.get(0)?)),
            )?
            .collect::<Result<_, _>>()?;

        Ok(note_ids)
    }

    fn get_sent_outputs(
        &self,
        txid: &TxId,
    ) -> Result<Vec<OutputOfSentTx>, <Self as WalletRead>::Error> {
        let mut stmt_sent = self.conn.borrow().prepare(
            "SELECT value, to_address,
                    a.cached_transparent_receiver_address, a.transparent_child_index
             FROM sent_notes
             JOIN transactions t ON t.id_tx = sent_notes.tx
             LEFT JOIN transparent_received_outputs tro ON tro.transaction_id = t.id_tx
             LEFT JOIN addresses a ON a.id = tro.address_id AND a.key_scope = :key_scope
             WHERE t.txid = :txid
             ORDER BY value",
        )?;

        let sends = stmt_sent
            .query_map(
                named_params![
                    ":txid": txid.as_ref(),
                    ":key_scope": KeyScope::Ephemeral.encode()
                ],
                |row| {
                    let v = row.get(0)?;
                    let to_address = row
                        .get::<_, Option<String>>(1)?
                        .and_then(|s| Address::decode(&self.params, &s));
                    let ephemeral_address = row
                        .get::<_, Option<String>>(2)?
                        .and_then(|s| Address::decode(&self.params, &s));
                    let address_index: Option<u32> = row.get(3)?;
                    Ok((v, to_address, ephemeral_address.zip(address_index)))
                },
            )?
            .map(|res| {
                let (amount, external_recipient, ephemeral_address) = res?;
                Ok::<_, <Self as WalletRead>::Error>(OutputOfSentTx::from_parts(
                    Zatoshis::from_u64(amount)?,
                    external_recipient,
                    ephemeral_address,
                ))
            })
            .collect::<Result<_, _>>()?;

        Ok(sends)
    }

    fn get_checkpoint_history(
        &self,
        protocol: &ShieldedProtocol,
    ) -> Result<
        Vec<(BlockHeight, Option<incrementalmerkletree::Position>)>,
        <Self as WalletRead>::Error,
    > {
        wallet::testing::get_checkpoint_history(self.conn.borrow(), protocol)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_output(
        &self,
        outpoint: &OutPoint,
        allow_unspendable: bool,
    ) -> Result<Option<WalletTransparentOutput>, <Self as InputSource>::Error> {
        wallet::transparent::get_wallet_transparent_output(
            self.conn.borrow(),
            outpoint,
            allow_unspendable,
        )
    }

    fn get_notes(
        &self,
        protocol: ShieldedProtocol,
    ) -> Result<Vec<ReceivedNote<Self::NoteRef, Note>>, <Self as InputSource>::Error> {
        let (table_prefix, index_col, _) = wallet::common::per_protocol_names(protocol);
        let mut stmt_received_notes = self.conn.borrow().prepare(&format!(
            "SELECT txid, {index_col}
             FROM {table_prefix}_received_notes rn
             INNER JOIN transactions ON transactions.id_tx = rn.tx
             WHERE transactions.block IS NOT NULL
             AND recipient_key_scope IS NOT NULL
             AND nf IS NOT NULL
             AND commitment_tree_position IS NOT NULL"
        ))?;

        let result = stmt_received_notes
            .query_map([], |row| {
                let txid: [u8; 32] = row.get(0)?;
                let output_index: u32 = row.get(1)?;
                let note = self
                    .get_spendable_note(&TxId::from_bytes(txid), protocol, output_index)
                    .unwrap()
                    .unwrap();
                Ok(note)
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(result)
    }
}

impl<C: BorrowMut<rusqlite::Connection>, P: consensus::Parameters, CL: Clock, R> WalletWrite
    for WalletDb<C, P, CL, R>
{
    type UtxoRef = UtxoId;

    fn create_account(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(Self::AccountId, UnifiedSpendingKey), Self::Error> {
        self.borrow_mut().transactionally(|wdb| {
            let seed_fingerprint =
                SeedFingerprint::from_seed(seed.expose_secret()).ok_or_else(|| {
                    SqliteClientError::BadAccountData(
                        "Seed must be between 32 and 252 bytes in length.".to_owned(),
                    )
                })?;
            let zip32_account_index =
                wallet::max_zip32_account_index(wdb.conn.0, &seed_fingerprint)?
                    .map(|a| {
                        a.next()
                            .ok_or(SqliteClientError::Zip32AccountIndexOutOfRange)
                    })
                    .transpose()?
                    .unwrap_or(zip32::AccountId::ZERO);

            let usk = UnifiedSpendingKey::from_seed(
                &wdb.params,
                seed.expose_secret(),
                zip32_account_index,
            )
            .map_err(|_| SqliteClientError::KeyDerivationError(zip32_account_index))?;
            let ufvk = usk.to_unified_full_viewing_key();

            let account = wallet::add_account(
                wdb.conn.0,
                &wdb.params,
                account_name,
                &AccountSource::Derived {
                    derivation: Zip32Derivation::new(seed_fingerprint, zip32_account_index),
                    key_source: key_source.map(|s| s.to_owned()),
                },
                wallet::ViewingKey::Full(Box::new(ufvk)),
                birthday,
                #[cfg(feature = "transparent-inputs")]
                &wdb.gap_limits,
            )?;

            Ok((account.id(), usk))
        })
    }

    fn import_account_hd(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        account_index: zip32::AccountId,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(Self::Account, UnifiedSpendingKey), Self::Error> {
        self.transactionally(|wdb| {
            let seed_fingerprint =
                SeedFingerprint::from_seed(seed.expose_secret()).ok_or_else(|| {
                    SqliteClientError::BadAccountData(
                        "Seed must be between 32 and 252 bytes in length.".to_owned(),
                    )
                })?;

            let usk =
                UnifiedSpendingKey::from_seed(&wdb.params, seed.expose_secret(), account_index)
                    .map_err(|_| SqliteClientError::KeyDerivationError(account_index))?;
            let ufvk = usk.to_unified_full_viewing_key();

            let account = wallet::add_account(
                wdb.conn.0,
                &wdb.params,
                account_name,
                &AccountSource::Derived {
                    derivation: Zip32Derivation::new(seed_fingerprint, account_index),
                    key_source: key_source.map(|s| s.to_owned()),
                },
                wallet::ViewingKey::Full(Box::new(ufvk)),
                birthday,
                #[cfg(feature = "transparent-inputs")]
                &wdb.gap_limits,
            )?;

            Ok((account, usk))
        })
    }

    fn import_account_ufvk(
        &mut self,
        account_name: &str,
        ufvk: &UnifiedFullViewingKey,
        birthday: &AccountBirthday,
        purpose: AccountPurpose,
        key_source: Option<&str>,
    ) -> Result<Self::Account, Self::Error> {
        self.transactionally(|wdb| {
            wallet::add_account(
                wdb.conn.0,
                &wdb.params,
                account_name,
                &AccountSource::Imported {
                    purpose,
                    key_source: key_source.map(|s| s.to_owned()),
                },
                wallet::ViewingKey::Full(Box::new(ufvk.to_owned())),
                birthday,
                #[cfg(feature = "transparent-inputs")]
                &wdb.gap_limits,
            )
        })
    }

    fn get_next_available_address(
        &mut self,
        account_uuid: Self::AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, Self::Error> {
        self.transactionally(|wdb| {
            wallet::get_next_available_address(
                wdb.conn.0,
                &wdb.params,
                &wdb.clock,
                account_uuid,
                request,
                #[cfg(feature = "transparent-inputs")]
                &wdb.gap_limits,
            )
        })
    }

    fn get_address_for_index(
        &mut self,
        account: Self::AccountId,
        diversifier_index: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        if let Some(account) = self.get_account(account)? {
            use zcash_keys::keys::AddressGenerationError::*;

            match account.uivk().address(diversifier_index, request) {
                Ok(address) => {
                    let chain_tip_height = wallet::chain_tip_height(self.conn.borrow())?;
                    upsert_address(
                        self.conn.borrow(),
                        &self.params,
                        account.internal_id(),
                        diversifier_index,
                        &address,
                        Some(chain_tip_height.unwrap_or(account.birthday())),
                        true,
                    )?;

                    Ok(Some(address))
                }
                #[cfg(feature = "transparent-inputs")]
                Err(InvalidTransparentChildIndex(_)) => Ok(None),
                Err(InvalidSaplingDiversifierIndex(_)) => Ok(None),
                Err(e) => Err(SqliteClientError::AddressGeneration(e)),
            }
        } else {
            Err(SqliteClientError::AccountUnknown)
        }
    }

    fn update_chain_tip(&mut self, tip_height: BlockHeight) -> Result<(), Self::Error> {
        let tx = self.conn.borrow_mut().transaction()?;
        wallet::scanning::update_chain_tip(&tx, &self.params, tip_height)?;
        tx.commit()?;
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(height = blocks.first().map(|b| u32::from(b.height())), count = blocks.len()))]
    #[allow(clippy::type_complexity)]
    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<Self::AccountId>>,
    ) -> Result<(), Self::Error> {
        struct BlockPositions {
            height: BlockHeight,
            sapling_start_position: Position,
            #[cfg(feature = "orchard")]
            orchard_start_position: Position,
        }

        if blocks.is_empty() {
            return Ok(());
        }

        self.transactionally(|wdb| {
            let initial_block = blocks.first().expect("blocks is known to be nonempty");
            assert!(from_state.block_height() + 1 == initial_block.height());

            let start_positions = BlockPositions {
                height: initial_block.height(),
                sapling_start_position: Position::from(
                    u64::from(initial_block.sapling().final_tree_size())
                        - u64::try_from(initial_block.sapling().commitments().len()).unwrap(),
                ),
                #[cfg(feature = "orchard")]
                orchard_start_position: Position::from(
                    u64::from(initial_block.orchard().final_tree_size())
                        - u64::try_from(initial_block.orchard().commitments().len()).unwrap(),
                ),
            };

            let mut sapling_commitments = vec![];
            #[cfg(feature = "orchard")]
            let mut orchard_commitments = vec![];
            let mut last_scanned_height = None;
            let mut note_positions = vec![];

            #[cfg(feature = "transparent-inputs")]
            let mut tx_refs = BTreeSet::new();

            for block in blocks.into_iter() {
                if last_scanned_height
                    .iter()
                    .any(|prev| block.height() != *prev + 1)
                {
                    return Err(SqliteClientError::NonSequentialBlocks);
                }

                // Insert the block into the database.
                wallet::put_block(
                    wdb.conn.0,
                    block.height(),
                    block.block_hash(),
                    block.block_time(),
                    block.sapling().final_tree_size(),
                    block.sapling().commitments().len().try_into().unwrap(),
                    #[cfg(feature = "orchard")]
                    block.orchard().final_tree_size(),
                    #[cfg(feature = "orchard")]
                    block.orchard().commitments().len().try_into().unwrap(),
                )?;

                for tx in block.transactions() {
                    let tx_ref = wallet::put_tx_meta(wdb.conn.0, tx, block.height())?;

                    #[cfg(feature = "transparent-inputs")]
                    tx_refs.insert(tx_ref);

                    wallet::queue_tx_retrieval(wdb.conn.0, std::iter::once(tx.txid()), None)?;

                    // Mark notes as spent and remove them from the scanning cache
                    for spend in tx.sapling_spends() {
                        wallet::sapling::mark_sapling_note_spent(wdb.conn.0, tx_ref, spend.nf())?;
                    }
                    #[cfg(feature = "orchard")]
                    for spend in tx.orchard_spends() {
                        wallet::orchard::mark_orchard_note_spent(wdb.conn.0, tx_ref, spend.nf())?;
                    }

                    for output in tx.sapling_outputs() {
                        // Check whether this note was spent in a later block range that
                        // we previously scanned.
                        let spent_in = output
                            .nf()
                            .map(|nf| {
                                wallet::query_nullifier_map(
                                    wdb.conn.0,
                                    ShieldedProtocol::Sapling,
                                    nf,
                                )
                            })
                            .transpose()?
                            .flatten();

                        wallet::sapling::put_received_note(
                            wdb.conn.0,
                            &wdb.params,
                            output,
                            tx_ref,
                            Some(block.height()),
                            spent_in,
                        )?;
                    }
                    #[cfg(feature = "orchard")]
                    for output in tx.orchard_outputs() {
                        // Check whether this note was spent in a later block range that
                        // we previously scanned.
                        let spent_in = output
                            .nf()
                            .map(|nf| {
                                wallet::query_nullifier_map(
                                    wdb.conn.0,
                                    ShieldedProtocol::Orchard,
                                    &nf.to_bytes(),
                                )
                            })
                            .transpose()?
                            .flatten();

                        wallet::orchard::put_received_note(
                            wdb.conn.0,
                            &wdb.params,
                            output,
                            tx_ref,
                            Some(block.height()),
                            spent_in,
                        )?;
                    }
                }

                // Insert the new nullifiers from this block into the nullifier map.
                wallet::insert_nullifier_map(
                    wdb.conn.0,
                    block.height(),
                    ShieldedProtocol::Sapling,
                    block.sapling().nullifier_map(),
                )?;
                #[cfg(feature = "orchard")]
                wallet::insert_nullifier_map(
                    wdb.conn.0,
                    block.height(),
                    ShieldedProtocol::Orchard,
                    &block
                        .orchard()
                        .nullifier_map()
                        .iter()
                        .map(|(txid, idx, nfs)| {
                            (*txid, *idx, nfs.iter().map(|nf| nf.to_bytes()).collect())
                        })
                        .collect::<Vec<_>>(),
                )?;

                note_positions.extend(block.transactions().iter().flat_map(|wtx| {
                    let iter = wtx.sapling_outputs().iter().map(|out| {
                        (
                            ShieldedProtocol::Sapling,
                            out.note_commitment_tree_position(),
                        )
                    });
                    #[cfg(feature = "orchard")]
                    let iter = iter.chain(wtx.orchard_outputs().iter().map(|out| {
                        (
                            ShieldedProtocol::Orchard,
                            out.note_commitment_tree_position(),
                        )
                    }));

                    iter
                }));

                last_scanned_height = Some(block.height());
                let block_commitments = block.into_commitments();
                trace!(
                    "Sapling commitments for {:?}: {:?}",
                    last_scanned_height,
                    block_commitments
                        .sapling
                        .iter()
                        .map(|(_, r)| *r)
                        .collect::<Vec<_>>()
                );
                #[cfg(feature = "orchard")]
                trace!(
                    "Orchard commitments for {:?}: {:?}",
                    last_scanned_height,
                    block_commitments
                        .orchard
                        .iter()
                        .map(|(_, r)| *r)
                        .collect::<Vec<_>>()
                );

                sapling_commitments.extend(block_commitments.sapling.into_iter().map(Some));
                #[cfg(feature = "orchard")]
                orchard_commitments.extend(block_commitments.orchard.into_iter().map(Some));
            }

            #[cfg(feature = "transparent-inputs")]
            for (account_id, key_scope) in wallet::involved_accounts(wdb.conn.0, tx_refs)? {
                use ReceiverRequirement::*;
                wallet::transparent::generate_gap_addresses(
                    wdb.conn.0,
                    &wdb.params,
                    account_id,
                    key_scope,
                    &wdb.gap_limits,
                    UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
                    false,
                )?;
            }

            // Prune the nullifier map of entries we no longer need.
            if let Some(meta) = wdb.block_fully_scanned()? {
                wallet::prune_nullifier_map(
                    wdb.conn.0,
                    meta.block_height().saturating_sub(PRUNING_DEPTH),
                )?;
            }

            // We will have a start position and a last scanned height in all cases where
            // `blocks` is non-empty.
            if let Some(last_scanned_height) = last_scanned_height {
                // Create subtrees from the note commitments in parallel.
                const CHUNK_SIZE: usize = 1024;
                let sapling_subtrees = sapling_commitments
                    .par_chunks_mut(CHUNK_SIZE)
                    .enumerate()
                    .filter_map(|(i, chunk)| {
                        let start =
                            start_positions.sapling_start_position + (i * CHUNK_SIZE) as u64;
                        let end = start + chunk.len() as u64;

                        shardtree::LocatedTree::from_iter(
                            start..end,
                            SAPLING_SHARD_HEIGHT.into(),
                            chunk.iter_mut().map(|n| n.take().expect("always Some")),
                        )
                    })
                    .map(|res| (res.subtree, res.checkpoints))
                    .collect::<Vec<_>>();

                #[cfg(feature = "orchard")]
                let orchard_subtrees = orchard_commitments
                    .par_chunks_mut(CHUNK_SIZE)
                    .enumerate()
                    .filter_map(|(i, chunk)| {
                        let start =
                            start_positions.orchard_start_position + (i * CHUNK_SIZE) as u64;
                        let end = start + chunk.len() as u64;

                        shardtree::LocatedTree::from_iter(
                            start..end,
                            ORCHARD_SHARD_HEIGHT.into(),
                            chunk.iter_mut().map(|n| n.take().expect("always Some")),
                        )
                    })
                    .map(|res| (res.subtree, res.checkpoints))
                    .collect::<Vec<_>>();

                // Collect the complete set of Sapling checkpoints
                #[cfg(feature = "orchard")]
                let sapling_checkpoint_positions: BTreeMap<BlockHeight, Position> =
                    sapling_subtrees
                        .iter()
                        .flat_map(|(_, checkpoints)| checkpoints.iter())
                        .map(|(k, v)| (*k, *v))
                        .collect();

                #[cfg(feature = "orchard")]
                let orchard_checkpoint_positions: BTreeMap<BlockHeight, Position> =
                    orchard_subtrees
                        .iter()
                        .flat_map(|(_, checkpoints)| checkpoints.iter())
                        .map(|(k, v)| (*k, *v))
                        .collect();

                #[cfg(feature = "orchard")]
                fn ensure_checkpoints<
                    'a,
                    H,
                    I: Iterator<Item = &'a BlockHeight>,
                    const DEPTH: u8,
                >(
                    // An iterator of checkpoints heights for which we wish to ensure that
                    // checkpoints exists.
                    ensure_heights: I,
                    // The map of checkpoint positions from which we will draw note commitment tree
                    // position information for the newly created checkpoints.
                    existing_checkpoint_positions: &BTreeMap<BlockHeight, Position>,
                    // The frontier whose position will be used for an inserted checkpoint when
                    // there is no preceding checkpoint in existing_checkpoint_positions.
                    state_final_tree: &Frontier<H, DEPTH>,
                ) -> Vec<(BlockHeight, Checkpoint)> {
                    ensure_heights
                        .flat_map(|ensure_height| {
                            existing_checkpoint_positions
                                .range::<BlockHeight, _>(..=*ensure_height)
                                .last()
                                .map_or_else(
                                    || {
                                        Some((
                                            *ensure_height,
                                            state_final_tree
                                                .value()
                                                .map_or_else(Checkpoint::tree_empty, |t| {
                                                    Checkpoint::at_position(t.position())
                                                }),
                                        ))
                                    },
                                    |(existing_checkpoint_height, position)| {
                                        if *existing_checkpoint_height < *ensure_height {
                                            Some((
                                                *ensure_height,
                                                Checkpoint::at_position(*position),
                                            ))
                                        } else {
                                            // The checkpoint already exists, so we don't need to
                                            // do anything.
                                            None
                                        }
                                    },
                                )
                                .into_iter()
                        })
                        .collect::<Vec<_>>()
                }

                #[cfg(feature = "orchard")]
                let (missing_sapling_checkpoints, missing_orchard_checkpoints) = (
                    ensure_checkpoints(
                        orchard_checkpoint_positions.keys(),
                        &sapling_checkpoint_positions,
                        from_state.final_sapling_tree(),
                    ),
                    ensure_checkpoints(
                        sapling_checkpoint_positions.keys(),
                        &orchard_checkpoint_positions,
                        from_state.final_orchard_tree(),
                    ),
                );

                // Update the Sapling note commitment tree with all newly read note commitments
                {
                    let mut sapling_subtrees_iter = sapling_subtrees.into_iter();
                    wdb.with_sapling_tree_mut::<_, _, Self::Error>(|sapling_tree| {
                        debug!(
                            "Sapling initial tree size at {:?}: {:?}",
                            from_state.block_height(),
                            from_state.final_sapling_tree().tree_size()
                        );
                        // We insert the frontier with `Checkpoint` retention because we need to be
                        // able to truncate the tree back to this point.
                        sapling_tree.insert_frontier(
                            from_state.final_sapling_tree().clone(),
                            Retention::Checkpoint {
                                id: from_state.block_height(),
                                marking: Marking::Reference,
                            },
                        )?;

                        for (tree, checkpoints) in &mut sapling_subtrees_iter {
                            sapling_tree.insert_tree(tree, checkpoints)?;
                        }

                        // Ensure we have a Sapling checkpoint for each checkpointed Orchard block height.
                        // We skip all checkpoints below the minimum retained checkpoint in the
                        // Sapling tree, because branches below this height may be pruned.
                        #[cfg(feature = "orchard")]
                        {
                            let min_checkpoint_height = sapling_tree
                                .store()
                                .min_checkpoint_id()
                                .map_err(ShardTreeError::Storage)?
                                .expect(
                                    "At least one checkpoint was inserted (by insert_frontier)",
                                );

                            for (height, checkpoint) in &missing_sapling_checkpoints {
                                if *height > min_checkpoint_height {
                                    sapling_tree
                                        .store_mut()
                                        .add_checkpoint(*height, checkpoint.clone())
                                        .map_err(ShardTreeError::Storage)?;
                                }
                            }
                        }

                        Ok(())
                    })?;
                }

                // Update the Orchard note commitment tree with all newly read note commitments
                #[cfg(feature = "orchard")]
                {
                    let mut orchard_subtrees = orchard_subtrees.into_iter();
                    wdb.with_orchard_tree_mut::<_, _, Self::Error>(|orchard_tree| {
                        debug!(
                            "Orchard initial tree size at {:?}: {:?}",
                            from_state.block_height(),
                            from_state.final_orchard_tree().tree_size()
                        );
                        // We insert the frontier with `Checkpoint` retention because we need to be
                        // able to truncate the tree back to this point.
                        orchard_tree.insert_frontier(
                            from_state.final_orchard_tree().clone(),
                            Retention::Checkpoint {
                                id: from_state.block_height(),
                                marking: Marking::Reference,
                            },
                        )?;

                        for (tree, checkpoints) in &mut orchard_subtrees {
                            orchard_tree.insert_tree(tree, checkpoints)?;
                        }

                        // Ensure we have an Orchard checkpoint for each checkpointed Sapling block height.
                        // We skip all checkpoints below the minimum retained checkpoint in the
                        // Orchard tree, because branches below this height may be pruned.
                        {
                            let min_checkpoint_height = orchard_tree
                                .store()
                                .min_checkpoint_id()
                                .map_err(ShardTreeError::Storage)?
                                .expect(
                                    "At least one checkpoint was inserted (by insert_frontier)",
                                );

                            for (height, checkpoint) in &missing_orchard_checkpoints {
                                if *height > min_checkpoint_height {
                                    debug!(
                                        "Adding missing Orchard checkpoint for height: {:?}: {:?}",
                                        height,
                                        checkpoint.position()
                                    );
                                    orchard_tree
                                        .store_mut()
                                        .add_checkpoint(*height, checkpoint.clone())
                                        .map_err(ShardTreeError::Storage)?;
                                }
                            }
                        }
                        Ok(())
                    })?;
                }

                wallet::scanning::scan_complete(
                    wdb.conn.0,
                    &wdb.params,
                    Range {
                        start: start_positions.height,
                        end: last_scanned_height + 1,
                    },
                    &note_positions,
                )?;
            }

            Ok(())
        })
    }

    fn put_received_transparent_utxo(
        &mut self,
        _output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error> {
        #[cfg(feature = "transparent-inputs")]
        return self.transactionally(|wdb| {
            let (account_id, key_scope, utxo_id) =
                wallet::transparent::put_received_transparent_utxo(
                    wdb.conn.0,
                    &wdb.params,
                    _output,
                )?;

            use ReceiverRequirement::*;
            wallet::transparent::generate_gap_addresses(
                wdb.conn.0,
                &wdb.params,
                account_id,
                key_scope,
                &wdb.gap_limits,
                UnifiedAddressRequest::unsafe_custom(Allow, Allow, Require),
                true,
            )?;

            Ok(utxo_id)
        });

        #[cfg(not(feature = "transparent-inputs"))]
        panic!(
            "The wallet must be compiled with the transparent-inputs feature to use this method."
        );
    }

    fn store_decrypted_tx(
        &mut self,
        d_tx: DecryptedTransaction<Self::AccountId>,
    ) -> Result<(), Self::Error> {
        self.transactionally(|wdb| {
            wallet::store_decrypted_tx(
                wdb.conn.0,
                &wdb.params,
                d_tx,
                #[cfg(feature = "transparent-inputs")]
                &wdb.gap_limits,
            )
        })
    }

    fn store_transactions_to_be_sent(
        &mut self,
        transactions: &[SentTransaction<Self::AccountId>],
    ) -> Result<(), Self::Error> {
        self.transactionally(|wdb| {
            for sent_tx in transactions {
                wallet::store_transaction_to_be_sent(wdb.conn.0, &wdb.params, sent_tx)?;
            }
            Ok(())
        })
    }

    fn truncate_to_height(&mut self, max_height: BlockHeight) -> Result<BlockHeight, Self::Error> {
        self.transactionally(|wdb| {
            wallet::truncate_to_height(
                wdb.conn.0,
                &wdb.params,
                #[cfg(feature = "transparent-inputs")]
                &wdb.gap_limits,
                max_height,
            )
        })
    }

    #[cfg(feature = "transparent-inputs")]
    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        account_id: Self::AccountId,
        n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Self::Error> {
        self.transactionally(|wdb| {
            let account_id = wallet::get_account_ref(wdb.conn.0, account_id)?;
            let reserved = wallet::transparent::reserve_next_n_addresses(
                wdb.conn.0,
                &wdb.params,
                account_id,
                KeyScope::Ephemeral,
                wdb.gap_limits.ephemeral(),
                n,
            )?;

            Ok(reserved.into_iter().map(|(_, a, m)| (a, m)).collect())
        })
    }

    fn set_transaction_status(
        &mut self,
        txid: TxId,
        status: data_api::TransactionStatus,
    ) -> Result<(), Self::Error> {
        self.transactionally(|wdb| wallet::set_transaction_status(wdb.conn.0, txid, status))
    }
}

pub(crate) type SaplingShardStore<C> = SqliteShardStore<C, sapling::Node, SAPLING_SHARD_HEIGHT>;
pub(crate) type SaplingCommitmentTree<C> =
    ShardTree<SaplingShardStore<C>, { sapling::NOTE_COMMITMENT_TREE_DEPTH }, SAPLING_SHARD_HEIGHT>;

pub(crate) fn sapling_tree<C>(
    conn: C,
) -> Result<SaplingCommitmentTree<C>, ShardTreeError<commitment_tree::Error>>
where
    SaplingShardStore<C>: ShardStore<H = sapling::Node, CheckpointId = BlockHeight>,
{
    Ok(ShardTree::new(
        SqliteShardStore::from_connection(conn, SAPLING_TABLES_PREFIX)
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?,
        PRUNING_DEPTH.try_into().unwrap(),
    ))
}

#[cfg(feature = "orchard")]
pub(crate) type OrchardShardStore<C> =
    SqliteShardStore<C, orchard::tree::MerkleHashOrchard, ORCHARD_SHARD_HEIGHT>;

#[cfg(feature = "orchard")]
pub(crate) type OrchardCommitmentTree<C> = ShardTree<
    OrchardShardStore<C>,
    { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
    ORCHARD_SHARD_HEIGHT,
>;

#[cfg(feature = "orchard")]
pub(crate) fn orchard_tree<C>(
    conn: C,
) -> Result<OrchardCommitmentTree<C>, ShardTreeError<commitment_tree::Error>>
where
    OrchardShardStore<C>:
        ShardStore<H = orchard::tree::MerkleHashOrchard, CheckpointId = BlockHeight>,
{
    Ok(ShardTree::new(
        SqliteShardStore::from_connection(conn, ORCHARD_TABLES_PREFIX)
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?,
        PRUNING_DEPTH.try_into().unwrap(),
    ))
}

impl<C: BorrowMut<rusqlite::Connection>, P: consensus::Parameters, CL, R> WalletCommitmentTrees
    for WalletDb<C, P, CL, R>
{
    type Error = commitment_tree::Error;
    type SaplingShardStore<'a> = SaplingShardStore<&'a rusqlite::Transaction<'a>>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F:
            FnMut(&'a mut SaplingCommitmentTree<&'a rusqlite::Transaction<'a>>) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        let tx = self
            .conn
            .borrow_mut()
            .transaction()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        let result = {
            let mut shardtree = sapling_tree(&tx)?;
            callback(&mut shardtree)?
        };

        tx.commit()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        Ok(result)
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        let tx = self
            .conn
            .borrow_mut()
            .transaction()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        put_shard_roots::<_, { sapling::NOTE_COMMITMENT_TREE_DEPTH }, SAPLING_SHARD_HEIGHT>(
            &tx,
            SAPLING_TABLES_PREFIX,
            start_index,
            roots,
        )?;
        tx.commit()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        Ok(())
    }

    #[cfg(feature = "orchard")]
    type OrchardShardStore<'a> = SqliteShardStore<
        &'a rusqlite::Transaction<'a>,
        orchard::tree::MerkleHashOrchard,
        ORCHARD_SHARD_HEIGHT,
    >;

    #[cfg(feature = "orchard")]
    fn with_orchard_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F:
            FnMut(&'a mut OrchardCommitmentTree<&'a rusqlite::Transaction<'a>>) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        let tx = self
            .conn
            .borrow_mut()
            .transaction()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        let result = {
            let mut shardtree = orchard_tree(&tx)?;
            callback(&mut shardtree)?
        };

        tx.commit()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        Ok(result)
    }

    #[cfg(feature = "orchard")]
    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        let tx = self
            .conn
            .borrow_mut()
            .transaction()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        put_shard_roots::<_, { ORCHARD_SHARD_HEIGHT * 2 }, ORCHARD_SHARD_HEIGHT>(
            &tx,
            ORCHARD_TABLES_PREFIX,
            start_index,
            roots,
        )?;
        tx.commit()
            .map_err(|e| ShardTreeError::Storage(commitment_tree::Error::Query(e)))?;
        Ok(())
    }
}

impl<P: consensus::Parameters, CL, R> WalletCommitmentTrees
    for WalletDb<SqlTransaction<'_>, P, CL, R>
{
    type Error = commitment_tree::Error;
    type SaplingShardStore<'a> = crate::SaplingShardStore<&'a rusqlite::Transaction<'a>>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F:
            FnMut(&'a mut SaplingCommitmentTree<&'a rusqlite::Transaction<'a>>) -> Result<A, E>,
        E: From<ShardTreeError<commitment_tree::Error>>,
    {
        let mut shardtree = sapling_tree(self.conn.0)?;
        let result = callback(&mut shardtree)?;

        Ok(result)
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        put_shard_roots::<_, { sapling::NOTE_COMMITMENT_TREE_DEPTH }, SAPLING_SHARD_HEIGHT>(
            self.conn.0,
            SAPLING_TABLES_PREFIX,
            start_index,
            roots,
        )
    }

    #[cfg(feature = "orchard")]
    type OrchardShardStore<'a> = crate::OrchardShardStore<&'a rusqlite::Transaction<'a>>;

    #[cfg(feature = "orchard")]
    fn with_orchard_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F:
            FnMut(&'a mut OrchardCommitmentTree<&'a rusqlite::Transaction<'a>>) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        let mut shardtree = orchard_tree(self.conn.0)?;
        let result = callback(&mut shardtree)?;

        Ok(result)
    }

    #[cfg(feature = "orchard")]
    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        put_shard_roots::<_, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }, ORCHARD_SHARD_HEIGHT>(
            self.conn.0,
            ORCHARD_TABLES_PREFIX,
            start_index,
            roots,
        )
    }
}

/// A handle for the SQLite block source.
pub struct BlockDb(Connection);

impl BlockDb {
    /// Opens a connection to the wallet database stored at the specified path.
    pub fn for_path<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        Connection::open(path).map(BlockDb)
    }
}

impl BlockSource for BlockDb {
    type Error = SqliteClientError;

    fn with_blocks<F, DbErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        with_row: F,
    ) -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error>>,
    {
        chain::blockdb_with_blocks(self, from_height, limit, with_row)
    }
}

/// A block source that reads block data from disk and block metadata from a SQLite database.
///
/// This block source expects each compact block to be stored on disk in the `blocks` subdirectory
/// of the `blockstore_root` path provided at the time of construction. Each block should be
/// written, as the serialized bytes of its protobuf representation, where the path for each block
/// has the pattern:
///
/// `<blockstore_root>/blocks/<block_height>-<block_hash>-compactblock`
///
/// where `<block_height>` is the decimal value of the height at which the block was mined, and
/// `<block_hash>` is the hexadecimal representation of the block hash, as produced by the
/// [`fmt::Display`] implementation for [`zcash_primitives::block::BlockHash`].
///
/// This block source is intended to be used with the following data flow:
/// * When the cache is being filled:
///   * The caller requests the current maximum height at which cached data is available
///     using [`FsBlockDb::get_max_cached_height`]. If no cached data is available, the caller
///     can use the wallet's synced-to height for the following operations instead.
///   * (recommended for privacy) the caller should round the returned height down to some 100- /
///     1000-block boundary.
///   * The caller uses the lightwalletd's `getblock` gRPC method to obtain a stream of blocks.
///     For each block returned, the caller writes the compact block to `blocks_dir` using the
///     path format specified above. It is fine to overwrite an existing block, since block hashes
///     are immutable and collision-resistant.
///   * Once a caller-determined number of blocks have been successfully written to disk, the
///     caller should invoke [`FsBlockDb::write_block_metadata`] with the metadata for each block
///     written to disk.
/// * The cache can then be scanned using the [`BlockSource`] implementation, providing the
///   wallet's synced-to-height as a starting point.
/// * When part of the cache is no longer needed:
///   * The caller determines some height `H` that is the earliest block data it needs to preserve.
///     This might be determined based on where the wallet is fully-synced to, or other heuristics.
///   * The caller searches the defined filesystem folder for all files beginning in `HEIGHT-*` where
///     `HEIGHT < H`, and deletes those files.
///
/// Note: This API is unstable, and may change in the future. In particular, the [`BlockSource`]
/// API and the above description currently assume that scanning is performed in linear block
/// order; this assumption is likely to be weakened and/or removed in a future update.
#[cfg(feature = "unstable")]
pub struct FsBlockDb {
    conn: Connection,
    blocks_dir: PathBuf,
}

/// Errors that can be generated by the filesystem/sqlite-backed
/// block source.
#[derive(Debug)]
#[cfg(feature = "unstable")]
pub enum FsBlockDbError {
    Fs(io::Error),
    Db(rusqlite::Error),
    Protobuf(prost::DecodeError),
    MissingBlockPath(PathBuf),
    InvalidBlockstoreRoot(PathBuf),
    InvalidBlockPath(PathBuf),
    CorruptedData(String),
    CacheMiss(BlockHeight),
}

#[cfg(feature = "unstable")]
impl From<io::Error> for FsBlockDbError {
    fn from(err: io::Error) -> Self {
        FsBlockDbError::Fs(err)
    }
}

#[cfg(feature = "unstable")]
impl From<rusqlite::Error> for FsBlockDbError {
    fn from(err: rusqlite::Error) -> Self {
        FsBlockDbError::Db(err)
    }
}

#[cfg(feature = "unstable")]
impl From<prost::DecodeError> for FsBlockDbError {
    fn from(e: prost::DecodeError) -> Self {
        FsBlockDbError::Protobuf(e)
    }
}

#[cfg(feature = "unstable")]
impl FsBlockDb {
    /// Creates a filesystem-backed block store at the given path.
    ///
    /// This will construct or open a SQLite database at the path
    /// `<fsblockdb_root>/blockmeta.sqlite` and will ensure that a directory exists at
    /// `<fsblockdb_root>/blocks` where this block store will expect to find serialized block
    /// files as described for [`FsBlockDb`].
    ///
    /// An application using this constructor should ensure that they call
    /// [`crate::chain::init::init_blockmeta_db`] at application startup to ensure
    /// that the resulting metadata database is properly initialized and has had all required
    /// migrations applied before use.
    pub fn for_path<P: AsRef<Path>>(fsblockdb_root: P) -> Result<Self, FsBlockDbError> {
        let meta = fs::metadata(&fsblockdb_root).map_err(FsBlockDbError::Fs)?;
        if meta.is_dir() {
            let db_path = fsblockdb_root.as_ref().join("blockmeta.sqlite");
            let blocks_dir = fsblockdb_root.as_ref().join("blocks");
            fs::create_dir_all(&blocks_dir)?;
            Ok(FsBlockDb {
                conn: Connection::open(db_path).map_err(FsBlockDbError::Db)?,
                blocks_dir,
            })
        } else {
            Err(FsBlockDbError::InvalidBlockstoreRoot(
                fsblockdb_root.as_ref().to_path_buf(),
            ))
        }
    }

    /// Returns the maximum height of blocks known to the block metadata database.
    pub fn get_max_cached_height(&self) -> Result<Option<BlockHeight>, FsBlockDbError> {
        Ok(chain::blockmetadb_get_max_cached_height(&self.conn)?)
    }

    /// Adds a set of block metadata entries to the metadata database, overwriting any
    /// existing entries at the given block heights.
    ///
    /// This will return an error if any block file corresponding to one of these metadata records
    /// is absent from the blocks directory.
    pub fn write_block_metadata(&self, block_meta: &[BlockMeta]) -> Result<(), FsBlockDbError> {
        for m in block_meta {
            let block_path = m.block_file_path(&self.blocks_dir);
            match fs::metadata(&block_path) {
                Err(e) => {
                    return Err(match e.kind() {
                        io::ErrorKind::NotFound => FsBlockDbError::MissingBlockPath(block_path),
                        _ => FsBlockDbError::Fs(e),
                    });
                }
                Ok(meta) => {
                    if !meta.is_file() {
                        return Err(FsBlockDbError::InvalidBlockPath(block_path));
                    }
                }
            }
        }

        Ok(chain::blockmetadb_insert(&self.conn, block_meta)?)
    }

    /// Returns the metadata for the block with the given height, if it exists in the
    /// database.
    pub fn find_block(&self, height: BlockHeight) -> Result<Option<BlockMeta>, FsBlockDbError> {
        Ok(chain::blockmetadb_find_block(&self.conn, height)?)
    }

    /// Rewinds the BlockMeta Db to the `block_height` provided.
    ///
    /// This doesn't delete any files referenced by the records
    /// stored in BlockMeta.
    ///
    /// If the requested height is greater than or equal to the height
    /// of the last scanned block, or if the DB is empty, this function
    /// does nothing.
    pub fn truncate_to_height(&self, block_height: BlockHeight) -> Result<(), FsBlockDbError> {
        Ok(chain::blockmetadb_truncate_to_height(
            &self.conn,
            block_height,
        )?)
    }
}

#[cfg(feature = "unstable")]
impl BlockSource for FsBlockDb {
    type Error = FsBlockDbError;

    fn with_blocks<F, DbErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        with_row: F,
    ) -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), data_api::chain::error::Error<DbErrT, Self::Error>>,
    {
        fsblockdb_with_blocks(self, from_height, limit, with_row)
    }
}

#[cfg(feature = "unstable")]
impl std::fmt::Display for FsBlockDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FsBlockDbError::Fs(io_error) => {
                write!(f, "Failed to access the file system: {}", io_error)
            }
            FsBlockDbError::Db(e) => {
                write!(f, "There was a problem with the sqlite db: {}", e)
            }
            FsBlockDbError::Protobuf(e) => {
                write!(f, "Failed to parse protobuf-encoded record: {}", e)
            }
            FsBlockDbError::MissingBlockPath(block_path) => {
                write!(
                    f,
                    "CompactBlock file expected but not found at {}",
                    block_path.display(),
                )
            }
            FsBlockDbError::InvalidBlockstoreRoot(fsblockdb_root) => {
                write!(
                    f,
                    "The block storage root {} is not a directory",
                    fsblockdb_root.display(),
                )
            }
            FsBlockDbError::InvalidBlockPath(block_path) => {
                write!(
                    f,
                    "CompactBlock path {} is not a file",
                    block_path.display(),
                )
            }
            FsBlockDbError::CorruptedData(e) => {
                write!(
                    f,
                    "The block cache has corrupted data and this caused an error: {}",
                    e,
                )
            }
            FsBlockDbError::CacheMiss(height) => {
                write!(
                    f,
                    "Requested height {} does not exist in the block cache",
                    height
                )
            }
        }
    }
}

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use secrecy::{ExposeSecret, Secret, SecretVec};
    use uuid::Uuid;
    use zcash_client_backend::data_api::{
        chain::ChainState,
        testing::{TestBuilder, TestState},
        Account, AccountBirthday, AccountPurpose, AccountSource, WalletRead, WalletTest,
        WalletWrite,
    };
    use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus;

    use crate::{
        error::SqliteClientError, testing::db::TestDbFactory, util::Clock as _,
        wallet::MIN_SHIELDED_DIVERSIFIER_OFFSET, AccountUuid,
    };

    #[cfg(feature = "unstable")]
    use zcash_keys::keys::sapling;

    #[test]
    fn validate_seed() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account = st.test_account().unwrap();

        assert!({
            st.wallet()
                .validate_seed(account.id(), st.test_seed().unwrap())
                .unwrap()
        });

        // check that passing an invalid account results in a failure
        assert!({
            let wrong_account_uuid = AccountUuid(Uuid::nil());
            !st.wallet()
                .validate_seed(wrong_account_uuid, st.test_seed().unwrap())
                .unwrap()
        });

        // check that passing an invalid seed results in a failure
        assert!({
            !st.wallet()
                .validate_seed(account.id(), &SecretVec::new(vec![1u8; 32]))
                .unwrap()
        });
    }

    #[test]
    pub(crate) fn get_next_available_address() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account = st.test_account().cloned().unwrap();

        // We have to have the chain tip height in order to allocate new addresses, to record the
        // exposed-at height.
        st.wallet_mut()
            .update_chain_tip(account.birthday().height())
            .unwrap();

        let current_addr = st
            .wallet()
            .get_last_generated_address_matching(
                account.id(),
                UnifiedAddressRequest::AllAvailableKeys,
            )
            .unwrap();
        assert!(current_addr.is_some());

        let addr2 = st
            .wallet_mut()
            .get_next_available_address(account.id(), UnifiedAddressRequest::AllAvailableKeys)
            .unwrap()
            .map(|(a, _)| a);
        assert!(addr2.is_some());
        assert_ne!(current_addr, addr2);

        let addr2_cur = st
            .wallet()
            .get_last_generated_address_matching(
                account.id(),
                UnifiedAddressRequest::AllAvailableKeys,
            )
            .unwrap();
        assert_eq!(addr2, addr2_cur);

        // Perform similar tests for shielded-only addresses. These should be timestamp-based; we
        // will tick the clock between each generation.
        use zcash_keys::keys::ReceiverRequirement::*;
        #[cfg(feature = "orchard")]
        let shielded_only_request = UnifiedAddressRequest::unsafe_custom(Require, Require, Omit);
        #[cfg(not(feature = "orchard"))]
        let shielded_only_request = UnifiedAddressRequest::unsafe_custom(Omit, Require, Omit);

        let cur_shielded_only = st
            .wallet()
            .get_last_generated_address_matching(account.id(), shielded_only_request)
            .unwrap();
        // If transparent support is disabled, then the previous "transparent-including"
        // addresses were actually shielded-only, so we do have a current address.
        #[cfg(not(feature = "transparent-inputs"))]
        assert_eq!(cur_shielded_only, addr2);
        // If transparent support is enabled, this works as expected.
        #[cfg(feature = "transparent-inputs")]
        assert!(cur_shielded_only.is_none());

        let di_lower = st
            .wallet()
            .db()
            .clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("current time is valid")
            .as_secs()
            .saturating_add(MIN_SHIELDED_DIVERSIFIER_OFFSET);

        let (shielded_only, di) = st
            .wallet_mut()
            .get_next_available_address(account.id(), shielded_only_request)
            .unwrap()
            .expect("generated a shielded-only address");

        // since not every Sapling diversifier index is valid, the resulting index will be bounded
        // by the current time, but may not be equal to it
        assert!(u128::from(di) >= u128::from(di_lower));

        let cur_shielded_only = st
            .wallet()
            .get_last_generated_address_matching(account.id(), shielded_only_request)
            .unwrap()
            .expect("retrieved the last-generated shielded-only address");
        assert_eq!(cur_shielded_only, shielded_only);

        // This gives around a 2^{-32} probability of `di` and `di_2` colliding, which is
        // low enough for unit tests.
        let collision_offset = 32;

        st.wallet_mut()
            .db_mut()
            .clock
            .tick(Duration::from_secs(collision_offset));

        let (shielded_only_2, di_2) = st
            .wallet_mut()
            .get_next_available_address(account.id(), shielded_only_request)
            .unwrap()
            .expect("generated a shielded-only address");
        assert_ne!(shielded_only_2, shielded_only);
        assert!(u128::from(di_2) >= u128::from(di_lower) + u128::from(collision_offset));
    }

    #[test]
    pub(crate) fn import_account_hd_0() {
        let st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .set_account_index(zip32::AccountId::ZERO)
            .build();
        assert_matches!(
            st.test_account().unwrap().account().source(),
            AccountSource::Derived { derivation, .. } if derivation.account_index() == zip32::AccountId::ZERO);
    }

    #[test]
    pub(crate) fn import_account_hd_1_then_2() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .build();

        let birthday = AccountBirthday::from_parts(
            ChainState::empty(st.network().sapling.unwrap() - 1, BlockHash([0; 32])),
            None,
        );

        let seed = Secret::new(vec![0u8; 32]);
        let zip32_index_1 = zip32::AccountId::ZERO.next().unwrap();

        let first = st
            .wallet_mut()
            .import_account_hd("", &seed, zip32_index_1, &birthday, None)
            .unwrap();
        assert_matches!(
            first.0.source(),
            AccountSource::Derived { derivation, .. } if derivation.account_index() == zip32_index_1);

        let zip32_index_2 = zip32_index_1.next().unwrap();
        let second = st
            .wallet_mut()
            .import_account_hd("", &seed, zip32_index_2, &birthday, None)
            .unwrap();
        assert_matches!(
            second.0.source(),
            AccountSource::Derived { derivation, .. } if derivation.account_index() == zip32_index_2);
    }

    fn check_collisions<C, DbT: WalletTest + WalletWrite, P: consensus::Parameters>(
        st: &mut TestState<C, DbT, P>,
        ufvk: &UnifiedFullViewingKey,
        birthday: &AccountBirthday,
        is_account_collision: impl Fn(&<DbT as WalletRead>::Error) -> bool,
    ) where
        DbT::Account: core::fmt::Debug,
    {
        assert_matches!(
            st.wallet_mut()
                .import_account_ufvk("", ufvk, birthday, AccountPurpose::Spending { derivation: None }, None),
            Err(e) if is_account_collision(&e)
        );

        // Remove the transparent component so that we don't have a match on the full UFVK.
        // That should still produce an AccountCollision error.
        #[cfg(feature = "transparent-inputs")]
        {
            assert!(ufvk.transparent().is_some());
            let subset_ufvk = UnifiedFullViewingKey::new(
                None,
                ufvk.sapling().cloned(),
                #[cfg(feature = "orchard")]
                ufvk.orchard().cloned(),
            )
            .unwrap();
            assert_matches!(
                st.wallet_mut().import_account_ufvk(
                    "",
                    &subset_ufvk,
                    birthday,
                    AccountPurpose::Spending { derivation: None },
                    None,
                ),
                Err(e) if is_account_collision(&e)
            );
        }

        // Remove the Orchard component so that we don't have a match on the full UFVK.
        // That should still produce an AccountCollision error.
        #[cfg(feature = "orchard")]
        {
            assert!(ufvk.orchard().is_some());
            let subset_ufvk = UnifiedFullViewingKey::new(
                #[cfg(feature = "transparent-inputs")]
                ufvk.transparent().cloned(),
                ufvk.sapling().cloned(),
                None,
            )
            .unwrap();
            assert_matches!(
                st.wallet_mut().import_account_ufvk(
                    "",
                    &subset_ufvk,
                    birthday,
                    AccountPurpose::Spending { derivation: None },
                    None,
                ),
                Err(e) if is_account_collision(&e)
            );
        }
    }

    #[test]
    pub(crate) fn import_account_hd_1_then_conflicts() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .build();

        let birthday = AccountBirthday::from_parts(
            ChainState::empty(st.network().sapling.unwrap() - 1, BlockHash([0; 32])),
            None,
        );

        let seed = Secret::new(vec![0u8; 32]);
        let zip32_index_1 = zip32::AccountId::ZERO.next().unwrap();

        let (first_account, _) = st
            .wallet_mut()
            .import_account_hd("", &seed, zip32_index_1, &birthday, None)
            .unwrap();
        let ufvk = first_account.ufvk().unwrap();

        assert_matches!(
            st.wallet_mut().import_account_hd("", &seed, zip32_index_1, &birthday, None),
            Err(SqliteClientError::AccountCollision(id)) if id == first_account.id());

        check_collisions(
            &mut st,
            ufvk,
            &birthday,
            |e| matches!(e, SqliteClientError::AccountCollision(id) if *id == first_account.id()),
        );
    }

    #[test]
    pub(crate) fn import_account_ufvk_then_conflicts() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .build();

        let birthday = AccountBirthday::from_parts(
            ChainState::empty(st.network().sapling.unwrap() - 1, BlockHash([0; 32])),
            None,
        );

        let seed = Secret::new(vec![0u8; 32]);
        let zip32_index_0 = zip32::AccountId::ZERO;
        let usk = UnifiedSpendingKey::from_seed(st.network(), seed.expose_secret(), zip32_index_0)
            .unwrap();
        let ufvk = usk.to_unified_full_viewing_key();

        let account = st
            .wallet_mut()
            .import_account_ufvk(
                "",
                &ufvk,
                &birthday,
                AccountPurpose::Spending { derivation: None },
                None,
            )
            .unwrap();
        assert_eq!(
            ufvk.encode(st.network()),
            account.ufvk().unwrap().encode(st.network())
        );

        assert_matches!(
            account.source(),
            AccountSource::Imported {
                purpose: AccountPurpose::Spending { .. },
                ..
            }
        );

        assert_matches!(
            st.wallet_mut().import_account_hd("", &seed, zip32_index_0, &birthday, None),
            Err(SqliteClientError::AccountCollision(id)) if id == account.id());

        check_collisions(
            &mut st,
            &ufvk,
            &birthday,
            |e| matches!(e, SqliteClientError::AccountCollision(id) if *id == account.id()),
        );
    }

    #[test]
    pub(crate) fn create_account_then_conflicts() {
        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .build();

        let birthday = AccountBirthday::from_parts(
            ChainState::empty(st.network().sapling.unwrap() - 1, BlockHash([0; 32])),
            None,
        );

        let seed = Secret::new(vec![0u8; 32]);
        let zip32_index_0 = zip32::AccountId::ZERO;
        let seed_based = st
            .wallet_mut()
            .create_account("", &seed, &birthday, None)
            .unwrap();
        let seed_based_account = st.wallet().get_account(seed_based.0).unwrap().unwrap();
        let ufvk = seed_based_account.ufvk().unwrap();

        assert_matches!(
            st.wallet_mut().import_account_hd("", &seed, zip32_index_0, &birthday, None),
            Err(SqliteClientError::AccountCollision(id)) if id == seed_based.0);

        check_collisions(
            &mut st,
            ufvk,
            &birthday,
            |e| matches!(e, SqliteClientError::AccountCollision(id) if *id == seed_based.0),
        );
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn transparent_receivers() {
        use std::collections::BTreeSet;

        use crate::{
            testing::BlockCache, wallet::transparent::transaction_data_requests, GapLimits,
        };
        use zcash_client_backend::data_api::TransactionDataRequest;

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let account = st.test_account().unwrap();
        let ufvk = account.usk().to_unified_full_viewing_key();
        let (taddr, _) = account.usk().default_transparent_address();
        let birthday = account.birthday().height();
        let account_id = account.id();

        let receivers = st
            .wallet()
            .get_transparent_receivers(account.id(), false)
            .unwrap();

        // The receiver for the default UA should be in the set.
        assert!(receivers.contains_key(
            ufvk.default_address(UnifiedAddressRequest::AllAvailableKeys)
                .expect("A valid default address exists for the UFVK")
                .0
                .transparent()
                .unwrap()
        ));

        // The default t-addr should be in the set.
        assert!(receivers.contains_key(&taddr));

        // The chain tip height must be known in order to query for data requests.
        st.wallet_mut().update_chain_tip(birthday).unwrap();

        // Transaction data requests should include a request for each ephemeral address
        let ephemeral_addrs = st
            .wallet()
            .get_known_ephemeral_addresses(account_id, None)
            .unwrap();

        assert_eq!(
            ephemeral_addrs.len(),
            GapLimits::default().ephemeral() as usize
        );

        st.wallet_mut()
            .db_mut()
            .schedule_ephemeral_address_checks()
            .unwrap();
        let data_requests =
            transaction_data_requests(st.wallet().conn(), &st.wallet().db().params).unwrap();

        let base_time = st.wallet().db().clock.now();
        let day = Duration::from_secs(60 * 60 * 24);
        let mut check_times = BTreeSet::new();
        for (addr, _) in ephemeral_addrs {
            let has_valid_request = data_requests.iter().any(|req| match req {
                TransactionDataRequest::TransactionsInvolvingAddress {
                    address,
                    request_at: Some(t),
                    ..
                } => {
                    *address == addr && *t > base_time && {
                        let t_delta = t.duration_since(base_time).unwrap();
                        // This is an imprecise check; the objective of the randomized time
                        // selection is that all ephemeral address checks be performed within a
                        // day, and that their check times be distinct.
                        let result = t_delta < day && !check_times.contains(t);
                        check_times.insert(*t);
                        result
                    }
                }
                _ => false,
            });

            assert!(has_valid_request);
        }
    }

    #[cfg(feature = "unstable")]
    #[test]
    pub(crate) fn fsblockdb_api() {
        use zcash_client_backend::data_api::testing::AddressType;
        use zcash_protocol::{consensus::NetworkConstants, value::Zatoshis};

        use crate::testing::FsBlockCache;

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(FsBlockCache::new())
            .build();

        // The BlockMeta DB starts off empty.
        assert_eq!(st.cache().get_max_cached_height().unwrap(), None);

        // Generate some fake CompactBlocks.
        let seed = [0u8; 32];
        let hd_account_index = zip32::AccountId::ZERO;
        let extsk = sapling::spending_key(&seed, st.network().coin_type(), hd_account_index);
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let (h1, meta1, _) = st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(5),
        );
        let (h2, meta2, _) = st.generate_next_block(
            &dfvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10),
        );

        // The BlockMeta DB is not updated until we do so explicitly.
        assert_eq!(st.cache().get_max_cached_height().unwrap(), None);

        // Inform the BlockMeta DB about the newly-persisted CompactBlocks.
        st.cache().write_block_metadata(&[meta1, meta2]).unwrap();

        // The BlockMeta DB now sees blocks up to height 2.
        assert_eq!(st.cache().get_max_cached_height().unwrap(), Some(h2),);
        assert_eq!(st.cache().find_block(h1).unwrap(), Some(meta1));
        assert_eq!(st.cache().find_block(h2).unwrap(), Some(meta2));
        assert_eq!(st.cache().find_block(h2 + 1).unwrap(), None);

        // Rewinding to height 1 should cause the metadata for height 2 to be deleted.
        st.cache().truncate_to_height(h1).unwrap();
        assert_eq!(st.cache().get_max_cached_height().unwrap(), Some(h1));
        assert_eq!(st.cache().find_block(h1).unwrap(), Some(meta1));
        assert_eq!(st.cache().find_block(h2).unwrap(), None);
        assert_eq!(st.cache().find_block(h2 + 1).unwrap(), None);
    }
}
