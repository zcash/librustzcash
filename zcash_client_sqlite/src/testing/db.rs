//! An in-memory [`WalletDb`]-backed data store and [`DataStoreFactory`] for the
//! `zcash_client_backend` testing framework.

use ambassador::Delegate;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use rusqlite::Connection;
use std::num::NonZeroU32;
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    time::SystemTime,
};
use uuid::Uuid;

use tempfile::NamedTempFile;

use rusqlite::{self};
use secrecy::SecretVec;
use shardtree::{ShardTree, error::ShardTreeError};

use zcash_client_backend::{
    data_api::{
        TargetValue,
        anchor_retention::AnchorRetentionInterval,
        chain::{ChainState, CommitmentTreeRoot},
        error::{LockError, RewindError},
        scanning::{ScanPriority, ScanRange},
        testing::{DataStoreFactory, Reset, TestState},
        wallet::{ConfirmationsPolicy, TargetHeight, input_selection::LockFilter},
        *,
    },
    wallet::{LockOwner, Note, NoteId, OutputRef, ReceivedNote, WalletTransparentOutput},
};
use zcash_keys::{
    address::UnifiedAddress,
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TxId},
};
use zcash_protocol::{
    ShieldedPool, consensus, consensus::BlockHeight, local_consensus::LocalNetwork, memo::Memo,
    value::Zatoshis,
};
use zip32::DiversifierIndex;

use crate::{
    AccountUuid, WalletDb, error::SqliteClientError, util::testing::FixedClock,
    wallet::init::WalletMigrator,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::TransparentAddressMetadata,
    ::transparent::{address::TransparentAddress, bundle::OutPoint, keys::NonHardenedChildIndex},
    core::ops::Range,
    zcash_client_backend::fees::StandardFeeRule,
    zcash_keys::keys::transparent::gap_limits::GapLimits,
};

/// Tuesday, 25 February 2025 00:00:00Z (the day the clock code was added).
const TEST_EPOCH_SECONDS_OFFSET: Duration = Duration::from_secs(1740441600);

pub(crate) fn test_clock() -> FixedClock {
    FixedClock::new(SystemTime::UNIX_EPOCH + TEST_EPOCH_SECONDS_OFFSET)
}

pub(crate) fn test_rng() -> ChaChaRng {
    ChaChaRng::from_seed([0u8; 32])
}

/// A [`WalletDb`] wrapped as a testing-framework data store: it delegates the wallet traits to the
/// inner database and owns the temporary file backing it.
#[allow(clippy::duplicated_attributes, reason = "False positive")]
#[derive(Delegate)]
#[delegate(InputSource, target = "wallet_db")]
#[delegate(WalletRead, target = "wallet_db")]
#[delegate(WalletTest, target = "wallet_db")]
#[delegate(OutputLockStore, target = "wallet_db")]
#[delegate(WalletWrite, target = "wallet_db")]
#[delegate(WalletCommitmentTrees, target = "wallet_db")]
pub struct TestDb {
    wallet_db: WalletDb<Connection, LocalNetwork, FixedClock, ChaChaRng>,
    data_file: Option<NamedTempFile>,
}

impl TestDb {
    fn from_parts(
        wallet_db: WalletDb<Connection, LocalNetwork, FixedClock, ChaChaRng>,
        data_file: Option<NamedTempFile>,
    ) -> Self {
        Self {
            wallet_db,
            data_file,
        }
    }

    /// The wrapped wallet database.
    pub fn db(&self) -> &WalletDb<Connection, LocalNetwork, FixedClock, ChaChaRng> {
        &self.wallet_db
    }

    /// The wrapped wallet database, mutably.
    pub fn db_mut(&mut self) -> &mut WalletDb<Connection, LocalNetwork, FixedClock, ChaChaRng> {
        &mut self.wallet_db
    }

    /// The wallet database's own SQLite connection, over which a sibling store (a
    /// `pool_migration` store, say) is opened.
    pub fn conn(&self) -> &Connection {
        &self.wallet_db.conn
    }

    /// The wallet database's own SQLite connection, mutably. See [`Self::conn`].
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.wallet_db.conn
    }

    pub(crate) fn take_data_file(self) -> Option<NamedTempFile> {
        self.data_file
    }

    #[allow(dead_code)]
    pub(crate) fn data_file_path(&self) -> &std::path::Path {
        self.data_file
            .as_ref()
            .expect("this test requires a file-backed TestDbFactory")
            .path()
    }

    /// Dump the schema and contents of the given database table, in
    /// sqlite3 ".dump" format. The name of the table must be a static
    /// string. This assumes that `sqlite3` is on your path and that it
    /// invokes a compatible version of sqlite3.
    ///
    /// # Panics
    ///
    /// Panics if `name` contains characters outside `[a-zA-Z_]`.
    #[allow(dead_code)]
    #[cfg(feature = "unstable")]
    pub(crate) fn dump_table(&self, name: &'static str) {
        assert!(name.chars().all(|c| c.is_ascii_alphabetic() || c == '_'));
        unsafe {
            run_sqlite3(self.data_file_path(), &format!(r#".dump "{name}""#));
        }
    }

    /// Print the results of an arbitrary sqlite3 command (with "-safe"
    /// and "-readonly" flags) to stderr. This is completely insecure and
    /// should not be exposed in production. Use of the "-safe" and
    /// "-readonly" flags is intended only to limit *accidental* misuse.
    /// The output is unfiltered, and control codes could mess up your
    /// terminal. This assumes that `sqlite3` is on your path and that it
    /// invokes a compatible version of sqlite3.
    #[allow(dead_code)]
    #[cfg(feature = "unstable")]
    pub(crate) unsafe fn run_sqlite3(&self, command: &str) {
        unsafe { run_sqlite3(self.data_file_path(), command) }
    }
}

#[cfg(feature = "unstable")]
use std::{ffi::OsStr, process::Command};

// See the doc comment for `TestState::run_sqlite3` above.
//
// - `db_path` is the path to the database file.
// - `command` may contain newlines.
#[allow(dead_code)]
#[cfg(feature = "unstable")]
unsafe fn run_sqlite3<S: AsRef<OsStr>>(db_path: S, command: &str) {
    let output = Command::new("sqlite3")
        .arg(db_path)
        .arg("-safe")
        .arg("-readonly")
        .arg(command)
        .output()
        .expect("failed to execute sqlite3 process");

    eprintln!(
        "{}\n------\n{}",
        command,
        String::from_utf8_lossy(&output.stdout)
    );
    if !output.stderr.is_empty() {
        eprintln!(
            "------ stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    eprintln!("------");
}

/// A [`DataStoreFactory`] that builds fresh in-memory [`TestDb`] wallets, optionally migrated only
/// to a given set of migrations rather than all of them.
///
/// Tests that exercise reopening or multiple independent connections can opt into file-backed
/// storage with [`Self::file_backed`].
#[derive(Default)]
pub struct TestDbFactory {
    target_migrations: Option<Vec<Uuid>>,
    file_backed: bool,
}

impl TestDbFactory {
    /// Constructs a factory for tests that require a database file.
    pub fn file_backed() -> Self {
        Self {
            target_migrations: None,
            file_backed: true,
        }
    }
}

impl DataStoreFactory for TestDbFactory {
    type Error = ();
    type AccountId = AccountUuid;
    type Account = crate::wallet::Account;
    type DsError = SqliteClientError;
    type DataStore = TestDb;

    fn new_data_store(
        &self,
        network: LocalNetwork,
        anchor_retention_interval: Option<AnchorRetentionInterval>,
        #[cfg(feature = "transparent-inputs")] gap_limits: Option<GapLimits>,
    ) -> Result<Self::DataStore, Self::Error> {
        let (mut db_data, data_file) = if self.file_backed {
            let data_file = NamedTempFile::new().unwrap();
            let db_data =
                WalletDb::for_path(data_file.path(), network, test_clock(), test_rng()).unwrap();
            (db_data, Some(data_file))
        } else {
            let conn = Connection::open_in_memory().unwrap();
            rusqlite::vtab::array::load_module(&conn).unwrap();
            (
                WalletDb::from_connection(conn, network, test_clock(), test_rng()),
                None,
            )
        };
        if let Some(interval) = anchor_retention_interval {
            db_data = db_data.with_anchor_retention_interval(interval);
        }
        #[cfg(feature = "transparent-inputs")]
        if let Some(gap_limits) = gap_limits {
            db_data = db_data.with_gap_limits(gap_limits);
        }

        let migrator = WalletMigrator::new();
        if let Some(migrations) = &self.target_migrations {
            migrator
                .init_or_migrate_to(&mut db_data, migrations)
                .expect("wallet migration succeeds for test setup with target migrations");
        } else {
            migrator
                .init_or_migrate(&mut db_data)
                .expect("wallet migration succeeds for test setup with default migrations");
        }
        Ok(TestDb::from_parts(db_data, data_file))
    }
}

impl Reset for TestDb {
    type Handle = Option<NamedTempFile>;

    fn reset<C>(st: &mut TestState<C, Self, LocalNetwork>) -> Self::Handle {
        let network = *st.network();
        let anchor_retention_interval = st.wallet().db().anchor_retention_interval;
        #[cfg(feature = "transparent-inputs")]
        let gap_limits = st.wallet().db().gap_limits;
        let old_db = std::mem::replace(
            st.wallet_mut(),
            TestDbFactory::default()
                .new_data_store(
                    network,
                    Some(anchor_retention_interval),
                    #[cfg(feature = "transparent-inputs")]
                    Some(gap_limits),
                )
                .unwrap(),
        );
        old_db.take_data_file()
    }
}
