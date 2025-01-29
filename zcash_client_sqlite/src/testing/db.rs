use ambassador::Delegate;
use rusqlite::Connection;
use std::collections::HashMap;
use std::num::NonZeroU32;
use uuid::Uuid;

use tempfile::NamedTempFile;

use rusqlite::{self};
use secrecy::SecretVec;
use shardtree::{error::ShardTreeError, ShardTree};
use zip32::fingerprint::SeedFingerprint;

use zcash_client_backend::{
    data_api::{
        chain::{ChainState, CommitmentTreeRoot},
        scanning::ScanRange,
        testing::{DataStoreFactory, Reset, TestState},
        *,
    },
    wallet::{Note, NoteId, ReceivedNote, WalletTransparentOutput},
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
    consensus::BlockHeight, local_consensus::LocalNetwork, memo::Memo, value::Zatoshis,
    ShieldedProtocol,
};

use crate::{
    error::SqliteClientError,
    wallet::init::{init_wallet_db, init_wallet_db_internal},
    AccountUuid, WalletDb,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::TransparentAddressMetadata,
    ::transparent::{address::TransparentAddress, bundle::OutPoint, keys::NonHardenedChildIndex},
    core::ops::Range,
};

#[allow(clippy::duplicated_attributes, reason = "False positive")]
#[derive(Delegate)]
#[delegate(InputSource, target = "wallet_db")]
#[delegate(WalletRead, target = "wallet_db")]
#[delegate(WalletTest, target = "wallet_db")]
#[delegate(WalletWrite, target = "wallet_db")]
#[delegate(WalletCommitmentTrees, target = "wallet_db")]
pub(crate) struct TestDb {
    wallet_db: WalletDb<Connection, LocalNetwork>,
    data_file: NamedTempFile,
}

impl TestDb {
    fn from_parts(wallet_db: WalletDb<Connection, LocalNetwork>, data_file: NamedTempFile) -> Self {
        Self {
            wallet_db,
            data_file,
        }
    }

    pub(crate) fn db(&self) -> &WalletDb<Connection, LocalNetwork> {
        &self.wallet_db
    }

    pub(crate) fn db_mut(&mut self) -> &mut WalletDb<Connection, LocalNetwork> {
        &mut self.wallet_db
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.wallet_db.conn
    }

    pub(crate) fn conn_mut(&mut self) -> &mut Connection {
        &mut self.wallet_db.conn
    }

    pub(crate) fn take_data_file(self) -> NamedTempFile {
        self.data_file
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
            run_sqlite3(self.data_file.path(), &format!(r#".dump "{name}""#));
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
        run_sqlite3(self.data_file.path(), command)
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

#[derive(Default)]
pub(crate) struct TestDbFactory {
    target_migrations: Option<Vec<Uuid>>,
}

impl TestDbFactory {
    #[allow(dead_code)]
    pub(crate) fn new(target_migrations: Vec<Uuid>) -> Self {
        Self {
            target_migrations: Some(target_migrations),
        }
    }
}

impl DataStoreFactory for TestDbFactory {
    type Error = ();
    type AccountId = AccountUuid;
    type Account = crate::wallet::Account;
    type DsError = SqliteClientError;
    type DataStore = TestDb;

    fn new_data_store(&self, network: LocalNetwork) -> Result<Self::DataStore, Self::Error> {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), network).unwrap();
        if let Some(migrations) = &self.target_migrations {
            init_wallet_db_internal(&mut db_data, None, migrations, true).unwrap();
        } else {
            init_wallet_db(&mut db_data, None).unwrap();
        }
        Ok(TestDb::from_parts(db_data, data_file))
    }
}

impl Reset for TestDb {
    type Handle = NamedTempFile;

    fn reset<C>(st: &mut TestState<C, Self, LocalNetwork>) -> NamedTempFile {
        let network = *st.network();
        let old_db = std::mem::replace(
            st.wallet_mut(),
            TestDbFactory::default().new_data_store(network).unwrap(),
        );
        old_db.take_data_file()
    }
}
