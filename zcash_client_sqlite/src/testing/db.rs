use ambassador::Delegate;
use rusqlite::Connection;
use std::collections::HashMap;
use std::num::NonZeroU32;

use tempfile::NamedTempFile;

use rusqlite::{self};
use secrecy::SecretVec;
use shardtree::{error::ShardTreeError, ShardTree};
use zip32::fingerprint::SeedFingerprint;

use zcash_client_backend::{
    data_api::{
        chain::{ChainState, CommitmentTreeRoot},
        scanning::ScanRange,
        *,
    },
    keys::UnifiedFullViewingKey,
    wallet::{Note, NoteId, ReceivedNote, WalletTransparentOutput},
    ShieldedProtocol,
};
use zcash_keys::{
    address::UnifiedAddress,
    keys::{UnifiedAddressRequest, UnifiedSpendingKey},
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{components::amount::NonNegativeAmount, Transaction, TxId},
};
use zcash_protocol::{consensus::BlockHeight, local_consensus::LocalNetwork, memo::Memo};

use super::{DataStoreFactory, Reset, TestState};
use crate::{wallet::init::init_wallet_db, AccountId, WalletDb};

#[cfg(feature = "transparent-inputs")]
use {
    core::ops::Range,
    crate::TransparentAddressMetadata,
    zcash_primitives::{legacy::TransparentAddress, transaction::components::OutPoint},
};

#[derive(Delegate)]
#[delegate(InputSource, target = "wallet_db")]
#[delegate(WalletRead, target = "wallet_db")]
#[delegate(WalletWrite, target = "wallet_db")]
#[delegate(WalletCommitmentTrees, target = "wallet_db")]
pub(crate) struct TestDb {
    wallet_db: WalletDb<Connection, LocalNetwork>,
    data_file: NamedTempFile,
}

impl TestDb {
    pub(crate) fn from_parts(
        wallet_db: WalletDb<Connection, LocalNetwork>,
        data_file: NamedTempFile,
    ) -> Self {
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

    #[cfg(feature = "unstable")]
    pub(crate) fn data_file(&self) -> &NamedTempFile {
        &self.data_file
    }

    pub(crate) fn take_data_file(self) -> NamedTempFile {
        self.data_file
    }
}

pub(crate) struct TestDbFactory;

impl DataStoreFactory for TestDbFactory {
    type Error = ();
    type AccountId = AccountId;
    type DataStore = TestDb;

    fn new_data_store(&self, network: LocalNetwork) -> Result<Self::DataStore, Self::Error> {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), network).unwrap();
        init_wallet_db(&mut db_data, None).unwrap();
        Ok(TestDb::from_parts(db_data, data_file))
    }
}

impl Reset for TestDb {
    type Handle = NamedTempFile;

    fn reset<C>(st: &mut TestState<C, Self, LocalNetwork>) -> NamedTempFile {
        let network = *st.network();
        let old_db = std::mem::replace(
            &mut st.wallet_data,
            TestDbFactory.new_data_store(network).unwrap(),
        );
        old_db.take_data_file()
    }
}
