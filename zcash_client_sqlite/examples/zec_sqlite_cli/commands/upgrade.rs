use gumdrop::Options;
use zcash_client_sqlite::{
    chain::init::init_blockmeta_db,
    wallet::init::{init_wallet_db, WalletMigrationError},
    FsBlockDb, WalletDb,
};
use zcash_primitives::consensus::Parameters;

use crate::{
    data::{get_db_paths, get_wallet_seed},
    error,
};

// Options accepted for the `upgrade` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run(
        self,
        params: impl Parameters + 'static,
        wallet_dir: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let (fsblockdb_root, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_cache = FsBlockDb::for_path(fsblockdb_root).map_err(error::Error::from)?;
        let mut db_data = WalletDb::for_path(db_data, params)?;

        init_blockmeta_db(&mut db_cache)?;

        if let Err(e) = init_wallet_db(&mut db_data, None) {
            if matches!(&e, schemer::MigratorError::Migration {
                error, ..
            } if matches!(error, WalletMigrationError::SeedRequired))
            {
                let seed = get_wallet_seed(wallet_dir)?;
                init_wallet_db(&mut db_data, Some(seed))?;
            } else {
                return Err(e.into());
            }
        }

        println!("Wallet successfully upgraded!");
        Ok(())
    }
}
