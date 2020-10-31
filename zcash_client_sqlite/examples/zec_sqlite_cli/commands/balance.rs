use gumdrop::Options;
use zcash_client_backend::data_api::WalletRead;
use zcash_client_sqlite::WalletDb;
use zcash_primitives::{consensus::Parameters, zip32::AccountId};

use crate::{data::get_db_paths, error, MIN_CONFIRMATIONS};

// Options accepted for the `balance` command
#[derive(Debug, Options)]
pub(crate) struct Command {}

impl Command {
    pub(crate) fn run(
        self,
        params: impl Parameters + Copy + 'static,
        wallet_dir: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let account = AccountId::from(0);
        let (_, db_data) = get_db_paths(wallet_dir);
        let db_data = WalletDb::for_path(db_data, params)?;

        let address = db_data
            .get_current_address(account)?
            .ok_or(error::Error::InvalidRecipient)?;
        let (balance, verified_balance) = {
            let (target_height, anchor_height) = db_data
                .get_target_and_anchor_heights(MIN_CONFIRMATIONS)?
                .ok_or(error::WalletErrorT::ScanRequired)?;
            (
                db_data.get_balance_at(account, target_height)?,
                db_data.get_balance_at(account, anchor_height)?,
            )
        };

        println!("{}", address.encode(&params));
        println!("  Balance:  {} zatoshis", u64::from(balance));
        println!("  Verified: {} zatoshis", u64::from(verified_balance));

        Ok(())
    }
}
