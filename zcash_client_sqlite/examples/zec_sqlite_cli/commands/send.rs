use gumdrop::Options;
use secrecy::ExposeSecret;
use zcash_client_backend::{
    address::RecipientAddress,
    data_api::{
        wallet::{input_selection::GreedyInputSelector, spend},
        WalletRead,
    },
    fees::zip317::SingleOutputChangeStrategy,
    keys::UnifiedSpendingKey,
    proto::service,
    wallet::OvkPolicy,
    zip321::{Payment, TransactionRequest},
};
use zcash_client_sqlite::WalletDb;
use zcash_primitives::{
    consensus::Parameters,
    transaction::{components::Amount, fees::zip317::FeeRule},
    zip32::AccountId,
};
use zcash_proofs::prover::LocalTxProver;

use crate::{
    data::{get_db_paths, get_wallet_seed},
    error,
    remote::connect_to_lightwalletd,
    MIN_CONFIRMATIONS,
};

// Options accepted for the `send` command
#[derive(Debug, Options)]
pub(crate) struct Command {
    #[options(help = "the recipient's Sapling or transparent address")]
    address: String,

    #[options(help = "the amount in zatoshis")]
    value: u64,
}

impl Command {
    pub(crate) async fn run(
        self,
        params: impl Parameters + Copy + 'static,
        wallet_dir: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let account = AccountId::from(0);
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params)?;
        let mut db_data = db_data.get_update_ops()?;

        let seed = get_wallet_seed(wallet_dir)?;
        let usk = UnifiedSpendingKey::from_seed(&params, seed.expose_secret(), account)
            .map_err(error::Error::from)?;

        let mut client = connect_to_lightwalletd().await?;

        // Create the transaction.
        println!("Creating transaction...");
        let prover =
            LocalTxProver::with_default_location().ok_or(error::Error::MissingParameters)?;
        let input_selector = GreedyInputSelector::new(
            SingleOutputChangeStrategy::new(FeeRule::standard()),
            Default::default(),
        );

        let request = TransactionRequest::new(vec![Payment {
            recipient_address: RecipientAddress::decode(&params, &self.address)
                .ok_or(error::Error::InvalidRecipient)?,
            amount: Amount::from_u64(self.value).map_err(|_| error::Error::InvalidAmount)?,
            memo: None,
            label: None,
            message: None,
            other_params: vec![],
        }])
        .map_err(error::Error::from)?;

        let id_tx = spend(
            &mut db_data,
            &params,
            prover,
            &input_selector,
            &usk,
            request,
            OvkPolicy::Sender,
            MIN_CONFIRMATIONS,
        )
        .map_err(error::Error::from)?;

        // Send the transaction.
        println!("Sending transaction...");
        let (txid, raw_tx) = db_data.get_transaction(id_tx).map(|tx| {
            let mut raw_tx = service::RawTransaction::default();
            tx.write(&mut raw_tx.data).unwrap();
            (tx.txid(), raw_tx)
        })?;
        let response = client.send_transaction(raw_tx).await?.into_inner();

        if response.error_code != 0 {
            Err(error::Error::SendFailed {
                code: response.error_code,
                reason: response.error_message,
            }
            .into())
        } else {
            println!("{}", txid);
            Ok(())
        }
    }
}
