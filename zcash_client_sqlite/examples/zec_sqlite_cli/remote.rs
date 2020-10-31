use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

const LIGHTWALLETD_HOST: &str = "lightwalletd.testnet.electriccoin.co";
const LIGHTWALLETD_PORT: u16 = 9067;

pub(crate) async fn connect_to_lightwalletd(
) -> Result<CompactTxStreamerClient<Channel>, anyhow::Error> {
    println!("Connecting to {}:{}", LIGHTWALLETD_HOST, LIGHTWALLETD_PORT);

    let tls = ClientTlsConfig::new().domain_name(LIGHTWALLETD_HOST);

    let channel = Channel::from_shared(format!(
        "https://{}:{}",
        LIGHTWALLETD_HOST, LIGHTWALLETD_PORT
    ))?
    .tls_config(tls)?
    .connect()
    .await?;

    Ok(CompactTxStreamerClient::new(channel))
}
