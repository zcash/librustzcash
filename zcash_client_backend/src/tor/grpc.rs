use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use arti_client::DataStream;
use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};
use tower::Service;
use tracing::debug;

use super::{http, Client, Error};
use crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

impl Client {
    /// Connects to the `lightwalletd` server at the given endpoint.
    pub async fn connect_to_lightwalletd(
        &self,
        endpoint: Uri,
    ) -> Result<CompactTxStreamerClient<Channel>, Error> {
        let is_https = http::url_is_https(&endpoint)?;

        let channel = Endpoint::from(endpoint);
        let channel = if is_https {
            channel
                .tls_config(ClientTlsConfig::new().with_webpki_roots())
                .map_err(GrpcError::Tonic)?
        } else {
            channel
        };

        let conn = channel
            .connect_with_connector(self.http_tcp_connector())
            .await
            .map_err(GrpcError::Tonic)?;

        Ok(CompactTxStreamerClient::new(conn))
    }

    fn http_tcp_connector(&self) -> HttpTcpConnector {
        HttpTcpConnector {
            client: self.clone(),
        }
    }
}

struct HttpTcpConnector {
    client: Client,
}

impl Service<Uri> for HttpTcpConnector {
    type Response = TokioIo<DataStream>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, endpoint: Uri) -> Self::Future {
        let parsed = http::parse_url(&endpoint);
        let client = self.client.clone();

        let fut = async move {
            let (_, host, port) = parsed?;

            debug!("Connecting through Tor to {}:{}", host, port);
            let stream = client.inner.connect((host.as_str(), port)).await?;

            Ok(TokioIo::new(stream))
        };

        Box::pin(fut)
    }
}

/// Errors that can occurr while using HTTP-over-Tor.
#[derive(Debug)]
pub enum GrpcError {
    /// A [`tonic`] error.
    Tonic(tonic::transport::Error),
}

impl fmt::Display for GrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrpcError::Tonic(e) => write!(f, "Hyper error: {}", e),
        }
    }
}

impl std::error::Error for GrpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GrpcError::Tonic(e) => Some(e),
        }
    }
}

impl From<tonic::transport::Error> for GrpcError {
    fn from(e: tonic::transport::Error) -> Self {
        GrpcError::Tonic(e)
    }
}
