use std::{
    error::Error as _,
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use arti_client::{DataStream, StreamPrefs, config::BoolOrAuto};
use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};
use tower::Service;
use tracing::debug;

use super::{Client, Error, http};
use crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

impl Client {
    /// Connects to the `lightwalletd` server at the given endpoint.
    ///
    /// If `allow_onion_services` is `true`, the connection will be permitted to reach
    /// Tor hidden services (`.onion` addresses). The caller is responsible for deciding
    /// whether onion connections are appropriate for the given endpoint; this crate
    /// does not infer that from the endpoint host.
    pub async fn connect_to_lightwalletd(
        &self,
        endpoint: Uri,
        allow_onion_services: bool,
    ) -> Result<CompactTxStreamerClient<Channel>, Error> {
        self.ensure_bootstrapped().await?;

        let is_https = http::url_is_https(&endpoint)?;

        let connector = if allow_onion_services {
            HttpTcpConnector::with_onion_services(self.clone())
        } else {
            HttpTcpConnector::new(self.clone())
        };

        let channel = Endpoint::from(endpoint);
        let channel = if is_https {
            channel
                .tls_config(ClientTlsConfig::new().with_webpki_roots())
                .map_err(GrpcError::Tonic)?
        } else {
            channel
        };

        let conn = channel
            .connect_with_connector(connector)
            .await
            .map_err(GrpcError::Tonic)?;

        Ok(CompactTxStreamerClient::new(conn))
    }
}

struct HttpTcpConnector {
    client: Client,
    prefs: StreamPrefs,
}

impl HttpTcpConnector {
    /// Creates a new `HttpTcpConnector` with default [`StreamPrefs`].
    ///
    /// Connections made through this connector will not attempt to connect to `.onion`
    /// services.
    fn new(client: Client) -> Self {
        HttpTcpConnector {
            client,
            prefs: StreamPrefs::new(),
        }
    }

    /// Creates a new `HttpTcpConnector` that enables connections to `.onion` services.
    ///
    /// Use this constructor when the endpoint host is a Tor hidden service (`.onion`
    /// address). For regular clearnet endpoints, use [`HttpTcpConnector::new`] instead.
    fn with_onion_services(client: Client) -> Self {
        let mut prefs = StreamPrefs::new();
        prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
        HttpTcpConnector { client, prefs }
    }
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
        let prefs = self.prefs.clone();

        let fut = async move {
            let (_, host, port) = parsed?;

            debug!("Connecting through Tor to {}:{}", host, port);
            let stream = client
                .inner
                .connect_with_prefs((host.as_str(), port), &prefs)
                .await?;

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
            GrpcError::Tonic(e) => {
                if let Some(source) = e.source() {
                    // Tonic doesn't include the source error in its `Display` impl;
                    // add it manually for the benefit of our downstreams.
                    write!(f, "Tonic error: {e}: {source}")
                } else {
                    write!(f, "Tonic error: {e}")
                }
            }
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
