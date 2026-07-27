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
    ///
    /// The returned client applies this `Client`'s [`Timeouts`] to every request it makes.
    /// Note that the request deadline bounds the wait for a response's headers, not the
    /// duration of the response itself, so long-running streaming methods such as
    /// `GetBlockRange` are not capped by it; a peer that stalls partway through a stream
    /// is instead detected by the HTTP/2 keep-alive.
    ///
    /// [`Timeouts`]: super::Timeouts
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

        let channel = Endpoint::from(endpoint)
            .connect_timeout(self.timeouts.connect)
            .timeout(self.timeouts.request)
            .http2_keep_alive_interval(self.timeouts.grpc_keepalive_interval)
            .keep_alive_timeout(self.timeouts.grpc_keepalive_timeout)
            .keep_alive_while_idle(false);
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
#[non_exhaustive]
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

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, pending},
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use hyper_util::rt::TokioIo;
    use tokio::io::DuplexStream;
    use tonic::transport::{Endpoint, Uri};
    use tower::Service;

    /// A connector that accepts a connection request and then never completes it, modelling
    /// a Tor circuit that hangs while opening. Unlike the HTTP transport, the gRPC deadlines
    /// live in `tonic`'s `Endpoint`, so this checks that the `connect_timeout` we configure
    /// there actually bounds a connector that never returns.
    #[derive(Clone)]
    struct StallingConnector;

    impl Service<Uri> for StallingConnector {
        // The connector never returns a stream, so this type is only a phantom to satisfy
        // tonic's bounds; `TokioIo<DuplexStream>` is a convenient one that is `Read + Write`.
        type Response = TokioIo<DuplexStream>;
        type Error = std::io::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Uri) -> Self::Future {
            Box::pin(pending::<Result<Self::Response, Self::Error>>())
        }
    }

    /// The gRPC `connect_timeout` must bound a connector that never completes, so a Tor
    /// circuit that hangs on open cannot leave `connect_to_lightwalletd` pending forever.
    /// The outer timeout is a safety net that must not be the one to fire; if it does, the
    /// `connect_timeout` we set on the `Endpoint` is not being applied.
    #[tokio::test(start_paused = true)]
    async fn connect_timeout_bounds_a_stalling_connector() {
        let endpoint = Endpoint::from_static("http://198.51.100.1:8232")
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(60));

        let connect = endpoint.connect_with_connector(StallingConnector);
        let res = tokio::time::timeout(Duration::from_secs(30), connect).await;

        assert!(
            res.is_ok(),
            "connect_timeout did not bound the stalling connector; the 30s safety net fired",
        );
        assert!(
            res.unwrap().is_err(),
            "expected the connect to fail once connect_timeout elapsed",
        );
    }
}
