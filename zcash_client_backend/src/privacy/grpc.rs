//! gRPC to a `lightwalletd` server over a [`PrivateNetwork`].

use std::{
    error::Error as _,
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};
use tower::Service;
use tracing::debug;

use super::{Error, PrivateNetwork, http};
use crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

/// Connects to the `lightwalletd` server at the given endpoint over the provided
/// [`PrivateNetwork`].
pub async fn connect_to_lightwalletd<N>(
    net: &N,
    endpoint: Uri,
) -> Result<CompactTxStreamerClient<Channel>, Error>
where
    N: PrivateNetwork + Clone + 'static,
{
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
        .connect_with_connector(PrivateNetworkConnector { net: net.clone() })
        .await
        .map_err(GrpcError::Tonic)?;

    Ok(CompactTxStreamerClient::new(conn))
}

struct PrivateNetworkConnector<N> {
    net: N,
}

impl<N: PrivateNetwork + Clone + 'static> Service<Uri> for PrivateNetworkConnector<N> {
    type Response = TokioIo<N::Stream>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, endpoint: Uri) -> Self::Future {
        let net = self.net.clone();

        Box::pin(async move {
            let (_, host, port) = http::parse_url(&endpoint)?;

            debug!("Connecting through privacy backend to {}:{}", host, port);
            let stream = net.connect(&host, port).await?;

            Ok(TokioIo::new(stream))
        })
    }
}

/// Errors that can occur while using gRPC over a [`PrivateNetwork`].
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
