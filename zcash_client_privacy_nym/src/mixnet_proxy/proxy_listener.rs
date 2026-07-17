//! The server side of the mixnet-proxy backend: a listener that accepts inbound mixnet
//! streams and forwards their bytes to a TCP upstream.
//!
//! An operator runs a [`ProxyListener`] next to a `lightwalletd` (or any TCP service) to
//! make it reachable over the Nym mixnet. Wallets configure a
//! [`MixnetProxyNetwork`](super::MixnetProxyNetwork) with the listener's
//! [`nym_address`](ProxyListener::nym_address) as the [`Recipient`] for that endpoint.
//!
//! The listener multiplexes many concurrent streams over its single mixnet client: each
//! remote `open_stream` is accepted, a TCP connection to the configured upstream is
//! opened, and bytes are pumped in both directions (replies flow back to the dialer over
//! SURBs, so the listener never learns the wallet's mixnet address).
//!
//! The same type is used by this crate's in-process end-to-end test, which points the
//! upstream at a local echo server.

use nym_sdk::mixnet::{MixnetClient, Recipient};
use tokio::{io::copy_bidirectional, net::TcpStream};
use tracing::{debug, warn};

use super::Error;

/// A mixnet-to-TCP forwarding proxy.
///
/// Build one with [`ProxyListener::new_ephemeral`] (or wrap an existing client with
/// [`ProxyListener::with_client`]), publish its [`nym_address`](ProxyListener::nym_address)
/// to wallets, then drive it with [`run`](ProxyListener::run).
pub struct ProxyListener {
    client: MixnetClient,
    upstream: String,
}

impl ProxyListener {
    /// Creates a proxy backed by a fresh ephemeral, no-credentials mixnet client that
    /// forwards accepted streams to `upstream` (a `host:port` string).
    pub async fn new_ephemeral(upstream: impl Into<String>) -> Result<Self, Error> {
        let client = MixnetClient::connect_new().await.map_err(Error::Client)?;
        Ok(Self::with_client(client, upstream))
    }

    /// Wraps an already-connected mixnet `client`, forwarding accepted streams to
    /// `upstream`.
    pub fn with_client(client: MixnetClient, upstream: impl Into<String>) -> Self {
        Self {
            client,
            upstream: upstream.into(),
        }
    }

    /// Returns the mixnet address wallets should use as the [`Recipient`] for the fronted
    /// endpoint.
    pub fn nym_address(&self) -> &Recipient {
        self.client.nym_address()
    }

    /// Runs the accept loop until the mixnet client's router shuts down.
    ///
    /// Each accepted stream is served on its own task: a TCP connection to the upstream is
    /// opened and bytes are copied in both directions. Per-stream failures (e.g. the
    /// upstream being unreachable) are logged and do not stop the loop.
    pub async fn run(self) -> Result<(), Error> {
        let ProxyListener {
            mut client,
            upstream,
        } = self;

        let mut listener = client.listener().map_err(Error::Client)?;
        debug!("mixnet proxy listening, forwarding to {upstream}");

        while let Some(mut stream) = listener.accept().await {
            let upstream = upstream.clone();
            tokio::spawn(async move {
                match TcpStream::connect(&upstream).await {
                    Ok(mut tcp) => {
                        if let Err(e) = copy_bidirectional(&mut stream, &mut tcp).await {
                            debug!("mixnet proxy stream closed: {e}");
                        }
                    }
                    Err(e) => warn!("mixnet proxy could not reach upstream {upstream}: {e}"),
                }
            });
        }

        // Keep the client alive for the whole accept loop; dropping it here tears down the
        // mixnet connection.
        drop(client);
        Ok(())
    }
}
