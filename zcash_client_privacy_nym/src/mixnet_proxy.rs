//! A [`PrivateNetwork`] backed by the Nym Sphinx mixnet, reaching pre-configured
//! endpoints through proxy listeners.
//!
//! [`MixnetProxyNetwork`] sends wallet traffic through the full Nym mixnet (Sphinx mixing
//! plus cover traffic) to a Nym [`Recipient`]. The mixnet is client-to-client, so it
//! cannot dial an arbitrary internet host: every reachable endpoint must be fronted by a
//! [`proxy_listener`] (typically operated next to the `lightwalletd` it serves). The
//! backend is configured with a [`routing table`](MixnetProxyConfig) mapping each
//! `(host, port)` to the [`Recipient`] of its proxy listener.
//!
//! # Privacy semantics
//!
//! For the wallet↔proxy path this backend provides the full Nym mixnet properties:
//! IP-address privacy plus resistance to traffic-analysis by a global passive adversary
//! (Sphinx mixing, cover traffic, per-hop bit-unlinkability). Its limitations are
//! structural, not cryptographic:
//!
//! - It can only reach **pre-configured** endpoints. A [`connect`](PrivateNetwork::connect)
//!   to a `(host, port)` with no configured route returns
//!   [`zcash_client_backend::privacy::Error::NoRoute`].
//! - The final hop (proxy → `lightwalletd`) is an ordinary TCP connection made by the
//!   proxy operator, so it does not hide the wallet's traffic from the proxy. Run the
//!   proxy adjacent to (or co-operated with) the `lightwalletd` it fronts.
//!
//! # Credentials
//!
//! The Nym mixnet currently has a **free tier** that requires no credentials. This backend
//! builds clients in that free, no-credentials mode by default (ephemeral, or with
//! optional persistent storage). This may change as Nym's economics evolve.
//!
//! # Isolation and dormancy
//!
//! - [`PrivateNetwork::isolated_handle`] returns a handle backed by a **fresh ephemeral
//!   [`MixnetClient`]** (a new mixnet identity), genuinely unlinking its subsequent
//!   traffic. The fresh client is built lazily on first use.
//! - [`PrivateNetwork::set_dormant`] with [`DormantMode::Soft`] drops the underlying
//!   mixnet client and rebuilds it lazily on next use. A disconnected Nym mixnet client
//!   **cannot** reconnect, so dormancy is modelled as teardown + rebuild; expect a
//!   multi-second (~5–10s) reconnection cost on the next [`connect`](PrivateNetwork::connect).
//!   (The teardown is a non-graceful drop rather than a full [`MixnetClient::disconnect`],
//!   since `set_dormant` is synchronous.)

use std::{collections::HashMap, fmt, path::PathBuf, sync::Arc, time::Duration};

use nym_sdk::mixnet::{MixnetClient, MixnetClientBuilder, MixnetStream, Recipient, StoragePaths};
use tokio::sync::Mutex as AsyncMutex;

use zcash_client_backend::privacy::{DormantMode, Error as PrivacyError, PrivateNetwork};

pub mod proxy_listener;

/// The `(host, port)` key used by a [`MixnetProxyConfig`] routing table.
///
/// Hosts are compared case-insensitively (they are lower-cased on insertion and lookup).
type RouteKey = (String, u16);

fn route_key(host: &str, port: u16) -> RouteKey {
    (host.to_ascii_lowercase(), port)
}

/// Where a [`MixnetProxyNetwork`]'s mixnet client keeps its identity keys.
#[derive(Clone, Debug)]
enum ClientStorage {
    /// Ephemeral in-memory keys, discarded when the client is dropped. Each build yields a
    /// fresh mixnet identity.
    Ephemeral,
    /// Persistent on-disk keys under the given directory, so the client keeps a stable
    /// mixnet identity across rebuilds.
    Persistent(PathBuf),
}

/// Configuration for a [`MixnetProxyNetwork`].
///
/// A configuration carries the routing table (which endpoints are reachable and through
/// which proxy [`Recipient`]) plus mixnet-client build options. It contains no
/// credentials.
#[derive(Clone)]
pub struct MixnetProxyConfig {
    routes: HashMap<RouteKey, Recipient>,
    reply_surbs: Option<u32>,
    storage: ClientStorage,
    extended_topology: bool,
    ignore_epoch_roles: bool,
    stream_idle_timeout: Option<Duration>,
}

impl Default for MixnetProxyConfig {
    fn default() -> Self {
        Self {
            routes: HashMap::new(),
            reply_surbs: None,
            storage: ClientStorage::Ephemeral,
            extended_topology: false,
            ignore_epoch_roles: false,
            stream_idle_timeout: None,
        }
    }
}

impl MixnetProxyConfig {
    /// Creates an empty configuration (ephemeral client, no routes).
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a route mapping `host:port` to the proxy listener at `recipient`.
    ///
    /// Hosts are matched case-insensitively. Adding a route for an existing `host:port`
    /// replaces the previous recipient.
    #[must_use]
    pub fn route(mut self, host: &str, port: u16, recipient: Recipient) -> Self {
        self.routes.insert(route_key(host, port), recipient);
        self
    }

    /// Sets the number of reply-SURBs attached to each outbound message, which bounds how
    /// much the proxy can send back anonymously before needing more.
    ///
    /// `None` (the default) uses the Nym SDK default (currently 10).
    #[must_use]
    pub fn reply_surbs(mut self, reply_surbs: Option<u32>) -> Self {
        self.reply_surbs = reply_surbs;
        self
    }

    /// Uses persistent on-disk client storage under `dir`, giving the mixnet client a
    /// stable identity across rebuilds.
    ///
    /// By default the client is ephemeral (a fresh identity each build). Note that
    /// [`PrivateNetwork::isolated_handle`] always uses a fresh ephemeral client regardless
    /// of this setting, so that isolation actually unlinks traffic.
    #[must_use]
    pub fn persistent_storage(mut self, dir: PathBuf) -> Self {
        self.storage = ClientStorage::Persistent(dir);
        self
    }

    /// Enables the mixnet client's extended-topology mode (routes to nodes in all roles).
    #[must_use]
    pub fn extended_topology(mut self, enabled: bool) -> Self {
        self.extended_topology = enabled;
        self
    }

    /// Enables the mixnet client's ignore-epoch-roles mode.
    #[must_use]
    pub fn ignore_epoch_roles(mut self, enabled: bool) -> Self {
        self.ignore_epoch_roles = enabled;
        self
    }

    /// Sets the idle timeout after which an inactive stream is torn down.
    ///
    /// The Nym mixnet has no stream close handshake; a much shorter timeout than the
    /// default is usually appropriate for a request/response proxy.
    #[must_use]
    pub fn stream_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.stream_idle_timeout = timeout;
        self
    }

    /// Looks up the proxy [`Recipient`] configured for `host:port`, if any.
    pub fn lookup(&self, host: &str, port: u16) -> Option<Recipient> {
        self.routes.get(&route_key(host, port)).copied()
    }
}

struct Inner {
    config: MixnetProxyConfig,
    /// Forces an ephemeral client regardless of `config.storage` (used by isolated
    /// handles so their traffic is genuinely unlinkable).
    force_ephemeral: bool,
    /// The current mixnet client, built lazily. Guarded by an async mutex because
    /// [`MixnetClient::open_stream`] takes `&mut self`.
    client: AsyncMutex<Option<MixnetClient>>,
}

impl Inner {
    async fn build_client(&self) -> Result<MixnetClient, Error> {
        let ephemeral =
            self.force_ephemeral || matches!(self.config.storage, ClientStorage::Ephemeral);

        if ephemeral {
            let mut builder = MixnetClientBuilder::new_ephemeral()
                .with_extended_topology(self.config.extended_topology)
                .with_ignore_epoch_roles(self.config.ignore_epoch_roles);
            if let Some(timeout) = self.config.stream_idle_timeout {
                builder = builder.with_stream_idle_timeout(timeout);
            }
            builder
                .build()
                .map_err(Error::Client)?
                .connect_to_mixnet()
                .await
                .map_err(Error::Client)
        } else {
            let ClientStorage::Persistent(dir) = &self.config.storage else {
                unreachable!("non-ephemeral storage is always persistent");
            };
            let paths = StoragePaths::new_from_dir(dir).map_err(Error::Storage)?;
            let mut builder = MixnetClientBuilder::new_with_default_storage(paths)
                .await
                .map_err(Error::Client)?
                .with_extended_topology(self.config.extended_topology)
                .with_ignore_epoch_roles(self.config.ignore_epoch_roles);
            if let Some(timeout) = self.config.stream_idle_timeout {
                builder = builder.with_stream_idle_timeout(timeout);
            }
            builder
                .build()
                .map_err(Error::Client)?
                .connect_to_mixnet()
                .await
                .map_err(Error::Client)
        }
    }
}

/// A [`PrivateNetwork`] that reaches pre-configured endpoints over the Nym mixnet.
///
/// Cloning a `MixnetProxyNetwork` yields another handle to the **same** mixnet client;
/// use [`PrivateNetwork::isolated_handle`] for an unlinkable one.
#[derive(Clone)]
pub struct MixnetProxyNetwork {
    inner: Arc<Inner>,
}

impl MixnetProxyNetwork {
    /// Creates a backend from the given configuration. The mixnet client is built lazily
    /// on the first [`connect`](PrivateNetwork::connect) to a configured endpoint.
    pub fn new(config: MixnetProxyConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                force_ephemeral: false,
                client: AsyncMutex::new(None),
            }),
        }
    }
}

impl PrivateNetwork for MixnetProxyNetwork {
    type Stream = MixnetStream;

    async fn connect(&self, host: &str, port: u16) -> Result<Self::Stream, PrivacyError> {
        // Resolve the route before touching the network, so an unconfigured endpoint fails
        // fast (and without building a mixnet client).
        let recipient =
            self.inner
                .config
                .lookup(host, port)
                .ok_or_else(|| PrivacyError::NoRoute {
                    host: host.to_string(),
                    port,
                })?;

        let mut guard = self.inner.client.lock().await;
        if guard.is_none() {
            *guard = Some(
                self.inner
                    .build_client()
                    .await
                    .map_err(|e| PrivacyError::Backend(Box::new(e)))?,
            );
        }
        let client = guard.as_mut().expect("client was just built");

        client
            .open_stream(recipient, self.inner.config.reply_surbs)
            .await
            .map_err(|e| PrivacyError::Backend(Box::new(Error::Client(e))))
    }

    fn isolated_handle(&self) -> Self {
        // A fresh ephemeral client (new mixnet identity) built lazily on first use.
        Self {
            inner: Arc::new(Inner {
                config: self.inner.config.clone(),
                force_ephemeral: true,
                client: AsyncMutex::new(None),
            }),
        }
    }

    fn set_dormant(&self, mode: DormantMode) {
        if let DormantMode::Soft = mode {
            // Best-effort: drop the client so it is rebuilt lazily. If a connection is in
            // progress (the lock is held), skip rather than block.
            if let Ok(mut guard) = self.inner.client.try_lock() {
                *guard = None;
            }
        }
    }
}

/// Errors that can occur while building or using a [`MixnetProxyNetwork`].
#[derive(Debug)]
pub enum Error {
    /// An error from the underlying Nym mixnet client (build, connect, or stream).
    Client(nym_sdk::Error),
    /// An error configuring on-disk persistent client storage.
    Storage(nym_sdk::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Client(e) => write!(f, "Nym mixnet client error: {e}"),
            Error::Storage(e) => write!(f, "Nym mixnet client storage error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Client(e) | Error::Storage(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A syntactically-valid Nym recipient address (`identity.encryption@gateway`), used to
    // exercise config/routing logic without any network.
    const RECIPIENT: &str = "9Rgcp1L6PrX9AgpEmFJb3xJqZUwqB9pFEmz1jgZeCV7T.\
        EXTHrqvpKPqf7NGRLXHf6Q6dqZ1kZ6oNhq1jZ8gDpXNB@\
        2BuMSeq9id13tGVBqEqf1St9YEHnvz4dfGZBqZ8pXsCV";

    fn recipient() -> Recipient {
        RECIPIENT.parse().expect("valid recipient")
    }

    #[test]
    fn recipient_round_trips_through_config() {
        let r = recipient();
        let config = MixnetProxyConfig::new().route("zec.rocks", 443, r);
        assert_eq!(config.lookup("zec.rocks", 443), Some(r));
    }

    #[test]
    fn host_lookup_is_case_insensitive() {
        let config = MixnetProxyConfig::new().route("ZEC.Rocks", 443, recipient());
        assert!(config.lookup("zec.rocks", 443).is_some());
        assert!(config.lookup("ZEC.ROCKS", 443).is_some());
    }

    #[test]
    fn unconfigured_endpoint_has_no_route() {
        let config = MixnetProxyConfig::new().route("zec.rocks", 443, recipient());
        assert_eq!(config.lookup("zec.rocks", 9067), None);
        assert_eq!(config.lookup("other.host", 443), None);
    }

    #[test]
    fn connect_to_unconfigured_endpoint_reports_no_route() {
        let net =
            MixnetProxyNetwork::new(MixnetProxyConfig::new().route("zec.rocks", 443, recipient()));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let err = rt.block_on(async { net.connect("unconfigured.example", 443).await });
        match err {
            Err(PrivacyError::NoRoute { host, port }) => {
                assert_eq!(host, "unconfigured.example");
                assert_eq!(port, 443);
            }
            Ok(_) => panic!("expected NoRoute, but a stream was opened"),
            Err(other) => panic!("expected NoRoute, got {other:?}"),
        }
    }

    // Compile-time check that the backend satisfies the erased `DynPrivateNetwork` layer
    // used by FFI consumers.
    #[test]
    fn is_dyn_private_network() {
        fn assert_dyn<N: zcash_client_backend::privacy::DynPrivateNetwork>() {}
        assert_dyn::<MixnetProxyNetwork>();
    }
}
