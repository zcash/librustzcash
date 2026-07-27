//! Tor support for Zcash wallets.

use std::{fmt, io, path::Path, time::Duration};

use arti_client::{TorClient, config::TorClientConfigBuilder};
use tor_rtcompat::PreferredRuntime;
use tracing::debug;

#[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
mod grpc;

pub mod http;

// Re-exported as this is currently the only `arti_client` type users would need to use
// our minimal client API.
pub use arti_client::DormantMode;

/// Deadlines applied to network operations performed by a [`Client`].
///
/// Without these, a server that accepts a connection and then goes silent would leave the
/// corresponding future pending forever. Tor circuits make this more likely than it is on
/// the clearnet: a half-open circuit can persist for a long time without the peer's TCP
/// stack ever delivering a reset.
///
/// Use [`Timeouts::default`] for values suitable for typical Tor circuit latency, or the
/// `with_*` methods to tune them.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    connect: Duration,
    request: Duration,
    response_body: Duration,
    grpc_keepalive_interval: Duration,
    grpc_keepalive_timeout: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(30),
            request: Duration::from_secs(60),
            response_body: Duration::from_secs(60),
            grpc_keepalive_interval: Duration::from_secs(30),
            grpc_keepalive_timeout: Duration::from_secs(20),
        }
    }
}

impl Timeouts {
    /// Sets the maximum time allowed to establish a usable connection to a server.
    ///
    /// This covers opening the Tor stream and, for HTTPS or gRPC-over-TLS endpoints,
    /// completing the TLS handshake.
    ///
    /// The default is 30 seconds.
    #[must_use]
    pub fn with_connect(mut self, timeout: Duration) -> Self {
        self.connect = timeout;
        self
    }

    /// Sets the maximum time allowed to send a request and receive its response headers.
    ///
    /// This does not bound the time taken to receive a response body; see
    /// [`Self::with_response_body`] for HTTP, and [`Self::with_grpc_keepalive`] for gRPC.
    ///
    /// The default is 60 seconds.
    #[must_use]
    pub fn with_request(mut self, timeout: Duration) -> Self {
        self.request = timeout;
        self
    }

    /// Sets the maximum time allowed to receive a complete HTTP response body.
    ///
    /// This is not applied to gRPC responses, because a gRPC response may be a
    /// long-running stream (such as `GetBlockRange`) for which no fixed deadline is
    /// appropriate. Use [`Self::with_grpc_keepalive`] to bound those instead.
    ///
    /// The default is 60 seconds.
    #[must_use]
    pub fn with_response_body(mut self, timeout: Duration) -> Self {
        self.response_body = timeout;
        self
    }

    /// Sets the HTTP/2 keep-alive parameters used for gRPC connections.
    ///
    /// A ping is sent every `interval` while a request is in flight, and the connection is
    /// closed if no acknowledgement is received within `timeout`. This is what detects a
    /// gRPC peer that stalls partway through streaming a response, which no request
    /// deadline can bound without also capping legitimately long streams.
    ///
    /// The defaults are a 30 second interval and a 20 second timeout.
    #[must_use]
    pub fn with_grpc_keepalive(mut self, interval: Duration, timeout: Duration) -> Self {
        self.grpc_keepalive_interval = interval;
        self.grpc_keepalive_timeout = timeout;
        self
    }
}

/// A Tor client that exposes capabilities designed for Zcash wallets.
#[derive(Clone)]
pub struct Client {
    inner: TorClient<PreferredRuntime>,
    timeouts: Timeouts,
}

impl Client {
    /// Creates and bootstraps a Tor client with default [`Timeouts`].
    ///
    /// The client's persistent data and cache are both stored in the given directory.
    /// Preserving the contents of this directory will speed up subsequent calls to
    /// `Client::create`.
    ///
    /// If the `with_permissions` closure does not make any changes (e.g. is
    /// passed as `|_| {}`), the default from [`arti_client`] will be used.
    /// This default will enable permissions checks unless the
    /// `ARTI_FS_DISABLE_PERMISSION_CHECKS` env variable is set.
    ///
    /// Returns an error if `tor_dir` does not exist, or if bootstrapping fails.
    pub async fn create(
        tor_dir: &Path,
        with_permissions: impl FnOnce(&mut fs_mistrust::MistrustBuilder),
    ) -> Result<Self, Error> {
        Self::create_with_timeouts(tor_dir, with_permissions, Timeouts::default()).await
    }

    /// Creates and bootstraps a Tor client that applies the given [`Timeouts`] to its
    /// network operations.
    ///
    /// This is otherwise identical to [`Client::create`]; see its documentation for
    /// details of the other arguments.
    pub async fn create_with_timeouts(
        tor_dir: &Path,
        with_permissions: impl FnOnce(&mut fs_mistrust::MistrustBuilder),
        timeouts: Timeouts,
    ) -> Result<Self, Error> {
        let runtime = PreferredRuntime::current()?;

        if !tokio::fs::try_exists(tor_dir).await? {
            return Err(Error::MissingTorDirectory);
        }

        let mut config_builder = TorClientConfigBuilder::from_directories(
            tor_dir.join("arti-data"),
            tor_dir.join("arti-cache"),
        );

        with_permissions(config_builder.storage().permissions());

        let config = config_builder
            .build()
            .expect("all required fields initialized");

        let client_builder = TorClient::with_runtime(runtime).config(config);

        debug!("Bootstrapping Tor");
        let inner = client_builder.create_bootstrapped().await?;
        debug!("Tor bootstrapped");

        Ok(Self { inner, timeouts })
    }

    /// Ensures the Tor client is bootstrapped.
    ///
    /// This should be called first inside every public method that makes network requests
    /// using the Tor client.
    ///
    /// `Client` ensures it cannot be constructed in an un-bootstrapped state, but Tor
    /// clients can become less bootstrapped over time (for example if it loses its
    /// internet connectivity, or if its directory information expires before it's able to
    /// replace it).
    async fn ensure_bootstrapped(&self) -> Result<(), Error> {
        if !self.inner.bootstrap_status().ready_for_traffic() {
            debug!("Re-bootstrapping Tor");
            self.inner.bootstrap().await?;
            debug!("Tor re-bootstrapped");
        }
        Ok(())
    }

    /// Returns a new isolated `tor::Client` handle.
    ///
    /// The two `tor::Client`s will share internal state and configuration, but their
    /// streams will never share circuits with one another.
    ///
    /// Use this method when you want separate parts of your program to each have a
    /// `tor::Client` handle, but where you don't want their activities to be linkable to
    /// one another over the Tor network.
    ///
    /// Calling this method is usually preferable to creating a completely separate
    /// `tor::Client` instance, since it can share its internals with the existing
    /// `tor::Client`.
    ///
    /// (Connections made with clones of the returned `tor::Client` may share circuits
    /// with each other.)
    ///
    /// The returned handle uses the same [`Timeouts`] as this one.
    #[must_use]
    pub fn isolated_client(&self) -> Self {
        Self {
            inner: self.inner.isolated_client(),
            timeouts: self.timeouts,
        }
    }

    /// Changes the client's current dormant mode, putting background tasks to sleep or
    /// waking them up as appropriate.
    ///
    /// This can be used to conserve CPU usage if you aren’t planning on using the client
    /// for a while, especially on mobile platforms.
    ///
    /// See the [`DormantMode`] documentation for more details.
    pub fn set_dormant(&self, mode: DormantMode) {
        self.inner.set_dormant(mode);
    }
}

/// Errors that can occur while creating or using a Tor [`Client`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The directory passed to [`Client::create`] does not exist.
    MissingTorDirectory,
    #[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
    /// An error occurred while using gRPC-over-Tor.
    Grpc(self::grpc::GrpcError),
    /// An error occurred while using HTTP-over-Tor.
    Http(self::http::HttpError),
    /// An IO error occurred while interacting with the filesystem.
    Io(io::Error),
    /// A Tor-specific error.
    Tor(arti_client::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingTorDirectory => write!(f, "Tor directory is missing"),
            #[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
            Error::Grpc(e) => write!(f, "gRPC-over-Tor error: {e}"),
            Error::Http(e) => write!(f, "HTTP-over-Tor error: {e}"),
            Error::Io(e) => write!(f, "IO error: {e}"),
            Error::Tor(e) => write!(f, "Tor error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::MissingTorDirectory => None,
            #[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
            Error::Grpc(e) => Some(e),
            Error::Http(e) => Some(e),
            Error::Io(e) => Some(e),
            Error::Tor(e) => Some(e),
        }
    }
}

#[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
impl From<self::grpc::GrpcError> for Error {
    fn from(e: self::grpc::GrpcError) -> Self {
        Error::Grpc(e)
    }
}

impl From<self::http::HttpError> for Error {
    fn from(e: self::http::HttpError) -> Self {
        Error::Http(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<arti_client::Error> for Error {
    fn from(e: arti_client::Error) -> Self {
        Error::Tor(e)
    }
}
