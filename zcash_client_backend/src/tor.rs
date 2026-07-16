//! Tor support for Zcash wallets.
//!
//! This module provides the Tor (via `arti`) implementation of the crate's
//! backend-agnostic [`crate::privacy`] network-privacy layer. [`Client`] implements
//! [`PrivateNetwork`], and its gRPC, HTTP, and exchange-rate methods delegate to the
//! generic helpers in [`crate::privacy`].

use std::{fmt, io, path::Path};

use arti_client::{DataStream, TorClient, config::TorClientConfigBuilder};
use tor_rtcompat::PreferredRuntime;
use tracing::debug;

use crate::privacy::{Error as PrivacyError, PrivateNetwork};

pub mod http;

// Re-exported so that `tor::DormantMode` continues to resolve for downstream users; it is
// now the crate-owned [`crate::privacy::DormantMode`] rather than `arti_client`'s.
pub use crate::privacy::DormantMode;

/// A Tor client that exposes capabilities designed for Zcash wallets.
#[derive(Clone)]
pub struct Client {
    inner: TorClient<PreferredRuntime>,
}

impl Client {
    /// Creates and bootstraps a Tor client.
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

        Ok(Self { inner })
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
    #[must_use]
    pub fn isolated_client(&self) -> Self {
        Self {
            inner: self.inner.isolated_client(),
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
        self.inner.set_dormant(mode.into());
    }

    /// Connects to the `lightwalletd` server at the given endpoint.
    #[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
    pub async fn connect_to_lightwalletd(
        &self,
        endpoint: tonic::transport::Uri,
    ) -> Result<
        crate::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<
            tonic::transport::Channel,
        >,
        Error,
    > {
        self.ensure_bootstrapped().await?;
        Ok(crate::privacy::grpc::connect_to_lightwalletd(self, endpoint).await?)
    }
}

impl PrivateNetwork for Client {
    type Stream = DataStream;

    async fn connect(&self, host: &str, port: u16) -> Result<Self::Stream, PrivacyError> {
        // Ensure the Tor client is bootstrapped before attempting to connect.
        if !self.inner.bootstrap_status().ready_for_traffic() {
            debug!("Re-bootstrapping Tor");
            self.inner
                .bootstrap()
                .await
                .map_err(|e| PrivacyError::Backend(Box::new(e)))?;
            debug!("Tor re-bootstrapped");
        }
        self.inner
            .connect((host, port))
            .await
            .map_err(|e| PrivacyError::Backend(Box::new(e)))
    }

    fn isolated_handle(&self) -> Self {
        self.isolated_client()
    }

    fn set_dormant(&self, mode: DormantMode) {
        self.inner.set_dormant(mode.into());
    }
}

/// Errors that can occur while creating or using a Tor [`Client`].
#[derive(Debug)]
pub enum Error {
    /// The directory passed to [`Client::create`] does not exist.
    MissingTorDirectory,
    #[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
    /// An error occurred while using gRPC-over-Tor.
    Grpc(crate::privacy::grpc::GrpcError),
    /// An error occurred while using HTTP-over-Tor.
    Http(crate::privacy::http::HttpError),
    /// An IO error occurred while interacting with the filesystem.
    Io(io::Error),
    /// A Tor-specific error.
    Tor(arti_client::Error),
    /// A network-privacy backend error not covered by the more specific variants.
    Backend(Box<dyn std::error::Error + Send + Sync + 'static>),
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
            Error::Backend(e) => write!(f, "Network backend error: {e}"),
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
            Error::Backend(e) => Some(e.as_ref()),
        }
    }
}

#[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
impl From<crate::privacy::grpc::GrpcError> for Error {
    fn from(e: crate::privacy::grpc::GrpcError) -> Self {
        Error::Grpc(e)
    }
}

impl From<crate::privacy::http::HttpError> for Error {
    fn from(e: crate::privacy::http::HttpError) -> Self {
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

impl From<PrivacyError> for Error {
    fn from(e: PrivacyError) -> Self {
        match e {
            #[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
            PrivacyError::Grpc(e) => Error::Grpc(e),
            PrivacyError::Http(e) => Error::Http(e),
            PrivacyError::NoRoute { host, port } => {
                Error::Backend(Box::new(PrivacyError::NoRoute { host, port }))
            }
            // The Tor backend nests its native errors as `arti_client::Error`; recover
            // that specific type where possible for a more precise error.
            PrivacyError::Backend(b) => match b.downcast::<arti_client::Error>() {
                Ok(e) => Error::Tor(*e),
                Err(b) => Error::Backend(b),
            },
        }
    }
}
