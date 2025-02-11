//! Tor support for Zcash wallets.

use std::{fmt, io, path::Path};

use arti_client::{config::TorClientConfigBuilder, TorClient};
use tor_rtcompat::PreferredRuntime;
use tracing::debug;

#[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
mod grpc;

pub mod http;

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
}

/// Errors that can occur while creating or using a Tor [`Client`].
#[derive(Debug)]
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
            Error::Grpc(e) => write!(f, "gRPC-over-Tor error: {}", e),
            Error::Http(e) => write!(f, "HTTP-over-Tor error: {}", e),
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Tor(e) => write!(f, "Tor error: {}", e),
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
