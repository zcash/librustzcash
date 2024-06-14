//! Tor support for Zcash wallets.

use std::{fmt, io, path::Path};

use arti_client::{config::TorClientConfigBuilder, TorClient};
use tor_rtcompat::PreferredRuntime;
use tracing::debug;

/// A Tor client that exposes capabilities designed for Zcash wallets.
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
    /// Returns an error if `tor_dir` does not exist, or if bootstrapping fails.
    pub async fn create(tor_dir: &Path) -> Result<Self, Error> {
        let runtime = PreferredRuntime::current()?;

        if !tokio::fs::try_exists(tor_dir).await? {
            return Err(Error::MissingTorDirectory);
        }

        let config = TorClientConfigBuilder::from_directories(
            tor_dir.join("arti-data"),
            tor_dir.join("arti-cache"),
        )
        .build()
        .expect("all required fields initialized");

        let client_builder = TorClient::with_runtime(runtime).config(config);

        debug!("Bootstrapping Tor");
        let inner = client_builder.create_bootstrapped().await?;
        debug!("Tor bootstrapped");

        Ok(Self { inner })
    }
}

/// Errors that can occur while creating or using a Tor [`Client`].
#[derive(Debug)]
pub enum Error {
    /// The directory passed to [`Client::create`] does not exist.
    MissingTorDirectory,
    /// An IO error occurred while interacting with the filesystem.
    Io(io::Error),
    /// A Tor-specific error.
    Tor(arti_client::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingTorDirectory => write!(f, "Tor directory is missing"),
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Tor(e) => write!(f, "Tor error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::MissingTorDirectory => None,
            Error::Io(e) => Some(e),
            Error::Tor(e) => Some(e),
        }
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
