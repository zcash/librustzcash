//! Backend-agnostic network privacy for lightwallet clients.
//!
//! Wallets frequently need to hide the network-level metadata (in particular their IP
//! address) that they would otherwise reveal to a `lightwalletd` server or to an exchange
//! rate provider. This module abstracts over the transport that provides this privacy so
//! that the same gRPC, HTTP, and exchange-rate machinery can run over any such transport.
//!
//! The central abstraction is the [`PrivateNetwork`] trait, which exposes the single
//! capability the higher layers require: opening a byte stream to a remote `host:port`.
//! The [`crate::tor`] module provides the reference implementation (Tor, via `arti`);
//! other backends (for example a dVPN tunnel or a mixnet proxy) can be implemented in
//! separate crates without depending on `arti`.
//!
//! Because [`PrivateNetwork`] uses return-position `impl Trait` and an associated stream
//! type, it is not object-safe. FFI layers that need to store a backend behind a pointer
//! can instead use the object-safe [`DynPrivateNetwork`] mirror, for which a blanket
//! implementation is provided for every [`PrivateNetwork`]. `Arc<dyn DynPrivateNetwork>`
//! itself implements [`PrivateNetwork`], so the generic helpers in this module accept
//! either a concrete backend or its erased form.

use std::{fmt, future::Future, pin::Pin, sync::Arc};

use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "lightwalletd-blocking")]
pub mod blocking;
#[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
pub mod grpc;
pub mod http;

/// The level of background activity a [`PrivateNetwork`] should maintain.
///
/// This is a crate-owned generalization of `arti_client::DormantMode`; the [`crate::tor`]
/// backend maps between the two. Backends without a native notion of dormancy may treat a
/// [`DormantMode::Soft`] request as a hint to tear down idle resources and rebuild them
/// lazily on next use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DormantMode {
    /// The backend functions as normal, and background tasks run periodically.
    #[default]
    Normal,
    /// Background tasks are suspended, conserving CPU usage. Attempts to use the backend
    /// will wake it back up again.
    Soft,
}

#[cfg(feature = "tor")]
impl From<DormantMode> for arti_client::DormantMode {
    fn from(mode: DormantMode) -> Self {
        match mode {
            DormantMode::Normal => arti_client::DormantMode::Normal,
            DormantMode::Soft => arti_client::DormantMode::Soft,
        }
    }
}

#[cfg(feature = "tor")]
impl From<arti_client::DormantMode> for DormantMode {
    fn from(mode: arti_client::DormantMode) -> Self {
        match mode {
            arti_client::DormantMode::Soft => DormantMode::Soft,
            // `arti_client::DormantMode` is `#[non_exhaustive]`; treat anything we don't
            // specifically recognise as the fully-awake mode.
            _ => DormantMode::Normal,
        }
    }
}

/// A byte stream produced by a [`PrivateNetwork`], type-erased for use behind a pointer.
///
/// This is the stream type carried by [`DynPrivateNetwork`] and by the blanket
/// `PrivateNetwork` implementation for `Arc<dyn DynPrivateNetwork>`.
pub trait NetworkStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> NetworkStream for T {}

/// A boxed [`NetworkStream`].
pub type BoxedStream = Box<dyn NetworkStream + 'static>;

/// A network transport that provides connection-level privacy for wallet traffic.
///
/// Implementations open byte streams to arbitrary `host:port` endpoints while concealing
/// network metadata (at minimum, the client's IP address) to the degree the backend
/// supports. Name resolution happens remotely wherever the backend supports it, so `host`
/// is passed through as a string rather than a resolved address.
pub trait PrivateNetwork: Send + Sync {
    /// The byte stream produced by [`PrivateNetwork::connect`].
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Opens a byte stream to the given `host` and `port`.
    fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Self::Stream, Error>> + Send;

    /// Returns a new handle whose traffic is unlinkable to this handle's, to the degree
    /// the backend supports.
    ///
    /// For example, the Tor backend returns a handle that uses fresh circuits, while a
    /// dVPN backend that shares a single tunnel may return an equivalent handle (and
    /// should document that its isolation is best-effort).
    fn isolated_handle(&self) -> Self
    where
        Self: Sized;

    /// Best-effort reduction of the backend's background activity.
    ///
    /// See [`DormantMode`] for the semantics backends should provide.
    fn set_dormant(&self, mode: DormantMode);
}

/// An object-safe mirror of [`PrivateNetwork`], suitable for storage behind a pointer
/// (for example `Arc<dyn DynPrivateNetwork>` in an FFI layer).
///
/// A blanket implementation is provided for every `PrivateNetwork + 'static`, boxing the
/// backend's stream into a [`BoxedStream`] and its futures into [`Pin<Box<...>>`]. In turn,
/// `Arc<dyn DynPrivateNetwork>` implements [`PrivateNetwork`], so the two forms are freely
/// interchangeable at the boundaries of this module's generic helpers.
///
/// Note that the blanket implementation therefore also applies to
/// `Arc<dyn DynPrivateNetwork>` itself. When holding such an `Arc`, call the
/// [`PrivateNetwork`] methods (or explicitly deref to `&dyn DynPrivateNetwork`) rather
/// than invoking `dyn_*` methods on the `Arc` directly: method resolution would select
/// the blanket implementation on the `Arc`, adding a layer of boxing per call — and for
/// [`DynPrivateNetwork::dyn_isolated_handle`], an additional permanent `Arc` layer per
/// handle.
pub trait DynPrivateNetwork: Send + Sync {
    /// Opens a byte stream to the given `host` and `port`, erased to a [`BoxedStream`].
    fn dyn_connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<BoxedStream, Error>> + Send + 'a>>;

    /// Returns a new isolated handle; see [`PrivateNetwork::isolated_handle`].
    fn dyn_isolated_handle(&self) -> Arc<dyn DynPrivateNetwork>;

    /// See [`PrivateNetwork::set_dormant`].
    fn dyn_set_dormant(&self, mode: DormantMode);
}

impl<P: PrivateNetwork + 'static> DynPrivateNetwork for P {
    fn dyn_connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<BoxedStream, Error>> + Send + 'a>> {
        Box::pin(async move {
            let stream = self.connect(host, port).await?;
            Ok(Box::new(stream) as BoxedStream)
        })
    }

    fn dyn_isolated_handle(&self) -> Arc<dyn DynPrivateNetwork> {
        Arc::new(self.isolated_handle())
    }

    fn dyn_set_dormant(&self, mode: DormantMode) {
        self.set_dormant(mode);
    }
}

impl PrivateNetwork for Arc<dyn DynPrivateNetwork> {
    type Stream = BoxedStream;

    async fn connect(&self, host: &str, port: u16) -> Result<Self::Stream, Error> {
        // Dispatch to the inner trait object rather than back through this impl, which
        // would otherwise recurse via the blanket `DynPrivateNetwork` implementation.
        DynPrivateNetwork::dyn_connect(&**self, host, port).await
    }

    fn isolated_handle(&self) -> Self {
        DynPrivateNetwork::dyn_isolated_handle(&**self)
    }

    fn set_dormant(&self, mode: DormantMode) {
        DynPrivateNetwork::dyn_set_dormant(&**self, mode);
    }
}

/// Errors that can occur while connecting or transferring data over a [`PrivateNetwork`].
#[derive(Debug)]
pub enum Error {
    /// An error occurred while using gRPC over a [`PrivateNetwork`].
    #[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
    Grpc(self::grpc::GrpcError),
    /// An error occurred while using HTTP over a [`PrivateNetwork`].
    Http(self::http::HttpError),
    /// The backend cannot route to the requested `host:port`.
    ///
    /// This is returned by backends (such as a mixnet proxy) that can only reach a fixed
    /// set of pre-configured endpoints.
    NoRoute {
        /// The host that could not be routed to.
        host: String,
        /// The port that could not be routed to.
        port: u16,
    },
    /// A backend-specific error occurred while connecting or transferring data.
    ///
    /// This nests the native error of whichever [`PrivateNetwork`] backend produced it
    /// (for example an `arti_client::Error` from the Tor backend).
    Backend(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
            Error::Grpc(e) => write!(f, "gRPC-over-privacy error: {e}"),
            Error::Http(e) => write!(f, "HTTP-over-privacy error: {e}"),
            Error::NoRoute { host, port } => {
                write!(f, "No route to {host}:{port} via this network backend")
            }
            Error::Backend(e) => write!(f, "Network backend error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
            Error::Grpc(e) => Some(e),
            Error::Http(e) => Some(e),
            Error::NoRoute { .. } => None,
            Error::Backend(e) => Some(e.as_ref()),
        }
    }
}

impl From<self::http::HttpError> for Error {
    fn from(e: self::http::HttpError) -> Self {
        Error::Http(e)
    }
}

#[cfg(feature = "lightwalletd-tonic-tls-webpki-roots")]
impl From<self::grpc::GrpcError> for Error {
    fn from(e: self::grpc::GrpcError) -> Self {
        Error::Grpc(e)
    }
}
