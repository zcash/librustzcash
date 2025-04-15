//! HTTP requests over Tor.

use std::{fmt, future::Future, io, sync::Arc};

use futures_util::task::SpawnExt;
use http_body_util::{BodyExt, Empty};
use hyper::{
    body::{Buf, Bytes, Incoming},
    client::conn,
    http::{request::Builder, uri::Scheme},
    Request, Response, Uri,
};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, error};

use super::{Client, Error};

pub mod cryptex;

pub(super) fn url_is_https(url: &Uri) -> Result<bool, HttpError> {
    Ok(url.scheme().ok_or_else(|| HttpError::NonHttpUrl)? == &Scheme::HTTPS)
}

pub(super) fn parse_url(url: &Uri) -> Result<(bool, String, u16), Error> {
    let is_https = url_is_https(url)?;

    let host = url.host().ok_or_else(|| HttpError::NonHttpUrl)?.to_string();

    let port = match url.port_u16() {
        Some(port) => port,
        None if is_https => 443,
        None => 80,
    };

    Ok((is_https, host, port))
}

impl Client {
    #[tracing::instrument(skip(self, h, f))]
    async fn get<T, F: Future<Output = Result<T, Error>>>(
        &self,
        url: Uri,
        h: impl FnOnce(Builder) -> Builder,
        f: impl FnOnce(Incoming) -> F,
    ) -> Result<Response<T>, Error> {
        let (is_https, host, port) = parse_url(&url)?;

        // Connect to the server.
        debug!("Connecting through Tor to {}:{}", host, port);
        let stream = self.inner.connect((host.as_str(), port)).await?;

        if is_https {
            // On apple-darwin targets there's an issue with the native TLS implementation
            // when used over Tor circuits. We use Rustls instead.
            //
            // https://gitlab.torproject.org/tpo/core/arti/-/issues/715
            let root_store = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let dnsname = ServerName::try_from(host).expect("Already checked");
            let stream = connector
                .connect(dnsname, stream)
                .await
                .map_err(HttpError::Tls)?;
            make_http_request(stream, url, h, f).await
        } else {
            make_http_request(stream, url, h, f).await
        }
    }

    async fn get_json<T: DeserializeOwned>(&self, url: Uri) -> Result<Response<T>, Error> {
        self.get(
            url,
            |builder| builder.header(hyper::header::ACCEPT, "application/json"),
            |body| async {
                Ok(serde_json::from_reader(
                    body.collect()
                        .await
                        .map_err(HttpError::from)?
                        .aggregate()
                        .reader(),
                )
                .map_err(HttpError::from)?)
            },
        )
        .await
    }
}

async fn make_http_request<T, F: Future<Output = Result<T, Error>>>(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    url: Uri,
    h: impl FnOnce(Builder) -> Builder,
    f: impl FnOnce(Incoming) -> F,
) -> Result<Response<T>, Error> {
    debug!("Making request");
    let (mut sender, connection) = conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(HttpError::from)?;

    // Spawn a task to poll the connection and drive the HTTP state.
    PreferredRuntime::current()?
        .spawn(async move {
            if let Err(e) = connection.await {
                error!("Connection failed: {}", e);
            }
        })
        .map_err(HttpError::from)?;

    let req = h(Request::builder()
        .header(
            hyper::header::HOST,
            url.authority().expect("Already checked").as_str(),
        )
        .uri(url))
    .body(Empty::<Bytes>::new())
    .map_err(HttpError::from)?;
    let (parts, body) = sender
        .send_request(req)
        .await
        .map_err(HttpError::from)?
        .into_parts();
    debug!("Response status code: {}", parts.status);

    if parts.status.is_success() {
        Ok(Response::from_parts(parts, f(body).await?))
    } else {
        Err(Error::Http(HttpError::Unsuccessful(parts.status)))
    }
}

/// Errors that can occurr while using HTTP-over-Tor.
#[derive(Debug)]
pub enum HttpError {
    /// A non-HTTP URL was encountered.
    NonHttpUrl,
    /// An HTTP error.
    Http(hyper::http::Error),
    /// A [`hyper`] error.
    Hyper(hyper::Error),
    /// A JSON parsing error.
    Json(serde_json::Error),
    /// An error occurred while spawning a background worker task for driving the HTTP
    /// connection.
    Spawn(futures_util::task::SpawnError),
    /// A TLS-specific IO error.
    Tls(io::Error),
    /// The status code indicated that the request was unsuccessful.
    Unsuccessful(hyper::http::StatusCode),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::NonHttpUrl => write!(f, "Only HTTP or HTTPS URLs are supported"),
            HttpError::Http(e) => write!(f, "HTTP error: {}", e),
            HttpError::Hyper(e) => write!(f, "Hyper error: {}", e),
            HttpError::Json(e) => write!(f, "Failed to parse JSON: {}", e),
            HttpError::Spawn(e) => write!(f, "Failed to spawn task: {}", e),
            HttpError::Tls(e) => write!(f, "TLS error: {}", e),
            HttpError::Unsuccessful(status) => write!(f, "Request was unsuccessful ({:?})", status),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HttpError::NonHttpUrl => None,
            HttpError::Http(e) => Some(e),
            HttpError::Hyper(e) => Some(e),
            HttpError::Json(e) => Some(e),
            HttpError::Spawn(e) => Some(e),
            HttpError::Tls(e) => Some(e),
            HttpError::Unsuccessful(_) => None,
        }
    }
}

impl From<hyper::http::Error> for HttpError {
    fn from(e: hyper::http::Error) -> Self {
        HttpError::Http(e)
    }
}

impl From<hyper::Error> for HttpError {
    fn from(e: hyper::Error) -> Self {
        HttpError::Hyper(e)
    }
}

impl From<serde_json::Error> for HttpError {
    fn from(e: serde_json::Error) -> Self {
        HttpError::Json(e)
    }
}

impl From<futures_util::task::SpawnError> for HttpError {
    fn from(e: futures_util::task::SpawnError) -> Self {
        HttpError::Spawn(e)
    }
}
