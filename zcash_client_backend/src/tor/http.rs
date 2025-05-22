//! HTTP requests over Tor.

use std::{fmt, future::Future, io, sync::Arc};

use arti_client::TorClient;
use futures_util::task::SpawnExt;
use http_body_util::{BodyExt, Empty};
use hyper::{
    body::{Body, Buf, Bytes, Incoming},
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
    /// Makes an HTTP GET request over Tor.
    ///
    /// On error, retries will be attempted as follows:
    /// - A successful request that resulted in a client error (HTTP 400-499) will cause a
    ///   retry with an isolated client.
    /// - All other errors will cause a retry with the same client.
    #[tracing::instrument(skip(self, h, f))]
    async fn get<T, F: Future<Output = Result<T, Error>>>(
        &self,
        url: Uri,
        h: impl Fn(Builder) -> Builder,
        f: impl FnOnce(Incoming) -> F,
        retry_limit: u8,
    ) -> Result<Response<T>, Error> {
        self.http_request(
            url,
            |builder| h(builder).method("GET"),
            Empty::<Bytes>::new(),
            f,
            retry_limit,
        )
        .await
    }

    /// Makes an HTTP request over Tor.
    ///
    /// On error, retries will be attempted as follows:
    /// - A successful request that resulted in a client error (HTTP 400-499) will cause a
    ///   retry with an isolated client.
    /// - All other errors will cause a retry with the same client.
    async fn http_request<B, T, F>(
        &self,
        url: Uri,
        h: impl Fn(Builder) -> Builder,
        body: B,
        f: impl FnOnce(Incoming) -> F,
        retry_limit: u8,
    ) -> Result<Response<T>, Error>
    where
        B: Body + Clone + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        F: Future<Output = Result<T, Error>>,
    {
        let mut retries_remaining = retry_limit;
        let mut client = None;

        let (parts, body) = loop {
            match one_http_request(
                &client.as_ref().unwrap_or(self).inner,
                url.clone(),
                &h,
                body.clone(),
            )
            .await
            {
                Ok(response) => break Ok(response),

                Err(e) => match retries_remaining.checked_sub(1) {
                    Some(retries) => {
                        debug!("Retrying due to error: {e}");
                        retries_remaining = retries;

                        // A common failure with HTTP requests over Tor is a particular
                        // exit node being blocked by the server. `Client::http_request`
                        // isn't used for anything that requires a persistent Tor client
                        // identity across queries, so we retry with an isolated client in
                        // order to use new circuits that have a decent chance of using a
                        // different exit node. The isolation is not for privacy; the
                        // server can trivially link the two requests together via timing.
                        if let Error::Http(HttpError::Unsuccessful(status)) = e {
                            if status.is_client_error() {
                                debug!("Switching to isolated Tor circuit after getting {status}");
                                client = Some(self.isolated_client());
                            }
                        }
                    }
                    None => break Err(e),
                },
            }
        }?
        .into_parts();

        Ok(Response::from_parts(parts, f(body).await?))
    }

    /// Makes an HTTP GET request over Tor, parsing the response as JSON.
    ///
    /// On error, retries will be attempted as follows:
    /// - A successful request that resulted in a client error (HTTP 400-499) will cause a
    ///   retry with an isolated client.
    /// - All other errors will cause a retry with the same client.
    async fn get_json<T: DeserializeOwned>(
        &self,
        url: Uri,
        retry_limit: u8,
    ) -> Result<Response<T>, Error> {
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
            retry_limit,
        )
        .await
    }
}

async fn one_http_request<B>(
    tor_client: &TorClient<PreferredRuntime>,
    url: Uri,
    h: impl FnOnce(Builder) -> Builder,
    body: B,
) -> Result<Response<Incoming>, Error>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (is_https, host, port) = parse_url(&url)?;

    // Connect to the server.
    debug!("Connecting through Tor to {}:{}", host, port);
    let stream = tor_client.connect((host.as_str(), port)).await?;

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
        make_http_request(stream, url, h, body).await
    } else {
        make_http_request(stream, url, h, body).await
    }
}

async fn make_http_request<B>(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    url: Uri,
    h: impl FnOnce(Builder) -> Builder,
    body: B,
) -> Result<Response<Incoming>, Error>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
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

    // Build the request. We let the caller make whatever request modifications they need,
    // and then set the Host and URI afterwards so that they are guaranteed to match the
    // circuit and TLS connection.
    let req = h(Request::builder())
        .header(
            hyper::header::HOST,
            url.authority().expect("Already checked").as_str(),
        )
        .uri(url)
        .body(body)
        .map_err(HttpError::from)?;
    let response = sender.send_request(req).await.map_err(HttpError::from)?;
    debug!("Response status code: {}", response.status());

    if response.status().is_success() {
        Ok(response)
    } else {
        Err(Error::Http(HttpError::Unsuccessful(response.status())))
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
