//! HTTP requests over Tor.

use std::{fmt, future::Future, io, sync::Arc};

use arti_client::TorClient;
use futures_util::task::SpawnExt;
use http_body_util::{BodyExt, Empty};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::{Body, Buf, Bytes, Incoming},
    client::conn,
    http::{request::Builder, uri::Scheme},
};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, error};

use super::{Client, Error};

pub mod cryptex;

/// How a particular connection failure should be retried.
pub enum Retry {
    /// Retry using the same Tor circuits that resulted in this error.
    Same,
    /// Retry using separate Tor circuits isolated from any other Tor usage.
    Isolated,
}

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
    /// The `request` closure can be used to modify or append HTTP request headers. You
    /// must not call the following [`Builder`] methods within it:
    /// - [`Builder::method`] (this is internally set to `GET`).
    /// - [`Builder::uri`] (this is internally set to `url`).
    /// - [`Builder::header`] with header name `"Host"` (this is internally set based on
    ///   `url`).
    ///
    /// Returns `Ok(response)` if an HTTP response is received, even if the HTTP status
    /// code is not in the 200-299 success range (i.e. [`HttpError::Unsuccessful`] is
    /// never returned).
    ///
    /// There are two arguments for controlling retry behaviour:
    /// - `retry_limit` is the maximum number of times that a failed request should be
    ///   retried. You can disable retries by setting this to 0.
    /// - `retry_filter` can be used to only retry requests that fail in specific ways,
    ///   and control how the retry is performed. You can disable retries by setting this
    ///   to `|_| None`, and you can ensure the same circuit is reused by setting this to
    ///   `|res| res.is_err().then_some(Retry::Same)` (e.g. if you require a persistent
    ///   Tor client identity across queries).
    #[tracing::instrument(skip(self, request, parse_response, retry_filter))]
    pub async fn http_get<T, F: Future<Output = Result<T, Error>>>(
        &self,
        url: Uri,
        request: impl Fn(Builder) -> Builder,
        parse_response: impl FnOnce(Incoming) -> F,
        retry_limit: u8,
        retry_filter: impl Fn(Result<StatusCode, &Error>) -> Option<Retry>,
    ) -> Result<Response<T>, Error> {
        self.http_request(
            url,
            |builder| request(builder).method("GET"),
            Empty::<Bytes>::new(),
            parse_response,
            retry_limit,
            retry_filter,
        )
        .await
    }

    /// Makes an HTTP POST request over Tor.
    ///
    /// The `request` closure can be used to modify or append HTTP request headers. You
    /// must not call the following [`Builder`] methods within it:
    /// - [`Builder::method`] (this is internally set to `POST`).
    /// - [`Builder::uri`] (this is internally set to `url`).
    /// - [`Builder::header`] with header name `"Host"` (this is internally set based on
    ///   `url`).
    ///
    /// Returns `Ok(response)` if an HTTP response is received, even if the HTTP status
    /// code is not in the 200-299 success range (i.e. [`HttpError::Unsuccessful`] is
    /// never returned).
    ///
    /// There are two arguments for controlling retry behaviour:
    /// - `retry_limit` is the maximum number of times that a failed request should be
    ///   retried. You can disable retries by setting this to 0.
    /// - `retry_filter` can be used to only retry requests that fail in specific ways,
    ///   and control how the retry is performed. You can disable retries by setting this
    ///   to `|_| None`, and you can ensure the same circuit is reused by setting this to
    ///   `|res| res.is_err().then_some(Retry::Same)` (e.g. if you require a persistent
    ///   Tor client identity across queries).
    #[tracing::instrument(skip(self, request, body, parse_response, retry_filter))]
    pub async fn http_post<B, T, F>(
        &self,
        url: Uri,
        request: impl Fn(Builder) -> Builder,
        body: B,
        parse_response: impl FnOnce(Incoming) -> F,
        retry_limit: u8,
        retry_filter: impl Fn(Result<StatusCode, &Error>) -> Option<Retry>,
    ) -> Result<Response<T>, Error>
    where
        B: Body + Clone + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        F: Future<Output = Result<T, Error>>,
    {
        self.http_request(
            url,
            |builder| request(builder).method("POST"),
            body,
            parse_response,
            retry_limit,
            retry_filter,
        )
        .await
    }

    /// Makes an HTTP request over Tor.
    ///
    /// There are two arguments for controlling retry behaviour:
    /// - `retry_limit` is the maximum number of times that a failed request should be
    ///   retried. You can disable retries by setting this to 0.
    /// - `retry_filter` can be used to only retry requests that fail in specific ways,
    ///   and control how the retry is performed. You can disable retries by setting this
    ///   to `|_| None`, and you can ensure the same circuit is reused by setting this to
    ///   `|res| res.is_err().then_some(Retry::Same)` (e.g. if you require a persistent
    ///   Tor client identity across queries).
    async fn http_request<B, T, F>(
        &self,
        url: Uri,
        request: impl Fn(Builder) -> Builder,
        body: B,
        parse_response: impl FnOnce(Incoming) -> F,
        retry_limit: u8,
        retry_filter: impl Fn(Result<StatusCode, &Error>) -> Option<Retry>,
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
            let response = one_http_request(
                &client.as_ref().unwrap_or(self).inner,
                url.clone(),
                &request,
                body.clone(),
            )
            .await;

            match (
                retries_remaining.checked_sub(1),
                retry_filter(response.as_ref().map(|response| response.status())),
            ) {
                (Some(retries), Some(retry)) => {
                    debug!("Retrying due to filter match");
                    retries_remaining = retries;

                    match retry {
                        Retry::Same => (),
                        Retry::Isolated => {
                            debug!("Switching to isolated Tor circuit for retry");
                            client = Some(self.isolated_client());
                        }
                    }
                }
                (None, _) | (_, None) => break response,
            }
        }?
        .into_parts();

        Ok(Response::from_parts(parts, parse_response(body).await?))
    }

    /// Makes an HTTP GET request over Tor, parsing the response as JSON.
    ///
    /// This is a simple wapper around [`Self::http_get`]. Use that method if you need
    /// more control over the request headers or response parsing.
    ///
    /// Returns `Ok(response)` if an HTTP response is received, even if the HTTP status
    /// code is not in the 200-299 success range (i.e. [`HttpError::Unsuccessful`] is
    /// never returned).
    ///
    /// There are two arguments for controlling retry behaviour:
    /// - `retry_limit` is the maximum number of times that a failed request should be
    ///   retried. You can disable retries by setting this to 0.
    /// - `retry_filter` can be used to only retry requests that fail in specific ways,
    ///   and control how the retry is performed. You can disable retries by setting this
    ///   to `|_| None`, and you can ensure the same circuit is reused by setting this to
    ///   `|res| res.is_err().then_some(Retry::Same)` (e.g. if you require a persistent
    ///   Tor client identity across queries).
    pub async fn http_get_json<T: DeserializeOwned>(
        &self,
        url: Uri,
        retry_limit: u8,
        retry_filter: impl Fn(Result<StatusCode, &Error>) -> Option<Retry>,
    ) -> Result<Response<T>, Error> {
        self.http_get(
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
            retry_filter,
        )
        .await
    }
}

async fn one_http_request<B>(
    tor_client: &TorClient<PreferredRuntime>,
    url: Uri,
    request: impl FnOnce(Builder) -> Builder,
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
        make_http_request(stream, url, request, body).await
    } else {
        make_http_request(stream, url, request, body).await
    }
}

async fn make_http_request<B>(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    url: Uri,
    request: impl FnOnce(Builder) -> Builder,
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
    let req = request(Request::builder())
        .header(
            hyper::header::HOST,
            url.authority().expect("Already checked").as_str(),
        )
        .uri(url)
        .body(body)
        .map_err(HttpError::from)?;
    let response = sender.send_request(req).await.map_err(HttpError::from)?;
    debug!("Response status code: {}", response.status());

    Ok(response)
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
    ///
    /// This is only returned by APIs that make specific queries, such as
    /// [`Client::get_latest_zec_to_usd_rate`]. Generic APIs like [`Client::http_get`]
    /// will not return this error variant.
    Unsuccessful(hyper::http::StatusCode),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::NonHttpUrl => write!(f, "Only HTTP or HTTPS URLs are supported"),
            HttpError::Http(e) => write!(f, "HTTP error: {e}"),
            HttpError::Hyper(e) => write!(f, "Hyper error: {e}"),
            HttpError::Json(e) => write!(f, "Failed to parse JSON: {e}"),
            HttpError::Spawn(e) => write!(f, "Failed to spawn task: {e}"),
            HttpError::Tls(e) => write!(f, "TLS error: {e}"),
            HttpError::Unsuccessful(status) => write!(f, "Request was unsuccessful ({status:?})"),
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

#[cfg(all(test, live_network_tests))]
mod live_network_tests {
    use http_body_util::BodyExt;
    use hyper::body::Buf;

    use crate::tor::{
        Client,
        http::{HttpError, Retry},
    };

    #[test]
    fn httpbin() {
        let tor_dir = tempfile::tempdir().unwrap();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            // Start a new Tor client.
            let client = Client::create(tor_dir.path(), |_| ()).await.unwrap();

            // Test HTTP GET
            let get_response = client
                .http_get_json::<serde_json::Value>(
                    "https://httpbin.org/get".parse().unwrap(),
                    3,
                    |res| res.is_err().then_some(Retry::Same),
                )
                .await
                .unwrap();
            assert_eq!(
                get_response.body().get("url").and_then(|v| v.as_str()),
                Some("https://httpbin.org/get"),
            );
            assert_eq!(
                get_response
                    .body()
                    .get("headers")
                    .and_then(|v| v.as_object())
                    .and_then(|h| h.get("Host"))
                    .and_then(|v| v.as_str()),
                Some("httpbin.org"),
            );
            assert!(
                get_response
                    .body()
                    .get("args")
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .is_empty()
            );

            // Test HTTP POST
            let post_body = "Some body";
            let post_response = client
                .http_post(
                    "https://httpbin.org/post".parse().unwrap(),
                    |builder| builder.header(hyper::header::ACCEPT, "application/json"),
                    http_body_util::Full::new(post_body.as_bytes()),
                    |body| async {
                        Ok(serde_json::from_reader::<_, serde_json::Value>(
                            body.collect()
                                .await
                                .map_err(HttpError::from)?
                                .aggregate()
                                .reader(),
                        )
                        .map_err(HttpError::from)?)
                    },
                    3,
                    |res| res.is_err().then_some(Retry::Same),
                )
                .await
                .unwrap();
            assert!(
                post_response
                    .body()
                    .get("args")
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                post_response.body().get("data").and_then(|v| v.as_str()),
                Some(post_body),
            );
        })
    }
}
