//! HTTP requests over Tor.

use std::{fmt, future::Future, io, sync::Arc, time::Duration};

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

use super::{Client, Error, Timeouts};

pub mod cryptex;

/// How a particular connection failure should be retried.
pub enum Retry {
    /// Retry using the same Tor circuits that resulted in this error.
    Same,
    /// Retry using separate Tor circuits isolated from any other Tor usage.
    Isolated,
}

/// The stage of an HTTP request that exceeded its deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeoutPhase {
    /// Opening the Tor stream to the server, or completing the TLS handshake.
    Connect,
    /// Sending the request and receiving its response headers.
    Request,
    /// Receiving and parsing the response body.
    ResponseBody,
}

impl fmt::Display for TimeoutPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeoutPhase::Connect => write!(f, "connecting to the server"),
            TimeoutPhase::Request => write!(f, "awaiting the response headers"),
            TimeoutPhase::ResponseBody => write!(f, "reading the response body"),
        }
    }
}

/// Runs `f`, failing with [`HttpError::Timeout`] if it does not finish within `limit`.
async fn with_timeout<T>(
    limit: Duration,
    phase: TimeoutPhase,
    f: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    tokio::time::timeout(limit, f)
        .await
        .unwrap_or_else(|_| Err(HttpError::Timeout(phase).into()))
}

pub(super) fn url_is_https(url: &Uri) -> Result<bool, HttpError> {
    // Only HTTP and HTTPS are supported. A missing scheme, or any other scheme (`ftp`,
    // `ws`, `file`, ...), is rejected rather than silently treated as plaintext HTTP.
    match url.scheme() {
        Some(scheme) if scheme == &Scheme::HTTPS => Ok(true),
        Some(scheme) if scheme == &Scheme::HTTP => Ok(false),
        _ => Err(HttpError::NonHttpUrl),
    }
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
    ///
    /// The [`Timeouts`] this client was created with are applied to each attempt
    /// individually, so the total time this method can take is bounded by `retry_limit + 1`
    /// times those deadlines. A request that exceeds one of them fails with
    /// [`HttpError::Timeout`], which `retry_filter` sees like any other error.
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
    ///
    /// The [`Timeouts`] this client was created with are applied to each attempt
    /// individually, so the total time this method can take is bounded by `retry_limit + 1`
    /// times those deadlines. A request that exceeds one of them fails with
    /// [`HttpError::Timeout`], which `retry_filter` sees like any other error.
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
    ///
    /// The [`Timeouts`] this client was created with are applied to each attempt
    /// individually, so the total time this method can take is bounded by `retry_limit + 1`
    /// times those deadlines. A request that exceeds one of them fails with
    /// [`HttpError::Timeout`], which `retry_filter` sees like any other error.
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
            let active = client.as_ref().unwrap_or(self);
            let response = one_http_request(
                &active.inner,
                &active.timeouts,
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

        Ok(Response::from_parts(
            parts,
            with_timeout(
                self.timeouts.response_body,
                TimeoutPhase::ResponseBody,
                parse_response(body),
            )
            .await?,
        ))
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
    ///
    /// The [`Timeouts`] this client was created with are applied to each attempt
    /// individually, so the total time this method can take is bounded by `retry_limit + 1`
    /// times those deadlines. A request that exceeds one of them fails with
    /// [`HttpError::Timeout`], which `retry_filter` sees like any other error.
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
    timeouts: &Timeouts,
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

    debug!("Connecting through Tor to {}:{}", host, port);

    // The Tor stream and the TLS handshake are bounded together, so that
    // `Timeouts::connect` means the same thing here as it does for the gRPC transport
    // (where `tonic` applies it to the connector as a whole).
    if is_https {
        let stream = with_timeout(timeouts.connect, TimeoutPhase::Connect, async {
            let stream = tor_client.connect((host.as_str(), port)).await?;
            tls_handshake(stream, host).await
        })
        .await?;

        with_timeout(
            timeouts.request,
            TimeoutPhase::Request,
            make_http_request(stream, url, request, body),
        )
        .await
    } else {
        let stream = with_timeout(timeouts.connect, TimeoutPhase::Connect, async {
            Ok(tor_client.connect((host.as_str(), port)).await?)
        })
        .await?;

        with_timeout(
            timeouts.request,
            TimeoutPhase::Request,
            make_http_request(stream, url, request, body),
        )
        .await
    }
}

/// Completes a TLS handshake with `host` over an already-open stream.
///
/// Split out of [`one_http_request`] so that the handshake can be exercised on its own by
/// the tests. It is the part of the `Timeouts::connect` phase that runs *above* the Tor
/// stream: opening the stream itself is bounded separately by `arti`. Over Tor this is a
/// real exposure, because a half-open circuit can leave the handshake waiting on a
/// `ServerHello` that never arrives and never fails.
async fn tls_handshake<S>(
    stream: S,
    host: String,
) -> Result<tokio_rustls::client::TlsStream<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // On apple-darwin targets there's an issue with the native TLS implementation when
    // used over Tor circuits. We use Rustls instead.
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
    Ok(connector
        .connect(dnsname, stream)
        .await
        .map_err(HttpError::Tls)?)
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
#[non_exhaustive]
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
    /// The request did not complete within the corresponding [`Timeouts`] deadline.
    ///
    /// [`Timeouts`]: super::Timeouts
    Timeout(TimeoutPhase),
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
            HttpError::Timeout(phase) => write!(f, "Timed out while {phase}"),
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
            HttpError::Timeout(_) => None,
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

/// Tests that drive the HTTP-over-Tor timeout machinery against a fake, adversarial
/// server.
///
/// The transport is generic over the byte stream, so an in-memory [`tokio::io::duplex`]
/// pair stands in for a Tor `DataStream`: one end is handed to the client code, the other
/// is driven by [`serve`] as the server. This is a faithful model of the failure this
/// layer exists to survive, because every stalling scenario *holds the peer end open and
/// silent* (see [`hold_open`]). Over Tor a stalled peer delivers neither more bytes nor a
/// close: a half-open circuit persists without the peer's TCP stack sending a reset, so
/// the future would hang forever without a deadline. Dropping the peer instead would
/// deliver an EOF, which is the clearnet case, not the one under test.
///
/// What this harness does *not* cover, because it needs a real `TorClient`:
/// - opening the Tor stream (the other half of the `Connect` phase; `arti` bounds that
///   itself via `StreamTimeoutConfig::connect_timeout`), and
/// - the circuit-isolating retry loop in [`Client::http_request`].
///
/// Deadlines fire deterministically and with no real delay under `start_paused`: virtual
/// time only advances when every task is blocked, at which point the sole pending timer
/// (the client's deadline) elapses.
#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use http_body_util::{BodyExt, Empty};
    use hyper::{StatusCode, Uri, body::Bytes};
    use proptest::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::{
        HttpError, TimeoutPhase, make_http_request, parse_url, tls_handshake, url_is_https,
        with_timeout,
    };
    use crate::tor::Error;

    // The absolute values are irrelevant under `start_paused`; they only need to be
    // positive so the deadline exists to be advanced to.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
    const RESPONSE_BODY_TIMEOUT: Duration = Duration::from_secs(5);
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    /// Backing buffer for the in-memory duplex. Large enough that neither side's writes
    /// block on the other draining, so the tests never deadlock on buffer pressure.
    const DUPLEX_BUF_SIZE: usize = 64 * 1024;

    /// Per-read buffer size in [`read_request_head`]. The loop accumulates across reads, so
    /// this bounds only how much is read at once, not how much the peer may send.
    const CHUNK_SIZE: usize = 1024;

    /// Extracts the phase from a `Timeout` error, or `None` for any other result. Keeps the
    /// assertions from spelling out `Err(Error::Http(HttpError::Timeout(_)))` each time.
    fn timeout_phase<T>(res: &Result<T, Error>) -> Option<TimeoutPhase> {
        match res {
            Err(Error::Http(HttpError::Timeout(phase))) => Some(*phase),
            _ => None,
        }
    }

    /// A minimal, typed HTTP/1.1 response head for the fake server. Typed rather than a
    /// bare format string so new cases (other status codes or versions, extra headers) are
    /// a field change, not a new string to get subtly wrong.
    struct ResponseHead {
        version: &'static str,
        status: StatusCode,
        content_length: usize,
    }

    impl ResponseHead {
        /// A `200 OK` head declaring a body of `content_length` bytes.
        fn ok(content_length: usize) -> Self {
            Self {
                version: "HTTP/1.1",
                status: StatusCode::OK,
                content_length,
            }
        }

        /// Renders the head, including the terminating blank line.
        fn render(&self) -> String {
            format!(
                "{} {} {}\r\nContent-Length: {}\r\n\r\n",
                self.version,
                self.status.as_u16(),
                self.status.canonical_reason().unwrap_or(""),
                self.content_length,
            )
        }
    }

    /// How the fake server behaves once a client has connected. Each stalling variant
    /// models a half-open Tor circuit: the peer accepted the stream, but no further bytes
    /// and no close will ever arrive.
    enum Behavior {
        /// Read the request, then go silent without sending any response.
        StallBeforeHead,
        /// Send response headers promising `content_length` body bytes, send `sent_len` of
        /// them (`sent_len < content_length`), then go silent. Models a circuit that
        /// trickles and then half-opens partway through the body.
        StallDuringBody {
            sent_len: usize,
            content_length: usize,
        },
        /// Send response headers, then dribble the body one byte at a time, pausing
        /// `chunk_gap` between bytes, so the body never completes within the deadline
        /// *despite continuous progress*. Distinct from `StallDuringBody`, which goes
        /// idle: this shows the response-body deadline is a total-duration cap, not an
        /// inter-byte idle cap (the job the gRPC keep-alive does instead).
        TrickleBody {
            chunk_gap: Duration,
            content_length: usize,
        },
        /// Send a complete, well-formed response. The control: a responsive peer must not
        /// be timed out.
        Complete { body: Vec<u8> },
    }

    /// Holds `peer` open forever, reading and writing nothing. This is what makes the
    /// duplex a faithful model of a half-open Tor circuit rather than a clean close.
    async fn hold_open(peer: DuplexStream) {
        let _held = peer;
        pending::<()>().await;
    }

    /// Consumes bytes from `peer` up to the end of the HTTP request head (`\r\n\r\n`). The
    /// GET requests issued here carry no body, so this reads the whole request.
    async fn read_request_head(peer: &mut DuplexStream) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; CHUNK_SIZE];
        loop {
            let n = peer.read(&mut chunk).await.expect("read from client");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    }

    /// Serves one connection according to `behavior`.
    async fn serve(mut peer: DuplexStream, behavior: Behavior) {
        read_request_head(&mut peer).await;
        match behavior {
            Behavior::StallBeforeHead => hold_open(peer).await,
            Behavior::StallDuringBody {
                sent_len,
                content_length,
            } => {
                let head = ResponseHead::ok(content_length).render();
                peer.write_all(head.as_bytes()).await.expect("write head");
                peer.write_all(&vec![b'a'; sent_len])
                    .await
                    .expect("write partial body");
                peer.flush().await.expect("flush");
                hold_open(peer).await;
            }
            Behavior::TrickleBody {
                chunk_gap,
                content_length,
            } => {
                let head = ResponseHead::ok(content_length).render();
                peer.write_all(head.as_bytes()).await.expect("write head");
                for _ in 0..content_length {
                    peer.write_all(b"a").await.expect("write body byte");
                    peer.flush().await.expect("flush");
                    tokio::time::sleep(chunk_gap).await;
                }
                hold_open(peer).await;
            }
            Behavior::Complete { body } => {
                let head = ResponseHead::ok(body.len()).render();
                peer.write_all(head.as_bytes()).await.expect("write head");
                peer.write_all(&body).await.expect("write body");
                peer.flush().await.expect("flush");
                // Return, closing the connection; the body is already complete.
            }
        }
    }

    /// Runs one GET request against a fake server exhibiting `behavior`, applying the
    /// `Request` and `ResponseBody` deadlines exactly as [`Client::http_request`] does,
    /// and returns the collected body.
    async fn run_get(behavior: Behavior) -> Result<Vec<u8>, Error> {
        let (client, peer) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        tokio::spawn(serve(peer, behavior));

        let response = with_timeout(
            REQUEST_TIMEOUT,
            TimeoutPhase::Request,
            make_http_request(
                client,
                "http://example.com/".parse().unwrap(),
                |builder| builder.method("GET"),
                Empty::<Bytes>::new(),
            ),
        )
        .await?;

        with_timeout(RESPONSE_BODY_TIMEOUT, TimeoutPhase::ResponseBody, async {
            Ok(response
                .into_body()
                .collect()
                .await
                .map_err(HttpError::from)?
                .to_bytes()
                .to_vec())
        })
        .await
    }

    /// A peer that never sends response headers must surface as a `Request` timeout.
    #[tokio::test(start_paused = true)]
    async fn stall_before_head_times_out_as_request() {
        let res = run_get(Behavior::StallBeforeHead).await;
        assert_eq!(
            timeout_phase(&res),
            Some(TimeoutPhase::Request),
            "expected a request timeout, got {res:?}",
        );
    }

    /// A peer that sends headers then stalls partway through the body must surface as a
    /// `ResponseBody` timeout, not a `Request` one: the phase boundary is the arrival of
    /// the response head.
    #[tokio::test(start_paused = true)]
    async fn stall_during_body_times_out_as_response_body() {
        let res = run_get(Behavior::StallDuringBody {
            sent_len: 8,
            content_length: 1024,
        })
        .await;
        assert_eq!(
            timeout_phase(&res),
            Some(TimeoutPhase::ResponseBody),
            "expected a response-body timeout, got {res:?}",
        );
    }

    /// A responsive peer must complete without ever tripping a deadline.
    #[tokio::test(start_paused = true)]
    async fn well_behaved_server_is_not_timed_out() {
        let body = b"hello over tor".to_vec();
        let res = run_get(Behavior::Complete { body: body.clone() }).await;
        assert!(
            matches!(res, Ok(ref got) if *got == body),
            "expected the body back, got {res:?}",
        );
    }

    /// A peer that accepts the stream but never completes the TLS handshake must surface
    /// as a `Connect` timeout. Models a half-open circuit mid-handshake: the `ServerHello`
    /// never arrives.
    #[tokio::test(start_paused = true)]
    async fn tls_handshake_stall_times_out_as_connect() {
        let (client, peer) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let res = with_timeout(CONNECT_TIMEOUT, TimeoutPhase::Connect, async {
            tls_handshake(client, "example.com".to_string()).await
        })
        .await;
        // Keep the peer alive across the handshake so it stalls rather than EOFs.
        drop(peer);
        assert_eq!(
            timeout_phase(&res),
            Some(TimeoutPhase::Connect),
            "expected a connect timeout, got {res:?}",
        );
    }

    /// A body that arrives continuously but too slowly must still time out as
    /// `ResponseBody`: the deadline caps total duration, not idle time.
    #[tokio::test(start_paused = true)]
    async fn slowly_trickled_body_still_times_out_as_response_body() {
        // A byte every 2s against a 5s budget: progress never stops, yet the 1000-byte
        // body cannot complete in time.
        let res = run_get(Behavior::TrickleBody {
            chunk_gap: Duration::from_secs(2),
            content_length: 1_000,
        })
        .await;
        assert_eq!(
            timeout_phase(&res),
            Some(TimeoutPhase::ResponseBody),
            "expected a response-body timeout, got {res:?}",
        );
    }

    /// A genuine TLS failure (here a plaintext server answering a TLS `ClientHello`, a
    /// realistic misconfiguration) must be reported as [`HttpError::Tls`] and must not be
    /// masked by the `Connect` deadline: a fast, specific failure beats a slow, generic
    /// timeout.
    #[tokio::test(start_paused = true)]
    async fn tls_protocol_error_is_reported_as_tls_not_timeout() {
        let (client, mut peer) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        tokio::spawn(async move {
            // The first byte (0x48, 'H') is not a valid TLS content type, so rustls
            // rejects the record immediately rather than waiting for more data.
            peer.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await
                .expect("write");
            peer.flush().await.expect("flush");
            // Stay open so the failure is a protocol error, not an EOF.
            hold_open(peer).await;
        });
        let res = with_timeout(CONNECT_TIMEOUT, TimeoutPhase::Connect, async {
            tls_handshake(client, "example.com".to_string()).await
        })
        .await;
        assert!(
            matches!(res, Err(Error::Http(HttpError::Tls(_)))),
            "expected a TLS error, got {res:?}",
        );
        assert_eq!(
            timeout_phase(&res),
            None,
            "a real TLS error must not be reported as a timeout, got {res:?}",
        );
    }

    #[derive(Clone, Debug)]
    enum Scenario {
        StallHead,
        StallBody {
            sent_len: usize,
            content_length: usize,
        },
        Complete {
            body: Vec<u8>,
        },
    }

    #[derive(Debug)]
    enum Expected {
        Timeout(TimeoutPhase),
        Body(Vec<u8>),
    }

    impl Scenario {
        fn expected(&self) -> Expected {
            match self {
                Scenario::StallHead => Expected::Timeout(TimeoutPhase::Request),
                Scenario::StallBody { .. } => Expected::Timeout(TimeoutPhase::ResponseBody),
                Scenario::Complete { body } => Expected::Body(body.clone()),
            }
        }

        fn into_behavior(self) -> Behavior {
            match self {
                Scenario::StallHead => Behavior::StallBeforeHead,
                Scenario::StallBody {
                    sent_len,
                    content_length,
                } => Behavior::StallDuringBody {
                    sent_len,
                    content_length,
                },
                Scenario::Complete { body } => Behavior::Complete { body },
            }
        }
    }

    /// Strategy over adversarial and well-behaved servers. `StallBody` always promises
    /// more than it sends (`content_length = sent_len + remaining`, `remaining >= 1`), so
    /// the body never completes.
    fn arb_scenario() -> impl Strategy<Value = Scenario> {
        prop_oneof![
            Just(Scenario::StallHead),
            (0usize..64, 1usize..2048).prop_map(|(sent_len, remaining)| Scenario::StallBody {
                sent_len,
                content_length: sent_len + remaining,
            }),
            proptest::collection::vec(any::<u8>(), 0..512)
                .prop_map(|body| Scenario::Complete { body }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// The safety property the timeout layer must satisfy: against any of these
        /// servers the request resolves in bounded time, and when it stalls, the phase
        /// named by the `Timeout` error is exactly the phase that stalled (or it returns
        /// the body when the server is well-behaved).
        #[test]
        fn timeout_phase_matches_the_stalled_phase(scenario in arb_scenario()) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
                .unwrap();
            rt.block_on(async {
                let expected = scenario.expected();
                let res = run_get(scenario.into_behavior()).await;
                match expected {
                    Expected::Timeout(phase) => prop_assert_eq!(
                        timeout_phase(&res),
                        Some(phase),
                        "expected Timeout({:?}), got {:?}",
                        phase,
                        res,
                    ),
                    Expected::Body(body) => prop_assert!(
                        matches!(res, Ok(ref got) if *got == body),
                        "expected body of {} bytes, got {res:?}",
                        body.len(),
                    ),
                }
                Ok(())
            })?;
        }
    }

    #[test]
    fn parse_url_infers_default_ports() {
        assert_eq!(
            parse_url(&"https://example.com/".parse::<Uri>().unwrap()).unwrap(),
            (true, "example.com".to_string(), 443),
        );
        assert_eq!(
            parse_url(&"http://example.com/".parse::<Uri>().unwrap()).unwrap(),
            (false, "example.com".to_string(), 80),
        );
    }

    #[test]
    fn parse_url_respects_explicit_port() {
        assert_eq!(
            parse_url(&"http://example.com:8080/".parse::<Uri>().unwrap()).unwrap(),
            (false, "example.com".to_string(), 8080),
        );
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        // The bug this guards against: a URL with an explicit non-HTTP(S) scheme used to
        // be accepted and treated as plaintext HTTP, contradicting `NonHttpUrl`'s "only
        // HTTP or HTTPS" contract. A non-HTTP(S) URL must never yield a usable request,
        // by either of two paths: it fails to parse as a URI at all (`file:///...` has an
        // empty authority, which hyper rejects), or it parses and `url_is_https` /
        // `parse_url` reject its scheme.
        for url in [
            "ftp://example.com/",
            "ws://example.com/",
            "wss://example.com/",
            "file:///etc/passwd",
        ] {
            let Ok(uri) = url.parse::<Uri>() else {
                continue; // rejected at the URI-parse boundary; nothing reaches the transport
            };
            assert!(
                matches!(url_is_https(&uri), Err(HttpError::NonHttpUrl)),
                "{url} should be rejected by url_is_https",
            );
            assert!(
                matches!(parse_url(&uri), Err(Error::Http(HttpError::NonHttpUrl))),
                "{url} should be rejected by parse_url",
            );
        }
    }

    #[test]
    fn missing_scheme_is_rejected() {
        let uri = "//example.com/".parse::<Uri>().unwrap();
        assert!(matches!(url_is_https(&uri), Err(HttpError::NonHttpUrl)));
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
