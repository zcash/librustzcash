//! HTTP requests over a [`PrivateNetwork`].

use std::{fmt, future::Future, io, sync::Arc, time::Duration};

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
use tracing::{debug, error};

use super::{DynPrivateNetwork, Error, PrivateNetwork, Timeouts};

pub mod cryptex;

/// How a particular connection failure should be retried.
pub enum Retry {
    /// Retry using the same network handle that resulted in this error.
    Same,
    /// Retry using a fresh handle that is isolated from any other usage.
    Isolated,
}

/// The stage of an HTTP request that exceeded its deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeoutPhase {
    /// Opening the network stream to the server, or completing the TLS handshake.
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
async fn with_timeout<T, E: From<HttpError>>(
    limit: Duration,
    phase: TimeoutPhase,
    f: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    tokio::time::timeout(limit, f)
        .await
        .unwrap_or_else(|_| Err(HttpError::Timeout(phase).into()))
}

pub(crate) fn url_is_https(url: &Uri) -> Result<bool, HttpError> {
    // Only HTTP and HTTPS are supported. A missing scheme, or any other scheme (`ftp`,
    // `ws`, `file`, ...), is rejected rather than silently treated as plaintext HTTP.
    match url.scheme() {
        Some(scheme) if scheme == &Scheme::HTTPS => Ok(true),
        Some(scheme) if scheme == &Scheme::HTTP => Ok(false),
        _ => Err(HttpError::NonHttpUrl),
    }
}

pub(crate) fn parse_url(url: &Uri) -> Result<(bool, String, u16), HttpError> {
    let is_https = url_is_https(url)?;

    let host = url.host().ok_or(HttpError::NonHttpUrl)?.to_string();

    let port = match url.port_u16() {
        Some(port) => port,
        None if is_https => 443,
        None => 80,
    };

    Ok((is_https, host, port))
}

/// Applies the caller's `request` closure, then defaults `Accept` to `application/json`
/// if the closure did not already set it.
///
/// The default is applied *after* the closure (rather than before) because
/// [`Builder::header`] appends rather than replaces: setting `Accept` before running the
/// closure would leave the default value in place (as the first of two `Accept` values)
/// even if the closure also set `Accept`, silently defeating any attempt by the caller to
/// override it.
pub(crate) fn with_default_json_accept(
    request: impl Fn(Builder) -> Builder,
) -> impl Fn(Builder) -> Builder {
    move |builder| {
        let builder = request(builder);
        if builder
            .headers_ref()
            .is_some_and(|headers| headers.contains_key(hyper::header::ACCEPT))
        {
            builder
        } else {
            builder.header(hyper::header::ACCEPT, "application/json")
        }
    }
}

/// Makes an HTTP GET request over the given [`PrivateNetwork`].
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
///   to `|_| None`, and you can ensure the same handle is reused by setting this to
///   `|res| res.is_err().then_some(Retry::Same)` (e.g. if you require a persistent
///   network identity across queries).
///
/// The [`PrivateNetwork::timeouts`] of `net` are applied to each attempt individually,
/// so the total time this function can take is bounded by `retry_limit + 1` times those
/// deadlines. A request that exceeds one of them fails with [`HttpError::Timeout`],
/// which `retry_filter` sees like any other error.
#[tracing::instrument(skip(net, request, parse_response, retry_filter))]
pub async fn http_get<N, T, F>(
    net: &N,
    url: Uri,
    request: impl Fn(Builder) -> Builder,
    parse_response: impl FnOnce(Incoming) -> F,
    retry_limit: u8,
    retry_filter: impl Fn(Result<StatusCode, &Error>) -> Option<Retry>,
) -> Result<Response<T>, Error>
where
    N: PrivateNetwork + 'static,
    F: Future<Output = Result<T, Error>>,
{
    http_request_over::<Error, Empty<Bytes>, T, F>(
        net,
        url,
        |builder| request(builder).method("GET"),
        Empty::<Bytes>::new(),
        parse_response,
        retry_limit,
        retry_filter,
    )
    .await
}

/// Makes an HTTP POST request over the given [`PrivateNetwork`].
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
/// See [`http_get`] for a description of the retry arguments.
#[tracing::instrument(skip(net, request, body, parse_response, retry_filter))]
pub async fn http_post<N, B, T, F>(
    net: &N,
    url: Uri,
    request: impl Fn(Builder) -> Builder,
    body: B,
    parse_response: impl FnOnce(Incoming) -> F,
    retry_limit: u8,
    retry_filter: impl Fn(Result<StatusCode, &Error>) -> Option<Retry>,
) -> Result<Response<T>, Error>
where
    N: PrivateNetwork + 'static,
    B: Body + Clone + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    F: Future<Output = Result<T, Error>>,
{
    http_request_over::<Error, B, T, F>(
        net,
        url,
        |builder| request(builder).method("POST"),
        body,
        parse_response,
        retry_limit,
        retry_filter,
    )
    .await
}

/// Makes an HTTP GET request over the given [`PrivateNetwork`], parsing the response as
/// JSON.
///
/// This is a simple wrapper around [`http_get`]. Use that function if you need more
/// control over the response parsing.
///
/// The `request` closure runs first; this function then defaults `Accept` to
/// `application/json` only if the closure did not already set it, so a caller can
/// override the default `Accept` (or add other headers, such as `User-Agent`) by
/// setting them in the closure. See [`http_get`] for the [`Builder`] methods you must
/// not call within it.
///
/// See [`http_get`] for a description of the retry arguments.
pub async fn http_get_json<N, T>(
    net: &N,
    url: Uri,
    request: impl Fn(Builder) -> Builder,
    retry_limit: u8,
    retry_filter: impl Fn(Result<StatusCode, &Error>) -> Option<Retry>,
) -> Result<Response<T>, Error>
where
    N: PrivateNetwork + 'static,
    T: DeserializeOwned,
{
    http_get_json_over(net, url, request, retry_limit, retry_filter).await
}

/// Makes an HTTP GET request that parses its response as JSON, over an erased network
/// handle.
///
/// See [`http_get_json`] for how the `request` closure interacts with the default
/// `Accept` header.
pub(crate) async fn http_get_json_over<T: DeserializeOwned>(
    net: &dyn DynPrivateNetwork,
    url: Uri,
    request: impl Fn(Builder) -> Builder,
    retry_limit: u8,
    retry_filter: impl Fn(Result<StatusCode, &Error>) -> Option<Retry>,
) -> Result<Response<T>, Error> {
    let request = with_default_json_accept(request);
    http_request_over::<Error, Empty<Bytes>, T, _>(
        net,
        url,
        |builder| request(builder).method("GET"),
        Empty::<Bytes>::new(),
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

/// Makes an HTTP request over an erased network handle, with retry handling.
///
/// This is the engine shared by every HTTP helper in the crate. It is generic over the
/// error type `E` so that callers (such as [`crate::tor::Client`]) can surface a
/// backend-specific error type, provided transport and HTTP errors convert into it.
pub(crate) async fn http_request_over<E, B, T, F>(
    net: &dyn DynPrivateNetwork,
    url: Uri,
    request: impl Fn(Builder) -> Builder,
    body: B,
    parse_response: impl FnOnce(Incoming) -> F,
    retry_limit: u8,
    retry_filter: impl Fn(Result<StatusCode, &E>) -> Option<Retry>,
) -> Result<Response<T>, E>
where
    E: From<HttpError> + From<Error>,
    B: Body + Clone + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    F: Future<Output = Result<T, E>>,
{
    let mut retries_remaining = retry_limit;
    let mut isolated: Option<Arc<dyn DynPrivateNetwork>> = None;

    let (parts, body) = loop {
        let current: &dyn DynPrivateNetwork = isolated.as_ref().map_or(net, |c| c.as_ref());
        let response = one_http_request::<E, _>(
            current,
            &current.dyn_timeouts(),
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
                        debug!("Switching to isolated handle for retry");
                        isolated = Some(net.dyn_isolated_handle());
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
            net.dyn_timeouts().response_body,
            TimeoutPhase::ResponseBody,
            parse_response(body),
        )
        .await?,
    ))
}

async fn one_http_request<E, B>(
    net: &dyn DynPrivateNetwork,
    timeouts: &Timeouts,
    url: Uri,
    request: impl FnOnce(Builder) -> Builder,
    body: B,
) -> Result<Response<Incoming>, E>
where
    E: From<HttpError> + From<Error>,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (is_https, host, port) = parse_url(&url)?;

    debug!("Connecting through privacy backend to {}:{}", host, port);

    // The transport stream and the TLS handshake are bounded together, so that
    // `Timeouts::connect` means the same thing here as it does for the gRPC transport
    // (where `tonic` applies it to the connector as a whole).
    if is_https {
        let stream = with_timeout::<_, E>(timeouts.connect, TimeoutPhase::Connect, async {
            let stream = net.dyn_connect(&host, port).await?;

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
            Ok(connector
                .connect(dnsname, stream)
                .await
                .map_err(HttpError::Tls)?)
        })
        .await?;

        with_timeout(
            timeouts.request,
            TimeoutPhase::Request,
            make_http_request(stream, url, request, body),
        )
        .await
    } else {
        let stream = with_timeout::<_, E>(timeouts.connect, TimeoutPhase::Connect, async {
            net.dyn_connect(&host, port).await.map_err(E::from)
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

/// Overwrites `headers`'s `Host` value with `host`.
///
/// Uses [`HeaderMap::insert`], which replaces any existing values, rather than
/// [`Builder::header`] (used for every other header on the request), which only appends.
/// This is what lets [`make_http_request`] enforce that `Host` matches the transport
/// stream and TLS connection even if a caller's request-construction closure also set it.
///
/// [`HeaderMap::insert`]: hyper::HeaderMap::insert
fn set_host_header(headers: &mut hyper::HeaderMap, host: &str) {
    headers.insert(
        hyper::header::HOST,
        hyper::header::HeaderValue::from_str(host)
            .expect("a URI authority is always a valid header value"),
    );
}

async fn make_http_request<E, B>(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    url: Uri,
    request: impl FnOnce(Builder) -> Builder,
    body: B,
) -> Result<Response<Incoming>, E>
where
    E: From<HttpError>,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    debug!("Making request");
    let (mut sender, connection) = conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(HttpError::from)?;

    // Spawn a task to poll the connection and drive the HTTP state. The connection must
    // continue to be driven while the caller consumes the response body, so it cannot be
    // awaited inline. A missing ambient Tokio runtime surfaces as a recoverable
    // [`HttpError::Runtime`] rather than the panic `tokio::spawn` would produce.
    let runtime = tokio::runtime::Handle::try_current().map_err(HttpError::from)?;
    runtime.spawn(async move {
        if let Err(e) = connection.await {
            error!("Connection failed: {}", e);
        }
    });

    // Build the request. We let the caller make whatever request modifications they need,
    // then set the URI and forcibly overwrite the Host header (see `set_host_header`) so
    // that they are guaranteed to match the transport stream and TLS connection,
    // regardless of whether the caller's closure also set Host. Host is `host[":"port]`
    // per RFC 9110: never userinfo, even if `url` carries any, and the port only when
    // it's set.
    let authority = url.authority().expect("Already checked");
    let host = match authority.port() {
        Some(port) => format!("{}:{}", authority.host(), port),
        None => authority.host().to_string(),
    };
    let mut req = request(Request::builder())
        .uri(url)
        .body(body)
        .map_err(HttpError::from)?;
    set_host_header(req.headers_mut(), &host);
    let response = sender.send_request(req).await.map_err(HttpError::from)?;
    debug!("Response status code: {}", response.status());

    Ok(response)
}

/// Errors that can occur while using HTTP over a [`PrivateNetwork`].
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
    /// A TLS-specific IO error.
    Tls(io::Error),
    /// The request did not complete within the corresponding [`Timeouts`] deadline.
    ///
    /// [`Timeouts`]: super::Timeouts
    Timeout(TimeoutPhase),
    /// The status code indicated that the request was unsuccessful.
    ///
    /// This is only returned by APIs that make specific queries, such as the
    /// exchange-rate helpers. Generic APIs like [`http_get`] will not return this error
    /// variant.
    Unsuccessful(hyper::http::StatusCode),
    /// No Tokio runtime was available to drive the HTTP connection.
    Runtime(tokio::runtime::TryCurrentError),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::NonHttpUrl => write!(f, "Only HTTP or HTTPS URLs are supported"),
            HttpError::Http(e) => write!(f, "HTTP error: {e}"),
            HttpError::Hyper(e) => write!(f, "Hyper error: {e}"),
            HttpError::Json(e) => write!(f, "Failed to parse JSON: {e}"),
            HttpError::Tls(e) => write!(f, "TLS error: {e}"),
            HttpError::Timeout(phase) => write!(f, "Timed out while {phase}"),
            HttpError::Unsuccessful(status) => write!(f, "Request was unsuccessful ({status:?})"),
            HttpError::Runtime(e) => write!(
                f,
                "No Tokio runtime available to drive the HTTP connection: {e}"
            ),
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
            HttpError::Tls(e) => Some(e),
            HttpError::Timeout(_) => None,
            HttpError::Unsuccessful(_) => None,
            HttpError::Runtime(e) => Some(e),
        }
    }
}

impl From<tokio::runtime::TryCurrentError> for HttpError {
    fn from(e: tokio::runtime::TryCurrentError) -> Self {
        HttpError::Runtime(e)
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http_body_util::Empty;
    use hyper::{Uri, body::Bytes};
    use tokio::io::AsyncReadExt;

    use super::{
        HttpError, TimeoutPhase, make_http_request, parse_url, set_host_header, url_is_https,
        with_default_json_accept, with_timeout,
    };
    use crate::privacy::Error;

    /// A server that accepts the connection and then never speaks must not be able to
    /// hold a request pending forever.
    #[tokio::test]
    async fn silent_server_times_out() {
        // The far end of this duplex stream is held open for the duration of the test but
        // never read from or written to, modelling a peer that stalls after connecting.
        let (stream, _silent_peer) = tokio::io::duplex(1024);

        let res: Result<_, Error> = with_timeout(
            Duration::from_millis(100),
            TimeoutPhase::Request,
            make_http_request(
                stream,
                "http://example.com/".parse().unwrap(),
                |builder| builder.method("GET"),
                Empty::<Bytes>::new(),
            ),
        )
        .await;

        assert!(
            matches!(
                res,
                Err(Error::Http(HttpError::Timeout(TimeoutPhase::Request)))
            ),
            "expected a request timeout, got {res:?}",
        );
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
                matches!(parse_url(&uri), Err(HttpError::NonHttpUrl)),
                "{url} should be rejected by parse_url",
            );
        }
    }

    #[test]
    fn missing_scheme_is_rejected() {
        let uri = "//example.com/".parse::<Uri>().unwrap();
        assert!(matches!(url_is_https(&uri), Err(HttpError::NonHttpUrl)));
    }

    /// A caller that doesn't set `Accept` itself gets the default `application/json`.
    #[test]
    fn with_default_json_accept_sets_accept_by_default() {
        let builder = with_default_json_accept(|b| b)(hyper::Request::builder());
        assert_eq!(
            builder
                .headers_ref()
                .and_then(|h| h.get(hyper::header::ACCEPT))
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );
    }

    /// The caller's closure runs before the default is applied, so a caller that sets
    /// `Accept` itself gets that value instead of the default. (`Builder::header` appends
    /// rather than replaces, so applying the default first would not achieve this: the
    /// caller's value would just become a second, effectively-ignored `Accept` header.)
    #[test]
    fn with_default_json_accept_lets_caller_override_accept() {
        let builder = with_default_json_accept(|b| b.header(hyper::header::ACCEPT, "text/plain"))(
            hyper::Request::builder(),
        );
        assert_eq!(
            builder
                .headers_ref()
                .and_then(|h| h.get(hyper::header::ACCEPT))
                .and_then(|v| v.to_str().ok()),
            Some("text/plain"),
        );
    }

    /// The caller's closure can also set additional headers, such as `User-Agent`, that
    /// `http_get_json` does not set itself.
    #[test]
    fn with_default_json_accept_allows_additional_headers() {
        let builder =
            with_default_json_accept(|b| b.header(hyper::header::USER_AGENT, "test-agent"))(
                hyper::Request::builder(),
            );
        let headers = builder.headers_ref().unwrap();
        assert_eq!(
            headers
                .get(hyper::header::ACCEPT)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );
        assert_eq!(
            headers
                .get(hyper::header::USER_AGENT)
                .and_then(|v| v.to_str().ok()),
            Some("test-agent"),
        );
    }

    /// With no prior `Host` value, `set_host_header` simply sets it.
    #[test]
    fn set_host_header_sets_host() {
        let mut headers = hyper::HeaderMap::new();
        set_host_header(&mut headers, "example.com");
        assert_eq!(
            headers
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok()),
            Some("example.com"),
        );
    }

    /// A bogus `Host` set by a request-construction closure must not survive into the
    /// final request: `set_host_header` replaces it (via `HeaderMap::insert`) rather than
    /// appending a second, easily-overlooked value alongside it (as `Builder::header`
    /// would), so that `Host` cannot end up disagreeing with the transport stream and TLS
    /// connection that were established using the real host.
    #[test]
    fn set_host_header_overwrites_a_prior_value() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(hyper::header::HOST, "evil.example".parse().unwrap());
        set_host_header(&mut headers, "example.com");

        let values: Vec<&str> = headers
            .get_all(hyper::header::HOST)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, vec!["example.com"]);
    }

    /// `make_http_request` must send exactly the `Host` header derived from the
    /// connection's URL, discarding any `Host` a request-construction closure tries to
    /// set. This pins the actual wiring end-to-end (through `Builder::header`'s append and
    /// `set_host_header`'s insert) rather than just `set_host_header` in isolation:
    /// deleting the `set_host_header` call in `make_http_request` turns this test red. The
    /// URL's userinfo (`user:pass@`) must not appear in `Host` either.
    #[tokio::test]
    async fn make_http_request_forces_host_to_match_the_connection() {
        let (stream, mut peer) = tokio::io::duplex(4096);

        // Nothing ever responds, so `make_http_request` itself would hang forever
        // awaiting a response; drive it in the background and inspect only what it wrote
        // to the wire before that point.
        let _handle = tokio::spawn(make_http_request::<Error, _>(
            stream,
            "http://user:pass@example.com:1234/path".parse().unwrap(),
            |builder| builder.header(hyper::header::HOST, "evil.example"),
            Empty::<Bytes>::new(),
        ));

        // Read until the full request head has arrived.
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = peer.read(&mut buf).await.unwrap();
            assert!(
                n > 0,
                "connection closed before a full request head arrived"
            );
            received.extend_from_slice(&buf[..n]);
            if received.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8(received).unwrap();

        let host_values: Vec<&str> = head
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("host").then(|| value.trim())
            })
            .collect();
        assert_eq!(
            host_values,
            vec!["example.com:1234"],
            "expected exactly one Host header, carrying the connection's own \
             userinfo-stripped host:port, in request head:\n{head}",
        );
    }
}
