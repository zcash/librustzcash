//! HTTP requests over Tor.
//!
//! The generic machinery lives in [`crate::privacy::http`]; the methods here are thin
//! Tor-specific wrappers that surface [`super::Error`]. The [`HttpError`], [`Retry`], and
//! [`cryptex`] items are re-exported from [`crate::privacy::http`] so that existing
//! `tor::http::*` paths continue to resolve.

use http_body_util::{BodyExt, Empty};
use hyper::{
    Response, StatusCode, Uri,
    body::{Body, Buf, Bytes, Incoming},
    http::request::Builder,
};
use rust_decimal::Decimal;
use serde::de::DeserializeOwned;
use std::future::Future;

pub use crate::privacy::http::{HttpError, Retry, cryptex};

use super::{Client, Error};
use crate::privacy::http::http_request_over;

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
        http_request_over::<Error, Empty<Bytes>, T, F>(
            self,
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
    /// See [`Client::http_get`] for a description of the retry arguments.
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
        http_request_over::<Error, B, T, F>(
            self,
            url,
            |builder| request(builder).method("POST"),
            body,
            parse_response,
            retry_limit,
            retry_filter,
        )
        .await
    }

    /// Makes an HTTP GET request over Tor, parsing the response as JSON.
    ///
    /// This is a simple wrapper around [`Client::http_get`]. Use that method if you need
    /// more control over the request headers or response parsing.
    ///
    /// See [`Client::http_get`] for a description of the retry arguments.
    pub async fn http_get_json<T: DeserializeOwned>(
        &self,
        url: Uri,
        retry_limit: u8,
        retry_filter: impl Fn(Result<StatusCode, &Error>) -> Option<Retry>,
    ) -> Result<Response<T>, Error> {
        http_request_over::<Error, Empty<Bytes>, T, _>(
            self,
            url,
            |builder| {
                builder
                    .method("GET")
                    .header(hyper::header::ACCEPT, "application/json")
            },
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

    /// Fetches the latest USD/ZEC exchange rate over Tor, derived from the given
    /// exchanges.
    ///
    /// Returns:
    /// - `Ok(rate)` if at least one exchange request succeeds.
    /// - `Err(_)` if none of the exchange queries succeed.
    pub async fn get_latest_zec_to_usd_rate(
        &self,
        exchanges: &cryptex::Exchanges,
    ) -> Result<Decimal, Error> {
        self.ensure_bootstrapped().await?;
        Ok(cryptex::get_latest_zec_to_usd_rate(self, exchanges).await?)
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
