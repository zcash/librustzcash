//! A blocking (synchronous) facade over the network-privacy layer.
//!
//! [`PrivacyRuntime`] bundles a Tokio runtime with a [`PrivateNetwork`] backend (held in
//! its erased [`DynPrivateNetwork`] form), exposing synchronous entry points that FFI
//! layers can call without managing async themselves. [`LwdConn`] is a blocking facade
//! over a `lightwalletd` gRPC connection carrying the point queries wallets make over the
//! privacy layer.
//!
//! This module does not require the `tor` feature: construct a [`PrivacyRuntime`] from any
//! [`PrivateNetwork`] via [`PrivacyRuntime::new`]. The [`PrivacyRuntime::create_tor`]
//! convenience constructor is additionally available under the `tor` feature.

use std::sync::Arc;

use tokio::runtime::Runtime;
use tonic::transport::{Channel, Uri};

use transparent::{
    address::{Script, TransparentAddress},
    bundle::{OutPoint, TxOut},
};
use zcash_keys::encoding::AddressCodec;
use zcash_primitives::block::BlockHash;
use zcash_protocol::{
    TxId,
    consensus::{self, BlockHeight},
    value::Zatoshis,
};
use zcash_script::script;

use super::{DormantMode, DynPrivateNetwork, Error as PrivacyError, PrivateNetwork};
use crate::proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient};
use crate::wallet::WalletTransparentOutput;

/// A synchronous runtime that drives a [`PrivateNetwork`] backend.
///
/// It owns a Tokio runtime and an erased handle to the backend, so it can be stored behind
/// an FFI pointer and used from synchronous code.
pub struct PrivacyRuntime {
    runtime: Arc<Runtime>,
    net: Arc<dyn DynPrivateNetwork>,
}

fn build_runtime() -> Result<Arc<Runtime>, Error> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map(Arc::new)
        .map_err(Error::Runtime)
}

impl PrivacyRuntime {
    /// Builds a blocking runtime around the given [`PrivateNetwork`] backend.
    pub fn new(net: impl PrivateNetwork + 'static) -> Result<Self, Error> {
        Ok(Self {
            runtime: build_runtime()?,
            net: Arc::new(net),
        })
    }

    /// Builds a blocking runtime backed by a freshly-bootstrapped Tor client.
    ///
    /// The client's persistent data and cache are stored in `tor_dir`. If
    /// `dangerously_trust_everyone` is set, Tor's filesystem permission checks are
    /// disabled; do this only where the platform already sandboxes the app's data.
    #[cfg(feature = "tor")]
    pub fn create_tor(
        tor_dir: &std::path::Path,
        dangerously_trust_everyone: bool,
    ) -> Result<Self, Error> {
        let runtime = build_runtime()?;
        let client = runtime
            .block_on(async {
                crate::tor::Client::create(
                    tor_dir,
                    |permissions: &mut fs_mistrust::MistrustBuilder| {
                        if dangerously_trust_everyone {
                            permissions.dangerously_trust_everyone();
                        }
                    },
                )
                .await
            })
            .map_err(Error::TorSetup)?;

        Ok(Self {
            runtime,
            net: Arc::new(client),
        })
    }

    /// Returns a new runtime handle whose backend is isolated from this one's, sharing the
    /// same Tokio runtime.
    ///
    /// See [`PrivateNetwork::isolated_handle`] for the isolation semantics.
    #[must_use]
    pub fn isolated_client(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            // Go through `PrivateNetwork::isolated_handle`: calling `dyn_isolated_handle`
            // on the `Arc` itself would resolve to the blanket `DynPrivateNetwork` impl
            // for `Arc<dyn DynPrivateNetwork>` and wrap the handle in an additional layer
            // on every call.
            net: self.net.isolated_handle(),
        }
    }

    /// Changes the backend's current dormant mode. See [`DormantMode`].
    pub fn set_dormant(&self, mode: DormantMode) {
        self.net.dyn_set_dormant(mode);
    }

    /// Connects to the `lightwalletd` server at the given endpoint.
    ///
    /// Each connection returned by this method is isolated from any other usage of the
    /// backend.
    pub fn connect_to_lightwalletd(&self, endpoint: Uri) -> Result<LwdConn, Error> {
        // See `isolated_client` for why this is not `dyn_isolated_handle`.
        let net = self.net.isolated_handle();
        let conn = self
            .runtime
            .block_on(async { super::grpc::connect_to_lightwalletd(&net, endpoint).await })?;

        Ok(LwdConn {
            runtime: self.runtime.clone(),
            _net: net,
            conn,
        })
    }

    /// Makes an HTTP GET request over the backend. See [`super::http::http_get`].
    pub fn http_get<T, F>(
        &self,
        url: Uri,
        request: impl Fn(hyper::http::request::Builder) -> hyper::http::request::Builder,
        parse_response: impl FnOnce(hyper::body::Incoming) -> F,
        retry_limit: u8,
        retry_filter: impl Fn(Result<hyper::StatusCode, &PrivacyError>) -> Option<super::http::Retry>,
    ) -> Result<hyper::Response<T>, PrivacyError>
    where
        F: std::future::Future<Output = Result<T, PrivacyError>>,
    {
        self.runtime.block_on(super::http::http_get(
            &self.net,
            url,
            request,
            parse_response,
            retry_limit,
            retry_filter,
        ))
    }

    /// Makes an HTTP POST request over the backend. See [`super::http::http_post`].
    #[allow(clippy::too_many_arguments)]
    pub fn http_post<B, T, F>(
        &self,
        url: Uri,
        request: impl Fn(hyper::http::request::Builder) -> hyper::http::request::Builder,
        body: B,
        parse_response: impl FnOnce(hyper::body::Incoming) -> F,
        retry_limit: u8,
        retry_filter: impl Fn(Result<hyper::StatusCode, &PrivacyError>) -> Option<super::http::Retry>,
    ) -> Result<hyper::Response<T>, PrivacyError>
    where
        B: hyper::body::Body + Clone + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        F: std::future::Future<Output = Result<T, PrivacyError>>,
    {
        self.runtime.block_on(super::http::http_post(
            &self.net,
            url,
            request,
            body,
            parse_response,
            retry_limit,
            retry_filter,
        ))
    }

    /// Fetches the latest USD/ZEC exchange rate over the backend, derived from the given
    /// exchanges. See [`super::http::cryptex::get_latest_zec_to_usd_rate`].
    pub fn get_latest_zec_to_usd_rate(
        &self,
        exchanges: &super::http::cryptex::Exchanges,
    ) -> Result<rust_decimal::Decimal, PrivacyError> {
        self.runtime
            .block_on(super::http::cryptex::get_latest_zec_to_usd_rate(
                &self.net, exchanges,
            ))
    }
}

/// A blocking facade over a `lightwalletd` gRPC connection established through a
/// [`PrivacyRuntime`].
pub struct LwdConn {
    conn: CompactTxStreamerClient<Channel>,
    _net: Arc<dyn DynPrivateNetwork>,
    runtime: Arc<Runtime>,
}

impl LwdConn {
    /// Returns information about this `lightwalletd` instance and the blockchain.
    pub fn get_lightd_info(&mut self) -> Result<service::LightdInfo, Error> {
        Ok(self
            .runtime
            .clone()
            .block_on(self.conn.get_lightd_info(service::Empty {}))?
            .into_inner())
    }

    /// Fetches the height and hash of the block at the tip of the best chain.
    pub fn get_latest_block(&mut self) -> Result<(BlockHeight, BlockHash), Error> {
        let response = self
            .runtime
            .clone()
            .block_on(self.conn.get_latest_block(service::ChainSpec {}))?
            .into_inner();

        Ok((
            BlockHeight::from_u32(response.height.try_into()?),
            BlockHash::try_from_slice(&response.hash).ok_or(Error::InvalidBlockHash {
                length: response.hash.len(),
            })?,
        ))
    }

    /// Fetches the raw [`service::BlockId`] of the block at the tip of the best chain.
    pub fn get_latest_block_id(&mut self) -> Result<service::BlockId, Error> {
        Ok(self
            .runtime
            .clone()
            .block_on(self.conn.get_latest_block(service::ChainSpec {}))?
            .into_inner())
    }

    /// Fetches the transaction with the given ID, returning its raw bytes and the height of
    /// the block it was mined in (0 if unmined).
    pub fn get_transaction(&mut self, txid: TxId) -> Result<(Vec<u8>, u64), Error> {
        let request = service::TxFilter {
            hash: txid.as_ref().to_vec(),
            ..Default::default()
        };

        let response = self
            .runtime
            .clone()
            .block_on(self.conn.get_transaction(request))?
            .into_inner();

        Ok((response.data, response.height))
    }

    /// Submits a transaction to the Zcash network.
    pub fn send_transaction(&mut self, tx_bytes: Vec<u8>) -> Result<(), Error> {
        let request = service::RawTransaction {
            data: tx_bytes,
            ..Default::default()
        };

        let response = self
            .runtime
            .clone()
            .block_on(self.conn.send_transaction(request))?
            .into_inner();

        if response.error_code == 0 {
            Ok(())
        } else {
            Err(Error::TransactionRejected {
                code: response.error_code,
                message: response.error_message,
            })
        }
    }

    /// Fetches the note commitment tree state corresponding to the given block.
    pub fn get_tree_state(&mut self, height: BlockHeight) -> Result<service::TreeState, Error> {
        let request = service::BlockId {
            height: u32::from(height).into(),
            ..Default::default()
        };

        Ok(self
            .runtime
            .clone()
            .block_on(self.conn.get_tree_state(request))?
            .into_inner())
    }

    /// Discovers UTXOs received by the given transparent address in the provided block
    /// range, invoking `f` with each corresponding [`WalletTransparentOutput`].
    pub fn with_taddress_utxos<E: From<Error>>(
        &mut self,
        params: &impl consensus::Parameters,
        address: TransparentAddress,
        start: Option<BlockHeight>,
        limit: Option<u32>,
        mut f: impl FnMut(WalletTransparentOutput<()>) -> Result<(), E>,
    ) -> Result<(), E> {
        let request = service::GetAddressUtxosArg {
            addresses: vec![address.encode(params)],
            start_height: start.map_or(0, u64::from),
            max_entries: match limit {
                None => 0,
                Some(0) => return Err(Error::InvalidLimit.into()),
                Some(n) => n,
            },
        };

        self.runtime.clone().block_on(async {
            let mut utxos = self
                .conn
                .get_address_utxos_stream(request)
                .await
                .map_err(Error::from)
                .map_err(E::from)?
                .into_inner();

            while let Some(result) = utxos
                .message()
                .await
                .map_err(Error::from)
                .map_err(E::from)?
            {
                let output = WalletTransparentOutput::<()>::from_parts(
                    OutPoint::new(
                        result.txid[..]
                            .try_into()
                            .map_err(Error::from)
                            .map_err(E::from)?,
                        result
                            .index
                            .try_into()
                            .map_err(Error::from)
                            .map_err(E::from)?,
                    ),
                    TxOut::new(
                        Zatoshis::from_nonnegative_i64(result.value_zat)
                            .map_err(Error::from)
                            .map_err(E::from)?,
                        Script(script::Code(result.script)),
                    ),
                    Some(BlockHeight::from(
                        u32::try_from(result.height)
                            .map_err(Error::from)
                            .map_err(E::from)?,
                    )),
                    None,
                    None,
                    None,
                )
                .ok_or(Error::InvalidUtxo)
                .map_err(E::from)?;

                f(output)?;
            }

            Ok(())
        })
    }

    /// Invokes `f` with the transactions corresponding to the given t-address within the
    /// given block range, and the height of the main-chain block they are mined in (if
    /// any).
    pub fn with_taddress_transactions<E: From<Error>>(
        &mut self,
        params: &impl consensus::Parameters,
        address: TransparentAddress,
        start: BlockHeight,
        end: Option<BlockHeight>,
        mut f: impl FnMut(Vec<u8>, Option<BlockHeight>) -> Result<(), E>,
    ) -> Result<(), E> {
        let request = service::TransparentAddressBlockFilter {
            address: address.encode(params),
            range: Some(service::BlockRange {
                start: Some(service::BlockId {
                    height: u32::from(start).into(),
                    ..Default::default()
                }),
                end: end.map(|height| service::BlockId {
                    height: u32::from(height).into(),
                    ..Default::default()
                }),
                pool_types: vec![],
            }),
        };

        self.runtime.clone().block_on(async {
            let mut txs = self
                .conn
                .get_taddress_txids(request)
                .await
                .map_err(Error::from)
                .map_err(E::from)?
                .into_inner();

            while let Some(tx) = txs.message().await.map_err(Error::from).map_err(E::from)? {
                let mined_height = match tx.height {
                    0 => None,
                    // TODO: [#1447] Represent "not in main chain".
                    0xffff_ffff_ffff_ffff => None,
                    h => Some(BlockHeight::from_u32(
                        h.try_into().map_err(Error::from).map_err(E::from)?,
                    )),
                };

                f(tx.data, mined_height)?;
            }

            Ok(())
        })
    }
}

/// Errors that can occur while using the blocking network-privacy facade.
#[derive(Debug)]
pub enum Error {
    /// The internal Tokio runtime could not be built.
    Runtime(std::io::Error),
    /// A network-privacy layer error occurred (connecting or transferring data).
    Network(PrivacyError),
    /// Bootstrapping the Tor backend failed.
    #[cfg(feature = "tor")]
    TorSetup(crate::tor::Error),
    /// The `lightwalletd` server returned a gRPC status error.
    Grpc(tonic::Status),
    /// The server returned a block hash whose length was not 32 bytes.
    InvalidBlockHash {
        /// The length of the returned hash.
        length: usize,
    },
    /// A numeric field from the server was out of the supported range.
    IntegerOverflow(std::num::TryFromIntError),
    /// A fixed-width field from the server had an unexpected length.
    InvalidSlice(std::array::TryFromSliceError),
    /// A value field from the server was not a valid amount of zatoshis.
    InvalidAmount(zcash_protocol::value::BalanceError),
    /// A returned UTXO did not correspond to a P2PKH or P2SH address.
    InvalidUtxo,
    /// A zero `limit` was supplied to a bounded query.
    InvalidLimit,
    /// The server rejected a submitted transaction.
    TransactionRejected {
        /// The error code returned by the server.
        code: i32,
        /// The error message returned by the server.
        message: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Runtime(e) => write!(f, "Failed to build Tokio runtime: {e}"),
            Error::Network(e) => write!(f, "Network privacy error: {e}"),
            #[cfg(feature = "tor")]
            Error::TorSetup(e) => write!(f, "Failed to set up Tor: {e}"),
            Error::Grpc(e) => write!(f, "lightwalletd gRPC error: {e}"),
            Error::InvalidBlockHash { length } => {
                write!(f, "Returned block hash has invalid length {length}")
            }
            Error::IntegerOverflow(e) => write!(f, "Numeric field out of range: {e}"),
            Error::InvalidSlice(e) => write!(f, "Fixed-width field had wrong length: {e}"),
            Error::InvalidAmount(e) => write!(f, "Invalid amount: {e}"),
            Error::InvalidUtxo => write!(
                f,
                "Received UTXO that doesn't correspond to a valid P2PKH or P2SH address"
            ),
            Error::InvalidLimit => write!(f, "Invalid limit"),
            Error::TransactionRejected { code, message } => {
                write!(f, "Failed to submit transaction ({code}): {message}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Runtime(e) => Some(e),
            Error::Network(e) => Some(e),
            #[cfg(feature = "tor")]
            Error::TorSetup(e) => Some(e),
            Error::Grpc(e) => Some(e),
            Error::IntegerOverflow(e) => Some(e),
            Error::InvalidSlice(e) => Some(e),
            Error::InvalidAmount(e) => Some(e),
            Error::InvalidBlockHash { .. }
            | Error::InvalidUtxo
            | Error::InvalidLimit
            | Error::TransactionRejected { .. } => None,
        }
    }
}

impl From<PrivacyError> for Error {
    fn from(e: PrivacyError) -> Self {
        Error::Network(e)
    }
}

impl From<tonic::Status> for Error {
    fn from(e: tonic::Status) -> Self {
        Error::Grpc(e)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(e: std::num::TryFromIntError) -> Self {
        Error::IntegerOverflow(e)
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(e: std::array::TryFromSliceError) -> Self {
        Error::InvalidSlice(e)
    }
}

impl From<zcash_protocol::value::BalanceError> for Error {
    fn from(e: zcash_protocol::value::BalanceError) -> Self {
        Error::InvalidAmount(e)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde::Deserialize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::PrivacyRuntime;
    use crate::privacy::{DormantMode, DynPrivateNetwork, Error as PrivacyError, PrivateNetwork};

    /// A [`PrivateNetwork`] whose connections are served by an in-process HTTP responder
    /// over Tokio duplex streams, for exercising the privacy plumbing without a network.
    struct MockNetwork;

    impl PrivateNetwork for MockNetwork {
        type Stream = tokio::io::DuplexStream;

        async fn connect(&self, _host: &str, _port: u16) -> Result<Self::Stream, PrivacyError> {
            let (client_side, server_side) = tokio::io::duplex(4096);
            tokio::spawn(serve_http(server_side));
            Ok(client_side)
        }

        fn isolated_handle(&self) -> Self {
            MockNetwork
        }

        fn set_dormant(&self, _mode: DormantMode) {}
    }

    async fn serve_http(mut stream: tokio::io::DuplexStream) {
        // Read (and discard) the request; a small GET fits in one read.
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let body = br#"{"price":"1.23"}"#;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len(),
        );
        let _ = stream.write_all(head.as_bytes()).await;
        let _ = stream.write_all(body).await;
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
    }

    #[derive(Deserialize)]
    struct Body {
        price: String,
    }

    #[test]
    fn http_round_trips_over_concrete_and_erased_backends() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let url: hyper::Uri = "http://example.com/".parse().unwrap();

            // Over the concrete backend.
            let net = MockNetwork;
            let res = crate::privacy::http::http_get_json::<MockNetwork, Body>(
                &net,
                url.clone(),
                0,
                |_| None,
            )
            .await
            .unwrap();
            assert_eq!(res.into_body().price, "1.23");

            // Over the erased backend, proving `Arc<dyn DynPrivateNetwork>` plumbs through.
            let erased: Arc<dyn DynPrivateNetwork> = Arc::new(MockNetwork);
            let res = crate::privacy::http::http_get_json::<Arc<dyn DynPrivateNetwork>, Body>(
                &erased,
                url,
                0,
                |_| None,
            )
            .await
            .unwrap();
            assert_eq!(res.into_body().price, "1.23");
        });
    }

    #[test]
    fn privacy_runtime_wraps_a_backend() {
        let runtime = PrivacyRuntime::new(MockNetwork).unwrap();
        let _isolated = runtime.isolated_client();
        runtime.set_dormant(DormantMode::Soft);
    }

    // Confirms the gRPC helper instantiates over the erased backend (compile-time check).
    #[allow(dead_code)]
    async fn grpc_plumbing_typechecks(net: Arc<dyn DynPrivateNetwork>, uri: tonic::transport::Uri) {
        let _ = crate::privacy::grpc::connect_to_lightwalletd(&net, uri).await;
    }
}
