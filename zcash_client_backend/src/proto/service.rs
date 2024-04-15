/// A BlockID message contains identifiers to select a block: a height or a
/// hash. Specification by hash is not implemented, but may be in the future.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockId {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// BlockRange specifies a series of blocks from start to end inclusive.
/// Both BlockIDs must be heights; specification by hash is not yet supported.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockRange {
    #[prost(message, optional, tag = "1")]
    pub start: ::core::option::Option<BlockId>,
    #[prost(message, optional, tag = "2")]
    pub end: ::core::option::Option<BlockId>,
}
/// A TxFilter contains the information needed to identify a particular
/// transaction: either a block and an index, or a direct transaction hash.
/// Currently, only specification by hash is supported.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TxFilter {
    /// block identifier, height or hash
    #[prost(message, optional, tag = "1")]
    pub block: ::core::option::Option<BlockId>,
    /// index within the block
    #[prost(uint64, tag = "2")]
    pub index: u64,
    /// transaction ID (hash, txid)
    #[prost(bytes = "vec", tag = "3")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
/// RawTransaction contains the complete transaction data. It also optionally includes
/// the block height in which the transaction was included, or, when returned
/// by GetMempoolStream(), the latest block height.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RawTransaction {
    /// exact data returned by Zcash 'getrawtransaction'
    #[prost(bytes = "vec", tag = "1")]
    pub data: ::prost::alloc::vec::Vec<u8>,
    /// height that the transaction was mined (or -1)
    #[prost(uint64, tag = "2")]
    pub height: u64,
}
/// A SendResponse encodes an error code and a string. It is currently used
/// only by SendTransaction(). If error code is zero, the operation was
/// successful; if non-zero, it and the message specify the failure.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendResponse {
    #[prost(int32, tag = "1")]
    pub error_code: i32,
    #[prost(string, tag = "2")]
    pub error_message: ::prost::alloc::string::String,
}
/// Chainspec is a placeholder to allow specification of a particular chain fork.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainSpec {}
/// Empty is for gRPCs that take no arguments, currently only GetLightdInfo.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Empty {}
/// LightdInfo returns various information about this lightwalletd instance
/// and the state of the blockchain.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LightdInfo {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub vendor: ::prost::alloc::string::String,
    /// true
    #[prost(bool, tag = "3")]
    pub taddr_support: bool,
    /// either "main" or "test"
    #[prost(string, tag = "4")]
    pub chain_name: ::prost::alloc::string::String,
    /// depends on mainnet or testnet
    #[prost(uint64, tag = "5")]
    pub sapling_activation_height: u64,
    /// protocol identifier, see consensus/upgrades.cpp
    #[prost(string, tag = "6")]
    pub consensus_branch_id: ::prost::alloc::string::String,
    /// latest block on the best chain
    #[prost(uint64, tag = "7")]
    pub block_height: u64,
    #[prost(string, tag = "8")]
    pub git_commit: ::prost::alloc::string::String,
    #[prost(string, tag = "9")]
    pub branch: ::prost::alloc::string::String,
    #[prost(string, tag = "10")]
    pub build_date: ::prost::alloc::string::String,
    #[prost(string, tag = "11")]
    pub build_user: ::prost::alloc::string::String,
    /// less than tip height if zcashd is syncing
    #[prost(uint64, tag = "12")]
    pub estimated_height: u64,
    /// example: "v4.1.1-877212414"
    #[prost(string, tag = "13")]
    pub zcashd_build: ::prost::alloc::string::String,
    /// example: "/MagicBean:4.1.1/"
    #[prost(string, tag = "14")]
    pub zcashd_subversion: ::prost::alloc::string::String,
}
/// TransparentAddressBlockFilter restricts the results to the given address
/// or block range.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransparentAddressBlockFilter {
    /// t-address
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
    /// start, end heights
    #[prost(message, optional, tag = "2")]
    pub range: ::core::option::Option<BlockRange>,
}
/// Duration is currently used only for testing, so that the Ping rpc
/// can simulate a delay, to create many simultaneous connections. Units
/// are microseconds.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Duration {
    #[prost(int64, tag = "1")]
    pub interval_us: i64,
}
/// PingResponse is used to indicate concurrency, how many Ping rpcs
/// are executing upon entry and upon exit (after the delay).
/// This rpc is used for testing only.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PingResponse {
    #[prost(int64, tag = "1")]
    pub entry: i64,
    #[prost(int64, tag = "2")]
    pub exit: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Address {
    #[prost(string, tag = "1")]
    pub address: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddressList {
    #[prost(string, repeated, tag = "1")]
    pub addresses: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Balance {
    #[prost(int64, tag = "1")]
    pub value_zat: i64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Exclude {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub txid: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// The TreeState is derived from the Zcash z_gettreestate rpc.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TreeState {
    /// "main" or "test"
    #[prost(string, tag = "1")]
    pub network: ::prost::alloc::string::String,
    /// block height
    #[prost(uint64, tag = "2")]
    pub height: u64,
    /// block id
    #[prost(string, tag = "3")]
    pub hash: ::prost::alloc::string::String,
    /// Unix epoch time when the block was mined
    #[prost(uint32, tag = "4")]
    pub time: u32,
    /// sapling commitment tree state
    #[prost(string, tag = "5")]
    pub sapling_tree: ::prost::alloc::string::String,
    /// orchard commitment tree state
    #[prost(string, tag = "6")]
    pub orchard_tree: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSubtreeRootsArg {
    /// Index identifying where to start returning subtree roots
    #[prost(uint32, tag = "1")]
    pub start_index: u32,
    /// Shielded protocol to return subtree roots for
    #[prost(enumeration = "ShieldedProtocol", tag = "2")]
    pub shielded_protocol: i32,
    /// Maximum number of entries to return, or 0 for all entries.
    #[prost(uint32, tag = "3")]
    pub max_entries: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubtreeRoot {
    /// The 32-byte Merkle root of the subtree.
    #[prost(bytes = "vec", tag = "2")]
    pub root_hash: ::prost::alloc::vec::Vec<u8>,
    /// The hash of the block that completed this subtree.
    #[prost(bytes = "vec", tag = "3")]
    pub completing_block_hash: ::prost::alloc::vec::Vec<u8>,
    /// The height of the block that completed this subtree in the main chain.
    #[prost(uint64, tag = "4")]
    pub completing_block_height: u64,
}
/// Results are sorted by height, which makes it easy to issue another
/// request that picks up from where the previous left off.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAddressUtxosArg {
    #[prost(string, repeated, tag = "1")]
    pub addresses: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(uint64, tag = "2")]
    pub start_height: u64,
    /// zero means unlimited
    #[prost(uint32, tag = "3")]
    pub max_entries: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAddressUtxosReply {
    #[prost(string, tag = "6")]
    pub address: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "1")]
    pub txid: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "2")]
    pub index: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub script: ::prost::alloc::vec::Vec<u8>,
    #[prost(int64, tag = "4")]
    pub value_zat: i64,
    #[prost(uint64, tag = "5")]
    pub height: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetAddressUtxosReplyList {
    #[prost(message, repeated, tag = "1")]
    pub address_utxos: ::prost::alloc::vec::Vec<GetAddressUtxosReply>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ShieldedProtocol {
    Sapling = 0,
    Orchard = 1,
}
impl ShieldedProtocol {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ShieldedProtocol::Sapling => "sapling",
            ShieldedProtocol::Orchard => "orchard",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "sapling" => Some(Self::Sapling),
            "orchard" => Some(Self::Orchard),
            _ => None,
        }
    }
}
/// Generated client implementations.
#[cfg(feature = "lightwalletd-tonic")]
pub mod compact_tx_streamer_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct CompactTxStreamerClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl<T> CompactTxStreamerClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> CompactTxStreamerClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            CompactTxStreamerClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// Return the height of the tip of the best chain
        pub async fn get_latest_block(
            &mut self,
            request: impl tonic::IntoRequest<super::ChainSpec>,
        ) -> std::result::Result<tonic::Response<super::BlockId>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetLatestBlock",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        /// Return the compact block corresponding to the given block identifier
        pub async fn get_block(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockId>,
        ) -> std::result::Result<
            tonic::Response<crate::proto::compact_formats::CompactBlock>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlock",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetBlock",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        /// Same as GetBlock except actions contain only nullifiers
        pub async fn get_block_nullifiers(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockId>,
        ) -> std::result::Result<
            tonic::Response<crate::proto::compact_formats::CompactBlock>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockNullifiers",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetBlockNullifiers",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        /// Return a list of consecutive compact blocks
        pub async fn get_block_range(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockRange>,
        ) -> std::result::Result<
            tonic::Response<
                tonic::codec::Streaming<crate::proto::compact_formats::CompactBlock>,
            >,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetBlockRange",
                    ),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        /// Same as GetBlockRange except actions contain only nullifiers
        pub async fn get_block_range_nullifiers(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockRange>,
        ) -> std::result::Result<
            tonic::Response<
                tonic::codec::Streaming<crate::proto::compact_formats::CompactBlock>,
            >,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRangeNullifiers",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetBlockRangeNullifiers",
                    ),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        /// Return the requested full (not compact) transaction (as from zcashd)
        pub async fn get_transaction(
            &mut self,
            request: impl tonic::IntoRequest<super::TxFilter>,
        ) -> std::result::Result<tonic::Response<super::RawTransaction>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetTransaction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        /// Submit the given transaction to the Zcash network
        pub async fn send_transaction(
            &mut self,
            request: impl tonic::IntoRequest<super::RawTransaction>,
        ) -> std::result::Result<tonic::Response<super::SendResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "SendTransaction",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        /// Return the txids corresponding to the given t-address within the given block range
        pub async fn get_taddress_txids(
            &mut self,
            request: impl tonic::IntoRequest<super::TransparentAddressBlockFilter>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::RawTransaction>>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressTxids",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetTaddressTxids",
                    ),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        pub async fn get_taddress_balance(
            &mut self,
            request: impl tonic::IntoRequest<super::AddressList>,
        ) -> std::result::Result<tonic::Response<super::Balance>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressBalance",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetTaddressBalance",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_taddress_balance_stream(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::Address>,
        ) -> std::result::Result<tonic::Response<super::Balance>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressBalanceStream",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetTaddressBalanceStream",
                    ),
                );
            self.inner.client_streaming(req, path, codec).await
        }
        /// Return the compact transactions currently in the mempool; the results
        /// can be a few seconds out of date. If the Exclude list is empty, return
        /// all transactions; otherwise return all *except* those in the Exclude list
        /// (if any); this allows the client to avoid receiving transactions that it
        /// already has (from an earlier call to this rpc). The transaction IDs in the
        /// Exclude list can be shortened to any number of bytes to make the request
        /// more bandwidth-efficient; if two or more transactions in the mempool
        /// match a shortened txid, they are all sent (none is excluded). Transactions
        /// in the exclude list that don't exist in the mempool are ignored.
        pub async fn get_mempool_tx(
            &mut self,
            request: impl tonic::IntoRequest<super::Exclude>,
        ) -> std::result::Result<
            tonic::Response<
                tonic::codec::Streaming<crate::proto::compact_formats::CompactTx>,
            >,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolTx",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetMempoolTx",
                    ),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        /// Return a stream of current Mempool transactions. This will keep the output stream open while
        /// there are mempool transactions. It will close the returned stream when a new block is mined.
        pub async fn get_mempool_stream(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::RawTransaction>>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolStream",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetMempoolStream",
                    ),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        /// GetTreeState returns the note commitment tree state corresponding to the given block.
        /// See section 3.7 of the Zcash protocol specification. It returns several other useful
        /// values also (even though they can be obtained using GetBlock).
        /// The block can be specified by either height or hash.
        pub async fn get_tree_state(
            &mut self,
            request: impl tonic::IntoRequest<super::BlockId>,
        ) -> std::result::Result<tonic::Response<super::TreeState>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetTreeState",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_latest_tree_state(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> std::result::Result<tonic::Response<super::TreeState>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestTreeState",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetLatestTreeState",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        /// Returns a stream of information about roots of subtrees of the Sapling and Orchard
        /// note commitment trees.
        pub async fn get_subtree_roots(
            &mut self,
            request: impl tonic::IntoRequest<super::GetSubtreeRootsArg>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::SubtreeRoot>>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetSubtreeRoots",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetSubtreeRoots",
                    ),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        pub async fn get_address_utxos(
            &mut self,
            request: impl tonic::IntoRequest<super::GetAddressUtxosArg>,
        ) -> std::result::Result<
            tonic::Response<super::GetAddressUtxosReplyList>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetAddressUtxos",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetAddressUtxos",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn get_address_utxos_stream(
            &mut self,
            request: impl tonic::IntoRequest<super::GetAddressUtxosArg>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::GetAddressUtxosReply>>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetAddressUtxosStream",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetAddressUtxosStream",
                    ),
                );
            self.inner.server_streaming(req, path, codec).await
        }
        /// Return information about this lightwalletd instance and the blockchain
        pub async fn get_lightd_info(
            &mut self,
            request: impl tonic::IntoRequest<super::Empty>,
        ) -> std::result::Result<tonic::Response<super::LightdInfo>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "cash.z.wallet.sdk.rpc.CompactTxStreamer",
                        "GetLightdInfo",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        /// Testing-only, requires lightwalletd --ping-very-insecure (do not enable in production)
        pub async fn ping(
            &mut self,
            request: impl tonic::IntoRequest<super::Duration>,
        ) -> std::result::Result<tonic::Response<super::PingResponse>, tonic::Status> {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/Ping",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new("cash.z.wallet.sdk.rpc.CompactTxStreamer", "Ping"),
                );
            self.inner.unary(req, path, codec).await
        }
    }
}
