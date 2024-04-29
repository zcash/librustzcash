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
/// Generated server implementations.
pub mod compact_tx_streamer_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with CompactTxStreamerServer.
    #[async_trait]
    pub trait CompactTxStreamer: Send + Sync + 'static {
        /// Return the height of the tip of the best chain
        async fn get_latest_block(
            &self,
            request: tonic::Request<super::ChainSpec>,
        ) -> std::result::Result<tonic::Response<super::BlockId>, tonic::Status>;
        /// Return the compact block corresponding to the given block identifier
        async fn get_block(
            &self,
            request: tonic::Request<super::BlockId>,
        ) -> std::result::Result<
            tonic::Response<crate::proto::compact_formats::CompactBlock>,
            tonic::Status,
        >;
        /// Same as GetBlock except actions contain only nullifiers
        async fn get_block_nullifiers(
            &self,
            request: tonic::Request<super::BlockId>,
        ) -> std::result::Result<
            tonic::Response<crate::proto::compact_formats::CompactBlock>,
            tonic::Status,
        >;
        /// Server streaming response type for the GetBlockRange method.
        type GetBlockRangeStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<
                    crate::proto::compact_formats::CompactBlock,
                    tonic::Status,
                >,
            >
            + Send
            + 'static;
        /// Return a list of consecutive compact blocks
        async fn get_block_range(
            &self,
            request: tonic::Request<super::BlockRange>,
        ) -> std::result::Result<
            tonic::Response<Self::GetBlockRangeStream>,
            tonic::Status,
        >;
        /// Server streaming response type for the GetBlockRangeNullifiers method.
        type GetBlockRangeNullifiersStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<
                    crate::proto::compact_formats::CompactBlock,
                    tonic::Status,
                >,
            >
            + Send
            + 'static;
        /// Same as GetBlockRange except actions contain only nullifiers
        async fn get_block_range_nullifiers(
            &self,
            request: tonic::Request<super::BlockRange>,
        ) -> std::result::Result<
            tonic::Response<Self::GetBlockRangeNullifiersStream>,
            tonic::Status,
        >;
        /// Return the requested full (not compact) transaction (as from zcashd)
        async fn get_transaction(
            &self,
            request: tonic::Request<super::TxFilter>,
        ) -> std::result::Result<tonic::Response<super::RawTransaction>, tonic::Status>;
        /// Submit the given transaction to the Zcash network
        async fn send_transaction(
            &self,
            request: tonic::Request<super::RawTransaction>,
        ) -> std::result::Result<tonic::Response<super::SendResponse>, tonic::Status>;
        /// Server streaming response type for the GetTaddressTxids method.
        type GetTaddressTxidsStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::RawTransaction, tonic::Status>,
            >
            + Send
            + 'static;
        /// Return the txids corresponding to the given t-address within the given block range
        async fn get_taddress_txids(
            &self,
            request: tonic::Request<super::TransparentAddressBlockFilter>,
        ) -> std::result::Result<
            tonic::Response<Self::GetTaddressTxidsStream>,
            tonic::Status,
        >;
        async fn get_taddress_balance(
            &self,
            request: tonic::Request<super::AddressList>,
        ) -> std::result::Result<tonic::Response<super::Balance>, tonic::Status>;
        async fn get_taddress_balance_stream(
            &self,
            request: tonic::Request<tonic::Streaming<super::Address>>,
        ) -> std::result::Result<tonic::Response<super::Balance>, tonic::Status>;
        /// Server streaming response type for the GetMempoolTx method.
        type GetMempoolTxStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<
                    crate::proto::compact_formats::CompactTx,
                    tonic::Status,
                >,
            >
            + Send
            + 'static;
        /// Return the compact transactions currently in the mempool; the results
        /// can be a few seconds out of date. If the Exclude list is empty, return
        /// all transactions; otherwise return all *except* those in the Exclude list
        /// (if any); this allows the client to avoid receiving transactions that it
        /// already has (from an earlier call to this rpc). The transaction IDs in the
        /// Exclude list can be shortened to any number of bytes to make the request
        /// more bandwidth-efficient; if two or more transactions in the mempool
        /// match a shortened txid, they are all sent (none is excluded). Transactions
        /// in the exclude list that don't exist in the mempool are ignored.
        async fn get_mempool_tx(
            &self,
            request: tonic::Request<super::Exclude>,
        ) -> std::result::Result<
            tonic::Response<Self::GetMempoolTxStream>,
            tonic::Status,
        >;
        /// Server streaming response type for the GetMempoolStream method.
        type GetMempoolStreamStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::RawTransaction, tonic::Status>,
            >
            + Send
            + 'static;
        /// Return a stream of current Mempool transactions. This will keep the output stream open while
        /// there are mempool transactions. It will close the returned stream when a new block is mined.
        async fn get_mempool_stream(
            &self,
            request: tonic::Request<super::Empty>,
        ) -> std::result::Result<
            tonic::Response<Self::GetMempoolStreamStream>,
            tonic::Status,
        >;
        /// GetTreeState returns the note commitment tree state corresponding to the given block.
        /// See section 3.7 of the Zcash protocol specification. It returns several other useful
        /// values also (even though they can be obtained using GetBlock).
        /// The block can be specified by either height or hash.
        async fn get_tree_state(
            &self,
            request: tonic::Request<super::BlockId>,
        ) -> std::result::Result<tonic::Response<super::TreeState>, tonic::Status>;
        async fn get_latest_tree_state(
            &self,
            request: tonic::Request<super::Empty>,
        ) -> std::result::Result<tonic::Response<super::TreeState>, tonic::Status>;
        /// Server streaming response type for the GetSubtreeRoots method.
        type GetSubtreeRootsStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::SubtreeRoot, tonic::Status>,
            >
            + Send
            + 'static;
        /// Returns a stream of information about roots of subtrees of the Sapling and Orchard
        /// note commitment trees.
        async fn get_subtree_roots(
            &self,
            request: tonic::Request<super::GetSubtreeRootsArg>,
        ) -> std::result::Result<
            tonic::Response<Self::GetSubtreeRootsStream>,
            tonic::Status,
        >;
        async fn get_address_utxos(
            &self,
            request: tonic::Request<super::GetAddressUtxosArg>,
        ) -> std::result::Result<
            tonic::Response<super::GetAddressUtxosReplyList>,
            tonic::Status,
        >;
        /// Server streaming response type for the GetAddressUtxosStream method.
        type GetAddressUtxosStreamStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::GetAddressUtxosReply, tonic::Status>,
            >
            + Send
            + 'static;
        async fn get_address_utxos_stream(
            &self,
            request: tonic::Request<super::GetAddressUtxosArg>,
        ) -> std::result::Result<
            tonic::Response<Self::GetAddressUtxosStreamStream>,
            tonic::Status,
        >;
        /// Return information about this lightwalletd instance and the blockchain
        async fn get_lightd_info(
            &self,
            request: tonic::Request<super::Empty>,
        ) -> std::result::Result<tonic::Response<super::LightdInfo>, tonic::Status>;
        /// Testing-only, requires lightwalletd --ping-very-insecure (do not enable in production)
        async fn ping(
            &self,
            request: tonic::Request<super::Duration>,
        ) -> std::result::Result<tonic::Response<super::PingResponse>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct CompactTxStreamerServer<T: CompactTxStreamer> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: CompactTxStreamer> CompactTxStreamerServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for CompactTxStreamerServer<T>
    where
        T: CompactTxStreamer,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock" => {
                    #[allow(non_camel_case_types)]
                    struct GetLatestBlockSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::UnaryService<super::ChainSpec>
                    for GetLatestBlockSvc<T> {
                        type Response = super::BlockId;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ChainSpec>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_latest_block(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetLatestBlockSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlock" => {
                    #[allow(non_camel_case_types)]
                    struct GetBlockSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::UnaryService<super::BlockId> for GetBlockSvc<T> {
                        type Response = crate::proto::compact_formats::CompactBlock;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::BlockId>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_block(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetBlockSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockNullifiers" => {
                    #[allow(non_camel_case_types)]
                    struct GetBlockNullifiersSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::UnaryService<super::BlockId>
                    for GetBlockNullifiersSvc<T> {
                        type Response = crate::proto::compact_formats::CompactBlock;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::BlockId>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_block_nullifiers(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetBlockNullifiersSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange" => {
                    #[allow(non_camel_case_types)]
                    struct GetBlockRangeSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::ServerStreamingService<super::BlockRange>
                    for GetBlockRangeSvc<T> {
                        type Response = crate::proto::compact_formats::CompactBlock;
                        type ResponseStream = T::GetBlockRangeStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::BlockRange>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_block_range(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetBlockRangeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRangeNullifiers" => {
                    #[allow(non_camel_case_types)]
                    struct GetBlockRangeNullifiersSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::ServerStreamingService<super::BlockRange>
                    for GetBlockRangeNullifiersSvc<T> {
                        type Response = crate::proto::compact_formats::CompactBlock;
                        type ResponseStream = T::GetBlockRangeNullifiersStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::BlockRange>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_block_range_nullifiers(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetBlockRangeNullifiersSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction" => {
                    #[allow(non_camel_case_types)]
                    struct GetTransactionSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::UnaryService<super::TxFilter>
                    for GetTransactionSvc<T> {
                        type Response = super::RawTransaction;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::TxFilter>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_transaction(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetTransactionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction" => {
                    #[allow(non_camel_case_types)]
                    struct SendTransactionSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::UnaryService<super::RawTransaction>
                    for SendTransactionSvc<T> {
                        type Response = super::SendResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RawTransaction>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::send_transaction(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = SendTransactionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressTxids" => {
                    #[allow(non_camel_case_types)]
                    struct GetTaddressTxidsSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::ServerStreamingService<
                        super::TransparentAddressBlockFilter,
                    > for GetTaddressTxidsSvc<T> {
                        type Response = super::RawTransaction;
                        type ResponseStream = T::GetTaddressTxidsStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::TransparentAddressBlockFilter>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_taddress_txids(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetTaddressTxidsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressBalance" => {
                    #[allow(non_camel_case_types)]
                    struct GetTaddressBalanceSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::UnaryService<super::AddressList>
                    for GetTaddressBalanceSvc<T> {
                        type Response = super::Balance;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::AddressList>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_taddress_balance(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetTaddressBalanceSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressBalanceStream" => {
                    #[allow(non_camel_case_types)]
                    struct GetTaddressBalanceStreamSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::ClientStreamingService<super::Address>
                    for GetTaddressBalanceStreamSvc<T> {
                        type Response = super::Balance;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<tonic::Streaming<super::Address>>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_taddress_balance_stream(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetTaddressBalanceStreamSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.client_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolTx" => {
                    #[allow(non_camel_case_types)]
                    struct GetMempoolTxSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::ServerStreamingService<super::Exclude>
                    for GetMempoolTxSvc<T> {
                        type Response = crate::proto::compact_formats::CompactTx;
                        type ResponseStream = T::GetMempoolTxStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Exclude>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_mempool_tx(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetMempoolTxSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolStream" => {
                    #[allow(non_camel_case_types)]
                    struct GetMempoolStreamSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::ServerStreamingService<super::Empty>
                    for GetMempoolStreamSvc<T> {
                        type Response = super::RawTransaction;
                        type ResponseStream = T::GetMempoolStreamStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Empty>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_mempool_stream(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetMempoolStreamSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState" => {
                    #[allow(non_camel_case_types)]
                    struct GetTreeStateSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::UnaryService<super::BlockId>
                    for GetTreeStateSvc<T> {
                        type Response = super::TreeState;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::BlockId>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_tree_state(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetTreeStateSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestTreeState" => {
                    #[allow(non_camel_case_types)]
                    struct GetLatestTreeStateSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<T: CompactTxStreamer> tonic::server::UnaryService<super::Empty>
                    for GetLatestTreeStateSvc<T> {
                        type Response = super::TreeState;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Empty>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_latest_tree_state(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetLatestTreeStateSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetSubtreeRoots" => {
                    #[allow(non_camel_case_types)]
                    struct GetSubtreeRootsSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::ServerStreamingService<super::GetSubtreeRootsArg>
                    for GetSubtreeRootsSvc<T> {
                        type Response = super::SubtreeRoot;
                        type ResponseStream = T::GetSubtreeRootsStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetSubtreeRootsArg>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_subtree_roots(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetSubtreeRootsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetAddressUtxos" => {
                    #[allow(non_camel_case_types)]
                    struct GetAddressUtxosSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::UnaryService<super::GetAddressUtxosArg>
                    for GetAddressUtxosSvc<T> {
                        type Response = super::GetAddressUtxosReplyList;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetAddressUtxosArg>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_address_utxos(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetAddressUtxosSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetAddressUtxosStream" => {
                    #[allow(non_camel_case_types)]
                    struct GetAddressUtxosStreamSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::ServerStreamingService<super::GetAddressUtxosArg>
                    for GetAddressUtxosStreamSvc<T> {
                        type Response = super::GetAddressUtxosReply;
                        type ResponseStream = T::GetAddressUtxosStreamStream;
                        type Future = BoxFuture<
                            tonic::Response<Self::ResponseStream>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetAddressUtxosArg>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_address_utxos_stream(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetAddressUtxosStreamSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo" => {
                    #[allow(non_camel_case_types)]
                    struct GetLightdInfoSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<T: CompactTxStreamer> tonic::server::UnaryService<super::Empty>
                    for GetLightdInfoSvc<T> {
                        type Response = super::LightdInfo;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Empty>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::get_lightd_info(&inner, request)
                                    .await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetLightdInfoSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/Ping" => {
                    #[allow(non_camel_case_types)]
                    struct PingSvc<T: CompactTxStreamer>(pub Arc<T>);
                    impl<
                        T: CompactTxStreamer,
                    > tonic::server::UnaryService<super::Duration> for PingSvc<T> {
                        type Response = super::PingResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::Duration>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as CompactTxStreamer>::ping(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = PingSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: CompactTxStreamer> Clone for CompactTxStreamerServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    impl<T: CompactTxStreamer> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: CompactTxStreamer> tonic::server::NamedService
    for CompactTxStreamerServer<T> {
        const NAME: &'static str = "cash.z.wallet.sdk.rpc.CompactTxStreamer";
    }
}
