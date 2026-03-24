use std::{collections::VecDeque, ops::Deref};

use zcash_client_backend::data_api::TransactionDataRequest;
use zcash_primitives::transaction::TxId;

#[derive(Debug, Default, PartialEq)]
pub struct TransactionDataRequestQueue(pub(crate) VecDeque<TransactionDataRequest>);

impl TransactionDataRequestQueue {
    pub fn new() -> Self {
        Self(VecDeque::new())
    }

    pub fn queue_status_retrieval(&mut self, txid: &TxId) {
        self.0.push_back(TransactionDataRequest::GetStatus(*txid));
    }
}

impl Deref for TransactionDataRequestQueue {
    type Target = VecDeque<TransactionDataRequest>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

mod serialization {
    use super::*;
    use crate::{error::Error, proto::memwallet as proto, read_optional};

    #[cfg(feature = "transparent-inputs")]
    use {
        ::transparent::address::TransparentAddress, zcash_keys::encoding::AddressCodec as _,
        zcash_protocol::consensus::Network::MainNetwork as EncodingParams,
    };

    impl From<TransactionDataRequest> for proto::TransactionDataRequest {
        fn from(request: TransactionDataRequest) -> Self {
            match request {
                TransactionDataRequest::GetStatus(txid) => Self {
                    request_type: proto::TransactionDataRequestType::GetStatus as i32,
                    tx_id: Some(txid.into()),
                    address: None,
                    block_range_start: None,
                    block_range_end: None,
                },
                TransactionDataRequest::Enhancement(txid) => Self {
                    request_type: proto::TransactionDataRequestType::Enhancement as i32,
                    tx_id: Some(txid.into()),
                    address: None,
                    block_range_start: None,
                    block_range_end: None,
                },
                #[cfg(feature = "transparent-inputs")]
                TransactionDataRequest::TransactionsInvolvingAddress(req) => Self {
                    request_type: proto::TransactionDataRequestType::SpendsFromAddress as i32,
                    tx_id: None,
                    address: Some(req.address().encode(&EncodingParams).as_bytes().to_vec()),
                    block_range_start: Some(u32::from(req.block_range_start())),
                    block_range_end: req.block_range_end().map(u32::from),
                },
            }
        }
    }

    impl TryFrom<proto::TransactionDataRequest> for TransactionDataRequest {
        type Error = crate::Error;

        fn try_from(request: proto::TransactionDataRequest) -> Result<Self, crate::Error> {
            Ok(match request.request_type() {
                proto::TransactionDataRequestType::GetStatus => {
                    TransactionDataRequest::GetStatus(read_optional!(request, tx_id)?.try_into()?)
                }
                proto::TransactionDataRequestType::Enhancement => {
                    TransactionDataRequest::Enhancement(read_optional!(request, tx_id)?.try_into()?)
                }
                #[cfg(feature = "transparent-inputs")]
                proto::TransactionDataRequestType::SpendsFromAddress => {
                    use zcash_client_backend::data_api::{
                        OutputStatusFilter, TransactionStatusFilter,
                    };

                    TransactionDataRequest::transactions_involving_address(
                        TransparentAddress::decode(
                            &EncodingParams,
                            &String::from_utf8(read_optional!(request, address)?)?,
                        )?,
                        read_optional!(request, block_range_start)?.into(),
                        Some(read_optional!(request, block_range_end)?.into()),
                        None,
                        TransactionStatusFilter::Mined,
                        OutputStatusFilter::All,
                    )
                }
                #[cfg(not(feature = "transparent-inputs"))]
                _ => panic!("invalid request type"),
            })
        }
    }
}
