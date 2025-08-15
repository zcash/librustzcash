use std::{io, time::Duration};

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;

use super::{retry_filter, Exchange, ExchangeData, RETRY_LIMIT};
use crate::tor::{Client, Error};

const ZEC_ASSET: &str = "zec.omft.near";
const USDT_ASSET: &str = "usdt.tether-token.near";
const DUMMY_ZCASH_MAINNET_ADDR: &str = "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs";
const DUMMY_USDT_ADDR: &str = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb";
const ONE_ZEC_IN_ZATOSHIS: &str = "100000000";

/// Querier for the Near Intents 1Click API.
pub struct NearIntents {
    _private: (),
}

impl NearIntents {
    /// Prepares for unauthenticated connections to the Near Intents 1Click API.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct QuoteRequest {
    dry: bool,
    swapType: String,
    slippageTolerance: u16,
    originAsset: String,
    depositType: String,
    destinationAsset: String,
    amount: String,
    refundTo: String,
    refundType: String,
    recipient: String,
    recipientType: String,
    deadline: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    referral: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quoteWaitingTimeMs: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    appFees: Option<Vec<AppFees>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct AppFees {
    recipient: String,
    fee: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum QuoteResponse {
    Success(QuoteSuccess),
    Err { message: String },
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
#[allow(non_snake_case)]
struct QuoteSuccess {
    timestamp: String,
    signature: String,
    quoteRequest: QuoteRequest,
    quote: Quote,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
#[allow(non_snake_case)]
struct Quote {
    amountIn: String,
    amountInFormatted: Decimal,
    amountInUsd: Decimal,
    minAmountIn: String,
    amountOut: String,
    amountOutFormatted: Decimal,
    amountOutUsd: Decimal,
    minAmountOut: String,
    timeEstimate: u32,
}

impl Exchange for NearIntents {
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://docs.near-intents.org/near-intents/integration/distribution-channels/1click-api
        #[allow(non_snake_case)]
        let request_quote = |swapType: String,
                             originAsset: String,
                             destinationAsset: String,
                             refundTo: String,
                             recipient: String| QuoteRequest {
            dry: true,
            swapType,
            slippageTolerance: 50,
            originAsset,
            depositType: "ORIGIN_CHAIN".into(),
            destinationAsset,
            amount: ONE_ZEC_IN_ZATOSHIS.into(),
            refundTo,
            refundType: "ORIGIN_CHAIN".into(),
            recipient,
            recipientType: "DESTINATION_CHAIN".into(),
            deadline: (time::OffsetDateTime::now_utc() + Duration::from_secs(75 * 40))
                .format(&Rfc3339)
                .expect("valid"),
            referral: None,
            quoteWaitingTimeMs: None,
            appFees: None,
        };

        // Request a quote for selling 1 ZEC, which gives us a bid price (what the DEX
        // will pay for ZEC).
        let bid_request = request_quote(
            "EXACT_INPUT".into(),
            ZEC_ASSET.into(),
            USDT_ASSET.into(),
            DUMMY_ZCASH_MAINNET_ADDR.into(),
            DUMMY_USDT_ADDR.into(),
        );
        let bid = client
            .http_post_json::<_, QuoteResponse>(
                "https://1click.chaindefuser.com/v0/quote".parse().unwrap(),
                &bid_request,
                RETRY_LIMIT,
                retry_filter,
            )
            .await?
            .into_body();

        // Request a quote for buying 1 ZEC, which gives us an ask price (what the DEX
        // will sell ZEC for).
        let ask_request = request_quote(
            "EXACT_OUTPUT".into(),
            USDT_ASSET.into(),
            ZEC_ASSET.into(),
            DUMMY_USDT_ADDR.into(),
            DUMMY_ZCASH_MAINNET_ADDR.into(),
        );
        let ask = client
            .http_post_json::<_, QuoteResponse>(
                "https://1click.chaindefuser.com/v0/quote".parse().unwrap(),
                &ask_request,
                RETRY_LIMIT,
                retry_filter,
            )
            .await?
            .into_body();

        match (bid, ask) {
            (QuoteResponse::Success(bid), QuoteResponse::Success(ask)) => Ok(ExchangeData {
                bid: bid.quote.amountOutFormatted,
                ask: ask.quote.amountInFormatted,
            }),
            (QuoteResponse::Err { message }, _) | (_, QuoteResponse::Err { message }) => {
                Err(Error::Io(io::Error::other(message)))
            }
        }
    }
}
