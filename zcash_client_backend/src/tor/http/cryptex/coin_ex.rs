use hyper::StatusCode;
use rust_decimal::Decimal;
use serde::Deserialize;

use super::{Exchange, ExchangeData, RETRY_LIMIT, retry_filter};
use crate::tor::{Client, Error, http::HttpError};

/// Querier for the CoinEx exchange.
pub struct CoinEx {
    _private: (),
}

impl CoinEx {
    /// Prepares for unauthenticated connections to CoinEx.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CoinExDepth {
    asks: Vec<(Decimal, Decimal)>,
    bids: Vec<(Decimal, Decimal)>,
    checksum: i32,
    last: Decimal,
    updated_at: u64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CoinExData {
    market: String,
    is_full: bool,
    depth: CoinExDepth,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CoinExResponse {
    code: u32,
    message: String,
    data: CoinExData,
}

impl Exchange for CoinEx {
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://docs.coinex.com/api/v2/spot/market/http/list-market-depth
        let res = client
            .http_get_json::<CoinExResponse>(
                "https://api.coinex.com/v2/spot/depth?market=ZECUSDT&limit=5&interval=0"
                    .parse()
                    .unwrap(),
                RETRY_LIMIT,
                retry_filter,
            )
            .await?;
        let data = res.into_body().data.depth;
        Ok(ExchangeData {
            bid: data
                .bids
                .first()
                .ok_or(Error::Http(HttpError::Unsuccessful(
                    StatusCode::SERVICE_UNAVAILABLE,
                )))?
                .0,
            ask: data
                .asks
                .first()
                .ok_or(Error::Http(HttpError::Unsuccessful(
                    StatusCode::SERVICE_UNAVAILABLE,
                )))?
                .0,
        })
    }
}
