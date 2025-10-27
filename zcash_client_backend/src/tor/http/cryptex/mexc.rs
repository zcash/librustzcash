use rust_decimal::Decimal;
use serde::Deserialize;

use super::{Exchange, ExchangeData, RETRY_LIMIT, retry_filter};
use crate::tor::{Client, Error};

/// Querier for the MEXC exchange.
pub struct Mexc {
    _private: (),
}

impl Mexc {
    /// Prepares for unauthenticated connections to MEXC.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
#[allow(non_snake_case)]
struct MexcData {
    symbol: String,
    priceChange: Decimal,
    priceChangePercent: Decimal,
    prevClosePrice: Decimal,
    lastPrice: Decimal,
    bidPrice: Decimal,
    bidQty: Decimal,
    askPrice: Decimal,
    askQty: Decimal,
    openPrice: Decimal,
    highPrice: Decimal,
    lowPrice: Decimal,
    volume: Decimal,
    quoteVolume: Decimal,
    openTime: u64,
    closeTime: u64,
}

impl Exchange for Mexc {
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://mexcdevelop.github.io/apidocs/spot_v3_en/#24hr-ticker-price-change-statistics
        let res = client
            .http_get_json::<MexcData>(
                "https://api.mexc.com/api/v3/ticker/24hr?symbol=ZECUSDT"
                    .parse()
                    .unwrap(),
                RETRY_LIMIT,
                retry_filter,
            )
            .await?;
        let data = res.into_body();
        Ok(ExchangeData {
            bid: data.bidPrice,
            ask: data.askPrice,
        })
    }
}
