use rust_decimal::Decimal;
use serde::Deserialize;

use super::{Exchange, ExchangeData};
use crate::tor::{Client, Error};

/// Querier for the Binance exchange.
pub struct Binance {
    _private: (),
}

impl Binance {
    /// Prepares for unauthenticated connections to Binance.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
#[allow(non_snake_case)]
struct BinanceData {
    symbol: String,
    priceChange: Decimal,
    priceChangePercent: Decimal,
    weightedAvgPrice: Decimal,
    prevClosePrice: Decimal,
    lastPrice: Decimal,
    lastQty: Decimal,
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
    firstId: u32,
    lastId: u32,
    count: u32,
}

impl Exchange for Binance {
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://binance-docs.github.io/apidocs/spot/en/#24hr-ticker-price-change-statistics
        let res = client
            .get_json::<BinanceData>(
                "https://api.binance.com/api/v3/ticker/24hr?symbol=ZECUSDT"
                    .parse()
                    .unwrap(),
            )
            .await?;
        let data = res.into_body();
        Ok(ExchangeData {
            bid: data.bidPrice,
            ask: data.askPrice,
        })
    }
}
