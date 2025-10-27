use rust_decimal::Decimal;
use serde::Deserialize;

use super::{Exchange, ExchangeData, RETRY_LIMIT, retry_filter};
use crate::tor::{Client, Error};

/// Querier for the Coinbase exchange.
pub struct Coinbase {
    _private: (),
}

impl Coinbase {
    /// Prepares for unauthenticated connections to Coinbase.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CoinbaseData {
    ask: Decimal,
    bid: Decimal,
    volume: Decimal,
    trade_id: u32,
    price: Decimal,
    size: Decimal,
    time: String,
    rfq_volume: Option<Decimal>,
    conversions_volume: Option<Decimal>,
}

impl Exchange for Coinbase {
    #[allow(dead_code)]
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://docs.cdp.coinbase.com/exchange/reference/exchangerestapi_getproductticker
        let res = client
            .http_get_json::<CoinbaseData>(
                "https://api.exchange.coinbase.com/products/ZEC-USD/ticker"
                    .parse()
                    .unwrap(),
                RETRY_LIMIT,
                retry_filter,
            )
            .await?;
        let data = res.into_body();
        Ok(ExchangeData {
            bid: data.bid,
            ask: data.ask,
        })
    }
}
