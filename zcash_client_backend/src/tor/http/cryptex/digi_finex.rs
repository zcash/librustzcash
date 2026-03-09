use rust_decimal::Decimal;
use serde::Deserialize;

use super::{Exchange, ExchangeData, RETRY_LIMIT, retry_filter};
use crate::tor::{Client, Error};

/// Querier for the DigiFinex exchange.
pub struct DigiFinex {
    _private: (),
}

impl DigiFinex {
    /// Prepares for unauthenticated connections to DigiFinex.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DigiFinexData {
    vol: Decimal,
    change: Decimal,
    base_vol: Decimal,
    sell: Decimal,
    last: Decimal,
    symbol: String,
    low: Decimal,
    buy: Decimal,
    high: Decimal,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DigiFinexResponse {
    date: u64,
    code: u32,
    ticker: (DigiFinexData,),
}

impl Exchange for DigiFinex {
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://docs.digifinex.com/en-ww/spot/v3/rest.html#ticker-price
        let res = client
            .http_get_json::<DigiFinexResponse>(
                "https://openapi.digifinex.com/v3/ticker?symbol=zec_usdt"
                    .parse()
                    .unwrap(),
                RETRY_LIMIT,
                retry_filter,
            )
            .await?;
        let data = res.into_body().ticker.0;
        Ok(ExchangeData {
            bid: data.buy,
            ask: data.sell,
        })
    }
}
