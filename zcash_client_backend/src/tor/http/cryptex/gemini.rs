use rust_decimal::Decimal;
use serde::Deserialize;

use super::{Exchange, ExchangeData};
use crate::tor::{Client, Error};

/// Querier for the Gemini exchange.
pub struct Gemini {
    _private: (),
}

impl Gemini {
    /// Prepares for unauthenticated connections to Gemini.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GeminiData {
    symbol: String,
    open: Decimal,
    high: Decimal,
    low: Decimal,
    close: Decimal,
    changes: Vec<Decimal>,
    bid: Decimal,
    ask: Decimal,
}

impl Exchange for Gemini {
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://docs.gemini.com/rest-api/#ticker-v2
        let res = client
            .get_json::<GeminiData>("https://api.gemini.com/v2/ticker/zecusd".parse().unwrap())
            .await?;
        let data = res.into_body();
        Ok(ExchangeData {
            bid: data.bid,
            ask: data.ask,
        })
    }
}
