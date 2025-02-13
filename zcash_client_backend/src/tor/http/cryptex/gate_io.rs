use hyper::StatusCode;
use rust_decimal::Decimal;
use serde::Deserialize;

use super::{Exchange, ExchangeData};
use crate::tor::{Client, Error};

/// Querier for the Gate.io exchange.
pub struct GateIo {
    _private: (),
}

impl GateIo {
    /// Prepares for unauthenticated connections to Gate.io.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GateIoData {
    currency_pair: String,
    last: Decimal,
    lowest_ask: Decimal,
    highest_bid: Decimal,
    change_percentage: Decimal,
    base_volume: Decimal,
    quote_volume: Decimal,
    high_24h: Decimal,
    low_24h: Decimal,
}

impl Exchange for GateIo {
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://www.gate.io/docs/developers/apiv4/#retrieve-ticker-information
        let res = client
            .get_json::<Vec<GateIoData>>(
                "https://api.gateio.ws/api/v4/spot/tickers?currency_pair=ZEC_USDT"
                    .parse()
                    .unwrap(),
            )
            .await?;
        let data = res.into_body().into_iter().next().ok_or(Error::Http(
            super::super::HttpError::Unsuccessful(StatusCode::GONE),
        ))?;

        Ok(ExchangeData {
            bid: data.highest_bid,
            ask: data.lowest_ask,
        })
    }
}
