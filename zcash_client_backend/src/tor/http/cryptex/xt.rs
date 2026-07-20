use rust_decimal::Decimal;
use serde::Deserialize;

use super::{Exchange, ExchangeData, RETRY_LIMIT, retry_filter};
use crate::tor::{Client, Error};

/// Querier for the XT exchange.
pub struct Xt {
    _private: (),
}

impl Xt {
    /// Prepares for unauthenticated connections to XT.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct XtData {
    s: String,
    t: u64,
    ap: Decimal,
    aq: Decimal,
    bp: Decimal,
    bq: Decimal,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct XtResponse {
    rc: u32,
    mc: String,
    ma: Vec<String>,
    result: (XtData,),
}

impl Exchange for Xt {
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://doc.xt.com/docs/spot/Market/GetBestPendingOrderTicker
        let res = client
            .http_get_json::<XtResponse>(
                "https://sapi.xt.com/v4/public/ticker/book?symbol=zec_usdt"
                    .parse()
                    .unwrap(),
                RETRY_LIMIT,
                retry_filter,
            )
            .await?;
        let data = res.into_body().result.0;
        Ok(ExchangeData {
            bid: data.bp,
            ask: data.ap,
        })
    }
}
