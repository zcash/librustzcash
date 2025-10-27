use std::io;

use rust_decimal::Decimal;
use serde::Deserialize;

use super::{Exchange, ExchangeData, RETRY_LIMIT, retry_filter};
use crate::tor::{Client, Error};

/// Querier for the Kraken exchange.
pub struct Kraken {
    _private: (),
}

impl Kraken {
    /// Prepares for unauthenticated connections to Kraken.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct KrakenData {
    a: (Decimal, u64, Decimal),
    b: (Decimal, u64, Decimal),
    c: (Decimal, Decimal),
    v: (Decimal, Decimal),
    p: (Decimal, Decimal),
    t: (u32, u32),
    l: (Decimal, Decimal),
    h: (Decimal, Decimal),
    o: Decimal,
}

type KrakenResponse = Result<KrakenData, Vec<String>>;

impl Exchange for Kraken {
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://docs.kraken.com/api/docs/rest-api/get-ticker-information
        let res = client
            .http_get_json::<KrakenResponse>(
                "https://api.kraken.com/0/public/Ticker?pair=XZECZUSD"
                    .parse()
                    .unwrap(),
                RETRY_LIMIT,
                retry_filter,
            )
            .await?;
        let data = res.into_body().map_err(|e| {
            Error::Io(io::Error::other(
                e.into_iter()
                    .reduce(|mut acc, e| {
                        acc.push_str("; ");
                        acc.push_str(&e);
                        acc
                    })
                    .unwrap_or_default(),
            ))
        })?;
        Ok(ExchangeData {
            bid: data.b.0,
            ask: data.a.0,
        })
    }
}
