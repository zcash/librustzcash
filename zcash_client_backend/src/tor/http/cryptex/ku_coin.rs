use rust_decimal::Decimal;
use serde::Deserialize;

use super::{Exchange, ExchangeData};
use crate::tor::{Client, Error};

/// Querier for the KuCoin exchange.
pub struct KuCoin {
    _private: (),
}

impl KuCoin {
    /// Prepares for unauthenticated connections to KuCoin.
    pub fn unauthenticated() -> Self {
        Self { _private: () }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
#[allow(non_snake_case)]
struct KuCoinData {
    time: u64,
    symbol: String,
    buy: Decimal,
    sell: Decimal,
    changeRate: Decimal,
    changePrice: Decimal,
    high: Decimal,
    low: Decimal,
    vol: Decimal,
    volValue: Decimal,
    last: Decimal,
    averagePrice: Decimal,
    takerFeeRate: Decimal,
    makerFeeRate: Decimal,
    takerCoefficient: Decimal,
    makerCoefficient: Decimal,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct KuCoinResponse {
    code: String,
    data: KuCoinData,
}

impl Exchange for KuCoin {
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error> {
        // API documentation:
        // https://www.kucoin.com/docs/rest/spot-trading/market-data/get-24hr-stats
        let res = client
            .get_json::<KuCoinResponse>(
                "https://api.kucoin.com/api/v1/market/stats?symbol=ZEC-USDT"
                    .parse()
                    .unwrap(),
            )
            .await?;
        let data = res.into_body().data;
        Ok(ExchangeData {
            bid: data.buy,
            ask: data.sell,
        })
    }
}
