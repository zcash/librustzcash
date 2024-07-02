use futures_util::join;
use hyper::StatusCode;
use iso_currency::Currency;
use rand::{seq::IteratorRandom, thread_rng};
use rust_decimal::Decimal;
use serde::Deserialize;
use tracing::{error, trace};

use crate::tor::{Client, Error};

impl Client {
    /// Fetches the latest `currency`/ZEC exchange rate, derived from several exchanges.
    ///
    /// Supported currencies:
    /// - USD
    ///
    /// Returns:
    /// - `Ok(Some(rate))` if at least one exchange request succeeds.
    /// - `Ok(None)` if the given currency is unsupported.
    /// - `Err(_)` if none of the exchange queries succeed.
    pub async fn get_exchange_rate(&self, currency: Currency) -> Result<Option<Decimal>, Error> {
        let pair = match ExchangePair::get(currency) {
            Some(pair) => pair,
            None => return Ok(None),
        };

        // Fetch the data in parallel.
        let res = join!(
            Binance::query(self, pair),
            Coinbase::query(self, pair),
            GateIo::query(self, pair),
            Gemini::query(self, pair),
            KuCoin::query(self, pair),
            Mexc::query(self, pair),
        );
        trace!(?res, "Exchange results");
        let (binance, coinbase, gate_io, gemini, ku_coin, mexc) = res;

        // Split into successful queries and errors.
        fn split<T: ExchangeData>(s: &mut Vec<Decimal>, e: &mut Vec<Error>, res: Result<T, Error>) {
            match res {
                Ok(d) => s.push(d.price()),
                Err(error) => e.push(error),
            }
        }
        let mut prices = vec![];
        let mut errors = vec![];
        split(&mut prices, &mut errors, binance);
        split(&mut prices, &mut errors, coinbase);
        split(&mut prices, &mut errors, gate_io);
        // We handle Gemini below to exclude it from eviction.
        split(&mut prices, &mut errors, ku_coin);
        split(&mut prices, &mut errors, mexc);

        // "Never go to sea with two chronometers; take one or three."
        // Randomly drop one price if necessary to have an odd number of prices.
        let evict_random = |s: &mut Vec<Decimal>| {
            if let Some(index) = (0..s.len()).choose(&mut thread_rng()) {
                s.remove(index);
            }
        };
        if let Ok(gemini) = gemini {
            if prices.len() % 2 != 0 {
                evict_random(&mut prices);
            }
            prices.push(gemini.price());
        } else {
            if prices.len() % 2 == 0 {
                evict_random(&mut prices);
            }
        };

        // If all of the requests failed, log all errors and return one of them.
        if prices.is_empty() {
            error!("All exchange requests failed");
            Err(errors.into_iter().next().expect("All requests failed"))
        } else {
            // We have an odd number of prices; take the median.
            assert!(prices.len() % 2 != 0);
            prices.sort();
            let median = prices.len() / 2;
            Ok(Some(prices[median]))
        }
    }
}

#[derive(Clone, Copy)]
enum ExchangePair {
    Usd,
}

impl ExchangePair {
    fn get(currency: Currency) -> Option<Self> {
        match currency {
            Currency::USD => Some(Self::Usd),
            _ => None,
        }
    }

    fn binance(&self) -> &str {
        match self {
            ExchangePair::Usd => "ZECUSDT",
        }
    }

    #[allow(dead_code)]
    fn coinbase(&self) -> &str {
        match self {
            ExchangePair::Usd => "ZEC-USD",
        }
    }

    fn gate_io(&self) -> &str {
        match self {
            ExchangePair::Usd => "ZEC_USDT",
        }
    }

    fn gemini(&self) -> &str {
        match self {
            ExchangePair::Usd => "zecusd",
        }
    }

    fn ku_coin(&self) -> &str {
        match self {
            ExchangePair::Usd => "ZEC-USDT",
        }
    }

    fn mexc(&self) -> &str {
        match self {
            ExchangePair::Usd => "ZECUSDT",
        }
    }
}

trait ExchangeData {
    /// The highest current bid.
    fn bid(&self) -> Decimal;

    /// The lowest current ask.
    fn ask(&self) -> Decimal;

    /// Returns the mid-point between current best bid and current best ask, to avoid
    /// manipulation by targeted trade fulfilment.
    fn price(&self) -> Decimal {
        (self.bid() + self.ask()) / Decimal::TWO
    }
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
#[allow(non_snake_case)]
struct Binance {
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

impl Binance {
    async fn query(client: &Client, pair: ExchangePair) -> Result<Self, Error> {
        let res = client
            .get_json::<Self>(
                format!(
                    "https://api.binance.com/api/v3/ticker/24hr?symbol={}",
                    pair.binance()
                )
                .parse()
                .unwrap(),
            )
            .await?;
        Ok(res.into_body())
    }
}

impl ExchangeData for Binance {
    fn bid(&self) -> Decimal {
        self.bidPrice
    }

    fn ask(&self) -> Decimal {
        self.askPrice
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Coinbase {
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

impl Coinbase {
    #[allow(dead_code)]
    async fn query(client: &Client, pair: ExchangePair) -> Result<Self, Error> {
        let res = client
            .get_json(
                format!(
                    "https://api.exchange.coinbase.com/products/{}/ticker",
                    pair.coinbase()
                )
                .parse()
                .unwrap(),
            )
            .await?;
        Ok(res.into_body())
    }
}

impl ExchangeData for Coinbase {
    fn bid(&self) -> Decimal {
        self.bid
    }

    fn ask(&self) -> Decimal {
        self.ask
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GateIo {
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

impl GateIo {
    async fn query(client: &Client, pair: ExchangePair) -> Result<Self, Error> {
        let res = client
            .get_json::<Vec<Self>>(
                format!(
                    "https://api.gateio.ws/api/v4/spot/tickers?currency_pair={}",
                    pair.gate_io()
                )
                .parse()
                .unwrap(),
            )
            .await?;
        res.into_body()
            .into_iter()
            .next()
            .ok_or(Error::Http(super::HttpError::Unsuccessful(
                StatusCode::GONE,
            )))
    }
}

impl ExchangeData for GateIo {
    fn bid(&self) -> Decimal {
        self.highest_bid
    }

    fn ask(&self) -> Decimal {
        self.lowest_ask
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Gemini {
    symbol: String,
    open: Decimal,
    high: Decimal,
    low: Decimal,
    close: Decimal,
    changes: Vec<Decimal>,
    bid: Decimal,
    ask: Decimal,
}

impl Gemini {
    async fn query(client: &Client, pair: ExchangePair) -> Result<Self, Error> {
        let res = client
            .get_json(
                format!("https://api.gemini.com/v2/ticker/{}", pair.gemini())
                    .parse()
                    .unwrap(),
            )
            .await?;
        Ok(res.into_body())
    }
}

impl ExchangeData for Gemini {
    fn bid(&self) -> Decimal {
        self.bid
    }

    fn ask(&self) -> Decimal {
        self.ask
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
#[allow(non_snake_case)]
struct KuCoin {
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
    data: KuCoin,
}

impl KuCoin {
    async fn query(client: &Client, pair: ExchangePair) -> Result<Self, Error> {
        let res = client
            .get_json::<KuCoinResponse>(
                format!(
                    "https://api.kucoin.com/api/v1/market/stats?symbol={}",
                    pair.ku_coin()
                )
                .parse()
                .unwrap(),
            )
            .await?;
        Ok(res.into_body().data)
    }
}

impl ExchangeData for KuCoin {
    fn bid(&self) -> Decimal {
        self.buy
    }

    fn ask(&self) -> Decimal {
        self.sell
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
#[allow(non_snake_case)]
struct Mexc {
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

impl Mexc {
    async fn query(client: &Client, pair: ExchangePair) -> Result<Self, Error> {
        let res = client
            .get_json(
                format!(
                    "https://api.mexc.com/api/v3/ticker/24hr?symbol={}",
                    pair.mexc()
                )
                .parse()
                .unwrap(),
            )
            .await?;
        Ok(res.into_body())
    }
}

impl ExchangeData for Mexc {
    fn bid(&self) -> Decimal {
        self.bidPrice
    }

    fn ask(&self) -> Decimal {
        self.askPrice
    }
}
