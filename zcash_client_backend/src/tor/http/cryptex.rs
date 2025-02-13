//! Cryptocurrency exchange rate APIs.

use futures_util::{future::join_all, join};
use rand::{seq::IteratorRandom, thread_rng};
use rust_decimal::Decimal;
use tracing::{error, trace};

use crate::tor::{Client, Error};

mod binance;
mod coinbase;
mod gate_io;
mod gemini;
mod ku_coin;
mod mexc;

/// Exchanges for which we know how to query data over Tor.
pub mod exchanges {
    pub use super::binance::Binance;
    pub use super::coinbase::Coinbase;
    pub use super::gate_io::GateIo;
    pub use super::gemini::Gemini;
    pub use super::ku_coin::KuCoin;
    pub use super::mexc::Mexc;
}

/// An exchange that can be queried for ZEC data.
#[trait_variant::make(Exchange: Send)]
#[dynosaur::dynosaur(DynExchange = dyn Exchange)]
#[dynosaur::dynosaur(DynLocalExchange = dyn LocalExchange)]
pub trait LocalExchange {
    /// Queries data about the USD/ZEC pair.
    ///
    /// The returned bid and ask data must be denominated in USD, i.e. the latest bid and
    /// ask for 1 ZEC.
    async fn query_zec_to_usd(&self, client: &Client) -> Result<ExchangeData, Error>;
}

/// Data queried from an [`Exchange`].
#[derive(Debug)]
pub struct ExchangeData {
    /// The highest current bid.
    pub bid: Decimal,

    /// The lowest current ask.
    pub ask: Decimal,
}

impl ExchangeData {
    /// Returns the mid-point between current best bid and current best ask, to avoid
    /// manipulation by targeted trade fulfilment.
    fn exchange_rate(&self) -> Decimal {
        (self.bid + self.ask) / Decimal::TWO
    }
}

/// A set of [`Exchange`]s that can be queried for ZEC data.
pub struct Exchanges {
    trusted: Box<DynExchange<'static>>,
    others: Vec<Box<DynExchange<'static>>>,
}

impl Exchanges {
    /// Unauthenticated connections to all known exchanges with USD/ZEC pairs.
    ///
    /// Gemini is treated as a "trusted" data source due to being a NYDFS-regulated
    /// exchange.
    pub fn unauthenticated_known_with_gemini_trusted() -> Self {
        Self::builder(exchanges::Gemini::unauthenticated())
            .with(exchanges::Binance::unauthenticated())
            .with(exchanges::Coinbase::unauthenticated())
            .with(exchanges::GateIo::unauthenticated())
            .with(exchanges::KuCoin::unauthenticated())
            .with(exchanges::Mexc::unauthenticated())
            .build()
    }

    /// Returns an `Exchanges` builder.
    ///
    /// The `trusted` exchange will always have its data used, _if_ data is successfully
    /// obtained via Tor (i.e. no transient failures).
    pub fn builder(trusted: impl Exchange + 'static) -> ExchangesBuilder {
        ExchangesBuilder::new(trusted)
    }
}

/// Builder type for [`Exchanges`].
///
/// Every [`Exchanges`] is configured with a "trusted" [`Exchange`] that will always have
/// its data used, if data is successfully obtained via Tor (i.e. no transient failures).
/// Additional data sources can be provided to [`ExchangesBuilder::with`] for resiliency
/// against transient network failures or adversarial market manipulation on individual
/// sources.
///
/// The number of times [`ExchangesBuilder::with`] is called will affect the behaviour of
/// the final [`Exchanges`]:
/// - With no additional sources, the trusted [`Exchange`] is used on its own.
/// - With one additional source, the trusted [`Exchange`] is used preferentially,
///   with the additional source as a backup if the trusted source cannot be queried.
/// - With two or more additional sources, a minimum of three successful responses are
///   required from any of the sources.
pub struct ExchangesBuilder(Exchanges);

impl ExchangesBuilder {
    /// Constructs a new [`Exchanges`] builder.
    ///
    /// The `trusted` exchange will always have its data used, _if_ data is successfully
    /// obtained via Tor (i.e. no transient failures).
    pub fn new(trusted: impl Exchange + 'static) -> Self {
        Self(Exchanges {
            trusted: DynExchange::boxed(trusted),
            others: vec![],
        })
    }

    /// Adds another [`Exchange`] as a data source.
    pub fn with(mut self, other: impl Exchange + 'static) -> Self {
        self.0.others.push(DynExchange::boxed(other));
        self
    }

    /// Builds the [`Exchanges`].
    pub fn build(self) -> Exchanges {
        self.0
    }
}

impl Client {
    /// Fetches the latest USD/ZEC exchange rate, derived from the given exchanges.
    ///
    /// Returns:
    /// - `Ok(rate)` if at least one exchange request succeeds.
    /// - `Err(_)` if none of the exchange queries succeed.
    pub async fn get_latest_zec_to_usd_rate(
        &self,
        exchanges: &Exchanges,
    ) -> Result<Decimal, Error> {
        // Fetch the data in parallel.
        let res = join!(
            exchanges.trusted.query_zec_to_usd(self),
            join_all(exchanges.others.iter().map(|e| e.query_zec_to_usd(self)))
        );
        trace!(?res, "Data results");
        let (trusted_res, other_res) = res;

        // Split into successful queries and errors.
        let mut rates: Vec<Decimal> = vec![];
        let mut errors = vec![];
        for res in other_res {
            match res {
                Ok(d) => rates.push(d.exchange_rate()),
                Err(e) => errors.push(e),
            }
        }

        // "Never go to sea with two chronometers; take one or three."
        // Randomly drop one rate if necessary to have an odd number of rates, as long as
        // we have either at least three rates, or fewer than three sources.
        if exchanges.others.len() >= 2 && rates.len() + usize::from(trusted_res.is_ok()) < 3 {
            error!("Too many exchange requests failed");
            return Err(errors
                .into_iter()
                .next()
                .expect("At least one request failed"));
        }
        let evict_random = |s: &mut Vec<Decimal>| {
            if let Some(index) = (0..s.len()).choose(&mut thread_rng()) {
                s.remove(index);
            }
        };
        match trusted_res {
            Ok(trusted) => {
                if rates.len() % 2 != 0 {
                    evict_random(&mut rates);
                }
                rates.push(trusted.exchange_rate());
            }
            Err(e) => {
                if rates.len() % 2 == 0 {
                    evict_random(&mut rates);
                }
                errors.push(e);
            }
        }

        // If all of the requests failed, log all errors and return one of them.
        if rates.is_empty() {
            error!("All exchange requests failed");
            Err(errors.into_iter().next().expect("All requests failed"))
        } else {
            // We have an odd number of rates; take the median.
            assert!(rates.len() % 2 != 0);
            rates.sort();
            let median = rates.len() / 2;
            Ok(rates[median])
        }
    }
}
