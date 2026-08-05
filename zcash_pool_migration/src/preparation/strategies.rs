//! The concrete [`PreparationStrategy`] implementations.
//!
//! One ships today: [`LayeredGreedy`], the largest-first layered greedy the [parent
//! module](super) documents, which is what [`plan_preparation`] runs. It is named here so that the
//! rule is a value a caller can hold, compare against another rule, and record alongside the plan
//! it produced, rather than a fact about which function was called.
//!
//! [`plan_preparation`]: super::plan_preparation

use zcash_protocol::value::Zatoshis;

use super::{PrepError, PreparationPlan, PreparationStrategy, plan_preparation};

/// The largest-first layered greedy described in the [parent module](super): in each layer it feeds
/// each splitting transaction from the largest available note it can, routes every leftover forward
/// as an intermediate note, and consolidates notes too small to fund anything on their own; a lone
/// note that can fund every remaining part instead takes the balanced fan-out tree.
///
/// This is the rule the crate has always used, and [`plan_preparation`](super::plan_preparation)
/// remains its direct entry point.
///
/// Its known weakness, for whoever compares a future strategy against it: every SPLITTING
/// transaction it builds has exactly one input (multiple inputs appear only in a consolidation,
/// which produces exactly one output), so it reaches only the two extreme shapes of the
/// `spends + outputs <= PREP_TX_ACTIONS` budget and never the interior. A wallet holding one
/// balance across two notes can therefore be told that a set of funding notes is unfundable when a
/// single two-input transaction would mint all of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LayeredGreedy;

impl PreparationStrategy for LayeredGreedy {
    fn name(&self) -> &'static str {
        "layered-greedy"
    }

    fn plan(
        &self,
        available: &[Zatoshis],
        funding: &[Zatoshis],
        fee_per_tx: Zatoshis,
    ) -> Result<PreparationPlan, PrepError> {
        plan_preparation(available, funding, fee_per_tx)
    }
}
