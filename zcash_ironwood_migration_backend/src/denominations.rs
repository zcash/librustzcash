//! Note-split planning: deterministic decomposition of a spendable Orchard balance into
//! self-funding denomination notes whose crossing values follow the `{1, 2, 5} * 10^k` series
//! (1, 2, 5, 10, 20, 50, 100, ... ZEC). Pure arithmetic.
//!
//! Each prepared note holds `denomination + TRANSFER_FEE_BUFFER_ZATOSHI`, so when it is later spent
//! in a migration transfer it pays its own fee (2 Orchard + 2 Ironwood actions) while an exact
//! `{1, 2, 5} * 10^k` ZEC value crosses the turnstile. Any residual that cannot form a whole
//! self-funding note is returned as Orchard change, never folded into the transaction fee; folding
//! an identifiable dust amount into a fee would deanonymise a dust-attacked wallet.

pub(crate) const ZATOSHIS_PER_ZEC: u64 = 100_000_000;
pub(crate) const MIGRATION_MAX_PREPARED_NOTES_PER_RUN: usize = 64;
/// Per-note fee buffer: 4x the ZIP-317 marginal fee (5_000), covering 2 Orchard + 2 Ironwood
/// actions, so each prepared note can pay its own migration-transfer fee.
pub(crate) const TRANSFER_FEE_BUFFER_ZATOSHI: u64 = 20_000;
/// The sub-threshold (0.01 ZEC) below which a leftover Orchard balance is never migrated: it is
/// left untouched in the wallet, preserving privacy. Once the main migration completes, a leftover
/// at or above this threshold (but too small to form a whole self-funding note) is surfaced to the
/// user as an opt-in choice: migrate the remainder too (which can compromise privacy, so it is
/// shown with a disclaimer) or lock it to keep that privacy. Consumed by the context module in a
/// later slice.
pub(crate) const RESIDUAL_MIGRATION_MIN_ZATOSHI: u64 = ZATOSHIS_PER_ZEC / 100; // 0.01 ZEC

/// The outcome of planning a note split: the self-funding notes to create, the values that will
/// cross the turnstile, and the residual kept in Orchard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DenominationPlan {
    migration_outputs: Vec<u64>,
    crossing_values: Vec<u64>,
    orchard_change: Option<u64>,
    prep_fee_zatoshi: u64,
    total_input_zatoshi: u64,
    total_migratable_zatoshi: u64,
}

impl DenominationPlan {
    /// The value (in zatoshi) of each prepared note the split will create: the crossing value at
    /// the same index plus [`TRANSFER_FEE_BUFFER_ZATOSHI`], so the note can later pay its own
    /// migration-transfer fee.
    pub(crate) fn migration_outputs(&self) -> &[u64] {
        &self.migration_outputs
    }

    /// The `{1, 2, 5} * 10^k` ZEC values (in zatoshi) that will cross the Orchard -> Ironwood
    /// turnstile when the note at the same index is spent; parallel to [`Self::migration_outputs`].
    pub(crate) fn crossing_values(&self) -> &[u64] {
        &self.crossing_values
    }

    /// Any residual left in the Orchard pool (in zatoshi) because it could not form a whole
    /// self-funding note, or `None` if the balance was consumed exactly. Includes dust.
    pub(crate) fn orchard_change(&self) -> Option<u64> {
        self.orchard_change
    }

    /// The fee (in zatoshi) reserved for the note-split ("prep") transaction before decomposition.
    // Rounds out the plan's read API; the engine does not consume these three yet. Remove the
    // `allow` once a consumer is added.
    #[allow(dead_code)]
    pub(crate) fn prep_fee_zatoshi(&self) -> u64 {
        self.prep_fee_zatoshi
    }

    /// The total spendable Orchard balance (in zatoshi) this plan decomposes.
    #[allow(dead_code)]
    pub(crate) fn total_input_zatoshi(&self) -> u64 {
        self.total_input_zatoshi
    }

    /// The total value (in zatoshi) that will migrate to Ironwood: the sum of the crossing values.
    #[allow(dead_code)]
    pub(crate) fn total_migratable_zatoshi(&self) -> u64 {
        self.total_migratable_zatoshi
    }
}

/// The largest `{1, 2, 5} * 10^k` ZEC value (in whole ZEC) not exceeding `n`, for `n >= 1`.
fn largest_denomination_zec(n: u64) -> u64 {
    // Largest power of ten not exceeding `n`.
    let mut pow = 1u64;
    while pow.checked_mul(10).is_some_and(|p| p <= n) {
        pow *= 10;
    }
    // Prefer the 5- then 2- then 1-multiple of that power of ten.
    for multiple in [5u64, 2, 1] {
        if let Some(v) = pow.checked_mul(multiple) {
            if v <= n {
                return v;
            }
        }
    }
    pow
}

/// Decompose `total_input_zatoshi` (after reserving `prep_fee_zatoshi`) into self-funding
/// `{1, 2, 5} * 10^k` ZEC notes, capped at [`MIGRATION_MAX_PREPARED_NOTES_PER_RUN`]. Each note
/// costs `denomination + TRANSFER_FEE_BUFFER_ZATOSHI` from the budget; whatever cannot form a whole
/// note stays in Orchard as change.
pub(crate) fn plan_denominations(
    total_input_zatoshi: u64,
    prep_fee_zatoshi: u64,
) -> Result<DenominationPlan, String> {
    let base = |orchard_change: Option<u64>| DenominationPlan {
        migration_outputs: Vec::new(),
        crossing_values: Vec::new(),
        orchard_change,
        prep_fee_zatoshi,
        total_input_zatoshi,
        total_migratable_zatoshi: 0,
    };

    if total_input_zatoshi <= prep_fee_zatoshi {
        return Ok(base(None));
    }
    let mut budget = total_input_zatoshi - prep_fee_zatoshi;

    let mut migration_outputs = Vec::new();
    let mut crossing_values = Vec::new();
    loop {
        // Smallest self-funding note is 1 ZEC + buffer.
        if budget < ZATOSHIS_PER_ZEC + TRANSFER_FEE_BUFFER_ZATOSHI {
            break;
        }
        // Largest `{1, 2, 5} * 10^k` ZEC denomination `d` (in zatoshi) with `d + buffer <= budget`.
        let affordable_zec = (budget - TRANSFER_FEE_BUFFER_ZATOSHI) / ZATOSHIS_PER_ZEC;
        let d = largest_denomination_zec(affordable_zec) * ZATOSHIS_PER_ZEC;
        let note = d + TRANSFER_FEE_BUFFER_ZATOSHI;
        migration_outputs.push(note);
        crossing_values.push(d);
        budget -= note;
        if migration_outputs.len() > MIGRATION_MAX_PREPARED_NOTES_PER_RUN {
            return Err(format!(
                "Migration plan would create {} prepared notes, above the {} note limit",
                migration_outputs.len(),
                MIGRATION_MAX_PREPARED_NOTES_PER_RUN
            ));
        }
    }

    let total_migratable_zatoshi = crossing_values.iter().sum();
    Ok(DenominationPlan {
        migration_outputs,
        crossing_values,
        orchard_change: if budget > 0 { Some(budget) } else { None },
        prep_fee_zatoshi,
        total_input_zatoshi,
        total_migratable_zatoshi,
    })
}
