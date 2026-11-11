//! Types related to implementing a [`FeeRule`] provides [ZIP 317] fee calculation.
//!
//! [`FeeRule`]: crate::transaction::fees::FeeRule
//! [ZIP 317]: https://zips.z.cash/zip-0317
use alloc::vec::Vec;
use core::cmp::max;

use ::transparent::bundle::OutPoint;
use zcash_protocol::{
    consensus::{self, BlockHeight, NetworkType, NetworkUpgrade},
    value::{BalanceError, Zatoshis},
};

use crate::transaction::fees::transparent;

/// The [ZIP 317] marginal fee before Revision 2 ([ZIP 2009]).
///
/// [ZIP 317]: https://zips.z.cash/zip-0317
/// [ZIP 2009]: https://zips.z.cash/zip-2009
#[deprecated(
    since = "0.32.0",
    note = "Use `zip317::marginal_fee(params, target_height)` for the marginal fee in effect at the height a transaction is expected to be mined."
)]
pub const MARGINAL_FEE: Zatoshis = Zatoshis::const_from_u64(5_000);

/// The [ZIP 317] marginal fee from Revision 2 ([ZIP 2009]), in zatoshis per logical action.
///
/// [ZIP 317]: https://zips.z.cash/zip-0317
/// [ZIP 2009]: https://zips.z.cash/zip-2009
pub const REVISION_2_MARGINAL_FEE: Zatoshis = Zatoshis::const_from_u64(1_000);

/// The Mainnet height from which Revision 2 applies (`FEE_REDUCTION_HEIGHT` in [ZIP 2009]).
///
/// [ZIP 2009]: https://zips.z.cash/zip-2009
pub const MAINNET_FEE_REDUCTION_HEIGHT: BlockHeight = BlockHeight::from_u32(3_590_000);

/// The Testnet height from which Revision 2 applies; equal to the Testnet NU7 activation height.
pub const TESTNET_FEE_REDUCTION_HEIGHT: BlockHeight = BlockHeight::from_u32(4_465_026);

/// Returns the height from which [ZIP 317] Revision 2 applies on the network `params` describes,
/// or `None` if it never applies there. On a regtest network this is the NU7 activation height.
///
/// [ZIP 317]: https://zips.z.cash/zip-0317
pub fn fee_reduction_height<P: consensus::Parameters>(params: &P) -> Option<BlockHeight> {
    match params.network_type() {
        NetworkType::Main => Some(MAINNET_FEE_REDUCTION_HEIGHT),
        NetworkType::Test => Some(TESTNET_FEE_REDUCTION_HEIGHT),
        NetworkType::Regtest => params.activation_height(NetworkUpgrade::Nu7),
    }
}

/// Whether Revision 2 applies to a transaction expected to be mined at `target_height`.
fn revision_2_applies<P: consensus::Parameters>(params: &P, target_height: BlockHeight) -> bool {
    fee_reduction_height(params).is_some_and(|h| h <= target_height)
}

/// Returns the [ZIP 317] marginal fee for a transaction expected to be mined at `target_height`:
/// [`REVISION_2_MARGINAL_FEE`] from [`fee_reduction_height`], 5000 zatoshis before it.
///
/// [ZIP 317]: https://zips.z.cash/zip-0317
pub fn marginal_fee<P: consensus::Parameters>(params: &P, target_height: BlockHeight) -> Zatoshis {
    // The pre-Revision-2 constant is deprecated for external callers; this is its only reader.
    #[allow(deprecated)]
    let pre_revision_2 = MARGINAL_FEE;
    if revision_2_applies(params, target_height) {
        REVISION_2_MARGINAL_FEE
    } else {
        pre_revision_2
    }
}

/// Returns the [ZIP 317] minimum conventional fee at `target_height`: [`marginal_fee`] times
/// [`GRACE_ACTIONS`].
///
/// [ZIP 317]: https://zips.z.cash/zip-0317
pub fn minimum_fee<P: consensus::Parameters>(params: &P, target_height: BlockHeight) -> Zatoshis {
    // Cannot overflow: the product is at most `MARGINAL_FEE * GRACE_ACTIONS` (the value of
    // `MINIMUM_FEE`), which is far below `MAX_MONEY`.
    (marginal_fee(params, target_height) * GRACE_ACTIONS)
        .expect("MARGINAL_FEE * GRACE_ACTIONS is below MAX_MONEY")
}

/// The minimum number of logical actions that must be paid according to [ZIP 317].
///
/// [ZIP 317]: https://zips.z.cash/zip-0317
pub const GRACE_ACTIONS: usize = 2;

/// The standard size of a P2PKH input, in bytes, according to [ZIP 317].
///
/// [ZIP 317]: https://zips.z.cash/zip-0317
pub const P2PKH_STANDARD_INPUT_SIZE: usize = 150;

/// The standard size of a P2PKH output, in bytes, according to [ZIP 317].
///
/// [ZIP 317]: https://zips.z.cash/zip-0317
pub const P2PKH_STANDARD_OUTPUT_SIZE: usize = 34;

/// The consensus maximum size of a serialized transparent input: outpoint (36) +
/// CompactSize prefix for the scriptSig (at most 9) + scriptSig (at most
/// `MAX_SCRIPT_SIZE = 10_000`) + sequence (4). This is the safe upper bound for a
/// transparent input whose script size is unknown.
pub const MAX_TRANSPARENT_INPUT_SIZE: usize = 36 + 9 + 10_000 + 4;

/// The per-bundle overhead of a transparent bundle: two CompactSize vector-length
/// prefixes (one for `vin`, one for `vout`), at most 9 bytes each.
pub const TRANSPARENT_BUNDLE_OVERHEAD: usize = 18;

/// The fixed size of a Zcash transaction header: version (4) +
/// `consensus_branch_id` (4) + `lock_time` (4) + `expiry_height` (4). The constant
/// leaves room for future header fields.
pub const TX_HEADER_SIZE: usize = 32;

/// The [ZIP 317] minimum conventional fee before Revision 2 ([ZIP 2009]). Equivalent to
/// `MARGINAL_FEE * GRACE_ACTIONS`.
///
/// [ZIP 317]: https://zips.z.cash/zip-0317
/// [ZIP 2009]: https://zips.z.cash/zip-2009
#[deprecated(
    since = "0.32.0",
    note = "Use `zip317::minimum_fee(params, target_height)` for the minimum conventional fee in effect at the height a transaction is expected to be mined."
)]
pub const MINIMUM_FEE: Zatoshis = Zatoshis::const_from_u64(10_000);

/// A [`FeeRule`] implementation that implements the [ZIP 317] fee rule.
///
/// This fee rule supports Ironwood, Orchard, Sapling, and (P2PKH only) transparent
/// inputs. Returns an error if a coin containing a non-P2PKH script is provided as an input.
///
/// This fee rule may slightly overestimate fees in case where the user is attempting
/// to spend a large number of transparent inputs. This is intentional and is relied
/// on for the correctness of transaction construction algorithms in the
/// `zcash_client_backend` crate.
///
/// [`FeeRule`]: crate::transaction::fees::FeeRule
/// [ZIP 317]: https://zips.z.cash/zip-0317
#[derive(Clone, Debug)]
pub struct FeeRule {
    marginal_fee: MarginalFee,
    grace_actions: usize,
    p2pkh_standard_input_size: usize,
    p2pkh_standard_output_size: usize,
}

/// The marginal fee a [`FeeRule`] charges.
#[derive(Clone, Debug)]
enum MarginalFee {
    /// The ZIP 317 schedule ([`marginal_fee`]).
    Standard,
    /// A fixed value, from [`FeeRule::non_standard`].
    #[cfg(feature = "non-standard-fees")]
    Fixed(Zatoshis),
}

impl FeeRule {
    /// The standard [ZIP 317] rule: the marginal fee in effect at the height a transaction is
    /// expected to be mined ([`marginal_fee`]), with the standard grace actions and P2PKH sizes.
    ///
    /// [ZIP 317]: https://zips.z.cash/zip-0317
    pub fn standard() -> Self {
        Self {
            marginal_fee: MarginalFee::Standard,
            grace_actions: GRACE_ACTIONS,
            p2pkh_standard_input_size: P2PKH_STANDARD_INPUT_SIZE,
            p2pkh_standard_output_size: P2PKH_STANDARD_OUTPUT_SIZE,
        }
    }

    /// Construct a new FeeRule instance with the specified parameter values.
    ///
    /// Using this fee rule with
    /// ```text
    /// marginal_fee < marginal_fee(params, target_height) || grace_actions < 2
    ///     || p2pkh_standard_input_size > P2PKH_STANDARD_INPUT_SIZE
    ///     || p2pkh_standard_output_size > P2PKH_STANDARD_OUTPUT_SIZE
    /// ```
    /// violates ZIP 317, and might cause transactions built with it to fail.
    ///
    /// Returns `None` if either `p2pkh_standard_input_size` or `p2pkh_standard_output_size` are
    /// zero.
    #[cfg(feature = "non-standard-fees")]
    pub fn non_standard(
        marginal_fee: Zatoshis,
        grace_actions: usize,
        p2pkh_standard_input_size: usize,
        p2pkh_standard_output_size: usize,
    ) -> Option<Self> {
        if p2pkh_standard_input_size == 0 || p2pkh_standard_output_size == 0 {
            None
        } else {
            Some(Self {
                marginal_fee: MarginalFee::Fixed(marginal_fee),
                grace_actions,
                p2pkh_standard_input_size,
                p2pkh_standard_output_size,
            })
        }
    }

    /// Returns the marginal fee this rule charges a transaction expected to be mined at
    /// `target_height`.
    pub fn marginal_fee<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
    ) -> Zatoshis {
        match self.marginal_fee {
            MarginalFee::Standard => marginal_fee(params, target_height),
            #[cfg(feature = "non-standard-fees")]
            MarginalFee::Fixed(fee) => fee,
        }
    }
    /// Returns the ZIP 317 number of grace actions
    pub fn grace_actions(&self) -> usize {
        self.grace_actions
    }
    /// Returns the ZIP 317 standard P2PKH input size
    pub fn p2pkh_standard_input_size(&self) -> usize {
        self.p2pkh_standard_input_size
    }
    /// Returns the ZIP 317 standard P2PKH output size
    pub fn p2pkh_standard_output_size(&self) -> usize {
        self.p2pkh_standard_output_size
    }
}

/// Errors that can occur in ZIP 317 fee computation
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeError {
    /// An overflow or underflow of amount computation occurred.
    Balance(BalanceError),
    /// Transparent inputs provided to the fee calculation included coins that pay to
    /// unknown P2SH redeem scripts.
    UnknownP2shInputs(Vec<OutPoint>),
}

impl From<BalanceError> for FeeError {
    fn from(err: BalanceError) -> Self {
        FeeError::Balance(err)
    }
}

impl core::fmt::Display for FeeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self {
            FeeError::Balance(e) => write!(
                f,
                "A balance calculation violated amount validity bounds: {e}."
            ),
            FeeError::UnknownP2shInputs(_) => {
                write!(f, "Only P2PKH or known-P2SH inputs are supported.")
            }
        }
    }
}

impl super::FeeRule for FeeRule {
    type Error = FeeError;

    fn fee_required<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_input_sizes: impl IntoIterator<Item = transparent::InputSize>,
        transparent_output_sizes: impl IntoIterator<Item = usize>,
        sapling_input_count: usize,
        sapling_output_count: usize,
        orchard_action_count: usize,
        ironwood_action_count: usize,
    ) -> Result<Zatoshis, Self::Error> {
        let mut t_in_total_size: usize = 0;
        let mut unknown_p2sh_outpoints = vec![];
        for sz in transparent_input_sizes.into_iter() {
            match sz {
                transparent::InputSize::Known(s) => {
                    t_in_total_size += s;
                }
                transparent::InputSize::Unknown(outpoint) => {
                    unknown_p2sh_outpoints.push(outpoint.clone());
                }
            }
        }

        if !unknown_p2sh_outpoints.is_empty() {
            return Err(FeeError::UnknownP2shInputs(unknown_p2sh_outpoints));
        }

        let t_out_total_size = transparent_output_sizes.into_iter().sum();

        let ceildiv = |num: usize, den: usize| num.div_ceil(den);

        let logical_actions = max(
            ceildiv(t_in_total_size, self.p2pkh_standard_input_size),
            ceildiv(t_out_total_size, self.p2pkh_standard_output_size),
        ) + max(sapling_input_count, sapling_output_count)
            + orchard_action_count
            + ironwood_action_count;

        (self.marginal_fee(params, target_height) * max(self.grace_actions, logical_actions))
            .ok_or_else(|| BalanceError::Overflow.into())
    }
}

#[cfg(test)]
mod tests {
    // The tests pin the deprecated pre-Revision-2 constants themselves.
    #![allow(deprecated)]

    use core::iter;

    use zcash_protocol::{
        consensus::{BlockHeight, MAIN_NETWORK, NetworkUpgrade, Parameters, TEST_NETWORK},
        local_consensus::LocalNetwork,
        value::Zatoshis,
    };

    use super::{
        FeeRule, GRACE_ACTIONS, MAINNET_FEE_REDUCTION_HEIGHT, MARGINAL_FEE, MINIMUM_FEE,
        REVISION_2_MARGINAL_FEE, TESTNET_FEE_REDUCTION_HEIGHT, fee_reduction_height, marginal_fee,
        minimum_fee,
    };
    use crate::transaction::fees::{FeeRule as _, transparent::InputSize};

    #[cfg(feature = "non-standard-fees")]
    use super::{P2PKH_STANDARD_INPUT_SIZE, P2PKH_STANDARD_OUTPUT_SIZE};

    /// The regtest NU7 activation height used by the schedule tests.
    const REGTEST_NU7_HEIGHT: BlockHeight = BlockHeight::from_u32(10);

    fn regtest(nu7: Option<BlockHeight>) -> LocalNetwork {
        LocalNetwork {
            overwinter: None,
            sapling: None,
            blossom: None,
            heartwood: None,
            canopy: None,
            nu5: None,
            nu6: None,
            nu6_1: None,
            nu6_2: None,
            nu6_3: None,
            nu7,
            #[cfg(zcash_unstable = "nutachyon")]
            nu_tachyon: None,
        }
    }

    fn fee_for(orchard_action_count: usize, ironwood_action_count: usize) -> Zatoshis {
        FeeRule::standard()
            .fee_required(
                &MAIN_NETWORK,
                BlockHeight::from_u32(1_000_000),
                iter::empty::<InputSize>(),
                iter::empty::<usize>(),
                0,
                0,
                orchard_action_count,
                ironwood_action_count,
            )
            .unwrap()
    }

    /// The fee `rule` charges a transaction of `orchard_action_count` Orchard actions and nothing
    /// else, expected to be mined at `height`.
    fn fee_at<P: Parameters>(
        rule: &FeeRule,
        params: &P,
        height: BlockHeight,
        orchard_action_count: usize,
    ) -> Zatoshis {
        rule.fee_required(
            params,
            height,
            iter::empty::<InputSize>(),
            iter::empty::<usize>(),
            0,
            0,
            orchard_action_count,
            0,
        )
        .unwrap()
    }

    /// Asserts the marginal fee at `height`, and that the minimum fee follows it.
    fn assert_fees_at<P: Parameters>(params: &P, height: BlockHeight, expected: Zatoshis) {
        assert_eq!(marginal_fee(params, height), expected);
        assert_eq!(
            minimum_fee(params, height),
            (expected * GRACE_ACTIONS).unwrap()
        );
    }

    #[test]
    fn ironwood_actions_charged_marginal_fee() {
        // Five Ironwood actions exceed the grace allowance, so each is charged the
        // marginal fee.
        assert_eq!(fee_for(0, 5), (MARGINAL_FEE * 5usize).unwrap());
    }

    #[test]
    fn ironwood_actions_combine_with_orchard() {
        // Orchard and Ironwood actions are summed into the logical action count.
        assert_eq!(fee_for(2, 3), (MARGINAL_FEE * 5usize).unwrap());
    }

    #[test]
    fn fee_reduction_height_and_marginal_fee_per_network() {
        let below = |h: BlockHeight| h - 1;

        assert_eq!(
            fee_reduction_height(&MAIN_NETWORK),
            Some(MAINNET_FEE_REDUCTION_HEIGHT)
        );
        assert_fees_at(
            &MAIN_NETWORK,
            below(MAINNET_FEE_REDUCTION_HEIGHT),
            MARGINAL_FEE,
        );
        assert_fees_at(
            &MAIN_NETWORK,
            MAINNET_FEE_REDUCTION_HEIGHT,
            REVISION_2_MARGINAL_FEE,
        );

        assert_eq!(
            fee_reduction_height(&TEST_NETWORK),
            Some(TESTNET_FEE_REDUCTION_HEIGHT)
        );
        assert_eq!(
            TEST_NETWORK.activation_height(NetworkUpgrade::Nu7),
            Some(TESTNET_FEE_REDUCTION_HEIGHT)
        );
        assert_fees_at(
            &TEST_NETWORK,
            below(TESTNET_FEE_REDUCTION_HEIGHT),
            MARGINAL_FEE,
        );
        assert_fees_at(
            &TEST_NETWORK,
            TESTNET_FEE_REDUCTION_HEIGHT,
            REVISION_2_MARGINAL_FEE,
        );

        let with_nu7 = regtest(Some(REGTEST_NU7_HEIGHT));
        assert_eq!(fee_reduction_height(&with_nu7), Some(REGTEST_NU7_HEIGHT));
        assert_fees_at(&with_nu7, below(REGTEST_NU7_HEIGHT), MARGINAL_FEE);
        assert_fees_at(&with_nu7, REGTEST_NU7_HEIGHT, REVISION_2_MARGINAL_FEE);

        let without_nu7 = regtest(None);
        assert_eq!(fee_reduction_height(&without_nu7), None);
        assert_fees_at(&without_nu7, BlockHeight::from_u32(u32::MAX), MARGINAL_FEE);

        // The pre-Revision 2 constants keep their values.
        assert_eq!(MARGINAL_FEE, Zatoshis::const_from_u64(5_000));
        assert_eq!(MINIMUM_FEE, Zatoshis::const_from_u64(10_000));
    }

    #[test]
    fn standard_rule_follows_schedule_and_fixed_rule_does_not() {
        let rule = FeeRule::standard();
        let before = MAINNET_FEE_REDUCTION_HEIGHT - 1;
        let from = MAINNET_FEE_REDUCTION_HEIGHT;

        // A transaction of exactly `GRACE_ACTIONS` logical actions pays the minimum fee.
        assert_eq!(
            fee_at(&rule, &MAIN_NETWORK, before, GRACE_ACTIONS),
            minimum_fee(&MAIN_NETWORK, before)
        );
        assert_eq!(
            fee_at(&rule, &MAIN_NETWORK, from, GRACE_ACTIONS),
            minimum_fee(&MAIN_NETWORK, from)
        );
        assert_eq!(
            rule.marginal_fee(&MAIN_NETWORK, from),
            REVISION_2_MARGINAL_FEE
        );

        #[cfg(feature = "non-standard-fees")]
        {
            let fixed = FeeRule::non_standard(
                MARGINAL_FEE,
                GRACE_ACTIONS,
                P2PKH_STANDARD_INPUT_SIZE,
                P2PKH_STANDARD_OUTPUT_SIZE,
            )
            .unwrap();
            assert_eq!(fixed.marginal_fee(&MAIN_NETWORK, from), MARGINAL_FEE);
            assert_eq!(
                fee_at(&fixed, &MAIN_NETWORK, from, GRACE_ACTIONS),
                (MARGINAL_FEE * GRACE_ACTIONS).unwrap()
            );
        }
    }
}
