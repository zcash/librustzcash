//! Types related to implementing a [`FeeRule`] provides [ZIP 317] fee calculation.
//!
//! [`FeeRule`]: crate::transaction::fees::FeeRule
//! [ZIP 317]: https//zips.z.cash/zip-0317
use alloc::vec::Vec;
use core::cmp::max;

use ::transparent::bundle::OutPoint;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    value::{BalanceError, Zatoshis},
};

use crate::transaction::fees::transparent;

/// The standard [ZIP 317] marginal fee.
///
/// [ZIP 317]: https//zips.z.cash/zip-0317
pub const MARGINAL_FEE: Zatoshis = Zatoshis::const_from_u64(5_000);

/// The minimum number of logical actions that must be paid according to [ZIP 317].
///
/// [ZIP 317]: https//zips.z.cash/zip-0317
pub const GRACE_ACTIONS: usize = 2;

/// The standard size of a P2PKH input, in bytes, according to [ZIP 317].
///
/// [ZIP 317]: https//zips.z.cash/zip-0317
pub const P2PKH_STANDARD_INPUT_SIZE: usize = 150;

/// The standard size of a P2PKH output, in bytes, according to [ZIP 317].
///
/// [ZIP 317]: https//zips.z.cash/zip-0317
pub const P2PKH_STANDARD_OUTPUT_SIZE: usize = 34;

/// The minimum conventional fee computed from the standard [ZIP 317] constants. Equivalent to
/// `MARGINAL_FEE * GRACE_ACTIONS`.
///
/// [ZIP 317]: https//zips.z.cash/zip-0317
pub const MINIMUM_FEE: Zatoshis = Zatoshis::const_from_u64(10_000);

/// A [`FeeRule`] implementation that implements the [ZIP 317] fee rule.
///
/// This fee rule supports Orchard, Sapling, and (P2PKH only) transparent inputs.
/// Returns an error if a coin containing a non-P2PKH script is provided as an input.
///
/// This fee rule may slightly overestimate fees in case where the user is attempting
/// to spend a large number of transparent inputs. This is intentional and is relied
/// on for the correctness of transaction construction algorithms in the
/// `zcash_client_backend` crate.
///
/// [`FeeRule`]: crate::transaction::fees::FeeRule
/// [ZIP 317]: https//zips.z.cash/zip-0317
#[derive(Clone, Debug)]
pub struct FeeRule {
    marginal_fee: Zatoshis,
    grace_actions: usize,
    p2pkh_standard_input_size: usize,
    p2pkh_standard_output_size: usize,
}

impl FeeRule {
    /// Construct a new FeeRule using the standard [ZIP 317] constants.
    ///
    /// [ZIP 317]: https//zips.z.cash/zip-0317
    pub fn standard() -> Self {
        Self {
            marginal_fee: MARGINAL_FEE,
            grace_actions: GRACE_ACTIONS,
            p2pkh_standard_input_size: P2PKH_STANDARD_INPUT_SIZE,
            p2pkh_standard_output_size: P2PKH_STANDARD_OUTPUT_SIZE,
        }
    }

    /// Construct a new FeeRule instance with the specified parameter values.
    ///
    /// Using this fee rule with
    /// ```compile_fail
    /// marginal_fee < 5000 || grace_actions < 2
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
                marginal_fee,
                grace_actions,
                p2pkh_standard_input_size,
                p2pkh_standard_output_size,
            })
        }
    }

    /// Returns the ZIP 317 marginal fee.
    pub fn marginal_fee(&self) -> Zatoshis {
        self.marginal_fee
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
        _params: &P,
        _target_height: BlockHeight,
        transparent_input_sizes: impl IntoIterator<Item = transparent::InputSize>,
        transparent_output_sizes: impl IntoIterator<Item = usize>,
        sapling_input_count: usize,
        sapling_output_count: usize,
        orchard_action_count: usize,
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
            + orchard_action_count;

        (self.marginal_fee * max(self.grace_actions, logical_actions))
            .ok_or_else(|| BalanceError::Overflow.into())
    }
}
