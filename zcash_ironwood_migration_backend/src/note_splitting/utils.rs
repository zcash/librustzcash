//! Shared denomination-value helpers for the note-split strategies: finding the largest denomination
//! not exceeding a value and enumerating the denominations in a range, over both the
//! `{1, 2, 5} * 10^k` series and the pure powers of ten. Pure integer arithmetic.

/// The base of the denomination scale: every denomination is a multiple of a power of this radix.
const DENOMINATION_RADIX: u64 = 10;

/// The significand multipliers of the `{1, 2, 5} * 10^k` series, ascending.
const ONE_TWO_FIVE_ASCENDING: [u64; 3] = [1, 2, 5];

/// The significand multipliers of the `{1, 2, 5} * 10^k` series, descending (largest first).
const ONE_TWO_FIVE_DESCENDING: [u64; 3] = [5, 2, 1];

/// The largest `{1, 2, 5} * 10^k` value (a multiple of the power-of-radix `floor`) not exceeding
/// `hi`, or `0` if `hi < floor`. `floor` must be a power of the radix. Works in whatever unit `hi`
/// and `floor` share (here, zatoshi), so it can mint sub-1-ZEC denominations down to `floor`.
pub(crate) fn largest_one_two_five(hi: u64, floor: u64) -> u64 {
    if hi < floor {
        return 0;
    }
    // Largest power of the radix, at least `floor`, not exceeding `hi`.
    let mut pow = floor;
    while pow.checked_mul(DENOMINATION_RADIX).is_some_and(|p| p <= hi) {
        pow *= DENOMINATION_RADIX;
    }
    // Prefer the largest significand multiple of that power that still fits.
    for multiple in ONE_TWO_FIVE_DESCENDING {
        if let Some(v) = pow.checked_mul(multiple) {
            if v <= hi {
                return v;
            }
        }
    }
    pow
}

/// Every `{1, 2, 5} * 10^k` denomination `d` with `lo <= d <= hi`, in ascending order, in whatever
/// unit `lo` and `hi` share (here, zatoshi, so sub-1-ZEC denominations are included). Empty when
/// `hi == 0`.
pub(crate) fn denominations_between(lo: u64, hi: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut pow = 1u64;
    'outer: loop {
        for multiple in ONE_TWO_FIVE_ASCENDING {
            let v = multiple * pow;
            if v > hi {
                break 'outer;
            }
            if v >= lo {
                out.push(v);
            }
        }
        match pow.checked_mul(DENOMINATION_RADIX) {
            Some(p) => pow = p,
            None => break,
        }
    }
    out
}

/// The largest power of the radix `p` (a multiple of the power-of-radix `floor`) with
/// `floor <= p <= hi`, or `0` if `hi < floor`.
pub(crate) fn largest_power_of_ten(hi: u64, floor: u64) -> u64 {
    if hi < floor {
        return 0;
    }
    let mut p = floor;
    while p.checked_mul(DENOMINATION_RADIX).is_some_and(|q| q <= hi) {
        p *= DENOMINATION_RADIX;
    }
    p
}
