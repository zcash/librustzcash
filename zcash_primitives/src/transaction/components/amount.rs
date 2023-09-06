use std::convert::TryFrom;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use memuse::DynamicUsage;
use orchard::value as orchard;

pub const COIN: i64 = 1_0000_0000;
pub const MAX_MONEY: i64 = 21_000_000 * COIN;

/// A type-safe representation of some quantity of Zcash.
///
/// An Amount can only be constructed from an integer that is within the valid monetary
/// range of `{-MAX_MONEY..MAX_MONEY}` (where `MAX_MONEY` = 21,000,000 × 10⁸ zatoshis).
/// However, this range is not preserved as an invariant internally; it is possible to
/// add two valid Amounts together to obtain an invalid Amount. It is the user's
/// responsibility to handle the result of serializing potentially-invalid Amounts. In
/// particular, a [`Transaction`] containing serialized invalid Amounts will be rejected
/// by the network consensus rules.
///
/// [`Transaction`]: crate::transaction::Transaction
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct Amount(i64);

memuse::impl_no_dynamic_usage!(Amount);

impl Amount {
    /// Returns a zero-valued Amount.
    pub const fn zero() -> Self {
        Amount(0)
    }

    /// Creates a constant Amount from an i64.
    ///
    /// Panics: if the amount is outside the range `{-MAX_MONEY..MAX_MONEY}`.
    pub const fn const_from_i64(amount: i64) -> Self {
        assert!(-MAX_MONEY <= amount && amount <= MAX_MONEY); // contains is not const
        Amount(amount)
    }

    /// Creates an Amount from an i64.
    ///
    /// Returns an error if the amount is outside the range `{-MAX_MONEY..MAX_MONEY}`.
    pub fn from_i64(amount: i64) -> Result<Self, ()> {
        if (-MAX_MONEY..=MAX_MONEY).contains(&amount) {
            Ok(Amount(amount))
        } else {
            Err(())
        }
    }

    /// Creates a non-negative Amount from an i64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_nonnegative_i64(amount: i64) -> Result<Self, ()> {
        if (0..=MAX_MONEY).contains(&amount) {
            Ok(Amount(amount))
        } else {
            Err(())
        }
    }

    /// Creates an Amount from a u64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_u64(amount: u64) -> Result<Self, ()> {
        if amount <= MAX_MONEY as u64 {
            Ok(Amount(amount as i64))
        } else {
            Err(())
        }
    }

    /// Reads an Amount from a signed 64-bit little-endian integer.
    ///
    /// Returns an error if the amount is outside the range `{-MAX_MONEY..MAX_MONEY}`.
    pub fn from_i64_le_bytes(bytes: [u8; 8]) -> Result<Self, ()> {
        let amount = i64::from_le_bytes(bytes);
        Amount::from_i64(amount)
    }

    /// Reads a non-negative Amount from a signed 64-bit little-endian integer.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_nonnegative_i64_le_bytes(bytes: [u8; 8]) -> Result<Self, ()> {
        let amount = i64::from_le_bytes(bytes);
        Amount::from_nonnegative_i64(amount)
    }

    /// Reads an Amount from an unsigned 64-bit little-endian integer.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_u64_le_bytes(bytes: [u8; 8]) -> Result<Self, ()> {
        let amount = u64::from_le_bytes(bytes);
        Amount::from_u64(amount)
    }

    /// Returns the Amount encoded as a signed 64-bit little-endian integer.
    pub fn to_i64_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Returns `true` if `self` is positive and `false` if the Amount is zero or
    /// negative.
    pub const fn is_positive(self) -> bool {
        self.0.is_positive()
    }

    /// Returns `true` if `self` is negative and `false` if the Amount is zero or
    /// positive.
    pub const fn is_negative(self) -> bool {
        self.0.is_negative()
    }

    pub fn sum<I: IntoIterator<Item = Amount>>(values: I) -> Option<Amount> {
        let mut result = Amount::zero();
        for value in values {
            result = (result + value)?;
        }
        Some(result)
    }
}

impl TryFrom<i64> for Amount {
    type Error = ();

    fn try_from(value: i64) -> Result<Self, ()> {
        Amount::from_i64(value)
    }
}

impl From<Amount> for i64 {
    fn from(amount: Amount) -> i64 {
        amount.0
    }
}

impl From<&Amount> for i64 {
    fn from(amount: &Amount) -> i64 {
        amount.0
    }
}

impl From<Amount> for u64 {
    fn from(amount: Amount) -> u64 {
        amount.0 as u64
    }
}

impl Add<Amount> for Amount {
    type Output = Option<Amount>;

    fn add(self, rhs: Amount) -> Option<Amount> {
        Amount::from_i64(self.0 + rhs.0).ok()
    }
}

impl Add<Amount> for Option<Amount> {
    type Output = Self;

    fn add(self, rhs: Amount) -> Option<Amount> {
        self.and_then(|lhs| lhs + rhs)
    }
}

impl AddAssign<Amount> for Amount {
    fn add_assign(&mut self, rhs: Amount) {
        *self = (*self + rhs).expect("Addition must produce a valid amount value.")
    }
}

impl Sub<Amount> for Amount {
    type Output = Option<Amount>;

    fn sub(self, rhs: Amount) -> Option<Amount> {
        Amount::from_i64(self.0 - rhs.0).ok()
    }
}

impl Sub<Amount> for Option<Amount> {
    type Output = Self;

    fn sub(self, rhs: Amount) -> Option<Amount> {
        self.and_then(|lhs| lhs - rhs)
    }
}

impl SubAssign<Amount> for Amount {
    fn sub_assign(&mut self, rhs: Amount) {
        *self = (*self - rhs).expect("Subtraction must produce a valid amount value.")
    }
}

impl Sum<Amount> for Option<Amount> {
    fn sum<I: Iterator<Item = Amount>>(iter: I) -> Self {
        iter.fold(Some(Amount::zero()), |acc, a| acc? + a)
    }
}

impl<'a> Sum<&'a Amount> for Option<Amount> {
    fn sum<I: Iterator<Item = &'a Amount>>(iter: I) -> Self {
        iter.fold(Some(Amount::zero()), |acc, a| acc? + *a)
    }
}

impl Neg for Amount {
    type Output = Self;

    fn neg(self) -> Self {
        Amount(-self.0)
    }
}

impl Mul<usize> for Amount {
    type Output = Option<Amount>;

    fn mul(self, rhs: usize) -> Option<Amount> {
        let rhs: i64 = rhs.try_into().ok()?;
        self.0
            .checked_mul(rhs)
            .and_then(|i| Amount::try_from(i).ok())
    }
}

impl TryFrom<orchard::ValueSum> for Amount {
    type Error = ();

    fn try_from(v: orchard::ValueSum) -> Result<Amount, Self::Error> {
        i64::try_from(v).map_err(|_| ()).and_then(Amount::try_from)
    }
}

/// A type-safe representation of some nonnegative amount of Zcash.
///
/// A NonNegativeAmount can only be constructed from an integer that is within the valid monetary
/// range of `{0..MAX_MONEY}` (where `MAX_MONEY` = 21,000,000 × 10⁸ zatoshis).
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct NonNegativeAmount(Amount);

impl NonNegativeAmount {
    /// Returns the identity `NonNegativeAmount`
    pub const ZERO: Self = NonNegativeAmount(Amount(0));

    /// Creates a NonNegativeAmount from a u64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_u64(amount: u64) -> Result<Self, ()> {
        Amount::from_u64(amount).map(NonNegativeAmount)
    }

    /// Creates a NonNegativeAmount from an i64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_nonnegative_i64(amount: i64) -> Result<Self, ()> {
        Amount::from_nonnegative_i64(amount).map(NonNegativeAmount)
    }
}

impl From<NonNegativeAmount> for Amount {
    fn from(n: NonNegativeAmount) -> Self {
        n.0
    }
}

impl TryFrom<Amount> for NonNegativeAmount {
    type Error = ();

    fn try_from(value: Amount) -> Result<Self, Self::Error> {
        if value.is_negative() {
            Err(())
        } else {
            Ok(NonNegativeAmount(value))
        }
    }
}

impl Add<NonNegativeAmount> for NonNegativeAmount {
    type Output = Option<NonNegativeAmount>;

    fn add(self, rhs: NonNegativeAmount) -> Option<NonNegativeAmount> {
        (self.0 + rhs.0).map(NonNegativeAmount)
    }
}

impl Add<NonNegativeAmount> for Option<NonNegativeAmount> {
    type Output = Self;

    fn add(self, rhs: NonNegativeAmount) -> Option<NonNegativeAmount> {
        self.and_then(|lhs| lhs + rhs)
    }
}

impl Sub<NonNegativeAmount> for NonNegativeAmount {
    type Output = Option<NonNegativeAmount>;

    fn sub(self, rhs: NonNegativeAmount) -> Option<NonNegativeAmount> {
        (self.0 - rhs.0).and_then(|amt| NonNegativeAmount::try_from(amt).ok())
    }
}

impl Sub<NonNegativeAmount> for Option<NonNegativeAmount> {
    type Output = Self;

    fn sub(self, rhs: NonNegativeAmount) -> Option<NonNegativeAmount> {
        self.and_then(|lhs| lhs - rhs)
    }
}

/// A type for balance violations in amount addition and subtraction
/// (overflow and underflow of allowed ranges)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BalanceError {
    Overflow,
    Underflow,
}

impl std::fmt::Display for BalanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            BalanceError::Overflow => {
                write!(
                    f,
                    "Amount addition resulted in a value outside the valid range."
                )
            }
            BalanceError::Underflow => write!(
                f,
                "Amount subtraction resulted in a value outside the valid range."
            ),
        }
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::prop_compose;

    use super::{Amount, MAX_MONEY};

    prop_compose! {
        pub fn arb_amount()(amt in -MAX_MONEY..MAX_MONEY) -> Amount {
            Amount::from_i64(amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_nonnegative_amount()(amt in 0i64..MAX_MONEY) -> Amount {
            Amount::from_i64(amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_positive_amount()(amt in 1i64..MAX_MONEY) -> Amount {
            Amount::from_i64(amt).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Amount, MAX_MONEY};

    #[test]
    fn amount_in_range() {
        let zero = b"\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(Amount::from_u64_le_bytes(*zero).unwrap(), Amount(0));
        assert_eq!(
            Amount::from_nonnegative_i64_le_bytes(*zero).unwrap(),
            Amount(0)
        );
        assert_eq!(Amount::from_i64_le_bytes(*zero).unwrap(), Amount(0));

        let neg_one = b"\xff\xff\xff\xff\xff\xff\xff\xff";
        assert!(Amount::from_u64_le_bytes(*neg_one).is_err());
        assert!(Amount::from_nonnegative_i64_le_bytes(*neg_one).is_err());
        assert_eq!(Amount::from_i64_le_bytes(*neg_one).unwrap(), Amount(-1));

        let max_money = b"\x00\x40\x07\x5a\xf0\x75\x07\x00";
        assert_eq!(
            Amount::from_u64_le_bytes(*max_money).unwrap(),
            Amount(MAX_MONEY)
        );
        assert_eq!(
            Amount::from_nonnegative_i64_le_bytes(*max_money).unwrap(),
            Amount(MAX_MONEY)
        );
        assert_eq!(
            Amount::from_i64_le_bytes(*max_money).unwrap(),
            Amount(MAX_MONEY)
        );

        let max_money_p1 = b"\x01\x40\x07\x5a\xf0\x75\x07\x00";
        assert!(Amount::from_u64_le_bytes(*max_money_p1).is_err());
        assert!(Amount::from_nonnegative_i64_le_bytes(*max_money_p1).is_err());
        assert!(Amount::from_i64_le_bytes(*max_money_p1).is_err());

        let neg_max_money = b"\x00\xc0\xf8\xa5\x0f\x8a\xf8\xff";
        assert!(Amount::from_u64_le_bytes(*neg_max_money).is_err());
        assert!(Amount::from_nonnegative_i64_le_bytes(*neg_max_money).is_err());
        assert_eq!(
            Amount::from_i64_le_bytes(*neg_max_money).unwrap(),
            Amount(-MAX_MONEY)
        );

        let neg_max_money_m1 = b"\xff\xbf\xf8\xa5\x0f\x8a\xf8\xff";
        assert!(Amount::from_u64_le_bytes(*neg_max_money_m1).is_err());
        assert!(Amount::from_nonnegative_i64_le_bytes(*neg_max_money_m1).is_err());
        assert!(Amount::from_i64_le_bytes(*neg_max_money_m1).is_err());
    }

    #[test]
    fn add_overflow() {
        let v = Amount(MAX_MONEY);
        assert_eq!(v + Amount(1), None)
    }

    #[test]
    #[should_panic]
    fn add_assign_panics_on_overflow() {
        let mut a = Amount(MAX_MONEY);
        a += Amount(1);
    }

    #[test]
    fn sub_underflow() {
        let v = Amount(-MAX_MONEY);
        assert_eq!(v - Amount(1), None)
    }

    #[test]
    #[should_panic]
    fn sub_assign_panics_on_underflow() {
        let mut a = Amount(-MAX_MONEY);
        a -= Amount(1);
    }
}
