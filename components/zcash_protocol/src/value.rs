use std::convert::{Infallible, TryFrom};
use std::error;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use memuse::DynamicUsage;

pub const COIN: u64 = 1_0000_0000;
pub const MAX_MONEY: u64 = 21_000_000 * COIN;
pub const MAX_BALANCE: i64 = MAX_MONEY as i64;

/// A type-safe representation of a Zcash value delta, in zatoshis.
///
/// An ZatBalance can only be constructed from an integer that is within the valid monetary
/// range of `{-MAX_MONEY..MAX_MONEY}` (where `MAX_MONEY` = 21,000,000 × 10⁸ zatoshis).
/// However, this range is not preserved as an invariant internally; it is possible to
/// add two valid ZatBalances together to obtain an invalid ZatBalance. It is the user's
/// responsibility to handle the result of serializing potentially-invalid ZatBalances. In
/// particular, a [`Transaction`] containing serialized invalid ZatBalances will be rejected
/// by the network consensus rules.
///
/// [`Transaction`]: crate::transaction::Transaction
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct ZatBalance(i64);

memuse::impl_no_dynamic_usage!(ZatBalance);

impl ZatBalance {
    /// Returns a zero-valued ZatBalance.
    pub const fn zero() -> Self {
        ZatBalance(0)
    }

    /// Creates a constant ZatBalance from an i64.
    ///
    /// Panics: if the amount is outside the range `{-MAX_BALANCE..MAX_BALANCE}`.
    pub const fn const_from_i64(amount: i64) -> Self {
        assert!(-MAX_BALANCE <= amount && amount <= MAX_BALANCE); // contains is not const
        ZatBalance(amount)
    }

    /// Creates a constant ZatBalance from a u64.
    ///
    /// Panics: if the amount is outside the range `{0..MAX_BALANCE}`.
    pub const fn const_from_u64(amount: u64) -> Self {
        assert!(amount <= MAX_MONEY); // contains is not const
        ZatBalance(amount as i64)
    }

    /// Creates an ZatBalance from an i64.
    ///
    /// Returns an error if the amount is outside the range `{-MAX_BALANCE..MAX_BALANCE}`.
    pub fn from_i64(amount: i64) -> Result<Self, ()> {
        if (-MAX_BALANCE..=MAX_BALANCE).contains(&amount) {
            Ok(ZatBalance(amount))
        } else {
            Err(())
        }
    }

    /// Creates a non-negative ZatBalance from an i64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_BALANCE}`.
    pub fn from_nonnegative_i64(amount: i64) -> Result<Self, ()> {
        if (0..=MAX_BALANCE).contains(&amount) {
            Ok(ZatBalance(amount))
        } else {
            Err(())
        }
    }

    /// Creates an ZatBalance from a u64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_u64(amount: u64) -> Result<Self, ()> {
        if amount <= MAX_MONEY {
            Ok(ZatBalance(amount as i64))
        } else {
            Err(())
        }
    }

    /// Reads an ZatBalance from a signed 64-bit little-endian integer.
    ///
    /// Returns an error if the amount is outside the range `{-MAX_BALANCE..MAX_BALANCE}`.
    pub fn from_i64_le_bytes(bytes: [u8; 8]) -> Result<Self, ()> {
        let amount = i64::from_le_bytes(bytes);
        ZatBalance::from_i64(amount)
    }

    /// Reads a non-negative ZatBalance from a signed 64-bit little-endian integer.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_BALANCE}`.
    pub fn from_nonnegative_i64_le_bytes(bytes: [u8; 8]) -> Result<Self, ()> {
        let amount = i64::from_le_bytes(bytes);
        ZatBalance::from_nonnegative_i64(amount)
    }

    /// Reads an ZatBalance from an unsigned 64-bit little-endian integer.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_BALANCE}`.
    pub fn from_u64_le_bytes(bytes: [u8; 8]) -> Result<Self, ()> {
        let amount = u64::from_le_bytes(bytes);
        ZatBalance::from_u64(amount)
    }

    /// Returns the ZatBalance encoded as a signed 64-bit little-endian integer.
    pub fn to_i64_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Returns `true` if `self` is positive and `false` if the ZatBalance is zero or
    /// negative.
    pub const fn is_positive(self) -> bool {
        self.0.is_positive()
    }

    /// Returns `true` if `self` is negative and `false` if the ZatBalance is zero or
    /// positive.
    pub const fn is_negative(self) -> bool {
        self.0.is_negative()
    }

    pub fn sum<I: IntoIterator<Item = ZatBalance>>(values: I) -> Option<ZatBalance> {
        let mut result = ZatBalance::zero();
        for value in values {
            result = (result + value)?;
        }
        Some(result)
    }
}

impl TryFrom<i64> for ZatBalance {
    type Error = ();

    fn try_from(value: i64) -> Result<Self, ()> {
        ZatBalance::from_i64(value)
    }
}

impl From<ZatBalance> for i64 {
    fn from(amount: ZatBalance) -> i64 {
        amount.0
    }
}

impl From<&ZatBalance> for i64 {
    fn from(amount: &ZatBalance) -> i64 {
        amount.0
    }
}

impl TryFrom<ZatBalance> for u64 {
    type Error = ();

    fn try_from(value: ZatBalance) -> Result<Self, Self::Error> {
        value.0.try_into().map_err(|_| ())
    }
}

impl Add<ZatBalance> for ZatBalance {
    type Output = Option<ZatBalance>;

    fn add(self, rhs: ZatBalance) -> Option<ZatBalance> {
        ZatBalance::from_i64(self.0 + rhs.0).ok()
    }
}

impl Add<ZatBalance> for Option<ZatBalance> {
    type Output = Self;

    fn add(self, rhs: ZatBalance) -> Option<ZatBalance> {
        self.and_then(|lhs| lhs + rhs)
    }
}

impl AddAssign<ZatBalance> for ZatBalance {
    fn add_assign(&mut self, rhs: ZatBalance) {
        *self = (*self + rhs).expect("Addition must produce a valid amount value.")
    }
}

impl Sub<ZatBalance> for ZatBalance {
    type Output = Option<ZatBalance>;

    fn sub(self, rhs: ZatBalance) -> Option<ZatBalance> {
        ZatBalance::from_i64(self.0 - rhs.0).ok()
    }
}

impl Sub<ZatBalance> for Option<ZatBalance> {
    type Output = Self;

    fn sub(self, rhs: ZatBalance) -> Option<ZatBalance> {
        self.and_then(|lhs| lhs - rhs)
    }
}

impl SubAssign<ZatBalance> for ZatBalance {
    fn sub_assign(&mut self, rhs: ZatBalance) {
        *self = (*self - rhs).expect("Subtraction must produce a valid amount value.")
    }
}

impl Sum<ZatBalance> for Option<ZatBalance> {
    fn sum<I: Iterator<Item = ZatBalance>>(iter: I) -> Self {
        iter.fold(Some(ZatBalance::zero()), |acc, a| acc? + a)
    }
}

impl<'a> Sum<&'a ZatBalance> for Option<ZatBalance> {
    fn sum<I: Iterator<Item = &'a ZatBalance>>(iter: I) -> Self {
        iter.fold(Some(ZatBalance::zero()), |acc, a| acc? + *a)
    }
}

impl Neg for ZatBalance {
    type Output = Self;

    fn neg(self) -> Self {
        ZatBalance(-self.0)
    }
}

impl Mul<usize> for ZatBalance {
    type Output = Option<ZatBalance>;

    fn mul(self, rhs: usize) -> Option<ZatBalance> {
        let rhs: i64 = rhs.try_into().ok()?;
        self.0
            .checked_mul(rhs)
            .and_then(|i| ZatBalance::try_from(i).ok())
    }
}

/// A type-safe representation of some nonnegative amount of Zcash.
///
/// A Zatoshis can only be constructed from an integer that is within the valid monetary
/// range of `{0..MAX_MONEY}` (where `MAX_MONEY` = 21,000,000 × 10⁸ zatoshis).
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct Zatoshis(u64);

impl Zatoshis {
    /// Returns the identity `Zatoshis`
    pub const ZERO: Self = Zatoshis(0);

    /// Returns this Zatoshis as a u64.
    pub fn into_u64(self) -> u64 {
        self.0
    }

    /// Creates a Zatoshis from a u64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_u64(amount: u64) -> Result<Self, ()> {
        if (0..=MAX_MONEY).contains(&amount) {
            Ok(Zatoshis(amount))
        } else {
            Err(())
        }
    }

    /// Creates a constant Zatoshis from a u64.
    ///
    /// Panics: if the amount is outside the range `{0..MAX_MONEY}`.
    pub const fn const_from_u64(amount: u64) -> Self {
        assert!(amount <= MAX_MONEY); // contains is not const
        Zatoshis(amount)
    }

    /// Creates a Zatoshis from an i64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_nonnegative_i64(amount: i64) -> Result<Self, ()> {
        u64::try_from(amount).map(Zatoshis).map_err(|_| ())
    }

    /// Reads an Zatoshis from an unsigned 64-bit little-endian integer.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_u64_le_bytes(bytes: [u8; 8]) -> Result<Self, ()> {
        let amount = u64::from_le_bytes(bytes);
        Self::from_u64(amount)
    }

    /// Reads a Zatoshis from a signed integer represented as a two's
    /// complement 64-bit little-endian value.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_nonnegative_i64_le_bytes(bytes: [u8; 8]) -> Result<Self, ()> {
        let amount = i64::from_le_bytes(bytes);
        Self::from_nonnegative_i64(amount)
    }

    /// Returns this Zatoshis encoded as a signed two's complement 64-bit
    /// little-endian value.
    pub fn to_i64_le_bytes(self) -> [u8; 8] {
        (self.0 as i64).to_le_bytes()
    }

    /// Returns whether or not this `Zatoshis` is the zero value.
    pub fn is_zero(&self) -> bool {
        self == &Zatoshis::ZERO
    }

    /// Returns whether or not this `Zatoshis` is positive.
    pub fn is_positive(&self) -> bool {
        self > &Zatoshis::ZERO
    }
}

impl From<Zatoshis> for ZatBalance {
    fn from(n: Zatoshis) -> Self {
        ZatBalance(n.0 as i64)
    }
}

impl From<&Zatoshis> for ZatBalance {
    fn from(n: &Zatoshis) -> Self {
        ZatBalance(n.0 as i64)
    }
}

impl From<Zatoshis> for u64 {
    fn from(n: Zatoshis) -> Self {
        n.into_u64()
    }
}

impl TryFrom<u64> for Zatoshis {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Zatoshis::from_u64(value)
    }
}

impl TryFrom<ZatBalance> for Zatoshis {
    type Error = ();

    fn try_from(value: ZatBalance) -> Result<Self, Self::Error> {
        Zatoshis::from_nonnegative_i64(value.0)
    }
}

impl Add<Zatoshis> for Zatoshis {
    type Output = Option<Zatoshis>;

    fn add(self, rhs: Zatoshis) -> Option<Zatoshis> {
        Self::from_u64(self.0.checked_add(rhs.0)?).ok()
    }
}

impl Add<Zatoshis> for Option<Zatoshis> {
    type Output = Self;

    fn add(self, rhs: Zatoshis) -> Option<Zatoshis> {
        self.and_then(|lhs| lhs + rhs)
    }
}

impl Sub<Zatoshis> for Zatoshis {
    type Output = Option<Zatoshis>;

    fn sub(self, rhs: Zatoshis) -> Option<Zatoshis> {
        Zatoshis::from_u64(self.0.checked_sub(rhs.0)?).ok()
    }
}

impl Sub<Zatoshis> for Option<Zatoshis> {
    type Output = Self;

    fn sub(self, rhs: Zatoshis) -> Option<Zatoshis> {
        self.and_then(|lhs| lhs - rhs)
    }
}

impl Mul<usize> for Zatoshis {
    type Output = Option<Self>;

    fn mul(self, rhs: usize) -> Option<Zatoshis> {
        Zatoshis::from_u64(self.0.checked_mul(u64::try_from(rhs).ok()?)?).ok()
    }
}

impl Sum<Zatoshis> for Option<Zatoshis> {
    fn sum<I: Iterator<Item = Zatoshis>>(iter: I) -> Self {
        iter.fold(Some(Zatoshis::ZERO), |acc, a| acc? + a)
    }
}

impl<'a> Sum<&'a Zatoshis> for Option<Zatoshis> {
    fn sum<I: Iterator<Item = &'a Zatoshis>>(iter: I) -> Self {
        iter.fold(Some(Zatoshis::ZERO), |acc, a| acc? + *a)
    }
}

/// A type for balance violations in amount addition and subtraction
/// (overflow and underflow of allowed ranges)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BalanceError {
    Overflow,
    Underflow,
}

impl error::Error for BalanceError {}

impl std::fmt::Display for BalanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            BalanceError::Overflow => {
                write!(
                    f,
                    "ZatBalance addition resulted in a value outside the valid range."
                )
            }
            BalanceError::Underflow => write!(
                f,
                "ZatBalance subtraction resulted in a value outside the valid range."
            ),
        }
    }
}

impl From<Infallible> for BalanceError {
    fn from(_value: Infallible) -> Self {
        unreachable!()
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::prop_compose;

    use super::{ZatBalance, Zatoshis, MAX_BALANCE, MAX_MONEY};

    prop_compose! {
        pub fn arb_zat_balance()(amt in -MAX_BALANCE..MAX_BALANCE) -> ZatBalance {
            ZatBalance::from_i64(amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_positive_zat_balance()(amt in 1i64..MAX_BALANCE) -> ZatBalance {
            ZatBalance::from_i64(amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_zatoshis()(amt in 0u64..MAX_MONEY) -> Zatoshis {
            Zatoshis::from_u64(amt).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::value::MAX_BALANCE;

    use super::ZatBalance;

    #[test]
    fn amount_in_range() {
        let zero = b"\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(ZatBalance::from_u64_le_bytes(*zero).unwrap(), ZatBalance(0));
        assert_eq!(
            ZatBalance::from_nonnegative_i64_le_bytes(*zero).unwrap(),
            ZatBalance(0)
        );
        assert_eq!(ZatBalance::from_i64_le_bytes(*zero).unwrap(), ZatBalance(0));

        let neg_one = b"\xff\xff\xff\xff\xff\xff\xff\xff";
        assert!(ZatBalance::from_u64_le_bytes(*neg_one).is_err());
        assert!(ZatBalance::from_nonnegative_i64_le_bytes(*neg_one).is_err());
        assert_eq!(
            ZatBalance::from_i64_le_bytes(*neg_one).unwrap(),
            ZatBalance(-1)
        );

        let max_money = b"\x00\x40\x07\x5a\xf0\x75\x07\x00";
        assert_eq!(
            ZatBalance::from_u64_le_bytes(*max_money).unwrap(),
            ZatBalance(MAX_BALANCE)
        );
        assert_eq!(
            ZatBalance::from_nonnegative_i64_le_bytes(*max_money).unwrap(),
            ZatBalance(MAX_BALANCE)
        );
        assert_eq!(
            ZatBalance::from_i64_le_bytes(*max_money).unwrap(),
            ZatBalance(MAX_BALANCE)
        );

        let max_money_p1 = b"\x01\x40\x07\x5a\xf0\x75\x07\x00";
        assert!(ZatBalance::from_u64_le_bytes(*max_money_p1).is_err());
        assert!(ZatBalance::from_nonnegative_i64_le_bytes(*max_money_p1).is_err());
        assert!(ZatBalance::from_i64_le_bytes(*max_money_p1).is_err());

        let neg_max_money = b"\x00\xc0\xf8\xa5\x0f\x8a\xf8\xff";
        assert!(ZatBalance::from_u64_le_bytes(*neg_max_money).is_err());
        assert!(ZatBalance::from_nonnegative_i64_le_bytes(*neg_max_money).is_err());
        assert_eq!(
            ZatBalance::from_i64_le_bytes(*neg_max_money).unwrap(),
            ZatBalance(-MAX_BALANCE)
        );

        let neg_max_money_m1 = b"\xff\xbf\xf8\xa5\x0f\x8a\xf8\xff";
        assert!(ZatBalance::from_u64_le_bytes(*neg_max_money_m1).is_err());
        assert!(ZatBalance::from_nonnegative_i64_le_bytes(*neg_max_money_m1).is_err());
        assert!(ZatBalance::from_i64_le_bytes(*neg_max_money_m1).is_err());
    }

    #[test]
    fn add_overflow() {
        let v = ZatBalance(MAX_BALANCE);
        assert_eq!(v + ZatBalance(1), None)
    }

    #[test]
    #[should_panic]
    fn add_assign_panics_on_overflow() {
        let mut a = ZatBalance(MAX_BALANCE);
        a += ZatBalance(1);
    }

    #[test]
    fn sub_underflow() {
        let v = ZatBalance(-MAX_BALANCE);
        assert_eq!(v - ZatBalance(1), None)
    }

    #[test]
    #[should_panic]
    fn sub_assign_panics_on_underflow() {
        let mut a = ZatBalance(-MAX_BALANCE);
        a -= ZatBalance(1);
    }
}
