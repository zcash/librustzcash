//! This module provides a "CtOption" abstraction as a constant-time
//! alternative for APIs that want to return optional values.
//! Ideally, this would be merged into upstream `subtle` at some
//! point.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The `CtOption<T>` type represents an optional value similar to the
/// [`Option<T>`](core::option::Option) type but is intended for
/// use in constant time APIs. Any given `CtOption<T>` is either
/// `Some` or `None`, but unlike `Option<T>` these variants are
/// not exposed. The `is_some()` method is used to determine if the
/// value is `Some`, and `unwrap_or`/`unwrap_or_else` methods are
/// provided to access the underlying value. The value can also be
/// obtained with `unwrap()` but this will panic if it is None.
///
/// Functions that are intended to be constant time may not produce
/// valid results for all inputs, such as square root and inversion
/// operations in finite field arithmetic. Returning an `Option<T>`
/// from these functions makes it difficult for the caller to reason
/// about the result in constant time, and returning an incorrect
/// value burdens the caller and increases the chance of bugs.
#[derive(Clone, Copy, Debug)]
pub struct CtOption<T> {
    value: T,
    is_some: Choice,
}

impl<T> CtOption<T> {
    /// This method is used to construct a new `CtOption<T>` and takes
    /// a value of type `T`, and a `Choice` that determines whether
    /// the optional value should be `Some` or not. If `is_some` is
    /// false, the value will still be stored but its value is never
    /// exposed.
    #[inline]
    pub fn new(value: T, is_some: Choice) -> CtOption<T> {
        CtOption { value, is_some }
    }

    /// This returns the underlying value but panics if it
    /// is not `Some`.
    #[inline]
    pub fn unwrap(self) -> T {
        assert_eq!(self.is_some.unwrap_u8(), 1);

        self.value
    }

    /// This returns the underlying value if it is `Some`
    /// or the provided value otherwise.
    #[inline]
    pub fn unwrap_or(self, def: T) -> T
    where
        T: ConditionallySelectable,
    {
        T::conditional_select(&def, &self.value, self.is_some)
    }

    /// This returns the underlying value if it is `Some`
    /// or the value produced by the provided closure otherwise.
    #[inline]
    pub fn unwrap_or_else<F>(self, f: F) -> T
    where
        T: ConditionallySelectable,
        F: FnOnce() -> T,
    {
        T::conditional_select(&f(), &self.value, self.is_some)
    }

    /// Returns a true `Choice` if this value is `Some`.
    #[inline]
    pub fn is_some(&self) -> Choice {
        self.is_some
    }

    /// Returns a true `Choice` if this value is `None`.
    #[inline]
    pub fn is_none(&self) -> Choice {
        !self.is_some
    }

    /// Returns a `None` value if the option is `None`, otherwise
    /// returns a `CtOption` enclosing the value of the provided closure.
    /// The closure is given the enclosed value or, if the option is
    /// `None`, it is provided a dummy value computed using
    /// `Default::default()`.
    ///
    /// This operates in constant time, because the provided closure
    /// is always called.
    #[inline]
    pub fn map<U, F>(self, f: F) -> CtOption<U>
    where
        T: Default + ConditionallySelectable,
        F: FnOnce(T) -> U,
    {
        CtOption::new(
            f(T::conditional_select(
                &T::default(),
                &self.value,
                self.is_some,
            )),
            self.is_some,
        )
    }

    /// Returns a `None` value if the option is `None`, otherwise
    /// returns the result of the provided closure. The closure is
    /// given the enclosed value or, if the option is `None`, it
    /// is provided a dummy value computed using `Default::default()`.
    ///
    /// This operates in constant time, because the provided closure
    /// is always called.
    #[inline]
    pub fn and_then<U, F>(self, f: F) -> CtOption<U>
    where
        T: Default + ConditionallySelectable,
        F: FnOnce(T) -> CtOption<U>,
    {
        let mut tmp = f(T::conditional_select(
            &T::default(),
            &self.value,
            self.is_some,
        ));
        tmp.is_some &= self.is_some;

        tmp
    }
}

impl<T: ConditionallySelectable> ConditionallySelectable for CtOption<T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        CtOption::new(
            T::conditional_select(&a.value, &b.value, choice),
            // TODO: subtle crate currently doesn't implement ConditionallySelectable
            // for Choice so we must unwrap these manually.
            Choice::from(u8::conditional_select(
                &a.is_some.unwrap_u8(),
                &b.is_some.unwrap_u8(),
                choice,
            )),
        )
    }
}

impl<T: ConstantTimeEq> ConstantTimeEq for CtOption<T> {
    /// Two `CtOption<T>`s are equal if they are both `Some` and
    /// their values are equal, or both `None`.
    #[inline]
    fn ct_eq(&self, rhs: &CtOption<T>) -> Choice {
        let a = self.is_some();
        let b = rhs.is_some();

        (a & b & self.value.ct_eq(&rhs.value)) | (!a & !b)
    }
}

#[test]
fn test_ctoption() {
    let a = CtOption::new(10, Choice::from(1));
    let b = CtOption::new(9, Choice::from(1));
    let c = CtOption::new(10, Choice::from(0));
    let d = CtOption::new(9, Choice::from(0));

    // Test is_some / is_none
    assert!(bool::from(a.is_some()));
    assert!(bool::from(!a.is_none()));
    assert!(bool::from(b.is_some()));
    assert!(bool::from(!b.is_none()));
    assert!(bool::from(!c.is_some()));
    assert!(bool::from(c.is_none()));
    assert!(bool::from(!d.is_some()));
    assert!(bool::from(d.is_none()));

    // Test unwrap for Some
    assert_eq!(a.unwrap(), 10);
    assert_eq!(b.unwrap(), 9);

    // Test equality
    assert!(bool::from(a.ct_eq(&a)));
    assert!(bool::from(!a.ct_eq(&b)));
    assert!(bool::from(!a.ct_eq(&c)));
    assert!(bool::from(!a.ct_eq(&d)));

    // Test equality of None with different
    // dummy value
    assert!(bool::from(c.ct_eq(&d)));

    // Test unwrap_or
    assert_eq!(CtOption::new(1, Choice::from(1)).unwrap_or(2), 1);
    assert_eq!(CtOption::new(1, Choice::from(0)).unwrap_or(2), 2);

    // Test unwrap_or_else
    assert_eq!(CtOption::new(1, Choice::from(1)).unwrap_or_else(|| 2), 1);
    assert_eq!(CtOption::new(1, Choice::from(0)).unwrap_or_else(|| 2), 2);

    // Test map
    assert_eq!(
        CtOption::new(1, Choice::from(1))
            .map(|v| {
                assert_eq!(v, 1);
                2
            })
            .unwrap(),
        2
    );
    assert_eq!(
        CtOption::new(1, Choice::from(0))
            .map(|_| 2)
            .is_none()
            .unwrap_u8(),
        1
    );

    // Test and_then
    assert_eq!(
        CtOption::new(1, Choice::from(1))
            .and_then(|v| {
                assert_eq!(v, 1);
                CtOption::new(2, Choice::from(0))
            })
            .is_none()
            .unwrap_u8(),
        1
    );
    assert_eq!(
        CtOption::new(1, Choice::from(1))
            .and_then(|v| {
                assert_eq!(v, 1);
                CtOption::new(2, Choice::from(1))
            })
            .unwrap(),
        2
    );

    assert_eq!(
        CtOption::new(1, Choice::from(0))
            .and_then(|_| CtOption::new(2, Choice::from(0)))
            .is_none()
            .unwrap_u8(),
        1
    );
    assert_eq!(
        CtOption::new(1, Choice::from(0))
            .and_then(|_| CtOption::new(2, Choice::from(1)))
            .is_none()
            .unwrap_u8(),
        1
    );
}

#[test]
#[should_panic]
fn unwrap_none_ctoption() {
    // This test might fail (in release mode?) if the
    // compiler decides to optimize it away.
    CtOption::new(10, Choice::from(0)).unwrap();
}
