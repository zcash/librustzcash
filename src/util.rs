/// Compute a + b + carry, returning the result and the new carry over.
#[inline(always)]
pub fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = u128::from(a) + u128::from(b) + u128::from(carry);
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a - (b + borrow), returning the result and the new borrow.
#[inline(always)]
pub fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = u128::from(a).wrapping_sub(u128::from(b) + u128::from(borrow >> 63));
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a + (b * c) + carry, returning the result and the new carry over.
#[inline(always)]
pub fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = u128::from(a) + (u128::from(b) * u128::from(c)) + u128::from(carry);
    (ret as u64, (ret >> 64) as u64)
}

macro_rules! impl_binops_additive {
    ($lhs:ident, $rhs:ident) => {
        impl<'b> Sub<&'b $rhs> for $lhs {
            type Output = $lhs;

            #[inline]
            fn sub(self, rhs: &'b $rhs) -> $lhs {
                &self - rhs
            }
        }

        impl<'b> Add<&'b $rhs> for $lhs {
            type Output = $lhs;

            #[inline]
            fn add(self, rhs: &'b $rhs) -> $lhs {
                &self + rhs
            }
        }

        impl<'a> Sub<$rhs> for &'a $lhs {
            type Output = $lhs;

            #[inline]
            fn sub(self, rhs: $rhs) -> $lhs {
                self - &rhs
            }
        }

        impl<'a> Add<$rhs> for &'a $lhs {
            type Output = $lhs;

            #[inline]
            fn add(self, rhs: $rhs) -> $lhs {
                self + &rhs
            }
        }

        impl Sub<$rhs> for $lhs {
            type Output = $lhs;

            #[inline]
            fn sub(self, rhs: $rhs) -> $lhs {
                &self - &rhs
            }
        }

        impl Add<$rhs> for $lhs {
            type Output = $lhs;

            #[inline]
            fn add(self, rhs: $rhs) -> $lhs {
                &self + &rhs
            }
        }

        impl SubAssign<$rhs> for $lhs {
            #[inline]
            fn sub_assign(&mut self, rhs: $rhs) {
                *self = &*self - &rhs;
            }
        }

        impl AddAssign<$rhs> for $lhs {
            #[inline]
            fn add_assign(&mut self, rhs: $rhs) {
                *self = &*self + &rhs;
            }
        }

        impl<'b> SubAssign<&'b $rhs> for $lhs {
            #[inline]
            fn sub_assign(&mut self, rhs: &'b $rhs) {
                *self = &*self - rhs;
            }
        }

        impl<'b> AddAssign<&'b $rhs> for $lhs {
            #[inline]
            fn add_assign(&mut self, rhs: &'b $rhs) {
                *self = &*self + rhs;
            }
        }
    };
}

macro_rules! impl_binops_multiplicative {
    ($lhs:ident, $rhs:ident) => {
        impl<'b> Mul<&'b $rhs> for $lhs {
            type Output = $lhs;

            #[inline]
            fn mul(self, rhs: &'b $rhs) -> $lhs {
                &self * rhs
            }
        }

        impl<'a> Mul<$rhs> for &'a $lhs {
            type Output = $lhs;

            #[inline]
            fn mul(self, rhs: $rhs) -> $lhs {
                self * &rhs
            }
        }

        impl Mul<$rhs> for $lhs {
            type Output = $lhs;

            #[inline]
            fn mul(self, rhs: $rhs) -> $lhs {
                &self * &rhs
            }
        }

        impl MulAssign<$rhs> for $lhs {
            #[inline]
            fn mul_assign(&mut self, rhs: $rhs) {
                *self = &*self * &rhs;
            }
        }

        impl<'b> MulAssign<&'b $rhs> for $lhs {
            #[inline]
            fn mul_assign(&mut self, rhs: &'b $rhs) {
                *self = &*self * rhs;
            }
        }
    };
}
