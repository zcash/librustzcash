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
