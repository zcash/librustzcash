macro_rules! curve_impl {
    (
        $name:expr,
        $projective:ident,
        $affine:ident,
        $prepared:ident,
        $basefield:ident,
        $scalarfield:ident,
        $uncompressed:ident,
        $compressed:ident,
        $pairing:ident
    ) => {
        #[derive(Copy, Clone, PartialEq, Eq, Debug)]
        pub struct $affine {
            pub(crate) x: $basefield,
            pub(crate) y: $basefield,
            pub(crate) infinity: bool,
        }

        impl ::std::fmt::Display for $affine {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                if self.infinity {
                    write!(f, "{}(Infinity)", $name)
                } else {
                    write!(f, "{}(x={}, y={})", $name, self.x, self.y)
                }
            }
        }

        #[derive(Copy, Clone, Debug, Eq)]
        pub struct $projective {
            pub(crate) x: $basefield,
            pub(crate) y: $basefield,
            pub(crate) z: $basefield,
        }

        impl ::std::fmt::Display for $projective {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", self.into_affine())
            }
        }

        impl PartialEq for $projective {
            fn eq(&self, other: &$projective) -> bool {
                if self.is_zero() {
                    return other.is_zero();
                }

                if other.is_zero() {
                    return false;
                }

                // The points (X, Y, Z) and (X', Y', Z')
                // are equal when (X * Z^2) = (X' * Z'^2)
                // and (Y * Z^3) = (Y' * Z'^3).

                let mut z1 = self.z.square();
                let mut z2 = other.z.square();

                let mut tmp1 = self.x;
                tmp1.mul_assign(&z2);

                let mut tmp2 = other.x;
                tmp2.mul_assign(&z1);

                if tmp1 != tmp2 {
                    return false;
                }

                z1.mul_assign(&self.z);
                z2.mul_assign(&other.z);
                z2.mul_assign(&self.y);
                z1.mul_assign(&other.y);

                if z1 != z2 {
                    return false;
                }

                true
            }
        }

        impl $affine {
            fn mul_bits_u64<S: AsRef<[u64]>>(&self, bits: BitIterator<u64, S>) -> $projective {
                let mut res = $projective::zero();
                for i in bits {
                    res.double();
                    if i {
                        res.add_assign(self)
                    }
                }
                res
            }

            fn mul_bits_u8<S: AsRef<[u8]>>(&self, bits: BitIterator<u8, S>) -> $projective {
                let mut res = $projective::zero();
                for i in bits {
                    res.double();
                    if i {
                        res.add_assign(self)
                    }
                }
                res
            }

            /// Attempts to construct an affine point given an x-coordinate. The
            /// point is not guaranteed to be in the prime order subgroup.
            ///
            /// If and only if `greatest` is set will the lexicographically
            /// largest y-coordinate be selected.
            fn get_point_from_x(x: $basefield, greatest: bool) -> CtOption<$affine> {
                // Compute x^3 + b
                let mut x3b = x.square();
                x3b.mul_assign(&x);
                x3b.add_assign(&$affine::get_coeff_b());

                x3b.sqrt().map(|y| {
                    let negy = y.neg();

                    $affine {
                        x: x,
                        y: if (y < negy) ^ greatest { y } else { negy },
                        infinity: false,
                    }
                })
            }

            fn is_on_curve(&self) -> bool {
                if self.is_zero() {
                    true
                } else {
                    // Check that the point is on the curve
                    let y2 = self.y.square();

                    let mut x3b = self.x.square();
                    x3b.mul_assign(&self.x);
                    x3b.add_assign(&Self::get_coeff_b());

                    y2 == x3b
                }
            }

            fn is_in_correct_subgroup_assuming_on_curve(&self) -> bool {
                self.mul($scalarfield::char()).is_zero()
            }
        }

        impl ::std::ops::Neg for $affine {
            type Output = Self;

            #[inline]
            fn neg(self) -> Self {
                let mut ret = self;
                if !ret.is_zero() {
                    ret.y = ret.y.neg();
                }
                ret
            }
        }

        impl CurveAffine for $affine {
            type Engine = Bls12;
            type Scalar = $scalarfield;
            type Base = $basefield;
            type Projective = $projective;
            type Uncompressed = $uncompressed;
            type Compressed = $compressed;

            fn zero() -> Self {
                $affine {
                    x: $basefield::zero(),
                    y: $basefield::one(),
                    infinity: true,
                }
            }

            fn one() -> Self {
                Self::get_generator()
            }

            fn is_zero(&self) -> bool {
                self.infinity
            }

            fn mul<S: Into<<Self::Scalar as PrimeField>::Repr>>(&self, by: S) -> $projective {
                let bits = BitIterator::<u8, _>::new(by.into());
                self.mul_bits_u8(bits)
            }

            fn into_projective(&self) -> $projective {
                (*self).into()
            }
        }

        impl PairingCurveAffine for $affine {
            type Prepared = $prepared;
            type Pair = $pairing;
            type PairingResult = Fq12;

            fn prepare(&self) -> Self::Prepared {
                $prepared::from_affine(*self)
            }

            fn pairing_with(&self, other: &Self::Pair) -> Self::PairingResult {
                self.perform_pairing(other)
            }
        }

        impl ::std::ops::Neg for $projective {
            type Output = Self;

            #[inline]
            fn neg(self) -> Self {
                let mut ret = self;
                if !ret.is_zero() {
                    ret.y = ret.y.neg();
                }
                ret
            }
        }

        impl<'r> ::std::ops::Add<&'r $projective> for $projective {
            type Output = Self;

            #[inline]
            fn add(self, other: &Self) -> Self {
                let mut ret = self;
                ret.add_assign(other);
                ret
            }
        }

        impl ::std::ops::Add for $projective {
            type Output = Self;

            #[inline]
            fn add(self, other: Self) -> Self {
                self + &other
            }
        }

        impl<'r> ::std::ops::AddAssign<&'r $projective> for $projective {
            fn add_assign(&mut self, other: &Self) {
                if self.is_zero() {
                    *self = *other;
                    return;
                }

                if other.is_zero() {
                    return;
                }

                // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl

                // Z1Z1 = Z1^2
                let z1z1 = self.z.square();

                // Z2Z2 = Z2^2
                let z2z2 = other.z.square();

                // U1 = X1*Z2Z2
                let mut u1 = self.x;
                u1.mul_assign(&z2z2);

                // U2 = X2*Z1Z1
                let mut u2 = other.x;
                u2.mul_assign(&z1z1);

                // S1 = Y1*Z2*Z2Z2
                let mut s1 = self.y;
                s1.mul_assign(&other.z);
                s1.mul_assign(&z2z2);

                // S2 = Y2*Z1*Z1Z1
                let mut s2 = other.y;
                s2.mul_assign(&self.z);
                s2.mul_assign(&z1z1);

                if u1 == u2 && s1 == s2 {
                    // The two points are equal, so we double.
                    self.double();
                } else {
                    // If we're adding -a and a together, self.z becomes zero as H becomes zero.

                    // H = U2-U1
                    let mut h = u2;
                    h.sub_assign(&u1);

                    // I = (2*H)^2
                    let i = h.double().square();

                    // J = H*I
                    let mut j = h;
                    j.mul_assign(&i);

                    // r = 2*(S2-S1)
                    let mut r = s2;
                    r.sub_assign(&s1);
                    r = r.double();

                    // V = U1*I
                    let mut v = u1;
                    v.mul_assign(&i);

                    // X3 = r^2 - J - 2*V
                    self.x = r.square();
                    self.x.sub_assign(&j);
                    self.x.sub_assign(&v);
                    self.x.sub_assign(&v);

                    // Y3 = r*(V - X3) - 2*S1*J
                    self.y = v;
                    self.y.sub_assign(&self.x);
                    self.y.mul_assign(&r);
                    s1.mul_assign(&j); // S1 = S1 * J * 2
                    s1 = s1.double();
                    self.y.sub_assign(&s1);

                    // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2)*H
                    self.z.add_assign(&other.z);
                    self.z = self.z.square();
                    self.z.sub_assign(&z1z1);
                    self.z.sub_assign(&z2z2);
                    self.z.mul_assign(&h);
                }
            }
        }

        impl ::std::ops::AddAssign for $projective {
            #[inline]
            fn add_assign(&mut self, other: Self) {
                self.add_assign(&other);
            }
        }

        impl<'r> ::std::ops::Sub<&'r $projective> for $projective {
            type Output = Self;

            #[inline]
            fn sub(self, other: &Self) -> Self {
                let mut ret = self;
                ret.sub_assign(other);
                ret
            }
        }

        impl ::std::ops::Sub for $projective {
            type Output = Self;

            #[inline]
            fn sub(self, other: Self) -> Self {
                self - &other
            }
        }

        impl<'r> ::std::ops::SubAssign<&'r $projective> for $projective {
            fn sub_assign(&mut self, other: &Self) {
                self.add_assign(&other.neg());
            }
        }

        impl ::std::ops::SubAssign for $projective {
            #[inline]
            fn sub_assign(&mut self, other: Self) {
                self.sub_assign(&other);
            }
        }

        impl<'r> ::std::ops::Add<&'r <$projective as CurveProjective>::Affine> for $projective {
            type Output = Self;

            #[inline]
            fn add(self, other: &<$projective as CurveProjective>::Affine) -> Self {
                let mut ret = self;
                ret.add_assign(other);
                ret
            }
        }

        impl ::std::ops::Add<<$projective as CurveProjective>::Affine> for $projective {
            type Output = Self;

            #[inline]
            fn add(self, other: <$projective as CurveProjective>::Affine) -> Self {
                self + &other
            }
        }

        impl<'r> ::std::ops::AddAssign<&'r <$projective as CurveProjective>::Affine>
            for $projective
        {
            fn add_assign(&mut self, other: &<$projective as CurveProjective>::Affine) {
                if other.is_zero() {
                    return;
                }

                if self.is_zero() {
                    self.x = other.x;
                    self.y = other.y;
                    self.z = $basefield::one();
                    return;
                }

                // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl

                // Z1Z1 = Z1^2
                let z1z1 = self.z.square();

                // U2 = X2*Z1Z1
                let mut u2 = other.x;
                u2.mul_assign(&z1z1);

                // S2 = Y2*Z1*Z1Z1
                let mut s2 = other.y;
                s2.mul_assign(&self.z);
                s2.mul_assign(&z1z1);

                if self.x == u2 && self.y == s2 {
                    // The two points are equal, so we double.
                    self.double();
                } else {
                    // If we're adding -a and a together, self.z becomes zero as H becomes zero.

                    // H = U2-X1
                    let mut h = u2;
                    h.sub_assign(&self.x);

                    // HH = H^2
                    let hh = h.square();

                    // I = 4*HH
                    let i = hh.double().double();

                    // J = H*I
                    let mut j = h;
                    j.mul_assign(&i);

                    // r = 2*(S2-Y1)
                    let mut r = s2;
                    r.sub_assign(&self.y);
                    r = r.double();

                    // V = X1*I
                    let mut v = self.x;
                    v.mul_assign(&i);

                    // X3 = r^2 - J - 2*V
                    self.x = r.square();
                    self.x.sub_assign(&j);
                    self.x.sub_assign(&v);
                    self.x.sub_assign(&v);

                    // Y3 = r*(V-X3)-2*Y1*J
                    j.mul_assign(&self.y); // J = 2*Y1*J
                    j = j.double();
                    self.y = v;
                    self.y.sub_assign(&self.x);
                    self.y.mul_assign(&r);
                    self.y.sub_assign(&j);

                    // Z3 = (Z1+H)^2-Z1Z1-HH
                    self.z.add_assign(&h);
                    self.z = self.z.square();
                    self.z.sub_assign(&z1z1);
                    self.z.sub_assign(&hh);
                }
            }
        }

        impl ::std::ops::AddAssign<<$projective as CurveProjective>::Affine> for $projective {
            #[inline]
            fn add_assign(&mut self, other: <$projective as CurveProjective>::Affine) {
                self.add_assign(&other);
            }
        }

        impl<'r> ::std::ops::Sub<&'r <$projective as CurveProjective>::Affine> for $projective {
            type Output = Self;

            #[inline]
            fn sub(self, other: &<$projective as CurveProjective>::Affine) -> Self {
                let mut ret = self;
                ret.sub_assign(other);
                ret
            }
        }

        impl ::std::ops::Sub<<$projective as CurveProjective>::Affine> for $projective {
            type Output = Self;

            #[inline]
            fn sub(self, other: <$projective as CurveProjective>::Affine) -> Self {
                self - &other
            }
        }

        impl<'r> ::std::ops::SubAssign<&'r <$projective as CurveProjective>::Affine>
            for $projective
        {
            fn sub_assign(&mut self, other: &<$projective as CurveProjective>::Affine) {
                self.add_assign(&other.neg());
            }
        }

        impl ::std::ops::SubAssign<<$projective as CurveProjective>::Affine> for $projective {
            #[inline]
            fn sub_assign(&mut self, other: <$projective as CurveProjective>::Affine) {
                self.sub_assign(&other);
            }
        }

        impl CurveProjective for $projective {
            type Engine = Bls12;
            type Scalar = $scalarfield;
            type Base = $basefield;
            type Affine = $affine;

            fn random<R: RngCore + ?std::marker::Sized>(rng: &mut R) -> Self {
                loop {
                    let x = $basefield::random(rng);
                    let greatest = rng.next_u32() % 2 != 0;

                    let p = $affine::get_point_from_x(x, greatest);
                    if p.is_some().into() {
                        let p = p.unwrap().scale_by_cofactor();

                        if !p.is_zero() {
                            return p;
                        }
                    }
                }
            }

            // The point at infinity is always represented by
            // Z = 0.
            fn zero() -> Self {
                $projective {
                    x: $basefield::zero(),
                    y: $basefield::one(),
                    z: $basefield::zero(),
                }
            }

            fn one() -> Self {
                $affine::one().into()
            }

            // The point at infinity is always represented by
            // Z = 0.
            fn is_zero(&self) -> bool {
                self.z.is_zero()
            }

            fn is_normalized(&self) -> bool {
                self.is_zero() || self.z == $basefield::one()
            }

            fn batch_normalization(v: &mut [Self]) {
                // Montgomery’s Trick and Fast Implementation of Masked AES
                // Genelle, Prouff and Quisquater
                // Section 3.2

                // First pass: compute [a, ab, abc, ...]
                let mut prod = Vec::with_capacity(v.len());
                let mut tmp = $basefield::one();
                for g in v
                    .iter_mut()
                    // Ignore normalized elements
                    .filter(|g| !g.is_normalized())
                {
                    tmp.mul_assign(&g.z);
                    prod.push(tmp);
                }

                // Invert `tmp`.
                tmp = tmp.invert().unwrap(); // Guaranteed to be nonzero.

                // Second pass: iterate backwards to compute inverses
                for (g, s) in v
                    .iter_mut()
                    // Backwards
                    .rev()
                    // Ignore normalized elements
                    .filter(|g| !g.is_normalized())
                    // Backwards, skip last element, fill in one for last term.
                    .zip(
                        prod.into_iter()
                            .rev()
                            .skip(1)
                            .chain(Some($basefield::one())),
                    )
                {
                    // tmp := tmp * g.z; g.z := tmp * s = 1/z
                    let mut newtmp = tmp;
                    newtmp.mul_assign(&g.z);
                    g.z = tmp;
                    g.z.mul_assign(&s);
                    tmp = newtmp;
                }

                // Perform affine transformations
                for g in v.iter_mut().filter(|g| !g.is_normalized()) {
                    let mut z = g.z.square(); // 1/z^2
                    g.x.mul_assign(&z); // x/z^2
                    z.mul_assign(&g.z); // 1/z^3
                    g.y.mul_assign(&z); // y/z^3
                    g.z = $basefield::one(); // z = 1
                }
            }

            fn double(&mut self) {
                if self.is_zero() {
                    return;
                }

                // Other than the point at infinity, no points on E or E'
                // can double to equal the point at infinity, as y=0 is
                // never true for points on the curve. (-4 and -4u-4
                // are not cubic residue in their respective fields.)

                // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

                // A = X1^2
                let a = self.x.square();

                // B = Y1^2
                let b = self.y.square();

                // C = B^2
                let mut c = b.square();

                // D = 2*((X1+B)2-A-C)
                let mut d = self.x;
                d.add_assign(&b);
                d = d.square();
                d.sub_assign(&a);
                d.sub_assign(&c);
                d = d.double();

                // E = 3*A
                let mut e = a.double();
                e.add_assign(&a);

                // F = E^2
                let f = e.square();

                // Z3 = 2*Y1*Z1
                self.z.mul_assign(&self.y);
                self.z = self.z.double();

                // X3 = F-2*D
                self.x = f;
                self.x.sub_assign(&d);
                self.x.sub_assign(&d);

                // Y3 = E*(D-X3)-8*C
                self.y = d;
                self.y.sub_assign(&self.x);
                self.y.mul_assign(&e);
                c = c.double().double().double();
                self.y.sub_assign(&c);
            }

            fn mul_assign<S: Into<<Self::Scalar as PrimeField>::Repr>>(&mut self, other: S) {
                let mut res = Self::zero();

                let mut found_one = false;

                for i in BitIterator::<u8, _>::new(other.into()) {
                    if found_one {
                        res.double();
                    } else {
                        found_one = i;
                    }

                    if i {
                        res.add_assign(&*self);
                    }
                }

                *self = res;
            }

            fn into_affine(&self) -> $affine {
                (*self).into()
            }

            fn recommended_wnaf_for_scalar(_: &Self::Scalar) -> usize {
                Self::empirical_recommended_wnaf_for_scalar(
                    <Self::Scalar as PrimeField>::NUM_BITS as usize,
                )
            }

            fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
                Self::empirical_recommended_wnaf_for_num_scalars(num_scalars)
            }
        }

        // The affine point X, Y is represented in the jacobian
        // coordinates with Z = 1.
        impl From<$affine> for $projective {
            fn from(p: $affine) -> $projective {
                if p.is_zero() {
                    $projective::zero()
                } else {
                    $projective {
                        x: p.x,
                        y: p.y,
                        z: $basefield::one(),
                    }
                }
            }
        }

        // The projective point X, Y, Z is represented in the affine
        // coordinates as X/Z^2, Y/Z^3.
        impl From<$projective> for $affine {
            fn from(p: $projective) -> $affine {
                if p.is_zero() {
                    $affine::zero()
                } else if p.z == $basefield::one() {
                    // If Z is one, the point is already normalized.
                    $affine {
                        x: p.x,
                        y: p.y,
                        infinity: false,
                    }
                } else {
                    // Z is nonzero, so it must have an inverse in a field.
                    let zinv = p.z.invert().unwrap();
                    let mut zinv_powered = zinv.square();

                    // X/Z^2
                    let mut x = p.x;
                    x.mul_assign(&zinv_powered);

                    // Y/Z^3
                    let mut y = p.y;
                    zinv_powered.mul_assign(&zinv);
                    y.mul_assign(&zinv_powered);

                    $affine {
                        x: x,
                        y: y,
                        infinity: false,
                    }
                }
            }
        }
    };
}

pub mod g1 {
    use super::super::{Bls12, Fq, Fq12, FqRepr, Fr};
    use super::g2::G2Affine;
    use crate::{Engine, PairingCurveAffine};
    use ff::{BitIterator, Field, PrimeField};
    use group::{CurveAffine, CurveProjective, EncodedPoint, GroupDecodingError};
    use rand_core::RngCore;
    use std::fmt;
    use std::ops::{AddAssign, MulAssign, Neg, SubAssign};
    use subtle::CtOption;

    curve_impl!(
        "G1",
        G1,
        G1Affine,
        G1Prepared,
        Fq,
        Fr,
        G1Uncompressed,
        G1Compressed,
        G2Affine
    );

    #[derive(Copy, Clone)]
    pub struct G1Uncompressed([u8; 96]);

    impl AsRef<[u8]> for G1Uncompressed {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl AsMut<[u8]> for G1Uncompressed {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    impl fmt::Debug for G1Uncompressed {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            self.0[..].fmt(formatter)
        }
    }

    impl EncodedPoint for G1Uncompressed {
        type Affine = G1Affine;

        fn empty() -> Self {
            G1Uncompressed([0; 96])
        }
        fn size() -> usize {
            96
        }
        fn into_affine(&self) -> Result<G1Affine, GroupDecodingError> {
            let affine = self.into_affine_unchecked()?;

            if !affine.is_on_curve() {
                Err(GroupDecodingError::NotOnCurve)
            } else if !affine.is_in_correct_subgroup_assuming_on_curve() {
                Err(GroupDecodingError::NotInSubgroup)
            } else {
                Ok(affine)
            }
        }
        fn into_affine_unchecked(&self) -> Result<G1Affine, GroupDecodingError> {
            // Create a copy of this representation.
            let mut copy = self.0;

            if copy[0] & (1 << 7) != 0 {
                // Distinguisher bit is set, but this should be uncompressed!
                return Err(GroupDecodingError::UnexpectedCompressionMode);
            }

            if copy[0] & (1 << 6) != 0 {
                // This is the point at infinity, which means that if we mask away
                // the first two bits, the entire representation should consist
                // of zeroes.
                copy[0] &= 0x3f;

                if copy.iter().all(|b| *b == 0) {
                    Ok(G1Affine::zero())
                } else {
                    Err(GroupDecodingError::UnexpectedInformation)
                }
            } else {
                if copy[0] & (1 << 5) != 0 {
                    // The bit indicating the y-coordinate should be lexicographically
                    // largest is set, but this is an uncompressed element.
                    return Err(GroupDecodingError::UnexpectedInformation);
                }

                // Unset the three most significant bits.
                copy[0] &= 0x1f;

                fn copy_segment(s: &[u8], start: usize) -> [u8; 48] {
                    let mut ret = [0; 48];
                    ret.copy_from_slice(&s[start..start + 48]);
                    ret
                }

                let x = FqRepr(copy_segment(&copy, 0));
                let y = FqRepr(copy_segment(&copy, 48));

                Ok(G1Affine {
                    x: Fq::from_repr(x).ok_or_else(|| {
                        GroupDecodingError::CoordinateDecodingError("x coordinate")
                    })?,
                    y: Fq::from_repr(y).ok_or_else(|| {
                        GroupDecodingError::CoordinateDecodingError("y coordinate")
                    })?,
                    infinity: false,
                })
            }
        }
        fn from_affine(affine: G1Affine) -> Self {
            let mut res = Self::empty();

            if affine.is_zero() {
                // Set the second-most significant bit to indicate this point
                // is at infinity.
                res.0[0] |= 1 << 6;
            } else {
                res.0[..48].copy_from_slice(&affine.x.to_repr().0);
                res.0[48..].copy_from_slice(&affine.y.to_repr().0);
            }

            res
        }
    }

    #[derive(Copy, Clone)]
    pub struct G1Compressed([u8; 48]);

    impl AsRef<[u8]> for G1Compressed {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl AsMut<[u8]> for G1Compressed {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    impl fmt::Debug for G1Compressed {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            self.0[..].fmt(formatter)
        }
    }

    impl EncodedPoint for G1Compressed {
        type Affine = G1Affine;

        fn empty() -> Self {
            G1Compressed([0; 48])
        }
        fn size() -> usize {
            48
        }
        fn into_affine(&self) -> Result<G1Affine, GroupDecodingError> {
            let affine = self.into_affine_unchecked()?;

            // NB: Decompression guarantees that it is on the curve already.

            if !affine.is_in_correct_subgroup_assuming_on_curve() {
                Err(GroupDecodingError::NotInSubgroup)
            } else {
                Ok(affine)
            }
        }
        fn into_affine_unchecked(&self) -> Result<G1Affine, GroupDecodingError> {
            // Create a copy of this representation.
            let mut copy = self.0;

            if copy[0] & (1 << 7) == 0 {
                // Distinguisher bit isn't set.
                return Err(GroupDecodingError::UnexpectedCompressionMode);
            }

            if copy[0] & (1 << 6) != 0 {
                // This is the point at infinity, which means that if we mask away
                // the first two bits, the entire representation should consist
                // of zeroes.
                copy[0] &= 0x3f;

                if copy.iter().all(|b| *b == 0) {
                    Ok(G1Affine::zero())
                } else {
                    Err(GroupDecodingError::UnexpectedInformation)
                }
            } else {
                // Determine if the intended y coordinate must be greater
                // lexicographically.
                let greatest = copy[0] & (1 << 5) != 0;

                // Unset the three most significant bits.
                copy[0] &= 0x1f;

                // Interpret as Fq element.
                let x = Fq::from_repr(FqRepr(copy))
                    .ok_or_else(|| GroupDecodingError::CoordinateDecodingError("x coordinate"))?;

                let ret = G1Affine::get_point_from_x(x, greatest);
                if ret.is_some().into() {
                    Ok(ret.unwrap())
                } else {
                    Err(GroupDecodingError::NotOnCurve)
                }
            }
        }
        fn from_affine(affine: G1Affine) -> Self {
            let mut res = Self::empty();

            if affine.is_zero() {
                // Set the second-most significant bit to indicate this point
                // is at infinity.
                res.0[0] |= 1 << 6;
            } else {
                res.0 = affine.x.to_repr().0;

                let negy = affine.y.neg();

                // Set the third most significant bit if the correct y-coordinate
                // is lexicographically largest.
                if affine.y > negy {
                    res.0[0] |= 1 << 5;
                }
            }

            // Set highest bit to distinguish this as a compressed element.
            res.0[0] |= 1 << 7;

            res
        }
    }

    impl G1Affine {
        fn scale_by_cofactor(&self) -> G1 {
            // G1 cofactor = (x - 1)^2 / 3  = 76329603384216526031706109802092473003
            let cofactor = BitIterator::<u64, _>::new([0x8c00aaab0000aaab, 0x396c8c005555e156]);
            self.mul_bits_u64(cofactor)
        }

        fn get_generator() -> Self {
            G1Affine {
                x: super::super::fq::G1_GENERATOR_X,
                y: super::super::fq::G1_GENERATOR_Y,
                infinity: false,
            }
        }

        fn get_coeff_b() -> Fq {
            super::super::fq::B_COEFF
        }

        fn perform_pairing(&self, other: &G2Affine) -> Fq12 {
            super::super::Bls12::pairing(*self, *other)
        }
    }

    impl G1 {
        fn empirical_recommended_wnaf_for_scalar(num_bits: usize) -> usize {
            if num_bits >= 130 {
                4
            } else if num_bits >= 34 {
                3
            } else {
                2
            }
        }

        fn empirical_recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
            const RECOMMENDATIONS: [usize; 12] =
                [1, 3, 7, 20, 43, 120, 273, 563, 1630, 3128, 7933, 62569];

            let mut ret = 4;
            for r in &RECOMMENDATIONS {
                if num_scalars > *r {
                    ret += 1;
                } else {
                    break;
                }
            }

            ret
        }
    }

    #[derive(Clone, Debug)]
    pub struct G1Prepared(pub(crate) G1Affine);

    impl G1Prepared {
        pub fn is_zero(&self) -> bool {
            self.0.is_zero()
        }

        pub fn from_affine(p: G1Affine) -> Self {
            G1Prepared(p)
        }
    }

    #[test]
    fn g1_generator() {
        let mut x = Fq::zero();
        let mut i = 0;
        loop {
            // y^2 = x^3 + b
            let mut rhs = x.square();
            rhs.mul_assign(&x);
            rhs.add_assign(&G1Affine::get_coeff_b());

            let y = rhs.sqrt();
            if y.is_some().into() {
                let y = y.unwrap();
                let negy = y.neg();

                let p = G1Affine {
                    x,
                    y: if y < negy { y } else { negy },
                    infinity: false,
                };
                assert!(!p.is_in_correct_subgroup_assuming_on_curve());

                let g1 = p.scale_by_cofactor();
                if !g1.is_zero() {
                    assert_eq!(i, 4);
                    let g1 = G1Affine::from(g1);

                    assert!(g1.is_in_correct_subgroup_assuming_on_curve());

                    assert_eq!(g1, G1Affine::one());
                    break;
                }
            }

            i += 1;
            x.add_assign(&Fq::one());
        }
    }

    #[test]
    fn g1_test_is_valid() {
        // Reject point on isomorphic twist (b = 24)
        {
            let p = G1Affine {
                x: Fq::from_repr(FqRepr([
                    0x0c, 0x3a, 0xd2, 0xae, 0xfd, 0xe0, 0xbb, 0x13, 0xf5, 0x83, 0xcc, 0x5a, 0x50,
                    0x8f, 0x6a, 0x40, 0x9f, 0xe8, 0x3b, 0x1b, 0x4a, 0x5d, 0x64, 0x8d, 0xaf, 0x23,
                    0xe0, 0x64, 0xf1, 0x13, 0x1e, 0xe5, 0x10, 0xcb, 0xfd, 0x30, 0x1d, 0x55, 0x38,
                    0x22, 0xc5, 0x8d, 0x88, 0x7b, 0x66, 0xc0, 0x35, 0xdc,
                ]))
                .unwrap(),
                y: Fq::from_repr(FqRepr([
                    0x0f, 0xe3, 0xae, 0x09, 0x22, 0xdf, 0x70, 0x2c, 0x95, 0x37, 0x03, 0xf5, 0x79,
                    0x5a, 0x39, 0xe5, 0xe7, 0x60, 0xf5, 0x79, 0x22, 0x99, 0x8c, 0x9d, 0x8a, 0xf1,
                    0xcd, 0xb8, 0xaa, 0x8c, 0xe1, 0x67, 0xec, 0xd0, 0x1d, 0x51, 0x81, 0x30, 0x0d,
                    0x35, 0x60, 0xaa, 0x6f, 0x95, 0x52, 0xf0, 0x3a, 0xae,
                ]))
                .unwrap(),
                infinity: false,
            };
            assert!(!p.is_on_curve());
            assert!(p.is_in_correct_subgroup_assuming_on_curve());
        }

        // Reject point on a twist (b = 3)
        {
            let p = G1Affine {
                x: Fq::from_repr(FqRepr([
                    0x0e, 0x45, 0xc9, 0xf0, 0xc0, 0x43, 0x86, 0x75, 0xbd, 0x88, 0x33, 0xdc, 0x7c,
                    0x79, 0xa7, 0xf7, 0xea, 0x03, 0x4e, 0xe2, 0x92, 0x8b, 0x30, 0xa8, 0xe3, 0x05,
                    0xbd, 0x1a, 0xc6, 0x5a, 0xdb, 0xa7, 0x92, 0xdd, 0xd3, 0x28, 0xf2, 0x7a, 0x4b,
                    0xa6, 0xee, 0x6a, 0xdf, 0x83, 0x51, 0x1e, 0x15, 0xf5,
                ]))
                .unwrap(),
                y: Fq::from_repr(FqRepr([
                    0x11, 0x8d, 0x2c, 0x54, 0x3f, 0x03, 0x11, 0x02, 0x53, 0x2d, 0x0b, 0x64, 0x0b,
                    0xd3, 0xff, 0x8b, 0x75, 0x3d, 0xdf, 0x21, 0xa2, 0x60, 0x1d, 0x20, 0xaa, 0x54,
                    0x86, 0x82, 0xb2, 0x17, 0x26, 0xe5, 0xa6, 0x5c, 0xb8, 0x1e, 0x97, 0x5e, 0x86,
                    0x75, 0x3b, 0x45, 0x0e, 0xb1, 0xab, 0x7b, 0x5d, 0xad,
                ]))
                .unwrap(),
                infinity: false,
            };
            assert!(!p.is_on_curve());
            assert!(!p.is_in_correct_subgroup_assuming_on_curve());
        }

        // Reject point in an invalid subgroup
        // There is only one r-order subgroup, as r does not divide the cofactor.
        {
            let p = G1Affine {
                x: Fq::from_repr(FqRepr([
                    0x12, 0xa8, 0x77, 0x80, 0x88, 0x45, 0x83, 0x08, 0x26, 0x5b, 0xdd, 0xd2, 0x3d,
                    0x1d, 0xec, 0x54, 0xf3, 0x5d, 0xe9, 0xce, 0x0d, 0x6b, 0x4e, 0x84, 0x88, 0xae,
                    0x9c, 0x49, 0x9f, 0x46, 0xf0, 0xc0, 0xe3, 0x7e, 0x1a, 0x61, 0x0e, 0xff, 0x2f,
                    0x79, 0x76, 0xe1, 0xc9, 0x71, 0xc6, 0xdb, 0x8f, 0xe8,
                ]))
                .unwrap(),
                y: Fq::from_repr(FqRepr([
                    0x0e, 0xd7, 0x4a, 0xb9, 0xf3, 0x02, 0xcb, 0xe0, 0x5b, 0x6f, 0xda, 0x44, 0xad,
                    0x85, 0xfa, 0x78, 0x92, 0x1b, 0xee, 0xf8, 0x9d, 0x4f, 0x29, 0xdf, 0x1b, 0xa1,
                    0x94, 0xe8, 0x9b, 0xab, 0x26, 0x10, 0xc5, 0x7c, 0xa5, 0x54, 0x56, 0xfc, 0xb9,
                    0xae, 0x8a, 0x22, 0xde, 0xfa, 0x0d, 0x52, 0x62, 0x56,
                ]))
                .unwrap(),
                infinity: false,
            };
            assert!(p.is_on_curve());
            assert!(!p.is_in_correct_subgroup_assuming_on_curve());
        }
    }

    #[test]
    fn test_g1_addition_correctness() {
        let mut p = G1 {
            x: Fq::from_repr(FqRepr([
                0x08, 0x6e, 0xd4, 0xd9, 0x90, 0x6f, 0xb0, 0x64, 0x4c, 0x6f, 0xca, 0xc4, 0xb5, 0x5f,
                0xd4, 0x79, 0x48, 0x5e, 0x77, 0xd5, 0x0a, 0x5d, 0xf1, 0x0d, 0x08, 0x1f, 0x33, 0x39,
                0xe5, 0xf9, 0x96, 0x8f, 0x79, 0xa3, 0xb0, 0x44, 0x8f, 0x31, 0xa2, 0xaa, 0x47, 0xfd,
                0x1f, 0x89, 0x1d, 0x6e, 0x8b, 0xbf,
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0x15, 0x2c, 0xa6, 0x96, 0xfe, 0x03, 0x44, 0x42, 0x57, 0x0c, 0x80, 0x05, 0xf8, 0x57,
                0x3f, 0xa6, 0xce, 0xfc, 0xa6, 0x83, 0x33, 0xc3, 0x52, 0x88, 0xa0, 0x6f, 0xd3, 0xf1,
                0xe5, 0x40, 0x91, 0x0d, 0x9f, 0x3b, 0xbb, 0x2e, 0xcd, 0x37, 0x19, 0xb9, 0x0d, 0x25,
                0xee, 0x64, 0x61, 0x53, 0x8c, 0x65,
            ]))
            .unwrap(),
            z: Fq::one(),
        };

        p.add_assign(&G1 {
            x: Fq::from_repr(FqRepr([
                0x08, 0xab, 0xd6, 0x23, 0xa5, 0x94, 0xfb, 0xa8, 0x24, 0xe8, 0x53, 0x87, 0x37, 0xc6,
                0xe6, 0x75, 0x5f, 0x44, 0x31, 0x4e, 0xc5, 0xe3, 0xfb, 0x03, 0xc2, 0x86, 0xc0, 0x21,
                0x1c, 0x40, 0xdd, 0x54, 0xa1, 0x2b, 0xeb, 0x1f, 0xea, 0x10, 0x56, 0xe6, 0xee, 0xc7,
                0x8f, 0x30, 0x96, 0x21, 0x3c, 0xbf,
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0x00, 0xe7, 0x48, 0x46, 0x15, 0x4a, 0x9e, 0x44, 0x1f, 0x29, 0x98, 0xa5, 0xa9, 0xc6,
                0x12, 0x53, 0xd6, 0x51, 0x04, 0xc6, 0xf9, 0x5a, 0x87, 0x2a, 0x9a, 0x51, 0x81, 0xf2,
                0xfa, 0xc2, 0x26, 0xad, 0x2f, 0xde, 0xb5, 0xc8, 0x29, 0x17, 0xff, 0x9e, 0x6b, 0x05,
                0x28, 0xf0, 0x88, 0xbb, 0x70, 0x44,
            ]))
            .unwrap(),
            z: Fq::one(),
        });

        let p = G1Affine::from(p);

        assert_eq!(
            p,
            G1Affine {
                x: Fq::from_repr(FqRepr([
                    0x17, 0xfb, 0x89, 0x05, 0xe9, 0x18, 0x3c, 0x69, 0xd1, 0x78, 0xb2, 0x8d, 0xd4,
                    0xf4, 0x07, 0xef, 0xc4, 0xf9, 0xa5, 0x2a, 0x42, 0x8e, 0x23, 0xbb, 0xeb, 0x96,
                    0xbb, 0x99, 0xfa, 0x50, 0x77, 0x9f, 0xe8, 0x65, 0xd2, 0x21, 0xc8, 0x09, 0x02,
                    0x60, 0x06, 0xdd, 0x30, 0x98, 0xf2, 0x22, 0x35, 0xdf,
                ]))
                .unwrap(),
                y: Fq::from_repr(FqRepr([
                    0x04, 0x30, 0xcb, 0xdc, 0x54, 0x55, 0xb0, 0x0a, 0x4b, 0xc3, 0x62, 0x64, 0x9d,
                    0xce, 0x63, 0x76, 0xee, 0xc8, 0xd1, 0xa5, 0xb7, 0x46, 0x6c, 0x58, 0x10, 0x40,
                    0xe2, 0x70, 0x12, 0xf2, 0x0b, 0x64, 0xf6, 0xa0, 0x5f, 0x2b, 0xcf, 0x1d, 0x9c,
                    0xa7, 0xd0, 0xde, 0x9d, 0x65, 0x29, 0x2b, 0x77, 0x10,
                ]))
                .unwrap(),
                infinity: false,
            }
        );
    }

    #[test]
    fn test_g1_doubling_correctness() {
        let mut p = G1 {
            x: Fq::from_repr(FqRepr([
                0x08, 0x6e, 0xd4, 0xd9, 0x90, 0x6f, 0xb0, 0x64, 0x4c, 0x6f, 0xca, 0xc4, 0xb5, 0x5f,
                0xd4, 0x79, 0x48, 0x5e, 0x77, 0xd5, 0x0a, 0x5d, 0xf1, 0x0d, 0x08, 0x1f, 0x33, 0x39,
                0xe5, 0xf9, 0x96, 0x8f, 0x79, 0xa3, 0xb0, 0x44, 0x8f, 0x31, 0xa2, 0xaa, 0x47, 0xfd,
                0x1f, 0x89, 0x1d, 0x6e, 0x8b, 0xbf,
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0x15, 0x2c, 0xa6, 0x96, 0xfe, 0x03, 0x44, 0x42, 0x57, 0x0c, 0x80, 0x05, 0xf8, 0x57,
                0x3f, 0xa6, 0xce, 0xfc, 0xa6, 0x83, 0x33, 0xc3, 0x52, 0x88, 0xa0, 0x6f, 0xd3, 0xf1,
                0xe5, 0x40, 0x91, 0x0d, 0x9f, 0x3b, 0xbb, 0x2e, 0xcd, 0x37, 0x19, 0xb9, 0x0d, 0x25,
                0xee, 0x64, 0x61, 0x53, 0x8c, 0x65,
            ]))
            .unwrap(),
            z: Fq::one(),
        };

        p.double();

        let p = G1Affine::from(p);

        assert_eq!(
            p,
            G1Affine {
                x: Fq::from_repr(FqRepr([
                    0x0a, 0xf9, 0x60, 0xcf, 0xf3, 0xd8, 0x38, 0x33, 0x66, 0xc8, 0xba, 0xf1, 0x77,
                    0xd2, 0x05, 0x33, 0x4b, 0x91, 0x4c, 0x16, 0x68, 0x7d, 0xcd, 0xe0, 0xce, 0x0e,
                    0x9c, 0x38, 0xfd, 0xb1, 0x18, 0x51, 0x03, 0xb0, 0x39, 0x42, 0xe7, 0x32, 0xae,
                    0xcb, 0xf9, 0x39, 0xdd, 0xfe, 0x0e, 0xad, 0x70, 0x18,
                ]))
                .unwrap(),
                y: Fq::from_repr(FqRepr([
                    0x13, 0x50, 0x75, 0x58, 0x9a, 0x68, 0x7b, 0x1e, 0x8b, 0x54, 0x7c, 0x13, 0x13,
                    0xb2, 0x75, 0x55, 0x17, 0x71, 0xa6, 0x5b, 0x60, 0x57, 0x2f, 0x4e, 0x90, 0x96,
                    0x38, 0x0d, 0xd8, 0xe5, 0x1b, 0x11, 0x2b, 0x6d, 0x82, 0xae, 0x17, 0x8a, 0x1b,
                    0xa0, 0x3f, 0x06, 0x75, 0x69, 0x5f, 0x51, 0x77, 0xa8,
                ]))
                .unwrap(),
                infinity: false,
            }
        );
    }

    #[test]
    fn test_g1_same_y() {
        // Test the addition of two points with different x coordinates
        // but the same y coordinate.

        // x1 = 128100205326445210408953809171070606737678357140298133325128175840781723996595026100005714405541449960643523234125
        // x2 = 3821408151224848222394078037104966877485040835569514006839342061575586899845797797516352881516922679872117658572470
        // y = 2291134451313223670499022936083127939567618746216464377735567679979105510603740918204953301371880765657042046687078

        let a = G1Affine {
            x: Fq::from_repr(FqRepr([
                0x00, 0xd5, 0x10, 0x8d, 0x8f, 0xf1, 0xfb, 0xd6, 0x07, 0x41, 0x8d, 0x48, 0x43, 0x86,
                0xd2, 0x67, 0x07, 0x1f, 0xfa, 0x80, 0x21, 0x53, 0x17, 0x05, 0xfe, 0x66, 0x9f, 0x13,
                0x3f, 0x16, 0xc2, 0x6a, 0x3a, 0xd2, 0x35, 0x4a, 0x07, 0xf5, 0x47, 0x2b, 0xea, 0x43,
                0x1f, 0x2c, 0xc3, 0x8f, 0xc9, 0x4d,
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0x0e, 0xe2, 0xc3, 0xd9, 0x22, 0x00, 0x8c, 0xc6, 0x04, 0x84, 0xc8, 0xfc, 0x98, 0x20,
                0x08, 0xf0, 0x52, 0x0f, 0x74, 0x77, 0x3e, 0x74, 0xc8, 0xc3, 0xc0, 0x97, 0x44, 0xe6,
                0x50, 0xb0, 0x04, 0x99, 0x25, 0x56, 0x32, 0x96, 0x4f, 0xf4, 0x0f, 0x4a, 0xa7, 0x76,
                0xcc, 0xbf, 0xe9, 0x98, 0x17, 0x66,
            ]))
            .unwrap(),
            infinity: false,
        };

        let b = G1Affine {
            x: Fq::from_repr(FqRepr([
                0x18, 0xd4, 0x04, 0x3e, 0x78, 0x10, 0x31, 0x06, 0xf7, 0xc7, 0x59, 0x10, 0x81, 0x6f,
                0x20, 0x7c, 0xc6, 0xe0, 0x52, 0x01, 0xe5, 0xf8, 0x39, 0x91, 0xe7, 0x02, 0xf1, 0x4b,
                0xb0, 0xe2, 0xac, 0xa5, 0xd9, 0x04, 0x0b, 0x2d, 0x75, 0x44, 0x8a, 0xd9, 0xe0, 0x6c,
                0xdb, 0x15, 0x6b, 0x63, 0x56, 0xb6,
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0x0e, 0xe2, 0xc3, 0xd9, 0x22, 0x00, 0x8c, 0xc6, 0x04, 0x84, 0xc8, 0xfc, 0x98, 0x20,
                0x08, 0xf0, 0x52, 0x0f, 0x74, 0x77, 0x3e, 0x74, 0xc8, 0xc3, 0xc0, 0x97, 0x44, 0xe6,
                0x50, 0xb0, 0x04, 0x99, 0x25, 0x56, 0x32, 0x96, 0x4f, 0xf4, 0x0f, 0x4a, 0xa7, 0x76,
                0xcc, 0xbf, 0xe9, 0x98, 0x17, 0x66,
            ]))
            .unwrap(),
            infinity: false,
        };

        // Expected
        // x = 52901198670373960614757979459866672334163627229195745167587898707663026648445040826329033206551534205133090753192
        // y = 1711275103908443722918766889652776216989264073722543507596490456144926139887096946237734327757134898380852225872709
        let c = G1Affine {
            x: Fq::from_repr(FqRepr([
                0x00, 0x57, 0xfd, 0x1e, 0x31, 0x7d, 0xb9, 0xbd, 0x4c, 0x12, 0xc1, 0x5d, 0x7e, 0x55,
                0xb9, 0xf3, 0x96, 0x76, 0xff, 0x02, 0xec, 0x39, 0xc2, 0x27, 0x81, 0xc7, 0x42, 0x42,
                0x06, 0xb7, 0x87, 0x14, 0x0a, 0xd5, 0xbf, 0x87, 0x34, 0x1a, 0x2d, 0xf9, 0xef, 0x4f,
                0x05, 0xbd, 0xd1, 0x0c, 0x8a, 0xa8,
            ]))
            .unwrap(),
            y: Fq::from_repr(FqRepr([
                0x0b, 0x1e, 0x4e, 0x11, 0x17, 0x7f, 0x59, 0xd4, 0x46, 0x96, 0xde, 0xb9, 0xab, 0x2b,
                0xa3, 0xe7, 0x12, 0x67, 0xd7, 0x0d, 0xb5, 0x10, 0x49, 0xfb, 0xa6, 0x99, 0x8d, 0xba,
                0xa6, 0x00, 0xf1, 0x8a, 0xf9, 0x55, 0xcd, 0x68, 0x61, 0x5f, 0xf0, 0xb5, 0x12, 0x88,
                0x33, 0x40, 0x16, 0x67, 0x93, 0x45,
            ]))
            .unwrap(),
            infinity: false,
        };

        assert!(a.is_on_curve() && a.is_in_correct_subgroup_assuming_on_curve());
        assert!(b.is_on_curve() && b.is_in_correct_subgroup_assuming_on_curve());
        assert!(c.is_on_curve() && c.is_in_correct_subgroup_assuming_on_curve());

        let mut tmp1 = a.into_projective();
        tmp1.add_assign(&b.into_projective());
        assert_eq!(tmp1.into_affine(), c);
        assert_eq!(tmp1, c.into_projective());

        let mut tmp2 = a.into_projective();
        tmp2.add_assign(&b);
        assert_eq!(tmp2.into_affine(), c);
        assert_eq!(tmp2, c.into_projective());
    }

    #[test]
    fn g1_curve_tests() {
        use group::tests::curve_tests;
        curve_tests::<G1>();
    }
}

pub mod g2 {
    use super::super::{Bls12, Fq, Fq12, Fq2, FqRepr, Fr};
    use super::g1::G1Affine;
    use crate::{Engine, PairingCurveAffine};
    use ff::{BitIterator, Field, PrimeField};
    use group::{CurveAffine, CurveProjective, EncodedPoint, GroupDecodingError};
    use rand_core::RngCore;
    use std::fmt;
    use std::ops::{AddAssign, MulAssign, Neg, SubAssign};
    use subtle::CtOption;

    curve_impl!(
        "G2",
        G2,
        G2Affine,
        G2Prepared,
        Fq2,
        Fr,
        G2Uncompressed,
        G2Compressed,
        G1Affine
    );

    #[derive(Copy, Clone)]
    pub struct G2Uncompressed([u8; 192]);

    impl AsRef<[u8]> for G2Uncompressed {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl AsMut<[u8]> for G2Uncompressed {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    impl fmt::Debug for G2Uncompressed {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            self.0[..].fmt(formatter)
        }
    }

    impl EncodedPoint for G2Uncompressed {
        type Affine = G2Affine;

        fn empty() -> Self {
            G2Uncompressed([0; 192])
        }
        fn size() -> usize {
            192
        }
        fn into_affine(&self) -> Result<G2Affine, GroupDecodingError> {
            let affine = self.into_affine_unchecked()?;

            if !affine.is_on_curve() {
                Err(GroupDecodingError::NotOnCurve)
            } else if !affine.is_in_correct_subgroup_assuming_on_curve() {
                Err(GroupDecodingError::NotInSubgroup)
            } else {
                Ok(affine)
            }
        }
        fn into_affine_unchecked(&self) -> Result<G2Affine, GroupDecodingError> {
            // Create a copy of this representation.
            let mut copy = self.0;

            if copy[0] & (1 << 7) != 0 {
                // Distinguisher bit is set, but this should be uncompressed!
                return Err(GroupDecodingError::UnexpectedCompressionMode);
            }

            if copy[0] & (1 << 6) != 0 {
                // This is the point at infinity, which means that if we mask away
                // the first two bits, the entire representation should consist
                // of zeroes.
                copy[0] &= 0x3f;

                if copy.iter().all(|b| *b == 0) {
                    Ok(G2Affine::zero())
                } else {
                    Err(GroupDecodingError::UnexpectedInformation)
                }
            } else {
                if copy[0] & (1 << 5) != 0 {
                    // The bit indicating the y-coordinate should be lexicographically
                    // largest is set, but this is an uncompressed element.
                    return Err(GroupDecodingError::UnexpectedInformation);
                }

                // Unset the three most significant bits.
                copy[0] &= 0x1f;

                fn copy_segment(s: &[u8], start: usize) -> [u8; 48] {
                    let mut ret = [0; 48];
                    ret.copy_from_slice(&s[start..start + 48]);
                    ret
                }

                let x_c1 = FqRepr(copy_segment(&copy, 0));
                let x_c0 = FqRepr(copy_segment(&copy, 48));
                let y_c1 = FqRepr(copy_segment(&copy, 96));
                let y_c0 = FqRepr(copy_segment(&copy, 144));

                Ok(G2Affine {
                    x: Fq2 {
                        c0: Fq::from_repr(x_c0).ok_or_else(|| {
                            GroupDecodingError::CoordinateDecodingError("x coordinate (c0)")
                        })?,
                        c1: Fq::from_repr(x_c1).ok_or_else(|| {
                            GroupDecodingError::CoordinateDecodingError("x coordinate (c1)")
                        })?,
                    },
                    y: Fq2 {
                        c0: Fq::from_repr(y_c0).ok_or_else(|| {
                            GroupDecodingError::CoordinateDecodingError("y coordinate (c0)")
                        })?,
                        c1: Fq::from_repr(y_c1).ok_or_else(|| {
                            GroupDecodingError::CoordinateDecodingError("y coordinate (c1)")
                        })?,
                    },
                    infinity: false,
                })
            }
        }
        fn from_affine(affine: G2Affine) -> Self {
            let mut res = Self::empty();

            if affine.is_zero() {
                // Set the second-most significant bit to indicate this point
                // is at infinity.
                res.0[0] |= 1 << 6;
            } else {
                res.0[0..48].copy_from_slice(&affine.x.c1.to_repr().0);
                res.0[48..96].copy_from_slice(&affine.x.c0.to_repr().0);
                res.0[96..144].copy_from_slice(&affine.y.c1.to_repr().0);
                res.0[144..192].copy_from_slice(&affine.y.c0.to_repr().0);
            }

            res
        }
    }

    #[derive(Copy, Clone)]
    pub struct G2Compressed([u8; 96]);

    impl AsRef<[u8]> for G2Compressed {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl AsMut<[u8]> for G2Compressed {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    impl fmt::Debug for G2Compressed {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            self.0[..].fmt(formatter)
        }
    }

    impl EncodedPoint for G2Compressed {
        type Affine = G2Affine;

        fn empty() -> Self {
            G2Compressed([0; 96])
        }
        fn size() -> usize {
            96
        }
        fn into_affine(&self) -> Result<G2Affine, GroupDecodingError> {
            let affine = self.into_affine_unchecked()?;

            // NB: Decompression guarantees that it is on the curve already.

            if !affine.is_in_correct_subgroup_assuming_on_curve() {
                Err(GroupDecodingError::NotInSubgroup)
            } else {
                Ok(affine)
            }
        }
        fn into_affine_unchecked(&self) -> Result<G2Affine, GroupDecodingError> {
            // Create a copy of this representation.
            let mut copy = self.0;

            if copy[0] & (1 << 7) == 0 {
                // Distinguisher bit isn't set.
                return Err(GroupDecodingError::UnexpectedCompressionMode);
            }

            if copy[0] & (1 << 6) != 0 {
                // This is the point at infinity, which means that if we mask away
                // the first two bits, the entire representation should consist
                // of zeroes.
                copy[0] &= 0x3f;

                if copy.iter().all(|b| *b == 0) {
                    Ok(G2Affine::zero())
                } else {
                    Err(GroupDecodingError::UnexpectedInformation)
                }
            } else {
                // Determine if the intended y coordinate must be greater
                // lexicographically.
                let greatest = copy[0] & (1 << 5) != 0;

                // Unset the three most significant bits.
                copy[0] &= 0x1f;

                fn copy_segment(s: &[u8], start: usize) -> [u8; 48] {
                    let mut ret = [0; 48];
                    ret.copy_from_slice(&s[start..start + 48]);
                    ret
                }

                let x_c1 = FqRepr(copy_segment(&copy, 0));
                let x_c0 = FqRepr(copy_segment(&copy, 48));

                // Interpret as Fq element.
                let x = Fq2 {
                    c0: Fq::from_repr(x_c0).ok_or_else(|| {
                        GroupDecodingError::CoordinateDecodingError("x coordinate (c0)")
                    })?,
                    c1: Fq::from_repr(x_c1).ok_or_else(|| {
                        GroupDecodingError::CoordinateDecodingError("x coordinate (c1)")
                    })?,
                };

                let ret = G2Affine::get_point_from_x(x, greatest);
                if ret.is_some().into() {
                    Ok(ret.unwrap())
                } else {
                    Err(GroupDecodingError::NotOnCurve)
                }
            }
        }
        fn from_affine(affine: G2Affine) -> Self {
            let mut res = Self::empty();

            if affine.is_zero() {
                // Set the second-most significant bit to indicate this point
                // is at infinity.
                res.0[0] |= 1 << 6;
            } else {
                res.0[..48].copy_from_slice(&affine.x.c1.to_repr().0);
                res.0[48..].copy_from_slice(&affine.x.c0.to_repr().0);

                let negy = affine.y.neg();

                // Set the third most significant bit if the correct y-coordinate
                // is lexicographically largest.
                if affine.y > negy {
                    res.0[0] |= 1 << 5;
                }
            }

            // Set highest bit to distinguish this as a compressed element.
            res.0[0] |= 1 << 7;

            res
        }
    }

    impl G2Affine {
        fn get_generator() -> Self {
            G2Affine {
                x: Fq2 {
                    c0: super::super::fq::G2_GENERATOR_X_C0,
                    c1: super::super::fq::G2_GENERATOR_X_C1,
                },
                y: Fq2 {
                    c0: super::super::fq::G2_GENERATOR_Y_C0,
                    c1: super::super::fq::G2_GENERATOR_Y_C1,
                },
                infinity: false,
            }
        }

        fn get_coeff_b() -> Fq2 {
            Fq2 {
                c0: super::super::fq::B_COEFF,
                c1: super::super::fq::B_COEFF,
            }
        }

        fn scale_by_cofactor(&self) -> G2 {
            // G2 cofactor = (x^8 - 4 x^7 + 5 x^6) - (4 x^4 + 6 x^3 - 4 x^2 - 4 x + 13) // 9
            // 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5
            let cofactor = BitIterator::<u64, _>::new([
                0xcf1c38e31c7238e5,
                0x1616ec6e786f0c70,
                0x21537e293a6691ae,
                0xa628f1cb4d9e82ef,
                0xa68a205b2e5a7ddf,
                0xcd91de4547085aba,
                0x91d50792876a202,
                0x5d543a95414e7f1,
            ]);
            self.mul_bits_u64(cofactor)
        }

        fn perform_pairing(&self, other: &G1Affine) -> Fq12 {
            super::super::Bls12::pairing(*other, *self)
        }
    }

    impl G2 {
        fn empirical_recommended_wnaf_for_scalar(num_bits: usize) -> usize {
            if num_bits >= 103 {
                4
            } else if num_bits >= 37 {
                3
            } else {
                2
            }
        }

        fn empirical_recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
            const RECOMMENDATIONS: [usize; 11] =
                [1, 3, 8, 20, 47, 126, 260, 826, 1501, 4555, 84071];

            let mut ret = 4;
            for r in &RECOMMENDATIONS {
                if num_scalars > *r {
                    ret += 1;
                } else {
                    break;
                }
            }

            ret
        }
    }

    #[derive(Clone, Debug)]
    pub struct G2Prepared {
        pub(crate) coeffs: Vec<(Fq2, Fq2, Fq2)>,
        pub(crate) infinity: bool,
    }

    #[test]
    fn g2_generator() {
        let mut x = Fq2::zero();
        let mut i = 0;
        loop {
            // y^2 = x^3 + b
            let mut rhs = x.square();
            rhs.mul_assign(&x);
            rhs.add_assign(&G2Affine::get_coeff_b());

            let y = rhs.sqrt();
            if y.is_some().into() {
                let y = y.unwrap();
                let negy = y.neg();

                let p = G2Affine {
                    x,
                    y: if y < negy { y } else { negy },
                    infinity: false,
                };

                assert!(!p.is_in_correct_subgroup_assuming_on_curve());

                let g2 = p.scale_by_cofactor();
                if !g2.is_zero() {
                    assert_eq!(i, 2);
                    let g2 = G2Affine::from(g2);

                    assert!(g2.is_in_correct_subgroup_assuming_on_curve());
                    assert_eq!(g2, G2Affine::one());
                    break;
                }
            }

            i += 1;
            x.add_assign(&Fq2::one());
        }
    }

    #[test]
    fn g2_test_is_valid() {
        // Reject point on isomorphic twist (b = 3 * (u + 1))
        {
            let p = G2Affine {
                x: Fq2 {
                    c0: Fq::from_repr(FqRepr([
                        0x10, 0xb8, 0xc0, 0x3d, 0x64, 0xdb, 0x4d, 0x0c, 0xcc, 0x65, 0x40, 0x6a,
                        0x7c, 0x2e, 0x5a, 0x73, 0x7a, 0x17, 0xa0, 0x04, 0x74, 0x7e, 0x3d, 0xbe,
                        0xc1, 0x59, 0x8e, 0xc4, 0x6f, 0xaa, 0x0c, 0x7c, 0xae, 0x3f, 0xb2, 0xfb,
                        0x41, 0x8f, 0x6e, 0x8a, 0xa7, 0x57, 0x07, 0x2d, 0x9f, 0xa3, 0x5b, 0xa9,
                    ]))
                    .unwrap(),
                    c1: Fq::from_repr(FqRepr([
                        0x13, 0x42, 0xf0, 0x2e, 0x2d, 0xa5, 0x44, 0x05, 0x78, 0x9b, 0xac, 0x1f,
                        0xec, 0x71, 0xa2, 0xb9, 0xfb, 0x77, 0x7e, 0x5b, 0x9b, 0x56, 0x86, 0x08,
                        0x5b, 0x47, 0xa9, 0xff, 0x9a, 0x23, 0x3a, 0x50, 0xda, 0x30, 0x77, 0x2d,
                        0xf0, 0xf5, 0x21, 0x2e, 0xd3, 0x0e, 0x70, 0xfe, 0x2f, 0x02, 0x97, 0x78,
                    ]))
                    .unwrap(),
                },
                y: Fq2 {
                    c0: Fq::from_repr(FqRepr([
                        0x00, 0x40, 0xa0, 0x05, 0x45, 0xbb, 0x3c, 0x1e, 0x78, 0xe8, 0x2a, 0x79,
                        0xd8, 0x29, 0xa5, 0x44, 0x66, 0x30, 0x15, 0xd9, 0x41, 0x0e, 0xb6, 0x08,
                        0xa4, 0x93, 0xf3, 0x6b, 0xc2, 0x0b, 0xe9, 0x8a, 0xe4, 0x55, 0x17, 0x1a,
                        0x3d, 0x47, 0xa6, 0x46, 0xfe, 0x08, 0x12, 0x04, 0x3d, 0xe5, 0x4d, 0xca,
                    ]))
                    .unwrap(),
                    c1: Fq::from_repr(FqRepr([
                        0x16, 0xa6, 0x13, 0xdb, 0x5c, 0x87, 0x3a, 0xaa, 0x68, 0x12, 0x8f, 0xd0,
                        0x54, 0x8a, 0x38, 0x29, 0x15, 0x00, 0x8b, 0x1d, 0xc3, 0x99, 0xe8, 0xdf,
                        0xda, 0x36, 0x1c, 0x97, 0xd0, 0x2f, 0x42, 0xb2, 0xb5, 0xac, 0x4d, 0xc9,
                        0x20, 0x4b, 0xcf, 0xbd, 0x47, 0x09, 0x80, 0x23, 0x48, 0xe7, 0x93, 0x77,
                    ]))
                    .unwrap(),
                },
                infinity: false,
            };
            assert!(!p.is_on_curve());
            assert!(p.is_in_correct_subgroup_assuming_on_curve());
        }

        // Reject point on a twist (b = 2 * (u + 1))
        {
            let p = G2Affine {
                x: Fq2 {
                    c0: Fq::from_repr(FqRepr([
                        0x06, 0x99, 0x3e, 0xc0, 0x1b, 0x89, 0x34, 0xed, 0xff, 0xcc, 0x4b, 0x2b,
                        0x62, 0xce, 0x84, 0x84, 0x41, 0xab, 0xba, 0x71, 0x0d, 0x6c, 0x69, 0x2c,
                        0x37, 0xc6, 0xb1, 0x2c, 0xca, 0x35, 0xa3, 0x4b, 0xc2, 0x91, 0x4d, 0xf6,
                        0x88, 0x23, 0x32, 0x38, 0xf4, 0xfd, 0xfe, 0x95, 0xa7, 0x05, 0xf9, 0x17,
                    ]))
                    .unwrap(),
                    c1: Fq::from_repr(FqRepr([
                        0x10, 0xcf, 0x1d, 0x3a, 0xd8, 0xd9, 0x0b, 0xfa, 0x83, 0x80, 0x09, 0x65,
                        0x82, 0x23, 0x67, 0xe7, 0xa5, 0xa0, 0xc2, 0xb7, 0x13, 0x1f, 0x35, 0x55,
                        0xe9, 0x39, 0x46, 0xb2, 0x90, 0xca, 0xa5, 0x91, 0x44, 0x51, 0x64, 0x08,
                        0xbc, 0x11, 0x5d, 0x95, 0x0b, 0x94, 0xe9, 0x2d, 0x5f, 0x87, 0x4e, 0x26,
                    ]))
                    .unwrap(),
                },
                y: Fq2 {
                    c0: Fq::from_repr(FqRepr([
                        0x0b, 0x64, 0x90, 0x51, 0xbb, 0xc1, 0x16, 0x4d, 0x38, 0xeb, 0x4f, 0xd8,
                        0xd6, 0x58, 0xad, 0xb7, 0x5a, 0x91, 0x71, 0x72, 0x0e, 0x73, 0xeb, 0x51,
                        0xab, 0x70, 0xb2, 0x80, 0x02, 0xf3, 0xd8, 0x25, 0x4f, 0xe7, 0x14, 0xf9,
                        0xff, 0x20, 0x4f, 0x9a, 0xbf, 0x00, 0x33, 0x4c, 0x79, 0x70, 0x1d, 0x97,
                    ]))
                    .unwrap(),
                    c1: Fq::from_repr(FqRepr([
                        0x03, 0x77, 0xf2, 0xe6, 0x20, 0x8f, 0xd4, 0xcb, 0x73, 0x79, 0x34, 0x5e,
                        0xda, 0x55, 0x26, 0x5e, 0x55, 0xf2, 0xb8, 0xef, 0xad, 0x95, 0x3e, 0x04,
                        0xe0, 0x5e, 0x2f, 0xbd, 0x15, 0xa8, 0x04, 0xe0, 0xc1, 0x96, 0xc2, 0x51,
                        0x34, 0x77, 0xf8, 0x87, 0x92, 0x25, 0x81, 0x42, 0x53, 0xd7, 0xdf, 0x75,
                    ]))
                    .unwrap(),
                },
                infinity: false,
            };
            assert!(!p.is_on_curve());
            assert!(!p.is_in_correct_subgroup_assuming_on_curve());
        }

        // Reject point in an invalid subgroup
        // There is only one r-order subgroup, as r does not divide the cofactor.
        {
            let p = G2Affine {
                x: Fq2 {
                    c0: Fq::from_repr(FqRepr([
                        0x17, 0x76, 0x2a, 0x3b, 0x91, 0x08, 0xc4, 0xa7, 0x4a, 0x15, 0x1b, 0x73,
                        0x2a, 0x60, 0x75, 0xbf, 0x21, 0x99, 0xbc, 0x19, 0xc4, 0x8c, 0x39, 0x3d,
                        0x4c, 0xeb, 0x92, 0xd0, 0xa7, 0x60, 0x57, 0xbe, 0x02, 0xf0, 0x85, 0x40,
                        0x77, 0x0f, 0xab, 0xd6, 0x02, 0x62, 0xce, 0xa7, 0x3e, 0xa1, 0x90, 0x6c,
                    ]))
                    .unwrap(),
                    c1: Fq::from_repr(FqRepr([
                        0x01, 0x58, 0xb0, 0x08, 0x3c, 0x00, 0x04, 0x62, 0x72, 0xa9, 0xb6, 0x35,
                        0x83, 0x96, 0x3f, 0xff, 0x07, 0xe1, 0x47, 0xf3, 0xf9, 0xe6, 0xe2, 0x41,
                        0x74, 0x32, 0x8a, 0xd8, 0xbc, 0x2a, 0xa1, 0x50, 0x29, 0x8f, 0x31, 0x89,
                        0xa9, 0xcf, 0x6e, 0xd6, 0x26, 0xf4, 0x61, 0xe9, 0x44, 0xbb, 0xd3, 0xd1,
                    ]))
                    .unwrap(),
                },
                y: Fq2 {
                    c0: Fq::from_repr(FqRepr([
                        0x16, 0x60, 0xf9, 0x34, 0x34, 0x58, 0x8f, 0x8d, 0x3c, 0xcf, 0xb9, 0x7b,
                        0x92, 0x4d, 0xce, 0xa8, 0x68, 0xca, 0xd1, 0x94, 0x30, 0x70, 0x6b, 0x4d,
                        0x43, 0x93, 0x9b, 0x11, 0x99, 0x7b, 0x19, 0x43, 0x55, 0xd4, 0x2e, 0xdc,
                        0x1d, 0xc4, 0x6b, 0xa0, 0x91, 0xfb, 0x0b, 0x22, 0x5e, 0xcf, 0x10, 0x3b,
                    ]))
                    .unwrap(),
                    c1: Fq::from_repr(FqRepr([
                        0x16, 0x99, 0xee, 0x57, 0x7c, 0x61, 0xb6, 0x94, 0xbe, 0xb8, 0x81, 0x37,
                        0xcf, 0x34, 0xf3, 0xe7, 0x39, 0x40, 0xa2, 0xdb, 0xb9, 0x14, 0xb5, 0x29,
                        0x61, 0x8b, 0xd2, 0xac, 0x32, 0x71, 0xac, 0x42, 0xc1, 0xe9, 0x85, 0xd6,
                        0xd8, 0x98, 0xd9, 0xf4, 0xaa, 0xed, 0x39, 0x85, 0xb6, 0xdc, 0xb9, 0xc7,
                    ]))
                    .unwrap(),
                },
                infinity: false,
            };
            assert!(p.is_on_curve());
            assert!(!p.is_in_correct_subgroup_assuming_on_curve());
        }
    }

    #[test]
    fn test_g2_addition_correctness() {
        let mut p = G2 {
            x: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x10, 0x0b, 0x2f, 0xe5, 0xbf, 0xfe, 0x03, 0x0b, 0x46, 0x17, 0xf2, 0xe6, 0x77,
                    0x4e, 0x97, 0x11, 0x72, 0x55, 0x6c, 0x99, 0x9f, 0x37, 0x07, 0xac, 0x27, 0x50,
                    0x94, 0xf1, 0x35, 0x21, 0x23, 0xa9, 0xf0, 0x34, 0x64, 0x2d, 0x2c, 0x9e, 0x85,
                    0xbd, 0x6c, 0x99, 0x4c, 0xc1, 0xe3, 0x03, 0x09, 0x4e,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x0d, 0xe8, 0x84, 0xf8, 0x9a, 0x9a, 0x37, 0x1b, 0x93, 0xeb, 0xe7, 0xc3, 0xe4,
                    0x1f, 0x6a, 0xcc, 0x46, 0x37, 0xc4, 0xf4, 0x17, 0x66, 0x7e, 0x2e, 0x19, 0xce,
                    0x46, 0x78, 0xae, 0xd4, 0xfc, 0xb5, 0xe2, 0x30, 0x39, 0xd1, 0xfe, 0x9c, 0x08,
                    0x81, 0x07, 0xa3, 0x35, 0x55, 0x97, 0x7e, 0xc6, 0x08,
                ]))
                .unwrap(),
            },
            y: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x19, 0x1b, 0x24, 0x32, 0x40, 0x7c, 0xbb, 0x7f, 0x0d, 0x83, 0x11, 0x2a, 0xac,
                    0xe3, 0x5c, 0xae, 0x25, 0xfd, 0x42, 0x7b, 0x41, 0x22, 0xf2, 0x31, 0xaa, 0x9b,
                    0x06, 0x6d, 0x74, 0x69, 0x40, 0x06, 0x44, 0xfb, 0x33, 0x91, 0xfe, 0x3c, 0x9c,
                    0x30, 0xe0, 0x73, 0x11, 0x94, 0x72, 0xe1, 0xeb, 0x62,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x03, 0xbd, 0xaf, 0xaf, 0x7c, 0xa9, 0xb3, 0x9b, 0xf6, 0xa0, 0x3d, 0x31, 0xe2,
                    0xec, 0x21, 0x83, 0x9e, 0xaa, 0x6d, 0x19, 0xde, 0x56, 0x91, 0x96, 0x96, 0xc3,
                    0x0f, 0x04, 0x11, 0x59, 0x0b, 0x48, 0xe9, 0x86, 0x05, 0x70, 0x68, 0xb5, 0x0b,
                    0x7d, 0xf6, 0x8a, 0xe8, 0x2f, 0xe9, 0x76, 0x62, 0xf5,
                ]))
                .unwrap(),
            },
            z: Fq2::one(),
        };

        p.add_assign(&G2 {
            x: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x0a, 0x33, 0xd2, 0x7a, 0xdd, 0x5e, 0x7e, 0x82, 0x27, 0xc5, 0x46, 0xf7, 0x5e,
                    0xe1, 0xf3, 0xab, 0x8e, 0x73, 0xa9, 0x6b, 0x32, 0x9a, 0xd1, 0x90, 0x06, 0x11,
                    0x5f, 0xcc, 0x12, 0xe2, 0x76, 0x9e, 0x40, 0x87, 0x77, 0xb3, 0x0c, 0xa3, 0xad,
                    0xd4, 0xa8, 0xc7, 0x63, 0xd2, 0x59, 0x10, 0xbd, 0xd3,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x14, 0x1e, 0xcb, 0xac, 0x1d, 0xeb, 0x03, 0x8b, 0x82, 0x8e, 0x58, 0x48, 0xcd,
                    0x48, 0xea, 0x66, 0x20, 0x89, 0xfa, 0xf4, 0x62, 0x43, 0x82, 0x96, 0x82, 0x70,
                    0xdc, 0xa3, 0xa9, 0x12, 0x40, 0x7b, 0xf1, 0x57, 0x83, 0x00, 0xe1, 0x34, 0x2e,
                    0x11, 0x93, 0xb1, 0xeb, 0xcd, 0x54, 0x87, 0x0d, 0xfe,
                ]))
                .unwrap(),
            },
            y: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x16, 0x57, 0x6c, 0xcd, 0x3d, 0xd0, 0xa4, 0xe8, 0xd5, 0xee, 0x2a, 0xba, 0x84,
                    0xfd, 0x10, 0xfe, 0x27, 0x67, 0x03, 0x2f, 0xc3, 0x7c, 0xc3, 0x1d, 0xe8, 0xd8,
                    0x10, 0x21, 0x75, 0xf5, 0xdc, 0x19, 0x8c, 0x15, 0x74, 0x22, 0x87, 0x57, 0xca,
                    0x23, 0xf5, 0xd2, 0xc2, 0x88, 0x57, 0x22, 0x9c, 0x3f,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x11, 0xad, 0x23, 0x6b, 0x9b, 0xa0, 0x29, 0x90, 0xab, 0xab, 0x04, 0x0d, 0xdb,
                    0xd0, 0x97, 0xcc, 0x31, 0x89, 0x8d, 0xb6, 0x3f, 0x87, 0x36, 0x3a, 0xbc, 0x15,
                    0x07, 0x12, 0xf9, 0xff, 0xe6, 0xda, 0x96, 0x57, 0xf7, 0xda, 0x77, 0xf1, 0x65,
                    0x0e, 0x4d, 0xa9, 0xb6, 0xf6, 0xa9, 0x6d, 0x1d, 0xd2,
                ]))
                .unwrap(),
            },
            z: Fq2::one(),
        });

        let p = G2Affine::from(p);

        assert_eq!(
            p,
            G2Affine {
                x: Fq2 {
                    c0: Fq::from_repr(FqRepr([
                        0x00, 0xd7, 0xc2, 0x04, 0x56, 0x61, 0x7e, 0x89, 0xab, 0xab, 0xd7, 0x60,
                        0xff, 0x05, 0xcb, 0x92, 0xf1, 0x27, 0x3e, 0x64, 0x06, 0xee, 0xf9, 0xcc,
                        0xa7, 0xde, 0x72, 0xb7, 0xdd, 0x0e, 0x64, 0xb7, 0xfc, 0x64, 0x2e, 0xb3,
                        0x59, 0x75, 0xb0, 0x69, 0xcd, 0xe7, 0xee, 0x8a, 0x3f, 0x2a, 0xc8, 0xaf,
                    ]))
                    .unwrap(),
                    c1: Fq::from_repr(FqRepr([
                        0x01, 0xa3, 0xb5, 0x9d, 0x29, 0xa3, 0x12, 0x74, 0xc8, 0xa0, 0xb7, 0x30,
                        0xbb, 0xb2, 0x1f, 0x5e, 0x8b, 0x20, 0x32, 0x84, 0xc5, 0x1e, 0xdf, 0x6b,
                        0x4d, 0xbe, 0x92, 0x4f, 0xe5, 0xfd, 0x6a, 0xc2, 0x23, 0x8f, 0x0a, 0xc6,
                        0x11, 0x9d, 0x07, 0xdf, 0xd1, 0xa5, 0x0b, 0x85, 0x72, 0xcb, 0xd2, 0xb8,
                    ]))
                    .unwrap(),
                },
                y: Fq2 {
                    c0: Fq::from_repr(FqRepr([
                        0x04, 0xcb, 0x84, 0x74, 0x1f, 0x3c, 0xaf, 0xe8, 0x15, 0x93, 0x84, 0x33,
                        0x3d, 0x7c, 0xba, 0x97, 0x64, 0x52, 0x8a, 0xb3, 0x86, 0x36, 0x33, 0xdc,
                        0x6d, 0x1e, 0xf3, 0x32, 0x48, 0x6f, 0x5e, 0x34, 0xd3, 0x09, 0x21, 0xc9,
                        0x3e, 0xc3, 0x42, 0xf4, 0x9e, 0x70, 0x9e, 0x78, 0xa8, 0xea, 0xa4, 0xc9,
                    ]))
                    .unwrap(),
                    c1: Fq::from_repr(FqRepr([
                        0x03, 0xc0, 0x75, 0xd3, 0xec, 0x52, 0xba, 0x90, 0xb6, 0x88, 0x4d, 0xee,
                        0xc5, 0x9f, 0xb2, 0x1f, 0x38, 0x52, 0x8f, 0x92, 0xb6, 0x89, 0x64, 0x4d,
                        0x2b, 0xd7, 0xca, 0x7f, 0x43, 0x46, 0xf9, 0xec, 0xe9, 0x0a, 0x73, 0xad,
                        0x65, 0xc6, 0x69, 0x19, 0x24, 0x2a, 0xf0, 0xdc, 0x36, 0x40, 0xe1, 0xa4,
                    ]))
                    .unwrap(),
                },
                infinity: false,
            }
        );
    }

    #[test]
    fn test_g2_doubling_correctness() {
        let mut p = G2 {
            x: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x10, 0x0b, 0x2f, 0xe5, 0xbf, 0xfe, 0x03, 0x0b, 0x46, 0x17, 0xf2, 0xe6, 0x77,
                    0x4e, 0x97, 0x11, 0x72, 0x55, 0x6c, 0x99, 0x9f, 0x37, 0x07, 0xac, 0x27, 0x50,
                    0x94, 0xf1, 0x35, 0x21, 0x23, 0xa9, 0xf0, 0x34, 0x64, 0x2d, 0x2c, 0x9e, 0x85,
                    0xbd, 0x6c, 0x99, 0x4c, 0xc1, 0xe3, 0x03, 0x09, 0x4e,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x0d, 0xe8, 0x84, 0xf8, 0x9a, 0x9a, 0x37, 0x1b, 0x93, 0xeb, 0xe7, 0xc3, 0xe4,
                    0x1f, 0x6a, 0xcc, 0x46, 0x37, 0xc4, 0xf4, 0x17, 0x66, 0x7e, 0x2e, 0x19, 0xce,
                    0x46, 0x78, 0xae, 0xd4, 0xfc, 0xb5, 0xe2, 0x30, 0x39, 0xd1, 0xfe, 0x9c, 0x08,
                    0x81, 0x07, 0xa3, 0x35, 0x55, 0x97, 0x7e, 0xc6, 0x08,
                ]))
                .unwrap(),
            },
            y: Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x19, 0x1b, 0x24, 0x32, 0x40, 0x7c, 0xbb, 0x7f, 0x0d, 0x83, 0x11, 0x2a, 0xac,
                    0xe3, 0x5c, 0xae, 0x25, 0xfd, 0x42, 0x7b, 0x41, 0x22, 0xf2, 0x31, 0xaa, 0x9b,
                    0x06, 0x6d, 0x74, 0x69, 0x40, 0x06, 0x44, 0xfb, 0x33, 0x91, 0xfe, 0x3c, 0x9c,
                    0x30, 0xe0, 0x73, 0x11, 0x94, 0x72, 0xe1, 0xeb, 0x62,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x03, 0xbd, 0xaf, 0xaf, 0x7c, 0xa9, 0xb3, 0x9b, 0xf6, 0xa0, 0x3d, 0x31, 0xe2,
                    0xec, 0x21, 0x83, 0x9e, 0xaa, 0x6d, 0x19, 0xde, 0x56, 0x91, 0x96, 0x96, 0xc3,
                    0x0f, 0x04, 0x11, 0x59, 0x0b, 0x48, 0xe9, 0x86, 0x05, 0x70, 0x68, 0xb5, 0x0b,
                    0x7d, 0xf6, 0x8a, 0xe8, 0x2f, 0xe9, 0x76, 0x62, 0xf5,
                ]))
                .unwrap(),
            },
            z: Fq2::one(),
        };

        p.double();

        let p = G2Affine::from(p);

        assert_eq!(
            p,
            G2Affine {
                x: Fq2 {
                    c0: Fq::from_repr(FqRepr([
                        0x18, 0xba, 0xb7, 0x37, 0x60, 0xfd, 0x80, 0x24, 0x97, 0x55, 0xd4, 0xa3,
                        0x92, 0x6e, 0x98, 0x62, 0xbc, 0xed, 0xcf, 0xce, 0x1e, 0x52, 0xd9, 0x86,
                        0x11, 0x6a, 0xee, 0x59, 0x43, 0x4d, 0xe9, 0x02, 0x91, 0xa6, 0xcb, 0x18,
                        0x24, 0x38, 0xfa, 0xd7, 0x91, 0xcc, 0xb1, 0x29, 0x27, 0x27, 0xc4, 0x04,
                    ]))
                    .unwrap(),
                    c1: Fq::from_repr(FqRepr([
                        0x00, 0xf1, 0x36, 0xe4, 0x39, 0x09, 0xfc, 0xa0, 0x7b, 0x4c, 0x2b, 0xae,
                        0x8d, 0xb6, 0xe7, 0x0b, 0xeb, 0x0c, 0xf5, 0xe6, 0x10, 0xef, 0x4f, 0xe7,
                        0xc7, 0x4d, 0x1c, 0xf4, 0xef, 0x2d, 0x59, 0x26, 0x96, 0xe5, 0x82, 0xa2,
                        0x7f, 0x02, 0x89, 0x61, 0x4e, 0x7c, 0x5e, 0x0a, 0x2a, 0xe5, 0xb9, 0x9e,
                    ]))
                    .unwrap(),
                },
                y: Fq2 {
                    c0: Fq::from_repr(FqRepr([
                        0x08, 0x1a, 0x53, 0xfe, 0x53, 0x1d, 0x64, 0xef, 0x8b, 0x92, 0x86, 0x6b,
                        0xc6, 0x38, 0x41, 0x88, 0xa5, 0xa2, 0xa5, 0x1f, 0x7f, 0xde, 0x78, 0x7b,
                        0x85, 0x3b, 0xb1, 0xd2, 0x88, 0x77, 0x57, 0x7e, 0x3e, 0xe4, 0x2e, 0xec,
                        0x61, 0x4c, 0xf8, 0x90, 0x09, 0x54, 0xd4, 0x46, 0x6a, 0xb1, 0x3e, 0x58,
                    ]))
                    .unwrap(),
                    c1: Fq::from_repr(FqRepr([
                        0x19, 0xe2, 0xde, 0xae, 0x6e, 0xb9, 0xb4, 0x41, 0x24, 0x4e, 0x6c, 0x20,
                        0x15, 0xc8, 0x33, 0x48, 0xb2, 0x71, 0xf5, 0x2f, 0x12, 0xea, 0xd7, 0x42,
                        0x33, 0x71, 0x67, 0xee, 0x6e, 0x8e, 0x3c, 0xb6, 0xed, 0xdb, 0x5f, 0x48,
                        0x30, 0x4d, 0x14, 0xb3, 0x4c, 0x5d, 0x60, 0x76, 0x66, 0x23, 0x9b, 0x34,
                    ]))
                    .unwrap(),
                },
                infinity: false,
            }
        );
    }

    #[test]
    fn g2_curve_tests() {
        use group::tests::curve_tests;
        curve_tests::<G2>();
    }
}

pub use self::g1::*;
pub use self::g2::*;
