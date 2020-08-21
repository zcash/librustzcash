//! Gadgets implementing Jubjub elliptic curve operations.

use std::ops::{AddAssign, MulAssign, Neg, SubAssign};

use bellman::{ConstraintSystem, SynthesisError};

use bellman::gadgets::Assignment;

use bellman::gadgets::num::{AllocatedNum, Num};

use bellman::gadgets::lookup::lookup3_xy;

use bellman::gadgets::boolean::Boolean;

use group::Curve;

use crate::constants::{FixedGenerator, EDWARDS_D, MONTGOMERY_A, MONTGOMERY_SCALE};

#[derive(Clone)]
pub struct EdwardsPoint {
    x: AllocatedNum<bls12_381::Scalar>,
    y: AllocatedNum<bls12_381::Scalar>,
}

/// Perform a fixed-base scalar multiplication with
/// `by` being in little-endian bit order.
pub fn fixed_base_multiplication<CS>(
    mut cs: CS,
    base: FixedGenerator,
    by: &[Boolean],
) -> Result<EdwardsPoint, SynthesisError>
where
    CS: ConstraintSystem<bls12_381::Scalar>,
{
    // Represents the result of the multiplication
    let mut result = None;

    for (i, (chunk, window)) in by.chunks(3).zip(base.iter()).enumerate() {
        let chunk_a = chunk
            .get(0)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));
        let chunk_b = chunk
            .get(1)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));
        let chunk_c = chunk
            .get(2)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));

        let (x, y) = lookup3_xy(
            cs.namespace(|| format!("window table lookup {}", i)),
            &[chunk_a, chunk_b, chunk_c],
            window,
        )?;

        let p = EdwardsPoint { x, y };

        if result.is_none() {
            result = Some(p);
        } else {
            result = Some(
                result
                    .unwrap()
                    .add(cs.namespace(|| format!("addition {}", i)), &p)?,
            );
        }
    }

    Ok(result.get()?.clone())
}

impl EdwardsPoint {
    pub fn get_x(&self) -> &AllocatedNum<bls12_381::Scalar> {
        &self.x
    }

    pub fn get_y(&self) -> &AllocatedNum<bls12_381::Scalar> {
        &self.y
    }

    pub fn assert_not_small_order<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        let tmp = self.double(cs.namespace(|| "first doubling"))?;
        let tmp = tmp.double(cs.namespace(|| "second doubling"))?;
        let tmp = tmp.double(cs.namespace(|| "third doubling"))?;

        // (0, -1) is a small order point, but won't ever appear here
        // because cofactor is 2^3, and we performed three doublings.
        // (0, 1) is the neutral element, so checking if x is nonzero
        // is sufficient to prevent small order points here.
        tmp.x.assert_nonzero(cs.namespace(|| "check x != 0"))?;

        Ok(())
    }

    pub fn inputize<CS>(&self, mut cs: CS) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        self.x.inputize(cs.namespace(|| "x"))?;
        self.y.inputize(cs.namespace(|| "y"))?;

        Ok(())
    }

    /// This converts the point into a representation.
    pub fn repr<CS>(&self, mut cs: CS) -> Result<Vec<Boolean>, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        let mut tmp = vec![];

        let x = self.x.to_bits_le_strict(cs.namespace(|| "unpack x"))?;

        let y = self.y.to_bits_le_strict(cs.namespace(|| "unpack y"))?;

        tmp.extend(y);
        tmp.push(x[0].clone());

        Ok(tmp)
    }

    /// This 'witnesses' a point inside the constraint system.
    /// It guarantees the point is on the curve.
    pub fn witness<CS>(mut cs: CS, p: Option<jubjub::ExtendedPoint>) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        let p = p.map(|p| p.to_affine());

        // Allocate x
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(p.get()?.get_u()))?;

        // Allocate y
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(p.get()?.get_v()))?;

        Self::interpret(cs.namespace(|| "point interpretation"), &x, &y)
    }

    /// Returns `self` if condition is true, and the neutral
    /// element (0, 1) otherwise.
    pub fn conditionally_select<CS>(
        &self,
        mut cs: CS,
        condition: &Boolean,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute x' = self.x if condition, and 0 otherwise
        let x_prime = AllocatedNum::alloc(cs.namespace(|| "x'"), || {
            if *condition.get_value().get()? {
                Ok(*self.x.get_value().get()?)
            } else {
                Ok(bls12_381::Scalar::zero())
            }
        })?;

        // condition * x = x'
        // if condition is 0, x' must be 0
        // if condition is 1, x' must be x
        let one = CS::one();
        cs.enforce(
            || "x' computation",
            |lc| lc + self.x.get_variable(),
            |_| condition.lc(one, bls12_381::Scalar::one()),
            |lc| lc + x_prime.get_variable(),
        );

        // Compute y' = self.y if condition, and 1 otherwise
        let y_prime = AllocatedNum::alloc(cs.namespace(|| "y'"), || {
            if *condition.get_value().get()? {
                Ok(*self.y.get_value().get()?)
            } else {
                Ok(bls12_381::Scalar::one())
            }
        })?;

        // condition * y = y' - (1 - condition)
        // if condition is 0, y' must be 1
        // if condition is 1, y' must be y
        cs.enforce(
            || "y' computation",
            |lc| lc + self.y.get_variable(),
            |_| condition.lc(one, bls12_381::Scalar::one()),
            |lc| lc + y_prime.get_variable() - &condition.not().lc(one, bls12_381::Scalar::one()),
        );

        Ok(EdwardsPoint {
            x: x_prime,
            y: y_prime,
        })
    }

    /// Performs a scalar multiplication of this twisted Edwards
    /// point by a scalar represented as a sequence of booleans
    /// in little-endian bit order.
    pub fn mul<CS>(&self, mut cs: CS, by: &[Boolean]) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Represents the current "magnitude" of the base
        // that we're operating over. Starts at self,
        // then 2*self, then 4*self, ...
        let mut curbase = None;

        // Represents the result of the multiplication
        let mut result = None;

        for (i, bit) in by.iter().enumerate() {
            if curbase.is_none() {
                curbase = Some(self.clone());
            } else {
                // Double the previous value
                curbase = Some(
                    curbase
                        .unwrap()
                        .double(cs.namespace(|| format!("doubling {}", i)))?,
                );
            }

            // Represents the select base. If the bit for this magnitude
            // is true, this will return `curbase`. Otherwise it will
            // return the neutral element, which will have no effect on
            // the result.
            let thisbase = curbase
                .as_ref()
                .unwrap()
                .conditionally_select(cs.namespace(|| format!("selection {}", i)), bit)?;

            if result.is_none() {
                result = Some(thisbase);
            } else {
                result = Some(
                    result
                        .unwrap()
                        .add(cs.namespace(|| format!("addition {}", i)), &thisbase)?,
                );
            }
        }

        Ok(result.get()?.clone())
    }

    pub fn interpret<CS>(
        mut cs: CS,
        x: &AllocatedNum<bls12_381::Scalar>,
        y: &AllocatedNum<bls12_381::Scalar>,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // -x^2 + y^2 = 1 + dx^2y^2

        let x2 = x.square(cs.namespace(|| "x^2"))?;
        let y2 = y.square(cs.namespace(|| "y^2"))?;
        let x2y2 = x2.mul(cs.namespace(|| "x^2 y^2"), &y2)?;

        let one = CS::one();
        cs.enforce(
            || "on curve check",
            |lc| lc - x2.get_variable() + y2.get_variable(),
            |lc| lc + one,
            |lc| lc + one + (EDWARDS_D, x2y2.get_variable()),
        );

        Ok(EdwardsPoint {
            x: x.clone(),
            y: y.clone(),
        })
    }

    pub fn double<CS>(&self, mut cs: CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute T = (x1 + y1) * (x1 + y1)
        let t = AllocatedNum::alloc(cs.namespace(|| "T"), || {
            let mut t0 = *self.x.get_value().get()?;
            t0.add_assign(self.y.get_value().get()?);

            let mut t1 = *self.x.get_value().get()?;
            t1.add_assign(self.y.get_value().get()?);

            t0.mul_assign(&t1);

            Ok(t0)
        })?;

        cs.enforce(
            || "T computation",
            |lc| lc + self.x.get_variable() + self.y.get_variable(),
            |lc| lc + self.x.get_variable() + self.y.get_variable(),
            |lc| lc + t.get_variable(),
        );

        // Compute A = x1 * y1
        let a = self.x.mul(cs.namespace(|| "A computation"), &self.y)?;

        // Compute C = d*A*A
        let c = AllocatedNum::alloc(cs.namespace(|| "C"), || {
            let mut t0 = a.get_value().get()?.square();
            t0.mul_assign(EDWARDS_D);

            Ok(t0)
        })?;

        cs.enforce(
            || "C computation",
            |lc| lc + (EDWARDS_D, a.get_variable()),
            |lc| lc + a.get_variable(),
            |lc| lc + c.get_variable(),
        );

        // Compute x3 = (2.A) / (1 + C)
        let x3 = AllocatedNum::alloc(cs.namespace(|| "x3"), || {
            let mut t0 = *a.get_value().get()?;
            t0 = t0.double();

            let mut t1 = bls12_381::Scalar::one();
            t1.add_assign(c.get_value().get()?);

            let res = t1.invert().map(|t1| t0 * &t1);
            if bool::from(res.is_some()) {
                Ok(res.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        let one = CS::one();
        cs.enforce(
            || "x3 computation",
            |lc| lc + one + c.get_variable(),
            |lc| lc + x3.get_variable(),
            |lc| lc + a.get_variable() + a.get_variable(),
        );

        // Compute y3 = (U - 2.A) / (1 - C)
        let y3 = AllocatedNum::alloc(cs.namespace(|| "y3"), || {
            let mut t0 = *a.get_value().get()?;
            t0 = t0.double().neg();
            t0.add_assign(t.get_value().get()?);

            let mut t1 = bls12_381::Scalar::one();
            t1.sub_assign(c.get_value().get()?);

            let res = t1.invert().map(|t1| t0 * &t1);
            if bool::from(res.is_some()) {
                Ok(res.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        cs.enforce(
            || "y3 computation",
            |lc| lc + one - c.get_variable(),
            |lc| lc + y3.get_variable(),
            |lc| lc + t.get_variable() - a.get_variable() - a.get_variable(),
        );

        Ok(EdwardsPoint { x: x3, y: y3 })
    }

    /// Perform addition between any two points
    pub fn add<CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute U = (x1 + y1) * (x2 + y2)
        let u = AllocatedNum::alloc(cs.namespace(|| "U"), || {
            let mut t0 = *self.x.get_value().get()?;
            t0.add_assign(self.y.get_value().get()?);

            let mut t1 = *other.x.get_value().get()?;
            t1.add_assign(other.y.get_value().get()?);

            t0.mul_assign(&t1);

            Ok(t0)
        })?;

        cs.enforce(
            || "U computation",
            |lc| lc + self.x.get_variable() + self.y.get_variable(),
            |lc| lc + other.x.get_variable() + other.y.get_variable(),
            |lc| lc + u.get_variable(),
        );

        // Compute A = y2 * x1
        let a = other.y.mul(cs.namespace(|| "A computation"), &self.x)?;

        // Compute B = x2 * y1
        let b = other.x.mul(cs.namespace(|| "B computation"), &self.y)?;

        // Compute C = d*A*B
        let c = AllocatedNum::alloc(cs.namespace(|| "C"), || {
            let mut t0 = *a.get_value().get()?;
            t0.mul_assign(b.get_value().get()?);
            t0.mul_assign(EDWARDS_D);

            Ok(t0)
        })?;

        cs.enforce(
            || "C computation",
            |lc| lc + (EDWARDS_D, a.get_variable()),
            |lc| lc + b.get_variable(),
            |lc| lc + c.get_variable(),
        );

        // Compute x3 = (A + B) / (1 + C)
        let x3 = AllocatedNum::alloc(cs.namespace(|| "x3"), || {
            let mut t0 = *a.get_value().get()?;
            t0.add_assign(b.get_value().get()?);

            let mut t1 = bls12_381::Scalar::one();
            t1.add_assign(c.get_value().get()?);

            let ret = t1.invert().map(|t1| t0 * &t1);
            if bool::from(ret.is_some()) {
                Ok(ret.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        let one = CS::one();
        cs.enforce(
            || "x3 computation",
            |lc| lc + one + c.get_variable(),
            |lc| lc + x3.get_variable(),
            |lc| lc + a.get_variable() + b.get_variable(),
        );

        // Compute y3 = (U - A - B) / (1 - C)
        let y3 = AllocatedNum::alloc(cs.namespace(|| "y3"), || {
            let mut t0 = *u.get_value().get()?;
            t0.sub_assign(a.get_value().get()?);
            t0.sub_assign(b.get_value().get()?);

            let mut t1 = bls12_381::Scalar::one();
            t1.sub_assign(c.get_value().get()?);

            let ret = t1.invert().map(|t1| t0 * &t1);
            if bool::from(ret.is_some()) {
                Ok(ret.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        cs.enforce(
            || "y3 computation",
            |lc| lc + one - c.get_variable(),
            |lc| lc + y3.get_variable(),
            |lc| lc + u.get_variable() - a.get_variable() - b.get_variable(),
        );

        Ok(EdwardsPoint { x: x3, y: y3 })
    }
}

pub struct MontgomeryPoint {
    x: Num<bls12_381::Scalar>,
    y: Num<bls12_381::Scalar>,
}

impl MontgomeryPoint {
    /// Converts an element in the prime order subgroup into
    /// a point in the birationally equivalent twisted
    /// Edwards curve.
    pub fn into_edwards<CS>(self, mut cs: CS) -> Result<EdwardsPoint, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute u = (scale*x) / y
        let u = AllocatedNum::alloc(cs.namespace(|| "u"), || {
            let mut t0 = *self.x.get_value().get()?;
            t0.mul_assign(MONTGOMERY_SCALE);

            let ret = self.y.get_value().get()?.invert().map(|invy| t0 * &invy);
            if bool::from(ret.is_some()) {
                Ok(ret.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        cs.enforce(
            || "u computation",
            |lc| lc + &self.y.lc(bls12_381::Scalar::one()),
            |lc| lc + u.get_variable(),
            |lc| lc + &self.x.lc(MONTGOMERY_SCALE),
        );

        // Compute v = (x - 1) / (x + 1)
        let v = AllocatedNum::alloc(cs.namespace(|| "v"), || {
            let mut t0 = *self.x.get_value().get()?;
            let mut t1 = t0;
            t0.sub_assign(&bls12_381::Scalar::one());
            t1.add_assign(&bls12_381::Scalar::one());

            let ret = t1.invert().map(|t1| t0 * &t1);
            if bool::from(ret.is_some()) {
                Ok(ret.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        let one = CS::one();
        cs.enforce(
            || "v computation",
            |lc| lc + &self.x.lc(bls12_381::Scalar::one()) + one,
            |lc| lc + v.get_variable(),
            |lc| lc + &self.x.lc(bls12_381::Scalar::one()) - one,
        );

        Ok(EdwardsPoint { x: u, y: v })
    }

    /// Interprets an (x, y) pair as a point
    /// in Montgomery, does not check that it's
    /// on the curve. Useful for constants and
    /// window table lookups.
    pub fn interpret_unchecked(x: Num<bls12_381::Scalar>, y: Num<bls12_381::Scalar>) -> Self {
        MontgomeryPoint { x, y }
    }

    /// Performs an affine point addition, not defined for
    /// coincident points.
    pub fn add<CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<bls12_381::Scalar>,
    {
        // Compute lambda = (y' - y) / (x' - x)
        let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
            let mut n = *other.y.get_value().get()?;
            n.sub_assign(self.y.get_value().get()?);

            let mut d = *other.x.get_value().get()?;
            d.sub_assign(self.x.get_value().get()?);

            let ret = d.invert().map(|d| n * &d);
            if bool::from(ret.is_some()) {
                Ok(ret.unwrap())
            } else {
                Err(SynthesisError::DivisionByZero)
            }
        })?;

        cs.enforce(
            || "evaluate lambda",
            |lc| lc + &other.x.lc(bls12_381::Scalar::one()) - &self.x.lc(bls12_381::Scalar::one()),
            |lc| lc + lambda.get_variable(),
            |lc| lc + &other.y.lc(bls12_381::Scalar::one()) - &self.y.lc(bls12_381::Scalar::one()),
        );

        // Compute x'' = lambda^2 - A - x - x'
        let xprime = AllocatedNum::alloc(cs.namespace(|| "xprime"), || {
            let mut t0 = lambda.get_value().get()?.square();
            t0.sub_assign(MONTGOMERY_A);
            t0.sub_assign(self.x.get_value().get()?);
            t0.sub_assign(other.x.get_value().get()?);

            Ok(t0)
        })?;

        // (lambda) * (lambda) = (A + x + x' + x'')
        let one = CS::one();
        cs.enforce(
            || "evaluate xprime",
            |lc| lc + lambda.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| {
                lc + (MONTGOMERY_A, one)
                    + &self.x.lc(bls12_381::Scalar::one())
                    + &other.x.lc(bls12_381::Scalar::one())
                    + xprime.get_variable()
            },
        );

        // Compute y' = -(y + lambda(x' - x))
        let yprime = AllocatedNum::alloc(cs.namespace(|| "yprime"), || {
            let mut t0 = *xprime.get_value().get()?;
            t0.sub_assign(self.x.get_value().get()?);
            t0.mul_assign(lambda.get_value().get()?);
            t0.add_assign(self.y.get_value().get()?);
            t0 = t0.neg();

            Ok(t0)
        })?;

        // y' + y = lambda(x - x')
        cs.enforce(
            || "evaluate yprime",
            |lc| lc + &self.x.lc(bls12_381::Scalar::one()) - xprime.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| lc + yprime.get_variable() + &self.y.lc(bls12_381::Scalar::one()),
        );

        Ok(MontgomeryPoint {
            x: xprime.into(),
            y: yprime.into(),
        })
    }
}

#[cfg(test)]
mod test {
    use bellman::ConstraintSystem;
    use ff::{BitIterator, Field, PrimeField};
    use group::{Curve, Group};
    use rand_core::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use bellman::gadgets::test::*;

    use super::{fixed_base_multiplication, AllocatedNum, EdwardsPoint, MontgomeryPoint};
    use crate::constants::{to_montgomery_coords, NOTE_COMMITMENT_RANDOMNESS_GENERATOR};
    use bellman::gadgets::boolean::{AllocatedBit, Boolean};

    #[test]
    fn test_into_edwards() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::new();

            let p = jubjub::ExtendedPoint::random(rng);
            let (x, y) = to_montgomery_coords(p).unwrap();
            let p = p.to_affine();
            let (u, v) = (p.get_u(), p.get_v());

            let numx = AllocatedNum::alloc(cs.namespace(|| "mont x"), || Ok(x)).unwrap();
            let numy = AllocatedNum::alloc(cs.namespace(|| "mont y"), || Ok(y)).unwrap();

            let p = MontgomeryPoint::interpret_unchecked(numx.into(), numy.into());

            let q = p.into_edwards(&mut cs).unwrap();

            assert!(cs.is_satisfied());
            assert!(q.x.get_value().unwrap() == u);
            assert!(q.y.get_value().unwrap() == v);

            cs.set("u/num", bls12_381::Scalar::random(rng));
            assert_eq!(cs.which_is_unsatisfied().unwrap(), "u computation");
            cs.set("u/num", u);
            assert!(cs.is_satisfied());

            cs.set("v/num", bls12_381::Scalar::random(rng));
            assert_eq!(cs.which_is_unsatisfied().unwrap(), "v computation");
            cs.set("v/num", v);
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn test_interpret() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..100 {
            let p = jubjub::ExtendedPoint::random(rng);

            let mut cs = TestConstraintSystem::new();
            let q = EdwardsPoint::witness(&mut cs, Some(p.clone())).unwrap();

            let p = p.to_affine();

            assert!(cs.is_satisfied());
            assert_eq!(q.x.get_value().unwrap(), p.get_u());
            assert_eq!(q.y.get_value().unwrap(), p.get_v());
        }

        for _ in 0..100 {
            let p = jubjub::ExtendedPoint::random(rng).to_affine();
            let (x, y) = (p.get_u(), p.get_v());

            let mut cs = TestConstraintSystem::new();
            let numx = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(x)).unwrap();
            let numy = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(y)).unwrap();

            let p = EdwardsPoint::interpret(&mut cs, &numx, &numy).unwrap();

            assert!(cs.is_satisfied());
            assert_eq!(p.x.get_value().unwrap(), x);
            assert_eq!(p.y.get_value().unwrap(), y);
        }

        // Random (x, y) are unlikely to be on the curve.
        for _ in 0..100 {
            let x = bls12_381::Scalar::random(rng);
            let y = bls12_381::Scalar::random(rng);

            let mut cs = TestConstraintSystem::new();
            let numx = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(x)).unwrap();
            let numy = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(y)).unwrap();

            EdwardsPoint::interpret(&mut cs, &numx, &numy).unwrap();

            assert_eq!(cs.which_is_unsatisfied().unwrap(), "on curve check");
        }
    }

    #[test]
    fn test_edwards_fixed_base_multiplication() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();

            let p = zcash_primitives::constants::NOTE_COMMITMENT_RANDOMNESS_GENERATOR;
            let s = jubjub::Fr::random(rng);
            let q = jubjub::ExtendedPoint::from(p * s).to_affine();
            let (x1, y1) = (q.get_u(), q.get_v());

            let mut s_bits = BitIterator::<u8, _>::new(s.to_repr()).collect::<Vec<_>>();
            s_bits.reverse();
            s_bits.truncate(jubjub::Fr::NUM_BITS as usize);

            let s_bits = s_bits
                .into_iter()
                .enumerate()
                .map(|(i, b)| {
                    AllocatedBit::alloc(cs.namespace(|| format!("scalar bit {}", i)), Some(b))
                        .unwrap()
                })
                .map(|v| Boolean::from(v))
                .collect::<Vec<_>>();

            let q = fixed_base_multiplication(
                cs.namespace(|| "multiplication"),
                &NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
                &s_bits,
            )
            .unwrap();

            assert_eq!(q.x.get_value().unwrap(), x1);
            assert_eq!(q.y.get_value().unwrap(), y1);
        }
    }

    #[test]
    fn test_edwards_multiplication() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::new();

            let p = jubjub::ExtendedPoint::random(rng);
            let s = jubjub::Fr::random(rng);
            let q = (p * s).to_affine();
            let p = p.to_affine();

            let (x0, y0) = (p.get_u(), p.get_v());
            let (x1, y1) = (q.get_u(), q.get_v());

            let num_x0 = AllocatedNum::alloc(cs.namespace(|| "x0"), || Ok(x0)).unwrap();
            let num_y0 = AllocatedNum::alloc(cs.namespace(|| "y0"), || Ok(y0)).unwrap();

            let p = EdwardsPoint {
                x: num_x0,
                y: num_y0,
            };

            let mut s_bits = BitIterator::<u8, _>::new(s.to_repr()).collect::<Vec<_>>();
            s_bits.reverse();
            s_bits.truncate(jubjub::Fr::NUM_BITS as usize);

            let s_bits = s_bits
                .into_iter()
                .enumerate()
                .map(|(i, b)| {
                    AllocatedBit::alloc(cs.namespace(|| format!("scalar bit {}", i)), Some(b))
                        .unwrap()
                })
                .map(|v| Boolean::from(v))
                .collect::<Vec<_>>();

            let q = p.mul(cs.namespace(|| "scalar mul"), &s_bits).unwrap();

            assert!(cs.is_satisfied());

            assert_eq!(q.x.get_value().unwrap(), x1);

            assert_eq!(q.y.get_value().unwrap(), y1);
        }
    }

    #[test]
    fn test_conditionally_select() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..1000 {
            let mut cs = TestConstraintSystem::new();

            let p = jubjub::ExtendedPoint::random(rng).to_affine();

            let (x0, y0) = (p.get_u(), p.get_v());

            let num_x0 = AllocatedNum::alloc(cs.namespace(|| "x0"), || Ok(x0)).unwrap();
            let num_y0 = AllocatedNum::alloc(cs.namespace(|| "y0"), || Ok(y0)).unwrap();

            let p = EdwardsPoint {
                x: num_x0,
                y: num_y0,
            };

            let mut should_we_select = rng.next_u32() % 2 != 0;

            // Conditionally allocate
            let mut b = if rng.next_u32() % 2 != 0 {
                Boolean::from(
                    AllocatedBit::alloc(cs.namespace(|| "condition"), Some(should_we_select))
                        .unwrap(),
                )
            } else {
                Boolean::constant(should_we_select)
            };

            // Conditionally negate
            if rng.next_u32() % 2 != 0 {
                b = b.not();
                should_we_select = !should_we_select;
            }

            let q = p
                .conditionally_select(cs.namespace(|| "select"), &b)
                .unwrap();

            assert!(cs.is_satisfied());

            if should_we_select {
                assert_eq!(q.x.get_value().unwrap(), x0);
                assert_eq!(q.y.get_value().unwrap(), y0);

                cs.set("select/y'/num", bls12_381::Scalar::one());
                assert_eq!(cs.which_is_unsatisfied().unwrap(), "select/y' computation");
                cs.set("select/x'/num", bls12_381::Scalar::zero());
                assert_eq!(cs.which_is_unsatisfied().unwrap(), "select/x' computation");
            } else {
                assert_eq!(q.x.get_value().unwrap(), bls12_381::Scalar::zero());
                assert_eq!(q.y.get_value().unwrap(), bls12_381::Scalar::one());

                cs.set("select/y'/num", x0);
                assert_eq!(cs.which_is_unsatisfied().unwrap(), "select/y' computation");
                cs.set("select/x'/num", y0);
                assert_eq!(cs.which_is_unsatisfied().unwrap(), "select/x' computation");
            }
        }
    }

    #[test]
    fn test_edwards_addition() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..100 {
            let p1 = jubjub::ExtendedPoint::random(rng);
            let p2 = jubjub::ExtendedPoint::random(rng);

            let p3 = p1 + p2;

            let p1 = p1.to_affine();
            let p2 = p2.to_affine();
            let p3 = p3.to_affine();

            let (x0, y0) = (p1.get_u(), p1.get_v());
            let (x1, y1) = (p2.get_u(), p2.get_v());
            let (x2, y2) = (p3.get_u(), p3.get_v());

            let mut cs = TestConstraintSystem::new();

            let num_x0 = AllocatedNum::alloc(cs.namespace(|| "x0"), || Ok(x0)).unwrap();
            let num_y0 = AllocatedNum::alloc(cs.namespace(|| "y0"), || Ok(y0)).unwrap();

            let num_x1 = AllocatedNum::alloc(cs.namespace(|| "x1"), || Ok(x1)).unwrap();
            let num_y1 = AllocatedNum::alloc(cs.namespace(|| "y1"), || Ok(y1)).unwrap();

            let p1 = EdwardsPoint {
                x: num_x0,
                y: num_y0,
            };

            let p2 = EdwardsPoint {
                x: num_x1,
                y: num_y1,
            };

            let p3 = p1.add(cs.namespace(|| "addition"), &p2).unwrap();

            assert!(cs.is_satisfied());

            assert!(p3.x.get_value().unwrap() == x2);
            assert!(p3.y.get_value().unwrap() == y2);

            let u = cs.get("addition/U/num");
            cs.set("addition/U/num", bls12_381::Scalar::random(rng));
            assert_eq!(cs.which_is_unsatisfied(), Some("addition/U computation"));
            cs.set("addition/U/num", u);
            assert!(cs.is_satisfied());

            let x3 = cs.get("addition/x3/num");
            cs.set("addition/x3/num", bls12_381::Scalar::random(rng));
            assert_eq!(cs.which_is_unsatisfied(), Some("addition/x3 computation"));
            cs.set("addition/x3/num", x3);
            assert!(cs.is_satisfied());

            let y3 = cs.get("addition/y3/num");
            cs.set("addition/y3/num", bls12_381::Scalar::random(rng));
            assert_eq!(cs.which_is_unsatisfied(), Some("addition/y3 computation"));
            cs.set("addition/y3/num", y3);
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn test_edwards_doubling() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..100 {
            let p1 = jubjub::ExtendedPoint::random(rng);
            let p2 = p1.double();

            let p1 = p1.to_affine();
            let p2 = p2.to_affine();

            let (x0, y0) = (p1.get_u(), p1.get_v());
            let (x1, y1) = (p2.get_u(), p2.get_v());

            let mut cs = TestConstraintSystem::new();

            let num_x0 = AllocatedNum::alloc(cs.namespace(|| "x0"), || Ok(x0)).unwrap();
            let num_y0 = AllocatedNum::alloc(cs.namespace(|| "y0"), || Ok(y0)).unwrap();

            let p1 = EdwardsPoint {
                x: num_x0,
                y: num_y0,
            };

            let p2 = p1.double(cs.namespace(|| "doubling")).unwrap();

            assert!(cs.is_satisfied());

            assert!(p2.x.get_value().unwrap() == x1);
            assert!(p2.y.get_value().unwrap() == y1);
        }
    }

    #[test]
    fn test_montgomery_addition() {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..100 {
            let p1 = jubjub::ExtendedPoint::random(rng);
            let p2 = jubjub::ExtendedPoint::random(rng);
            let p3 = p1 + p2;

            let (x0, y0) = to_montgomery_coords(p1).unwrap();
            let (x1, y1) = to_montgomery_coords(p2).unwrap();
            let (x2, y2) = to_montgomery_coords(p3).unwrap();

            let mut cs = TestConstraintSystem::new();

            let num_x0 = AllocatedNum::alloc(cs.namespace(|| "x0"), || Ok(x0)).unwrap();
            let num_y0 = AllocatedNum::alloc(cs.namespace(|| "y0"), || Ok(y0)).unwrap();

            let num_x1 = AllocatedNum::alloc(cs.namespace(|| "x1"), || Ok(x1)).unwrap();
            let num_y1 = AllocatedNum::alloc(cs.namespace(|| "y1"), || Ok(y1)).unwrap();

            let p1 = MontgomeryPoint {
                x: num_x0.into(),
                y: num_y0.into(),
            };

            let p2 = MontgomeryPoint {
                x: num_x1.into(),
                y: num_y1.into(),
            };

            let p3 = p1.add(cs.namespace(|| "addition"), &p2).unwrap();

            assert!(cs.is_satisfied());

            assert!(p3.x.get_value().unwrap() == x2);
            assert!(p3.y.get_value().unwrap() == y2);

            cs.set("addition/yprime/num", bls12_381::Scalar::random(rng));
            assert_eq!(cs.which_is_unsatisfied(), Some("addition/evaluate yprime"));
            cs.set("addition/yprime/num", y2);
            assert!(cs.is_satisfied());

            cs.set("addition/xprime/num", bls12_381::Scalar::random(rng));
            assert_eq!(cs.which_is_unsatisfied(), Some("addition/evaluate xprime"));
            cs.set("addition/xprime/num", x2);
            assert!(cs.is_satisfied());

            cs.set("addition/lambda/num", bls12_381::Scalar::random(rng));
            assert_eq!(cs.which_is_unsatisfied(), Some("addition/evaluate lambda"));
        }
    }

    #[test]
    fn test_assert_not_small_order() {
        let check_small_order_from_p = |p: jubjub::ExtendedPoint, is_small_order| {
            let mut cs = TestConstraintSystem::new();

            let p = EdwardsPoint::witness(&mut cs, Some(p)).unwrap();
            assert!(cs.is_satisfied());
            assert!(p.assert_not_small_order(&mut cs).is_err() == is_small_order);
        };

        let check_small_order_from_strs = |x, y| {
            let (x, y) = (
                bls12_381::Scalar::from_str(x).unwrap(),
                bls12_381::Scalar::from_str(y).unwrap(),
            );
            let p = jubjub::AffinePoint::from_raw_unchecked(x, y);

            check_small_order_from_p(p.into(), true);
        };

        // zero has low order
        check_small_order_from_strs("0", "1");

        // prime subgroup order
        let prime_subgroup_order = jubjub::Fr::from_str(
            "6554484396890773809930967563523245729705921265872317281365359162392183254199",
        )
        .unwrap();
        let largest_small_subgroup_order = jubjub::Fr::from_str("8").unwrap();

        let (zero_x, zero_y) = (bls12_381::Scalar::zero(), bls12_381::Scalar::one());

        // generator for jubjub
        let (x, y) = (
            bls12_381::Scalar::from_str(
                "11076627216317271660298050606127911965867021807910416450833192264015104452986",
            )
            .unwrap(),
            bls12_381::Scalar::from_str(
                "44412834903739585386157632289020980010620626017712148233229312325549216099227",
            )
            .unwrap(),
        );
        let g = jubjub::AffinePoint::from_raw_unchecked(x, y).into();
        check_small_order_from_p(g, false);

        // generator for the prime subgroup
        let g_prime = g * largest_small_subgroup_order;
        check_small_order_from_p(g_prime.clone(), false);
        let prime_subgroup_order_minus_1 = prime_subgroup_order - jubjub::Fr::one();

        let should_not_be_zero = g_prime * prime_subgroup_order_minus_1;
        assert_ne!(zero_x, should_not_be_zero.to_affine().get_u());
        assert_ne!(zero_y, should_not_be_zero.to_affine().get_v());
        let should_be_zero = should_not_be_zero + g_prime;
        assert_eq!(zero_x, should_be_zero.to_affine().get_u());
        assert_eq!(zero_y, should_be_zero.to_affine().get_v());

        // generator for the small order subgroup
        let g_small = g * prime_subgroup_order_minus_1;
        let g_small = g_small + g;
        check_small_order_from_p(g_small.clone(), true);

        // g_small does have order 8
        let largest_small_subgroup_order_minus_1 = largest_small_subgroup_order - jubjub::Fr::one();

        let should_not_be_zero = g_small * largest_small_subgroup_order_minus_1;
        assert_ne!(zero_x, should_not_be_zero.to_affine().get_u());
        assert_ne!(zero_y, should_not_be_zero.to_affine().get_v());

        let should_be_zero = should_not_be_zero + g_small;
        assert_eq!(zero_x, should_be_zero.to_affine().get_u());
        assert_eq!(zero_y, should_be_zero.to_affine().get_v());

        // take all the points from the script
        // assert should be different than multiplying by cofactor, which is the solution
        // is user input verified? https://github.com/zcash/librustzcash/blob/f5d2afb4eabac29b1b1cc860d66e45a5b48b4f88/src/rustzcash.rs#L299
    }
}
