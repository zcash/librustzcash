#[derive(Clone, Copy)]
pub(crate) struct Params {
    pub(crate) n: u32,
    pub(crate) k: u32,
}

impl Params {
    /// Returns `None` if the parameters are invalid.
    pub(crate) fn new(n: u32, k: u32) -> Option<Self> {
        // We place the following requirements on the parameters:
        // - n is a multiple of 8, so the hash output has an exact byte length.
        // - k >= 3 so the encoded solutions have an exact byte length.
        // - k < n, so the collision bit length is at least 1.
        // - n is a multiple of k + 1, so we have an integer collision bit length.
        if (n % 8 == 0) && (k >= 3) && (k < n) && (n % (k + 1) == 0) {
            Some(Params { n, k })
        } else {
            None
        }
    }
    // Floor division: the number of whole `n`-bit indices that fit in a
    // 512-bit hash output. Verified by `params::tests`.
    #[allow(clippy::integer_division)]
    pub(crate) fn indices_per_hash_output(&self) -> u32 {
        512 / self.n
    }
    // Exact division: `Params::new` guarantees `n % 8 == 0`, so
    // `indices_per_hash_output() * n` is a multiple of 8. Verified by
    // `params::tests`.
    #[allow(clippy::integer_division)]
    pub(crate) fn hash_output(&self) -> u8 {
        (self.indices_per_hash_output() * self.n / 8) as u8
    }
    // Exact division: `Params::new` guarantees `n % (k + 1) == 0`. Verified by
    // `params::tests`.
    #[allow(clippy::integer_division)]
    pub(crate) fn collision_bit_length(&self) -> usize {
        (self.n / (self.k + 1)) as usize
    }
    pub(crate) fn collision_byte_length(&self) -> usize {
        self.collision_bit_length().div_ceil(8)
    }
    #[cfg(test)]
    pub(crate) fn hash_length(&self) -> usize {
        ((self.k as usize) + 1) * self.collision_byte_length()
    }
}

#[cfg(test)]
mod tests {
    // These tests deliberately reproduce the integer-division math they verify.
    #![allow(clippy::integer_division)]

    use super::Params;

    /// The derived quantities for the parameters Zcash actually uses
    /// (`n = 200`, `k = 9`) must match the known constants.
    #[test]
    fn zcash_params_derived_values() {
        let p = Params::new(200, 9).expect("(200, 9) are valid parameters");
        assert_eq!(p.indices_per_hash_output(), 2);
        assert_eq!(p.hash_output(), 50);
        assert_eq!(p.collision_bit_length(), 20);
        assert_eq!(p.collision_byte_length(), 3);
    }

    /// Every division performed by `Params` is either exact or an intended
    /// floor. Sweep all valid small parameter sets and assert the exactness
    /// invariants the surrounding code relies on, so a future change that
    /// reintroduces truncation is caught.
    #[test]
    fn division_invariants_hold_for_valid_params() {
        let mut checked = 0u32;
        for n in 8..=256 {
            for k in 0..n {
                let Some(p) = Params::new(n, k) else { continue };
                checked += 1;

                // collision_bit_length = n / (k + 1) is exact (no truncation):
                // multiplying back recovers n exactly.
                assert_eq!(n % (k + 1), 0, "n={n} k={k}");
                assert_eq!(
                    p.collision_bit_length() as u32 * (k + 1),
                    n,
                    "collision_bit_length truncated for n={n} k={k}"
                );

                // hash_output = ipho * n / 8 is exact: ipho * n is a multiple
                // of 8 because n is.
                let ipho = p.indices_per_hash_output();
                assert!(ipho >= 1, "ipho underflowed for n={n} k={k}");
                assert_eq!((ipho * n) % 8, 0, "n={n} k={k}");
                assert_eq!(u32::from(p.hash_output()), ipho * n / 8, "n={n} k={k}");
            }
        }
        assert!(checked > 0, "no valid parameter sets were exercised");
    }

    /// `verify::Node::new` slices the hash output at byte offsets derived by
    /// integer division: `start = (i % ipho) * n / 8`, `end = start + n / 8`.
    /// For every valid parameter set and every residue, those offsets must be
    /// 8-aligned and stay within `hash_output()` bytes, i.e. the divisions
    /// never truncate into an out-of-bounds slice.
    #[test]
    fn node_byte_offsets_stay_in_bounds() {
        for n in (8..=256).step_by(8) {
            for k in 3..n {
                let Some(p) = Params::new(n, k) else { continue };
                let ipho = p.indices_per_hash_output();
                let available = u32::from(p.hash_output());
                for r in 0..ipho {
                    assert_eq!((r * n) % 8, 0, "n={n} k={k} r={r}");
                    let start = r * n / 8;
                    let end = start + n / 8;
                    assert!(
                        end <= available,
                        "n={n} k={k} r={r}: end {end} exceeds hash_output {available}"
                    );
                }
            }
        }
    }
}
