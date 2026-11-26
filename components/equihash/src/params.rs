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
        // - n <= 512, so that one 512-bit BLAKE2b output covers at least one
        //   index (`indices_per_hash_output` is `512 / n`).
        // - 8 <= n / (k + 1) < 25, so that the collision bit width fits in the
        //   byte-wise expansion of the leaf hashes (which requires at least 8
        //   bits) and the bit width of an index (collision bit width + 1) fits
        //   in the u32 accumulator used by `minimal` (which requires
        //   `7 + bit_width <= 32` bits). The upper bound subsumes the index
        //   fitting in a `u32` at all.
        //
        // Without the last two, `is_valid_solution` panics for parameter
        // sets this constructor accepts: a division by zero in the tree
        // validator when `n > 512`, and assertion failures in `minimal`
        // when an index is too wide. The C++ zcashd implementation was
        // instantiated per parameter set and so never saw these inputs.
        if n.is_multiple_of(8)
            && (k >= 3)
            && (k < n)
            && n.is_multiple_of(k + 1)
            && n <= 512
            && (8..25).contains(&(n / (k + 1)))
        {
            Some(Params { n, k })
        } else {
            None
        }
    }
    /// The minimally encoded solution length, or `None` on overflow.
    pub(crate) fn solution_bytes(&self) -> Option<usize> {
        Some(
            self.solution_indices()?
                .checked_mul(self.collision_bit_length() + 1)?
                / 8,
        )
    }
    pub(crate) fn indices_per_hash_output(&self) -> u32 {
        512 / self.n
    }
    pub(crate) fn hash_output(&self) -> u8 {
        (self.indices_per_hash_output() * self.n / 8) as u8
    }
    pub(crate) fn collision_bit_length(&self) -> usize {
        (self.n / (self.k + 1)) as usize
    }
    pub(crate) fn collision_byte_length(&self) -> usize {
        self.collision_bit_length().div_ceil(8)
    }
    pub(crate) fn solution_indices(&self) -> Option<usize> {
        1usize.checked_shl(self.k)
    }
    pub(crate) fn hash_length(&self) -> usize {
        ((self.k as usize) + 1) * self.collision_byte_length()
    }
}
