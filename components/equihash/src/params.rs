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
        (self.collision_bit_length() + 7) / 8
    }
    #[cfg(test)]
    pub(crate) fn hash_length(&self) -> usize {
        ((self.k as usize) + 1) * self.collision_byte_length()
    }
}
