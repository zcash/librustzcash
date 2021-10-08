#[cfg(all(test, feature = "std"))]
pub(crate) struct TestVector {
    pub(crate) length: usize,
    pub(crate) jumbled_hash: &'static [u8],
}

// From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/f4jumble_long.py
#[cfg(all(test, feature = "std"))]
pub(crate) const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        length: 3246395,
        jumbled_hash: &[
            0x3f, 0xc2, 0xec, 0xdf, 0xb6, 0x86, 0x96, 0x57, 0x1d, 0x89, 0xe8, 0xbe, 0xdd, 0xb6,
            0x47, 0xe6, 0x99, 0x0b, 0x63, 0xa0, 0x17, 0x1c, 0x36, 0x44, 0x22, 0x73, 0xd6, 0x87,
            0xbd, 0x99, 0x25, 0x7e, 0xc5, 0x00, 0x2e, 0xc8, 0x19, 0x78, 0x01, 0xb6, 0x21, 0x73,
            0x2d, 0x6b, 0x05, 0xb8, 0xd7, 0x0f, 0x68, 0x86, 0x20, 0xa4, 0xc0, 0x88, 0x73, 0xc1,
            0x2e, 0x44, 0x39, 0xa0, 0x12, 0x7d, 0xc9, 0x45,
        ],
    },
    TestVector {
        length: 4194368,
        jumbled_hash: &[
            0xa5, 0xf1, 0x8f, 0x16, 0x3e, 0x59, 0x8d, 0x4a, 0xdb, 0x6e, 0xa7, 0x24, 0x80, 0x57,
            0xe2, 0x4c, 0x1b, 0x61, 0xf2, 0x9b, 0x33, 0xb7, 0xab, 0xcd, 0xab, 0xd4, 0x20, 0xa0,
            0xf2, 0xee, 0x6c, 0x3e, 0xd3, 0x13, 0x94, 0x65, 0x2f, 0x28, 0xb5, 0x9c, 0x44, 0xd3,
            0xea, 0x9e, 0xcf, 0x85, 0xf4, 0xd5, 0x01, 0xe6, 0xaa, 0xc1, 0x4d, 0xf2, 0x88, 0xef,
            0xd6, 0x2c, 0xf8, 0x0d, 0x18, 0x29, 0xd0, 0x25,
        ],
    },
];
