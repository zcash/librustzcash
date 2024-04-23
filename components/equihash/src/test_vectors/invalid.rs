use crate::{params::Params, verify::Kind};

pub(crate) struct TestVector {
    pub(crate) params: Params,
    pub(crate) input: &'static [u8],
    pub(crate) nonce: [u8; 32],
    pub(crate) solution: &'static [u32],
    pub(crate) error: Kind,
}

pub(crate) const INVALID_TEST_VECTORS: &[TestVector] = &[
    // Original valid solution: [
    //     2261, 15185, 36112, 104243, 23779, 118390, 118332, 130041, 32642, 69878, 76925, 80080,
    //     45858, 116805, 92842, 111026, 15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
    //     23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568,
    // ]

    // Change one index
    TestVector {
        params: Params { n: 96, k: 5 },
        input: b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
        nonce: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        solution: &[
            2262, 15185, 36112, 104243, 23779, 118390, 118332, 130041, 32642, 69878, 76925, 80080,
            45858, 116805, 92842, 111026, 15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
            23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568,
        ],
        error: Kind::Collision,
    },
    // Swap two arbitrary indices
    TestVector {
        params: Params { n: 96, k: 5 },
        input: b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
        nonce: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        solution: &[
            45858, 15185, 36112, 104243, 23779, 118390, 118332, 130041, 32642, 69878, 76925, 80080,
            2261, 116805, 92842, 111026, 15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
            23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568,
        ],
        error: Kind::Collision,
    },
    // Reverse the first pair of indices
    TestVector {
        params: Params { n: 96, k: 5 },
        input: b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
        nonce: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        solution: &[
            15185, 2261, 36112, 104243, 23779, 118390, 118332, 130041, 32642, 69878, 76925, 80080,
            45858, 116805, 92842, 111026, 15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
            23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568,
        ],
        error: Kind::OutOfOrder,
    },
    // Swap the first and second pairs of indices
    TestVector {
        params: Params { n: 96, k: 5 },
        input: b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
        nonce: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        solution: &[
            36112, 104243, 2261, 15185, 23779, 118390, 118332, 130041, 32642, 69878, 76925, 80080,
            45858, 116805, 92842, 111026, 15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
            23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568,
        ],
        error: Kind::OutOfOrder,
    },
    // Swap the second-to-last and last pairs of indices
    TestVector {
        params: Params { n: 96, k: 5 },
        input: b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
        nonce: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        solution: &[
            2261, 15185, 36112, 104243, 23779, 118390, 118332, 130041, 32642, 69878, 76925, 80080,
            45858, 116805, 92842, 111026, 15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
            23460, 49807, 52426, 80391, 104973, 122568, 69567, 114474,
        ],
        error: Kind::OutOfOrder,
    },
    // Swap the first half and second half
    TestVector {
        params: Params { n: 96, k: 5 },
        input: b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
        nonce: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        solution: &[
            15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132, 23460, 49807, 52426, 80391,
            69567, 114474, 104973, 122568, 2261, 15185, 36112, 104243, 23779, 118390, 118332,
            130041, 32642, 69878, 76925, 80080, 45858, 116805, 92842, 111026,
        ],
        error: Kind::OutOfOrder,
    },
    // Sort the indices
    TestVector {
        params: Params { n: 96, k: 5 },
        input: b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
        nonce: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        solution: &[
            2261, 15185, 15972, 23460, 23779, 32642, 36112, 45858, 49807, 52426, 68190, 69567,
            69878, 76925, 80080, 80391, 81830, 85191, 90330, 91132, 92842, 104243, 104973, 111026,
            114474, 115059, 116805, 118332, 118390, 122568, 122819, 130041,
        ],
        error: Kind::Collision,
    },
    // Duplicate indices
    TestVector {
        params: Params { n: 96, k: 5 },
        input: b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
        nonce: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        solution: &[
            2261, 2261, 15185, 15185, 36112, 36112, 104243, 104243, 23779, 23779, 118390, 118390,
            118332, 118332, 130041, 130041, 32642, 32642, 69878, 69878, 76925, 76925, 80080, 80080,
            45858, 45858, 116805, 116805, 92842, 92842, 111026, 111026,
        ],
        error: Kind::DuplicateIdxs,
    },
    // Duplicate first half
    TestVector {
        params: Params { n: 96, k: 5 },
        input: b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.",
        nonce: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        solution: &[
            2261, 15185, 36112, 104243, 23779, 118390, 118332, 130041, 32642, 69878, 76925, 80080,
            45858, 116805, 92842, 111026, 2261, 15185, 36112, 104243, 23779, 118390, 118332,
            130041, 32642, 69878, 76925, 80080, 45858, 116805, 92842, 111026,
        ],
        error: Kind::DuplicateIdxs,
    },
];
