//! Various constants used by the Zcash primitives.

use ff::PrimeField;
use group::Group;
use jubjub::SubgroupPoint;
use lazy_static::lazy_static;

/// First 64 bytes of the BLAKE2s input during group hash.
/// This is chosen to be some random string that we couldn't have anticipated when we designed
/// the algorithm, for rigidity purposes.
/// We deliberately use an ASCII hex string of 32 bytes here.
pub const GH_FIRST_BLOCK: &[u8; 64] =
    b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

// BLAKE2s invocation personalizations
/// BLAKE2s Personalization for CRH^ivk = BLAKE2s(ak | nk)
pub const CRH_IVK_PERSONALIZATION: &[u8; 8] = b"MASP_ivk";

/// BLAKE2s Personalization for PRF^nf = BLAKE2s(nk | rho)
pub const PRF_NF_PERSONALIZATION: &[u8; 8] = b"MASP__nf";

// Group hash personalizations
/// BLAKE2s Personalization for Pedersen hash generators.
pub const PEDERSEN_HASH_GENERATORS_PERSONALIZATION: &[u8; 8] = b"MASP__PH";

/// BLAKE2s Personalization for the group hash for key diversification
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &[u8; 8] = b"MASP__gd";

/// BLAKE2s Personalization for the spending key base point
pub const SPENDING_KEY_GENERATOR_PERSONALIZATION: &[u8; 8] = b"MASP__G_";

/// BLAKE2s Personalization for the proof generation key base point
pub const PROOF_GENERATION_KEY_BASE_GENERATOR_PERSONALIZATION: &[u8; 8] = b"MASP__H_";

/// BLAKE2s Personalization for the value commitment generator for the value
pub const VALUE_COMMITMENT_GENERATOR_PERSONALIZATION: &[u8; 8] = b"MASP__v_"; //b"MASP__cv";
pub const VALUE_COMMITMENT_RANDOMNESS_PERSONALIZATION: &[u8; 8] = b"MASP__r_";

/// BLAKE2s Personalization for the nullifier position generator (for computing rho)
pub const NULLIFIER_POSITION_IN_TREE_GENERATOR_PERSONALIZATION: &[u8; 8] = b"MASP__J_";

/// Length in bytes of the asset identifier
pub const ASSET_IDENTIFIER_LENGTH: usize = 32;

/// BLAKE2s Personalization for deriving asset identifier from asset name
pub const ASSET_IDENTIFIER_PERSONALIZATION: &[u8; 8] = b"MASP__t_";

/// The prover will demonstrate knowledge of discrete log with respect to this base when
/// they are constructing a proof, in order to authorize proof construction.
pub const PROOF_GENERATION_KEY_GENERATOR: SubgroupPoint = SubgroupPoint::from_raw_unchecked(
    bls12_381::Scalar::from_raw([
        0x5f3c_723a_a253_1b66,
        0x1e24_f832_67f1_5abd,
        0x4ba1_f065_e719_fd03,
        0x4caa_eaca_af28_ed4b,
    ]),
    bls12_381::Scalar::from_raw([
        0xfe6f_96be_c575_bff8,
        0x36b4_9c71_a2af_0708,
        0xc654_dfdd_3600_4de9,
        0x0093_0d67_d690_6365,
    ]),
);

/// The note commitment is randomized over this generator.
pub const NOTE_COMMITMENT_RANDOMNESS_GENERATOR: SubgroupPoint = SubgroupPoint::from_raw_unchecked(
    bls12_381::Scalar::from_raw([
        0xfc033fa2bf88cb2e,
        0xcd80edf5fe44c7bf,
        0xc6de7556abb84082,
        0x434c9be15267b091,
    ]),
    bls12_381::Scalar::from_raw([
        0xc6b8daa0ee22aeed,
        0x690b295c66b85c64,
        0x6d277197e97af8f0,
        0x29e2926993d3bc73,
    ]),
);

/// The node commitment is randomized again by the position in order to supply the
/// nullifier computation with a unique input w.r.t. the note being spent, to prevent
/// Faerie gold attacks.
pub const NULLIFIER_POSITION_GENERATOR: SubgroupPoint = SubgroupPoint::from_raw_unchecked(
    bls12_381::Scalar::from_raw([
        0xaafee844265fc1e7,
        0x1e09674f28a4b844,
        0x84678dc2d85293df,
        0x50de6d98fee5282f,
    ]),
    bls12_381::Scalar::from_raw([
        0xed034e3ee13a1eb3,
        0x226945aee96dfe0a,
        0xf3f70dc31afe799d,
        0x03260f0bf1244050,
    ]),
);

/// The value commitment is randomized over this generator, for privacy.
pub const VALUE_COMMITMENT_RANDOMNESS_GENERATOR: SubgroupPoint = SubgroupPoint::from_raw_unchecked(
    bls12_381::Scalar::from_raw([
        0xdd93d364cb8cec7e,
        0x91cc3e3835675450,
        0xcfa86026b8d99be9,
        0x1c6da0ce9a5e5fdb,
    ]),
    bls12_381::Scalar::from_raw([
        0x28e5fce99ce692d0,
        0xf94c2daa360302fe,
        0xbc900cd4b8ae1150,
        0x555f11f9b720d50b,
    ]),
);

/// The spender proves discrete log with respect to this base at spend time.
pub const SPENDING_KEY_GENERATOR: SubgroupPoint = SubgroupPoint::from_raw_unchecked(
    bls12_381::Scalar::from_raw([
        0xec75293d81248452,
        0x39f5b03380af6020,
        0xf831c2b19fec6026,
        0x5b389522a9e81532,
    ]),
    bls12_381::Scalar::from_raw([
        0x14b62623a186b4b1,
        0x2012d031f624fd52,
        0x75defecff1f49ef2,
        0x0cbc5f9f1e52e0ab,
    ]),
);

/// The generators (for each segment) used in all Pedersen commitments.
pub const PEDERSEN_HASH_GENERATORS: &[SubgroupPoint] = &[
    SubgroupPoint::from_raw_unchecked(
        bls12_381::Scalar::from_raw([
            0x1010503570c3ebf6,
            0x5c22a82a281c9181,
            0x98ba470b0d28801b,
            0x113de62be6e0d323,
        ]),
        bls12_381::Scalar::from_raw([
            0xf031edff274efb14,
            0x2ba3032d7064d633,
            0x15cea14bc9f6b04b,
            0x5059678472abb6ae,
        ]),
    ),
    SubgroupPoint::from_raw_unchecked(
        bls12_381::Scalar::from_raw([
            0xb9efa2cb80331936,
            0x0a0df10182a290fd,
            0xfc7cbea3c311f67f,
            0x08c02a4c57f7f2cf,
        ]),
        bls12_381::Scalar::from_raw([
            0xdaf19ac3ab182662,
            0xec376560c925452d,
            0x4dc07857131f22a0,
            0x2e560a50271fd3fc,
        ]),
    ),
    SubgroupPoint::from_raw_unchecked(
        bls12_381::Scalar::from_raw([
            0xc93573b98709291e,
            0xdf0694e57c6cbc03,
            0x413bc3c44e7aabe0,
            0x210f22d61b65767d,
        ]),
        bls12_381::Scalar::from_raw([
            0x4781e2656b1ddaad,
            0xc6262ed423179659,
            0xfb33884c42727482,
            0x3f46b3371cff7474,
        ]),
    ),
    SubgroupPoint::from_raw_unchecked(
        bls12_381::Scalar::from_raw([
            0xcf0bc7224a63d094,
            0x2bcc52dbba0ebf3a,
            0xa02f0d3f7aad771d,
            0x274e99b16d4af911,
        ]),
        bls12_381::Scalar::from_raw([
            0xe82e9061620a1df4,
            0xfd0153cfe15ec653,
            0x6b15ec6e59478694,
            0x31f5e34f0804a874,
        ]),
    ),
    SubgroupPoint::from_raw_unchecked(
        bls12_381::Scalar::from_raw([
            0xc64e25ca51961b53,
            0x7058160b9afaafaf,
            0x50aa77ad2f57d2f7,
            0x3ca8b98873e5d19e,
        ]),
        bls12_381::Scalar::from_raw([
            0x9dab539b32327842,
            0x5eb152c4606beb7e,
            0x238af7c9376608d6,
            0x10609ce821a5a292,
        ]),
    ),
    SubgroupPoint::from_raw_unchecked(
        bls12_381::Scalar::from_raw([
            0xf0ef2a816469118e,
            0x5bdd5c30d83781f0,
            0xdb3ff866eaf1bc85,
            0x1ab3fe2ac6b3ff8a,
        ]),
        bls12_381::Scalar::from_raw([
            0xe7c079b4e48233f5,
            0xa6b5863148627619,
            0xd5681f2f5c740d19,
            0x2031e442c4af8277,
        ]),
    ),
];

/// The maximum number of chunks per segment of the Pedersen hash.
pub const PEDERSEN_HASH_CHUNKS_PER_GENERATOR: usize = 63;

/// The window size for exponentiation of Pedersen hash generators outside the circuit.
pub const PEDERSEN_HASH_EXP_WINDOW_SIZE: u32 = 8;

lazy_static! {
    /// The exp table for [`PEDERSEN_HASH_GENERATORS`].
    pub static ref PEDERSEN_HASH_EXP_TABLE: Vec<Vec<Vec<SubgroupPoint>>> =
        generate_pedersen_hash_exp_table();
}

/// Creates the exp table for the Pedersen hash generators.
fn generate_pedersen_hash_exp_table() -> Vec<Vec<Vec<SubgroupPoint>>> {
    let window = PEDERSEN_HASH_EXP_WINDOW_SIZE;

    PEDERSEN_HASH_GENERATORS
        .iter()
        .cloned()
        .map(|mut g| {
            let mut tables = vec![];

            let mut num_bits = 0;
            while num_bits <= jubjub::Fr::NUM_BITS {
                let mut table = Vec::with_capacity(1 << window);
                let mut base = SubgroupPoint::identity();

                for _ in 0..(1 << window) {
                    table.push(base.clone());
                    base += g;
                }

                tables.push(table);
                num_bits += window;

                for _ in 0..window {
                    g = g.double();
                }
            }

            tables
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use jubjub::SubgroupPoint;

    use super::*;
    use zcash_primitives::group_hash::group_hash;

    fn find_group_hash(m: &[u8], personalization: &[u8; 8]) -> SubgroupPoint {
        let mut tag = m.to_vec();
        let i = tag.len();
        tag.push(0u8);

        loop {
            let gh = group_hash(&tag, personalization);

            // We don't want to overflow and start reusing generators
            assert!(tag[i] != u8::max_value());
            tag[i] += 1;

            if let Some(gh) = gh {
                break gh;
            }
        }
    }

    #[test]
    fn proof_generation_key_base_generator() {
        assert_eq!(
            find_group_hash(&[], PROOF_GENERATION_KEY_BASE_GENERATOR_PERSONALIZATION),
            PROOF_GENERATION_KEY_GENERATOR,
        );
    }

    #[test]
    fn note_commitment_randomness_generator() {
        assert_eq!(
            find_group_hash(b"r", PEDERSEN_HASH_GENERATORS_PERSONALIZATION),
            NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
        );
    }

    #[test]
    fn nullifier_position_generator() {
        assert_eq!(
            find_group_hash(&[], NULLIFIER_POSITION_IN_TREE_GENERATOR_PERSONALIZATION),
            NULLIFIER_POSITION_GENERATOR,
        );
    }

    #[test]
    fn value_commitment_randomness_generator() {
        assert_eq!(
            find_group_hash(b"r", VALUE_COMMITMENT_RANDOMNESS_PERSONALIZATION),
            VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
        );
    }

    #[test]
    fn spending_key_generator() {
        assert_eq!(
            find_group_hash(&[], SPENDING_KEY_GENERATOR_PERSONALIZATION),
            SPENDING_KEY_GENERATOR,
        );
    }

    #[test]
    fn pedersen_hash_generators() {
        for (m, actual) in PEDERSEN_HASH_GENERATORS.iter().enumerate() {
            assert_eq!(
                &find_group_hash(
                    &(m as u32).to_le_bytes(),
                    PEDERSEN_HASH_GENERATORS_PERSONALIZATION
                ),
                actual
            );
        }
    }

    #[test]
    fn no_duplicate_fixed_base_generators() {
        let fixed_base_generators = [
            PROOF_GENERATION_KEY_GENERATOR,
            NOTE_COMMITMENT_RANDOMNESS_GENERATOR,
            NULLIFIER_POSITION_GENERATOR,
            VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            SPENDING_KEY_GENERATOR,
        ];

        // Check for duplicates, far worse than spec inconsistencies!
        for (i, p1) in fixed_base_generators.iter().enumerate() {
            if p1.is_identity().into() {
                panic!("Neutral element!");
            }

            for p2 in fixed_base_generators.iter().skip(i + 1) {
                if p1 == p2 {
                    panic!("Duplicate generator!");
                }
            }
        }
    }

    /// Check for simple relations between the generators, that make finding collisions easy;
    /// far worse than spec inconsistencies!
    fn check_consistency_of_pedersen_hash_generators(
        pedersen_hash_generators: &[jubjub::SubgroupPoint],
    ) {
        for (i, p1) in pedersen_hash_generators.iter().enumerate() {
            if p1.is_identity().into() {
                panic!("Neutral element!");
            }
            for p2 in pedersen_hash_generators.iter().skip(i + 1) {
                if p1 == p2 {
                    panic!("Duplicate generator!");
                }
                if *p1 == -p2 {
                    panic!("Inverse generator!");
                }
            }

            // check for a generator being the sum of any other two
            for (j, p2) in pedersen_hash_generators.iter().enumerate() {
                if j == i {
                    continue;
                }
                for (k, p3) in pedersen_hash_generators.iter().enumerate() {
                    if k == j || k == i {
                        continue;
                    }
                    let sum = p2 + p3;
                    if sum == *p1 {
                        panic!("Linear relation between generators!");
                    }
                }
            }
        }
    }

    #[test]
    fn pedersen_hash_generators_consistency() {
        check_consistency_of_pedersen_hash_generators(PEDERSEN_HASH_GENERATORS);
    }

    #[test]
    #[should_panic(expected = "Linear relation between generators!")]
    fn test_jubjub_bls12_pedersen_hash_generators_consistency_check_linear_relation() {
        let mut pedersen_hash_generators = PEDERSEN_HASH_GENERATORS.to_vec();

        // Test for linear relation
        pedersen_hash_generators.push(PEDERSEN_HASH_GENERATORS[0] + PEDERSEN_HASH_GENERATORS[1]);

        check_consistency_of_pedersen_hash_generators(&pedersen_hash_generators);
    }
}
