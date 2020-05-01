use super::fq2::Fq2;
use ff::{Field, PrimeField};
use std::ops::{AddAssign, MulAssign, SubAssign};

#[cfg(test)]
use ff::PowVartime;
#[cfg(test)]
use std::ops::Neg;

// B coefficient of BLS12-381 curve, 4.
pub const B_COEFF: Fq = Fq([
    0xaa270000000cfff3,
    0x53cc0032fc34000a,
    0x478fe97a6b0a807f,
    0xb1d37ebee6ba24d7,
    0x8ec9733bbf78ab2f,
    0x9d645513d83de7e,
]);

// The generators of G1/G2 are computed by finding the lexicographically smallest valid x coordinate,
// and its lexicographically smallest y coordinate and multiplying it by the cofactor such that the
// result is nonzero.

// Generator of G1
// x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
// y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
pub const G1_GENERATOR_X: Fq = Fq([
    0x5cb38790fd530c16,
    0x7817fc679976fff5,
    0x154f95c7143ba1c1,
    0xf0ae6acdf3d0e747,
    0xedce6ecc21dbf440,
    0x120177419e0bfb75,
]);
pub const G1_GENERATOR_Y: Fq = Fq([
    0xbaac93d50ce72271,
    0x8c22631a7918fd8e,
    0xdd595f13570725ce,
    0x51ac582950405194,
    0xe1c8c3fad0059c0,
    0xbbc3efc5008a26a,
]);

// Generator of G2
// x = 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758*u + 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160
// y = 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582*u + 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905
pub const G2_GENERATOR_X_C0: Fq = Fq([
    0xf5f28fa202940a10,
    0xb3f5fb2687b4961a,
    0xa1a893b53e2ae580,
    0x9894999d1a3caee9,
    0x6f67b7631863366b,
    0x58191924350bcd7,
]);
pub const G2_GENERATOR_X_C1: Fq = Fq([
    0xa5a9c0759e23f606,
    0xaaa0c59dbccd60c3,
    0x3bb17e18e2867806,
    0x1b1ab6cc8541b367,
    0xc2b6ed0ef2158547,
    0x11922a097360edf3,
]);
pub const G2_GENERATOR_Y_C0: Fq = Fq([
    0x4c730af860494c4a,
    0x597cfa1f5e369c5a,
    0xe7e6856caa0a635a,
    0xbbefb5e96e0d495f,
    0x7d3a975f0ef25a2,
    0x83fd8e7e80dae5,
]);
pub const G2_GENERATOR_Y_C1: Fq = Fq([
    0xadc0fc92df64b05d,
    0x18aa270a2b1461dc,
    0x86adac6a3be4eba0,
    0x79495c4ec93da33a,
    0xe7175850a43ccaed,
    0xb2bc2a163de1bf2,
]);

// Coefficients for the Frobenius automorphism.
pub const FROBENIUS_COEFF_FQ2_C1: [Fq; 2] = [
    // Fq(-1)**(((q^0) - 1) / 2)
    Fq([
        0x760900000002fffd,
        0xebf4000bc40c0002,
        0x5f48985753c758ba,
        0x77ce585370525745,
        0x5c071a97a256ec6d,
        0x15f65ec3fa80e493,
    ]),
    // Fq(-1)**(((q^1) - 1) / 2)
    Fq([
        0x43f5fffffffcaaae,
        0x32b7fff2ed47fffd,
        0x7e83a49a2e99d69,
        0xeca8f3318332bb7a,
        0xef148d1ea0f4c069,
        0x40ab3263eff0206,
    ]),
];

pub const FROBENIUS_COEFF_FQ6_C1: [Fq2; 6] = [
    // Fq2(u + 1)**(((q^0) - 1) / 3)
    Fq2 {
        c0: Fq([
            0x760900000002fffd,
            0xebf4000bc40c0002,
            0x5f48985753c758ba,
            0x77ce585370525745,
            0x5c071a97a256ec6d,
            0x15f65ec3fa80e493,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((q^1) - 1) / 3)
    Fq2 {
        c0: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
        c1: Fq([
            0xcd03c9e48671f071,
            0x5dab22461fcda5d2,
            0x587042afd3851b95,
            0x8eb60ebe01bacb9e,
            0x3f97d6e83d050d2,
            0x18f0206554638741,
        ]),
    },
    // Fq2(u + 1)**(((q^2) - 1) / 3)
    Fq2 {
        c0: Fq([
            0x30f1361b798a64e8,
            0xf3b8ddab7ece5a2a,
            0x16a8ca3ac61577f7,
            0xc26a2ff874fd029b,
            0x3636b76660701c6e,
            0x51ba4ab241b6160,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((q^3) - 1) / 3)
    Fq2 {
        c0: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
        c1: Fq([
            0x760900000002fffd,
            0xebf4000bc40c0002,
            0x5f48985753c758ba,
            0x77ce585370525745,
            0x5c071a97a256ec6d,
            0x15f65ec3fa80e493,
        ]),
    },
    // Fq2(u + 1)**(((q^4) - 1) / 3)
    Fq2 {
        c0: Fq([
            0xcd03c9e48671f071,
            0x5dab22461fcda5d2,
            0x587042afd3851b95,
            0x8eb60ebe01bacb9e,
            0x3f97d6e83d050d2,
            0x18f0206554638741,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((q^5) - 1) / 3)
    Fq2 {
        c0: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
        c1: Fq([
            0x30f1361b798a64e8,
            0xf3b8ddab7ece5a2a,
            0x16a8ca3ac61577f7,
            0xc26a2ff874fd029b,
            0x3636b76660701c6e,
            0x51ba4ab241b6160,
        ]),
    },
];

pub const FROBENIUS_COEFF_FQ6_C2: [Fq2; 6] = [
    // Fq2(u + 1)**(((2q^0) - 2) / 3)
    Fq2 {
        c0: Fq([
            0x760900000002fffd,
            0xebf4000bc40c0002,
            0x5f48985753c758ba,
            0x77ce585370525745,
            0x5c071a97a256ec6d,
            0x15f65ec3fa80e493,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((2q^1) - 2) / 3)
    Fq2 {
        c0: Fq([
            0x890dc9e4867545c3,
            0x2af322533285a5d5,
            0x50880866309b7e2c,
            0xa20d1b8c7e881024,
            0x14e4f04fe2db9068,
            0x14e56d3f1564853a,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((2q^2) - 2) / 3)
    Fq2 {
        c0: Fq([
            0xcd03c9e48671f071,
            0x5dab22461fcda5d2,
            0x587042afd3851b95,
            0x8eb60ebe01bacb9e,
            0x3f97d6e83d050d2,
            0x18f0206554638741,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((2q^3) - 2) / 3)
    Fq2 {
        c0: Fq([
            0x43f5fffffffcaaae,
            0x32b7fff2ed47fffd,
            0x7e83a49a2e99d69,
            0xeca8f3318332bb7a,
            0xef148d1ea0f4c069,
            0x40ab3263eff0206,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((2q^4) - 2) / 3)
    Fq2 {
        c0: Fq([
            0x30f1361b798a64e8,
            0xf3b8ddab7ece5a2a,
            0x16a8ca3ac61577f7,
            0xc26a2ff874fd029b,
            0x3636b76660701c6e,
            0x51ba4ab241b6160,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((2q^5) - 2) / 3)
    Fq2 {
        c0: Fq([
            0xecfb361b798dba3a,
            0xc100ddb891865a2c,
            0xec08ff1232bda8e,
            0xd5c13cc6f1ca4721,
            0x47222a47bf7b5c04,
            0x110f184e51c5f59,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
];

// non_residue^((modulus^i-1)/6) for i=0,...,11
pub const FROBENIUS_COEFF_FQ12_C1: [Fq2; 12] = [
    // Fq2(u + 1)**(((q^0) - 1) / 6)
    Fq2 {
        c0: Fq([
            0x760900000002fffd,
            0xebf4000bc40c0002,
            0x5f48985753c758ba,
            0x77ce585370525745,
            0x5c071a97a256ec6d,
            0x15f65ec3fa80e493,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((q^1) - 1) / 6)
    Fq2 {
        c0: Fq([
            0x7089552b319d465,
            0xc6695f92b50a8313,
            0x97e83cccd117228f,
            0xa35baecab2dc29ee,
            0x1ce393ea5daace4d,
            0x8f2220fb0fb66eb,
        ]),
        c1: Fq([
            0xb2f66aad4ce5d646,
            0x5842a06bfc497cec,
            0xcf4895d42599d394,
            0xc11b9cba40a8e8d0,
            0x2e3813cbe5a0de89,
            0x110eefda88847faf,
        ]),
    },
    // Fq2(u + 1)**(((q^2) - 1) / 6)
    Fq2 {
        c0: Fq([
            0xecfb361b798dba3a,
            0xc100ddb891865a2c,
            0xec08ff1232bda8e,
            0xd5c13cc6f1ca4721,
            0x47222a47bf7b5c04,
            0x110f184e51c5f59,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((q^3) - 1) / 6)
    Fq2 {
        c0: Fq([
            0x3e2f585da55c9ad1,
            0x4294213d86c18183,
            0x382844c88b623732,
            0x92ad2afd19103e18,
            0x1d794e4fac7cf0b9,
            0xbd592fc7d825ec8,
        ]),
        c1: Fq([
            0x7bcfa7a25aa30fda,
            0xdc17dec12a927e7c,
            0x2f088dd86b4ebef1,
            0xd1ca2087da74d4a7,
            0x2da2596696cebc1d,
            0xe2b7eedbbfd87d2,
        ]),
    },
    // Fq2(u + 1)**(((q^4) - 1) / 6)
    Fq2 {
        c0: Fq([
            0x30f1361b798a64e8,
            0xf3b8ddab7ece5a2a,
            0x16a8ca3ac61577f7,
            0xc26a2ff874fd029b,
            0x3636b76660701c6e,
            0x51ba4ab241b6160,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((q^5) - 1) / 6)
    Fq2 {
        c0: Fq([
            0x3726c30af242c66c,
            0x7c2ac1aad1b6fe70,
            0xa04007fbba4b14a2,
            0xef517c3266341429,
            0x95ba654ed2226b,
            0x2e370eccc86f7dd,
        ]),
        c1: Fq([
            0x82d83cf50dbce43f,
            0xa2813e53df9d018f,
            0xc6f0caa53c65e181,
            0x7525cf528d50fe95,
            0x4a85ed50f4798a6b,
            0x171da0fd6cf8eebd,
        ]),
    },
    // Fq2(u + 1)**(((q^6) - 1) / 6)
    Fq2 {
        c0: Fq([
            0x43f5fffffffcaaae,
            0x32b7fff2ed47fffd,
            0x7e83a49a2e99d69,
            0xeca8f3318332bb7a,
            0xef148d1ea0f4c069,
            0x40ab3263eff0206,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((q^7) - 1) / 6)
    Fq2 {
        c0: Fq([
            0xb2f66aad4ce5d646,
            0x5842a06bfc497cec,
            0xcf4895d42599d394,
            0xc11b9cba40a8e8d0,
            0x2e3813cbe5a0de89,
            0x110eefda88847faf,
        ]),
        c1: Fq([
            0x7089552b319d465,
            0xc6695f92b50a8313,
            0x97e83cccd117228f,
            0xa35baecab2dc29ee,
            0x1ce393ea5daace4d,
            0x8f2220fb0fb66eb,
        ]),
    },
    // Fq2(u + 1)**(((q^8) - 1) / 6)
    Fq2 {
        c0: Fq([
            0xcd03c9e48671f071,
            0x5dab22461fcda5d2,
            0x587042afd3851b95,
            0x8eb60ebe01bacb9e,
            0x3f97d6e83d050d2,
            0x18f0206554638741,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((q^9) - 1) / 6)
    Fq2 {
        c0: Fq([
            0x7bcfa7a25aa30fda,
            0xdc17dec12a927e7c,
            0x2f088dd86b4ebef1,
            0xd1ca2087da74d4a7,
            0x2da2596696cebc1d,
            0xe2b7eedbbfd87d2,
        ]),
        c1: Fq([
            0x3e2f585da55c9ad1,
            0x4294213d86c18183,
            0x382844c88b623732,
            0x92ad2afd19103e18,
            0x1d794e4fac7cf0b9,
            0xbd592fc7d825ec8,
        ]),
    },
    // Fq2(u + 1)**(((q^10) - 1) / 6)
    Fq2 {
        c0: Fq([
            0x890dc9e4867545c3,
            0x2af322533285a5d5,
            0x50880866309b7e2c,
            0xa20d1b8c7e881024,
            0x14e4f04fe2db9068,
            0x14e56d3f1564853a,
        ]),
        c1: Fq([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]),
    },
    // Fq2(u + 1)**(((q^11) - 1) / 6)
    Fq2 {
        c0: Fq([
            0x82d83cf50dbce43f,
            0xa2813e53df9d018f,
            0xc6f0caa53c65e181,
            0x7525cf528d50fe95,
            0x4a85ed50f4798a6b,
            0x171da0fd6cf8eebd,
        ]),
        c1: Fq([
            0x3726c30af242c66c,
            0x7c2ac1aad1b6fe70,
            0xa04007fbba4b14a2,
            0xef517c3266341429,
            0x95ba654ed2226b,
            0x2e370eccc86f7dd,
        ]),
    },
];

// -((2**384) mod q) mod q
pub const NEGATIVE_ONE: Fq = Fq([
    0x43f5fffffffcaaae,
    0x32b7fff2ed47fffd,
    0x7e83a49a2e99d69,
    0xeca8f3318332bb7a,
    0xef148d1ea0f4c069,
    0x40ab3263eff0206,
]);

#[derive(PrimeField)]
#[PrimeFieldModulus = "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787"]
#[PrimeFieldGenerator = "2"]
#[PrimeFieldReprEndianness = "big"]
pub struct Fq([u64; 6]);

#[test]
fn test_b_coeff() {
    assert_eq!(Fq::from(4), B_COEFF);
}

#[test]
#[allow(clippy::cognitive_complexity)]
fn test_frob_coeffs() {
    let nqr = Fq::one().neg();

    assert_eq!(FROBENIUS_COEFF_FQ2_C1[0], Fq::one());
    assert_eq!(
        FROBENIUS_COEFF_FQ2_C1[1],
        nqr.pow_vartime([
            0xdcff7fffffffd555u64,
            0xf55ffff58a9ffff,
            0xb39869507b587b12,
            0xb23ba5c279c2895f,
            0x258dd3db21a5d66b,
            0xd0088f51cbff34d
        ])
    );

    let nqr = Fq2 {
        c0: Fq::one(),
        c1: Fq::one(),
    };

    assert_eq!(FROBENIUS_COEFF_FQ6_C1[0], Fq2::one());
    assert_eq!(
        FROBENIUS_COEFF_FQ6_C1[1],
        nqr.pow_vartime([
            0x9354ffffffffe38eu64,
            0xa395554e5c6aaaa,
            0xcd104635a790520c,
            0xcc27c3d6fbd7063f,
            0x190937e76bc3e447,
            0x8ab05f8bdd54cde
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ6_C1[2],
        nqr.pow_vartime([
            0xb78e0000097b2f68u64,
            0xd44f23b47cbd64e3,
            0x5cb9668120b069a9,
            0xccea85f9bf7b3d16,
            0xdba2c8d7adb356d,
            0x9cd75ded75d7429,
            0xfc65c31103284fab,
            0xc58cb9a9b249ee24,
            0xccf734c3118a2e9a,
            0xa0f4304c5a256ce6,
            0xc3f0d2f8e0ba61f8,
            0xe167e192ebca97
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ6_C1[3],
        nqr.pow_vartime([
            0xdbc6fcd6f35b9e06u64,
            0x997dead10becd6aa,
            0x9dbbd24c17206460,
            0x72b97acc6057c45e,
            0xf8e9a230bf0c628e,
            0x647ccb1885c63a7,
            0xce80264fc55bf6ee,
            0x94d8d716c3939fc4,
            0xad78f0eb77ee6ee1,
            0xd6fe49bfe57dc5f9,
            0x2656d6c15c63647,
            0xdf6282f111fa903,
            0x1bdba63e0632b4bb,
            0x6883597bcaa505eb,
            0xa56d4ec90c34a982,
            0x7e4c42823bbe90b2,
            0xf64728aa6dcb0f20,
            0x16e57e16ef152f
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ6_C1[4],
        nqr.pow_vartime([
            0x4649add3c71c6d90u64,
            0x43caa6528972a865,
            0xcda8445bbaaa0fbb,
            0xc93dea665662aa66,
            0x2863bc891834481d,
            0x51a0c3f5d4ccbed8,
            0x9210e660f90ccae9,
            0xe2bd6836c546d65e,
            0xf223abbaa7cf778b,
            0xd4f10b222cf11680,
            0xd540f5eff4a1962e,
            0xa123a1f140b56526,
            0x31ace500636a59f6,
            0x3a82bc8c8dfa57a9,
            0x648c511e217fc1f8,
            0x36c17ffd53a4558f,
            0x881bef5fd684eefd,
            0x5d648dbdc5dbb522,
            0x8fd07bf06e5e59b8,
            0x8ddec8a9acaa4b51,
            0x4cc1f8688e2def26,
            0xa74e63cb492c03de,
            0x57c968173d1349bb,
            0x253674e02a866
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ6_C1[5],
        nqr.pow_vartime([
            0xf896f792732eb2beu64,
            0x49c86a6d1dc593a1,
            0xe5b31e94581f91c3,
            0xe3da5cc0a6b20d7f,
            0x822caef950e0bfed,
            0x317ed950b9ee67cd,
            0xffd664016ee3f6cd,
            0x77d991c88810b122,
            0x62e72e635e698264,
            0x905e1a1a2d22814a,
            0xf5b7ab3a3f33d981,
            0x175871b0bc0e25dd,
            0x1e2e9a63df5c3772,
            0xe888b1f7445b149d,
            0x9551c19e5e7e2c24,
            0xecf21939a3d2d6be,
            0xd830dbfdab72dbd4,
            0x7b34af8d622d40c0,
            0x3df6d20a45671242,
            0xaf86bee30e21d98,
            0x41064c1534e5df5d,
            0xf5f6cabd3164c609,
            0xa5d14bdf2b7ee65,
            0xa718c069defc9138,
            0xdb1447e770e3110e,
            0xc1b164a9e90af491,
            0x7180441f9d251602,
            0x1fd3a5e6a9a893e,
            0x1e17b779d54d5db,
            0x3c7afafe3174
        ])
    );

    assert_eq!(FROBENIUS_COEFF_FQ6_C2[0], Fq2::one());
    assert_eq!(
        FROBENIUS_COEFF_FQ6_C2[1],
        nqr.pow_vartime([
            0x26a9ffffffffc71cu64,
            0x1472aaa9cb8d5555,
            0x9a208c6b4f20a418,
            0x984f87adf7ae0c7f,
            0x32126fced787c88f,
            0x11560bf17baa99bc
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ6_C2[2],
        nqr.pow_vartime([
            0x6f1c000012f65ed0u64,
            0xa89e4768f97ac9c7,
            0xb972cd024160d353,
            0x99d50bf37ef67a2c,
            0x1b74591af5b66adb,
            0x139aebbdaebae852,
            0xf8cb862206509f56,
            0x8b1973536493dc49,
            0x99ee698623145d35,
            0x41e86098b44ad9cd,
            0x87e1a5f1c174c3f1,
            0x1c2cfc325d7952f
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ6_C2[3],
        nqr.pow_vartime([
            0xb78df9ade6b73c0cu64,
            0x32fbd5a217d9ad55,
            0x3b77a4982e40c8c1,
            0xe572f598c0af88bd,
            0xf1d344617e18c51c,
            0xc8f996310b8c74f,
            0x9d004c9f8ab7eddc,
            0x29b1ae2d87273f89,
            0x5af1e1d6efdcddc3,
            0xadfc937fcafb8bf3,
            0x4cadad82b8c6c8f,
            0x1bec505e223f5206,
            0x37b74c7c0c656976,
            0xd106b2f7954a0bd6,
            0x4ada9d9218695304,
            0xfc988504777d2165,
            0xec8e5154db961e40,
            0x2dcafc2dde2a5f
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ6_C2[4],
        nqr.pow_vartime([
            0x8c935ba78e38db20u64,
            0x87954ca512e550ca,
            0x9b5088b775541f76,
            0x927bd4ccacc554cd,
            0x50c779123068903b,
            0xa34187eba9997db0,
            0x2421ccc1f21995d2,
            0xc57ad06d8a8dacbd,
            0xe44757754f9eef17,
            0xa9e2164459e22d01,
            0xaa81ebdfe9432c5d,
            0x424743e2816aca4d,
            0x6359ca00c6d4b3ed,
            0x750579191bf4af52,
            0xc918a23c42ff83f0,
            0x6d82fffaa748ab1e,
            0x1037debfad09ddfa,
            0xbac91b7b8bb76a45,
            0x1fa0f7e0dcbcb370,
            0x1bbd9153595496a3,
            0x9983f0d11c5bde4d,
            0x4e9cc796925807bc,
            0xaf92d02e7a269377,
            0x4a6ce9c0550cc
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ6_C2[5],
        nqr.pow_vartime([
            0xf12def24e65d657cu64,
            0x9390d4da3b8b2743,
            0xcb663d28b03f2386,
            0xc7b4b9814d641aff,
            0x4595df2a1c17fdb,
            0x62fdb2a173dccf9b,
            0xffacc802ddc7ed9a,
            0xefb3239110216245,
            0xc5ce5cc6bcd304c8,
            0x20bc34345a450294,
            0xeb6f56747e67b303,
            0x2eb0e361781c4bbb,
            0x3c5d34c7beb86ee4,
            0xd11163ee88b6293a,
            0x2aa3833cbcfc5849,
            0xd9e4327347a5ad7d,
            0xb061b7fb56e5b7a9,
            0xf6695f1ac45a8181,
            0x7beda4148ace2484,
            0x15f0d7dc61c43b30,
            0x820c982a69cbbeba,
            0xebed957a62c98c12,
            0x14ba297be56fdccb,
            0x4e3180d3bdf92270,
            0xb6288fcee1c6221d,
            0x8362c953d215e923,
            0xe300883f3a4a2c05,
            0x3fa74bcd535127c,
            0x3c2f6ef3aa9abb6,
            0x78f5f5fc62e8
        ])
    );

    assert_eq!(FROBENIUS_COEFF_FQ12_C1[0], Fq2::one());
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[1],
        nqr.pow_vartime([
            0x49aa7ffffffff1c7u64,
            0x51caaaa72e35555,
            0xe688231ad3c82906,
            0xe613e1eb7deb831f,
            0xc849bf3b5e1f223,
            0x45582fc5eeaa66f
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[2],
        nqr.pow_vartime([
            0xdbc7000004bd97b4u64,
            0xea2791da3e5eb271,
            0x2e5cb340905834d4,
            0xe67542fcdfbd9e8b,
            0x86dd1646bd6d9ab6,
            0x84e6baef6baeba14,
            0x7e32e188819427d5,
            0x62c65cd4d924f712,
            0x667b9a6188c5174d,
            0x507a18262d12b673,
            0xe1f8697c705d30fc,
            0x70b3f0c975e54b
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[3],
        nqr.pow_vartime(vec![
            0x6de37e6b79adcf03u64,
            0x4cbef56885f66b55,
            0x4edde9260b903230,
            0x395cbd66302be22f,
            0xfc74d1185f863147,
            0x323e658c42e31d3,
            0x67401327e2adfb77,
            0xca6c6b8b61c9cfe2,
            0xd6bc7875bbf73770,
            0xeb7f24dff2bee2fc,
            0x8132b6b60ae31b23,
            0x86fb1417888fd481,
            0x8dedd31f03195a5d,
            0x3441acbde55282f5,
            0x52b6a764861a54c1,
            0x3f2621411ddf4859,
            0xfb23945536e58790,
            0xb72bf0b778a97,
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[4],
        nqr.pow_vartime(vec![
            0xa324d6e9e38e36c8u64,
            0xa1e5532944b95432,
            0x66d4222ddd5507dd,
            0xe49ef5332b315533,
            0x1431de448c1a240e,
            0xa8d061faea665f6c,
            0x490873307c866574,
            0xf15eb41b62a36b2f,
            0x7911d5dd53e7bbc5,
            0x6a78859116788b40,
            0x6aa07af7fa50cb17,
            0x5091d0f8a05ab293,
            0x98d6728031b52cfb,
            0x1d415e4646fd2bd4,
            0xb246288f10bfe0fc,
            0x9b60bffea9d22ac7,
            0x440df7afeb42777e,
            0x2eb246dee2edda91,
            0xc7e83df8372f2cdc,
            0x46ef6454d65525a8,
            0x2660fc344716f793,
            0xd3a731e5a49601ef,
            0x2be4b40b9e89a4dd,
            0x129b3a7015433,
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[5],
        nqr.pow_vartime(vec![
            0xfc4b7bc93997595fu64,
            0xa4e435368ee2c9d0,
            0xf2d98f4a2c0fc8e1,
            0xf1ed2e60535906bf,
            0xc116577ca8705ff6,
            0x98bf6ca85cf733e6,
            0x7feb3200b771fb66,
            0x3becc8e444085891,
            0x31739731af34c132,
            0xc82f0d0d169140a5,
            0xfadbd59d1f99ecc0,
            0xbac38d85e0712ee,
            0x8f174d31efae1bb9,
            0x744458fba22d8a4e,
            0x4aa8e0cf2f3f1612,
            0x76790c9cd1e96b5f,
            0x6c186dfed5b96dea,
            0x3d9a57c6b116a060,
            0x1efb690522b38921,
            0x857c35f718710ecc,
            0xa083260a9a72efae,
            0xfafb655e98b26304,
            0x52e8a5ef95bf732,
            0x538c6034ef7e489c,
            0xed8a23f3b8718887,
            0x60d8b254f4857a48,
            0x38c0220fce928b01,
            0x80fe9d2f354d449f,
            0xf0bdbbceaa6aed,
            0x1e3d7d7f18ba,
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[6],
        nqr.pow_vartime(vec![
            0x21219610a012ba3cu64,
            0xa5c19ad35375325,
            0x4e9df1e497674396,
            0xfb05b717c991c6ef,
            0x4a1265bca93a32f2,
            0xd875ff2a7bdc1f66,
            0xc6d8754736c771b2,
            0x2d80c759ba5a2ae7,
            0x138a20df4b03cc1a,
            0xc22d07fe68e93024,
            0xd1dc474d3b433133,
            0xc22aa5e75044e5c,
            0xf657c6fbf9c17ebf,
            0xc591a794a58660d,
            0x2261850ee1453281,
            0xd17d3bd3b7f5efb4,
            0xf00cec8ec507d01,
            0x2a6a775657a00ae6,
            0x5f098a12ff470719,
            0x409d194e7b5c5afa,
            0x1d66478e982af5b,
            0xda425a5b5e01ca3f,
            0xf77e4f78747e903c,
            0x177d49f73732c6fc,
            0xa9618fecabe0e1f4,
            0xba5337eac90bd080,
            0x66fececdbc35d4e7,
            0xa4cd583203d9206f,
            0x98391632ceeca596,
            0x4946b76e1236ad3f,
            0xa0dec64e60e711a1,
            0xfcb41ed3605013,
            0x8ca8f9692ae1e3a9,
            0xd3078bfc28cc1baf,
            0xf0536f764e982f82,
            0x3125f1a2656,
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[7],
        nqr.pow_vartime(vec![
            0x742754a1f22fdbu64,
            0x2a1955c2dec3a702,
            0x9747b28c796d134e,
            0xc113a0411f59db79,
            0x3bb0fa929853bfc1,
            0x28c3c25f8f6fb487,
            0xbc2b6c99d3045b34,
            0x98fb67d6badde1fd,
            0x48841d76a24d2073,
            0xd49891145fe93ae6,
            0xc772b9c8e74d4099,
            0xccf4e7b9907755bb,
            0x9cf47b25d42fd908,
            0x5616a0c347fc445d,
            0xff93b7a7ad1b8a6d,
            0xac2099256b78a77a,
            0x7804a95b02892e1c,
            0x5cf59ca7bfd69776,
            0xa7023502acd3c866,
            0xc76f4982fcf8f37,
            0x51862a5a57ac986e,
            0x38b80ed72b1b1023,
            0x4a291812066a61e1,
            0xcd8a685eff45631,
            0x3f40f708764e4fa5,
            0x8aa0441891285092,
            0x9eff60d71cdf0a9,
            0x4fdd9d56517e2bfa,
            0x1f3c80d74a28bc85,
            0x24617417c064b648,
            0x7ddda1e4385d5088,
            0xf9e132b11dd32a16,
            0xcc957cb8ef66ab99,
            0xd4f206d37cb752c5,
            0x40de343f28ad616b,
            0x8d1f24379068f0e3,
            0x6f31d7947ea21137,
            0x27311f9c32184061,
            0x9eea0664cc78ce5f,
            0x7d4151f6fea9a0da,
            0x454096fa75bd571a,
            0x4fe0f20ecb,
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[8],
        nqr.pow_vartime(vec![
            0x802f5720d0b25710u64,
            0x6714f0a258b85c7c,
            0x31394c90afdf16e,
            0xe9d2b0c64f957b19,
            0xe67c0d9c5e7903ee,
            0x3156fdc5443ea8ef,
            0x7c4c50524d88c892,
            0xc99dc8990c0ad244,
            0xd37ababf3649a896,
            0x76fe4b838ff7a20c,
            0xcf69ee2cec728db3,
            0xb83535548e5f41,
            0x371147684ccb0c23,
            0x194f6f4fa500db52,
            0xc4571dc78a4c5374,
            0xe4d46d479999ca97,
            0x76b6785a615a151c,
            0xcceb8bcea7eaf8c1,
            0x80d87a6fbe5ae687,
            0x6a97ddddb85ce85,
            0xd783958f26034204,
            0x7144506f2e2e8590,
            0x948693d377aef166,
            0x8364621ed6f96056,
            0xf021777c4c09ee2d,
            0xc6cf5e746ecd50b,
            0xa2337b7aa22743df,
            0xae753f8bbacab39c,
            0xfc782a9e34d3c1cc,
            0x21b827324fe494d9,
            0x5692ce350ed03b38,
            0xf323a2b3cd0481b0,
            0xe859c97a4ccad2e3,
            0x48434b70381e4503,
            0x46042d62e4132ed8,
            0x48c4d6f56122e2f2,
            0xf87711ab9f5c1af7,
            0xb14b7a054759b469,
            0x8eb0a96993ffa9aa,
            0x9b21fb6fc58b760c,
            0xf3abdd115d2e7d25,
            0xf7beac3d4d12409c,
            0x40a5585cce69bf03,
            0x697881e1ba22d5a8,
            0x3d6c04e6ad373fd9,
            0x849871bf627be886,
            0x550f4b9b71b28ef9,
            0x81d2e0d78,
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[9],
        nqr.pow_vartime(vec![
            0x4af4accf7de0b977u64,
            0x742485e21805b4ee,
            0xee388fbc4ac36dec,
            0x1e199da57ad178a,
            0xc27c12b292c6726a,
            0x162e6ed84505b5e8,
            0xe191683f336e09df,
            0x17deb7e8d1e0fce6,
            0xd944f19ad06f5836,
            0x4c5f5e59f6276026,
            0xf1ba9c7c148a38a8,
            0xd205fe2dba72b326,
            0x9a2cf2a4c289824e,
            0x4f47ad512c39e24d,
            0xc5894d984000ea09,
            0x2974c03ff7cf01fa,
            0xfcd243b48cb99a22,
            0x2b5150c9313ac1e8,
            0x9089f37c7fc80eda,
            0x989540cc9a7aea56,
            0x1ab1d4e337e63018,
            0x42b546c30d357e43,
            0x1c6abc04f76233d9,
            0x78b3b8d88bf73e47,
            0x151c4e4c45dc68e6,
            0x519a79c4f54397ed,
            0x93f5b51535a127c5,
            0x5fc51b6f52fa153e,
            0x2e0504f2d4a965c3,
            0xc85bd3a3da52bffe,
            0x98c60957a46a89ef,
            0x48c03b5976b91cae,
            0xc6598040a0a61438,
            0xbf0b49dc255953af,
            0xb78dff905b628ab4,
            0x68140b797ba74ab8,
            0x116cf037991d1143,
            0x2f7fe82e58acb0b8,
            0xc20bf7a8f7be5d45,
            0x86c2905c338d5709,
            0xff13a3ae6c8ace3d,
            0xb6f95e2282d08337,
            0xd49f7b313e9cbf29,
            0xf794517193a1ce8c,
            0x39641fecb596a874,
            0x411c4c4edf462fb3,
            0x3f8cd55c10cf25b4,
            0x2bdd7ea165e860b6,
            0xacd7d2cef4caa193,
            0x6558a1d09a05f96,
            0x1f52b5f5b546fc20,
            0x4ee22a5a8c250c12,
            0xd3a63a54a205b6b3,
            0xd2ff5be8,
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[10],
        nqr.pow_vartime(vec![
            0xe5953a4f96cdda44u64,
            0x336b2d734cbc32bb,
            0x3f79bfe3cd7410e,
            0x267ae19aaa0f0332,
            0x85a9c4db78d5c749,
            0x90996b046b5dc7d8,
            0x8945eae9820afc6a,
            0x2644ddea2b036bd,
            0x39898e35ac2e3819,
            0x2574eab095659ab9,
            0x65953d51ac5ea798,
            0xc6b8c7afe6752466,
            0x40e9e993e9286544,
            0x7e0ad34ad9700ea0,
            0xac1015eba2c69222,
            0x24f057a19239b5d8,
            0x2043b48c8a3767eb,
            0x1117c124a75d7ff4,
            0x433cfd1a09fb3ce7,
            0x25b087ce4bcf7fb,
            0xbcee0dc53a3e5bdb,
            0xbffda040cf028735,
            0xf7cf103a25512acc,
            0x31d4ecda673130b9,
            0xea0906dab18461e6,
            0x5a40585a5ac3050d,
            0x803358fc14fd0eda,
            0x3678ca654eada770,
            0x7b91a1293a45e33e,
            0xcd5e5b8ea8530e43,
            0x21ae563ab34da266,
            0xecb00dad60df8894,
            0x77fe53e652facfef,
            0x9b7d1ad0b00244ec,
            0xe695df5ca73f801,
            0x23cdb21feeab0149,
            0x14de113e7ea810d9,
            0x52600cd958dac7e7,
            0xc83392c14667e488,
            0x9f808444bc1717fc,
            0x56facb4bcf7c788f,
            0x8bcad53245fc3ca0,
            0xdef661e83f27d81c,
            0x37d4ebcac9ad87e5,
            0x6fe8b24f5cdb9324,
            0xee08a26c1197654c,
            0xc98b22f65f237e9a,
            0xf54873a908ed3401,
            0x6e1cb951d41f3f3,
            0x290b2250a54e8df6,
            0x7f36d51eb1db669e,
            0xb08c7ed81a6ee43e,
            0x95e1c90fb092f680,
            0x429e4afd0e8b820,
            0x2c14a83ee87d715c,
            0xf37267575cfc8af5,
            0xb99e9afeda3c2c30,
            0x8f0f69da75792d5a,
            0x35074a85a533c73,
            0x156ed119,
        ])
    );
    assert_eq!(
        FROBENIUS_COEFF_FQ12_C1[11],
        nqr.pow_vartime(vec![
            0x107db680942de533u64,
            0x6262b24d2052393b,
            0x6136df824159ebc,
            0xedb052c9970c5deb,
            0xca813aea916c3777,
            0xf49dacb9d76c1788,
            0x624941bd372933bb,
            0xa5e60c2520638331,
            0xb38b661683411074,
            0x1d2c9af4c43d962b,
            0x17d807a0f14aa830,
            0x6e6581a51012c108,
            0x668a537e5b35e6f5,
            0x6c396cf3782dca5d,
            0x33b679d1bff536ed,
            0x736cce41805d90aa,
            0x8a562f369eb680bf,
            0x9f61aa208a11ded8,
            0x43dd89dd94d20f35,
            0xcf84c6610575c10a,
            0x9f318d49cf2fe8e6,
            0xbbc6e5f25a6e434e,
            0x6528c433d11d987b,
            0xffced71cc48c0e8a,
            0x4cbb1474f4cb2a26,
            0x66a035c0b28b7231,
            0xa6f2875faa1a82ae,
            0xdd1ea3deff818b02,
            0xe0cfdf0dcdecf701,
            0x9aefa231f2f6d23,
            0xfb251297efa06746,
            0x5a40d367df985538,
            0x1ea31d69ab506fed,
            0xc64ea8280e89a73f,
            0x969acf9f2d4496f4,
            0xe84c9181ee60c52c,
            0xc60f27fc19fc6ca4,
            0x760b33d850154048,
            0x84f69080f66c8457,
            0xc0192ba0fabf640e,
            0xd2c338765c23a3a8,
            0xa7838c20f02cec6c,
            0xb7cf01d020572877,
            0xd63ffaeba0be200a,
            0xf7492baeb5f041ac,
            0x8602c5212170d117,
            0xad9b2e83a5a42068,
            0x2461829b3ba1083e,
            0x7c34650da5295273,
            0xdc824ba800a8265a,
            0xd18d9b47836af7b2,
            0x3af78945c58cbf4d,
            0x7ed9575b8596906c,
            0x6d0c133895009a66,
            0x53bc1247ea349fe1,
            0x6b3063078d41aa7a,
            0x6184acd8cd880b33,
            0x76f4d15503fd1b96,
            0x7a9afd61eef25746,
            0xce974aadece60609,
            0x88ca59546a8ceafd,
            0x6d29391c41a0ac07,
            0x443843a60e0f46a6,
            0xa1590f62fd2602c7,
            0x536d5b15b514373f,
            0x22d582b,
        ])
    );
}

#[test]
fn test_neg_one() {
    let o = Fq::one().neg();

    assert_eq!(NEGATIVE_ONE, o);
}

#[cfg(test)]
use rand_core::SeedableRng;
#[cfg(test)]
use rand_xorshift::XorShiftRng;

#[test]
fn test_fq_is_valid() {
    let mut a = MODULUS_LIMBS;
    assert!(!a.is_valid());
    a.sub_noborrow(&Fq([1, 0, 0, 0, 0, 0]));
    assert!(a.is_valid());
    assert!(Fq::from(0).is_valid());
    assert!(Fq([
        0xdf4671abd14dab3e,
        0xe2dc0c9f534fbd33,
        0x31ca6c880cc444a6,
        0x257a67e70ef33359,
        0xf9b29e493f899b36,
        0x17c8be1800b9f059
    ])
    .is_valid());
    assert!(!Fq([
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff
    ])
    .is_valid());

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        let a = Fq::random(&mut rng);
        assert!(a.is_valid());
    }
}

#[test]
fn test_fq_add_assign() {
    {
        // Random number
        let mut tmp = Fq([
            0x624434821df92b69,
            0x503260c04fd2e2ea,
            0xd9df726e0d16e8ce,
            0xfbcb39adfd5dfaeb,
            0x86b8a22b0c88b112,
            0x165a2ed809e4201b,
        ]);
        assert!(tmp.is_valid());
        // Test that adding zero has no effect.
        tmp.add_assign(&Fq([0, 0, 0, 0, 0, 0]));
        assert_eq!(
            tmp,
            Fq([
                0x624434821df92b69,
                0x503260c04fd2e2ea,
                0xd9df726e0d16e8ce,
                0xfbcb39adfd5dfaeb,
                0x86b8a22b0c88b112,
                0x165a2ed809e4201b
            ])
        );
        // Add one and test for the result.
        tmp.add_assign(&Fq([1, 0, 0, 0, 0, 0]));
        assert_eq!(
            tmp,
            Fq([
                0x624434821df92b6a,
                0x503260c04fd2e2ea,
                0xd9df726e0d16e8ce,
                0xfbcb39adfd5dfaeb,
                0x86b8a22b0c88b112,
                0x165a2ed809e4201b
            ])
        );
        // Add another random number that exercises the reduction.
        tmp.add_assign(&Fq([
            0x374d8f8ea7a648d8,
            0xe318bb0ebb8bfa9b,
            0x613d996f0a95b400,
            0x9fac233cb7e4fef1,
            0x67e47552d253c52,
            0x5c31b227edf25da,
        ]));
        assert_eq!(
            tmp,
            Fq([
                0xdf92c410c59fc997,
                0x149f1bd05a0add85,
                0xd3ec393c20fba6ab,
                0x37001165c1bde71d,
                0x421b41c9f662408e,
                0x21c38104f435f5b
            ])
        );
        // Add one to (q - 1) and test for the result.
        tmp = Fq([
            0xb9feffffffffaaaa,
            0x1eabfffeb153ffff,
            0x6730d2a0f6b0f624,
            0x64774b84f38512bf,
            0x4b1ba7b6434bacd7,
            0x1a0111ea397fe69a,
        ]);
        tmp.add_assign(&Fq([1, 0, 0, 0, 0, 0]));
        assert!(tmp.is_zero());
        // Add a random number to another one such that the result is q - 1
        tmp = Fq([
            0x531221a410efc95b,
            0x72819306027e9717,
            0x5ecefb937068b746,
            0x97de59cd6feaefd7,
            0xdc35c51158644588,
            0xb2d176c04f2100,
        ]);
        tmp.add_assign(&Fq([
            0x66ecde5bef0fe14f,
            0xac2a6cf8aed568e8,
            0x861d70d86483edd,
            0xcc98f1b7839a22e8,
            0x6ee5e2a4eae7674e,
            0x194e40737930c599,
        ]));
        assert_eq!(
            tmp,
            Fq([
                0xb9feffffffffaaaa,
                0x1eabfffeb153ffff,
                0x6730d2a0f6b0f624,
                0x64774b84f38512bf,
                0x4b1ba7b6434bacd7,
                0x1a0111ea397fe69a
            ])
        );
        // Add one to the result and test for it.
        tmp.add_assign(&Fq([1, 0, 0, 0, 0, 0]));
        assert!(tmp.is_zero());
    }

    // Test associativity

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Generate a, b, c and ensure (a + b) + c == a + (b + c).
        let a = Fq::random(&mut rng);
        let b = Fq::random(&mut rng);
        let c = Fq::random(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.add_assign(&c);

        let mut tmp2 = b;
        tmp2.add_assign(&c);
        tmp2.add_assign(&a);

        assert!(tmp1.is_valid());
        assert!(tmp2.is_valid());
        assert_eq!(tmp1, tmp2);
    }
}

#[test]
fn test_fq_sub_assign() {
    {
        // Test arbitrary subtraction that tests reduction.
        let mut tmp = Fq([
            0x531221a410efc95b,
            0x72819306027e9717,
            0x5ecefb937068b746,
            0x97de59cd6feaefd7,
            0xdc35c51158644588,
            0xb2d176c04f2100,
        ]);
        tmp.sub_assign(&Fq([
            0x98910d20877e4ada,
            0x940c983013f4b8ba,
            0xf677dc9b8345ba33,
            0xbef2ce6b7f577eba,
            0xe1ae288ac3222c44,
            0x5968bb602790806,
        ]));
        assert_eq!(
            tmp,
            Fq([
                0x748014838971292c,
                0xfd20fad49fddde5c,
                0xcf87f198e3d3f336,
                0x3d62d6e6e41883db,
                0x45a3443cd88dc61b,
                0x151d57aaf755ff94
            ])
        );

        // Test the opposite subtraction which doesn't test reduction.
        tmp = Fq([
            0x98910d20877e4ada,
            0x940c983013f4b8ba,
            0xf677dc9b8345ba33,
            0xbef2ce6b7f577eba,
            0xe1ae288ac3222c44,
            0x5968bb602790806,
        ]);
        tmp.sub_assign(&Fq([
            0x531221a410efc95b,
            0x72819306027e9717,
            0x5ecefb937068b746,
            0x97de59cd6feaefd7,
            0xdc35c51158644588,
            0xb2d176c04f2100,
        ]));
        assert_eq!(
            tmp,
            Fq([
                0x457eeb7c768e817f,
                0x218b052a117621a3,
                0x97a8e10812dd02ed,
                0x2714749e0f6c8ee3,
                0x57863796abde6bc,
                0x4e3ba3f4229e706
            ])
        );

        // Test for sensible results with zero
        tmp = Fq::zero();
        tmp.sub_assign(&Fq::zero());
        assert!(tmp.is_zero());

        tmp = Fq([
            0x98910d20877e4ada,
            0x940c983013f4b8ba,
            0xf677dc9b8345ba33,
            0xbef2ce6b7f577eba,
            0xe1ae288ac3222c44,
            0x5968bb602790806,
        ]);
        tmp.sub_assign(&Fq::zero());
        assert_eq!(
            tmp,
            Fq([
                0x98910d20877e4ada,
                0x940c983013f4b8ba,
                0xf677dc9b8345ba33,
                0xbef2ce6b7f577eba,
                0xe1ae288ac3222c44,
                0x5968bb602790806
            ])
        );
    }

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Ensure that (a - b) + (b - a) = 0.
        let a = Fq::random(&mut rng);
        let b = Fq::random(&mut rng);

        let mut tmp1 = a;
        tmp1.sub_assign(&b);

        let mut tmp2 = b;
        tmp2.sub_assign(&a);

        tmp1.add_assign(&tmp2);
        assert!(tmp1.is_zero());
    }
}

#[test]
fn test_fq_mul_assign() {
    let mut tmp = Fq([
        0xcc6200000020aa8a,
        0x422800801dd8001a,
        0x7f4f5e619041c62c,
        0x8a55171ac70ed2ba,
        0x3f69cc3a3d07d58b,
        0xb972455fd09b8ef,
    ]);
    tmp.mul_assign(&Fq([
        0x329300000030ffcf,
        0x633c00c02cc40028,
        0xbef70d925862a942,
        0x4f7fa2a82a963c17,
        0xdf1eb2575b8bc051,
        0x1162b680fb8e9566,
    ]));
    assert!(
        tmp == Fq([
            0x9dc4000001ebfe14,
            0x2850078997b00193,
            0xa8197f1abb4d7bf,
            0xc0309573f4bfe871,
            0xf48d0923ffaf7620,
            0x11d4b58c7a926e66
        ])
    );

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000000 {
        // Ensure that (a * b) * c = a * (b * c)
        let a = Fq::random(&mut rng);
        let b = Fq::random(&mut rng);
        let c = Fq::random(&mut rng);

        let mut tmp1 = a;
        tmp1.mul_assign(&b);
        tmp1.mul_assign(&c);

        let mut tmp2 = b;
        tmp2.mul_assign(&c);
        tmp2.mul_assign(&a);

        assert_eq!(tmp1, tmp2);
    }

    for _ in 0..1000000 {
        // Ensure that r * (a + b + c) = r*a + r*b + r*c

        let r = Fq::random(&mut rng);
        let mut a = Fq::random(&mut rng);
        let mut b = Fq::random(&mut rng);
        let mut c = Fq::random(&mut rng);

        let mut tmp1 = a;
        tmp1.add_assign(&b);
        tmp1.add_assign(&c);
        tmp1.mul_assign(&r);

        a.mul_assign(&r);
        b.mul_assign(&r);
        c.mul_assign(&r);

        a.add_assign(&b);
        a.add_assign(&c);

        assert_eq!(tmp1, a);
    }
}

#[test]
fn test_fq_shr() {
    let mut a = Fq::from_repr(FqRepr([
        0x12, 0x25, 0xf2, 0x90, 0x1a, 0xea, 0x51, 0x4e, 0x16, 0x08, 0x0c, 0xf4, 0x07, 0x1e, 0x0b,
        0x05, 0xc5, 0x54, 0x1f, 0xd4, 0x80, 0x46, 0xb7, 0xe7, 0x9d, 0xdd, 0x5b, 0x31, 0x2f, 0x3d,
        0xd1, 0x04, 0x43, 0x24, 0x2c, 0x06, 0xae, 0xd5, 0x52, 0x87, 0xaa, 0x5c, 0xdd, 0x61, 0x72,
        0x84, 0x7f, 0xfd,
    ]))
    .unwrap();
    a = a >> 0;
    assert_eq!(
        a.into_repr(),
        FqRepr([
            0x12, 0x25, 0xf2, 0x90, 0x1a, 0xea, 0x51, 0x4e, 0x16, 0x08, 0x0c, 0xf4, 0x07, 0x1e,
            0x0b, 0x05, 0xc5, 0x54, 0x1f, 0xd4, 0x80, 0x46, 0xb7, 0xe7, 0x9d, 0xdd, 0x5b, 0x31,
            0x2f, 0x3d, 0xd1, 0x04, 0x43, 0x24, 0x2c, 0x06, 0xae, 0xd5, 0x52, 0x87, 0xaa, 0x5c,
            0xdd, 0x61, 0x72, 0x84, 0x7f, 0xfd,
        ])
    );
    a = a >> 1;
    assert_eq!(
        a.into_repr(),
        FqRepr([
            0x09, 0x12, 0xf9, 0x48, 0x0d, 0x75, 0x28, 0xa7, 0x0b, 0x04, 0x06, 0x7a, 0x03, 0x8f,
            0x05, 0x82, 0xe2, 0xaa, 0x0f, 0xea, 0x40, 0x23, 0x5b, 0xf3, 0xce, 0xee, 0xad, 0x98,
            0x97, 0x9e, 0xe8, 0x82, 0x21, 0x92, 0x16, 0x03, 0x57, 0x6a, 0xa9, 0x43, 0xd5, 0x2e,
            0x6e, 0xb0, 0xb9, 0x42, 0x3f, 0xfe,
        ])
    );
    a = a >> 50;
    assert_eq!(
        a.into_repr(),
        FqRepr([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x44, 0xbe, 0x52, 0x03, 0x5d, 0x4a, 0x29,
            0xc2, 0xc1, 0x01, 0x9e, 0x80, 0xe3, 0xc1, 0x60, 0xb8, 0xaa, 0x83, 0xfa, 0x90, 0x08,
            0xd6, 0xfc, 0xf3, 0xbb, 0xab, 0x66, 0x25, 0xe7, 0xba, 0x20, 0x88, 0x64, 0x85, 0x80,
            0xd5, 0xda, 0xaa, 0x50, 0xf5, 0x4b,
        ])
    );
    a = a >> 130;
    assert_eq!(
        a.into_repr(),
        FqRepr([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x91, 0x2f, 0x94, 0x80, 0xd7,
            0x52, 0x8a, 0x70, 0xb0, 0x40, 0x67, 0xa0, 0x38, 0xf0, 0x58, 0x2e, 0x2a, 0xa0, 0xfe,
            0xa4, 0x02, 0x35, 0xbf, 0x3c, 0xee,
        ])
    );
    a = a >> 64;
    assert_eq!(
        a.into_repr(),
        FqRepr([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x91, 0x2f, 0x94, 0x80, 0xd7, 0x52, 0x8a, 0x70, 0xb0, 0x40, 0x67,
            0xa0, 0x38, 0xf0, 0x58, 0x2e, 0x2a,
        ])
    );
}

#[test]
fn test_fq_squaring() {
    let a = Fq([
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x19ffffffffffffff,
    ]);
    assert!(a.is_valid());
    assert_eq!(
        a.square(),
        Fq::from_repr(FqRepr([
            0x02, 0x4b, 0xcb, 0xe5, 0xd5, 0x1b, 0x9a, 0x6f, 0x79, 0x36, 0x1e, 0x5a, 0x80, 0x2c,
            0x6a, 0x23, 0xdc, 0x05, 0xc6, 0x59, 0xb4, 0xe1, 0x5b, 0x27, 0xcc, 0xe1, 0xd4, 0xed,
            0xc1, 0x20, 0xe6, 0x6e, 0x02, 0x4c, 0xbe, 0x17, 0x31, 0x57, 0x7a, 0x59, 0x1c, 0xfb,
            0x28, 0xfe, 0x7d, 0xfb, 0xbb, 0x86,
        ]))
        .unwrap()
    );

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000000 {
        // Ensure that (a * a) = a^2
        let a = Fq::random(&mut rng);
        assert_eq!(a.square(), a * a);
    }
}

#[test]
fn test_fq_invert() {
    assert!(bool::from(Fq::zero().invert().is_none()));

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let one = Fq::one();

    for _ in 0..1000 {
        // Ensure that a * a^-1 = 1
        let mut a = Fq::random(&mut rng);
        let ainv = a.invert().unwrap();
        a.mul_assign(&ainv);
        assert_eq!(a, one);
    }
}

#[test]
fn test_fq_double() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Ensure doubling a is equivalent to adding a to itself.
        let a = Fq::random(&mut rng);
        assert_eq!(a.double(), a + a);
    }
}

#[test]
fn test_fq_neg() {
    {
        let a = Fq::zero().neg();

        assert!(a.is_zero());
    }

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Ensure (a - (-a)) = 0.
        let mut a = Fq::random(&mut rng);
        let b = a.neg();
        a.add_assign(&b);

        assert!(a.is_zero());
    }
}

#[test]
fn test_fq_pow() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for i in 0u64..1000 {
        // Exponentiate by various small numbers and ensure it consists with repeated
        // multiplication.
        let a = Fq::random(&mut rng);
        let target = a.pow_vartime(&[i]);
        let mut c = Fq::one();
        for _ in 0..i {
            c.mul_assign(&a);
        }
        assert_eq!(c, target);
    }

    for _ in 0..1000 {
        // Exponentiating by the modulus should have no effect in a prime field.
        let a = Fq::random(&mut rng);

        assert_eq!(a, a.pow_vartime(Fq::char()));
    }
}

#[test]
fn test_fq_sqrt() {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    assert_eq!(Fq::zero().sqrt().unwrap(), Fq::zero());

    for _ in 0..1000 {
        // Ensure sqrt(a^2) = a or -a
        let a = Fq::random(&mut rng);
        let nega = a.neg();
        let b = a.square();

        let b = b.sqrt().unwrap();

        assert!(a == b || nega == b);
    }

    for _ in 0..1000 {
        // Ensure sqrt(a)^2 = a for random a
        let a = Fq::random(&mut rng);

        let tmp = a.sqrt();
        if tmp.is_some().into() {
            assert_eq!(a, tmp.unwrap().square());
        }
    }
}

#[test]
fn test_fq_from_into_repr() {
    // q + 1 should not be in the field
    assert!(Fq::from_repr(FqRepr([
        0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac,
        0xd7, 0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0,
        0xf6, 0x24, 0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff,
        0xff, 0xaa, 0xac,
    ]))
    .is_none());

    // q should not be in the field
    assert!(Fq::from_repr(Fq::char()).is_none());

    // Multiply some arbitrary representations to see if the result is as expected.
    let a = FqRepr([
        0x06, 0xc8, 0x09, 0x18, 0xa3, 0x65, 0xef, 0x78, 0xae, 0x30, 0x74, 0x0c, 0x08, 0xa8, 0x75,
        0xd7, 0x90, 0x8a, 0x38, 0x7f, 0x48, 0x07, 0x35, 0xf1, 0x2b, 0x1f, 0x41, 0xab, 0x9f, 0x36,
        0xd6, 0x40, 0xac, 0x62, 0xa8, 0x2a, 0x8f, 0x51, 0xcd, 0x50, 0x4a, 0x49, 0xda, 0xd4, 0xff,
        0x6c, 0xde, 0x2d,
    ]);
    let mut a_fq = Fq::from_repr(a).unwrap();
    let b = FqRepr([
        0x0b, 0x13, 0x95, 0x5f, 0x5a, 0xc7, 0xf6, 0xa3, 0x1f, 0x60, 0x71, 0x86, 0xd5, 0xbb, 0x00,
        0x59, 0xd5, 0x9f, 0xd9, 0x4e, 0xe4, 0x57, 0x2c, 0xfa, 0x94, 0x98, 0xb4, 0x29, 0x2f, 0xd2,
        0x74, 0x59, 0xe7, 0xf8, 0x78, 0xcf, 0x87, 0xf0, 0x5e, 0x5d, 0xbb, 0xa5, 0x79, 0x17, 0xc3,
        0x2f, 0x0c, 0xf0,
    ]);
    let b_fq = Fq::from_repr(b).unwrap();
    let c = FqRepr([
        0x16, 0x84, 0x48, 0x77, 0x72, 0xbc, 0x9a, 0x5a, 0xa4, 0x4c, 0x20, 0x4c, 0x1d, 0xe7, 0xcd,
        0xb7, 0xf1, 0x6b, 0x9d, 0x77, 0xb0, 0xad, 0x7d, 0x10, 0xce, 0x60, 0xdd, 0x43, 0x41, 0x7e,
        0xc9, 0x60, 0x35, 0x5e, 0xa5, 0xac, 0x64, 0xcb, 0xba, 0xb1, 0xf5, 0xf7, 0x07, 0x13, 0xb7,
        0x17, 0x91, 0x4c,
    ]);
    a_fq.mul_assign(&b_fq);
    assert_eq!(a_fq.into_repr(), c);

    // Zero should be in the field.
    assert!(Fq::from_repr(FqRepr([0; 48])).unwrap().is_zero());

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for _ in 0..1000 {
        // Try to turn Fq elements into representations and back again, and compare.
        let a = Fq::random(&mut rng);
        let a_repr = a.into_repr();
        let b_repr = FqRepr::from(a);
        assert_eq!(a_repr, b_repr);
        let a_again = Fq::from_repr(a_repr).unwrap();

        assert_eq!(a, a_again);
    }
}

#[test]
fn test_fq_display() {
    assert_eq!(
        format!("{}", Fq::from_repr(FqRepr([
            0x19, 0x47, 0xf0, 0xd5, 0xf4, 0xfe, 0x32, 0x5a, 0xb1, 0xd4, 0xaa, 0xd8, 0x76, 0x51,
            0xe6, 0x94, 0x67, 0x6c, 0xc4, 0xee, 0xf4, 0xc4, 0x6f, 0x2c, 0xb3, 0x8d, 0x35, 0xb3,
            0xf6, 0x77, 0x95, 0x85, 0x39, 0xa8, 0xf1, 0x84, 0xf3, 0x53, 0x5c, 0x7b, 0xa9, 0x56,
            0xba, 0xbf, 0x93, 0x01, 0xea, 0x24,
        ])).unwrap()),
        "Fq(0x1947f0d5f4fe325ab1d4aad87651e694676cc4eef4c46f2cb38d35b3f677958539a8f184f3535c7ba956babf9301ea24)".to_string()
    );
    assert_eq!(
        format!("{}", Fq::from_repr(FqRepr([
            0x06, 0xc9, 0xf5, 0xa1, 0x06, 0x0d, 0xe9, 0x74, 0x9a, 0x55, 0x18, 0x59, 0xb1, 0xe4,
            0x3a, 0x9a, 0xb7, 0xf8, 0x9f, 0x88, 0xf5, 0x9c, 0x1d, 0xc5, 0xa4, 0xb6, 0x2a, 0xf4,
            0xa7, 0x92, 0xa6, 0x89, 0x41, 0x3f, 0x6f, 0x7f, 0x06, 0xea, 0x87, 0xeb, 0xe2, 0x8e,
            0x79, 0x39, 0x6a, 0xc2, 0xbb, 0xf8,
        ])).unwrap()),
        "Fq(0x06c9f5a1060de9749a551859b1e43a9ab7f89f88f59c1dc5a4b62af4a792a689413f6f7f06ea87ebe28e79396ac2bbf8)".to_string()
    );
}

#[test]
fn test_fq_is_odd() {
    assert!(!Fq::from(0).is_odd());
    assert!(Fq::from(0).is_even());
    assert!(Fq::from(1).is_odd());
    assert!(!Fq::from(1).is_even());
    assert!(!Fq::from(324834872).is_odd());
    assert!(Fq::from(324834872).is_even());
    assert!(Fq::from(324834873).is_odd());
    assert!(!Fq::from(324834873).is_even());
}

#[test]
fn test_fq_num_bits() {
    assert_eq!(Fq::NUM_BITS, 381);
    assert_eq!(Fq::CAPACITY, 380);
}

#[test]
fn test_fq_root_of_unity() {
    assert_eq!(Fq::S, 1);
    assert_eq!(Fq::multiplicative_generator(), Fq::from(2));
    assert_eq!(
        Fq::multiplicative_generator().pow_vartime([
            0xdcff7fffffffd555u64,
            0xf55ffff58a9ffff,
            0xb39869507b587b12,
            0xb23ba5c279c2895f,
            0x258dd3db21a5d66b,
            0xd0088f51cbff34d
        ]),
        Fq::root_of_unity()
    );
    assert_eq!(Fq::root_of_unity().pow_vartime([1u64 << Fq::S]), Fq::one());
    assert!(bool::from(Fq::multiplicative_generator().sqrt().is_none()));
}

#[test]
fn fq_field_tests() {
    crate::tests::field::random_field_tests::<Fq>();
    crate::tests::field::random_sqrt_tests::<Fq>();
    crate::tests::field::from_str_tests::<Fq>();
}

#[test]
fn test_fq_ordering() {
    // We need to make sure the Fq elements aren't being compared in Montgomery form.
    for i in 0..100 {
        assert!(Fq::from(i + 1) > Fq::from(i));
    }
}

#[test]
fn fq_repr_tests() {
    crate::tests::repr::random_repr_tests::<Fq>();
}
