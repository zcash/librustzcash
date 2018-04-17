extern crate libc;
extern crate sapling_crypto;
extern crate pairing;
extern crate bellman;

#[macro_use]
extern crate lazy_static;

use pairing::{
    BitIterator,
    PrimeFieldRepr,
    PrimeField,
    bls12_381::{
        Bls12,
        Fr,
        FrRepr
    }
};

use sapling_crypto::{
    jubjub::JubjubBls12,
    pedersen_hash::{
        pedersen_hash,
        Personalization
    }
};

use bellman::{
    groth16::{
        Parameters,
        PreparedVerifyingKey,
        VerifyingKey,
        prepare_verifying_key
    }
};

use libc::{uint64_t, size_t, c_uchar, c_char};
use std::ffi::CStr;
use std::fs::File;

lazy_static! {
    static ref JUBJUB: JubjubBls12 = {
        JubjubBls12::new()
    };
}

static mut SAPLING_SPEND_VK: Option<PreparedVerifyingKey<Bls12>> = None;
static mut SAPLING_OUTPUT_VK: Option<PreparedVerifyingKey<Bls12>> = None;
static mut SPROUT_GROTH16_VK: Option<PreparedVerifyingKey<Bls12>> = None;

static mut SAPLING_SPEND_PARAMS: Option<Parameters<Bls12>> = None;
static mut SAPLING_OUTPUT_PARAMS: Option<Parameters<Bls12>> = None;
static mut SPROUT_GROTH16_PARAMS_PATH: Option<String> = None;

#[no_mangle]
pub extern "system" fn librustzcash_init_zksnark_params(
    spend_path: *const c_char,
    output_path: *const c_char,
    sprout_path: *const c_char
)
{
    // These should be valid CStr's, but the decoding may fail on Windows
    // so we may need to use OSStr or something.
    let spend_path = unsafe { CStr::from_ptr(spend_path) }.to_str().expect("parameter path encoding error").to_string();
    let output_path = unsafe { CStr::from_ptr(output_path) }.to_str().expect("parameter path encoding error").to_string();
    let sprout_path = unsafe { CStr::from_ptr(sprout_path) }.to_str().expect("parameter path encoding error").to_string();

    // Load from each of the paths
    let mut spend_fs = File::open(spend_path).expect("couldn't load Sapling spend parameters file");
    let mut output_fs = File::open(output_path).expect("couldn't load Sapling output parameters file");
    let mut sprout_fs = File::open(&sprout_path).expect("couldn't load Sprout groth16 parameters file");

    // Deserialize params
    let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false).expect("couldn't deserialize Sapling spend parameters file");
    let output_params = Parameters::<Bls12>::read(&mut output_fs, false).expect("couldn't deserialize Sapling spend parameters file");
    let sprout_vk = VerifyingKey::<Bls12>::read(&mut sprout_fs).expect("couldn't deserialize Sprout Groth16 verifying key");

    // Prepare verifying keys
    let spend_vk = prepare_verifying_key(&spend_params.vk);
    let output_vk = prepare_verifying_key(&output_params.vk);
    let sprout_vk = prepare_verifying_key(&sprout_vk);

    // Caller is responsible for calling this function once, so
    // these global mutations are safe.
    unsafe {
        SAPLING_SPEND_PARAMS = Some(spend_params);
        SAPLING_OUTPUT_PARAMS = Some(output_params);
        SPROUT_GROTH16_PARAMS_PATH = Some(sprout_path);

        SAPLING_SPEND_VK = Some(spend_vk);
        SAPLING_OUTPUT_VK = Some(output_vk);
        SPROUT_GROTH16_VK = Some(sprout_vk);
    }
}

#[no_mangle]
pub extern "system" fn librustzcash_tree_uncommitted(
    result: *mut [c_uchar; 32]
)
{
    let tmp = sapling_crypto::primitives::Note::<Bls12>::uncommitted().into_repr();

    // Should be okay, caller is responsible for ensuring the pointer
    // is a valid pointer to 32 bytes that can be mutated.
    let result = unsafe { &mut *result };

    tmp.write_be(&mut result[..]).unwrap();
}

#[no_mangle]
pub extern "system" fn librustzcash_merkle_hash(
    depth: size_t,
    a: *const [c_uchar; 32],
    b: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
)
{
    let mut a_repr = FrRepr::default();
    let mut b_repr = FrRepr::default();

    // Should be okay, because caller is responsible for ensuring
    // the pointer is a valid pointer to 32 bytes, and that is the
    // size of the representation
    a_repr.read_be(unsafe { &(&*a)[..] }).unwrap();

    // Should be okay, because caller is responsible for ensuring
    // the pointer is a valid pointer to 32 bytes, and that is the
    // size of the representation
    b_repr.read_be(unsafe { &(&*b)[..] }).unwrap();

    let mut lhs = [false; 256];
    let mut rhs = [false; 256];

    for (a, b) in lhs.iter_mut().rev().zip(BitIterator::new(a_repr)) {
        *a = b;
    }

    for (a, b) in rhs.iter_mut().rev().zip(BitIterator::new(b_repr)) {
        *a = b;
    }
    
    let tmp = pedersen_hash::<Bls12, _>(
        Personalization::MerkleTree(depth),
        lhs.iter().map(|&x| x)
            .take(Fr::NUM_BITS as usize)
            .chain(rhs.iter().map(|&x| x).take(Fr::NUM_BITS as usize)),
        &JUBJUB
    ).into_xy().0.into_repr();

    // Should be okay, caller is responsible for ensuring the pointer
    // is a valid pointer to 32 bytes that can be mutated.
    let result = unsafe { &mut *result };

    tmp.write_be(&mut result[..]).unwrap();
}

/// XOR two uint64_t values and return the result, used
/// as a temporary mechanism for introducing Rust into
/// Zcash.
#[no_mangle]
pub extern "system" fn librustzcash_xor(a: uint64_t, b: uint64_t) -> uint64_t
{
    a ^ b
}

#[test]
fn test_xor() {
    assert_eq!(librustzcash_xor(0x0f0f0f0f0f0f0f0f, 0x1111111111111111), 0x1e1e1e1e1e1e1e1e);
}
