extern crate bellman;
extern crate blake2_rfc;
extern crate byteorder;
extern crate libc;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;

#[macro_use]
extern crate lazy_static;

use pairing::{BitIterator, Field, PrimeField, PrimeFieldRepr, bls12_381::{Bls12, Fr, FrRepr}};

use sapling_crypto::{circuit::multipack, constants::CRH_IVK_PERSONALIZATION,
                     jubjub::{edwards, FixedGenerators, JubjubBls12, JubjubEngine, JubjubParams,
                              PrimeOrder, ToUniform, Unknown, fs::{Fs, FsRepr}},
                     pedersen_hash::{pedersen_hash, Personalization}, redjubjub::{self, Signature}};

use sapling_crypto::circuit::sprout::{self, TREE_DEPTH as SPROUT_TREE_DEPTH};

use bellman::groth16::{create_random_proof, prepare_verifying_key, verify_proof, Parameters,
                       PreparedVerifyingKey, Proof, VerifyingKey};

use blake2_rfc::blake2s::Blake2s;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use rand::{OsRng, Rng};
use std::io::BufReader;

use libc::{c_char, c_uchar, size_t, int64_t, uint32_t, uint64_t};
use std::ffi::CStr;
use std::fs::File;
use std::slice;

pub mod equihash;

#[cfg(test)]
mod tests;

lazy_static! {
    static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}

static mut SAPLING_SPEND_VK: Option<PreparedVerifyingKey<Bls12>> = None;
static mut SAPLING_OUTPUT_VK: Option<PreparedVerifyingKey<Bls12>> = None;
static mut SPROUT_GROTH16_VK: Option<PreparedVerifyingKey<Bls12>> = None;

static mut SAPLING_SPEND_PARAMS: Option<Parameters<Bls12>> = None;
static mut SAPLING_OUTPUT_PARAMS: Option<Parameters<Bls12>> = None;
static mut SPROUT_GROTH16_PARAMS_PATH: Option<String> = None;

fn is_small_order<Order>(p: &edwards::Point<Bls12, Order>) -> bool {
    p.double(&JUBJUB).double(&JUBJUB).double(&JUBJUB) == edwards::Point::zero()
}

/// Writes an FrRepr to [u8] of length 32
fn write_le(f: FrRepr, to: &mut [u8]) {
    assert_eq!(to.len(), 32);

    f.write_le(to).expect("length is 32 bytes");
}

/// Reads an FrRepr from a [u8] of length 32.
/// This will panic (abort) if length provided is
/// not correct.
fn read_le(from: &[u8]) -> FrRepr {
    assert_eq!(from.len(), 32);

    let mut f = FrRepr::default();
    f.read_le(from).expect("length is 32 bytes");

    f
}

/// Reads an FsRepr from [u8] of length 32
/// This will panic (abort) if length provided is
/// not correct
fn read_fs(from: &[u8]) -> FsRepr {
    assert_eq!(from.len(), 32);

    let mut f = <<Bls12 as JubjubEngine>::Fs as PrimeField>::Repr::default();
    f.read_le(from).expect("length is 32 bytes");

    f
}

/// Reads an FsRepr from [u8] of length 32
/// and multiplies it by the given base.
/// This will panic (abort) if length provided is
/// not correct
fn fixed_scalar_mult(from: &[u8], p_g: FixedGenerators) -> edwards::Point<Bls12, PrimeOrder> {
    let f = read_fs(from);

    JUBJUB.generator(p_g).mul(f, &JUBJUB)
}

#[no_mangle]
pub extern "system" fn librustzcash_init_zksnark_params(
    spend_path: *const c_char,
    output_path: *const c_char,
    sprout_path: *const c_char,
) {
    // Initialize jubjub parameters here
    lazy_static::initialize(&JUBJUB);

    // These should be valid CStr's, but the decoding may fail on Windows
    // so we may need to use OSStr or something.
    let spend_path = unsafe { CStr::from_ptr(spend_path) }
        .to_str()
        .expect("parameter path encoding error")
        .to_string();
    let output_path = unsafe { CStr::from_ptr(output_path) }
        .to_str()
        .expect("parameter path encoding error")
        .to_string();
    let sprout_path = unsafe { CStr::from_ptr(sprout_path) }
        .to_str()
        .expect("parameter path encoding error")
        .to_string();

    // Load from each of the paths
    let mut spend_fs = File::open(spend_path).expect("couldn't load Sapling spend parameters file");
    let mut output_fs =
        File::open(output_path).expect("couldn't load Sapling output parameters file");
    let mut sprout_fs =
        File::open(&sprout_path).expect("couldn't load Sprout groth16 parameters file");

    // Deserialize params
    let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
        .expect("couldn't deserialize Sapling spend parameters file");
    let output_params = Parameters::<Bls12>::read(&mut output_fs, false)
        .expect("couldn't deserialize Sapling spend parameters file");
    let sprout_vk = VerifyingKey::<Bls12>::read(&mut sprout_fs)
        .expect("couldn't deserialize Sprout Groth16 verifying key");

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
pub extern "system" fn librustzcash_tree_uncommitted(result: *mut [c_uchar; 32]) {
    let tmp = sapling_crypto::primitives::Note::<Bls12>::uncommitted().into_repr();

    // Should be okay, caller is responsible for ensuring the pointer
    // is a valid pointer to 32 bytes that can be mutated.
    let result = unsafe { &mut *result };

    write_le(tmp, &mut result[..]);
}

#[no_mangle]
pub extern "system" fn librustzcash_merkle_hash(
    depth: size_t,
    a: *const [c_uchar; 32],
    b: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) {
    // Should be okay, because caller is responsible for ensuring
    // the pointer is a valid pointer to 32 bytes, and that is the
    // size of the representation
    let a_repr = read_le(unsafe { &(&*a)[..] });

    // Should be okay, because caller is responsible for ensuring
    // the pointer is a valid pointer to 32 bytes, and that is the
    // size of the representation
    let b_repr = read_le(unsafe { &(&*b)[..] });

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
        lhs.iter()
            .map(|&x| x)
            .take(Fr::NUM_BITS as usize)
            .chain(rhs.iter().map(|&x| x).take(Fr::NUM_BITS as usize)),
        &JUBJUB,
    ).into_xy()
        .0
        .into_repr();

    // Should be okay, caller is responsible for ensuring the pointer
    // is a valid pointer to 32 bytes that can be mutated.
    let result = unsafe { &mut *result };

    write_le(tmp, &mut result[..]);
}

#[no_mangle] // ToScalar
pub extern "system" fn librustzcash_to_scalar(
    input: *const [c_uchar; 64],
    result: *mut [c_uchar; 32],
) {
    // Should be okay, because caller is responsible for ensuring
    // the pointer is a valid pointer to 32 bytes, and that is the
    // size of the representation
    let scalar = <Bls12 as JubjubEngine>::Fs::to_uniform(unsafe { &(&*input)[..] }).into_repr();

    let result = unsafe { &mut *result };

    scalar
        .write_le(&mut result[..])
        .expect("length is 32 bytes");
}

#[no_mangle]
pub extern "system" fn librustzcash_ask_to_ak(
    ask: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) {
    let ask = unsafe { &*ask };
    let ak = fixed_scalar_mult(ask, FixedGenerators::SpendingKeyGenerator);

    let result = unsafe { &mut *result };

    ak.write(&mut result[..]).expect("length is 32 bytes");
}

#[no_mangle]
pub extern "system" fn librustzcash_nsk_to_nk(
    nsk: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) {
    let nsk = unsafe { &*nsk };
    let nk = fixed_scalar_mult(nsk, FixedGenerators::ProofGenerationKey);

    let result = unsafe { &mut *result };

    nk.write(&mut result[..]).expect("length is 32 bytes");
}

#[no_mangle]
pub extern "system" fn librustzcash_crh_ivk(
    ak: *const [c_uchar; 32],
    nk: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) {
    let ak = unsafe { &*ak };
    let nk = unsafe { &*nk };

    let mut h = Blake2s::with_params(32, &[], &[], CRH_IVK_PERSONALIZATION);
    h.update(ak);
    h.update(nk);
    let mut h = h.finalize().as_ref().to_vec();

    // Drop the last five bits, so it can be interpreted as a scalar.
    h[31] &= 0b0000_0111;

    let result = unsafe { &mut *result };

    result.copy_from_slice(&h);
}

#[no_mangle]
pub extern "system" fn librustzcash_check_diversifier(diversifier: *const [c_uchar; 11]) -> bool {
    let diversifier = sapling_crypto::primitives::Diversifier(unsafe { *diversifier });
    diversifier.g_d::<Bls12>(&JUBJUB).is_some()
}

#[no_mangle]
pub extern "system" fn librustzcash_ivk_to_pkd(
    ivk: *const [c_uchar; 32],
    diversifier: *const [c_uchar; 11],
    result: *mut [c_uchar; 32],
) -> bool {
    let ivk = read_fs(unsafe { &*ivk });
    let diversifier = sapling_crypto::primitives::Diversifier(unsafe { *diversifier });
    if let Some(g_d) = diversifier.g_d::<Bls12>(&JUBJUB) {
        let pk_d = g_d.mul(ivk, &JUBJUB);

        let result = unsafe { &mut *result };

        pk_d.write(&mut result[..]).expect("length is 32 bytes");

        true
    } else {
        false
    }
}

/// Return 32 byte randomness, uniform, to be used for a Sapling commitment.
#[no_mangle]
pub extern "system" fn librustzcash_sapling_generate_commitment_randomness(
    result: *mut [c_uchar; 32],
) -> bool {
    // create random 64 byte buffer
    let mut rng = OsRng::new().expect("should be able to construct RNG");
    let mut buffer = [0u8; 64];
    for i in 0..buffer.len() {
        buffer[i] = rng.gen();
    }

    // TODO: Remove this debug statement
    println!("buffer of random bytes: {:?}", &buffer[..]);

    // reduce to uniform value
    let r = <Bls12 as JubjubEngine>::Fs::to_uniform(&buffer[..]);
    let result = unsafe { &mut *result };
    r.into_repr()
        .write_le(&mut result[..])
        .expect("result must be 32 bytes");

    true
}

/// Compute Sapling note commitment.
#[no_mangle]
pub extern "system" fn librustzcash_sapling_compute_cm(
    diversifier: *const [c_uchar; 11],
    pk_d: *const [c_uchar; 32],
    value: uint64_t,
    r: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) -> bool {
    let diversifier = sapling_crypto::primitives::Diversifier(unsafe { *diversifier });
    let g_d = match diversifier.g_d::<Bls12>(&JUBJUB) {
        Some(g_d) => g_d,
        None => return false,
    };

    let pk_d = match edwards::Point::<Bls12, Unknown>::read(&(unsafe { &*pk_d })[..], &JUBJUB) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let pk_d = match pk_d.as_prime_order(&JUBJUB) {
        Some(pk_d) => pk_d,
        None => return false,
    };

    // Deserialize randomness
    let r = unsafe { *r };
    let mut repr = FsRepr::default();
    repr.read_le(&r[..]).expect("length is not 32 bytes");
    let r = match Fs::from_repr(repr) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let note = sapling_crypto::primitives::Note {
        value,
        g_d,
        pk_d,
        r,
    };

    let result = unsafe { &mut *result };
    write_le(note.cm(&JUBJUB).into_repr(), &mut result[..]);

    true
}

/// XOR two uint64_t values and return the result, used
/// as a temporary mechanism for introducing Rust into
/// Zcash.
#[no_mangle]
pub extern "system" fn librustzcash_xor(a: uint64_t, b: uint64_t) -> uint64_t {
    a ^ b
}

#[no_mangle]
pub extern "system" fn librustzcash_eh_isvalid(
    n: uint32_t,
    k: uint32_t,
    input: *const c_uchar,
    input_len: size_t,
    nonce: *const c_uchar,
    nonce_len: size_t,
    soln: *const c_uchar,
    soln_len: size_t,
) -> bool {
    if (k >= n) || (n % 8 != 0) || (soln_len != (1 << k) * ((n / (k + 1)) as usize + 1) / 8) {
        return false;
    }
    let rs_input = unsafe { slice::from_raw_parts(input, input_len) };
    let rs_nonce = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let rs_soln = unsafe { slice::from_raw_parts(soln, soln_len) };
    equihash::is_valid_solution(n, k, rs_input, rs_nonce, rs_soln)
}

#[test]
fn test_xor() {
    assert_eq!(
        librustzcash_xor(0x0f0f0f0f0f0f0f0f, 0x1111111111111111),
        0x1e1e1e1e1e1e1e1e
    );
}

pub struct SaplingVerificationContext {
    bvk: edwards::Point<Bls12, Unknown>,
}

#[no_mangle]
pub extern "system" fn librustzcash_sapling_verification_ctx_init(
) -> *mut SaplingVerificationContext {
    let ctx = Box::new(SaplingVerificationContext {
        bvk: edwards::Point::zero(),
    });

    Box::into_raw(ctx)
}

#[no_mangle]
pub extern "system" fn librustzcash_sapling_verification_ctx_free(
    ctx: *mut SaplingVerificationContext,
) {
    drop(unsafe { Box::from_raw(ctx) });
}

const GROTH_PROOF_SIZE: usize = 48 // π_A
    + 96 // π_B
    + 48; // π_C

#[no_mangle]
pub extern "system" fn librustzcash_sapling_check_spend(
    ctx: *mut SaplingVerificationContext,
    cv: *const [c_uchar; 32],
    anchor: *const [c_uchar; 32],
    nullifier: *const [c_uchar; 32],
    rk: *const [c_uchar; 32],
    zkproof: *const [c_uchar; GROTH_PROOF_SIZE],
    spend_auth_sig: *const [c_uchar; 64],
    sighash_value: *const [c_uchar; 32],
) -> bool {
    // Deserialize the value commitment
    let cv = match edwards::Point::<Bls12, Unknown>::read(&(unsafe { &*cv })[..], &JUBJUB) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if is_small_order(&cv) {
        return false;
    }

    // Accumulate the value commitment in the context
    {
        let mut tmp = cv.clone();
        tmp = tmp.add(&unsafe { &*ctx }.bvk, &JUBJUB);

        // Update the context
        unsafe { &mut *ctx }.bvk = tmp;
    }

    // Deserialize the anchor, which should be an element
    // of Fr.
    let anchor = match Fr::from_repr(read_le(&(unsafe { &*anchor })[..])) {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Grab the nullifier as a sequence of bytes
    let nullifier = &unsafe { &*nullifier }[..];

    // Compute the signature's message for rk/spend_auth_sig
    let mut data_to_be_signed = [0u8; 64];
    (&mut data_to_be_signed[0..32]).copy_from_slice(&(unsafe { &*rk })[..]);
    (&mut data_to_be_signed[32..64]).copy_from_slice(&(unsafe { &*sighash_value })[..]);

    // Deserialize rk
    let rk = match redjubjub::PublicKey::<Bls12>::read(&(unsafe { &*rk })[..], &JUBJUB) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if is_small_order(&rk.0) {
        return false;
    }

    // Deserialize the signature
    let spend_auth_sig = match Signature::read(&(unsafe { &*spend_auth_sig })[..]) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Verify the spend_auth_sig
    if !rk.verify(
        &data_to_be_signed,
        &spend_auth_sig,
        FixedGenerators::SpendingKeyGenerator,
        &JUBJUB,
    ) {
        return false;
    }

    // Construct public input for circuit
    let mut public_input = [Fr::zero(); 7];
    {
        let (x, y) = rk.0.into_xy();
        public_input[0] = x;
        public_input[1] = y;
    }
    {
        let (x, y) = cv.into_xy();
        public_input[2] = x;
        public_input[3] = y;
    }
    public_input[4] = anchor;

    // Add the nullifier through multiscalar packing
    {
        let nullifier = multipack::bytes_to_bits_le(nullifier);
        let nullifier = multipack::compute_multipacking::<Bls12>(&nullifier);

        assert_eq!(nullifier.len(), 2);

        public_input[5] = nullifier[0];
        public_input[6] = nullifier[1];
    }

    // Deserialize the proof
    let zkproof = match Proof::<Bls12>::read(&(unsafe { &*zkproof })[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Verify the proof
    match verify_proof(
        unsafe { SAPLING_SPEND_VK.as_ref() }.unwrap(),
        &zkproof,
        &public_input[..],
    ) {
        // No error, and proof verification successful
        Ok(true) => true,

        // Any other case
        _ => false,
    }
}

#[no_mangle]
pub extern "system" fn librustzcash_sapling_check_output(
    ctx: *mut SaplingVerificationContext,
    cv: *const [c_uchar; 32],
    cm: *const [c_uchar; 32],
    epk: *const [c_uchar; 32],
    zkproof: *const [c_uchar; GROTH_PROOF_SIZE],
) -> bool {
    // Deserialize the value commitment
    let cv = match edwards::Point::<Bls12, Unknown>::read(&(unsafe { &*cv })[..], &JUBJUB) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if is_small_order(&cv) {
        return false;
    }

    // Accumulate the value commitment in the context
    {
        let mut tmp = cv.clone();
        tmp.negate(); // Outputs subtract from the total.
        tmp = tmp.add(&unsafe { &*ctx }.bvk, &JUBJUB);

        // Update the context
        unsafe { &mut *ctx }.bvk = tmp;
    }

    // Deserialize the commitment, which should be an element
    // of Fr.
    let cm = match Fr::from_repr(read_le(&(unsafe { &*cm })[..])) {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Deserialize the ephemeral key
    let epk = match edwards::Point::<Bls12, Unknown>::read(&(unsafe { &*epk })[..], &JUBJUB) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if is_small_order(&epk) {
        return false;
    }

    // Construct public input for circuit
    let mut public_input = [Fr::zero(); 5];
    {
        let (x, y) = cv.into_xy();
        public_input[0] = x;
        public_input[1] = y;
    }
    {
        let (x, y) = epk.into_xy();
        public_input[2] = x;
        public_input[3] = y;
    }
    public_input[4] = cm;

    // Deserialize the proof
    let zkproof = match Proof::<Bls12>::read(&(unsafe { &*zkproof })[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Verify the proof
    match verify_proof(
        unsafe { SAPLING_OUTPUT_VK.as_ref() }.unwrap(),
        &zkproof,
        &public_input[..],
    ) {
        // No error, and proof verification successful
        Ok(true) => true,

        // Any other case
        _ => false,
    }
}

// This function computes `value` in the exponent of the value commitment base
fn compute_value_balance(value: int64_t) -> Option<edwards::Point<Bls12, Unknown>> {
    // Compute the absolute value (failing if -i64::MAX is
    // the value)
    let abs = match value.checked_abs() {
        Some(a) => a as u64,
        None => return None,
    };

    // Is it negative? We'll have to negate later if so.
    let is_negative = value.is_negative();

    // Compute it in the exponent
    let mut value_balance = JUBJUB
        .generator(FixedGenerators::ValueCommitmentValue)
        .mul(FsRepr::from(abs), &JUBJUB);

    // Negate if necessary
    if is_negative {
        value_balance = value_balance.negate();
    }

    // Convert to unknown order point
    Some(value_balance.into())
}

#[no_mangle]
pub extern "system" fn librustzcash_sapling_final_check(
    ctx: *mut SaplingVerificationContext,
    value_balance: int64_t,
    binding_sig: *const [c_uchar; 64],
    sighash_value: *const [c_uchar; 32],
) -> bool {
    // Obtain current bvk from the context
    let mut bvk = redjubjub::PublicKey(unsafe { &*ctx }.bvk.clone());

    // Compute value balance
    let mut value_balance = match compute_value_balance(value_balance) {
        Some(a) => a,
        None => return false,
    };

    // Subtract value_balance from current bvk to get final bvk
    value_balance = value_balance.negate();
    bvk.0 = bvk.0.add(&value_balance, &JUBJUB);

    // Compute the signature's message for bvk/binding_sig
    let mut data_to_be_signed = [0u8; 64];
    bvk.0
        .write(&mut data_to_be_signed[0..32])
        .expect("bvk is 32 bytes");
    (&mut data_to_be_signed[32..64]).copy_from_slice(&(unsafe { &*sighash_value })[..]);

    // Deserialize the signature
    let binding_sig = match Signature::read(&(unsafe { &*binding_sig })[..]) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Verify the binding_sig
    if !bvk.verify(
        &data_to_be_signed,
        &binding_sig,
        FixedGenerators::ValueCommitmentRandomness,
        &JUBJUB,
    ) {
        return false;
    }

    true
}

#[no_mangle]
pub extern "system" fn librustzcash_sprout_prove(
    proof_out: *mut [c_uchar; GROTH_PROOF_SIZE],

    phi: *const [c_uchar; 32],
    rt: *const [c_uchar; 32],
    h_sig: *const [c_uchar; 32],

    // First input
    in_sk1: *const [c_uchar; 32],
    in_value1: uint64_t,
    in_rho1: *const [c_uchar; 32],
    in_r1: *const [c_uchar; 32],
    in_auth1: *const [c_uchar; 1 + 33 * SPROUT_TREE_DEPTH + 8],

    // Second input
    in_sk2: *const [c_uchar; 32],
    in_value2: uint64_t,
    in_rho2: *const [c_uchar; 32],
    in_r2: *const [c_uchar; 32],
    in_auth2: *const [c_uchar; 1 + 33 * SPROUT_TREE_DEPTH + 8],

    // First output
    out_pk1: *const [c_uchar; 32],
    out_value1: uint64_t,
    out_r1: *const [c_uchar; 32],

    // Second output
    out_pk2: *const [c_uchar; 32],
    out_value2: uint64_t,
    out_r2: *const [c_uchar; 32],

    // Public value
    vpub_old: uint64_t,
    vpub_new: uint64_t,
) {
    let phi = unsafe { *phi };
    let rt = unsafe { *rt };
    let h_sig = unsafe { *h_sig };
    let in_sk1 = unsafe { *in_sk1 };
    let in_rho1 = unsafe { *in_rho1 };
    let in_r1 = unsafe { *in_r1 };
    let in_auth1 = unsafe { *in_auth1 };
    let in_sk2 = unsafe { *in_sk2 };
    let in_rho2 = unsafe { *in_rho2 };
    let in_r2 = unsafe { *in_r2 };
    let in_auth2 = unsafe { *in_auth2 };
    let out_pk1 = unsafe { *out_pk1 };
    let out_r1 = unsafe { *out_r1 };
    let out_pk2 = unsafe { *out_pk2 };
    let out_r2 = unsafe { *out_r2 };

    let mut inputs = Vec::with_capacity(2);
    {
        let mut handle_input = |sk, value, rho, r, mut auth: &[u8]| {
            let value = Some(value);
            let rho = Some(sprout::UniqueRandomness(rho));
            let r = Some(sprout::CommitmentRandomness(r));
            let a_sk = Some(sprout::SpendingKey(sk));

            // skip the first byte
            assert_eq!(auth[0], SPROUT_TREE_DEPTH as u8);
            auth = &auth[1..];

            let mut auth_path = [None; SPROUT_TREE_DEPTH];
            for i in (0..SPROUT_TREE_DEPTH).rev() {
                // skip length of inner vector
                assert_eq!(auth[0], 32);
                auth = &auth[1..];

                let mut sibling = [0u8; 32];
                sibling.copy_from_slice(&auth[0..32]);
                auth = &auth[32..];

                auth_path[i] = Some((sibling, false));
            }

            let mut position = auth.read_u64::<LittleEndian>()
                .expect("should have had index at the end");

            for i in 0..SPROUT_TREE_DEPTH {
                auth_path[i].as_mut().map(|p| p.1 = (position & 1) == 1);

                position >>= 1;
            }

            inputs.push(sprout::JSInput {
                value: value,
                a_sk: a_sk,
                rho: rho,
                r: r,
                auth_path: auth_path,
            });
        };

        handle_input(in_sk1, in_value1, in_rho1, in_r1, &in_auth1[..]);
        handle_input(in_sk2, in_value2, in_rho2, in_r2, &in_auth2[..]);
    }

    let mut outputs = Vec::with_capacity(2);
    {
        let mut handle_output = |a_pk, value, r| {
            outputs.push(sprout::JSOutput {
                value: Some(value),
                a_pk: Some(sprout::PayingKey(a_pk)),
                r: Some(sprout::CommitmentRandomness(r)),
            });
        };

        handle_output(out_pk1, out_value1, out_r1);
        handle_output(out_pk2, out_value2, out_r2);
    }

    let js = sprout::JoinSplit {
        vpub_old: Some(vpub_old),
        vpub_new: Some(vpub_new),
        h_sig: Some(h_sig),
        phi: Some(phi),
        inputs: inputs,
        outputs: outputs,
        rt: Some(rt),
    };

    // Load parameters from disk
    let sprout_fs = File::open(
        unsafe { &SPROUT_GROTH16_PARAMS_PATH }
            .as_ref()
            .expect("parameters should have been initialized"),
    ).expect("couldn't load Sprout groth16 parameters file");

    let mut sprout_fs = BufReader::with_capacity(1024 * 1024, sprout_fs);

    let params = Parameters::<Bls12>::read(&mut sprout_fs, false)
        .expect("couldn't deserialize Sprout JoinSplit parameters file");

    drop(sprout_fs);

    // Initialize secure RNG
    let mut rng = OsRng::new().expect("should be able to construct RNG");

    let proof = create_random_proof(js, &params, &mut rng).expect("proving should not fail");

    proof
        .write(&mut (unsafe { &mut *proof_out })[..])
        .expect("should be able to serialize a proof");
}

#[no_mangle]
pub extern "system" fn librustzcash_sprout_verify(
    proof: *const [c_uchar; GROTH_PROOF_SIZE],
    rt: *const [c_uchar; 32],
    h_sig: *const [c_uchar; 32],
    mac1: *const [c_uchar; 32],
    mac2: *const [c_uchar; 32],
    nf1: *const [c_uchar; 32],
    nf2: *const [c_uchar; 32],
    cm1: *const [c_uchar; 32],
    cm2: *const [c_uchar; 32],
    vpub_old: uint64_t,
    vpub_new: uint64_t,
) -> bool {
    // Prepare the public input for the verifier
    let mut public_input = Vec::with_capacity((32 * 8) + (8 * 2));
    public_input.extend(unsafe { &(&*rt)[..] });
    public_input.extend(unsafe { &(&*h_sig)[..] });
    public_input.extend(unsafe { &(&*nf1)[..] });
    public_input.extend(unsafe { &(&*mac1)[..] });
    public_input.extend(unsafe { &(&*nf2)[..] });
    public_input.extend(unsafe { &(&*mac2)[..] });
    public_input.extend(unsafe { &(&*cm1)[..] });
    public_input.extend(unsafe { &(&*cm2)[..] });
    public_input.write_u64::<LittleEndian>(vpub_old).unwrap();
    public_input.write_u64::<LittleEndian>(vpub_new).unwrap();

    let public_input = multipack::bytes_to_bits(&public_input);
    let public_input = multipack::compute_multipacking::<Bls12>(&public_input);

    let proof = match Proof::read(unsafe { &(&*proof)[..] }) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Verify the proof
    match verify_proof(
        unsafe { SPROUT_GROTH16_VK.as_ref() }.expect("parameters should have been initialized"),
        &proof,
        &public_input[..],
    ) {
        // No error, and proof verification successful
        Ok(true) => true,

        // Any other case
        _ => false,
    }
}
