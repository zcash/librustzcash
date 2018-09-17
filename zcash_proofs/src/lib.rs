extern crate bellman;
extern crate blake2_rfc;
extern crate byteorder;
extern crate ff;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;

use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey, VerifyingKey};
use pairing::bls12_381::Bls12;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

mod hashreader;
pub mod sapling;

pub fn load_parameters(
    spend_path: &Path,
    spend_hash: &str,
    output_path: &Path,
    output_hash: &str,
    sprout_path: &Path,
    sprout_hash: &str,
) -> (
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    PreparedVerifyingKey<Bls12>,
) {
    // Load from each of the paths
    let spend_fs = File::open(spend_path).expect("couldn't load Sapling spend parameters file");
    let output_fs = File::open(output_path).expect("couldn't load Sapling output parameters file");
    let sprout_fs = File::open(sprout_path).expect("couldn't load Sprout groth16 parameters file");

    let mut spend_fs = hashreader::HashReader::new(BufReader::with_capacity(1024 * 1024, spend_fs));
    let mut output_fs =
        hashreader::HashReader::new(BufReader::with_capacity(1024 * 1024, output_fs));
    let mut sprout_fs =
        hashreader::HashReader::new(BufReader::with_capacity(1024 * 1024, sprout_fs));

    // Deserialize params
    let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
        .expect("couldn't deserialize Sapling spend parameters file");
    let output_params = Parameters::<Bls12>::read(&mut output_fs, false)
        .expect("couldn't deserialize Sapling spend parameters file");

    // We only deserialize the verifying key for the Sprout parameters, which
    // appears at the beginning of the parameter file. The rest is loaded
    // during proving time.
    let sprout_vk = VerifyingKey::<Bls12>::read(&mut sprout_fs)
        .expect("couldn't deserialize Sprout Groth16 verifying key");

    // There is extra stuff (the transcript) at the end of the parameter file which is
    // used to verify the parameter validity, but we're not interested in that. We do
    // want to read it, though, so that the BLAKE2b computed afterward is consistent
    // with `b2sum` on the files.
    let mut sink = io::sink();
    io::copy(&mut spend_fs, &mut sink)
        .expect("couldn't finish reading Sapling spend parameter file");
    io::copy(&mut output_fs, &mut sink)
        .expect("couldn't finish reading Sapling output parameter file");
    io::copy(&mut sprout_fs, &mut sink)
        .expect("couldn't finish reading Sprout groth16 parameter file");

    if spend_fs.into_hash() != spend_hash {
        panic!("Sapling spend parameter file is not correct, please clean your `~/.zcash-params/` and re-run `fetch-params`.");
    }

    if output_fs.into_hash() != output_hash {
        panic!("Sapling output parameter file is not correct, please clean your `~/.zcash-params/` and re-run `fetch-params`.");
    }

    if sprout_fs.into_hash() != sprout_hash {
        panic!("Sprout groth16 parameter file is not correct, please clean your `~/.zcash-params/` and re-run `fetch-params`.");
    }

    // Prepare verifying keys
    let spend_vk = prepare_verifying_key(&spend_params.vk);
    let output_vk = prepare_verifying_key(&output_params.vk);
    let sprout_vk = prepare_verifying_key(&sprout_vk);

    (spend_params, spend_vk, output_params, output_vk, sprout_vk)
}
