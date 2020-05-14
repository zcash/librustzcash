//! *Zcash circuits and proofs.*
//!
//! `zcash_proofs` contains the zk-SNARK circuits used by Zcash, and the APIs for creating
//! and verifying proofs.

// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]

use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey, VerifyingKey};
use pairing::bls12_381::Bls12;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

pub mod circuit;
mod hashreader;
pub mod sapling;
pub mod sprout;

#[cfg(feature = "local-prover")]
pub mod prover;

pub fn load_parameters(
    spend_path: &Path,
    output_path: &Path,
    sprout_path: Option<&Path>,
) -> (
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    Option<PreparedVerifyingKey<Bls12>>,
) {
    // Sapling circuit hashes
    const SAPLING_SPEND_HASH: &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
    const SAPLING_OUTPUT_HASH: &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
    const SPROUT_HASH: &str = "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a";

    // Load from each of the paths
    let spend_fs = File::open(spend_path).expect("couldn't load Sapling spend parameters file");
    let output_fs = File::open(output_path).expect("couldn't load Sapling output parameters file");
    let sprout_fs =
        sprout_path.map(|p| File::open(p).expect("couldn't load Sprout groth16 parameters file"));

    let mut spend_fs = hashreader::HashReader::new(BufReader::with_capacity(1024 * 1024, spend_fs));
    let mut output_fs =
        hashreader::HashReader::new(BufReader::with_capacity(1024 * 1024, output_fs));
    let mut sprout_fs =
        sprout_fs.map(|fs| hashreader::HashReader::new(BufReader::with_capacity(1024 * 1024, fs)));

    // Deserialize params
    let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
        .expect("couldn't deserialize Sapling spend parameters file");
    let output_params = Parameters::<Bls12>::read(&mut output_fs, false)
        .expect("couldn't deserialize Sapling spend parameters file");

    // We only deserialize the verifying key for the Sprout parameters, which
    // appears at the beginning of the parameter file. The rest is loaded
    // during proving time.
    let sprout_vk = sprout_fs.as_mut().map(|mut fs| {
        VerifyingKey::<Bls12>::read(&mut fs)
            .expect("couldn't deserialize Sprout Groth16 verifying key")
    });

    // There is extra stuff (the transcript) at the end of the parameter file which is
    // used to verify the parameter validity, but we're not interested in that. We do
    // want to read it, though, so that the BLAKE2b computed afterward is consistent
    // with `b2sum` on the files.
    let mut sink = io::sink();
    io::copy(&mut spend_fs, &mut sink)
        .expect("couldn't finish reading Sapling spend parameter file");
    io::copy(&mut output_fs, &mut sink)
        .expect("couldn't finish reading Sapling output parameter file");
    if let Some(mut sprout_fs) = sprout_fs.as_mut() {
        io::copy(&mut sprout_fs, &mut sink)
            .expect("couldn't finish reading Sprout groth16 parameter file");
    }

    if spend_fs.into_hash() != SAPLING_SPEND_HASH {
        panic!("Sapling spend parameter file is not correct, please clean your `~/.zcash-params/` and re-run `fetch-params`.");
    }

    if output_fs.into_hash() != SAPLING_OUTPUT_HASH {
        panic!("Sapling output parameter file is not correct, please clean your `~/.zcash-params/` and re-run `fetch-params`.");
    }

    if sprout_fs
        .map(|fs| fs.into_hash() != SPROUT_HASH)
        .unwrap_or(false)
    {
        panic!("Sprout groth16 parameter file is not correct, please clean your `~/.zcash-params/` and re-run `fetch-params`.");
    }

    // Prepare verifying keys
    let spend_vk = prepare_verifying_key(&spend_params.vk);
    let output_vk = prepare_verifying_key(&output_params.vk);
    let sprout_vk = sprout_vk.map(|vk| prepare_verifying_key(&vk));

    (spend_params, spend_vk, output_params, output_vk, sprout_vk)
}
