//! *Zcash circuits and proofs.*
//!
//! `zcash_proofs` contains the zk-SNARK circuits used by Zcash, and the APIs for creating
//! and verifying proofs.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Catch documentation errors caused by code changes.
#![deny(broken_intra_doc_links)]
// Temporary until we have addressed all Result<T, ()> cases.
#![allow(clippy::result_unit_err)]

use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey, VerifyingKey};
use bls12_381::Bls12;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

#[cfg(feature = "directories")]
use directories::BaseDirs;
#[cfg(feature = "directories")]
use std::path::PathBuf;

pub mod circuit;
pub mod constants;
mod hashreader;
pub mod sapling;
pub mod sprout;

#[cfg(any(feature = "local-prover", feature = "bundled-prover"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "local-prover", feature = "bundled-prover")))
)]
pub mod prover;

// Circuit names

/// The sapling spend parameters file name.
#[cfg(any(feature = "local-prover", feature = "download-params"))]
pub const SAPLING_SPEND_NAME: &str = "sapling-spend.params";

/// The sapling output parameters file name.
#[cfg(any(feature = "local-prover", feature = "download-params"))]
pub const SAPLING_OUTPUT_NAME: &str = "sapling-output.params";

/// The sprout parameters file name.
#[cfg(any(feature = "local-prover", feature = "download-params"))]
pub const SPROUT_NAME: &str = "sprout-groth16.params";

// Circuit hashes
const SAPLING_SPEND_HASH: &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
const SAPLING_OUTPUT_HASH: &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
const SPROUT_HASH: &str = "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a";

#[cfg(feature = "download-params")]
const DOWNLOAD_URL: &str = "https://download.z.cash/downloads";

/// Returns the default folder that the Zcash proving parameters are located in.
#[cfg(feature = "directories")]
#[cfg_attr(docsrs, doc(cfg(feature = "directories")))]
pub fn default_params_folder() -> Option<PathBuf> {
    BaseDirs::new().map(|base_dirs| {
        if cfg!(any(windows, target_os = "macos")) {
            base_dirs.data_dir().join("ZcashParams")
        } else {
            base_dirs.home_dir().join(".zcash-params")
        }
    })
}

/// Download the Zcash Sapling parameters, check their hash, and store them in the default location.
///
/// This mirrors the behaviour of the `fetch-params.sh` script from `zcashd`.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
#[deprecated(
    since = "0.6.0",
    note = "please replace with `download_sapling_parameters`, and add `download_sprout_parameters` if needed"
)]
pub fn download_parameters() -> Result<(), minreq::Error> {
    download_sapling_parameters()
}

/// Download the Zcash Sapling parameters, storing them in the default location.
///
/// This mirrors the behaviour of the `fetch-params.sh` script from `zcashd`.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
pub fn download_sapling_parameters() -> Result<(), minreq::Error> {
    fetch_params(SAPLING_SPEND_NAME, SAPLING_SPEND_HASH)?;
    fetch_params(SAPLING_OUTPUT_NAME, SAPLING_OUTPUT_HASH)?;

    Ok(())
}

/// Download the Zcash Sprout parameters, check their has, and store them in the default location.
///
/// This mirrors the behaviour of the `fetch-params.sh` script from `zcashd`.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
pub fn download_sprout_parameters() -> Result<(), minreq::Error> {
    fetch_params(SPROUT_NAME, SPROUT_HASH)?;

    Ok(())
}

/// Download the specified parameters, check their hash, and store them in the default location.
///
/// This mirrors the behaviour of the `fetch-params.sh` script from `zcashd`.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
fn fetch_params(name: &str, expected_hash: &str) -> Result<(), minreq::Error> {
    use std::io::Write;

    // Ensure that the default Zcash parameters location exists.
    let params_dir = default_params_folder().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "Could not load default params folder")
    })?;
    std::fs::create_dir_all(&params_dir)?;

    // Download the parts directly
    // TODO: Sapling parameters are small enough for this, but Sprout parameters are ~720 MB.
    let part_1 = minreq::get(format!("{}/{}.part.1", DOWNLOAD_URL, name)).send()?;
    let part_2 = minreq::get(format!("{}/{}.part.2", DOWNLOAD_URL, name)).send()?;

    // Verify parameter file hash.
    let hash = blake2b_simd::State::new()
        .update(part_1.as_bytes())
        .update(part_2.as_bytes())
        .finalize()
        .to_hex();
    if &hash != expected_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} failed validation (expected: {}, actual: {}, fetched {} bytes)",
                name,
                expected_hash,
                hash,
                part_1.as_bytes().len() + part_2.as_bytes().len()
            ),
        )
        .into());
    }

    // Write parameter file.
    let mut f = File::create(params_dir.join(name))?;
    f.write_all(part_1.as_bytes())?;
    f.write_all(part_2.as_bytes())?;
    Ok(())
}

pub struct ZcashParameters {
    pub spend_params: Parameters<Bls12>,
    pub spend_vk: PreparedVerifyingKey<Bls12>,
    pub output_params: Parameters<Bls12>,
    pub output_vk: PreparedVerifyingKey<Bls12>,
    pub sprout_vk: Option<PreparedVerifyingKey<Bls12>>,
}

pub fn load_parameters(
    spend_path: &Path,
    output_path: &Path,
    sprout_path: Option<&Path>,
) -> ZcashParameters {
    // Load from each of the paths
    let spend_fs = File::open(spend_path).expect("couldn't load Sapling spend parameters file");
    let output_fs = File::open(output_path).expect("couldn't load Sapling output parameters file");
    let sprout_fs =
        sprout_path.map(|p| File::open(p).expect("couldn't load Sprout groth16 parameters file"));

    parse_parameters(
        BufReader::with_capacity(1024 * 1024, spend_fs),
        BufReader::with_capacity(1024 * 1024, output_fs),
        sprout_fs.map(|fs| BufReader::with_capacity(1024 * 1024, fs)),
    )
}

/// Parse Bls12 keys from bytes as serialized by [`Parameters::write`].
///
/// This function will panic if it encounters unparsable data.
pub fn parse_parameters<R: io::Read>(
    spend_fs: R,
    output_fs: R,
    sprout_fs: Option<R>,
) -> ZcashParameters {
    let mut spend_fs = hashreader::HashReader::new(spend_fs);
    let mut output_fs = hashreader::HashReader::new(output_fs);
    let mut sprout_fs = sprout_fs.map(hashreader::HashReader::new);

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

    ZcashParameters {
        spend_params,
        spend_vk,
        output_params,
        output_vk,
        sprout_vk,
    }
}
