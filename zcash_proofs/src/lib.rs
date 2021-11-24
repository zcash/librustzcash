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

// Circuit parameter file sizes
const SAPLING_SPEND_BYTES: u64 = 47958396;
const SAPLING_OUTPUT_BYTES: u64 = 3592860;
const SPROUT_BYTES: u64 = 725523612;

#[cfg(feature = "download-params")]
const DOWNLOAD_URL: &str = "https://download.z.cash/downloads";

/// The paths to the Sapling parameter files.
#[cfg(feature = "download-params")]
pub struct SaplingParameterPaths {
    /// The path to the Sapling spend parameter file.
    pub spend: PathBuf,

    /// The path to the Sapling output parameter file.
    pub output: PathBuf,
}

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

/// Download the Zcash Sapling parameters if needed, and store them in the default location.
/// Always checks the sizes and hashes of the files, even if they didn't need to be downloaded.
///
/// A download timeout can be set using the `MINREQ_TIMEOUT` environmental variable.
///
/// This mirrors the behaviour of the `fetch-params.sh` script from `zcashd`.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
#[deprecated(
    since = "0.6.0",
    note = "please replace with `download_sapling_parameters`, and use `download_sprout_parameters` if needed"
)]
pub fn download_parameters() -> Result<(), minreq::Error> {
    download_sapling_parameters(None).map(|_sapling_paths| ())
}

/// Download the Zcash Sapling parameters if needed, and store them in the default location.
/// Always checks the sizes and hashes of the files, even if they didn't need to be downloaded.
///
/// This mirrors the behaviour of the `fetch-params.sh` script from `zcashd`.
///
/// Use `timeout` to set a timeout in seconds for each file download.
/// If `timeout` is `None`, a timeout can be set using the `MINREQ_TIMEOUT` environmental variable.
///
/// Returns the paths to the downloaded files.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
pub fn download_sapling_parameters(
    timeout: Option<u64>,
) -> Result<SaplingParameterPaths, minreq::Error> {
    let spend = fetch_params(
        SAPLING_SPEND_NAME,
        SAPLING_SPEND_HASH,
        SAPLING_SPEND_BYTES,
        timeout,
    )?;
    let output = fetch_params(
        SAPLING_OUTPUT_NAME,
        SAPLING_OUTPUT_HASH,
        SAPLING_OUTPUT_BYTES,
        timeout,
    )?;

    Ok(SaplingParameterPaths { spend, output })
}

/// Download the Zcash Sprout parameters if needed, and store them in the default location.
/// Always checks the size and hash of the file, even if it didn't need to be downloaded.
///
/// This mirrors the behaviour of the `fetch-params.sh` script from `zcashd`.
///
/// Use `timeout` to set a timeout in seconds for the file download.
/// If `timeout` is `None`, a timeout can be set using the `MINREQ_TIMEOUT` environmental variable.
///
/// Returns the path to the downloaded file.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
pub fn download_sprout_parameters(timeout: Option<u64>) -> Result<PathBuf, minreq::Error> {
    fetch_params(SPROUT_NAME, SPROUT_HASH, SPROUT_BYTES, timeout)
}

/// Download the specified parameters if needed, and store them in the default location.
/// Always checks the size and hash of the file, even if it didn't need to be downloaded.
///
/// Returns the path to the downloaded file.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
fn fetch_params(
    name: &str,
    expected_hash: &str,
    expected_bytes: u64,
    timeout: Option<u64>,
) -> Result<PathBuf, minreq::Error> {
    use std::io::{BufWriter, Read};

    // Ensure that the default Zcash parameters location exists.
    let params_dir = default_params_folder().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "Could not load default params folder")
    })?;
    std::fs::create_dir_all(&params_dir)?;

    let params_path = params_dir.join(name);

    // Download parameters if needed.
    // TODO: use try_exists when it stabilises, to exit early on permissions errors (#83186)
    if !params_path.exists() {
        // Fail early if the directory isn't writeable.
        let new_params_file = File::create(&params_path)?;
        let new_params_file = BufWriter::with_capacity(1024 * 1024, new_params_file);

        // Set up the download requests.
        //
        // It's necessary for us to host these files in two parts,
        // because of CloudFlare's maximum cached file size limit of 512 MB.
        // The files must fit in the cache to prevent "denial of wallet" attacks.
        let params_url_1 = format!("{}/{}.part.1", DOWNLOAD_URL, name);
        // TODO: skip empty part.2 files when downloading sapling spend and sapling output
        let params_url_2 = format!("{}/{}.part.2", DOWNLOAD_URL, name);

        let mut params_download_1 = minreq::get(&params_url_1);
        let mut params_download_2 = minreq::get(&params_url_2);
        if let Some(timeout) = timeout {
            params_download_1 = params_download_1.with_timeout(timeout);
            params_download_2 = params_download_2.with_timeout(timeout);
        }

        // Download the responses and write them to a new file,
        // verifying the hash as bytes are read.
        let params_download_1 = ResponseLazyReader(params_download_1.send_lazy()?);
        let params_download_2 = ResponseLazyReader(params_download_2.send_lazy()?);

        // Limit the download size to avoid DoS.
        let params_download = params_download_1
            .chain(params_download_2)
            .take(expected_bytes);
        let params_download = BufReader::with_capacity(1024 * 1024, params_download);
        let params_download = hashreader::HashReader::new(params_download);

        verify_hash(
            params_download,
            new_params_file,
            expected_hash,
            expected_bytes,
            name,
            &format!("{} + {}", params_url_1, params_url_2),
        )?;
    } else {
        // TODO: avoid reading the files twice
        // Either:
        // - return Ok if the paths exist, or
        // - always load and return the parameters, for newly downloaded and existing files.

        let file_path_string = params_path.to_string_lossy();

        // Check the file size is correct before hashing large amounts of data.
        verify_file_size(&params_path, expected_bytes, name, &file_path_string).expect(
            "parameter file size is not correct, \
             please clean your Zcash parameters directory and re-run `fetch-params`.",
        );

        // Read the file to verify the hash,
        // discarding bytes after they're hashed.
        let params_file = File::open(&params_path)?;
        let params_file = BufReader::with_capacity(1024 * 1024, params_file);
        let params_file = hashreader::HashReader::new(params_file);

        verify_hash(
            params_file,
            io::sink(),
            expected_hash,
            expected_bytes,
            name,
            &file_path_string,
        )?;
    }

    Ok(params_path)
}

#[cfg(feature = "download-params")]
struct ResponseLazyReader(minreq::ResponseLazy);

#[cfg(feature = "download-params")]
impl io::Read for ResponseLazyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Zero-sized buffer. This should never happen.
        if buf.len() == 0 {
            return Ok(0);
        }

        // minreq has a very limited lazy reading interface.
        match &mut self.0.next() {
            // Read one byte into the buffer.
            // We ignore the expected length, because we have no way of telling the BufReader.
            Some(Ok((byte, _length))) => {
                buf[0] = *byte;
                Ok(1)
            }

            // Reading failed.
            Some(Err(error)) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("download failed: {:?}", error),
            )),

            // Finished reading.
            None => Ok(0),
        }
    }
}

pub struct ZcashParameters {
    pub spend_params: Parameters<Bls12>,
    pub spend_vk: PreparedVerifyingKey<Bls12>,
    pub output_params: Parameters<Bls12>,
    pub output_vk: PreparedVerifyingKey<Bls12>,
    pub sprout_vk: Option<PreparedVerifyingKey<Bls12>>,
}

/// Load the specified parameters, checking the sizes and hashes of the files.
///
/// Returns the loaded parameters.
pub fn load_parameters(
    spend_path: &Path,
    output_path: &Path,
    sprout_path: Option<&Path>,
) -> ZcashParameters {
    // Check the file sizes are correct before hashing large amounts of data.
    verify_file_size(
        spend_path,
        SAPLING_SPEND_BYTES,
        "sapling spend",
        &spend_path.to_string_lossy(),
    )
    .expect(
        "parameter file size is not correct, \
         please clean your Zcash parameters directory and re-run `fetch-params`.",
    );

    verify_file_size(
        output_path,
        SAPLING_OUTPUT_BYTES,
        "sapling output",
        &output_path.to_string_lossy(),
    )
    .expect(
        "parameter file size is not correct, \
         please clean your Zcash parameters directory and re-run `fetch-params`.",
    );

    if let Some(sprout_path) = sprout_path {
        verify_file_size(
            sprout_path,
            SPROUT_BYTES,
            "sprout groth16",
            &sprout_path.to_string_lossy(),
        )
        .expect(
            "parameter file size is not correct, \
             please clean your Zcash parameters directory and re-run `fetch-params`.",
        );
    }

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

    // TODO: use the correct paths for Windows and macOS
    //       use the actual file paths supplied by the caller
    verify_hash(
        spend_fs,
        &mut sink,
        SAPLING_SPEND_HASH,
        SAPLING_SPEND_BYTES,
        SAPLING_SPEND_NAME,
        "a file",
    )
    .expect(
        "Sapling spend parameter file is not correct, \
         please clean your `~/.zcash-params/` and re-run `fetch-params`.",
    );

    verify_hash(
        output_fs,
        &mut sink,
        SAPLING_OUTPUT_HASH,
        SAPLING_OUTPUT_BYTES,
        SAPLING_OUTPUT_NAME,
        "a file",
    )
    .expect(
        "Sapling output parameter file is not correct, \
         please clean your `~/.zcash-params/` and re-run `fetch-params`.",
    );

    if let Some(sprout_fs) = sprout_fs {
        verify_hash(
            sprout_fs,
            &mut sink,
            SPROUT_HASH,
            SPROUT_BYTES,
            SPROUT_NAME,
            "a file",
        )
        .expect(
            "Sprout groth16 parameter file is not correct, \
             please clean your `~/.zcash-params/` and re-run `fetch-params`.",
        );
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

/// Check if the size of the file at `params_path` matches `expected_bytes`,
/// using filesystem metadata.
///
/// Returns an error containing `name` and `params_source` on failure.
fn verify_file_size(
    params_path: &Path,
    expected_bytes: u64,
    name: &str,
    params_source: &str,
) -> Result<(), io::Error> {
    let file_size = std::fs::metadata(&params_path)?.len();

    if file_size != expected_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} failed validation: expected {} bytes, \
                 actual {} bytes from {:?}",
                name, expected_bytes, file_size, params_source,
            ),
        ));
    }

    Ok(())
}

/// Check if the Blake2b hash from `hash_reader` matches `expected_hash`,
/// while streaming from `data` into `sink`.
///
/// `hash_reader` can be used to partially read `data`,
/// before verifying the hash using this function.
///
/// Returns an error containing `name` and `params_source` on failure.
fn verify_hash<R: io::Read, W: io::Write>(
    mut hash_reader: hashreader::HashReader<R>,
    mut sink: W,
    expected_hash: &str,
    expected_bytes: u64,
    name: &str,
    params_source: &str,
) -> Result<(), io::Error> {
    let read_result = io::copy(&mut hash_reader, &mut sink);

    if let Err(read_error) = read_result {
        return Err(io::Error::new(
            read_error.kind(),
            format!(
                "{} failed reading after {} bytes, expected {} bytes from {:?}, error: {:?}",
                name,
                params_source,
                hash_reader.byte_count(),
                expected_bytes,
                read_error,
            ),
        ));
    }

    let byte_count = hash_reader.byte_count();
    let hash = hash_reader.into_hash();
    if hash != expected_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} failed validation: expected: {} hashing {} bytes, \
                 actual: {} hashing {} bytes from {:?}",
                name, expected_hash, expected_bytes, hash, byte_count, params_source,
            ),
        ));
    }

    Ok(())
}
