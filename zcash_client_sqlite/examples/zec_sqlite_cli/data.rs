use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use secrecy::{SecretVec, Zeroize};

use zcash_client_sqlite::chain::BlockMeta;
use zcash_primitives::zip339::Mnemonic;

use crate::error;

const DEFAULT_WALLET_DIR: &str = "./zec_sqlite_wallet";
const KEYS_FILE: &str = "keys.txt";
const BLOCKS_FOLDER: &str = "blocks";
const DATA_DB: &str = "data.sqlite";

pub(crate) fn init_wallet_keys<P: AsRef<Path>>(
    wallet_dir: Option<P>,
    mnemonic: &Mnemonic,
    birthday: u64,
) -> Result<(), anyhow::Error> {
    // Create the wallet directory.
    let wallet_dir = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref());
    fs::create_dir_all(&wallet_dir)?;

    // Write the mnemonic phrase to disk along with its birthday.
    let mut keys_file = {
        let mut p = wallet_dir.to_owned();
        p.push(KEYS_FILE);
        fs::OpenOptions::new().create_new(true).write(true).open(p)
    }?;
    writeln!(
        &mut keys_file,
        "{} # wallet mnemonic phrase",
        mnemonic.phrase()
    )?;
    writeln!(&mut keys_file, "{} # wallet birthday", birthday)?;

    Ok(())
}

pub(crate) fn get_keys_file<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> Result<BufReader<File>, anyhow::Error> {
    let mut p = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .to_owned();
    p.push(KEYS_FILE);
    Ok(BufReader::new(File::open(p)?))
}

pub(crate) fn get_wallet_seed<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> Result<SecretVec<u8>, anyhow::Error> {
    let keys_file = get_keys_file(wallet_dir)?;
    let mnemonic = Mnemonic::from_phrase(
        keys_file
            .lines()
            .next()
            .ok_or(error::Error::InvalidKeysFile)??
            .split('#')
            .next()
            .ok_or(error::Error::InvalidKeysFile)?
            .trim(),
    )?;
    let mut seed = mnemonic.to_seed("");
    let secret = seed.to_vec();
    seed.zeroize();
    Ok(SecretVec::new(secret))
}

// fn get_wallet_birthday<P: AsRef<Path>>(wallet_dir: Option<P>) -> Result<BlockHeight, error::Error> {
//     let keys_file = get_keys_file(wallet_dir)?;
//     keys_file
//         .lines()
//         .nth(1)
//         .ok_or(error::Error::InvalidKeysFile)??
//         .split('#')
//         .next()
//         .ok_or(error::Error::InvalidKeysFile)?
//         .trim()
//         .parse::<u32>()
//         .map(BlockHeight::from)
//         .map_err(|_| error::Error::InvalidKeysFile)
// }

pub(crate) fn get_db_paths<P: AsRef<Path>>(wallet_dir: Option<P>) -> (PathBuf, PathBuf) {
    let a = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .to_owned();
    let mut b = a.clone();
    b.push(DATA_DB);
    (a, b)
}

pub(crate) fn get_block_path(fsblockdb_root: &Path, meta: &BlockMeta) -> PathBuf {
    meta.block_file_path(&fsblockdb_root.join(BLOCKS_FOLDER))
}
