//! *An SQLite-based Zcash light client.*
//!
//! `zcash_client_backend` contains a set of APIs that collectively implement an
//! SQLite-based light client for the Zcash network.
//!
//! # Design
//!
//! The light client is built around two SQLite databases:
//!
//! - A cache database, used to inform the light client about new [`CompactBlock`]s. It is
//!   read-only within all light client APIs *except* for [`init_cache_database`] which
//!   can be used to initialize the database.
//!
//! - A data database, where the light client's state is stored. It is read-write within
//!   the light client APIs, and **assumed to be read-only outside these APIs**. Callers
//!   **MUST NOT** write to the database without using these APIs. Callers **MAY** read
//!   the database directly in order to extract information for display to users.
//!
//! # Features
//!
//! The `mainnet` feature configures the light client for use with the Zcash mainnet. By
//! default, the light client is configured for use with the Zcash testnet.
//!
//! [`CompactBlock`]: zcash_client_backend::proto::compact_formats::CompactBlock
//! [`init_cache_database`]: crate::init::init_cache_database

use rusqlite::{Connection, NO_PARAMS};
use std::cmp;
use std::path::Path;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    zip32::ExtendedFullViewingKey,
};

use zcash_client_backend::{
    data_api::{chain::ANCHOR_OFFSET, error::Error, CacheOps, DBOps},
    encoding::encode_payment_address,
    proto::compact_formats::CompactBlock,
};

use crate::error::SqliteClientError;

pub mod chain;
pub mod error;
pub mod init;
pub mod query;
pub mod scan;
pub mod transact;

pub struct Account(u32);

pub struct DataConnection(Connection);

impl DataConnection {
    pub fn for_path<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        Connection::open(path).map(DataConnection)
    }
}

impl DBOps for DataConnection {
    type Error = Error<rusqlite::Error>;

    fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        chain::block_height_extrema(self).map_err(Error::Database)
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        chain::get_block_hash(self, block_height).map_err(Error::Database)
    }

    fn rewind_to_height<P: consensus::Parameters>(
        &self,
        parameters: &P,
        block_height: BlockHeight,
    ) -> Result<(), Self::Error> {
        chain::rewind_to_height(self, parameters, block_height).map_err(|e| e.0)
    }
}

pub struct CacheConnection(Connection);

impl CacheConnection {
    pub fn for_path<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        Connection::open(path).map(CacheConnection)
    }
}

impl CacheOps for CacheConnection {
    type Error = Error<rusqlite::Error>;

    fn validate_chain<F>(
        &self,
        from_height: BlockHeight,
        validate: F,
    ) -> Result<Option<BlockHash>, Self::Error>
    where
        F: Fn(&CompactBlock, &CompactBlock) -> Result<(), Self::Error>,
    {
        chain::validate_chain(self, from_height, validate).map_err(|s| s.0)
    }
}

fn address_from_extfvk<P: consensus::Parameters>(
    params: &P,
    extfvk: &ExtendedFullViewingKey,
) -> String {
    let addr = extfvk.default_address().unwrap().1;
    encode_payment_address(params.hrp_sapling_payment_address(), &addr)
}

/// Determines the target height for a transaction, and the height from which to
/// select anchors, based on the current synchronised block chain.
fn get_target_and_anchor_heights(
    data: &DataConnection,
) -> Result<(BlockHeight, BlockHeight), SqliteClientError> {
    data.0.query_row_and_then(
        "SELECT MIN(height), MAX(height) FROM blocks",
        NO_PARAMS,
        |row| match (row.get::<_, u32>(0), row.get::<_, u32>(1)) {
            // If there are no blocks, the query returns NULL.
            (Err(rusqlite::Error::InvalidColumnType(_, _, _)), _)
            | (_, Err(rusqlite::Error::InvalidColumnType(_, _, _))) => {
                Err(Error::ScanRequired.into())
            }
            (Err(e), _) | (_, Err(e)) => Err(e.into()),
            (Ok(min_height), Ok(max_height)) => {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height =
                    cmp::max(target_height.saturating_sub(ANCHOR_OFFSET), min_height);

                Ok((
                    BlockHeight::from(target_height),
                    BlockHeight::from(anchor_height),
                ))
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use group::GroupEncoding;
    use protobuf::Message;
    use rand_core::{OsRng, RngCore};
    use rusqlite::types::ToSql;

    use zcash_client_backend::proto::compact_formats::{
        CompactBlock, CompactOutput, CompactSpend, CompactTx,
    };

    use zcash_primitives::{
        block::BlockHash,
        consensus::{BlockHeight, Network, NetworkUpgrade, Parameters},
        note_encryption::{Memo, SaplingNoteEncryption},
        primitives::{Note, PaymentAddress},
        transaction::components::Amount,
        util::generate_random_rseed,
        zip32::ExtendedFullViewingKey,
    };

    use super::CacheConnection;

    #[cfg(feature = "mainnet")]
    pub(crate) fn network() -> Network {
        Network::MainNetwork
    }

    #[cfg(not(feature = "mainnet"))]
    pub(crate) fn network() -> Network {
        Network::TestNetwork
    }

    #[cfg(feature = "mainnet")]
    pub(crate) fn sapling_activation_height() -> BlockHeight {
        Network::MainNetwork
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap()
    }

    #[cfg(not(feature = "mainnet"))]
    pub(crate) fn sapling_activation_height() -> BlockHeight {
        Network::TestNetwork
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap()
    }

    /// Create a fake CompactBlock at the given height, containing a single output paying
    /// the given address. Returns the CompactBlock and the nullifier for the new note.
    pub(crate) fn fake_compact_block(
        height: BlockHeight,
        prev_hash: BlockHash,
        extfvk: ExtendedFullViewingKey,
        value: Amount,
    ) -> (CompactBlock, Vec<u8>) {
        let to = extfvk.default_address().unwrap().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let rseed = generate_random_rseed(&network(), height, &mut rng);
        let note = Note {
            g_d: to.diversifier().g_d().unwrap(),
            pk_d: to.pk_d().clone(),
            value: value.into(),
            rseed,
        };
        let encryptor = SaplingNoteEncryption::new(
            Some(extfvk.fvk.ovk),
            note.clone(),
            to.clone(),
            Memo::default(),
            &mut rng,
        );
        let cmu = note.cmu().to_repr().as_ref().to_vec();
        let epk = encryptor.epk().to_bytes().to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        // Create a fake CompactBlock containing the note
        let mut cout = CompactOutput::new();
        cout.set_cmu(cmu);
        cout.set_epk(epk);
        cout.set_ciphertext(enc_ciphertext[..52].to_vec());
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
        ctx.outputs.push(cout);
        let mut cb = CompactBlock::new();
        cb.set_height(u64::from(height));
        cb.hash.resize(32, 0);
        rng.fill_bytes(&mut cb.hash);
        cb.prevHash.extend_from_slice(&prev_hash.0);
        cb.vtx.push(ctx);
        (cb, note.nf(&extfvk.fvk.vk, 0))
    }

    /// Create a fake CompactBlock at the given height, spending a single note from the
    /// given address.
    pub(crate) fn fake_compact_block_spending(
        height: BlockHeight,
        prev_hash: BlockHash,
        (nf, in_value): (Vec<u8>, Amount),
        extfvk: ExtendedFullViewingKey,
        to: PaymentAddress,
        value: Amount,
    ) -> CompactBlock {
        let mut rng = OsRng;
        let rseed = generate_random_rseed(&network(), height, &mut rng);

        // Create a fake CompactBlock containing the note
        let mut cspend = CompactSpend::new();
        cspend.set_nf(nf);
        let mut ctx = CompactTx::new();
        let mut txid = vec![0; 32];
        rng.fill_bytes(&mut txid);
        ctx.set_hash(txid);
        ctx.spends.push(cspend);

        // Create a fake Note for the payment
        ctx.outputs.push({
            let note = Note {
                g_d: to.diversifier().g_d().unwrap(),
                pk_d: to.pk_d().clone(),
                value: value.into(),
                rseed,
            };
            let encryptor = SaplingNoteEncryption::new(
                Some(extfvk.fvk.ovk),
                note.clone(),
                to,
                Memo::default(),
                &mut rng,
            );
            let cmu = note.cmu().to_repr().as_ref().to_vec();
            let epk = encryptor.epk().to_bytes().to_vec();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            let mut cout = CompactOutput::new();
            cout.set_cmu(cmu);
            cout.set_epk(epk);
            cout.set_ciphertext(enc_ciphertext[..52].to_vec());
            cout
        });

        // Create a fake Note for the change
        ctx.outputs.push({
            let change_addr = extfvk.default_address().unwrap().1;
            let rseed = generate_random_rseed(&network(), height, &mut rng);
            let note = Note {
                g_d: change_addr.diversifier().g_d().unwrap(),
                pk_d: change_addr.pk_d().clone(),
                value: (in_value - value).into(),
                rseed,
            };
            let encryptor = SaplingNoteEncryption::new(
                Some(extfvk.fvk.ovk),
                note.clone(),
                change_addr,
                Memo::default(),
                &mut rng,
            );
            let cmu = note.cmu().to_repr().as_ref().to_vec();
            let epk = encryptor.epk().to_bytes().to_vec();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            let mut cout = CompactOutput::new();
            cout.set_cmu(cmu);
            cout.set_epk(epk);
            cout.set_ciphertext(enc_ciphertext[..52].to_vec());
            cout
        });

        let mut cb = CompactBlock::new();
        cb.set_height(u64::from(height));
        cb.hash.resize(32, 0);
        rng.fill_bytes(&mut cb.hash);
        cb.prevHash.extend_from_slice(&prev_hash.0);
        cb.vtx.push(ctx);
        cb
    }

    /// Insert a fake CompactBlock into the cache DB.
    pub(crate) fn insert_into_cache(db_cache: &CacheConnection, cb: &CompactBlock) {
        let cb_bytes = cb.write_to_bytes().unwrap();
        db_cache
            .0
            .prepare("INSERT INTO compactblocks (height, data) VALUES (?, ?)")
            .unwrap()
            .execute(&[
                u32::from(cb.height()).to_sql().unwrap(),
                cb_bytes.to_sql().unwrap(),
            ])
            .unwrap();
    }
}
