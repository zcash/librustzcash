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
//! [`CompactBlock`]: zcash_client_backend::proto::compact_formats::CompactBlock
//! [`init_cache_database`]: crate::init::init_cache_database

use rusqlite::{Connection, NO_PARAMS};
use std::cmp;
use zcash_client_backend::{
    constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS, encoding::encode_payment_address,
};
use zcash_primitives::zip32::ExtendedFullViewingKey;

pub mod error;
pub mod init;
pub mod query;
pub mod scan;

const ANCHOR_OFFSET: u32 = 10;
const SAPLING_ACTIVATION_HEIGHT: i32 = 280_000;

fn address_from_extfvk(extfvk: &ExtendedFullViewingKey) -> String {
    let addr = extfvk.default_address().unwrap().1;
    encode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, &addr)
}

/// Determines the target height for a transaction, and the height from which to
/// select anchors, based on the current synchronised block chain.
fn get_target_and_anchor_heights(data: &Connection) -> Result<(u32, u32), error::Error> {
    data.query_row_and_then(
        "SELECT MIN(height), MAX(height) FROM blocks",
        NO_PARAMS,
        |row| match (row.get::<_, u32>(0), row.get::<_, u32>(1)) {
            // If there are no blocks, the query returns NULL.
            (Err(rusqlite::Error::InvalidColumnType(_, _, _)), _)
            | (_, Err(rusqlite::Error::InvalidColumnType(_, _, _))) => {
                Err(error::Error(error::ErrorKind::ScanRequired))
            }
            (Err(e), _) | (_, Err(e)) => Err(e.into()),
            (Ok(min_height), Ok(max_height)) => {
                let target_height = max_height + 1;

                // Select an anchor ANCHOR_OFFSET back from the target block,
                // unless that would be before the earliest block we have.
                let anchor_height =
                    cmp::max(target_height.saturating_sub(ANCHOR_OFFSET), min_height);

                Ok((target_height, anchor_height))
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use pairing::bls12_381::Bls12;
    use protobuf::Message;
    use rand_core::{OsRng, RngCore};
    use rusqlite::{types::ToSql, Connection};
    use std::path::Path;
    use zcash_client_backend::proto::compact_formats::{
        CompactBlock, CompactOutput, CompactSpend, CompactTx,
    };
    use zcash_primitives::{
        block::BlockHash,
        jubjub::fs::Fs,
        note_encryption::{Memo, SaplingNoteEncryption},
        primitives::{Note, PaymentAddress},
        transaction::components::Amount,
        zip32::ExtendedFullViewingKey,
        JUBJUB,
    };

    /// Create a fake CompactBlock at the given height, containing a single output paying
    /// the given address. Returns the CompactBlock and the nullifier for the new note.
    pub(crate) fn fake_compact_block(
        height: i32,
        prev_hash: BlockHash,
        extfvk: ExtendedFullViewingKey,
        value: Amount,
    ) -> (CompactBlock, Vec<u8>) {
        let to = extfvk.default_address().unwrap().1;

        // Create a fake Note for the account
        let mut rng = OsRng;
        let note = Note {
            g_d: to.diversifier().g_d::<Bls12>(&JUBJUB).unwrap(),
            pk_d: to.pk_d().clone(),
            value: value.into(),
            r: Fs::random(&mut rng),
        };
        let encryptor = SaplingNoteEncryption::new(
            extfvk.fvk.ovk,
            note.clone(),
            to.clone(),
            Memo::default(),
            &mut rng,
        );
        let cmu = note.cm(&JUBJUB).to_repr().as_ref().to_vec();
        let mut epk = vec![];
        encryptor.epk().write(&mut epk).unwrap();
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
        cb.set_height(height as u64);
        cb.hash.resize(32, 0);
        rng.fill_bytes(&mut cb.hash);
        cb.prevHash.extend_from_slice(&prev_hash.0);
        cb.vtx.push(ctx);
        (cb, note.nf(&extfvk.fvk.vk, 0, &JUBJUB))
    }

    /// Create a fake CompactBlock at the given height, spending a single note from the
    /// given address.
    pub(crate) fn fake_compact_block_spending(
        height: i32,
        prev_hash: BlockHash,
        (nf, in_value): (Vec<u8>, Amount),
        extfvk: ExtendedFullViewingKey,
        to: PaymentAddress<Bls12>,
        value: Amount,
    ) -> CompactBlock {
        let mut rng = OsRng;

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
                g_d: to.diversifier().g_d::<Bls12>(&JUBJUB).unwrap(),
                pk_d: to.pk_d().clone(),
                value: value.into(),
                r: Fs::random(&mut rng),
            };
            let encryptor = SaplingNoteEncryption::new(
                extfvk.fvk.ovk,
                note.clone(),
                to,
                Memo::default(),
                &mut rng,
            );
            let cmu = note.cm(&JUBJUB).to_repr().as_ref().to_vec();
            let mut epk = vec![];
            encryptor.epk().write(&mut epk).unwrap();
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
            let note = Note {
                g_d: change_addr.diversifier().g_d::<Bls12>(&JUBJUB).unwrap(),
                pk_d: change_addr.pk_d().clone(),
                value: (in_value - value).into(),
                r: Fs::random(&mut rng),
            };
            let encryptor = SaplingNoteEncryption::new(
                extfvk.fvk.ovk,
                note.clone(),
                change_addr,
                Memo::default(),
                &mut rng,
            );
            let cmu = note.cm(&JUBJUB).to_repr().as_ref().to_vec();
            let mut epk = vec![];
            encryptor.epk().write(&mut epk).unwrap();
            let enc_ciphertext = encryptor.encrypt_note_plaintext();

            let mut cout = CompactOutput::new();
            cout.set_cmu(cmu);
            cout.set_epk(epk);
            cout.set_ciphertext(enc_ciphertext[..52].to_vec());
            cout
        });

        let mut cb = CompactBlock::new();
        cb.set_height(height as u64);
        cb.hash.resize(32, 0);
        rng.fill_bytes(&mut cb.hash);
        cb.prevHash.extend_from_slice(&prev_hash.0);
        cb.vtx.push(ctx);
        cb
    }

    /// Insert a fake CompactBlock into the cache DB.
    pub(crate) fn insert_into_cache<P: AsRef<Path>>(db_cache: P, cb: &CompactBlock) {
        let cb_bytes = cb.write_to_bytes().unwrap();
        let cache = Connection::open(&db_cache).unwrap();
        cache
            .prepare("INSERT INTO compactblocks (height, data) VALUES (?, ?)")
            .unwrap()
            .execute(&[
                (cb.height as i32).to_sql().unwrap(),
                cb_bytes.to_sql().unwrap(),
            ])
            .unwrap();
    }
}
