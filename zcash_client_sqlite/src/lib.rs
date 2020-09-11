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

use std::fmt;
use std::path::Path;

use rusqlite::{types::ToSql, Connection, Statement, NO_PARAMS};

use ff::PrimeField;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    note_encryption::Memo,
    primitives::PaymentAddress,
    sapling::Node,
    transaction::{components::Amount, Transaction, TxId},
    zip32::ExtendedFullViewingKey,
};

use zcash_client_backend::{
    address::RecipientAddress,
    data_api::{error::Error, CacheOps, DBOps, DBUpdate, ShieldedOutput},
    encoding::encode_payment_address,
    proto::compact_formats::CompactBlock,
    wallet::{AccountId, SpendableNote, WalletTx},
    DecryptedOutput,
};

use crate::error::SqliteClientError;

pub mod chain;
pub mod error;
pub mod wallet;

#[derive(Debug, Copy, Clone)]
pub struct NoteId(pub i64);

impl fmt::Display for NoteId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Note {}", self.0)
    }
}

pub struct DataConnection(Connection);

impl DataConnection {
    pub fn for_path<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        Connection::open(path).map(DataConnection)
    }
}

impl<'a> DBOps for &'a DataConnection {
    type Error = SqliteClientError;
    type NoteRef = NoteId;
    type TxRef = i64;
    type UpdateOps = DataConnStmtCache<'a>;

    fn block_height_extrema(&self) -> Result<Option<(BlockHeight, BlockHeight)>, Self::Error> {
        wallet::block_height_extrema(self).map_err(SqliteClientError::from)
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        wallet::get_block_hash(self, block_height).map_err(SqliteClientError::from)
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        wallet::get_tx_height(self, txid).map_err(SqliteClientError::from)
    }

    fn get_extended_full_viewing_keys<P: consensus::Parameters>(
        &self,
        params: &P,
    ) -> Result<Vec<ExtendedFullViewingKey>, Self::Error> {
        wallet::get_extended_full_viewing_keys(self, params)
    }

    fn get_address<P: consensus::Parameters>(
        &self,
        params: &P,
        account: AccountId,
    ) -> Result<Option<PaymentAddress>, Self::Error> {
        wallet::get_address(self, params, account)
    }

    fn is_valid_account_extfvk<P: consensus::Parameters>(
        &self,
        params: &P,
        account: AccountId,
        extfvk: &ExtendedFullViewingKey,
    ) -> Result<bool, Self::Error> {
        wallet::is_valid_account_extfvk(self, params, account, extfvk)
    }

    fn get_balance(&self, account: AccountId) -> Result<Amount, Self::Error> {
        wallet::get_balance(self, account)
    }

    fn get_verified_balance(
        &self,
        account: AccountId,
        anchor_height: BlockHeight,
    ) -> Result<Amount, Self::Error> {
        wallet::get_verified_balance(self, account, anchor_height)
    }

    fn get_received_memo_as_utf8(
        &self,
        id_note: Self::NoteRef,
    ) -> Result<Option<String>, Self::Error> {
        wallet::get_received_memo_as_utf8(self, id_note)
    }

    fn get_sent_memo_as_utf8(&self, id_note: Self::NoteRef) -> Result<Option<String>, Self::Error> {
        wallet::get_sent_memo_as_utf8(self, id_note)
    }

    fn get_commitment_tree(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<CommitmentTree<Node>>, Self::Error> {
        wallet::get_commitment_tree(self, block_height)
    }

    fn get_witnesses(
        &self,
        block_height: BlockHeight,
    ) -> Result<Vec<(Self::NoteRef, IncrementalWitness<Node>)>, Self::Error> {
        wallet::get_witnesses(self, block_height)
    }

    fn get_nullifiers(&self) -> Result<Vec<(Vec<u8>, AccountId)>, Self::Error> {
        wallet::get_nullifiers(self)
    }

    fn select_spendable_notes(
        &self,
        account: AccountId,
        target_value: Amount,
        anchor_height: BlockHeight,
    ) -> Result<Vec<SpendableNote>, Self::Error> {
        wallet::transact::select_spendable_notes(self, account, target_value, anchor_height)
    }

    fn get_update_ops(&self) -> Result<Self::UpdateOps, Self::Error> {
        Ok(
            DataConnStmtCache {
                conn: self,
                stmt_insert_block: self.0.prepare(
                    "INSERT INTO blocks (height, hash, time, sapling_tree)
                    VALUES (?, ?, ?, ?)",
                )?,
                stmt_insert_tx_meta: self.0.prepare(
                    "INSERT INTO transactions (txid, block, tx_index)
                    VALUES (?, ?, ?)",
                )?,
                stmt_update_tx_meta: self.0.prepare(
                    "UPDATE transactions
                    SET block = ?, tx_index = ? WHERE txid = ?",
                )?,
                stmt_insert_tx_data: self.0.prepare(
                    "INSERT INTO transactions (txid, created, expiry_height, raw)
                    VALUES (?, ?, ?, ?)",
                )?,
                stmt_update_tx_data: self.0.prepare(
                    "UPDATE transactions
                    SET expiry_height = ?, raw = ? WHERE txid = ?",
                )?,
                stmt_select_tx_ref: self.0.prepare(
                    "SELECT id_tx FROM transactions WHERE txid = ?",
                )?,
                stmt_mark_recived_note_spent: self.0.prepare(
                    "UPDATE received_notes SET spent = ? WHERE nf = ?"
                )?,
                stmt_insert_received_note: self.0.prepare(
                    "INSERT INTO received_notes (tx, output_index, account, diversifier, value, rcm, memo, nf, is_change)
                    VALUES (:tx, :output_index, :account, :diversifier, :value, :rcm, :memo, :nf, :is_change)",
                )?,
                stmt_update_received_note: self.0.prepare(
                    "UPDATE received_notes
                    SET account = :account,
                        diversifier = :diversifier,
                        value = :value,
                        rcm = :rcm,
                        nf = IFNULL(:memo, nf),
                        memo = IFNULL(:nf, memo),
                        is_change = :is_change
                    WHERE tx = :tx AND output_index = :output_index",
                )?,
                stmt_select_received_note: self.0.prepare(
                    "SELECT id_note FROM received_notes WHERE tx = ? AND output_index = ?"
                )?,
                stmt_update_sent_note: self.0.prepare(
                    "UPDATE sent_notes
                    SET from_account = ?, address = ?, value = ?, memo = ?
                    WHERE tx = ? AND output_index = ?",
                )?,
                stmt_insert_sent_note: self.0.prepare(
                    "INSERT INTO sent_notes (tx, output_index, from_account, address, value, memo)
                    VALUES (?, ?, ?, ?, ?, ?)",
                )?,
                stmt_insert_witness: self.0.prepare(
                    "INSERT INTO sapling_witnesses (note, block, witness)
                    VALUES (?, ?, ?)",
                )?,
                stmt_prune_witnesses: self.0.prepare(
                    "DELETE FROM sapling_witnesses WHERE block < ?"
                )?,
                stmt_update_expired: self.0.prepare(
                    "UPDATE received_notes SET spent = NULL WHERE EXISTS (
                        SELECT id_tx FROM transactions
                        WHERE id_tx = received_notes.spent AND block IS NULL AND expiry_height < ?
                    )",
                )?,
            }
        )
    }
}

pub struct DataConnStmtCache<'a> {
    conn: &'a DataConnection,
    stmt_insert_block: Statement<'a>,

    stmt_insert_tx_meta: Statement<'a>,
    stmt_update_tx_meta: Statement<'a>,

    stmt_insert_tx_data: Statement<'a>,
    stmt_update_tx_data: Statement<'a>,
    stmt_select_tx_ref: Statement<'a>,

    stmt_mark_recived_note_spent: Statement<'a>,

    stmt_insert_received_note: Statement<'a>,
    stmt_update_received_note: Statement<'a>,
    stmt_select_received_note: Statement<'a>,

    stmt_insert_sent_note: Statement<'a>,
    stmt_update_sent_note: Statement<'a>,

    stmt_insert_witness: Statement<'a>,
    stmt_prune_witnesses: Statement<'a>,
    stmt_update_expired: Statement<'a>,
}

impl<'a> DBUpdate for DataConnStmtCache<'a> {
    type Error = SqliteClientError;
    type TxRef = i64;
    type NoteRef = NoteId;

    fn transactionally<F, A>(&mut self, f: F) -> Result<A, Self::Error>
    where
        F: FnOnce(&mut Self) -> Result<A, Self::Error>,
    {
        self.conn.0.execute("BEGIN IMMEDIATE", NO_PARAMS)?;
        match f(self) {
            Ok(result) => {
                self.conn.0.execute("COMMIT", NO_PARAMS)?;
                Ok(result)
            }
            Err(error) => {
                match self.conn.0.execute("ROLLBACK", NO_PARAMS) {
                    Ok(_) => Err(error),
                    Err(e) =>
                        // REVIEW: If rollback fails, what do we want to do? I think that
                        // panicking here is probably the right thing to do, because it
                        // means the database is corrupt?
                        panic!(
                            "Rollback failed with error {} while attempting to recover from error {}; database is likely corrupt.",
                            e,
                            error.0
                        )
                }
            }
        }
    }

    fn insert_block(
        &mut self,
        block_height: BlockHeight,
        block_hash: BlockHash,
        block_time: u32,
        commitment_tree: &CommitmentTree<Node>,
    ) -> Result<(), Self::Error> {
        let mut encoded_tree = Vec::new();

        commitment_tree
            .write(&mut encoded_tree)
            .expect("Should be able to write to a Vec");

        self.stmt_insert_block.execute(&[
            u32::from(block_height).to_sql()?,
            block_hash.0.to_sql()?,
            block_time.to_sql()?,
            encoded_tree.to_sql()?,
        ])?;

        Ok(())
    }

    fn rewind_to_height<P: consensus::Parameters>(
        &mut self,
        parameters: &P,
        block_height: BlockHeight,
    ) -> Result<(), Self::Error> {
        wallet::rewind_to_height(self.conn, parameters, block_height)
    }

    fn put_tx_meta(
        &mut self,
        tx: &WalletTx,
        height: BlockHeight,
    ) -> Result<Self::TxRef, Self::Error> {
        let txid = tx.txid.0.to_vec();
        if self.stmt_update_tx_meta.execute(&[
            u32::from(height).to_sql()?,
            (tx.index as i64).to_sql()?,
            txid.to_sql()?,
        ])? == 0
        {
            // It isn't there, so insert our transaction into the database.
            self.stmt_insert_tx_meta.execute(&[
                txid.to_sql()?,
                u32::from(height).to_sql()?,
                (tx.index as i64).to_sql()?,
            ])?;

            Ok(self.conn.0.last_insert_rowid())
        } else {
            // It was there, so grab its row number.
            self.stmt_select_tx_ref
                .query_row(&[txid], |row| row.get(0))
                .map_err(SqliteClientError::from)
        }
    }

    fn put_tx_data(
        &mut self,
        tx: &Transaction,
        created_at: Option<time::OffsetDateTime>,
    ) -> Result<Self::TxRef, Self::Error> {
        let txid = tx.txid().0.to_vec();

        let mut raw_tx = vec![];
        tx.write(&mut raw_tx)?;

        if self.stmt_update_tx_data.execute(&[
            u32::from(tx.expiry_height).to_sql()?,
            raw_tx.to_sql()?,
            txid.to_sql()?,
        ])? == 0
        {
            // It isn't there, so insert our transaction into the database.
            self.stmt_insert_tx_data.execute(&[
                txid.to_sql()?,
                created_at.to_sql()?,
                u32::from(tx.expiry_height).to_sql()?,
                raw_tx.to_sql()?,
            ])?;

            Ok(self.conn.0.last_insert_rowid())
        } else {
            // It was there, so grab its row number.
            self.stmt_select_tx_ref
                .query_row(&[txid], |row| row.get(0))
                .map_err(SqliteClientError::from)
        }
    }

    fn mark_spent(&mut self, tx_ref: Self::TxRef, nf: &[u8]) -> Result<(), Self::Error> {
        self.stmt_mark_recived_note_spent
            .execute(&[tx_ref.to_sql()?, nf.to_sql()?])?;
        Ok(())
    }

    // Assumptions:
    // - A transaction will not contain more than 2^63 shielded outputs.
    // - A note value will never exceed 2^63 zatoshis.
    fn put_received_note<T: ShieldedOutput>(
        &mut self,
        output: &T,
        nf: Option<&[u8]>,
        tx_ref: Self::TxRef,
    ) -> Result<Self::NoteRef, Self::Error> {
        let rcm = output.note().rcm().to_repr();
        let account = output.account().0 as i64;
        let diversifier = output.to().diversifier().0.to_vec();
        let value = output.note().value as i64;
        let rcm = rcm.as_ref();
        let memo = output.memo().map(|m| m.as_bytes());
        let is_change = output.is_change();
        let tx = tx_ref;
        let output_index = output.index() as i64;

        let sql_args: Vec<(&str, &dyn ToSql)> = vec![
            (&":account", &account),
            (&":diversifier", &diversifier),
            (&":value", &value),
            (&":rcm", &rcm),
            (&":nf", &nf),
            (&":memo", &memo),
            (&":is_change", &is_change),
            (&":tx", &tx),
            (&":output_index", &output_index),
        ];

        // First try updating an existing received note into the database.
        if self.stmt_update_received_note.execute_named(&sql_args)? == 0 {
            // It isn't there, so insert our note into the database.
            self.stmt_insert_received_note.execute_named(&sql_args)?;

            Ok(NoteId(self.conn.0.last_insert_rowid()))
        } else {
            // It was there, so grab its row number.
            self.stmt_select_received_note
                .query_row(
                    &[tx_ref.to_sql()?, (output.index() as i64).to_sql()?],
                    |row| row.get(0).map(NoteId),
                )
                .map_err(SqliteClientError::from)
        }
    }

    fn insert_witness(
        &mut self,
        note_id: Self::NoteRef,
        witness: &IncrementalWitness<Node>,
        height: BlockHeight,
    ) -> Result<(), Self::Error> {
        let mut encoded = Vec::new();
        witness
            .write(&mut encoded)
            .expect("Should be able to write to a Vec");
        self.stmt_insert_witness.execute(&[
            note_id.0.to_sql()?,
            u32::from(height).to_sql()?,
            encoded.to_sql()?,
        ])?;

        Ok(())
    }

    fn prune_witnesses(&mut self, below_height: BlockHeight) -> Result<(), Self::Error> {
        self.stmt_prune_witnesses
            .execute(&[u32::from(below_height)])?;
        Ok(())
    }

    fn update_expired_notes(&mut self, height: BlockHeight) -> Result<(), Self::Error> {
        self.stmt_update_expired.execute(&[u32::from(height)])?;
        Ok(())
    }

    fn put_sent_note<P: consensus::Parameters>(
        &mut self,
        params: &P,
        output: &DecryptedOutput,
        tx_ref: Self::TxRef,
    ) -> Result<(), Self::Error> {
        let output_index = output.index as i64;
        let account = output.account as i64;
        let value = output.note.value as i64;
        let to_str = encode_payment_address(params.hrp_sapling_payment_address(), &output.to);

        // Try updating an existing sent note.
        if self.stmt_update_sent_note.execute(&[
            account.to_sql()?,
            to_str.to_sql()?,
            value.to_sql()?,
            output.memo.as_bytes().to_sql()?,
            tx_ref.to_sql()?,
            output_index.to_sql()?,
        ])? == 0
        {
            // It isn't there, so insert.
            self.insert_sent_note(
                params,
                tx_ref,
                output.index,
                AccountId(output.account as u32),
                &RecipientAddress::Shielded(output.to.clone()),
                Amount::from_u64(output.note.value)
                    .map_err(|_| Error::CorruptedData("Note value invalid."))?,
                Some(output.memo.clone()),
            )?
        }

        Ok(())
    }

    fn insert_sent_note<P: consensus::Parameters>(
        &mut self,
        params: &P,
        tx_ref: Self::TxRef,
        output_index: usize,
        account: AccountId,
        to: &RecipientAddress,
        value: Amount,
        memo: Option<Memo>,
    ) -> Result<(), Self::Error> {
        let to_str = to.encode(params);
        let ivalue: i64 = value.into();
        self.stmt_insert_sent_note.execute(&[
            tx_ref.to_sql()?,
            (output_index as i64).to_sql()?,
            account.0.to_sql()?,
            to_str.to_sql()?,
            ivalue.to_sql()?,
            memo.map(|m| m.as_bytes().to_vec()).to_sql()?,
        ])?;

        Ok(())
    }
}

pub struct CacheConnection(Connection);

impl CacheConnection {
    pub fn for_path<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        Connection::open(path).map(CacheConnection)
    }
}

impl CacheOps for CacheConnection {
    type Error = SqliteClientError;

    fn init_cache(&self) -> Result<(), Self::Error> {
        chain::init::init_cache_database(self).map_err(SqliteClientError::from)
    }

    fn validate_chain<F>(
        &self,
        from_height: BlockHeight,
        validate: F,
    ) -> Result<Option<BlockHash>, Self::Error>
    where
        F: Fn(&CompactBlock, &CompactBlock) -> Result<(), Self::Error>,
    {
        chain::validate_chain(self, from_height, validate)
    }

    fn with_cached_blocks<F>(
        &self,
        from_height: BlockHeight,
        limit: Option<u32>,
        with_row: F,
    ) -> Result<(), Self::Error>
    where
        F: FnMut(BlockHeight, CompactBlock) -> Result<(), Self::Error>,
    {
        chain::with_cached_blocks(self, from_height, limit, with_row)
    }
}

fn address_from_extfvk<P: consensus::Parameters>(
    params: &P,
    extfvk: &ExtendedFullViewingKey,
) -> String {
    let addr = extfvk.default_address().unwrap().1;
    encode_payment_address(params.hrp_sapling_payment_address(), &addr)
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
