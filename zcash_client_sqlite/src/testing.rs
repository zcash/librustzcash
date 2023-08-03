use std::collections::HashMap;

#[cfg(feature = "unstable")]
use std::{fs::File, path::Path};

use prost::Message;
use rand_core::{OsRng, RngCore};
use rusqlite::params;

use zcash_client_backend::{
    keys::{sapling, UnifiedFullViewingKey},
    proto::compact_formats::{
        self as compact, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
    },
};
use zcash_note_encryption::Domain;
use zcash_primitives::{
    block::BlockHash,
    consensus::{BlockHeight, Network, NetworkUpgrade, Parameters},
    legacy::TransparentAddress,
    memo::MemoBytes,
    sapling::{
        note_encryption::{sapling_note_encryption, SaplingDomain},
        util::generate_random_rseed,
        value::NoteValue,
        Note, Nullifier, PaymentAddress,
    },
    transaction::components::Amount,
    zip32::{sapling::DiversifiableFullViewingKey, DiversifierIndex},
};

#[cfg(feature = "transparent-inputs")]
use zcash_primitives::{legacy, legacy::keys::IncomingViewingKey};

use crate::{wallet::init::init_accounts_table, AccountId, WalletDb};

use super::BlockDb;

#[cfg(feature = "unstable")]
use super::chain::BlockMeta;

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

#[cfg(test)]
pub(crate) fn init_test_accounts_table(
    db_data: &mut WalletDb<rusqlite::Connection, Network>,
) -> (DiversifiableFullViewingKey, Option<TransparentAddress>) {
    let (ufvk, taddr) = init_test_accounts_table_ufvk(db_data);
    (ufvk.sapling().unwrap().clone(), taddr)
}

#[cfg(test)]
pub(crate) fn init_test_accounts_table_ufvk(
    db_data: &mut WalletDb<rusqlite::Connection, Network>,
) -> (UnifiedFullViewingKey, Option<TransparentAddress>) {
    let seed = [0u8; 32];
    let account = AccountId::from(0);
    let extsk = sapling::spending_key(&seed, network().coin_type(), account);
    let dfvk = extsk.to_diversifiable_full_viewing_key();

    #[cfg(feature = "transparent-inputs")]
    let (tkey, taddr) = {
        let tkey = legacy::keys::AccountPrivKey::from_seed(&network(), &seed, account)
            .unwrap()
            .to_account_pubkey();
        let taddr = tkey.derive_external_ivk().unwrap().default_address().0;
        (Some(tkey), Some(taddr))
    };

    #[cfg(not(feature = "transparent-inputs"))]
    let taddr = None;

    let ufvk = UnifiedFullViewingKey::new(
        #[cfg(feature = "transparent-inputs")]
        tkey,
        Some(dfvk),
        None,
    )
    .unwrap();

    let ufvks = HashMap::from([(account, ufvk.clone())]);
    init_accounts_table(db_data, &ufvks).unwrap();

    (ufvk, taddr)
}

#[allow(dead_code)]
pub(crate) enum AddressType {
    DefaultExternal,
    DiversifiedExternal(DiversifierIndex),
    Internal,
}

/// Create a fake CompactBlock at the given height, containing a single output paying
/// an address. Returns the CompactBlock and the nullifier for the new note.
pub(crate) fn fake_compact_block(
    height: BlockHeight,
    prev_hash: BlockHash,
    dfvk: &DiversifiableFullViewingKey,
    req: AddressType,
    value: Amount,
    initial_sapling_tree_size: u32,
) -> (CompactBlock, Nullifier) {
    let to = match req {
        AddressType::DefaultExternal => dfvk.default_address().1,
        AddressType::DiversifiedExternal(idx) => dfvk.find_address(idx).unwrap().1,
        AddressType::Internal => dfvk.change_address().1,
    };

    // Create a fake Note for the account
    let mut rng = OsRng;
    let rseed = generate_random_rseed(&network(), height, &mut rng);
    let note = Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
    let encryptor = sapling_note_encryption::<_, Network>(
        Some(dfvk.fvk().ovk),
        note.clone(),
        MemoBytes::empty(),
        &mut rng,
    );
    let cmu = note.cmu().to_bytes().to_vec();
    let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
        .0
        .to_vec();
    let enc_ciphertext = encryptor.encrypt_note_plaintext();

    // Create a fake CompactBlock containing the note
    let cout = CompactSaplingOutput {
        cmu,
        ephemeral_key,
        ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
    };
    let mut ctx = CompactTx::default();
    let mut txid = vec![0; 32];
    rng.fill_bytes(&mut txid);
    ctx.hash = txid;
    ctx.outputs.push(cout);
    let mut cb = CompactBlock {
        hash: {
            let mut hash = vec![0; 32];
            rng.fill_bytes(&mut hash);
            hash
        },
        height: height.into(),
        ..Default::default()
    };
    cb.prev_hash.extend_from_slice(&prev_hash.0);
    cb.vtx.push(ctx);
    cb.chain_metadata = Some(compact::ChainMetadata {
        sapling_commitment_tree_size: initial_sapling_tree_size
            + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        ..Default::default()
    });
    (cb, note.nf(&dfvk.fvk().vk.nk, 0))
}

/// Create a fake CompactBlock at the given height, spending a single note from the
/// given address.
pub(crate) fn fake_compact_block_spending(
    height: BlockHeight,
    prev_hash: BlockHash,
    (nf, in_value): (Nullifier, Amount),
    dfvk: &DiversifiableFullViewingKey,
    to: PaymentAddress,
    value: Amount,
    initial_sapling_tree_size: u32,
) -> CompactBlock {
    let mut rng = OsRng;
    let rseed = generate_random_rseed(&network(), height, &mut rng);

    // Create a fake CompactBlock containing the note
    let cspend = CompactSaplingSpend { nf: nf.to_vec() };
    let mut ctx = CompactTx::default();
    let mut txid = vec![0; 32];
    rng.fill_bytes(&mut txid);
    ctx.hash = txid;
    ctx.spends.push(cspend);

    // Create a fake Note for the payment
    ctx.outputs.push({
        let note = Note::from_parts(to, NoteValue::from_raw(value.into()), rseed);
        let encryptor = sapling_note_encryption::<_, Network>(
            Some(dfvk.fvk().ovk),
            note.clone(),
            MemoBytes::empty(),
            &mut rng,
        );
        let cmu = note.cmu().to_bytes().to_vec();
        let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
            .0
            .to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        CompactSaplingOutput {
            cmu,
            ephemeral_key,
            ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
        }
    });

    // Create a fake Note for the change
    ctx.outputs.push({
        let change_addr = dfvk.default_address().1;
        let rseed = generate_random_rseed(&network(), height, &mut rng);
        let note = Note::from_parts(
            change_addr,
            NoteValue::from_raw((in_value - value).unwrap().into()),
            rseed,
        );
        let encryptor = sapling_note_encryption::<_, Network>(
            Some(dfvk.fvk().ovk),
            note.clone(),
            MemoBytes::empty(),
            &mut rng,
        );
        let cmu = note.cmu().to_bytes().to_vec();
        let ephemeral_key = SaplingDomain::<Network>::epk_bytes(encryptor.epk())
            .0
            .to_vec();
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        CompactSaplingOutput {
            cmu,
            ephemeral_key,
            ciphertext: enc_ciphertext.as_ref()[..52].to_vec(),
        }
    });

    let mut cb = CompactBlock {
        hash: {
            let mut hash = vec![0; 32];
            rng.fill_bytes(&mut hash);
            hash
        },
        height: height.into(),
        ..Default::default()
    };
    cb.prev_hash.extend_from_slice(&prev_hash.0);
    cb.vtx.push(ctx);
    cb.chain_metadata = Some(compact::ChainMetadata {
        sapling_commitment_tree_size: initial_sapling_tree_size
            + cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum::<u32>(),
        ..Default::default()
    });
    cb
}

/// Insert a fake CompactBlock into the cache DB.
pub(crate) fn insert_into_cache(db_cache: &BlockDb, cb: &CompactBlock) {
    let cb_bytes = cb.encode_to_vec();
    db_cache
        .0
        .prepare("INSERT INTO compactblocks (height, data) VALUES (?, ?)")
        .unwrap()
        .execute(params![u32::from(cb.height()), cb_bytes,])
        .unwrap();
}

#[cfg(feature = "unstable")]
pub(crate) fn store_in_fsblockdb<P: AsRef<Path>>(
    fsblockdb_root: P,
    cb: &CompactBlock,
) -> BlockMeta {
    use std::io::Write;

    let meta = BlockMeta {
        height: cb.height(),
        block_hash: cb.hash(),
        block_time: cb.time,
        sapling_outputs_count: cb.vtx.iter().map(|tx| tx.outputs.len() as u32).sum(),
        orchard_actions_count: cb.vtx.iter().map(|tx| tx.actions.len() as u32).sum(),
    };

    let blocks_dir = fsblockdb_root.as_ref().join("blocks");
    let block_path = meta.block_file_path(&blocks_dir);

    File::create(block_path)
        .unwrap()
        .write_all(&cb.encode_to_vec())
        .unwrap();

    meta
}
