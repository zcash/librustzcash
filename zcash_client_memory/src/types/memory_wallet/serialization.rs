use bytes::{Buf, BufMut};
use consensus::Parameters;
use prost::Message;

use super::*;
use crate::error::Result;
use crate::proto::memwallet as proto;
use crate::read_optional;
use crate::wallet_commitment_trees::serialization::{tree_from_protobuf, tree_to_protobuf};

impl<P: Parameters> MemoryWalletDb<P> {
    /// Encode a memory wallet db as a protobuf byte buffer
    /// Always uses the latest version of the wire protocol
    pub fn encode<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        let proto_wallet: proto::MemoryWallet = self.into();
        proto_wallet.encode(buf)?;
        Ok(())
    }

    /// Create a mew memory wallet db from a protobuf encoded byte buffer with version awareness
    pub fn decode_new<B: Buf>(buf: B, params: P, max_checkpoints: usize) -> Result<Self> {
        let proto_wallet = proto::MemoryWallet::decode(buf)?;
        Self::new_from_proto(proto_wallet, params, max_checkpoints)
    }

    /// Build a memory wallet db from protobuf type with version awareness
    pub fn new_from_proto(
        proto_wallet: proto::MemoryWallet,
        params: P,
        max_checkpoints: usize,
    ) -> Result<Self> {
        match proto_wallet.version {
            1 => Self::new_from_proto_v1(proto_wallet, params, max_checkpoints),
            _ => Err(Error::UnsupportedProtoVersion(1, proto_wallet.version)),
        }
    }

    fn new_from_proto_v1(
        proto_wallet: proto::MemoryWallet,
        params: P,
        max_checkpoints: usize,
    ) -> Result<Self> {
        if proto_wallet.version != 1 {
            return Err(Error::UnsupportedProtoVersion(1, proto_wallet.version));
        }

        let mut wallet = MemoryWalletDb::new(params, max_checkpoints);

        wallet.accounts = {
            let proto_accounts = read_optional!(proto_wallet, accounts)?;
            let accounts = proto_accounts
                .accounts
                .into_iter()
                .map(|proto_account| {
                    let id = proto_account.account_id;
                    let account = Account::try_from(proto_account)?;
                    Ok((AccountId::from(id), account))
                })
                .collect::<Result<_>>()?;
            Ok::<Accounts, Error>(Accounts {
                accounts,
                nonce: proto_accounts.account_nonce,
            })
        }?;

        wallet.blocks = proto_wallet
            .blocks
            .into_iter()
            .map(|proto_block| {
                Ok((
                    proto_block.height.into(),
                    MemoryWalletBlock::try_from(proto_block)?,
                ))
            })
            .collect::<Result<_>>()?;

        wallet.tx_table = TransactionTable(
            proto_wallet
                .tx_table
                .into_iter()
                .map(|proto_tx| {
                    let txid = read_optional!(proto_tx, tx_id)?;
                    let tx = read_optional!(proto_tx, tx_entry)?;
                    Ok((txid.try_into()?, tx.try_into()?))
                })
                .collect::<Result<_>>()?,
        );

        wallet.received_notes = ReceivedNoteTable(
            proto_wallet
                .received_note_table
                .into_iter()
                .map(ReceivedNote::try_from)
                .collect::<Result<_>>()?,
        );

        wallet.received_note_spends = ReceievedNoteSpends(
            proto_wallet
                .received_note_spends
                .into_iter()
                .map(|proto_spend| {
                    let note_id = read_optional!(proto_spend, note_id)?;
                    let tx_id = read_optional!(proto_spend, tx_id)?;
                    Ok((note_id.try_into()?, tx_id.try_into()?))
                })
                .collect::<Result<_>>()?,
        );

        wallet.nullifiers = NullifierMap(
            proto_wallet
                .nullifiers
                .into_iter()
                .map(|proto_nullifier| {
                    let block_height = proto_nullifier.block_height.into();
                    let tx_index = proto_nullifier.tx_index;
                    let nullifier = read_optional!(proto_nullifier, nullifier)?.try_into()?;
                    Ok((nullifier, (block_height, tx_index)))
                })
                .collect::<Result<_>>()?,
        );

        wallet.sent_notes = SentNoteTable(
            proto_wallet
                .sent_notes
                .into_iter()
                .map(|proto_sent_note| {
                    let sent_note_id = read_optional!(proto_sent_note, sent_note_id)?;
                    let sent_note = read_optional!(proto_sent_note, sent_note)?;
                    Ok((sent_note_id.try_into()?, SentNote::try_from(sent_note)?))
                })
                .collect::<Result<_>>()?,
        );

        wallet.tx_locator = TxLocatorMap(
            proto_wallet
                .tx_locator
                .into_iter()
                .map(|proto_locator| {
                    let block_height = proto_locator.block_height.into();
                    let tx_index = proto_locator.tx_index;
                    let tx_id = read_optional!(proto_locator, tx_id)?.try_into()?;
                    Ok(((block_height, tx_index), tx_id))
                })
                .collect::<Result<_>>()?,
        );

        wallet.scan_queue = ScanQueue(
            proto_wallet
                .scan_queue
                .into_iter()
                .map(|item| item.into())
                .collect(),
        );

        wallet.sapling_tree =
            tree_from_protobuf(read_optional!(proto_wallet, sapling_tree)?, 100, 16.into())?;

        wallet.sapling_tree_shard_end_heights = proto_wallet
            .sapling_tree_shard_end_heights
            .into_iter()
            .map(|proto_end_height| {
                let address = Address::from_parts(
                    Level::from(u8::try_from(proto_end_height.level)?),
                    proto_end_height.index,
                );
                let height = proto_end_height.block_height.into();
                Ok((address, height))
            })
            .collect::<Result<_>>()?;

        #[cfg(feature = "orchard")]
        {
            wallet.orchard_tree =
                tree_from_protobuf(read_optional!(proto_wallet, orchard_tree)?, 100, 16.into())?;
        };

        #[cfg(feature = "orchard")]
        {
            wallet.orchard_tree_shard_end_heights = proto_wallet
                .orchard_tree_shard_end_heights
                .into_iter()
                .map(|proto_end_height| {
                    let address = Address::from_parts(
                        Level::from(u8::try_from(proto_end_height.level)?),
                        proto_end_height.index,
                    );
                    let height = proto_end_height.block_height.into();
                    Ok((address, height))
                })
                .collect::<Result<_>>()?;
        };

        wallet.transparent_received_outputs = TransparentReceivedOutputs(
            proto_wallet
                .transparent_received_outputs
                .into_iter()
                .map(|proto_output| {
                    let outpoint = read_optional!(proto_output, outpoint)?;
                    let output = read_optional!(proto_output, output)?.try_into()?;
                    Ok((OutPoint::try_from(outpoint)?, output))
                })
                .collect::<Result<_>>()?,
        );

        wallet.transparent_received_output_spends = TransparentReceivedOutputSpends(
            proto_wallet
                .transparent_received_output_spends
                .into_iter()
                .map(|proto_spend| {
                    let outpoint = read_optional!(proto_spend, outpoint)?;
                    let txid = read_optional!(proto_spend, tx_id)?.try_into()?;
                    Ok((OutPoint::try_from(outpoint)?, txid))
                })
                .collect::<Result<_>>()?,
        );

        wallet.transparent_spend_map = TransparentSpendCache(
            proto_wallet
                .transparent_spend_map
                .into_iter()
                .map(|proto_spend| {
                    let txid = read_optional!(proto_spend, tx_id)?.try_into()?;
                    let outpoint = read_optional!(proto_spend, outpoint)?;
                    Ok((txid, OutPoint::try_from(outpoint)?))
                })
                .collect::<Result<_>>()?,
        );

        wallet.transaction_data_request_queue = TransactionDataRequestQueue(
            proto_wallet
                .transaction_data_requests
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
        );

        Ok(wallet)
    }
}

impl From<&TxId> for proto::TxId {
    fn from(txid: &TxId) -> Self {
        proto::TxId {
            hash: txid.as_ref().to_vec(),
        }
    }
}

impl From<TxId> for proto::TxId {
    fn from(txid: TxId) -> Self {
        proto::TxId {
            hash: txid.as_ref().to_vec(),
        }
    }
}

impl TryFrom<proto::TxId> for TxId {
    type Error = Error;

    fn try_from(txid: proto::TxId) -> Result<Self> {
        Ok(TxId::from_bytes(txid.hash.try_into()?))
    }
}

impl<P: Parameters> From<&MemoryWalletDb<P>> for proto::MemoryWallet {
    fn from(wallet: &MemoryWalletDb<P>) -> Self {
        Self {
            version: 1,
            accounts: Some(proto::Accounts {
                accounts: wallet
                    .accounts
                    .accounts
                    .clone()
                    .into_values()
                    .map(proto::Account::from)
                    .collect(),
                account_nonce: wallet.accounts.nonce,
            }),

            blocks: wallet
                .blocks
                .clone()
                .into_values()
                .map(proto::WalletBlock::from)
                .collect(),

            tx_table: wallet
                .tx_table
                .0
                .clone()
                .into_iter()
                .map(|(txid, tx)| proto::TransactionTableRecord {
                    tx_id: Some(txid.into()),
                    tx_entry: Some(tx.into()),
                })
                .collect(),

            received_note_table: wallet
                .received_notes
                .iter()
                .map(|note| proto::ReceivedNote::from(note.clone()))
                .collect(),

            received_note_spends: wallet
                .received_note_spends
                .0
                .clone()
                .into_iter()
                .map(|(note_id, tx_id)| proto::ReceivedNoteSpendRecord {
                    note_id: Some(note_id.into()),
                    tx_id: Some(tx_id.into()),
                })
                .collect(),

            nullifiers: wallet
                .nullifiers
                .0
                .clone()
                .into_iter()
                .map(|(nullifier, (height, tx_index))| proto::NullifierRecord {
                    block_height: height.into(),
                    tx_index,
                    nullifier: Some(nullifier.into()),
                })
                .collect(),

            sent_notes: wallet
                .sent_notes
                .0
                .clone()
                .into_iter()
                .map(|(id, note)| proto::SentNoteRecord {
                    sent_note_id: Some(id.into()),
                    sent_note: Some(proto::SentNote::from(note)),
                })
                .collect(),

            tx_locator: wallet
                .tx_locator
                .0
                .clone()
                .into_iter()
                .map(|((height, tx_index), txid)| proto::TxLocatorRecord {
                    block_height: height.into(),
                    tx_index,
                    tx_id: Some(txid.into()),
                })
                .collect(),

            scan_queue: wallet
                .scan_queue
                .iter()
                .map(|r| proto::ScanQueueRecord::from(*r))
                .collect(),

            sapling_tree: tree_to_protobuf(&wallet.sapling_tree).unwrap(),
            sapling_tree_shard_end_heights: wallet
                .sapling_tree_shard_end_heights
                .clone()
                .into_iter()
                .map(|(address, height)| proto::TreeEndHeightsRecord {
                    level: address.level().into(),
                    index: address.index(),
                    block_height: height.into(),
                })
                .collect(),

            #[cfg(feature = "orchard")]
            orchard_tree: tree_to_protobuf(&wallet.orchard_tree).unwrap(),
            #[cfg(not(feature = "orchard"))]
            orchard_tree: None,

            #[cfg(feature = "orchard")]
            orchard_tree_shard_end_heights: wallet
                .orchard_tree_shard_end_heights
                .clone()
                .into_iter()
                .map(|(address, height)| proto::TreeEndHeightsRecord {
                    level: address.level().into(),
                    index: address.index(),
                    block_height: height.into(),
                })
                .collect(),
            #[cfg(not(feature = "orchard"))]
            orchard_tree_shard_end_heights: Vec::new(),

            transparent_received_outputs: wallet
                .transparent_received_outputs
                .0
                .clone()
                .into_iter()
                .map(
                    |(outpoint, output)| proto::TransparentReceivedOutputRecord {
                        outpoint: Some(proto::OutPoint::from(outpoint)),
                        output: Some(proto::ReceivedTransparentOutput::from(output)),
                    },
                )
                .collect(),

            transparent_received_output_spends: wallet
                .transparent_received_output_spends
                .0
                .clone()
                .into_iter()
                .map(
                    |(outpoint, txid)| proto::TransparentReceivedOutputSpendRecord {
                        outpoint: Some(proto::OutPoint::from(outpoint)),
                        tx_id: Some(txid.into()),
                    },
                )
                .collect(),

            transparent_spend_map: wallet
                .transparent_spend_map
                .0
                .clone()
                .into_iter()
                .map(|(txid, outpoint)| proto::TransparentSpendCacheRecord {
                    tx_id: Some(txid.into()),
                    outpoint: Some(proto::OutPoint::from(outpoint)),
                })
                .collect(),

            transaction_data_requests: wallet
                .transaction_data_request_queue
                .0
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}
