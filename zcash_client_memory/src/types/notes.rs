use incrementalmerkletree::Position;

use std::collections::HashMap;

use zip32::Scope;

use zcash_primitives::transaction::TxId;
use zcash_protocol::{memo::Memo, PoolType, ShieldedProtocol::Sapling};

use zcash_client_backend::{
    data_api::SentTransactionOutput,
    wallet::{Note, NoteId, Recipient, WalletSaplingOutput},
};

use crate::AccountId;

#[cfg(feature = "orchard")]
use {
    zcash_client_backend::wallet::WalletOrchardOutput, zcash_protocol::ShieldedProtocol::Orchard,
};

use crate::{error::Error, Nullifier};

/// Keeps track of notes that are spent in which transaction
pub(crate) struct ReceievdNoteSpends(HashMap<NoteId, TxId>);

impl ReceievdNoteSpends {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
    pub fn insert_spend(&mut self, note_id: NoteId, txid: TxId) -> Option<TxId> {
        self.0.insert(note_id, txid)
    }
}

/// A note that has been received by the wallet
/// TODO: Instead of Vec, perhaps we should identify by some unique ID
pub(crate) struct ReceivedNoteTable(pub Vec<ReceivedNote>);

pub(crate) struct ReceivedNote {
    // Uniquely identifies this note
    pub(crate) note_id: NoteId,
    pub(crate) txid: TxId,
    // output_index: sapling, action_index: orchard
    pub(crate) _output_index: u32,
    pub(crate) account_id: AccountId,
    //sapling: (diversifier, value, rcm) orchard: (diversifier, value, rho, rseed)
    pub(crate) _note: Note,
    pub(crate) nf: Option<Nullifier>,
    pub(crate) _is_change: bool,
    pub(crate) _memo: Memo,
    pub(crate) _commitment_tree_position: Option<Position>,
    pub(crate) _recipient_key_scope: Option<Scope>,
}
impl ReceivedNote {
    pub fn _pool(&self) -> PoolType {
        match self._note {
            Note::Sapling { .. } => PoolType::SAPLING,
            #[cfg(feature = "orchard")]
            Note::Orchard { .. } => PoolType::ORCHARD,
        }
    }
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }
    pub fn nullifier(&self) -> Option<&Nullifier> {
        self.nf.as_ref()
    }
    pub fn txid(&self) -> TxId {
        self.txid
    }
    pub fn note_id(&self) -> NoteId {
        self.note_id
    }
    pub fn from_sent_tx_output(
        txid: TxId,
        output: &SentTransactionOutput<AccountId>,
    ) -> Result<Self, Error> {
        match output.recipient() {
            Recipient::InternalAccount {
                receiving_account,
                note: Note::Sapling(note),
                ..
            } => Ok(ReceivedNote {
                note_id: NoteId::new(txid, Sapling, output.output_index() as u16),
                txid,
                _output_index: output.output_index() as u32,
                account_id: *receiving_account,
                _note: Note::Sapling(note.clone()),
                nf: None,
                _is_change: true,
                _memo: output.memo().map(|m| Memo::try_from(m).unwrap()).unwrap(),
                _commitment_tree_position: None,
                _recipient_key_scope: Some(Scope::Internal),
            }),
            #[cfg(feature = "orchard")]
            Recipient::InternalAccount {
                receiving_account,
                note: Note::Orchard(note),
                ..
            } => Ok(ReceivedNote {
                note_id: NoteId::new(txid, Orchard, output.output_index() as u16),
                txid,
                _output_index: output.output_index() as u32,
                account_id: *receiving_account,
                _note: Note::Orchard(*note),
                nf: None,
                _is_change: true,
                _memo: output.memo().map(|m| Memo::try_from(m).unwrap()).unwrap(),
                _commitment_tree_position: None,
                _recipient_key_scope: Some(Scope::Internal),
            }),
            _ => Err(Error::Other(
                "Recipient is not an internal shielded account".to_owned(),
            )),
        }
    }
    pub fn from_wallet_sapling_output(
        note_id: NoteId,
        output: &WalletSaplingOutput<AccountId>,
    ) -> Self {
        ReceivedNote {
            note_id,
            txid: *note_id.txid(),
            _output_index: output.index() as u32,
            account_id: *output.account_id(),
            _note: Note::Sapling(output.note().clone()),
            nf: output.nf().map(|nf| Nullifier::Sapling(*nf)),
            _is_change: output.is_change(),
            _memo: Memo::Empty,
            _commitment_tree_position: Some(output.note_commitment_tree_position()),
            _recipient_key_scope: output.recipient_key_scope(),
        }
    }
    #[cfg(feature = "orchard")]
    pub fn from_wallet_orchard_output(
        note_id: NoteId,
        output: &WalletOrchardOutput<AccountId>,
    ) -> Self {
        ReceivedNote {
            note_id,
            txid: *note_id.txid(),
            _output_index: output.index() as u32,
            account_id: *output.account_id(),
            _note: Note::Orchard(*output.note()),
            nf: output.nf().map(|nf| Nullifier::Orchard(*nf)),
            _is_change: output.is_change(),
            _memo: Memo::Empty,
            _commitment_tree_position: Some(output.note_commitment_tree_position()),
            _recipient_key_scope: output.recipient_key_scope(),
        }
    }
}

impl ReceivedNoteTable {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn get_sapling_nullifiers(
        &self,
    ) -> impl Iterator<Item = (AccountId, TxId, sapling::Nullifier)> + '_ {
        self.0.iter().filter_map(|entry| {
            if let Some(Nullifier::Sapling(nf)) = entry.nullifier() {
                Some((entry.account_id(), entry.txid(), *nf))
            } else {
                None
            }
        })
    }
    #[cfg(feature = "orchard")]
    pub fn get_orchard_nullifiers(
        &self,
    ) -> impl Iterator<Item = (AccountId, TxId, orchard::note::Nullifier)> + '_ {
        self.0.iter().filter_map(|entry| {
            if let Some(Nullifier::Orchard(nf)) = entry.nullifier() {
                Some((entry.account_id(), entry.txid(), *nf))
            } else {
                None
            }
        })
    }

    pub fn insert_received_note(&mut self, note: ReceivedNote) {
        self.0.push(note);
    }
}
