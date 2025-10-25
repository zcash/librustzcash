use incrementalmerkletree::Position;

use std::collections::BTreeSet;
use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};
use zip32::Scope;

use zcash_primitives::transaction::TxId;
use zcash_protocol::{PoolType, ShieldedProtocol::Sapling, memo::Memo};

use zcash_client_backend::{
    data_api::{ReceivedNotes, SentTransactionOutput},
    wallet::{Note, NoteId, Recipient, WalletSaplingOutput},
};

use crate::AccountId;

#[cfg(feature = "orchard")]
use {
    zcash_client_backend::wallet::WalletOrchardOutput, zcash_protocol::ShieldedProtocol::Orchard,
};

use crate::{Nullifier, error::Error};

/// Keeps track of notes that are spent in which transaction
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReceievedNoteSpends(pub(crate) BTreeMap<NoteId, TxId>);

impl ReceievedNoteSpends {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
    pub fn insert_spend(&mut self, note_id: NoteId, txid: TxId) -> Option<TxId> {
        self.0.insert(note_id, txid)
    }
    pub fn get(&self, note_id: &NoteId) -> Option<&TxId> {
        self.0.get(note_id)
    }
}

impl Deref for ReceievedNoteSpends {
    type Target = BTreeMap<NoteId, TxId>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A note that has been received by the wallet
/// TODO: Instead of Vec, perhaps we should identify by some unique ID
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReceivedNoteTable(pub(crate) Vec<ReceivedNote>);

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReceivedNote {
    // Uniquely identifies this note
    pub(crate) note_id: NoteId,
    pub(crate) txid: TxId,
    // output_index: sapling, action_index: orchard
    pub(crate) output_index: u32,
    pub(crate) account_id: AccountId,
    //sapling: (diversifier, value, rcm) orchard: (diversifier, value, rho, rseed)
    pub(crate) note: Note,
    pub(crate) nf: Option<Nullifier>,
    pub(crate) is_change: bool,
    pub(crate) memo: Memo,
    pub(crate) commitment_tree_position: Option<Position>,
    pub(crate) recipient_key_scope: Option<Scope>,
}
impl ReceivedNote {
    pub fn pool(&self) -> PoolType {
        match self.note {
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
                note,
                ..
            } => match note.as_ref() {
                Note::Sapling(note) => Ok(ReceivedNote {
                    note_id: NoteId::new(txid, Sapling, output.output_index() as u16),
                    txid,
                    output_index: output.output_index() as u32,
                    account_id: *receiving_account,
                    note: Note::Sapling(note.clone()),
                    nf: None,
                    is_change: true,
                    memo: output
                        .memo()
                        .map(Memo::try_from)
                        .transpose()?
                        .expect("expected a memo for a non-transparent output"),
                    commitment_tree_position: None,
                    recipient_key_scope: Some(Scope::Internal),
                }),
                #[cfg(feature = "orchard")]
                Note::Orchard(note) => Ok(ReceivedNote {
                    note_id: NoteId::new(txid, Orchard, output.output_index() as u16),
                    txid,
                    output_index: output.output_index() as u32,
                    account_id: *receiving_account,
                    note: Note::Orchard(*note),
                    nf: None,
                    is_change: true,
                    memo: output
                        .memo()
                        .map(Memo::try_from)
                        .transpose()?
                        .expect("expected a memo for a non-transparent output"),
                    commitment_tree_position: None,
                    recipient_key_scope: Some(Scope::Internal),
                }),
            },
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
            output_index: output.index() as u32,
            account_id: *output.account_id(),
            note: Note::Sapling(output.note().clone()),
            nf: output.nf().map(|nf| Nullifier::Sapling(*nf)),
            is_change: output.is_change(),
            memo: Memo::Empty,
            commitment_tree_position: Some(output.note_commitment_tree_position()),
            recipient_key_scope: output.recipient_key_scope(),
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
            output_index: output.index() as u32,
            account_id: *output.account_id(),
            note: Note::Orchard(*output.note()),
            nf: output.nf().map(|nf| Nullifier::Orchard(*nf)),
            is_change: output.is_change(),
            memo: Memo::Empty,
            commitment_tree_position: Some(output.note_commitment_tree_position()),
            recipient_key_scope: output.recipient_key_scope(),
        }
    }
}

impl From<ReceivedNote>
    for zcash_client_backend::wallet::ReceivedNote<NoteId, zcash_client_backend::wallet::Note>
{
    fn from(value: ReceivedNote) -> Self {
        zcash_client_backend::wallet::ReceivedNote::from_parts(
            value.note_id,
            value.txid,
            value.output_index.try_into().unwrap(),
            value.note,
            value.recipient_key_scope.unwrap(),
            value.commitment_tree_position.unwrap(),
            None,
            None,
        )
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
        // ensure note_id is unique.
        // follow upsert rules to update the note if it already exists
        let is_absent = self
            .0
            .iter_mut()
            .find(|n| n.note_id == note.note_id)
            .map(|n| {
                n.nf = note.nf.or(n.nf);
                n.is_change = note.is_change || n.is_change;
                n.commitment_tree_position =
                    note.commitment_tree_position.or(n.commitment_tree_position);
            })
            .is_none();

        if is_absent {
            self.0.push(note);
        }
    }

    #[cfg(feature = "orchard")]
    pub fn detect_orchard_spending_accounts<'a>(
        &self,
        nfs: impl Iterator<Item = &'a orchard::note::Nullifier>,
    ) -> Result<BTreeSet<AccountId>, Error> {
        let mut acc = BTreeSet::new();
        let nfs = nfs.collect::<Vec<_>>();
        for (nf, id) in self.0.iter().filter_map(|n| match (n.nf, n.account_id) {
            (Some(Nullifier::Orchard(nf)), account_id) => Some((nf, account_id)),
            _ => None,
        }) {
            if nfs.contains(&&nf) {
                acc.insert(id);
            }
        }
        Ok(acc)
    }

    pub fn detect_sapling_spending_accounts<'a>(
        &self,
        nfs: impl Iterator<Item = &'a sapling::Nullifier>,
    ) -> Result<BTreeSet<AccountId>, Error> {
        let mut acc = BTreeSet::new();
        let nfs = nfs.collect::<Vec<_>>();
        for (nf, id) in self.0.iter().filter_map(|n| match (n.nf, n.account_id) {
            (Some(Nullifier::Sapling(nf)), account_id) => Some((nf, account_id)),
            _ => None,
        }) {
            if nfs.contains(&&nf) {
                acc.insert(id);
            }
        }
        Ok(acc)
    }
}

// We deref to slice so that we can reuse the slice impls
impl Deref for ReceivedNoteTable {
    type Target = [ReceivedNote];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}
impl DerefMut for ReceivedNoteTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}

pub(crate) fn to_spendable_notes(
    sapling_received_notes: &[&ReceivedNote],
    #[cfg(feature = "orchard")] orchard_received_notes: &[&ReceivedNote],
) -> Result<ReceivedNotes<NoteId>, Error> {
    let sapling = sapling_received_notes
        .iter()
        .map(|note| {
            #[allow(irrefutable_let_patterns)]
            if let Note::Sapling(inner) = &note.note {
                Ok(zcash_client_backend::wallet::ReceivedNote::from_parts(
                    note.note_id,
                    note.txid(),
                    note.output_index.try_into().unwrap(), // this overflow can never happen or else the chain is broken
                    inner.clone(),
                    note.recipient_key_scope
                        .ok_or(Error::Missing("recipient key scope".into()))?,
                    note.commitment_tree_position
                        .ok_or(Error::Missing("commitment tree position".into()))?,
                    None,
                    None,
                ))
            } else {
                Err(Error::Other("Note is not a sapling note".to_owned()))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    #[cfg(feature = "orchard")]
    let orchard = orchard_received_notes
        .iter()
        .map(|note| {
            if let Note::Orchard(inner) = &note.note {
                Ok(zcash_client_backend::wallet::ReceivedNote::from_parts(
                    note.note_id,
                    note.txid(),
                    note.output_index.try_into().unwrap(), // this overflow can never happen or else the chain is broken
                    *inner,
                    note.recipient_key_scope
                        .ok_or(Error::Missing("recipient key scope".into()))?,
                    note.commitment_tree_position
                        .ok_or(Error::Missing("commitment tree position".into()))?,
                    None,
                    None,
                ))
            } else {
                Err(Error::Other("Note is not an orchard note".to_owned()))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ReceivedNotes::new(
        sapling,
        #[cfg(feature = "orchard")]
        orchard,
    ))
}

mod serialization {
    use super::*;
    use crate::{proto::memwallet as proto, read_optional};

    impl From<ReceivedNote> for proto::ReceivedNote {
        fn from(value: ReceivedNote) -> Self {
            Self {
                note_id: Some(value.note_id.into()),
                tx_id: Some(value.txid.into()),
                output_index: value.output_index,
                account_id: *value.account_id,
                note: Some(value.note.into()),
                nullifier: value.nf.map(|nf| nf.into()),
                is_change: value.is_change,
                memo: value.memo.encode().as_array().to_vec(),
                commitment_tree_position: value.commitment_tree_position.map(|pos| pos.into()),
                recipient_key_scope: match value.recipient_key_scope {
                    Some(Scope::Internal) => Some(proto::Scope::Internal as i32),
                    Some(Scope::External) => Some(proto::Scope::External as i32),
                    None => None,
                },
            }
        }
    }

    impl TryFrom<proto::ReceivedNote> for ReceivedNote {
        type Error = Error;

        fn try_from(value: proto::ReceivedNote) -> Result<ReceivedNote, Error> {
            Ok(Self {
                note_id: read_optional!(value, note_id)?.try_into()?,
                txid: read_optional!(value, tx_id)?.try_into()?,
                output_index: value.output_index,
                account_id: value.account_id.into(),
                note: read_optional!(value, note)?.into(),
                nf: value.nullifier.map(|nf| nf.try_into()).transpose()?,
                is_change: value.is_change,
                memo: Memo::from_bytes(&value.memo)?,
                commitment_tree_position: value.commitment_tree_position.map(|pos| pos.into()),
                recipient_key_scope: match value.recipient_key_scope {
                    Some(0) => Some(Scope::Internal),
                    Some(1) => Some(Scope::External),
                    _ => None,
                },
            })
        }
    }
}
