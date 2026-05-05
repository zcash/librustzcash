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
    DecryptedOutput,
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

/// A note that has been received by the wallet, with O(1) lookup indexes.
#[derive(Debug, Clone)]
pub struct ReceivedNoteTable {
    pub(crate) notes: Vec<ReceivedNote>,
    /// Maps nullifier to index in `notes` for O(1) nullifier lookups
    nullifier_index: BTreeMap<Nullifier, usize>,
    /// Maps note_id to index in `notes` for O(1) note_id lookups (upsert)
    note_id_index: BTreeMap<NoteId, usize>,
}

impl PartialEq for ReceivedNoteTable {
    fn eq(&self, other: &Self) -> bool {
        // Indexes are derived state; only compare the notes themselves
        self.notes == other.notes
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReceivedNote {
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
    pub(crate) fn nullifier(&self) -> Option<&Nullifier> {
        self.nf.as_ref()
    }
    pub fn txid(&self) -> TxId {
        self.txid
    }
    pub fn note_id(&self) -> NoteId {
        self.note_id
    }
    /// Returns a reference to the note value
    pub fn note(&self) -> &Note {
        &self.note
    }
    /// Returns a reference to the memo
    pub fn memo(&self) -> &Memo {
        &self.memo
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

    /// Creates a ReceivedNote from a decrypted Sapling output (for incoming transactions).
    ///
    /// This is used when syncing discovers a new incoming Sapling note that was
    /// received to one of the wallet's external addresses.
    pub fn from_decrypted_sapling_output(
        txid: TxId,
        output: &DecryptedOutput<sapling::Note, AccountId>,
    ) -> Result<Self, Error> {
        let note_id = NoteId::new(txid, Sapling, output.index() as u16);
        let memo = Memo::try_from(output.memo().clone())?;

        Ok(ReceivedNote {
            note_id,
            txid,
            output_index: output.index() as u32,
            account_id: *output.account(),
            note: Note::Sapling(output.note().clone()),
            nf: None,         // Nullifier not yet known for incoming unspent notes
            is_change: false, // Incoming notes are not change
            memo,
            commitment_tree_position: None, // Position not yet known
            recipient_key_scope: Some(Scope::External), // Incoming uses external scope
        })
    }

    /// Creates a ReceivedNote from a decrypted Orchard output (for incoming transactions).
    ///
    /// This is used when syncing discovers a new incoming Orchard note that was
    /// received to one of the wallet's external addresses.
    #[cfg(feature = "orchard")]
    pub fn from_decrypted_orchard_output(
        txid: TxId,
        output: &DecryptedOutput<orchard::note::Note, AccountId>,
    ) -> Result<Self, Error> {
        let note_id = NoteId::new(txid, Orchard, output.index() as u16);
        let memo = Memo::try_from(output.memo().clone())?;

        Ok(ReceivedNote {
            note_id,
            txid,
            output_index: output.index() as u32,
            account_id: *output.account(),
            note: Note::Orchard(*output.note()),
            nf: None,         // Nullifier not yet known for incoming unspent notes
            is_change: false, // Incoming notes are not change
            memo,
            commitment_tree_position: None, // Position not yet known
            recipient_key_scope: Some(Scope::External), // Incoming uses external scope
        })
    }
}

impl TryFrom<ReceivedNote>
    for zcash_client_backend::wallet::ReceivedNote<NoteId, zcash_client_backend::wallet::Note>
{
    type Error = Error;
    fn try_from(value: ReceivedNote) -> Result<Self, Error> {
        Ok(zcash_client_backend::wallet::ReceivedNote::from_parts(
            value.note_id,
            value.txid,
            value.output_index.try_into()?,
            value.note,
            value.recipient_key_scope
                .ok_or(Error::Missing("recipient key scope".into()))?,
            value.commitment_tree_position
                .ok_or(Error::Missing("commitment tree position".into()))?,
            None,
            None,
        ))
    }
}

impl Default for ReceivedNoteTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceivedNoteTable {
    pub fn new() -> Self {
        Self {
            notes: Vec::new(),
            nullifier_index: BTreeMap::new(),
            note_id_index: BTreeMap::new(),
        }
    }

    /// Construct from a Vec of notes, rebuilding all indexes.
    pub(crate) fn from_notes(notes: Vec<ReceivedNote>) -> Self {
        let mut nullifier_index = BTreeMap::new();
        let mut note_id_index = BTreeMap::new();
        for (i, note) in notes.iter().enumerate() {
            note_id_index.insert(note.note_id, i);
            if let Some(nf) = note.nf {
                nullifier_index.insert(nf, i);
            }
        }
        Self {
            notes,
            nullifier_index,
            note_id_index,
        }
    }

    pub fn get_sapling_nullifiers(
        &self,
    ) -> impl Iterator<Item = (AccountId, TxId, sapling::Nullifier)> + '_ {
        self.notes.iter().filter_map(|entry| {
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
        self.notes.iter().filter_map(|entry| {
            if let Some(Nullifier::Orchard(nf)) = entry.nullifier() {
                Some((entry.account_id(), entry.txid(), *nf))
            } else {
                None
            }
        })
    }

    pub fn insert_received_note(&mut self, note: ReceivedNote) {
        // Check if note_id already exists via the index (O(1) lookup)
        if let Some(&idx) = self.note_id_index.get(&note.note_id) {
            // Upsert: update existing note
            let existing = &mut self.notes[idx];
            // If nullifier changed, update the nullifier index
            let old_nf = existing.nf;
            existing.nf = note.nf.or(existing.nf);
            existing.is_change = note.is_change || existing.is_change;
            existing.commitment_tree_position = note
                .commitment_tree_position
                .or(existing.commitment_tree_position);
            // Update nullifier index if it changed
            if existing.nf != old_nf {
                if let Some(old) = old_nf {
                    self.nullifier_index.remove(&old);
                }
                if let Some(new) = existing.nf {
                    self.nullifier_index.insert(new, idx);
                }
            }
        } else {
            // Insert new note
            let idx = self.notes.len();
            self.note_id_index.insert(note.note_id, idx);
            if let Some(nf) = note.nf {
                self.nullifier_index.insert(nf, idx);
            }
            self.notes.push(note);
        }
    }

    /// O(1) lookup of a note by its nullifier
    pub(crate) fn find_by_nullifier(&self, nf: &Nullifier) -> Option<&ReceivedNote> {
        self.nullifier_index.get(nf).map(|&idx| &self.notes[idx])
    }

    /// O(1) lookup of a note by its NoteId
    pub(crate) fn find_by_note_id(&self, note_id: &NoteId) -> Option<&ReceivedNote> {
        self.note_id_index.get(note_id).map(|&idx| &self.notes[idx])
    }

    #[cfg(feature = "orchard")]
    pub fn detect_orchard_spending_accounts<'a>(
        &self,
        nfs: impl Iterator<Item = &'a orchard::note::Nullifier>,
    ) -> Result<BTreeSet<AccountId>, Error> {
        let mut acc = BTreeSet::new();
        for nf in nfs {
            let key = Nullifier::Orchard(*nf);
            if let Some(note) = self.find_by_nullifier(&key) {
                acc.insert(note.account_id());
            }
        }
        Ok(acc)
    }

    pub fn detect_sapling_spending_accounts<'a>(
        &self,
        nfs: impl Iterator<Item = &'a sapling::Nullifier>,
    ) -> Result<BTreeSet<AccountId>, Error> {
        let mut acc = BTreeSet::new();
        for nf in nfs {
            let key = Nullifier::Sapling(*nf);
            if let Some(note) = self.find_by_nullifier(&key) {
                acc.insert(note.account_id());
            }
        }
        Ok(acc)
    }
}

// We deref to slice so that we can reuse the slice impls
impl Deref for ReceivedNoteTable {
    type Target = [ReceivedNote];

    fn deref(&self) -> &Self::Target {
        &self.notes[..]
    }
}
impl DerefMut for ReceivedNoteTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.notes[..]
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
                    note.output_index.try_into()?,
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
                    note.output_index.try_into()?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::Position;
    use zcash_client_backend::wallet::Note;
    use zcash_primitives::transaction::TxId;
    use zcash_protocol::ShieldedProtocol::Sapling;

    /// Known-valid sapling PaymentAddress bytes (from mod.rs serialization test).
    const VALID_PA_BYTES: [u8; 43] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x8e, 0x11, 0x9d,
        0x72, 0x99, 0x2b, 0x56, 0x0d, 0x26, 0x50, 0xff, 0xe0, 0xbe, 0x7f, 0x35, 0x42, 0xfd, 0x97,
        0x00, 0x3c, 0xb7, 0xcc, 0x3a, 0xbf, 0xf8, 0x1a, 0x7f, 0x90, 0x37, 0xf3, 0xea,
    ];

    fn make_test_note(
        txid_byte: u8,
        output_index: u16,
        account_id: u32,
        nullifier_bytes: Option<u8>,
    ) -> ReceivedNote {
        let txid = TxId::from_bytes([txid_byte; 32]);
        let note_id = NoteId::new(txid, Sapling, output_index);
        let pa = sapling::PaymentAddress::from_bytes(&VALID_PA_BYTES).unwrap();
        let sapling_note = sapling::Note::from_parts(
            pa,
            sapling::value::NoteValue::from_raw(1000),
            sapling::Rseed::AfterZip212([0; 32]),
        );
        let nf = nullifier_bytes
            .map(|b| Nullifier::Sapling(sapling::Nullifier::from_slice(&[b; 32]).unwrap()));

        ReceivedNote {
            note_id,
            txid,
            output_index: output_index as u32,
            account_id: AccountId::from(account_id),
            note: Note::Sapling(sapling_note),
            nf,
            is_change: false,
            memo: Memo::Empty,
            commitment_tree_position: Some(Position::from(0u64)),
            recipient_key_scope: Some(Scope::External),
        }
    }

    #[test]
    fn test_new_is_empty() {
        let table = ReceivedNoteTable::new();
        assert!(table.notes.is_empty());
        assert!(table.nullifier_index.is_empty());
        assert!(table.note_id_index.is_empty());
    }

    #[test]
    fn test_insert_and_find_by_note_id() {
        let mut table = ReceivedNoteTable::new();
        let note = make_test_note(0x01, 0, 1, Some(0xAA));
        let note_id = note.note_id;

        table.insert_received_note(note);

        let found = table.find_by_note_id(&note_id).unwrap();
        assert_eq!(found.note_id, note_id);
        assert_eq!(found.account_id, AccountId::from(1));
    }

    #[test]
    fn test_insert_and_find_by_nullifier() {
        let mut table = ReceivedNoteTable::new();
        let note = make_test_note(0x02, 0, 2, Some(0xBB));
        let nf = note.nf.unwrap();

        table.insert_received_note(note);

        let found = table.find_by_nullifier(&nf).unwrap();
        assert_eq!(found.account_id, AccountId::from(2));
    }

    #[test]
    fn test_find_missing_returns_none() {
        let table = ReceivedNoteTable::new();
        let missing_nf = Nullifier::Sapling(sapling::Nullifier::from_slice(&[0xFF; 32]).unwrap());
        assert!(table.find_by_nullifier(&missing_nf).is_none());
    }

    #[test]
    fn test_upsert_updates_existing() {
        let mut table = ReceivedNoteTable::new();
        let note1 = make_test_note(0x03, 0, 3, Some(0xCC));
        let note_id = note1.note_id;

        table.insert_received_note(note1);
        assert_eq!(table.notes.len(), 1);
        assert!(!table.find_by_note_id(&note_id).unwrap().is_change);

        // Upsert same note_id with is_change = true
        let mut note2 = make_test_note(0x03, 0, 3, Some(0xCC));
        note2.is_change = true;
        table.insert_received_note(note2);

        // Length unchanged, is_change merged via OR
        assert_eq!(table.notes.len(), 1);
        assert!(table.find_by_note_id(&note_id).unwrap().is_change);
    }

    #[test]
    fn test_upsert_adds_nullifier_to_index() {
        let mut table = ReceivedNoteTable::new();
        // Insert without nullifier
        let note1 = make_test_note(0x04, 0, 4, None);
        let note_id = note1.note_id;
        table.insert_received_note(note1);

        assert!(table.find_by_note_id(&note_id).unwrap().nf.is_none());
        assert!(table.nullifier_index.is_empty());

        // Upsert with nullifier
        let note2 = make_test_note(0x04, 0, 4, Some(0xDD));
        let nf = note2.nf.unwrap();
        table.insert_received_note(note2);

        // Nullifier index now populated
        assert_eq!(table.notes.len(), 1);
        assert!(table.find_by_nullifier(&nf).is_some());
        assert_eq!(table.find_by_note_id(&note_id).unwrap().nf, Some(nf));
    }

    #[test]
    fn test_from_notes_rebuilds_indexes() {
        let notes = vec![
            make_test_note(0x05, 0, 5, Some(0xEE)),
            make_test_note(0x06, 1, 6, None),
            make_test_note(0x07, 2, 7, Some(0xFF)),
        ];
        let nf0 = notes[0].nf.unwrap();
        let nf2 = notes[2].nf.unwrap();
        let id0 = notes[0].note_id;
        let id1 = notes[1].note_id;
        let id2 = notes[2].note_id;

        let table = ReceivedNoteTable::from_notes(notes);

        assert_eq!(table.notes.len(), 3);
        // note_id index works
        assert!(table.find_by_note_id(&id0).is_some());
        assert!(table.find_by_note_id(&id1).is_some());
        assert!(table.find_by_note_id(&id2).is_some());
        // nullifier index works (only 2 entries, middle note has no nf)
        assert_eq!(table.nullifier_index.len(), 2);
        assert!(table.find_by_nullifier(&nf0).is_some());
        assert!(table.find_by_nullifier(&nf2).is_some());
    }

    #[test]
    fn test_detect_sapling_spending_accounts() {
        let mut table = ReceivedNoteTable::new();
        table.insert_received_note(make_test_note(0x10, 0, 10, Some(0xA1)));
        table.insert_received_note(make_test_note(0x11, 1, 11, Some(0xA2)));
        table.insert_received_note(make_test_note(0x12, 2, 12, Some(0xA3)));

        let nf1 = sapling::Nullifier::from_slice(&[0xA1; 32]).unwrap();
        let nf3 = sapling::Nullifier::from_slice(&[0xA3; 32]).unwrap();

        let accounts = table
            .detect_sapling_spending_accounts([nf1, nf3].iter())
            .unwrap();

        assert_eq!(accounts.len(), 2);
        assert!(accounts.contains(&AccountId::from(10)));
        assert!(accounts.contains(&AccountId::from(12)));
    }

    #[test]
    fn test_detect_spending_accounts_unknown_nf() {
        let mut table = ReceivedNoteTable::new();
        table.insert_received_note(make_test_note(0x20, 0, 20, Some(0xB1)));

        let unknown = sapling::Nullifier::from_slice(&[0xFF; 32]).unwrap();
        let accounts = table
            .detect_sapling_spending_accounts([unknown].iter())
            .unwrap();

        assert!(accounts.is_empty());
    }
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
                note: read_optional!(value, note)?.try_into()?,
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
