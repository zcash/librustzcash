use zcash_client_backend::data_api::{InputSource, SpendableNotes, WalletRead};
use zcash_protocol::{consensus, value::Zatoshis};

use crate::{error::Error, to_spendable_notes, AccountId, MemoryWalletDb, NoteId};

impl<P: consensus::Parameters> InputSource for MemoryWalletDb<P> {
    type Error = crate::error::Error;
    type AccountId = AccountId;
    type NoteRef = NoteId;

    /// Find the note with the given index (output index for Sapling, action index for Orchard)
    /// that belongs to the given transaction
    fn get_spendable_note(
        &self,
        txid: &zcash_primitives::transaction::TxId,
        protocol: zcash_protocol::ShieldedProtocol,
        index: u32,
    ) -> Result<
        Option<
            zcash_client_backend::wallet::ReceivedNote<
                Self::NoteRef,
                zcash_client_backend::wallet::Note,
            >,
        >,
        Self::Error,
    > {
        let note = self.received_notes.iter().find(|rn| {
            &rn.txid == txid && rn.note.protocol() == protocol && rn.output_index == index
        });

        Ok(if let Some(note) = note {
            if self.note_is_spent(note, 0)? {
                None
            } else {
                Some(zcash_client_backend::wallet::ReceivedNote::from_parts(
                    note.note_id,
                    *txid,
                    index.try_into().unwrap(), // this overflow can never happen or else the chain is broken
                    note.note.clone(),
                    note.recipient_key_scope
                        .ok_or(Error::Missing("recipient key scope".into()))?,
                    note.commitment_tree_position
                        .ok_or(Error::Missing("commitment tree position".into()))?,
                ))
            }
        } else {
            None
        })
    }
    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: zcash_protocol::value::Zatoshis,
        sources: &[zcash_protocol::ShieldedProtocol],
        anchor_height: zcash_protocol::consensus::BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<zcash_client_backend::data_api::SpendableNotes<Self::NoteRef>, Self::Error> {
        let birthday_height = match self.get_wallet_birthday()? {
            Some(birthday) => birthday,
            None => {
                // the wallet birthday can only be unknown if there are no accounts in the wallet; in
                // such a case, the wallet has no notes to spend.
                return Ok(SpendableNotes::empty());
            }
        };

        // This uses the greedy approach to building a transaction that spends oldest notes first
        //
        // First grab all eligible (unspent, spendable) notes into a vec.
        // Sort them oldest to newest
        // Take from this vec until the first note is taken that meets or exceeds the target value
        let mut eligible_notes = self
            .received_notes
            .iter()
            .filter(|note| note.account_id == account)
            .filter(|note| sources.contains(&note.note.protocol()))
            .filter(|note| {
                self.note_is_spendable(note, anchor_height, exclude)
                    .unwrap()
            })
            .collect::<Vec<_>>();

        // sort by oldest first (block height then index)
        eligible_notes.sort_by(|a, b| a.txid.cmp(&b.txid));

        let mut value_acc = Zatoshis::ZERO;
        let selection: Vec<_> = eligible_notes
            .into_iter()
            .take_while(|note| {
                let take = value_acc <= target_value;
                value_acc = (value_acc + note.note.value()).expect("value overflow");
                take
            })
            .collect();

        Ok(to_spendable_notes(&selection)?)
    }
}
