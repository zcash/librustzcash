use zcash_client_backend::data_api::InputSource;
use zcash_protocol::consensus;

use crate::{AccountId, MemoryWalletDb, NoteId};

impl<P: consensus::Parameters> InputSource for MemoryWalletDb<P> {
    type Error = crate::error::Error;
    type AccountId = AccountId;
    type NoteRef = NoteId;

    fn get_spendable_note(
        &self,
        _txid: &zcash_primitives::transaction::TxId,
        _protocol: zcash_protocol::ShieldedProtocol,
        _index: u32,
    ) -> Result<
        Option<
            zcash_client_backend::wallet::ReceivedNote<
                Self::NoteRef,
                zcash_client_backend::wallet::Note,
            >,
        >,
        Self::Error,
    > {
        todo!()
    }

    fn select_spendable_notes(
        &self,
        _account: Self::AccountId,
        _target_value: zcash_protocol::value::Zatoshis,
        _sources: &[zcash_protocol::ShieldedProtocol],
        _anchor_height: zcash_protocol::consensus::BlockHeight,
        _exclude: &[Self::NoteRef],
    ) -> Result<zcash_client_backend::data_api::SpendableNotes<Self::NoteRef>, Self::Error> {
        todo!()
    }
}
