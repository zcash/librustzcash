use zcash_client_backend::data_api::InputSource;

use crate::mem_wallet::{AccountId, MemoryWalletDb};

impl InputSource for MemoryWalletDb {
    type Error = crate::error::Error;
    type AccountId = crate::mem_wallet::AccountId;
    type NoteRef = crate::mem_wallet::NoteId;

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
        todo!()
    }

    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: zcash_protocol::value::Zatoshis,
        sources: &[zcash_protocol::ShieldedProtocol],
        anchor_height: zcash_protocol::consensus::BlockHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<zcash_client_backend::data_api::SpendableNotes<Self::NoteRef>, Self::Error> {
        todo!()
    }
}
