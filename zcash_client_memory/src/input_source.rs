use std::num::NonZeroU32;

#[cfg(feature = "transparent-inputs")]
use zcash_client_backend::data_api::WalletUtxo;
use zcash_client_backend::{
    data_api::{
        AccountMeta, InputSource, NoteFilter, PoolMeta, ReceivedNotes, TargetValue, WalletRead,
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::NoteId,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    ShieldedProtocol::{self, Sapling},
    consensus::{self, BranchId},
    value::Zatoshis,
};

#[cfg(feature = "orchard")]
use zcash_protocol::ShieldedProtocol::Orchard;

#[cfg(feature = "transparent-inputs")]
use {
    ::transparent::{address::TransparentAddress, bundle::OutPoint},
    zcash_client_backend::data_api::TransactionStatus,
    zcash_protocol::consensus::BlockHeight,
};

use crate::{AccountId, MemoryWalletDb, error::Error, to_spendable_notes};

impl<P: consensus::Parameters> InputSource for MemoryWalletDb<P> {
    type Error = crate::error::Error;
    type AccountId = AccountId;
    type NoteRef = NoteId;

    fn get_spendable_note(
        &self,
        txid: &zcash_primitives::transaction::TxId,
        protocol: zcash_protocol::ShieldedProtocol,
        index: u32,
        target_height: TargetHeight,
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
            if self.note_is_spent(note, target_height)? {
                None
            } else {
                let tx = self.tx_table.get_transaction(&note.txid);
                Some(zcash_client_backend::wallet::ReceivedNote::from_parts(
                    note.note_id,
                    *txid,
                    index.try_into().unwrap(), // this overflow can never happen or else the chain is broken
                    note.note.clone(),
                    note.recipient_key_scope
                        .ok_or(Error::Missing("recipient key scope".into()))?,
                    note.commitment_tree_position
                        .ok_or(Error::Missing("commitment tree position".into()))?,
                    tx.and_then(|tx| tx.mined_height()),
                    // Find the maximum height among transparent inputs to the transaction that
                    // produced this note.
                    tx.and_then(|tx| {
                        tx.raw()
                            .and_then(|raw| {
                                // The branch id here is irrelevant; it does not affect any APIs that we
                                // end up using here.
                                Transaction::read(raw, BranchId::Sapling).ok()
                            })
                            .and_then(|tx| {
                                tx.transparent_bundle()
                                    .iter()
                                    .flat_map(|b| b.vin.iter())
                                    .filter_map(|txin| {
                                        self.tx_table
                                            .get_transaction(txin.prevout().txid())
                                            .and_then(|input_tx| input_tx.mined_height())
                                    })
                                    .max()
                            })
                    }),
                ))
            }
        } else {
            None
        })
    }

    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: TargetValue,
        sources: &[zcash_protocol::ShieldedProtocol],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[Self::NoteRef],
    ) -> Result<zcash_client_backend::data_api::ReceivedNotes<Self::NoteRef>, Self::Error> {
        let sapling_eligible_notes = if sources.contains(&Sapling) {
            self.select_spendable_notes_from_pool(
                account,
                target_value,
                &Sapling,
                target_height,
                confirmations_policy,
                exclude,
            )?
        } else {
            Vec::new()
        };

        #[cfg(feature = "orchard")]
        let orchard_eligible_notes = if sources.contains(&Orchard) {
            self.select_spendable_notes_from_pool(
                account,
                target_value,
                &Orchard,
                target_height,
                confirmations_policy,
                exclude,
            )?
        } else {
            Vec::new()
        };

        to_spendable_notes(
            &sapling_eligible_notes,
            #[cfg(feature = "orchard")]
            &orchard_eligible_notes,
        )
    }

    fn select_unspent_notes(
        &self,
        _account: Self::AccountId,
        _sources: &[ShieldedProtocol],
        _target_height: TargetHeight,
        _exclude: &[Self::NoteRef],
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        unimplemented!()
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_spendable_transparent_outputs(
        &self,
        address: &TransparentAddress,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Vec<WalletUtxo>, Self::Error> {
        let txos = self
            .transparent_received_outputs
            .iter()
            .filter(|(_, txo)| txo.address == *address)
            .map(|(outpoint, txo)| (outpoint, txo, self.tx_table.get(&txo.transaction_id)))
            .filter(|(outpoint, _, _)| {
                self.utxo_is_spendable(outpoint, target_height, confirmations_policy)
                    .unwrap_or(false)
            })
            .filter_map(|(outpoint, txo, tx)| {
                txo.to_wallet_transparent_output(outpoint, tx.and_then(|tx| tx.mined_height()))
                    .map(|out| {
                        WalletUtxo::new(
                            out,
                            // FIXME: this needs to be updated to identify the transparent key
                            // scope for derived addresses in the wallet.
                            None,
                        )
                    })
            })
            .collect();
        Ok(txos)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_unspent_transparent_output(
        &self,
        outpoint: &OutPoint,
        _target_height: TargetHeight,
    ) -> Result<Option<WalletUtxo>, Self::Error> {
        // FIXME: make use of `target_height` to check spendability.
        Ok(self
            .transparent_received_outputs
            .get(outpoint)
            .map(|txo| (txo, self.tx_table.get(&txo.transaction_id)))
            .and_then(|(txo, tx)| {
                txo.to_wallet_transparent_output(outpoint, tx.and_then(|tx| tx.mined_height()))
                    .map(|out| {
                        WalletUtxo::new(
                            out,
                            // FIXME: this needs to be updated to identify the transparent key
                            // scope for derived addresses in the wallet.
                            None,
                        )
                    })
            }))
    }

    fn get_account_metadata(
        &self,
        account_id: Self::AccountId,
        selector: &NoteFilter,
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<AccountMeta, Self::Error> {
        let confirmations_policy = ConfirmationsPolicy::new_symmetrical(
            NonZeroU32::MIN,
            #[cfg(feature = "transparent-inputs")]
            true,
        );

        let sapling_pool_meta = self.spendable_notes_meta(
            ShieldedProtocol::Sapling,
            account_id,
            selector,
            target_height,
            confirmations_policy,
            exclude,
        )?;

        #[cfg(feature = "orchard")]
        let orchard_pool_meta = self.spendable_notes_meta(
            ShieldedProtocol::Orchard,
            account_id,
            selector,
            target_height,
            confirmations_policy,
            exclude,
        )?;
        #[cfg(not(feature = "orchard"))]
        let orchard_pool_meta = None;

        Ok(AccountMeta::new(sapling_pool_meta, orchard_pool_meta))
    }
}

impl<P: consensus::Parameters> MemoryWalletDb<P> {
    // Select the spendable notes to cover the given target value considering only a single pool
    // Returns the notes sorted oldest to newest
    fn select_spendable_notes_from_pool(
        &self,
        account: AccountId,
        target_value: TargetValue,
        pool: &zcash_protocol::ShieldedProtocol,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[NoteId],
    ) -> Result<Vec<&crate::ReceivedNote>, Error> {
        let birthday_height = match self.get_wallet_birthday()? {
            Some(birthday) => birthday,
            None => {
                // the wallet birthday can only be unknown if there are no accounts in the wallet; in
                // such a case, the wallet has no notes to spend.
                return Ok(Vec::new());
            }
        };
        // First grab all eligible (unspent, spendable, fully scanned) notes into a vec.
        let mut eligible_notes = self
            .received_notes
            .iter()
            .filter(|note| note.account_id == account)
            .filter(|note| note.note.protocol() == *pool)
            .filter(|note| {
                self.note_is_spendable(
                    note,
                    birthday_height,
                    target_height,
                    confirmations_policy,
                    exclude,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        // sort by oldest first (use location in commitment tree since this gives a total order)
        eligible_notes.sort_by(|a, b| a.commitment_tree_position.cmp(&b.commitment_tree_position));

        // now take notes until we have enough to cover the target value
        let mut value_acc = Zatoshis::ZERO;
        let selection: Vec<_> = eligible_notes
            .into_iter()
            .take_while(|note| {
                let take = match target_value {
                    TargetValue::AtLeast(target) => value_acc <= target,
                    TargetValue::AllFunds(_) => unimplemented!(),
                };
                value_acc = (value_acc + note.note.value()).expect("value overflow");
                take
            })
            .collect();

        Ok(selection)
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn utxo_is_spendable(
        &self,
        outpoint: &OutPoint,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<bool, Error> {
        let confirmed_height =
            BlockHeight::from(target_height) - u32::from(confirmations_policy.trusted());
        let utxo = self
            .transparent_received_outputs
            .get(outpoint)
            .ok_or(Error::NoteNotFound)?;
        if let Some(tx) = self.tx_table.get(&utxo.transaction_id) {
            Ok(
                tx.is_mined_or_unexpired_at(confirmed_height) // tx that created it is mined
                && !self.utxo_is_spent(outpoint, target_height)?, // not spent
            )
        } else {
            Ok(false)
        }
    }

    #[cfg(feature = "transparent-inputs")]
    fn utxo_is_spent(
        &self,
        outpoint: &OutPoint,
        target_height: TargetHeight,
    ) -> Result<bool, Error> {
        let spend = self.transparent_received_output_spends.get(outpoint);

        let spent = match spend {
            Some(txid) => {
                let spending_tx = self
                    .tx_table
                    .get(txid)
                    .ok_or(Error::TransactionNotFound(*txid))?;
                match spending_tx.status() {
                    TransactionStatus::Mined(_height) => true,
                    TransactionStatus::TxidNotRecognized => unreachable!(),
                    TransactionStatus::NotInMainChain => {
                        // transaction either never expires, or expires in the future.
                        spending_tx
                            .expiry_height()
                            .iter()
                            .all(|h| *h >= BlockHeight::from(target_height))
                    }
                }
            }
            None => false,
        };
        Ok(spent)
    }

    fn spendable_notes_meta(
        &self,
        protocol: ShieldedProtocol,
        account: AccountId,
        filter: &NoteFilter,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[NoteId],
    ) -> Result<Option<PoolMeta>, Error> {
        let birthday_height = match self.get_wallet_birthday()? {
            Some(birthday) => birthday,
            None => {
                return Ok(None);
            }
        };
        let (count, total) = self
            .received_notes
            .iter()
            .filter(|note| note.account_id == account)
            .filter(|note| note.note.protocol() == protocol)
            .filter(|note| {
                self.note_is_spendable(
                    note,
                    birthday_height,
                    target_height,
                    confirmations_policy,
                    exclude,
                )
                .expect("note account & transaction are known to the wallet")
            })
            .filter(|note| {
                self.matches_note_filter(note, filter)
                    .unwrap()
                    .is_some_and(|b| b)
            })
            .fold((0, Zatoshis::ZERO), |(count, total), note| {
                (count + 1, (total + note.note.value()).unwrap())
            });

        Ok(Some(PoolMeta::new(count, total)))
    }

    #[allow(clippy::only_used_in_recursion)]
    fn matches_note_filter(
        &self,
        note: &crate::ReceivedNote,
        filter: &NoteFilter,
    ) -> Result<Option<bool>, Error> {
        match filter {
            NoteFilter::ExceedsMinValue(min_value) => Ok(Some(note.note.value() > *min_value)),
            NoteFilter::ExceedsPriorSendPercentile(_n) => todo!(),
            NoteFilter::ExceedsBalancePercentage(_p) => todo!(),
            // evaluate both conditions.
            // If one cannot be evaluated (e.g. it returns None) it is ignored
            NoteFilter::Combine(a, b) => {
                let matches_a = self.matches_note_filter(note, a)?.unwrap_or(true);
                let matches_b = self.matches_note_filter(note, b)?.unwrap_or(true);
                Ok(Some(matches_a && matches_b))
            }
            // Evaluate the first condition and return the result.
            // If the first condition cannot be evaluated then use the fallback instead
            NoteFilter::Attempt {
                condition,
                fallback,
            } => {
                if let Some(b) = self.matches_note_filter(note, condition)? {
                    Ok(Some(b))
                } else {
                    self.matches_note_filter(note, fallback)
                }
            }
        }
    }
}
