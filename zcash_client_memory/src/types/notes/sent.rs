use std::{collections::BTreeMap, ops::Deref};

use ::transparent::bundle::OutPoint;
use zcash_client_backend::{
    data_api::{SentTransaction, SentTransactionOutput},
    wallet::{NoteId, Recipient},
};
use zcash_protocol::{PoolType, ShieldedProtocol::Sapling, TxId, memo::Memo, value::Zatoshis};

use crate::AccountId;

#[cfg(feature = "orchard")]
use zcash_protocol::ShieldedProtocol::Orchard;

#[derive(PartialEq, PartialOrd, Eq, Ord, Debug, Clone)]
pub enum SentNoteId {
    Shielded(NoteId),
    Transparent { txid: TxId, output_index: u32 },
}

impl From<NoteId> for SentNoteId {
    fn from(note_id: NoteId) -> Self {
        SentNoteId::Shielded(note_id)
    }
}

impl From<&NoteId> for SentNoteId {
    fn from(note_id: &NoteId) -> Self {
        SentNoteId::Shielded(*note_id)
    }
}

impl SentNoteId {
    pub fn txid(&self) -> &TxId {
        match self {
            SentNoteId::Shielded(note_id) => note_id.txid(),
            SentNoteId::Transparent { txid, .. } => txid,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SentNoteTable(pub(crate) BTreeMap<SentNoteId, SentNote>);

impl SentNoteTable {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert_sent_output(
        &mut self,
        tx: &SentTransaction<AccountId>,
        output: &SentTransactionOutput<AccountId>,
    ) {
        let pool_type = match output.recipient() {
            Recipient::External { output_pool, .. } => *output_pool,
            #[cfg(feature = "transparent-inputs")]
            Recipient::EphemeralTransparent { .. } => PoolType::Transparent,
            Recipient::InternalAccount { note, .. } => PoolType::Shielded(note.protocol()),
        };
        match pool_type {
            PoolType::Transparent => {
                // we kind of are in a tricky spot here since NoteId cannot represent a transparent note..
                // just make it a sapling one for now until we figure out a better way to represent this
                let note_id = SentNoteId::Transparent {
                    txid: tx.tx().txid(),
                    output_index: output.output_index().try_into().unwrap(),
                };
                self.0.insert(
                    note_id,
                    SentNote {
                        from_account_id: *tx.account_id(),
                        to: output.recipient().clone(),
                        value: output.value(),
                        memo: Memo::Empty, // transparent notes don't have memos
                    },
                );
            }
            PoolType::Shielded(protocol) => {
                let note_id = NoteId::new(
                    tx.tx().txid(),
                    protocol,
                    output.output_index().try_into().unwrap(),
                );
                self.0.insert(
                    note_id.into(),
                    SentNote {
                        from_account_id: *tx.account_id(),
                        to: output.recipient().clone(),
                        value: output.value(),
                        memo: output.memo().map(|m| Memo::try_from(m).unwrap()).unwrap(),
                    },
                );
            }
        }
    }

    pub fn put_sent_output(
        &mut self,
        txid: TxId,
        from_account_id: AccountId,
        output: &SentTransactionOutput<AccountId>,
    ) {
        let pool_type = match output.recipient() {
            Recipient::External { output_pool, .. } => *output_pool,
            #[cfg(feature = "transparent-inputs")]
            Recipient::EphemeralTransparent { .. } => PoolType::Transparent,
            Recipient::InternalAccount { note, .. } => PoolType::Shielded(note.protocol()),
        };
        match pool_type {
            PoolType::Transparent => {
                // we kind of are in a tricky spot here since NoteId cannot represent a transparent note..
                // just make it a sapling one for now until we figure out a better way to represent this
                let note_id = SentNoteId::Transparent {
                    txid,
                    output_index: output.output_index().try_into().unwrap(),
                };
                self.0.insert(
                    note_id,
                    SentNote {
                        from_account_id,
                        to: output.recipient().clone(),
                        value: output.value(),
                        memo: Memo::Empty, // transparent notes don't have memos
                    },
                );
            }
            PoolType::Shielded(protocol) => {
                let note_id =
                    NoteId::new(txid, protocol, output.output_index().try_into().unwrap());
                self.0.insert(
                    note_id.into(),
                    SentNote {
                        from_account_id,
                        to: output.recipient().clone(),
                        value: output.value(),
                        memo: output.memo().map(|m| Memo::try_from(m).unwrap()).unwrap(),
                    },
                );
            }
        }
    }

    pub fn get_sent_note(&self, note_id: &NoteId) -> Option<&SentNote> {
        self.0.get(&note_id.into())
    }
}

impl Deref for SentNoteTable {
    type Target = BTreeMap<SentNoteId, SentNote>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SentNote {
    pub(crate) from_account_id: AccountId,
    pub(crate) to: Recipient<AccountId>,
    pub(crate) value: Zatoshis,
    pub(crate) memo: Memo,
}

mod serialization {
    use super::*;
    use crate::{error::Error, proto::memwallet as proto, read_optional};
    use zcash_address::ZcashAddress;
    use zcash_protocol::ShieldedProtocol;

    #[cfg(feature = "transparent-inputs")]
    use {
        transparent::address::TransparentAddress, zcash_keys::encoding::AddressCodec as _,
        zcash_protocol::consensus::Network::MainNetwork as EncodingParams,
    };

    impl From<SentNote> for proto::SentNote {
        fn from(note: SentNote) -> Self {
            Self {
                from_account_id: *note.from_account_id,
                to: Some(note.to.into()),
                value: note.value.into(),
                memo: note.memo.encode().as_array().to_vec(),
            }
        }
    }

    impl TryFrom<proto::SentNote> for SentNote {
        type Error = crate::Error;

        fn try_from(note: proto::SentNote) -> Result<Self, Self::Error> {
            Ok(Self {
                from_account_id: note.from_account_id.into(),
                to: read_optional!(note, to)?.try_into()?,
                value: Zatoshis::from_u64(note.value)?,
                memo: Memo::from_bytes(&note.memo)?,
            })
        }
    }

    impl From<SentNoteId> for proto::NoteId {
        fn from(note_id: SentNoteId) -> Self {
            match note_id {
                SentNoteId::Shielded(note_id) => proto::NoteId {
                    tx_id: Some(note_id.txid().into()),
                    output_index: note_id.output_index().into(),
                    pool: match note_id.protocol() {
                        ShieldedProtocol::Sapling => proto::PoolType::ShieldedSapling as i32,
                        ShieldedProtocol::Orchard => proto::PoolType::ShieldedOrchard as i32,
                    },
                },
                SentNoteId::Transparent { txid, output_index } => proto::NoteId {
                    tx_id: Some(txid.into()),
                    output_index,
                    pool: proto::PoolType::Transparent as i32,
                },
            }
        }
    }

    impl TryFrom<proto::NoteId> for SentNoteId {
        type Error = Error;

        fn try_from(note_id: proto::NoteId) -> Result<Self, Self::Error> {
            Ok(match note_id.pool() {
                proto::PoolType::ShieldedSapling => SentNoteId::Shielded(NoteId::new(
                    read_optional!(note_id, tx_id)?.try_into()?,
                    Sapling,
                    note_id.output_index.try_into()?,
                )),
                #[cfg(feature = "orchard")]
                proto::PoolType::ShieldedOrchard => SentNoteId::Shielded(NoteId::new(
                    read_optional!(note_id, tx_id)?.try_into()?,
                    Orchard,
                    note_id.output_index.try_into()?,
                )),
                #[cfg(not(feature = "orchard"))]
                proto::PoolType::ShieldedOrchard => return Err(Error::OrchardNotEnabled),
                proto::PoolType::Transparent => SentNoteId::Transparent {
                    txid: read_optional!(note_id, tx_id)?.try_into()?,
                    output_index: note_id.output_index,
                },
            })
        }
    }

    impl From<OutPoint> for proto::OutPoint {
        fn from(outpoint: OutPoint) -> Self {
            Self {
                hash: outpoint.txid().as_ref().to_vec(),
                n: outpoint.n(),
            }
        }
    }

    impl TryFrom<proto::OutPoint> for OutPoint {
        type Error = Error;

        fn try_from(outpoint: proto::OutPoint) -> Result<Self, Self::Error> {
            Ok(Self::new(outpoint.hash.try_into()?, outpoint.n))
        }
    }

    impl From<Recipient<AccountId>> for proto::Recipient {
        fn from(recipient: Recipient<AccountId>) -> Self {
            match recipient {
                Recipient::External {
                    recipient_address,
                    output_pool,
                } => proto::Recipient {
                    recipient_type: proto::RecipientType::ExternalRecipient as i32,

                    address: Some(recipient_address.to_string()),
                    pool_type: Some(match output_pool {
                        PoolType::Transparent => proto::PoolType::Transparent,
                        PoolType::Shielded(Sapling) => proto::PoolType::ShieldedSapling,
                        #[cfg(feature = "orchard")]
                        PoolType::Shielded(Orchard) => proto::PoolType::ShieldedOrchard,
                        #[cfg(not(feature = "orchard"))]
                        _ => panic!("Orchard not enabled"),
                    } as i32),

                    account_id: None,
                    outpoint: None,
                    note: None,
                },
                #[cfg(feature = "transparent-inputs")]
                Recipient::EphemeralTransparent {
                    receiving_account,
                    ephemeral_address,
                    outpoint,
                } => proto::Recipient {
                    recipient_type: proto::RecipientType::EphemeralTransparent as i32,

                    address: Some(ephemeral_address.encode(&EncodingParams)),
                    pool_type: Some(proto::PoolType::Transparent as i32),

                    account_id: Some(*receiving_account),
                    outpoint: Some(outpoint.into()),
                    note: None,
                },
                Recipient::InternalAccount {
                    receiving_account,
                    external_address,
                    note,
                } => proto::Recipient {
                    recipient_type: proto::RecipientType::InternalAccount as i32,

                    address: external_address.map(|a| a.to_string()),
                    pool_type: None,

                    account_id: Some(*receiving_account),
                    outpoint: None,
                    note: Some(note.deref().clone().into()),
                },
            }
        }
    }

    impl TryFrom<proto::Recipient> for Recipient<AccountId> {
        type Error = Error;
        fn try_from(recipient: proto::Recipient) -> Result<Self, Self::Error> {
            Ok(match recipient.recipient_type() {
                proto::RecipientType::ExternalRecipient => {
                    let address_str = read_optional!(recipient.clone(), address)?;
                    let address = ZcashAddress::try_from_encoded(&address_str)?;
                    Recipient::External {
                        recipient_address: address,
                        output_pool: match recipient.pool_type() {
                            proto::PoolType::Transparent => PoolType::Transparent,
                            proto::PoolType::ShieldedSapling => PoolType::Shielded(Sapling),
                            #[cfg(feature = "orchard")]
                            proto::PoolType::ShieldedOrchard => PoolType::Shielded(Orchard),
                            #[cfg(not(feature = "orchard"))]
                            proto::PoolType::ShieldedOrchard => {
                                return Err(Error::OrchardNotEnabled);
                            }
                        },
                    }
                }
                proto::RecipientType::EphemeralTransparent => {
                    #[cfg(not(feature = "transparent-inputs"))]
                    return Err(Error::Other("transparent inputs not enabled".to_string()));
                    #[cfg(feature = "transparent-inputs")]
                    Recipient::EphemeralTransparent {
                        receiving_account: read_optional!(recipient, account_id)?.into(),
                        ephemeral_address: TransparentAddress::decode(
                            &EncodingParams,
                            &read_optional!(recipient, address)?,
                        )?,
                        outpoint: read_optional!(recipient, outpoint)?.try_into()?,
                    }
                }
                proto::RecipientType::InternalAccount => Recipient::InternalAccount {
                    receiving_account: read_optional!(recipient, account_id)?.into(),
                    external_address: recipient.address.map(|a| a.parse()).transpose()?,
                    note: Box::new(read_optional!(recipient, note)?.into()),
                },
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::proto::memwallet as proto;

        use zcash_protocol::ShieldedProtocol;

        #[test]
        fn proto_roundtrip_recipient() {
            let recipient = Recipient::<AccountId>::External{
                recipient_address: ZcashAddress::try_from_encoded("uregtest1a7mkafdn9c87xywjnyup65uker8tx3y72r9f6elcfm6uh263c9s6smcw6xm5m8k8eythcreuyqktp9z7mtpcd6jsm5xw7skgdcfjx84z").unwrap(),
                output_pool: PoolType::Shielded(ShieldedProtocol::Sapling),
        };
            let proto = proto::Recipient::from(recipient.clone());
            let recipient2 = Recipient::<AccountId>::try_from(proto.clone()).unwrap();
            let proto2 = proto::Recipient::from(recipient2.clone());
            assert_eq!(proto, proto2);
        }
    }
}
