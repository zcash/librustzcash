mod received;
mod sent;

pub(crate) use received::{
    ReceievedNoteSpends, ReceivedNote, ReceivedNoteTable, to_spendable_notes,
};
#[cfg(test)]
pub(crate) use sent::SentNoteId;
pub(crate) use sent::{SentNote, SentNoteTable};

mod serialization {
    use crate::error::Error;
    use crate::proto::memwallet::{self as proto};
    use crate::read_optional;
    use jubjub::Fr;
    use zcash_client_backend::wallet::{Note, NoteId};

    impl From<NoteId> for proto::NoteId {
        fn from(note_id: NoteId) -> Self {
            Self {
                tx_id: Some(note_id.txid().into()),
                pool: match note_id.protocol() {
                    zcash_protocol::ShieldedProtocol::Sapling => {
                        proto::PoolType::ShieldedSapling.into()
                    }
                    #[cfg(feature = "orchard")]
                    zcash_protocol::ShieldedProtocol::Orchard => {
                        proto::PoolType::ShieldedOrchard.into()
                    }
                    #[cfg(not(feature = "orchard"))]
                    zcash_protocol::ShieldedProtocol::Orchard => panic!(
                        "Attempting to deserialize orchard supporting wallet using library built without orchard feature"
                    ),
                },
                output_index: u32::from(note_id.output_index()),
            }
        }
    }

    impl TryFrom<proto::NoteId> for NoteId {
        type Error = Error;
        fn try_from(note_id: proto::NoteId) -> Result<Self, Self::Error> {
            Ok(Self::new(
                read_optional!(note_id.clone(), tx_id)?.try_into()?,
                match note_id.pool() {
                    proto::PoolType::ShieldedSapling => zcash_protocol::ShieldedProtocol::Sapling,
                    #[cfg(feature = "orchard")]
                    proto::PoolType::ShieldedOrchard => zcash_protocol::ShieldedProtocol::Orchard,
                    _ => panic!("invalid pool"),
                },
                note_id.output_index.try_into()?,
            ))
        }
    }

    impl From<Note> for proto::Note {
        fn from(note: Note) -> Self {
            match note {
                Note::Sapling(note) => Self {
                    protocol: proto::ShieldedProtocol::Sapling.into(),
                    recipient: note.recipient().to_bytes().to_vec(),
                    value: note.value().inner(),
                    rseed: match note.rseed() {
                        sapling::Rseed::AfterZip212(inner) => Some(proto::RSeed {
                            rseed_type: Some(proto::RSeedType::AfterZip212 as i32),
                            payload: inner.to_vec(),
                        }),
                        sapling::Rseed::BeforeZip212(inner) => Some(proto::RSeed {
                            rseed_type: Some(proto::RSeedType::BeforeZip212 as i32),
                            payload: inner.to_bytes().to_vec(),
                        }),
                    },
                    rho: None,
                },
                #[cfg(feature = "orchard")]
                Note::Orchard(note) => Self {
                    protocol: proto::ShieldedProtocol::Orchard.into(),
                    recipient: note.recipient().to_raw_address_bytes().to_vec(),
                    value: note.value().inner(),
                    rseed: Some(proto::RSeed {
                        rseed_type: None,
                        payload: note.rseed().as_bytes().to_vec(),
                    }),
                    rho: Some(note.rho().to_bytes().to_vec()),
                },
            }
        }
    }

    impl TryFrom<proto::Note> for Note {
        type Error = Error;

        fn try_from(note: proto::Note) -> Result<Self, Self::Error> {
            match note.protocol() {
                proto::ShieldedProtocol::Sapling => {
                    let recipient_bytes: [u8; 43] = note.recipient.try_into()?;
                    let recipient = sapling::PaymentAddress::from_bytes(&recipient_bytes)
                        .ok_or_else(|| {
                            Error::CorruptedData("invalid sapling recipient".to_string())
                        })?;
                    let value = sapling::value::NoteValue::from_raw(note.value);
                    let rseed = match read_optional!(note, rseed)? {
                        proto::RSeed {
                            rseed_type: Some(0),
                            payload,
                        } => {
                            let payload: [u8; 32] = payload.try_into()?;
                            let fr = Option::from(Fr::from_bytes(&payload)).ok_or_else(|| {
                                Error::CorruptedData("invalid sapling rseed (BeforeZip212)".to_string())
                            })?;
                            sapling::Rseed::BeforeZip212(fr)
                        }
                        proto::RSeed {
                            rseed_type: Some(1),
                            payload,
                        } => sapling::Rseed::AfterZip212(payload.try_into()?),
                        _ => {
                            return Err(Error::CorruptedData(
                                "missing or unrecognized rseed_type".to_string(),
                            ));
                        }
                    };
                    Ok(Self::Sapling(sapling::Note::from_parts(
                        recipient, value, rseed,
                    )))
                }
                #[cfg(feature = "orchard")]
                proto::ShieldedProtocol::Orchard => {
                    let recipient_bytes: [u8; 43] = note.recipient.try_into()?;
                    let recipient =
                        Option::from(orchard::Address::from_raw_address_bytes(&recipient_bytes))
                            .ok_or_else(|| {
                                Error::CorruptedData("invalid orchard recipient".to_string())
                            })?;
                    let value = orchard::value::NoteValue::from_raw(note.value);
                    let rho_bytes: [u8; 32] = read_optional!(note, rho)?.try_into()?;
                    let rho = Option::from(orchard::note::Rho::from_bytes(&rho_bytes))
                        .ok_or_else(|| Error::CorruptedData("invalid orchard rho".to_string()))?;
                    let rseed_payload: [u8; 32] =
                        read_optional!(note, rseed)?.payload.try_into()?;
                    let rseed = Option::from(orchard::note::RandomSeed::from_bytes(
                        rseed_payload,
                        &rho,
                    ))
                    .ok_or_else(|| Error::CorruptedData("invalid orchard rseed".to_string()))?;
                    Ok(Self::Orchard(
                        Option::from(orchard::Note::from_parts(recipient, value, rho, rseed))
                            .ok_or_else(|| {
                                Error::CorruptedData("invalid orchard note parts".to_string())
                            })?,
                    ))
                }
                #[cfg(not(feature = "orchard"))]
                _ => Err(Error::OrchardNotEnabled),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::proto::memwallet as proto;

        #[test]
        fn test_note_roundtrip() {
            let note = Note::Sapling(sapling::note::Note::from_parts(
                sapling::PaymentAddress::from_bytes(&[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x8e,
                    0x11, 0x9d, 0x72, 0x99, 0x2b, 0x56, 0x0d, 0x26, 0x50, 0xff, 0xe0, 0xbe, 0x7f,
                    0x35, 0x42, 0xfd, 0x97, 0x00, 0x3c, 0xb7, 0xcc, 0x3a, 0xbf, 0xf8, 0x1a, 0x7f,
                    0x90, 0x37, 0xf3, 0xea,
                ])
                .unwrap(),
                sapling::value::NoteValue::from_raw(99),
                sapling::Rseed::AfterZip212([0; 32]),
            ));

            let proto_note: proto::Note = note.clone().into();
            let recovered: Note = proto_note.try_into().unwrap();

            assert_eq!(note, recovered);
        }

        #[test]
        fn try_from_proto_note_rejects_wrong_length_sapling_recipient() {
            let proto_note = proto::Note {
                protocol: proto::ShieldedProtocol::Sapling as i32,
                recipient: vec![0u8; 16],
                value: 99,
                rseed: Some(proto::RSeed {
                    rseed_type: Some(1),
                    payload: vec![0u8; 32],
                }),
                rho: None,
            };
            assert!(matches!(
                Note::try_from(proto_note),
                Err(Error::ByteVecToArrayConversion(_)),
            ));
        }

        #[test]
        fn try_from_proto_note_rejects_unrecognized_rseed_type() {
            let valid_recipient = vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x8e, 0x11,
                0x9d, 0x72, 0x99, 0x2b, 0x56, 0x0d, 0x26, 0x50, 0xff, 0xe0, 0xbe, 0x7f, 0x35, 0x42,
                0xfd, 0x97, 0x00, 0x3c, 0xb7, 0xcc, 0x3a, 0xbf, 0xf8, 0x1a, 0x7f, 0x90, 0x37, 0xf3,
                0xea,
            ];
            let proto_note = proto::Note {
                protocol: proto::ShieldedProtocol::Sapling as i32,
                recipient: valid_recipient,
                value: 99,
                rseed: Some(proto::RSeed {
                    rseed_type: Some(99),
                    payload: vec![0u8; 32],
                }),
                rho: None,
            };
            assert!(matches!(
                Note::try_from(proto_note),
                Err(Error::CorruptedData(_)),
            ));
        }

        #[test]
        fn try_from_proto_note_rejects_wrong_length_rseed_payload() {
            let valid_recipient = vec![
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x8e, 0x11,
                0x9d, 0x72, 0x99, 0x2b, 0x56, 0x0d, 0x26, 0x50, 0xff, 0xe0, 0xbe, 0x7f, 0x35, 0x42,
                0xfd, 0x97, 0x00, 0x3c, 0xb7, 0xcc, 0x3a, 0xbf, 0xf8, 0x1a, 0x7f, 0x90, 0x37, 0xf3,
                0xea,
            ];
            let proto_note = proto::Note {
                protocol: proto::ShieldedProtocol::Sapling as i32,
                recipient: valid_recipient,
                value: 99,
                rseed: Some(proto::RSeed {
                    rseed_type: Some(0),
                    payload: vec![0u8; 16],
                }),
                rho: None,
            };
            assert!(matches!(
                Note::try_from(proto_note),
                Err(Error::ByteVecToArrayConversion(_)),
            ));
        }
    }
}
