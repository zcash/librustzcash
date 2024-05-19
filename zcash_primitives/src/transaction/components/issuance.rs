use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use nonempty::NonEmpty;
use orchard::issuance::{IssueAction, IssueBundle, Signed};
use orchard::keys::IssuanceValidatingKey;
use orchard::note::{AssetBase, RandomSeed, Rho};
use orchard::value::NoteValue;
use orchard::{Address, Note};
/// Functions for parsing & serialization of the issuance bundle components.
use std::io;
use std::io::{Read, Write};
use zcash_encoding::{CompactSize, Vector};

/// Reads an [`orchard::Bundle`] from a v5 transaction format.
pub fn read_v6_bundle<R: Read>(mut reader: R) -> io::Result<Option<IssueBundle<Signed>>> {
    let actions = Vector::read(&mut reader, |r| read_action(r))?;

    if actions.is_empty() {
        Ok(None)
    } else {
        let ik = read_ik(&mut reader);
        let authorization = read_authorization(&mut reader);

        Ok(Some(IssueBundle::from_parts(
            ik?,
            NonEmpty::from_vec(actions).unwrap(),
            authorization?,
        )))
    }
}

fn read_ik<R: Read>(mut reader: R) -> io::Result<IssuanceValidatingKey> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(IssuanceValidatingKey::from_bytes(&bytes).unwrap())
}

fn read_authorization<R: Read>(mut reader: R) -> io::Result<Signed> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(Signed::from_data(bytes))
}

fn read_action<R: Read>(mut reader: R) -> io::Result<IssueAction> {
    let finalize = reader.read_u8()? != 0;
    let notes = Vector::read(&mut reader, |r| read_note(r))?;
    let asset_descr_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    let asset_descr: String = String::from_utf8(asset_descr_bytes).unwrap();
    Ok(IssueAction::from_parts(asset_descr, notes, finalize))
}

pub fn read_note<R: Read>(mut reader: R) -> io::Result<Note> {
    let recipient = read_recipient(&mut reader)?;
    let value = reader.read_u64::<LittleEndian>()?;
    let asset = read_asset(&mut reader)?;
    let rho = read_rho(&mut reader)?;
    let rseed = read_rseed(&mut reader, &rho)?;
    Ok(Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        asset,
        rho,
        rseed,
    ))
    .unwrap())
}

fn read_rho<R: Read>(mut reader: R) -> io::Result<Rho> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let rho_ctopt = Rho::from_bytes(&bytes);
    if rho_ctopt.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas point for rho".to_owned(),
        ))
    } else {
        Ok(rho_ctopt.unwrap())
    }
}

fn read_recipient<R: Read>(mut reader: R) -> io::Result<Address> {
    let mut bytes = [0u8; 43];
    reader.read_exact(&mut bytes)?;
    Ok(Option::from(Address::from_raw_address_bytes(&bytes)).unwrap())
}

pub fn read_asset<R: Read>(reader: &mut R) -> io::Result<AssetBase> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(Option::from(AssetBase::from_bytes(&bytes)).unwrap())
}

fn read_rseed<R: Read>(mut reader: R, nullifier: &Rho) -> io::Result<RandomSeed> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(Option::from(RandomSeed::from_bytes(bytes, nullifier)).unwrap())
}

/// Writes an [`IssueBundle`] in the v5 transaction format.
pub fn write_v6_bundle<W: Write>(
    bundle: Option<&IssueBundle<Signed>>,
    mut writer: W,
) -> io::Result<()> {
    if let Some(bundle) = &bundle {
        Vector::write_nonempty(&mut writer, bundle.actions(), |w, action| {
            write_action(action, w)
        })?;
        writer.write_all(&bundle.ik().to_bytes())?;
        writer.write_all(&<[u8; 64]>::from(bundle.authorization().signature()))?;
    } else {
        CompactSize::write(&mut writer, 0)?;
    }
    Ok(())
}

fn write_action<W: Write>(action: &IssueAction, mut writer: W) -> io::Result<()> {
    let is_finalized_u8 :u8 = if action.is_finalized() { 1 } else { 0 };
    writer.write_u8(is_finalized_u8)?;
    Vector::write(&mut writer, action.notes(), |w, note| write_note(note, w))?;
    Vector::write(&mut writer, action.asset_desc().as_bytes(), |w, b| {
        w.write_u8(*b)
    })?;
    Ok(())
}

pub fn write_note<W: Write>(note: &Note, writer: &mut W) -> io::Result<()> {
    writer.write_all(&note.recipient().to_raw_address_bytes())?;
    writer.write_u64::<LittleEndian>(note.value().inner())?;
    writer.write_all(&note.asset().to_bytes())?;
    writer.write_all(&note.rho().to_bytes())?;
    writer.write_all(note.rseed().as_bytes())?;
    Ok(())
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use orchard::issuance::{
        testing::{self as t_issue},
        IssueBundle, Signed,
    };

    use crate::transaction::TxVersion;

    prop_compose! {
        pub fn arb_issue_bundle(n_actions: usize)(
            bundle in t_issue::arb_signed_issue_bundle(n_actions)
        ) -> IssueBundle<Signed> {
            bundle
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<IssueBundle<Signed>>> {
        if v.has_zsa() {
            Strategy::boxed((1usize..100).prop_flat_map(|n| prop::option::of(arb_issue_bundle(n))))
        } else {
            Strategy::boxed(Just(None))
        }
    }
}
