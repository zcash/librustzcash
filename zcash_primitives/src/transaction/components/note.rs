use crate::transaction::components::orchard::read_nullifier;
use std::io;
use std::io::{Read, Write};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use orchard::note::{AssetBase, Nullifier, RandomSeed};
use orchard::{Address, Note};
use orchard::note::{Nullifier, RandomSeed};
use orchard::value::NoteValue;
use orchard::{Address, Note};
use std::io;
use std::io::{Read, Write};
use crate::transaction::components::orchard::read_nullifier;

/// This will be a part of the 'issuance' component in ZSA release
fn read_recipient<R: Read>(mut reader: R) -> io::Result<Address> {
    let mut bytes = [0u8; 43];
    reader.read_exact(&mut bytes)?;
    Ok(Option::from(Address::from_raw_address_bytes(&bytes)).unwrap())
}

fn read_rseed<R: Read>(mut reader: R, nullifier: &Nullifier) -> io::Result<RandomSeed> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(Option::from(RandomSeed::from_bytes(bytes, nullifier)).unwrap())
}

pub fn read_note<R: Read>(mut reader: R) -> io::Result<Note> {
    let recipient = read_recipient(&mut reader)?;
    let value = reader.read_u64::<LittleEndian>()?;
    let rho = read_nullifier(&mut reader)?;
    let rseed = read_rseed(&mut reader, &rho)?;
    Ok(Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        AssetBase::native(), // FIXME: pass burns here for ZSA
        rho,
        rseed,
    ))
    .unwrap())
}

pub fn write_note<W: Write>(note: &Note, writer: &mut W) -> io::Result<()> {
    writer.write_all(&note.recipient().to_raw_address_bytes())?;
    writer.write_u64::<LittleEndian>(note.value().inner())?;
    writer.write_all(&note.rho().to_bytes())?;
    writer.write_all(note.rseed().as_bytes())?;
    Ok(())
}
