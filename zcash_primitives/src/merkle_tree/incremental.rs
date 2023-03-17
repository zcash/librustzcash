//! Implementations of serialization and parsing for Orchard note commitment trees.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};

use incrementalmerkletree::{
    frontier::{Frontier, NonEmptyFrontier},
    Address, Hashable, Level, Position,
};
use orchard::tree::MerkleHashOrchard;
use zcash_encoding::{Optional, Vector};

use super::{read_commitment_tree, HashSer};
use crate::sapling;

pub const SER_V1: u8 = 1;
pub const SER_V2: u8 = 2;

impl HashSer for MerkleHashOrchard {
    fn read<R: Read>(mut reader: R) -> io::Result<Self>
    where
        Self: Sized,
    {
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr)?;
        <Option<_>>::from(Self::from_bytes(&repr)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Non-canonical encoding of Pallas base field value.",
            )
        })
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.to_bytes())
    }
}

/// Writes a usize value encoded as a u64 in little-endian order. Since usize
/// is platform-dependent, we consistently represent it as u64 in serialized
/// formats.
pub fn write_usize_leu64<W: Write>(mut writer: W, value: usize) -> io::Result<()> {
    // Panic if we get a usize value that can't fit into a u64.
    writer.write_u64::<LittleEndian>(value.try_into().unwrap())
}

/// Reads a usize value encoded as a u64 in little-endian order. Since usize
/// is platform-dependent, we consistently represent it as u64 in serialized
/// formats.
pub fn read_leu64_usize<R: Read>(mut reader: R) -> io::Result<usize> {
    reader.read_u64::<LittleEndian>()?.try_into().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "usize could not be decoded from a 64-bit value on this platform: {:?}",
                e
            ),
        )
    })
}

pub fn write_position<W: Write>(mut writer: W, position: Position) -> io::Result<()> {
    write_usize_leu64(&mut writer, position.into())
}

pub fn read_position<R: Read>(mut reader: R) -> io::Result<Position> {
    read_leu64_usize(&mut reader).map(Position::from)
}

pub fn write_address<W: Write>(mut writer: W, addr: Address) -> io::Result<()> {
    writer.write_u8(addr.level().into())?;
    write_usize_leu64(&mut writer, addr.index())
}

pub fn read_address<R: Read>(mut reader: R) -> io::Result<Address> {
    let level = reader.read_u8().map(Level::from)?;
    let index = read_leu64_usize(&mut reader)?;
    Ok(Address::from_parts(level, index))
}

pub fn read_frontier_v0<H: Hashable + HashSer + Clone, R: Read>(
    mut reader: R,
) -> io::Result<Frontier<H, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>> {
    let tree = read_commitment_tree(&mut reader)?;
    Ok(tree.to_frontier())
}

pub fn write_nonempty_frontier_v1<H: HashSer, W: Write>(
    mut writer: W,
    frontier: &NonEmptyFrontier<H>,
) -> io::Result<()> {
    write_position(&mut writer, frontier.position())?;
    if frontier.position().is_odd() {
        // The v1 serialization wrote the sibling of a right-hand leaf as a non-optional value,
        // rather than as part of the ommers vector.
        frontier
            .ommers()
            .get(0)
            .expect("ommers vector cannot be empty for right-hand nodes")
            .write(&mut writer)?;
        Optional::write(&mut writer, Some(frontier.leaf()), |w, n: &H| n.write(w))?;
        Vector::write(&mut writer, &frontier.ommers()[1..], |w, e| e.write(w))?;
    } else {
        frontier.leaf().write(&mut writer)?;
        Optional::write(&mut writer, None, |w, n: &H| n.write(w))?;
        Vector::write(&mut writer, frontier.ommers(), |w, e| e.write(w))?;
    }

    Ok(())
}

#[allow(clippy::redundant_closure)]
pub fn read_nonempty_frontier_v1<H: HashSer + Clone, R: Read>(
    mut reader: R,
) -> io::Result<NonEmptyFrontier<H>> {
    let position = read_position(&mut reader)?;
    let left = H::read(&mut reader)?;
    let right = Optional::read(&mut reader, H::read)?;
    let mut ommers = Vector::read(&mut reader, |r| H::read(r))?;

    let leaf = if let Some(right) = right {
        // if the frontier has a right leaf, then the left leaf is the first ommer
        ommers.insert(0, left);
        right
    } else {
        left
    };

    NonEmptyFrontier::from_parts(position, leaf, ommers).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Parsing resulted in an invalid Merkle frontier: {:?}", err),
        )
    })
}

pub fn write_frontier_v1<H: HashSer, W: Write>(
    writer: W,
    frontier: &Frontier<H, 32>,
) -> io::Result<()> {
    Optional::write(writer, frontier.value(), write_nonempty_frontier_v1)
}

#[allow(clippy::redundant_closure)]
pub fn read_frontier_v1<H: HashSer + Clone, R: Read>(reader: R) -> io::Result<Frontier<H, 32>> {
    match Optional::read(reader, read_nonempty_frontier_v1)? {
        None => Ok(Frontier::empty()),
        Some(f) => Frontier::try_from(f).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Parsing resulted in an invalid Merkle frontier: {:?}", err),
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{
        merkle_tree::write_commitment_tree,
        sapling::{testing as sapling, Node},
    };
    use incrementalmerkletree::frontier::{testing::arb_commitment_tree, Frontier};

    proptest! {
        #[test]
        fn frontier_serialization_v0(t in arb_commitment_tree::<_, _, 32>(0, sapling::arb_node()))
        {
            let mut buffer = vec![];
            write_commitment_tree(&t, &mut buffer).unwrap();
            let frontier: Frontier<Node, 32> = read_frontier_v0(&buffer[..]).unwrap();

            let expected: Frontier<Node, 32> = t.to_frontier();
            assert_eq!(frontier, expected);
        }

        #[test]
        fn frontier_serialization_v1(t in arb_commitment_tree::<_, _, 32>(1, sapling::arb_node()))
        {
            let original: Frontier<Node, 32> = t.to_frontier();

            let mut buffer = vec![];
            write_frontier_v1(&mut buffer, &original).unwrap();
            let read: Frontier<Node, 32> = read_frontier_v1(&buffer[..]).unwrap();

            assert_eq!(read, original);
        }
    }
}
