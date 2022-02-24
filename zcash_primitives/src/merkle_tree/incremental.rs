//! Implementations of serialization and parsing for Orchard note commitment trees.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::{TryFrom, TryInto};
use std::io::{self, Read, Write};

use incrementalmerkletree::{
    bridgetree::{AuthFragment, Frontier, Leaf, MerkleBridge, NonEmptyFrontier},
    Hashable, Position,
};
use orchard::tree::MerkleHashOrchard;
use zcash_encoding::{Optional, Vector};

use super::{CommitmentTree, HashSer};

pub const SER_V1: u8 = 1;

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

pub fn read_frontier_v0<H: Hashable + super::Hashable, R: Read>(
    mut reader: R,
) -> io::Result<Frontier<H, 32>> {
    let tree = CommitmentTree::read(&mut reader)?;

    Ok(tree.to_frontier())
}

pub fn write_nonempty_frontier_v1<H: HashSer, W: Write>(
    mut writer: W,
    frontier: &NonEmptyFrontier<H>,
) -> io::Result<()> {
    writer.write_u64::<LittleEndian>(<u64>::from(frontier.position()))?;
    match frontier.leaf() {
        Leaf::Left(a) => {
            a.write(&mut writer)?;
            Optional::write(&mut writer, None, |w, n: &H| n.write(w))?;
        }
        Leaf::Right(a, b) => {
            a.write(&mut writer)?;
            Optional::write(&mut writer, Some(b), |w, n| n.write(w))?;
        }
    }
    Vector::write(&mut writer, frontier.ommers(), |w, e| e.write(w))?;

    Ok(())
}

#[allow(clippy::redundant_closure)]
pub fn read_nonempty_frontier_v1<H: HashSer + Clone, R: Read>(
    mut reader: R,
) -> io::Result<NonEmptyFrontier<H>> {
    let position = read_position(&mut reader)?;
    let left = H::read(&mut reader)?;
    let right = Optional::read(&mut reader, H::read)?;

    let leaf = right.map_or_else(
        || Leaf::Left(left.clone()),
        |r| Leaf::Right(left.clone(), r),
    );
    let ommers = Vector::read(&mut reader, |r| H::read(r))?;

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

pub fn write_position<W: Write>(mut writer: W, position: Position) -> io::Result<()> {
    writer.write_u64::<LittleEndian>(position.try_into().unwrap())
}

pub fn read_position<R: Read>(mut reader: R) -> io::Result<Position> {
    let p = reader.read_u64::<LittleEndian>()?;
    <usize>::try_from(p).map(Position::from).map_err(|err| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "usize could not be decoded to a 64-bit value on this platform: {:?}",
                err
            ),
        )
    })
}

pub fn write_auth_fragment_v1<H: HashSer, W: Write>(
    mut writer: W,
    fragment: &AuthFragment<H>,
) -> io::Result<()> {
    write_position(&mut writer, fragment.position())?;
    writer.write_u64::<LittleEndian>(fragment.altitudes_observed().try_into().unwrap())?;
    Vector::write(&mut writer, fragment.values(), |w, a| a.write(w))
}

#[allow(clippy::redundant_closure)]
pub fn read_auth_fragment_v1<H: HashSer, R: Read>(mut reader: R) -> io::Result<AuthFragment<H>> {
    let position = read_position(&mut reader)?;
    let alts_observed = reader.read_u64::<LittleEndian>()? as usize;
    let values = Vector::read(&mut reader, |r| H::read(r))?;

    Ok(AuthFragment::from_parts(position, alts_observed, values))
}

pub fn write_bridge_v1<H: HashSer + Ord, W: Write>(
    mut writer: W,
    bridge: &MerkleBridge<H>,
) -> io::Result<()> {
    Optional::write(
        &mut writer,
        bridge.prior_position().map(<u64>::from),
        |w, n| w.write_u64::<LittleEndian>(n),
    )?;
    Vector::write(
        &mut writer,
        &bridge.auth_fragments().iter().collect::<Vec<_>>(),
        |w, (i, a)| {
            w.write_u64::<LittleEndian>(u64::from(**i))?;
            write_auth_fragment_v1(w, a)
        },
    )?;
    write_nonempty_frontier_v1(&mut writer, bridge.frontier())?;

    Ok(())
}

pub fn read_bridge_v1<H: HashSer + Ord + Clone, R: Read>(
    mut reader: R,
) -> io::Result<MerkleBridge<H>> {
    let prior_position = Optional::read(&mut reader, read_position)?;
    let auth_fragments = Vector::read(&mut reader, |mut r| {
        Ok((read_position(&mut r)?, read_auth_fragment_v1(r)?))
    })?
    .into_iter()
    .collect();
    let frontier = read_nonempty_frontier_v1(&mut reader)?;

    Ok(MerkleBridge::from_parts(
        prior_position,
        auth_fragments,
        frontier,
    ))
}

pub fn write_bridge<H: HashSer + Ord, W: Write>(
    mut writer: W,
    bridge: &MerkleBridge<H>,
) -> io::Result<()> {
    writer.write_u8(SER_V1)?;
    write_bridge_v1(writer, bridge)
}

pub fn read_bridge<H: HashSer + Ord + Clone, R: Read>(
    mut reader: R,
) -> io::Result<MerkleBridge<H>> {
    match reader.read_u8()? {
        SER_V1 => read_bridge_v1(&mut reader),
        flag => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unrecognized serialization version: {:?}", flag),
        )),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use incrementalmerkletree::bridgetree::Frontier;

    use super::*;
    use crate::{
        merkle_tree::testing::arb_commitment_tree,
        sapling::{testing as sapling, Node},
    };

    proptest! {
        #[test]
        fn frontier_serialization_v0(t in arb_commitment_tree(0, sapling::arb_node()))
        {
            let mut buffer = vec![];
            t.write(&mut buffer).unwrap();
            let frontier: Frontier<Node, 32> = read_frontier_v0(&buffer[..]).unwrap();

            let expected: Frontier<Node, 32> = t.to_frontier();
            assert_eq!(frontier, expected);
        }

        #[test]
        fn frontier_serialization_v1(t in arb_commitment_tree(1, sapling::arb_node()))
        {
            let original: Frontier<Node, 32> = t.to_frontier();

            let mut buffer = vec![];
            write_frontier_v1(&mut buffer, &original).unwrap();
            let read: Frontier<Node, 32> = read_frontier_v1(&buffer[..]).unwrap();

            assert_eq!(read, original);
        }
    }
}
