//! Implementations of serialization and parsing for Orchard note commitment trees.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::hash::Hash;
use std::io::{self, Read, Write};

use incrementalmerkletree::{
    bridgetree::{
        AuthFragment, BridgeTree, Checkpoint, Frontier, Leaf, MerkleBridge, NonEmptyFrontier,
    },
    Hashable, Position,
};
use orchard::tree::MerkleCrhOrchardOutput;
use zcash_encoding::{Optional, Vector};

use super::{CommitmentTree, HashSer};

pub const SER_V1: u8 = 1;

pub fn read_frontier_v0<H: Hashable + super::Hashable, R: Read>(
    mut reader: R,
) -> io::Result<Frontier<H, 32>> {
    let tree = CommitmentTree::read(&mut reader)?;

    Ok(tree.to_frontier())
}

impl HashSer for MerkleCrhOrchardOutput {
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
    Vector::write(&mut writer, &frontier.ommers(), |w, e| e.write(w))?;

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

pub fn write_auth_fragment_v1<H: HashSer, W: Write>(
    mut writer: W,
    fragment: &AuthFragment<H>,
) -> io::Result<()> {
    writer.write_u64::<LittleEndian>(<u64>::from(fragment.position()))?;
    writer.write_u64::<LittleEndian>(fragment.altitudes_observed() as u64)?;
    Vector::write(&mut writer, fragment.values(), |w, a| a.write(w))
}

pub fn read_position<R: Read>(mut reader: R) -> io::Result<Position> {
    Ok(Position::from(reader.read_u64::<LittleEndian>()? as usize))
}

#[allow(clippy::redundant_closure)]
pub fn read_auth_fragment_v1<H: HashSer, R: Read>(mut reader: R) -> io::Result<AuthFragment<H>> {
    let position = read_position(&mut reader)?;
    let alts_observed = reader.read_u64::<LittleEndian>()? as usize;
    let values = Vector::read(&mut reader, |r| H::read(r))?;

    Ok(AuthFragment::from_parts(position, alts_observed, values))
}

pub fn write_bridge_v1<H: HashSer, W: Write>(
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
            w.write_u64::<LittleEndian>(**i as u64)?;
            write_auth_fragment_v1(w, a)
        },
    )?;
    write_nonempty_frontier_v1(&mut writer, bridge.frontier())?;

    Ok(())
}

pub fn read_bridge_v1<H: HashSer + Clone, R: Read>(mut reader: R) -> io::Result<MerkleBridge<H>> {
    let prior_position = Optional::read(&mut reader, read_position)?;
    let auth_fragments = Vector::read(&mut reader, |r| {
        Ok((
            r.read_u64::<LittleEndian>()? as usize,
            read_auth_fragment_v1(r)?,
        ))
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

pub const EMPTY_CHECKPOINT: u8 = 0;
pub const BRIDGE_CHECKPOINT: u8 = 1;

pub fn write_checkpoint_v1<H: HashSer, W: Write>(
    mut writer: W,
    checkpoint: &Checkpoint<H>,
) -> io::Result<()> {
    match checkpoint {
        Checkpoint::Empty => {
            writer.write_u8(EMPTY_CHECKPOINT)?;
        }
        Checkpoint::AtIndex(i, b) => {
            writer.write_u8(BRIDGE_CHECKPOINT)?;
            writer.write_u64::<LittleEndian>(*i as u64)?;
            write_bridge_v1(&mut writer, b)?;
        }
    }

    Ok(())
}

pub fn read_checkpoint_v1<H: HashSer + Clone, R: Read>(mut reader: R) -> io::Result<Checkpoint<H>> {
    match reader.read_u8()? {
        EMPTY_CHECKPOINT => Ok(Checkpoint::Empty),
        BRIDGE_CHECKPOINT => Ok(Checkpoint::AtIndex(
            reader.read_u64::<LittleEndian>()? as usize,
            read_bridge_v1(&mut reader)?,
        )),
        flag => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unrecognized checkpoint variant identifier: {:?}", flag),
        )),
    }
}

pub fn write_tree_v1<H: HashSer + Hash + Eq, W: Write>(
    mut writer: W,
    tree: &BridgeTree<H, 32>,
) -> io::Result<()> {
    Vector::write(&mut writer, tree.bridges(), |w, b| write_bridge_v1(w, b))?;
    Vector::write(
        &mut writer,
        &tree.witnessable_leaves().iter().collect::<Vec<_>>(),
        |mut w, (a, i)| {
            a.write(&mut w)?;
            w.write_u64::<LittleEndian>(**i as u64)?;
            Ok(())
        },
    )?;
    Vector::write(&mut writer, tree.checkpoints(), |w, c| {
        write_checkpoint_v1(w, c)
    })?;
    writer.write_u64::<LittleEndian>(tree.max_checkpoints() as u64)?;

    Ok(())
}

#[allow(clippy::redundant_closure)]
pub fn read_tree_v1<H: Hashable + HashSer + Hash + Eq + Clone, R: Read>(
    mut reader: R,
) -> io::Result<BridgeTree<H, 32>> {
    BridgeTree::from_parts(
        Vector::read(&mut reader, |r| read_bridge_v1(r))?,
        Vector::read(&mut reader, |mut r| {
            Ok((H::read(&mut r)?, r.read_u64::<LittleEndian>()? as usize))
        })?
        .into_iter()
        .collect(),
        Vector::read(&mut reader, |r| read_checkpoint_v1(r))?,
        reader.read_u64::<LittleEndian>()? as usize,
    )
    .map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Consistency violation found when attempting to deserialize Merkle tree: {:?}",
                err
            ),
        )
    })
}

pub fn write_tree<H: HashSer + Hash + Eq, W: Write>(
    mut writer: W,
    tree: &BridgeTree<H, 32>,
) -> io::Result<()> {
    writer.write_u8(SER_V1)?;
    write_tree_v1(&mut writer, tree)
}

pub fn read_tree<H: Hashable + HashSer + Hash + Eq + Clone, R: Read>(
    mut reader: R,
) -> io::Result<BridgeTree<H, 32>> {
    match reader.read_u8()? {
        SER_V1 => read_tree_v1(&mut reader),
        flag => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unrecognized tree serialization version: {:?}", flag),
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
