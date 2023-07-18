//! Serialization formats for data stored as SQLite BLOBs

use byteorder::{ReadBytesExt, WriteBytesExt};
use core::ops::Deref;
use shardtree::{Node, PrunableTree, RetentionFlags, Tree};
use std::io::{self, Read, Write};
use std::sync::Arc;
use zcash_encoding::Optional;
use zcash_primitives::merkle_tree::HashSer;

const SER_V1: u8 = 1;

const NIL_TAG: u8 = 0;
const LEAF_TAG: u8 = 1;
const PARENT_TAG: u8 = 2;

/// Writes a [`PrunableTree`] to the provided [`Write`] instance.
///
/// This is the primary method used for ShardTree shard persistence. It writes a version identifier
/// for the most-current serialized form, followed by the tree data.
pub fn write_shard<H: HashSer, W: Write>(writer: &mut W, tree: &PrunableTree<H>) -> io::Result<()> {
    fn write_inner<H: HashSer, W: Write>(
        mut writer: &mut W,
        tree: &PrunableTree<H>,
    ) -> io::Result<()> {
        match tree.deref() {
            Node::Parent { ann, left, right } => {
                writer.write_u8(PARENT_TAG)?;
                Optional::write(&mut writer, ann.as_ref(), |w, h| {
                    <H as HashSer>::write(h, w)
                })?;
                write_inner(writer, left)?;
                write_inner(writer, right)?;
                Ok(())
            }
            Node::Leaf { value } => {
                writer.write_u8(LEAF_TAG)?;
                value.0.write(&mut writer)?;
                writer.write_u8(value.1.bits())?;
                Ok(())
            }
            Node::Nil => {
                writer.write_u8(NIL_TAG)?;
                Ok(())
            }
        }
    }

    writer.write_u8(SER_V1)?;
    write_inner(writer, tree)
}

fn read_shard_v1<H: HashSer, R: Read>(mut reader: &mut R) -> io::Result<PrunableTree<H>> {
    match reader.read_u8()? {
        PARENT_TAG => {
            let ann = Optional::read(&mut reader, <H as HashSer>::read)?.map(Arc::new);
            let left = read_shard_v1(reader)?;
            let right = read_shard_v1(reader)?;
            Ok(Tree::parent(ann, left, right))
        }
        LEAF_TAG => {
            let value = <H as HashSer>::read(&mut reader)?;
            let flags = reader.read_u8().and_then(|bits| {
                RetentionFlags::from_bits(bits).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Byte value {} does not correspond to a valid set of retention flags",
                            bits
                        ),
                    )
                })
            })?;
            Ok(Tree::leaf((value, flags)))
        }
        NIL_TAG => Ok(Tree::empty()),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Node tag not recognized: {}", other),
        )),
    }
}

/// Reads a [`PrunableTree`] from the provided [`Read`] instance.
///
/// This function operates by first parsing a 1-byte version identifier, and then dispatching to
/// the correct deserialization function for the observed version, or returns an
/// [`io::ErrorKind::InvalidData`] error in the case that the version is not recognized.
pub fn read_shard<H: HashSer, R: Read>(mut reader: R) -> io::Result<PrunableTree<H>> {
    match reader.read_u8()? {
        SER_V1 => read_shard_v1(&mut reader),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Shard serialization version not recognized: {}", other),
        )),
    }
}

#[cfg(test)]
mod tests {
    use incrementalmerkletree::frontier::testing::{arb_test_node, TestNode};
    use proptest::prelude::*;
    use shardtree::testing::arb_prunable_tree;
    use std::io::Cursor;

    use super::{read_shard, write_shard};

    proptest! {
        #[test]
        fn check_shard_roundtrip(
            tree in arb_prunable_tree(arb_test_node(), 8, 32)
        ) {
            let mut tree_data = vec![];
            write_shard(&mut tree_data, &tree).unwrap();
            let cursor = Cursor::new(tree_data);
            let tree_result = read_shard::<TestNode, _>(cursor).unwrap();
            assert_eq!(tree, tree_result);
        }
    }
}
