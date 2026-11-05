//! Single-pass solution tree validation.

use super::Kind;
use crate::{minimal::expand_array_into, params::Params};

pub(super) type Digest = [u8; 64];

/// Leaves hashed per call to `validate_tree`'s `hash`; a multiple of every
/// kernel's lane count.
const HASH_BATCH: usize = 64;

/// Validates the solution tree for `indices`, where `hash` writes the digest
/// of each block index in a batch.
///
/// Subtrees are merged in the same post-order, with the same checks in the
/// same order, as the recursive validator, so both report the same error.
pub(super) fn validate_tree(
    p: &Params,
    indices: &[u32],
    mut hash: impl FnMut(&[u32], &mut [Digest]),
) -> Result<(), Kind> {
    // Anything else would leave the tree, or its root, partly unvisited.
    let leaves = indices.len();
    if p.solution_indices() != Some(leaves) {
        return Err(Kind::InvalidParams);
    }
    let per_hash = p.indices_per_hash_output();
    let leaf_bytes = p.n as usize / 8;
    let collision_bytes = p.collision_byte_length();
    let row_len = p.hash_length();

    // With every index distinct, each subtree pair's duplicate check passes.
    let mut sorted = indices.to_vec();
    sorted.sort_unstable();
    let all_distinct = sorted.windows(2).all(|w| w[0] != w[1]);
    drop(sorted);

    // `pending[h]` holds the unmerged left subtree of height `h`, which has
    // `row_len - h * collision_bytes` hash bytes after trimming.
    let mut pending = vec![0u8; (p.k as usize + 1) * row_len];
    let mut row = vec![0u8; row_len];
    // Hash leaves in small batches as the walk reaches them, so memory does
    // not grow with `2^k` and an invalid solution stops within one batch of
    // its first failing check.
    let mut blocks = [0u32; HASH_BATCH];
    let mut digests = [[0u8; 64]; HASH_BATCH];
    for (batch, chunk) in indices.chunks(HASH_BATCH).enumerate() {
        let blocks = &mut blocks[..chunk.len()];
        let digests = &mut digests[..chunk.len()];
        for (block, index) in blocks.iter_mut().zip(chunk) {
            *block = index / per_hash;
        }
        hash(blocks, digests);
        for (offset, (index, digest)) in chunk.iter().zip(digests.iter()).enumerate() {
            let leaf = batch * HASH_BATCH + offset;
            let start = (index % per_hash) as usize * leaf_bytes;
            expand_array_into(
                &digest[start..start + leaf_bytes],
                p.collision_bit_length(),
                0,
                &mut row,
            );

            // Each set low bit of `leaf` marks a pending left sibling.
            let mut height = 0;
            while (leaf >> height) & 1 == 1 {
                let len = row_len - height * collision_bytes;
                let left = &pending[height * row_len..][..len];
                let right_start = leaf + 1 - (1 << height);
                let left_start = right_start - (1 << height);
                let left_indices = &indices[left_start..right_start];
                let right_indices = &indices[right_start..=leaf];

                if left[..collision_bytes] != row[..collision_bytes] {
                    return Err(Kind::Collision);
                }
                if right_indices[0] < left_indices[0] {
                    return Err(Kind::OutOfOrder);
                }
                if !all_distinct && left_indices.iter().any(|i| right_indices.contains(i)) {
                    return Err(Kind::DuplicateIdxs);
                }

                // On success the merged subtree's indices are `left || right`,
                // which is their order in `indices`.
                for (i, left) in left[collision_bytes..].iter().enumerate() {
                    row[i] = left ^ row[collision_bytes + i];
                }
                height += 1;
            }
            let len = row_len - height * collision_bytes;
            pending[height * row_len..][..len].copy_from_slice(&row[..len]);
        }
    }

    // Hashes were trimmed, so the root holds one collision's worth of bytes.
    let root = &pending[p.k as usize * row_len..][..collision_bytes];
    if root.iter().all(|b| *b == 0) {
        Ok(())
    } else {
        Err(Kind::NonZeroRootHash)
    }
}
