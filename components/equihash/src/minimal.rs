use std::io::Cursor;
use std::mem::size_of;

use byteorder::{BigEndian, ReadBytesExt};

use crate::params::Params;

// Rough translation of CompressArray() from:
// https://github.com/zcash/zcash/blob/6fdd9f1b81d3b228326c9826fa10696fc516444b/src/crypto/equihash.cpp#L39-L76
#[cfg(any(feature = "solver", test))]
fn compress_array(array: &[u8], bit_len: usize, byte_pad: usize) -> Vec<u8> {
    let index_bytes = (u32::BITS / 8) as usize;
    assert!(bit_len >= 8);
    assert!(8 * index_bytes >= 7 + bit_len);

    let in_width: usize = (bit_len + 7) / 8 + byte_pad;
    let out_len = bit_len * array.len() / (8 * in_width);

    let mut out = Vec::with_capacity(out_len);
    let bit_len_mask: u32 = (1 << (bit_len as u32)) - 1;

    // The acc_bits least-significant bits of acc_value represent a bit sequence
    // in big-endian order.
    let mut acc_bits: usize = 0;
    let mut acc_value: u32 = 0;

    let mut j: usize = 0;
    for _i in 0..out_len {
        // When we have fewer than 8 bits left in the accumulator, read the next
        // input element.
        if acc_bits < 8 {
            acc_value <<= bit_len;
            for x in byte_pad..in_width {
                acc_value |= (
                    // Apply bit_len_mask across byte boundaries
                    (array[j + x] & ((bit_len_mask >> (8 * (in_width - x - 1))) as u8)) as u32
                )
                    .wrapping_shl(8 * (in_width - x - 1) as u32); // Big-endian
            }
            j += in_width;
            acc_bits += bit_len;
        }

        acc_bits -= 8;
        out.push((acc_value >> acc_bits) as u8);
    }

    out
}

pub(crate) fn expand_array(vin: &[u8], bit_len: usize, byte_pad: usize) -> Vec<u8> {
    assert!(bit_len >= 8);
    assert!(u32::BITS as usize >= 7 + bit_len);

    let out_width = (bit_len + 7) / 8 + byte_pad;
    let out_len = 8 * out_width * vin.len() / bit_len;

    // Shortcut for parameters where expansion is a no-op
    if out_len == vin.len() {
        return vin.to_vec();
    }

    let mut vout: Vec<u8> = vec![0; out_len];
    let bit_len_mask: u32 = (1 << bit_len) - 1;

    // The acc_bits least-significant bits of acc_value represent a bit sequence
    // in big-endian order.
    let mut acc_bits = 0;
    let mut acc_value: u32 = 0;

    let mut j = 0;
    for b in vin {
        acc_value = (acc_value << 8) | u32::from(*b);
        acc_bits += 8;

        // When we have bit_len or more bits in the accumulator, write the next
        // output element.
        if acc_bits >= bit_len {
            acc_bits -= bit_len;
            for x in byte_pad..out_width {
                vout[j + x] = ((
                    // Big-endian
                    acc_value >> (acc_bits + (8 * (out_width - x - 1)))
                ) & (
                    // Apply bit_len_mask across byte boundaries
                    (bit_len_mask >> (8 * (out_width - x - 1))) & 0xFF
                )) as u8;
            }
            j += out_width;
        }
    }

    vout
}

// Rough translation of GetMinimalFromIndices() from:
// https://github.com/zcash/zcash/blob/6fdd9f1b81d3b228326c9826fa10696fc516444b/src/crypto/equihash.cpp#L130-L145
#[cfg(any(feature = "solver", test))]
pub(crate) fn minimal_from_indices(p: Params, indices: &[u32]) -> Vec<u8> {
    let c_bit_len = p.collision_bit_length();
    let index_bytes = (u32::BITS / 8) as usize;
    let digit_bytes = ((c_bit_len + 1) + 7) / 8;
    assert!(digit_bytes <= index_bytes);

    let len_indices = indices.len() * index_bytes;
    let byte_pad = index_bytes - digit_bytes;

    // Rough translation of EhIndexToArray(index, array_pointer) from:
    // https://github.com/zcash/zcash/blob/6fdd9f1b81d3b228326c9826fa10696fc516444b/src/crypto/equihash.cpp#L123-L128
    //
    // Big-endian so that lexicographic array comparison is equivalent to integer comparison.
    let array: Vec<u8> = indices
        .iter()
        .flat_map(|index| index.to_be_bytes())
        .collect();
    assert_eq!(array.len(), len_indices);

    compress_array(&array, c_bit_len + 1, byte_pad)
}

/// Returns `None` if the parameters are invalid for this minimal encoding.
pub(crate) fn indices_from_minimal(p: Params, minimal: &[u8]) -> Option<Vec<u32>> {
    let c_bit_len = p.collision_bit_length();
    // Division is exact because k >= 3.
    if minimal.len() != ((1 << p.k) * (c_bit_len + 1)) / 8 {
        return None;
    }

    assert!(((c_bit_len + 1) + 7) / 8 <= size_of::<u32>());
    let len_indices = u32::BITS as usize * minimal.len() / (c_bit_len + 1);
    let byte_pad = size_of::<u32>() - ((c_bit_len + 1) + 7) / 8;

    let mut csr = Cursor::new(expand_array(minimal, c_bit_len + 1, byte_pad));
    let mut ret = Vec::with_capacity(len_indices);

    // Big-endian so that lexicographic array comparison is equivalent to integer
    // comparison
    while let Ok(i) = csr.read_u32::<BigEndian>() {
        ret.push(i);
    }

    Some(ret)
}

#[cfg(test)]
mod tests {
    use crate::minimal::minimal_from_indices;

    use super::{compress_array, expand_array, indices_from_minimal, Params};

    #[test]
    fn array_compression_and_expansion() {
        let check_array = |(bit_len, byte_pad), compact, expanded| {
            assert_eq!(compress_array(expanded, bit_len, byte_pad), compact);
            assert_eq!(expand_array(compact, bit_len, byte_pad), expanded);
        };

        // 8 11-bit chunks, all-ones
        check_array(
            (11, 0),
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            &[
                0x07, 0xff, 0x07, 0xff, 0x07, 0xff, 0x07, 0xff, 0x07, 0xff, 0x07, 0xff, 0x07, 0xff,
                0x07, 0xff,
            ][..],
        );
        // 8 21-bit chunks, alternating 1s and 0s
        check_array(
            (21, 0),
            &[
                0xaa, 0xaa, 0xad, 0x55, 0x55, 0x6a, 0xaa, 0xab, 0x55, 0x55, 0x5a, 0xaa, 0xaa, 0xd5,
                0x55, 0x56, 0xaa, 0xaa, 0xb5, 0x55, 0x55,
            ],
            &[
                0x15, 0x55, 0x55, 0x15, 0x55, 0x55, 0x15, 0x55, 0x55, 0x15, 0x55, 0x55, 0x15, 0x55,
                0x55, 0x15, 0x55, 0x55, 0x15, 0x55, 0x55, 0x15, 0x55, 0x55,
            ][..],
        );
        // 8 21-bit chunks, based on example in the spec
        check_array(
            (21, 0),
            &[
                0x00, 0x02, 0x20, 0x00, 0x0a, 0x7f, 0xff, 0xfe, 0x00, 0x12, 0x30, 0x22, 0xb3, 0x82,
                0x26, 0xac, 0x19, 0xbd, 0xf2, 0x34, 0x56,
            ],
            &[
                0x00, 0x00, 0x44, 0x00, 0x00, 0x29, 0x1f, 0xff, 0xff, 0x00, 0x01, 0x23, 0x00, 0x45,
                0x67, 0x00, 0x89, 0xab, 0x00, 0xcd, 0xef, 0x12, 0x34, 0x56,
            ][..],
        );
        // 16 14-bit chunks, alternating 11s and 00s
        check_array(
            (14, 0),
            &[
                0xcc, 0xcf, 0x33, 0x3c, 0xcc, 0xf3, 0x33, 0xcc, 0xcf, 0x33, 0x3c, 0xcc, 0xf3, 0x33,
                0xcc, 0xcf, 0x33, 0x3c, 0xcc, 0xf3, 0x33, 0xcc, 0xcf, 0x33, 0x3c, 0xcc, 0xf3, 0x33,
            ],
            &[
                0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                0x33, 0x33, 0x33, 0x33,
            ][..],
        );
        // 8 11-bit chunks, all-ones, 2-byte padding
        check_array(
            (11, 2),
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            &[
                0x00, 0x00, 0x07, 0xff, 0x00, 0x00, 0x07, 0xff, 0x00, 0x00, 0x07, 0xff, 0x00, 0x00,
                0x07, 0xff, 0x00, 0x00, 0x07, 0xff, 0x00, 0x00, 0x07, 0xff, 0x00, 0x00, 0x07, 0xff,
                0x00, 0x00, 0x07, 0xff,
            ][..],
        );
    }

    #[test]
    fn minimal_solution_repr() {
        let check_repr = |minimal, indices| {
            let p = Params { n: 80, k: 3 };
            assert_eq!(minimal_from_indices(p, indices), minimal);
            assert_eq!(indices_from_minimal(p, minimal).unwrap(), indices);
        };

        // The solutions here are not intended to be valid.
        check_repr(
            &[
                0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x00, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00, 0x80,
                0x00, 0x04, 0x00, 0x00, 0x20, 0x00, 0x01,
            ],
            &[1, 1, 1, 1, 1, 1, 1, 1],
        );
        check_repr(
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
            &[
                2097151, 2097151, 2097151, 2097151, 2097151, 2097151, 2097151, 2097151,
            ],
        );
        check_repr(
            &[
                0x0f, 0xff, 0xf8, 0x00, 0x20, 0x03, 0xff, 0xfe, 0x00, 0x08, 0x00, 0xff, 0xff, 0x80,
                0x02, 0x00, 0x3f, 0xff, 0xe0, 0x00, 0x80,
            ],
            &[131071, 128, 131071, 128, 131071, 128, 131071, 128],
        );
        check_repr(
            &[
                0x00, 0x02, 0x20, 0x00, 0x0a, 0x7f, 0xff, 0xfe, 0x00, 0x4d, 0x10, 0x01, 0x4c, 0x80,
                0x0f, 0xfc, 0x00, 0x00, 0x2f, 0xff, 0xff,
            ],
            &[68, 41, 2097151, 1233, 665, 1023, 1, 1048575],
        );
    }
}
