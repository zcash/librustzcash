use ff::PrimeField;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use sapling_crypto::primitives::Note;

use sapling::merkle_hash;

const SAPLING_COMMITMENT_TREE_DEPTH: usize = 32;

trait Hashable: Clone + Copy {
    /// Returns the parent node within the tree of the two given nodes.
    fn combine(usize, &Self, &Self) -> Self;

    /// Returns a blank leaf node.
    fn blank() -> Self;
}

#[derive(Clone, Copy)]
pub struct Node {
    repr: FrRepr,
}

impl Node {
    pub fn new(repr: FrRepr) -> Self {
        Node { repr }
    }
}

impl Hashable for Node {
    fn combine(depth: usize, lhs: &Self, rhs: &Self) -> Self {
        Node {
            repr: merkle_hash(depth, &lhs.repr, &rhs.repr),
        }
    }

    fn blank() -> Self {
        Node {
            repr: Note::<Bls12>::uncommitted().into_repr(),
        }
    }
}

impl From<Node> for Fr {
    fn from(node: Node) -> Self {
        Fr::from_repr(node.repr).expect("Tree nodes should be in the prime field")
    }
}

lazy_static! {
    static ref EMPTY_ROOTS: Vec<Node> = {
        let mut v = vec![Node::blank()];
        for d in 0..SAPLING_COMMITMENT_TREE_DEPTH {
            let next = Node::combine(d, &v[d], &v[d]);
            v.push(next);
        }
        v
    };
}

#[cfg(test)]
mod tests {
    use super::EMPTY_ROOTS;

    use ff::PrimeFieldRepr;
    use hex;

    const HEX_EMPTY_ROOTS: [&str; 33] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "817de36ab2d57feb077634bca77819c8e0bd298c04f6fed0e6a83cc1356ca155",
        "ffe9fc03f18b176c998806439ff0bb8ad193afdb27b2ccbc88856916dd804e34",
        "d8283386ef2ef07ebdbb4383c12a739a953a4d6e0d6fb1139a4036d693bfbb6c",
        "e110de65c907b9dea4ae0bd83a4b0a51bea175646a64c12b4c9f931b2cb31b49",
        "912d82b2c2bca231f71efcf61737fbf0a08befa0416215aeef53e8bb6d23390a",
        "8ac9cf9c391e3fd42891d27238a81a8a5c1d3a72b1bcbea8cf44a58ce7389613",
        "d6c639ac24b46bd19341c91b13fdcab31581ddaf7f1411336a271f3d0aa52813",
        "7b99abdc3730991cc9274727d7d82d28cb794edbc7034b4f0053ff7c4b680444",
        "43ff5457f13b926b61df552d4e402ee6dc1463f99a535f9a713439264d5b616b",
        "ba49b659fbd0b7334211ea6a9d9df185c757e70aa81da562fb912b84f49bce72",
        "4777c8776a3b1e69b73a62fa701fa4f7a6282d9aee2c7a6b82e7937d7081c23c",
        "ec677114c27206f5debc1c1ed66f95e2b1885da5b7be3d736b1de98579473048",
        "1b77dac4d24fb7258c3c528704c59430b630718bec486421837021cf75dab651",
        "bd74b25aacb92378a871bf27d225cfc26baca344a1ea35fdd94510f3d157082c",
        "d6acdedf95f608e09fa53fb43dcd0990475726c5131210c9e5caeab97f0e642f",
        "1ea6675f9551eeb9dfaaa9247bc9858270d3d3a4c5afa7177a984d5ed1be2451",
        "6edb16d01907b759977d7650dad7e3ec049af1a3d875380b697c862c9ec5d51c",
        "cd1c8dbf6e3acc7a80439bc4962cf25b9dce7c896f3a5bd70803fc5a0e33cf00",
        "6aca8448d8263e547d5ff2950e2ed3839e998d31cbc6ac9fd57bc6002b159216",
        "8d5fa43e5a10d11605ac7430ba1f5d81fb1b68d29a640405767749e841527673",
        "08eeab0c13abd6069e6310197bf80f9c1ea6de78fd19cbae24d4a520e6cf3023",
        "0769557bc682b1bf308646fd0b22e648e8b9e98f57e29f5af40f6edb833e2c49",
        "4c6937d78f42685f84b43ad3b7b00f81285662f85c6a68ef11d62ad1a3ee0850",
        "fee0e52802cb0c46b1eb4d376c62697f4759f6c8917fa352571202fd778fd712",
        "16d6252968971a83da8521d65382e61f0176646d771c91528e3276ee45383e4a",
        "d2e1642c9a462229289e5b0e3b7f9008e0301cbb93385ee0e21da2545073cb58",
        "a5122c08ff9c161d9ca6fc462073396c7d7d38e8ee48cdb3bea7e2230134ed6a",
        "28e7b841dcbc47cceb69d7cb8d94245fb7cb2ba3a7a6bc18f13f945f7dbd6e2a",
        "e1f34b034d4a3cd28557e2907ebf990c918f64ecb50a94f01d6fda5ca5c7ef72",
        "12935f14b676509b81eb49ef25f39269ed72309238b4c145803544b646dca62d",
        "b2eed031d4d6a4f02a097f80b54cc1541d4163c6b6f5971f88b6e41d35c53814",
        "fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e",
    ];

    #[test]
    fn empty_root_test_vectors() {
        let mut tmp = [0u8; 32];
        for i in 0..HEX_EMPTY_ROOTS.len() {
            EMPTY_ROOTS[i]
                .repr
                .write_le(&mut tmp[..])
                .expect("length is 32 bytes");
            assert_eq!(hex::encode(tmp), HEX_EMPTY_ROOTS[i]);
        }
    }
}
