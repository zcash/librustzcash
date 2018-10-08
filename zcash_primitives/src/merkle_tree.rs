use ff::PrimeField;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use sapling_crypto::primitives::Note;
use std::collections::VecDeque;

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

struct PathFiller {
    queue: VecDeque<Node>,
}

impl PathFiller {
    fn empty() -> Self {
        PathFiller {
            queue: VecDeque::new(),
        }
    }

    fn next(&mut self, depth: usize) -> Node {
        self.queue.pop_front().unwrap_or_else(|| EMPTY_ROOTS[depth])
    }
}

/// A Merkle tree of Sapling note commitments.
pub struct CommitmentTree {
    left: Option<Node>,
    right: Option<Node>,
    parents: Vec<Option<Node>>,
}

impl CommitmentTree {
    /// Creates an empty tree.
    pub fn new() -> Self {
        CommitmentTree {
            left: None,
            right: None,
            parents: vec![],
        }
    }

    /// Returns the number of notes in the tree.
    pub fn size(&self) -> usize {
        self.parents.iter().enumerate().fold(
            match (self.left.is_some(), self.right.is_some()) {
                (false, false) => 0,
                (true, false) | (false, true) => 1,
                (true, true) => 2,
            },
            |acc, (i, p)| {
                // Treat occupation of parents array as a binary number
                // (right-shifted by 1)
                acc + if p.is_some() { 1 << (i + 1) } else { 0 }
            },
        )
    }

    fn is_complete(&self, depth: usize) -> bool {
        self.left.is_some()
            && self.right.is_some()
            && self.parents.len() == depth - 1
            && self.parents.iter().fold(true, |acc, p| acc && p.is_some())
    }

    /// Adds a note to the tree. Returns an error if the tree is full.
    pub fn append(&mut self, node: Node) -> Result<(), ()> {
        self.append_inner(node, SAPLING_COMMITMENT_TREE_DEPTH)
    }

    fn append_inner(&mut self, node: Node, depth: usize) -> Result<(), ()> {
        if self.is_complete(depth) {
            // Tree is full
            return Err(());
        }

        match (self.left, self.right) {
            (None, _) => self.left = Some(node),
            (_, None) => self.right = Some(node),
            (Some(l), Some(r)) => {
                let mut combined = Node::combine(0, &l, &r);
                self.left = Some(node);
                self.right = None;

                for i in 0..depth {
                    if i < self.parents.len() {
                        if let Some(p) = self.parents[i] {
                            combined = Node::combine(i + 1, &p, &combined);
                            self.parents[i] = None;
                        } else {
                            self.parents[i] = Some(combined);
                            break;
                        }
                    } else {
                        self.parents.push(Some(combined));
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Returns the current root of the tree.
    pub fn root(&self) -> Node {
        self.root_inner(SAPLING_COMMITMENT_TREE_DEPTH, PathFiller::empty())
    }

    fn root_inner(&self, depth: usize, mut filler: PathFiller) -> Node {
        assert!(depth > 0);

        // 1) Hash left and right leaves together.
        //    - Empty leaves are used as needed.
        let leaf_root = Node::combine(
            0,
            &match self.left {
                Some(node) => node,
                None => filler.next(0),
            },
            &match self.right {
                Some(node) => node,
                None => filler.next(0),
            },
        );

        // 2) Hash in parents up to the currently-filled depth.
        //    - Roots of the empty subtrees are used as needed.
        let mid_root = self
            .parents
            .iter()
            .enumerate()
            .fold(leaf_root, |root, (i, p)| match p {
                Some(node) => Node::combine(i + 1, node, &root),
                None => Node::combine(i + 1, &root, &filler.next(i + 1)),
            });

        // 3) Hash in roots of the empty subtrees up to the final depth.
        ((self.parents.len() + 1)..depth)
            .fold(mid_root, |root, d| Node::combine(d, &root, &filler.next(d)))
    }
}

#[cfg(test)]
mod tests {
    use super::{CommitmentTree, Hashable, Node, PathFiller, EMPTY_ROOTS};

    use ff::PrimeFieldRepr;
    use hex;
    use pairing::bls12_381::FrRepr;

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

    const TESTING_DEPTH: usize = 4;

    struct TestCommitmentTree(CommitmentTree);

    impl TestCommitmentTree {
        fn new() -> Self {
            TestCommitmentTree(CommitmentTree::new())
        }

        fn size(&self) -> usize {
            self.0.size()
        }

        fn append(&mut self, node: Node) -> Result<(), ()> {
            self.0.append_inner(node, TESTING_DEPTH)
        }

        fn root(&self) -> Node {
            self.0.root_inner(TESTING_DEPTH, PathFiller::empty())
        }
    }

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

    #[test]
    fn sapling_empty_root() {
        let mut tmp = [0u8; 32];
        CommitmentTree::new()
            .root()
            .repr
            .write_le(&mut tmp[..])
            .expect("length is 32 bytes");
        assert_eq!(
            hex::encode(tmp),
            "fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e"
        );
    }

    #[test]
    fn empty_commitment_tree_roots() {
        let tree = CommitmentTree::new();
        let mut tmp = [0u8; 32];
        for i in 1..HEX_EMPTY_ROOTS.len() {
            tree.root_inner(i, PathFiller::empty())
                .repr
                .write_le(&mut tmp[..])
                .expect("length is 32 bytes");
            assert_eq!(hex::encode(tmp), HEX_EMPTY_ROOTS[i]);
        }
    }

    #[test]
    fn test_sapling_tree() {
        // From https://github.com/zcash/zcash/blob/master/src/test/data/merkle_commitments_sapling.json
        // Byte-reversed because the original test vectors are loaded using uint256S()
        let commitments = [
            "b02310f2e087e55bfd07ef5e242e3b87ee5d00c9ab52f61e6bd42542f93a6f55",
            "225747f3b5d5dab4e5a424f81f85c904ff43286e0f3fd07ef0b8c6a627b11458",
            "7c3ea01a6e3a3d90cf59cd789e467044b5cd78eb2c84cc6816f960746d0e036c",
            "50421d6c2c94571dfaaa135a4ff15bf916681ebd62c0e43e69e3b90684d0a030",
            "aaec63863aaa0b2e3b8009429bdddd455e59be6f40ccab887a32eb98723efc12",
            "f76748d40d5ee5f9a608512e7954dd515f86e8f6d009141c89163de1cf351a02",
            "bc8a5ec71647415c380203b681f7717366f3501661512225b6dc3e121efc0b2e",
            "da1adda2ccde9381e11151686c121e7f52d19a990439161c7eb5a9f94be5a511",
            "3a27fed5dbbc475d3880360e38638c882fd9b273b618fc433106896083f77446",
            "c7ca8f7df8fd997931d33985d935ee2d696856cc09cc516d419ea6365f163008",
            "f0fa37e8063b139d342246142fc48e7c0c50d0a62c97768589e06466742c3702",
            "e6d4d7685894d01b32f7e081ab188930be6c2b9f76d6847b7f382e3dddd7c608",
            "8cebb73be883466d18d3b0c06990520e80b936440a2c9fd184d92a1f06c4e826",
            "22fab8bcdb88154dbf5877ad1e2d7f1b541bc8a5ec1b52266095381339c27c03",
            "f43e3aac61e5a753062d4d0508c26ceaf5e4c0c58ba3c956e104b5d2cf67c41c",
            "3a3661bc12b72646c94bc6c92796e81953985ee62d80a9ec3645a9a95740ac15",
        ];

        // From https://github.com/zcash/zcash/blob/master/src/test/data/merkle_roots_sapling.json
        let roots = [
            "8c3daa300c9710bf24d2595536e7c80ff8d147faca726636d28e8683a0c27703",
            "8611f17378eb55e8c3c3f0a5f002e2b0a7ca39442fc928322b8072d1079c213d",
            "3db73b998d536be0e1c2ec124df8e0f383ae7b602968ff6a5276ca0695023c46",
            "7ac2e6442fec5970e116dfa4f2ee606f395366cafb1fa7dfd6c3de3ce18c4363",
            "6a8f11ab2a11c262e39ed4ea3825ae6c94739ccf94479cb69402c5722b034532",
            "149595eed0b54a7e694cc8a68372525b9ae2c7b102514f527460db91eb690565",
            "8c0432f1994a2381a7a4b5fda770336011f9e0b30784f9a5597901619c797045",
            "e780c48d70420601f3313ff8488d7766b70c059c53aa3cda2ff1ef57ff62383c",
            "f919f03caaed8a2c60f58c0d43838f83e670dc7e8ccd25daa04a13f3e8f45541",
            "74f32b36629724038e71cbd6823b5a666440205a7d1a9242e95870b53d81f34a",
            "a4af205a4e1ee02102866b23a68930ac33efda9235832f49b17fcc4939be4525",
            "a946a42f1636045a16e65b2308e036d9da70089686c87c692e45912bd1cab772",
            "a1db2dbac055364c1cb43cbeb49c7e2815bff855122602a2ad0fb981a91e0e39",
            "16329b3ba4f0640f4d306532d9ea6ba0fbf0e70e44ed57d27b4277ed9cda6849",
            "7b6523b2d9b23f72fec6234aa6a1f8fae3dba1c6a266023ea8b1826feba7a25c",
            "5c0bea7e17bde5bee4eb795c2eec3d389a68da587b36dd687b134826ecc09308",
        ];

        fn assert_root_eq(root: Node, expected: &str) {
            let mut tmp = [0u8; 32];
            root.repr
                .write_le(&mut tmp[..])
                .expect("length is 32 bytes");
            assert_eq!(hex::encode(tmp), expected);
        }

        let mut tree = TestCommitmentTree::new();
        assert_eq!(tree.size(), 0);

        for i in 0..16 {
            let mut cm = FrRepr::default();
            cm.read_le(&hex::decode(commitments[i]).unwrap()[..])
                .expect("length is 32 bytes");

            let cm = Node::new(cm);

            // Append a commitment to the tree
            assert!(tree.append(cm).is_ok());

            // Size incremented by one.
            assert_eq!(tree.size(), i + 1);

            // Check tree root consistency
            assert_root_eq(tree.root(), roots[i]);
        }

        // Tree should be full now
        let node = Node::blank();
        assert!(tree.append(node).is_err());
    }
}
