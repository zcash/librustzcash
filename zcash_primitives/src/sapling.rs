//! Structs and constants specific to the Sapling shielded pool.

pub mod group_hash;
pub mod keys;
pub mod note_encryption;
pub mod pedersen_hash;
pub mod prover;
pub mod redjubjub;
pub mod util;

use bitvec::{order::Lsb0, view::AsBits};
use blake2s_simd::Params as Blake2sParams;
use byteorder::{LittleEndian, WriteBytesExt};
use ff::{Field, PrimeField};
use group::{Curve, Group, GroupEncoding};
use incrementalmerkletree::{self, Altitude};
use lazy_static::lazy_static;
use rand_core::{CryptoRng, RngCore};
use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::io::{self, Read, Write};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    constants::{self, SPENDING_KEY_GENERATOR},
    keys::prf_expand,
    merkle_tree::{HashSer, Hashable},
    transaction::components::amount::MAX_MONEY,
};

use self::{
    group_hash::group_hash,
    pedersen_hash::{pedersen_hash, Personalization},
    redjubjub::{PrivateKey, PublicKey, Signature},
};

pub const SAPLING_COMMITMENT_TREE_DEPTH: usize = 32;
pub const SAPLING_COMMITMENT_TREE_DEPTH_U8: u8 = 32;

/// Compute a parent node in the Sapling commitment tree given its two children.
pub fn merkle_hash(depth: usize, lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let lhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(lhs.as_bits::<Lsb0>()) {
            *a = *b;
        }
        tmp
    };

    let rhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(rhs.as_bits::<Lsb0>()) {
            *a = *b;
        }
        tmp
    };

    jubjub::ExtendedPoint::from(pedersen_hash(
        Personalization::MerkleTree(depth),
        lhs.iter()
            .copied()
            .take(bls12_381::Scalar::NUM_BITS as usize)
            .chain(
                rhs.iter()
                    .copied()
                    .take(bls12_381::Scalar::NUM_BITS as usize),
            ),
    ))
    .to_affine()
    .get_u()
    .to_repr()
}

/// A node within the Sapling commitment tree.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Node {
    repr: [u8; 32],
}

impl Node {
    pub fn new(repr: [u8; 32]) -> Self {
        Node { repr }
    }
}

impl incrementalmerkletree::Hashable for Node {
    fn empty_leaf() -> Self {
        Node {
            repr: Note::uncommitted().to_repr(),
        }
    }

    fn combine(altitude: Altitude, lhs: &Self, rhs: &Self) -> Self {
        Node {
            repr: merkle_hash(altitude.into(), &lhs.repr, &rhs.repr),
        }
    }

    fn empty_root(altitude: Altitude) -> Self {
        EMPTY_ROOTS[<usize>::from(altitude)]
    }
}

impl HashSer for Node {
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr)?;
        Ok(Node::new(repr))
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.repr.as_ref())
    }
}

impl From<Node> for bls12_381::Scalar {
    fn from(node: Node) -> Self {
        // Tree nodes should be in the prime field.
        bls12_381::Scalar::from_repr(node.repr).unwrap()
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

/// Create the spendAuthSig for a Sapling SpendDescription.
pub fn spend_sig<R: RngCore + CryptoRng>(
    ask: PrivateKey,
    ar: jubjub::Fr,
    sighash: &[u8; 32],
    rng: &mut R,
) -> Signature {
    spend_sig_internal(ask, ar, sighash, rng)
}

pub(crate) fn spend_sig_internal<R: RngCore>(
    ask: PrivateKey,
    ar: jubjub::Fr,
    sighash: &[u8; 32],
    rng: &mut R,
) -> Signature {
    // We compute `rsk`...
    let rsk = ask.randomize(ar);

    // We compute `rk` from there (needed for key prefixing)
    let rk = PublicKey::from_private(&rsk, SPENDING_KEY_GENERATOR);

    // Compute the signature's message for rk/spend_auth_sig
    let mut data_to_be_signed = [0u8; 64];
    data_to_be_signed[0..32].copy_from_slice(&rk.0.to_bytes());
    (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash[..]);

    // Do the signing
    rsk.sign(&data_to_be_signed, rng, SPENDING_KEY_GENERATOR)
}

#[derive(Clone)]
pub struct ValueCommitment {
    pub value: u64,
    pub randomness: jubjub::Fr,
}

impl ValueCommitment {
    pub fn commitment(&self) -> jubjub::SubgroupPoint {
        (constants::VALUE_COMMITMENT_VALUE_GENERATOR * jubjub::Fr::from(self.value))
            + (constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR * self.randomness)
    }
}

#[derive(Clone)]
pub struct ProofGenerationKey {
    pub ak: jubjub::SubgroupPoint,
    pub nsk: jubjub::Fr,
}

impl ProofGenerationKey {
    pub fn to_viewing_key(&self) -> ViewingKey {
        ViewingKey {
            ak: self.ak,
            nk: constants::PROOF_GENERATION_KEY_GENERATOR * self.nsk,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ViewingKey {
    pub ak: jubjub::SubgroupPoint,
    pub nk: jubjub::SubgroupPoint,
}

impl ViewingKey {
    pub fn rk(&self, ar: jubjub::Fr) -> jubjub::SubgroupPoint {
        self.ak + constants::SPENDING_KEY_GENERATOR * ar
    }

    pub fn ivk(&self) -> SaplingIvk {
        let mut h = [0; 32];
        h.copy_from_slice(
            Blake2sParams::new()
                .hash_length(32)
                .personal(constants::CRH_IVK_PERSONALIZATION)
                .to_state()
                .update(&self.ak.to_bytes())
                .update(&self.nk.to_bytes())
                .finalize()
                .as_bytes(),
        );

        // Drop the most significant five bits, so it can be interpreted as a scalar.
        h[31] &= 0b0000_0111;

        SaplingIvk(jubjub::Fr::from_repr(h).unwrap())
    }

    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        self.ivk().to_payment_address(diversifier)
    }
}

#[derive(Debug, Clone)]
pub struct SaplingIvk(pub jubjub::Fr);

impl SaplingIvk {
    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        diversifier.g_d().and_then(|g_d| {
            let pk_d = g_d * self.0;

            PaymentAddress::from_parts(diversifier, pk_d)
        })
    }

    pub fn to_repr(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    pub fn g_d(&self) -> Option<jubjub::SubgroupPoint> {
        group_hash(&self.0, constants::KEY_DIVERSIFICATION_PERSONALIZATION)
    }
}

/// A Sapling payment address.
///
/// # Invariants
///
/// `pk_d` is guaranteed to be prime-order (i.e. in the prime-order subgroup of Jubjub,
/// and not the identity).
#[derive(Clone, Debug)]
pub struct PaymentAddress {
    pk_d: jubjub::SubgroupPoint,
    diversifier: Diversifier,
}

impl PartialEq for PaymentAddress {
    fn eq(&self, other: &Self) -> bool {
        self.pk_d == other.pk_d && self.diversifier == other.diversifier
    }
}

impl PaymentAddress {
    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Returns None if `pk_d` is the identity.
    pub fn from_parts(diversifier: Diversifier, pk_d: jubjub::SubgroupPoint) -> Option<Self> {
        if pk_d.is_identity().into() {
            None
        } else {
            Some(PaymentAddress { pk_d, diversifier })
        }
    }

    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Only for test code, as this explicitly bypasses the invariant.
    #[cfg(test)]
    pub(crate) fn from_parts_unchecked(
        diversifier: Diversifier,
        pk_d: jubjub::SubgroupPoint,
    ) -> Self {
        PaymentAddress { pk_d, diversifier }
    }

    /// Parses a PaymentAddress from bytes.
    pub fn from_bytes(bytes: &[u8; 43]) -> Option<Self> {
        let diversifier = {
            let mut tmp = [0; 11];
            tmp.copy_from_slice(&bytes[0..11]);
            Diversifier(tmp)
        };
        // Check that the diversifier is valid
        diversifier.g_d()?;

        let pk_d = jubjub::SubgroupPoint::from_bytes(bytes[11..43].try_into().unwrap());
        if pk_d.is_some().into() {
            PaymentAddress::from_parts(diversifier, pk_d.unwrap())
        } else {
            None
        }
    }

    /// Returns the byte encoding of this `PaymentAddress`.
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes = [0; 43];
        bytes[0..11].copy_from_slice(&self.diversifier.0);
        bytes[11..].copy_from_slice(&self.pk_d.to_bytes());
        bytes
    }

    /// Returns the [`Diversifier`] for this `PaymentAddress`.
    pub fn diversifier(&self) -> &Diversifier {
        &self.diversifier
    }

    /// Returns `pk_d` for this `PaymentAddress`.
    pub fn pk_d(&self) -> &jubjub::SubgroupPoint {
        &self.pk_d
    }

    pub fn g_d(&self) -> Option<jubjub::SubgroupPoint> {
        self.diversifier.g_d()
    }

    pub fn create_note(&self, value: u64, rseed: Rseed) -> Option<Note> {
        self.g_d().map(|g_d| Note {
            value,
            rseed,
            g_d,
            pk_d: self.pk_d,
        })
    }
}

/// Enum for note randomness before and after [ZIP 212](https://zips.z.cash/zip-0212).
///
/// Before ZIP 212, the note commitment trapdoor `rcm` must be a scalar value.
/// After ZIP 212, the note randomness `rseed` is a 32-byte sequence, used to derive
/// both the note commitment trapdoor `rcm` and the ephemeral private key `esk`.
#[derive(Copy, Clone, Debug)]
pub enum Rseed {
    BeforeZip212(jubjub::Fr),
    AfterZip212([u8; 32]),
}

/// Typesafe wrapper for nullifier values.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    pub fn from_slice(bytes: &[u8]) -> Result<Nullifier, TryFromSliceError> {
        bytes.try_into().map(Nullifier)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}
impl AsRef<[u8]> for Nullifier {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ConstantTimeEq for Nullifier {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NoteValue(u64);

impl TryFrom<u64> for NoteValue {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value <= MAX_MONEY as u64 {
            Ok(NoteValue(value))
        } else {
            Err(())
        }
    }
}

impl From<NoteValue> for u64 {
    fn from(value: NoteValue) -> u64 {
        value.0
    }
}

#[derive(Clone, Debug)]
pub struct Note {
    /// The value of the note
    pub value: u64,
    /// The diversified base of the address, GH(d)
    pub g_d: jubjub::SubgroupPoint,
    /// The public key of the address, g_d^ivk
    pub pk_d: jubjub::SubgroupPoint,
    /// rseed
    pub rseed: Rseed,
}

impl PartialEq for Note {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
            && self.g_d == other.g_d
            && self.pk_d == other.pk_d
            && self.rcm() == other.rcm()
    }
}

impl Note {
    pub fn uncommitted() -> bls12_381::Scalar {
        // The smallest u-coordinate that is not on the curve
        // is one.
        bls12_381::Scalar::one()
    }

    /// Computes the note commitment, returning the full point.
    fn cm_full_point(&self) -> jubjub::SubgroupPoint {
        // Calculate the note contents, as bytes
        let mut note_contents = vec![];

        // Writing the value in little endian
        (&mut note_contents)
            .write_u64::<LittleEndian>(self.value)
            .unwrap();

        // Write g_d
        note_contents.extend_from_slice(&self.g_d.to_bytes());

        // Write pk_d
        note_contents.extend_from_slice(&self.pk_d.to_bytes());

        assert_eq!(note_contents.len(), 32 + 32 + 8);

        // Compute the Pedersen hash of the note contents
        let hash_of_contents = pedersen_hash(
            Personalization::NoteCommitment,
            note_contents
                .into_iter()
                .flat_map(|byte| (0..8).map(move |i| ((byte >> i) & 1) == 1)),
        );

        // Compute final commitment
        (constants::NOTE_COMMITMENT_RANDOMNESS_GENERATOR * self.rcm()) + hash_of_contents
    }

    /// Computes the nullifier given the viewing key and
    /// note position
    pub fn nf(&self, viewing_key: &ViewingKey, position: u64) -> Nullifier {
        // Compute rho = cm + position.G
        let rho = self.cm_full_point()
            + (constants::NULLIFIER_POSITION_GENERATOR * jubjub::Fr::from(position));

        // Compute nf = BLAKE2s(nk | rho)
        Nullifier::from_slice(
            Blake2sParams::new()
                .hash_length(32)
                .personal(constants::PRF_NF_PERSONALIZATION)
                .to_state()
                .update(&viewing_key.nk.to_bytes())
                .update(&rho.to_bytes())
                .finalize()
                .as_bytes(),
        )
        .unwrap()
    }

    /// Computes the note commitment
    pub fn cmu(&self) -> bls12_381::Scalar {
        // The commitment is in the prime order subgroup, so mapping the
        // commitment to the u-coordinate is an injective encoding.
        jubjub::ExtendedPoint::from(self.cm_full_point())
            .to_affine()
            .get_u()
    }

    pub fn rcm(&self) -> jubjub::Fr {
        match self.rseed {
            Rseed::BeforeZip212(rcm) => rcm,
            Rseed::AfterZip212(rseed) => {
                jubjub::Fr::from_bytes_wide(prf_expand(&rseed, &[0x04]).as_array())
            }
        }
    }

    pub fn generate_or_derive_esk<R: RngCore + CryptoRng>(&self, rng: &mut R) -> jubjub::Fr {
        self.generate_or_derive_esk_internal(rng)
    }

    pub(crate) fn generate_or_derive_esk_internal<R: RngCore>(&self, rng: &mut R) -> jubjub::Fr {
        match self.derive_esk() {
            None => jubjub::Fr::random(rng),
            Some(esk) => esk,
        }
    }

    /// Returns the derived `esk` if this note was created after ZIP 212 activated.
    pub fn derive_esk(&self) -> Option<jubjub::Fr> {
        match self.rseed {
            Rseed::BeforeZip212(_) => None,
            Rseed::AfterZip212(rseed) => Some(jubjub::Fr::from_bytes_wide(
                prf_expand(&rseed, &[0x05]).as_array(),
            )),
        }
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;
    use std::cmp::min;
    use std::convert::TryFrom;

    use crate::{
        transaction::components::amount::MAX_MONEY, zip32::testing::arb_extended_spending_key,
    };

    use super::{Node, Note, NoteValue, PaymentAddress, Rseed};

    prop_compose! {
        pub fn arb_note_value()(value in 0u64..=MAX_MONEY as u64) -> NoteValue {
            NoteValue::try_from(value).unwrap()
        }
    }

    prop_compose! {
        /// The
        pub fn arb_positive_note_value(bound: u64)(
            value in 1u64..=(min(bound, MAX_MONEY as u64))
        ) -> NoteValue {
            NoteValue::try_from(value).unwrap()
        }
    }

    pub fn arb_payment_address() -> impl Strategy<Value = PaymentAddress> {
        arb_extended_spending_key().prop_map(|sk| sk.default_address().1)
    }

    prop_compose! {
        pub fn arb_node()(value in prop::array::uniform32(prop::num::u8::ANY)) -> Node {
            Node::new(value)
        }
    }

    prop_compose! {
        pub fn arb_note(value: NoteValue)(
            addr in arb_payment_address(),
            rseed in prop::array::uniform32(prop::num::u8::ANY).prop_map(Rseed::AfterZip212)
        ) -> Note {
            Note {
                value: value.into(),
                g_d: addr.g_d().unwrap(), // this unwrap is safe because arb_payment_address always generates an address with a valid g_d
                pk_d: *addr.pk_d(),
                rseed
            }
        }
    }
}
