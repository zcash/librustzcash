//! [ZIP 304] protocol for signing arbitrary messages with Sapling payment addresses.
//!
//! [ZIP 304]: https://zips.z.cash/zip-0304

use std::{convert::TryInto, error, fmt, str::FromStr};

use base64::prelude::{Engine, BASE64_STANDARD};
use bellman::{
    gadgets::multipack,
    groth16::{verify_proof, Proof},
};
use group::{ff::Field, Curve};
use rand_core::OsRng;

use super::{
    bundle::GrothProofBytes,
    circuit::PreparedSpendVerifyingKey,
    constants::SPENDING_KEY_GENERATOR,
    keys::ExpandedSpendingKey,
    prover::SpendProver,
    redjubjub::{self, PrivateKey, PublicKey},
    spend_sig,
    tree::{CommitmentTree, IncrementalWitness},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    verify_spend_sig_internal, Node, Note, Nullifier, PaymentAddress, Rseed,
};

const ZIP304_PERSONALIZATION_PREFIX: &'static [u8; 12] = b"ZIP304Signed";

fn message_digest(coin_type: u32, zkproof: &GrothProofBytes, message: &[u8]) -> [u8; 32] {
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZIP304_PERSONALIZATION_PREFIX);
    personal[12..].copy_from_slice(&coin_type.to_le_bytes());
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(&personal)
        .to_state()
        .update(zkproof)
        .update(message)
        .finalize()
        .as_bytes()
        .try_into()
        .unwrap()
}

/// A ZIP 304 signature over an arbitrary message, created with the spending key of a
/// Sapling payment address.
///
/// A normal (and desired) property of signatures is that all signatures for a specific
/// public key are linkable if the public key is known. ZIP 304 signatures have the
/// additional property that all signatures for a specific payment address are linkable
/// without knowing the payment address, as the first 32 bytes of each signature will be
/// identical.
///
/// A signature is bound to a specific diversified address of the spending key. Signatures
/// for different diversified addresses of the same spending key are unlinkable.
pub struct Signature {
    nullifier: Nullifier,
    rk: redjubjub::PublicKey,
    zkproof: GrothProofBytes,
    spend_auth_sig: redjubjub::Signature,
}

impl Signature {
    pub fn from_bytes(bytes: &[u8; 320]) -> Option<Self> {
        let nullifier = Nullifier(bytes[0..32].try_into().unwrap());

        let rk = match PublicKey::read(&bytes[32..64]) {
            Ok(p) => p,
            Err(_) => return None,
        };
        if rk.0.is_small_order().into() {
            return None;
        }

        let mut zkproof = [0; 192];
        zkproof.copy_from_slice(&bytes[64..256]);

        let spend_auth_sig = match redjubjub::Signature::read(&bytes[256..320]) {
            Ok(sig) => sig,
            Err(_) => return None,
        };

        Some(Signature {
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        })
    }

    pub fn to_bytes(&self) -> [u8; 320] {
        let mut bytes = [0; 320];
        bytes[0..32].copy_from_slice(&self.nullifier.0);
        self.rk.write(&mut bytes[32..64]).unwrap();
        bytes[64..256].copy_from_slice(&self.zkproof);
        self.spend_auth_sig.write(&mut bytes[256..320]).unwrap();
        bytes
    }
}

/// Errors that can occur when parsing a ZIP 304 signature from a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    Base64(base64::DecodeSliceError),
    InvalidLength,
    InvalidPrefix,
    InvalidSignatureData,
}

impl From<base64::DecodeSliceError> for ParseError {
    fn from(e: base64::DecodeSliceError) -> Self {
        ParseError::Base64(e)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Base64(e) => write!(f, "Invalid Base64: {}", e),
            ParseError::InvalidLength => {
                write!(
                    f,
                    "Signature length is invalid (should be 435 characters including prefix)"
                )
            }
            ParseError::InvalidPrefix => write!(f, "Invalid prefix (should be 'zip304:')"),
            ParseError::InvalidSignatureData => {
                write!(f, "Base64 payload does not encode a ZIP 304 signature")
            }
        }
    }
}

impl error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ParseError::Base64(e) => Some(e),
            _ => None,
        }
    }
}

impl FromStr for Signature {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_at(7) {
            ("zip304:", encoded) => {
                if encoded.len() == 428 {
                    // We need an extra byte to decode into.
                    let mut bytes = [0; 321];
                    BASE64_STANDARD.decode_slice(encoded, &mut bytes)?;
                    Signature::from_bytes(&bytes[..320].try_into().unwrap())
                        .ok_or(ParseError::InvalidSignatureData)
                } else {
                    Err(ParseError::InvalidLength)
                }
            }
            _ => Err(ParseError::InvalidPrefix),
        }
    }
}

impl ToString for Signature {
    fn to_string(&self) -> String {
        format!("zip304:{}", BASE64_STANDARD.encode(self.to_bytes()))
    }
}

/// Signs an arbitrary message for the given [`PaymentAddress`] and [`SLIP 44`] coin type.
///
/// The coin type is used here in its index form, not its hardened form (i.e. 133 for
/// mainnet Zcash).
///
/// [`SLIP 44`]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub fn sign_message<Pr: SpendProver>(
    expsk: &ExpandedSpendingKey,
    payment_address: PaymentAddress,
    coin_type: u32,
    message: &[u8],
    prover: &Pr,
) -> Signature {
    // Initialize secure RNG.
    let mut rng = OsRng;

    // Derive the necessary key components.
    let proof_generation_key = expsk.proof_generation_key();

    // We make a Sapling spend proof for a fake note with value of 1 zatoshi, setting rcm
    // and rcv to zero.
    let value = NoteValue::from_raw(1);
    let rcm = jubjub::Scalar::zero();
    let rcv = ValueCommitTrapdoor::zero();

    // Create the fake note.
    let note = Note::from_parts(payment_address, value, Rseed::BeforeZip212(rcm));

    // Create a fake tree containing the fake note, and witness it.
    let (anchor, witness) = {
        let mut tree = CommitmentTree::empty();
        tree.append(Node::from_cmu(&note.cmu())).unwrap();
        (
            tree.root(),
            IncrementalWitness::from_tree(tree).path().unwrap(),
        )
    };

    // Derive the nullifier for the fake note.
    let nullifier = {
        let vk = proof_generation_key.to_viewing_key();
        note.nf(&vk.nk, witness.position().into())
    };

    // Re-randomize the payment address.
    let alpha = jubjub::Scalar::random(&mut rng);
    let rk = PublicKey(proof_generation_key.ak.into()).randomize(alpha, SPENDING_KEY_GENERATOR);

    // We now have the full witness for our circuit!
    let instance = Pr::prepare_circuit(
        proof_generation_key,
        *payment_address.diversifier(),
        Rseed::BeforeZip212(rcm),
        value,
        alpha,
        rcv,
        anchor.into(),
        witness,
    )
    .expect("payment address is valid");

    // Create the proof.
    let zkproof = Pr::encode_proof(prover.create_proof(instance, &mut rng));

    // Compute the message digest to be signed.
    let digest = message_digest(coin_type, &zkproof, message);

    // Create the signature.
    let spend_auth_sig = spend_sig(PrivateKey(expsk.ask), alpha, &digest, &mut rng);

    Signature {
        nullifier,
        rk,
        zkproof,
        spend_auth_sig,
    }
}

/// Verifies a [`Signature`] on a message with the given [`PaymentAddress`]  and
/// [`SLIP 44`] coin type.
///
/// The coin type is used here in its index form, not its hardened form (i.e. 133 for
/// mainnet Zcash).
///
/// [`SLIP 44`]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub fn verify_message(
    payment_address: PaymentAddress,
    coin_type: u32,
    message: &[u8],
    signature: &Signature,
    verifying_key: &PreparedSpendVerifyingKey,
) -> Result<(), ()> {
    // Compute the message digest that was signed.
    let digest = message_digest(coin_type, &signature.zkproof, message);

    // Verify the spend_auth_sig.
    if !verify_spend_sig_internal(&signature.rk, &digest, &signature.spend_auth_sig) {
        return Err(());
    }

    // Parse the proof.
    let zkproof = Proof::read(&signature.zkproof[..]).map_err(|_| ())?;

    // We created the proof for a fake note with value of 1 zatoshi, setting rcm and rcv
    // to zero.
    let value = NoteValue::from_raw(1);
    let rcm = jubjub::Scalar::zero();
    let rcv = ValueCommitTrapdoor::zero();

    // Recreate the fake note.
    let note = Note::from_parts(payment_address, value, Rseed::BeforeZip212(rcm));

    // Recreate the fake tree containing the fake note.
    let anchor = {
        let mut tree = CommitmentTree::empty();
        tree.append(Node::from_cmu(&note.cmu())).unwrap();
        tree.root()
    };

    // Construct the value commitment.
    let cv = ValueCommitment::derive(value, rcv);

    // Construct public input for circuit.
    let mut public_input = [bls12_381::Scalar::zero(); 7];
    {
        let affine = signature.rk.0.to_affine();
        let (u, v) = (affine.get_u(), affine.get_v());
        public_input[0] = u;
        public_input[1] = v;
    }
    {
        let affine = cv.as_inner().to_affine();
        let (u, v) = (affine.get_u(), affine.get_v());
        public_input[2] = u;
        public_input[3] = v;
    }
    public_input[4] = anchor.into();

    // Add the nullifier through multiscalar packing.
    {
        let nullifier = multipack::bytes_to_bits_le(&signature.nullifier.0);
        let nullifier = multipack::compute_multipacking(&nullifier);

        assert_eq!(nullifier.len(), 2);

        public_input[5] = nullifier[0];
        public_input[6] = nullifier[1];
    }

    // Verify the proof.
    verify_proof(&verifying_key.0, &zkproof, &public_input[..]).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use crate::sapling::{
        circuit::SpendParameters,
        keys::ExpandedSpendingKey,
        zip304::{sign_message, verify_message, Signature},
        Diversifier,
    };

    #[test]
    fn test_signatures() {
        let (spend_buf, _) = wagyu_zcash_parameters::load_sapling_parameters();
        let params = SpendParameters::read(&spend_buf[..], false)
            .expect("Sapling parameters should be valid");
        let spend_vk = params.prepared_verifying_key();

        let expsk = ExpandedSpendingKey::from_spending_key(&[42; 32][..]);
        let addr = {
            let diversifier = Diversifier([0; 11]);
            expsk
                .proof_generation_key()
                .to_viewing_key()
                .to_payment_address(diversifier)
                .unwrap()
        };

        let msg1 = b"Foo bar";
        let msg2 = b"Spam eggs";

        let sig1 = sign_message(&expsk, addr, 1, msg1, &params);
        let sig2 = sign_message(&expsk, addr, 1, msg2, &params);

        // The signatures are bound to the specific message they were created over
        assert!(verify_message(addr, 1, msg1, &sig1, &spend_vk).is_ok());
        assert!(verify_message(addr, 1, msg2, &sig2, &spend_vk).is_ok());
        assert!(verify_message(addr, 1, msg1, &sig2, &spend_vk).is_err());
        assert!(verify_message(addr, 1, msg2, &sig1, &spend_vk).is_err());

        // ... and the signatures are unique but trivially linkable by the nullifier
        assert_ne!(&sig1.to_bytes()[..], &sig2.to_bytes()[..]);
        assert_eq!(sig1.nullifier, sig2.nullifier);

        // Generate a signature with a diversified address
        let addr_b = {
            let diversifier = Diversifier([5; 11]);
            expsk
                .proof_generation_key()
                .to_viewing_key()
                .to_payment_address(diversifier)
                .unwrap()
        };
        let sig1_b = sign_message(&expsk, addr_b, 1, msg1, &params);

        // The signatures are bound to the specific address they were created with
        assert!(verify_message(addr_b, 1, msg1, &sig1_b, &spend_vk).is_ok());
        assert!(verify_message(addr_b, 1, msg1, &sig1, &spend_vk).is_err());
        assert!(verify_message(addr, 1, msg1, &sig1_b, &spend_vk).is_err());

        // ... and the signatures are unlinkable
        assert_ne!(&sig1.to_bytes()[..], &sig1_b.to_bytes()[..]);
        assert_ne!(sig1.nullifier, sig1_b.nullifier);
    }

    #[test]
    fn encoding_round_trip() {
        let (spend_buf, _) = wagyu_zcash_parameters::load_sapling_parameters();
        let params = SpendParameters::read(&spend_buf[..], false)
            .expect("Sapling parameters should be valid");

        let expsk = ExpandedSpendingKey::from_spending_key(&[42; 32][..]);
        let addr = {
            let diversifier = Diversifier([0; 11]);
            expsk
                .proof_generation_key()
                .to_viewing_key()
                .to_payment_address(diversifier)
                .unwrap()
        };

        let msg = b"Foo bar";
        let sig = sign_message(&expsk, addr.clone(), 1, msg, &params);

        let sigs_equal = |a: Signature, b: &Signature| {
            let mut a_sig_bytes = vec![];
            let mut b_sig_bytes = vec![];
            a.spend_auth_sig.write(&mut a_sig_bytes).unwrap();
            b.spend_auth_sig.write(&mut b_sig_bytes).unwrap();
            a.nullifier == b.nullifier
                && a.rk.0 == b.rk.0
                && a.zkproof == b.zkproof
                && a_sig_bytes == b_sig_bytes
        };

        assert!(sigs_equal(
            Signature::from_bytes(&sig.to_bytes()).unwrap(),
            &sig
        ));

        assert!(sigs_equal(sig.to_string().parse().unwrap(), &sig));
    }
}
