//! Structs representing the components within Zcash transactions.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};

use zcash_protocol::value::ZatBalance;

use super::GROTH_PROOF_SIZE;
use crate::transaction::bytes::{SproutBundleBytes, SproutJoinSplitBytes, SproutProofBytes};

const ZC_NUM_JS_INPUTS: usize = SproutJoinSplitBytes::ZC_NUM_JS_INPUTS;
const ZC_NUM_JS_OUTPUTS: usize = SproutJoinSplitBytes::ZC_NUM_JS_OUTPUTS;
const PHGR_PROOF_SIZE: usize = SproutProofBytes::PHGR_PROOF_SIZE;
const CIPHERTEXT_SIZE: usize = SproutJoinSplitBytes::CIPHERTEXT_SIZE;
const ANCHOR_SIZE: usize = SproutJoinSplitBytes::ANCHOR_SIZE;
const NULLIFIER_SIZE: usize = SproutJoinSplitBytes::NULLIFIER_SIZE;
const COMMITMENT_SIZE: usize = SproutJoinSplitBytes::COMMITMENT_SIZE;
const EPHEMERAL_KEY_SIZE: usize = SproutJoinSplitBytes::EPHEMERAL_KEY_SIZE;
const RANDOM_SEED_SIZE: usize = SproutJoinSplitBytes::RANDOM_SEED_SIZE;
const MAC_SIZE: usize = SproutJoinSplitBytes::MAC_SIZE;
const JOINSPLIT_PUBKEY_SIZE: usize = SproutBundleBytes::JOINSPLIT_PUBKEY_SIZE;
const JOINSPLIT_SIG_SIZE: usize = SproutBundleBytes::JOINSPLIT_SIG_SIZE;

#[derive(Debug, Clone)]
pub struct Bundle {
    pub joinsplits: Vec<JsDescription>,
    pub joinsplit_pubkey: [u8; JOINSPLIT_PUBKEY_SIZE],
    pub joinsplit_sig: [u8; JOINSPLIT_SIG_SIZE],
}

impl Bundle {
    /// The value balance for the bundle. When this is positive,
    /// its value is added to the transparent value pool; when it
    /// is negative, its value is subtracted from the transparent
    /// value pool.
    pub fn value_balance(&self) -> Option<ZatBalance> {
        self.joinsplits
            .iter()
            .try_fold(ZatBalance::zero(), |total, js| total + js.net_value())
    }

    /// Converts this bundle to its wire representation.
    ///
    /// Returns an error if the bundle has no JoinSplits, since an empty bundle
    /// is encoded as a bare zero count with no public key or signature.
    #[allow(dead_code)] // Used by the typed transaction layer, which requires Sapling and Orchard.
    pub(crate) fn to_bytes(&self) -> io::Result<SproutBundleBytes> {
        SproutBundleBytes::from_parts(
            self.joinsplits
                .iter()
                .map(JsDescription::to_bytes)
                .collect::<io::Result<Vec<_>>>()?,
            self.joinsplit_pubkey,
            self.joinsplit_sig,
        )
    }

    /// Converts a wire representation to a Sprout bundle.
    ///
    /// Returns an error if a JoinSplit's `vpub_old` or `vpub_new` is outside
    /// the monetary range.
    pub(crate) fn from_bytes(bytes: SproutBundleBytes) -> io::Result<Self> {
        let joinsplits = bytes
            .joinsplits()
            .iter()
            .map(|js| JsDescription::from_bytes(js.clone()))
            .collect::<io::Result<Vec<_>>>()?;

        Ok(Self {
            joinsplits,
            joinsplit_pubkey: *bytes.joinsplit_pubkey(),
            joinsplit_sig: *bytes.joinsplit_sig(),
        })
    }
}

#[derive(Clone)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum SproutProof {
    Groth([u8; GROTH_PROOF_SIZE]),
    PHGR([u8; PHGR_PROOF_SIZE]),
}

impl core::fmt::Debug for SproutProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            SproutProof::Groth(_) => write!(f, "SproutProof::Groth"),
            SproutProof::PHGR(_) => write!(f, "SproutProof::PHGR"),
        }
    }
}

#[derive(Clone)]
pub struct JsDescription {
    pub(crate) vpub_old: ZatBalance,
    pub(crate) vpub_new: ZatBalance,
    pub(crate) anchor: [u8; ANCHOR_SIZE],
    pub(crate) nullifiers: [[u8; NULLIFIER_SIZE]; ZC_NUM_JS_INPUTS],
    pub(crate) commitments: [[u8; COMMITMENT_SIZE]; ZC_NUM_JS_OUTPUTS],
    pub(crate) ephemeral_key: [u8; EPHEMERAL_KEY_SIZE],
    pub(crate) random_seed: [u8; RANDOM_SEED_SIZE],
    pub(crate) macs: [[u8; MAC_SIZE]; ZC_NUM_JS_INPUTS],
    pub(crate) proof: SproutProof,
    pub(crate) ciphertexts: [[u8; CIPHERTEXT_SIZE]; ZC_NUM_JS_OUTPUTS],
}

impl core::fmt::Debug for JsDescription {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "JSDescription(
                vpub_old = {:?}, vpub_new = {:?},
                anchor = {:?},
                nullifiers = {:?},
                commitments = {:?},
                ephemeral_key = {:?},
                random_seed = {:?},
                macs = {:?})",
            self.vpub_old,
            self.vpub_new,
            self.anchor,
            self.nullifiers,
            self.commitments,
            self.ephemeral_key,
            self.random_seed,
            self.macs
        )
    }
}

impl JsDescription {
    /// Reads a JoinSplit description.
    ///
    /// `use_groth` selects the proof encoding: Groth16 from version 4 onward,
    /// PHGR before it.
    pub fn read<R: Read>(reader: R, use_groth: bool) -> io::Result<Self> {
        Self::from_bytes(SproutJoinSplitBytes::read(reader, use_groth)?)
    }

    /// Writes this JoinSplit description.
    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        self.to_bytes()?.write(writer)
    }

    /// Converts this JoinSplit to its wire representation.
    ///
    /// Returns an error if `vpub_old` or `vpub_new` is negative.
    pub(crate) fn to_bytes(&self) -> io::Result<SproutJoinSplitBytes> {
        let vpub_old = u64::try_from(self.vpub_old)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "vpub_old is negative"))?;
        let vpub_new = u64::try_from(self.vpub_new)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "vpub_new is negative"))?;

        Ok(SproutJoinSplitBytes::from_parts(
            vpub_old,
            vpub_new,
            self.anchor,
            self.nullifiers,
            self.commitments,
            self.ephemeral_key,
            self.random_seed,
            self.macs,
            match &self.proof {
                SproutProof::Groth(proof) => SproutProofBytes::Groth(*proof),
                SproutProof::PHGR(proof) => SproutProofBytes::Phgr(*proof),
            },
            self.ciphertexts,
        ))
    }

    /// Converts a wire representation to a JoinSplit description.
    ///
    /// Returns an error if `vpub_old` or `vpub_new` is outside the monetary
    /// range.
    pub(crate) fn from_bytes(bytes: SproutJoinSplitBytes) -> io::Result<Self> {
        // Consensus rule (§4.3): Canonical encoding is enforced here.
        let vpub_old = ZatBalance::from_u64(bytes.vpub_old())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vpub_old out of range"))?;

        // Consensus rule (§4.3): Canonical encoding is enforced here.
        let vpub_new = ZatBalance::from_u64(bytes.vpub_new())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vpub_new out of range"))?;

        // Consensus rule (§4.3): One of vpub_old and vpub_new being zero is
        // enforced by CheckTransactionWithoutProofVerification() in zcashd.

        let proof = match bytes.proof() {
            // Consensus rules (§4.3):
            // - Canonical encoding is enforced in librustzcash_sprout_verify()
            // - Proof validity is enforced in librustzcash_sprout_verify()
            SproutProofBytes::Groth(proof) => SproutProof::Groth(*proof),
            // Consensus rules (§4.3):
            // - Canonical encoding is enforced by PHGRProof in zcashd
            // - Proof validity is enforced by JSDescription::Verify() in zcashd
            SproutProofBytes::Phgr(proof) => SproutProof::PHGR(*proof),
        };

        Ok(Self {
            vpub_old,
            vpub_new,
            anchor: *bytes.anchor(),
            nullifiers: *bytes.nullifiers(),
            commitments: *bytes.commitments(),
            // Consensus rule (§4.3): Canonical encoding is enforced by
            // ZCNoteDecryption::decrypt() in zcashd
            ephemeral_key: *bytes.ephemeral_key(),
            random_seed: *bytes.random_seed(),
            macs: *bytes.macs(),
            proof,
            ciphertexts: *bytes.ciphertexts(),
        })
    }

    /// The net value for the JoinSplit. When this is positive,
    /// its value is added to the transparent value pool; when it
    /// is negative, its value is subtracted from the transparent
    /// value pool.
    pub fn net_value(&self) -> ZatBalance {
        (self.vpub_new - self.vpub_old).expect("difference is in range [-MAX_MONEY..=MAX_MONEY]")
    }

    /// Returns the value added to the Sprout pool by this JoinSplit.
    pub fn vpub_old(&self) -> ZatBalance {
        self.vpub_old
    }

    /// Returns the value removed from the Sprout pool by this JoinSplit.
    pub fn vpub_new(&self) -> ZatBalance {
        self.vpub_new
    }

    /// Returns the Sprout note commitment tree anchor for this JoinSplit.
    pub fn anchor(&self) -> &[u8; ANCHOR_SIZE] {
        &self.anchor
    }

    /// Returns the nullifiers for the input notes of this JoinSplit.
    pub fn nullifiers(&self) -> &[[u8; NULLIFIER_SIZE]; ZC_NUM_JS_INPUTS] {
        &self.nullifiers
    }

    /// Returns the note commitments for the output notes of this JoinSplit.
    pub fn commitments(&self) -> &[[u8; COMMITMENT_SIZE]; ZC_NUM_JS_OUTPUTS] {
        &self.commitments
    }

    /// Returns the random seed for this JoinSplit.
    pub fn random_seed(&self) -> &[u8; RANDOM_SEED_SIZE] {
        &self.random_seed
    }

    /// Returns the message authentication codes for this JoinSplit.
    pub fn macs(&self) -> &[[u8; MAC_SIZE]; ZC_NUM_JS_INPUTS] {
        &self.macs
    }

    /// Returns the Groth16 proof bytes for this JoinSplit, if it uses Groth16.
    /// Returns `None` for PHGR proofs (pre-Sapling).
    pub fn groth_proof_bytes(&self) -> Option<&[u8; GROTH_PROOF_SIZE]> {
        match &self.proof {
            SproutProof::Groth(bytes) => Some(bytes),
            SproutProof::PHGR(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use zcash_protocol::value::MAX_MONEY;

    use super::*;

    fn join_split(use_groth: bool) -> SproutJoinSplitBytes {
        let proof = if use_groth {
            SproutProofBytes::Groth([0u8; GROTH_PROOF_SIZE])
        } else {
            SproutProofBytes::Phgr([0u8; PHGR_PROOF_SIZE])
        };
        SproutJoinSplitBytes::from_parts(
            1,
            2,
            [3u8; ANCHOR_SIZE],
            [[4u8; NULLIFIER_SIZE]; ZC_NUM_JS_INPUTS],
            [[5u8; COMMITMENT_SIZE]; ZC_NUM_JS_OUTPUTS],
            [6u8; EPHEMERAL_KEY_SIZE],
            [7u8; RANDOM_SEED_SIZE],
            [[8u8; MAC_SIZE]; ZC_NUM_JS_INPUTS],
            proof,
            [[9u8; CIPHERTEXT_SIZE]; ZC_NUM_JS_OUTPUTS],
        )
    }

    #[test]
    fn join_split_round_trips_through_bytes() {
        for use_groth in [false, true] {
            let bytes = join_split(use_groth);
            let js = JsDescription::from_bytes(bytes.clone()).unwrap();
            assert_eq!(js.to_bytes().unwrap(), bytes);
            assert_eq!(js.vpub_old(), ZatBalance::from_u64(1).unwrap());
            assert_eq!(js.vpub_new(), ZatBalance::from_u64(2).unwrap());
            assert_eq!(js.groth_proof_bytes().is_some(), use_groth);
        }
    }

    #[test]
    fn join_split_read_write_round_trip() {
        for use_groth in [false, true] {
            let js = JsDescription::from_bytes(join_split(use_groth)).unwrap();
            let mut encoded = Vec::new();
            js.write(&mut encoded).unwrap();
            let decoded = JsDescription::read(&encoded[..], use_groth).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), js.to_bytes().unwrap());
        }
    }

    #[test]
    fn join_split_rejects_out_of_range_vpub() {
        let bytes = join_split(true);
        let bytes = SproutJoinSplitBytes::from_parts(
            MAX_MONEY + 1,
            0,
            *bytes.anchor(),
            *bytes.nullifiers(),
            *bytes.commitments(),
            *bytes.ephemeral_key(),
            *bytes.random_seed(),
            *bytes.macs(),
            bytes.proof().clone(),
            *bytes.ciphertexts(),
        );
        assert!(JsDescription::from_bytes(bytes).is_err());
    }

    #[test]
    fn bundle_round_trips_through_bytes() {
        let bytes = SproutBundleBytes::from_parts(
            vec![join_split(true)],
            [10u8; JOINSPLIT_PUBKEY_SIZE],
            [11u8; JOINSPLIT_SIG_SIZE],
        )
        .unwrap();
        let bundle = Bundle::from_bytes(bytes.clone()).unwrap();
        assert_eq!(bundle.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn empty_bundle_has_no_wire_representation() {
        let bundle = Bundle {
            joinsplits: vec![],
            joinsplit_pubkey: [0u8; JOINSPLIT_PUBKEY_SIZE],
            joinsplit_sig: [0u8; JOINSPLIT_SIG_SIZE],
        };
        assert!(bundle.to_bytes().is_err());
    }
}
