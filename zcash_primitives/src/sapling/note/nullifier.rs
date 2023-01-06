use std::array::TryFromSliceError;

use subtle::{Choice, ConstantTimeEq};

use super::NoteCommitment;
use crate::sapling::{
    keys::NullifierDerivingKey,
    spec::{mixing_pedersen_hash, prf_nf},
};

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

    /// $DeriveNullifier$.
    ///
    /// Defined in [Zcash Protocol Spec § 4.16: Note Commitments and Nullifiers][commitmentsandnullifiers].
    ///
    /// [commitmentsandnullifiers]: https://zips.z.cash/protocol/protocol.pdf#commitmentsandnullifiers
    pub(super) fn derive(nk: &NullifierDerivingKey, cm: NoteCommitment, position: u64) -> Self {
        let rho = mixing_pedersen_hash(cm.inner(), position);
        Nullifier(prf_nf(&nk.0, &rho))
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
