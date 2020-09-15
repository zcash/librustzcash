//! Sapling key components.
//!
//! Implements [section 4.2.2] of the Zcash Protocol Specification.
//!
//! [section 4.2.2]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents

use crate::{
    constants::{PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR},
    primitives::{ProofGenerationKey, ViewingKey},
};
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use ff::PrimeField;
use group::{Group, GroupEncoding};
use std::io::{self, Read, Write};
use subtle::CtOption;

pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"MASP__ExpandSeed";

/// PRF^expand(sk, t) := BLAKE2b-512("Zcash_ExpandSeed", sk || t)
pub fn prf_expand(sk: &[u8], t: &[u8]) -> Blake2bHash {
    prf_expand_vec(sk, &[t])
}

pub fn prf_expand_vec(sk: &[u8], ts: &[&[u8]]) -> Blake2bHash {
    let mut h = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    h.update(sk);
    for t in ts {
        h.update(t);
    }
    h.finalize()
}

/// An outgoing viewing key
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OutgoingViewingKey(pub [u8; 32]);

/// A Sapling expanded spending key
#[derive(Clone)]
pub struct ExpandedSpendingKey {
    pub ask: jubjub::Fr,
    pub nsk: jubjub::Fr,
    pub ovk: OutgoingViewingKey,
}

/// A Sapling full viewing key
#[derive(Debug)]
pub struct FullViewingKey {
    pub vk: ViewingKey,
    pub ovk: OutgoingViewingKey,
}

impl ExpandedSpendingKey {
    pub fn from_spending_key(sk: &[u8]) -> Self {
        let ask = jubjub::Fr::from_bytes_wide(prf_expand(sk, &[0x00]).as_array());
        let nsk = jubjub::Fr::from_bytes_wide(prf_expand(sk, &[0x01]).as_array());
        let mut ovk = OutgoingViewingKey([0u8; 32]);
        ovk.0
            .copy_from_slice(&prf_expand(sk, &[0x02]).as_bytes()[..32]);
        ExpandedSpendingKey { ask, nsk, ovk }
    }

    pub fn proof_generation_key(&self) -> ProofGenerationKey {
        ProofGenerationKey {
            ak: SPENDING_KEY_GENERATOR * self.ask,
            nsk: self.nsk,
        }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut ask_repr = [0u8; 32];
        reader.read_exact(ask_repr.as_mut())?;
        let ask = jubjub::Fr::from_repr(ask_repr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ask not in field"))?;

        let mut nsk_repr = [0u8; 32];
        reader.read_exact(nsk_repr.as_mut())?;
        let nsk = jubjub::Fr::from_repr(nsk_repr)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "nsk not in field"))?;

        let mut ovk = [0u8; 32];
        reader.read_exact(&mut ovk)?;

        Ok(ExpandedSpendingKey {
            ask,
            nsk,
            ovk: OutgoingViewingKey(ovk),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.ask.to_repr().as_ref())?;
        writer.write_all(self.nsk.to_repr().as_ref())?;
        writer.write_all(&self.ovk.0)?;

        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        self.write(&mut result[..])
            .expect("should be able to serialize an ExpandedSpendingKey");
        result
    }
}

impl Clone for FullViewingKey {
    fn clone(&self) -> Self {
        FullViewingKey {
            vk: ViewingKey {
                ak: self.vk.ak.clone(),
                nk: self.vk.nk.clone(),
            },
            ovk: self.ovk,
        }
    }
}

impl FullViewingKey {
    pub fn from_expanded_spending_key(expsk: &ExpandedSpendingKey) -> Self {
        FullViewingKey {
            vk: ViewingKey {
                ak: SPENDING_KEY_GENERATOR * expsk.ask,
                nk: PROOF_GENERATION_KEY_GENERATOR * expsk.nsk,
            },
            ovk: expsk.ovk,
        }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let ak = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf).and_then(|p| CtOption::new(p, !p.is_identity()))
        };
        let nk = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf)
        };
        if ak.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ak not of prime order",
            ));
        }
        if nk.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nk not in prime-order subgroup",
            ));
        }
        let ak = ak.unwrap();
        let nk = nk.unwrap();

        let mut ovk = [0u8; 32];
        reader.read_exact(&mut ovk)?;

        Ok(FullViewingKey {
            vk: ViewingKey { ak, nk },
            ovk: OutgoingViewingKey(ovk),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.vk.ak.to_bytes())?;
        writer.write_all(&self.vk.nk.to_bytes())?;
        writer.write_all(&self.ovk.0)?;

        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        self.write(&mut result[..])
            .expect("should be able to serialize a FullViewingKey");
        result
    }
}

#[cfg(test)]
mod tests {
    use group::{Group, GroupEncoding};

    use super::FullViewingKey;
    use crate::constants::SPENDING_KEY_GENERATOR;

    #[test]
    fn ak_must_be_prime_order() {
        let mut buf = [0; 96];
        let identity = jubjub::SubgroupPoint::identity();

        // Set both ak and nk to the identity.
        buf[0..32].copy_from_slice(&identity.to_bytes());
        buf[32..64].copy_from_slice(&identity.to_bytes());

        // ak is not allowed to be the identity.
        assert_eq!(
            FullViewingKey::read(&buf[..]).unwrap_err().to_string(),
            "ak not of prime order"
        );

        // Set ak to a basepoint.
        let basepoint = SPENDING_KEY_GENERATOR;
        buf[0..32].copy_from_slice(&basepoint.to_bytes());

        // nk is allowed to be the identity.
        assert!(FullViewingKey::read(&buf[..]).is_ok());
    }
}
