//! Implementation of [RedJubjub], a specialization of RedDSA to the Jubjub
//! curve.
//!
//! [RedJubjub]: https://zips.z.cash/protocol/protocol.pdf#concretereddsa

use ff::{Field, PrimeField};
use group::GroupEncoding;
use jubjub::{AffinePoint, ExtendedPoint, SubgroupPoint};
use rand_core::RngCore;

use std::fmt;
use std::io::{self, Read, Write};
use std::ops::{AddAssign, MulAssign, Neg};

use super::util::hash_to_scalar;

fn read_scalar<R: Read>(mut reader: R) -> io::Result<jubjub::Fr> {
    let mut s_repr = [0u8; 32];
    reader.read_exact(s_repr.as_mut())?;

    Option::from(jubjub::Fr::from_repr(s_repr))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "scalar is not in field"))
}

fn write_scalar<W: Write>(s: &jubjub::Fr, mut writer: W) -> io::Result<()> {
    writer.write_all(s.to_repr().as_ref())
}

fn h_star(a: &[u8], b: &[u8]) -> jubjub::Fr {
    hash_to_scalar(b"Zcash_RedJubjubH", a, b)
}

#[derive(Copy, Clone)]
pub struct Signature {
    rbar: [u8; 32],
    sbar: [u8; 32],
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("rbar", &hex::encode(self.rbar))
            .field("sbar", &hex::encode(self.sbar))
            .finish()
    }
}

pub struct PrivateKey(pub jubjub::Fr);

#[derive(Debug, Clone)]
pub struct PublicKey(pub ExtendedPoint);

impl Signature {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut rbar = [0u8; 32];
        let mut sbar = [0u8; 32];
        reader.read_exact(&mut rbar)?;
        reader.read_exact(&mut sbar)?;
        Ok(Signature { rbar, sbar })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.rbar)?;
        writer.write_all(&self.sbar)
    }
}

impl PrivateKey {
    #[must_use]
    pub fn randomize(&self, alpha: jubjub::Fr) -> Self {
        let mut tmp = self.0;
        tmp.add_assign(&alpha);
        PrivateKey(tmp)
    }

    pub fn read<R: Read>(reader: R) -> io::Result<Self> {
        let pk = read_scalar::<R>(reader)?;
        Ok(PrivateKey(pk))
    }

    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        write_scalar::<W>(&self.0, writer)
    }

    pub fn sign<R: RngCore>(&self, msg: &[u8], rng: &mut R, p_g: SubgroupPoint) -> Signature {
        // T = (l_H + 128) bits of randomness
        // For H*, l_H = 512 bits
        let mut t = [0u8; 80];
        rng.fill_bytes(&mut t[..]);

        // r = H*(T || M)
        let r = h_star(&t[..], msg);

        // R = r . P_G
        let r_g = p_g * r;
        let rbar = r_g.to_bytes();

        // S = r + H*(Rbar || M) . sk
        let mut s = h_star(&rbar[..], msg);
        s.mul_assign(&self.0);
        s.add_assign(&r);
        let mut sbar = [0u8; 32];
        write_scalar::<&mut [u8]>(&s, &mut sbar[..])
            .expect("Jubjub scalars should serialize to 32 bytes");

        Signature { rbar, sbar }
    }
}

impl PublicKey {
    pub fn from_private(privkey: &PrivateKey, p_g: SubgroupPoint) -> Self {
        PublicKey((p_g * privkey.0).into())
    }

    #[must_use]
    pub fn randomize(&self, alpha: jubjub::Fr, p_g: SubgroupPoint) -> Self {
        PublicKey(ExtendedPoint::from(p_g * alpha) + self.0)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        let p = ExtendedPoint::from_bytes(&bytes).map(PublicKey);
        if p.is_some().into() {
            Ok(p.unwrap())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid RedJubjub public key",
            ))
        }
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0.to_bytes())
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature, p_g: SubgroupPoint) -> bool {
        self.verify_with_zip216(msg, sig, p_g, true)
    }

    pub fn verify_with_zip216(
        &self,
        msg: &[u8],
        sig: &Signature,
        p_g: SubgroupPoint,
        zip216_enabled: bool,
    ) -> bool {
        // c = H*(Rbar || M)
        let c = h_star(&sig.rbar[..], msg);

        // Signature checks:
        // R != invalid
        let r = {
            let r = if zip216_enabled {
                ExtendedPoint::from_bytes(&sig.rbar)
            } else {
                AffinePoint::from_bytes_pre_zip216_compatibility(sig.rbar).map(|p| p.to_extended())
            };
            if r.is_none().into() {
                return false;
            }
            r.unwrap()
        };
        // S < order(G)
        // (jubjub::Scalar guarantees its representation is in the field)
        let s = match read_scalar::<&[u8]>(&sig.sbar[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // 0 = h_G(-S . P_G + R + c . vk)
        ((self.0 * c) + r - (p_g * s))
            .mul_by_cofactor()
            .is_identity()
            .into()
    }
}

pub struct BatchEntry<'a> {
    vk: PublicKey,
    msg: &'a [u8],
    sig: Signature,
}

// TODO: #82: This is a naive implementation currently,
// and doesn't use multiexp.
pub fn batch_verify<'a, R: RngCore>(
    mut rng: &mut R,
    batch: &[BatchEntry<'a>],
    p_g: SubgroupPoint,
) -> bool {
    let mut acc = ExtendedPoint::identity();

    for entry in batch {
        let mut r = {
            let r = ExtendedPoint::from_bytes(&entry.sig.rbar);
            if r.is_none().into() {
                return false;
            }
            r.unwrap()
        };
        let mut s = match read_scalar::<&[u8]>(&entry.sig.sbar[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let mut c = h_star(&entry.sig.rbar[..], entry.msg);

        let z = jubjub::Fr::random(&mut rng);

        s.mul_assign(&z);
        s = s.neg();

        r *= z;

        c.mul_assign(&z);

        acc = acc + r + (entry.vk.0 * c) + (p_g * s);
    }

    acc.mul_by_cofactor().is_identity().into()
}

#[cfg(test)]
mod tests {
    use group::Group;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use super::*;
    use crate::constants::SPENDING_KEY_GENERATOR;

    #[test]
    fn test_batch_verify() {
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let p_g = SPENDING_KEY_GENERATOR;

        let sk1 = PrivateKey(jubjub::Fr::random(&mut rng));
        let vk1 = PublicKey::from_private(&sk1, p_g);
        let msg1 = b"Foo bar";
        let sig1 = sk1.sign(msg1, &mut rng, p_g);
        assert!(vk1.verify(msg1, &sig1, p_g));

        let sk2 = PrivateKey(jubjub::Fr::random(&mut rng));
        let vk2 = PublicKey::from_private(&sk2, p_g);
        let msg2 = b"Foo bar";
        let sig2 = sk2.sign(msg2, &mut rng, p_g);
        assert!(vk2.verify(msg2, &sig2, p_g));

        let mut batch = vec![
            BatchEntry {
                vk: vk1,
                msg: msg1,
                sig: sig1,
            },
            BatchEntry {
                vk: vk2,
                msg: msg2,
                sig: sig2,
            },
        ];

        assert!(batch_verify(&mut rng, &batch, p_g));

        batch[0].sig = sig2;

        assert!(!batch_verify(&mut rng, &batch, p_g));
    }

    #[test]
    fn cofactor_check() {
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let zero = jubjub::ExtendedPoint::identity();
        let p_g = SPENDING_KEY_GENERATOR;

        let jubjub_modulus_bytes = [
            0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20,
            0x68, 0xa6, 0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65,
            0xea, 0xb4, 0x7d, 0x0e,
        ];

        // Get a point of order 8
        let p8 = loop {
            let r = jubjub::ExtendedPoint::random(&mut rng)
                .to_niels()
                .multiply_bits(&jubjub_modulus_bytes);

            let r2 = r.double();
            let r4 = r2.double();
            let r8 = r4.double();

            if r2 != zero && r4 != zero && r8 == zero {
                break r;
            }
        };

        let sk = PrivateKey(jubjub::Fr::random(&mut rng));
        let vk = PublicKey::from_private(&sk, p_g);

        // TODO: This test will need to change when #77 is fixed
        let msg = b"Foo bar";
        let sig = sk.sign(msg, &mut rng, p_g);
        assert!(vk.verify(msg, &sig, p_g));

        let vktorsion = PublicKey(vk.0 + p8);
        assert!(vktorsion.verify(msg, &sig, p_g));
    }

    #[test]
    fn round_trip_serialization() {
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let p_g = SPENDING_KEY_GENERATOR;

        for _ in 0..1000 {
            let sk = PrivateKey(jubjub::Fr::random(&mut rng));
            let vk = PublicKey::from_private(&sk, p_g);
            let msg = b"Foo bar";
            let sig = sk.sign(msg, &mut rng, p_g);

            let mut sk_bytes = [0u8; 32];
            let mut vk_bytes = [0u8; 32];
            let mut sig_bytes = [0u8; 64];
            sk.write(&mut sk_bytes[..]).unwrap();
            vk.write(&mut vk_bytes[..]).unwrap();
            sig.write(&mut sig_bytes[..]).unwrap();

            let sk_2 = PrivateKey::read(&sk_bytes[..]).unwrap();
            let vk_2 = PublicKey::from_private(&sk_2, p_g);
            let mut vk_2_bytes = [0u8; 32];
            vk_2.write(&mut vk_2_bytes[..]).unwrap();
            assert!(vk_bytes == vk_2_bytes);

            let vk_2 = PublicKey::read(&vk_bytes[..]).unwrap();
            let sig_2 = Signature::read(&sig_bytes[..]).unwrap();
            assert!(vk.verify(msg, &sig_2, p_g));
            assert!(vk_2.verify(msg, &sig, p_g));
            assert!(vk_2.verify(msg, &sig_2, p_g));
        }
    }

    #[test]
    fn random_signatures() {
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let p_g = SPENDING_KEY_GENERATOR;

        for _ in 0..1000 {
            let sk = PrivateKey(jubjub::Fr::random(&mut rng));
            let vk = PublicKey::from_private(&sk, p_g);

            let msg1 = b"Foo bar";
            let msg2 = b"Spam eggs";

            let sig1 = sk.sign(msg1, &mut rng, p_g);
            let sig2 = sk.sign(msg2, &mut rng, p_g);

            assert!(vk.verify(msg1, &sig1, p_g));
            assert!(vk.verify(msg2, &sig2, p_g));
            assert!(!vk.verify(msg1, &sig2, p_g));
            assert!(!vk.verify(msg2, &sig1, p_g));

            let alpha = jubjub::Fr::random(&mut rng);
            let rsk = sk.randomize(alpha);
            let rvk = vk.randomize(alpha, p_g);

            let sig1 = rsk.sign(msg1, &mut rng, p_g);
            let sig2 = rsk.sign(msg2, &mut rng, p_g);

            assert!(rvk.verify(msg1, &sig1, p_g));
            assert!(rvk.verify(msg2, &sig2, p_g));
            assert!(!rvk.verify(msg1, &sig2, p_g));
            assert!(!rvk.verify(msg2, &sig1, p_g));
        }
    }
}
