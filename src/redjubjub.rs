//! Implementation of RedJubjub, a specialization of RedDSA to the Jubjub curve.
//! See section 5.4.6 of the Sapling protocol specification.

use pairing::{Field, PrimeField, PrimeFieldRepr};
use rand::Rng;
use std::io::{self, Read, Write};

use jubjub::{FixedGenerators, JubjubEngine, JubjubParams, Unknown, edwards::Point};
use util::{hash_to_scalar, swap_bits_u64};

fn read_scalar<E: JubjubEngine, R: Read>(reader: R) -> io::Result<E::Fs> {
    let mut s_repr = <E::Fs as PrimeField>::Repr::default();

    // This reads in big-endian, so we perform a swap of the
    // limbs in the representation and swap the bit order.
    s_repr.read_be(reader)?;
    s_repr.as_mut().reverse();
    for b in s_repr.as_mut() {
        *b = swap_bits_u64(*b);
    }

    match E::Fs::from_repr(s_repr) {
        Ok(s) => Ok(s),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scalar is not in field",
        )),
    }
}

fn write_scalar<E: JubjubEngine, W: Write>(s: &E::Fs, writer: W) -> io::Result<()> {
    let mut s_repr = s.into_repr();

    // This writes in big-endian, so we perform a swap of the
    // limbs in the representation and swap the bit order.
    s_repr.as_mut().reverse();
    for b in s_repr.as_mut() {
        *b = swap_bits_u64(*b);
    }
    s_repr.write_be(writer)
}

fn h_star<E: JubjubEngine>(a: &[u8], b: &[u8]) -> E::Fs {
    hash_to_scalar::<E>(b"Zcash_RedJubjubH", a, b)
}

pub struct Signature {
    rbar: [u8; 32],
    sbar: [u8; 32],
}

pub struct PrivateKey<E: JubjubEngine>(E::Fs);

pub struct PublicKey<E: JubjubEngine>(pub Point<E, Unknown>);

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

impl<E: JubjubEngine> PrivateKey<E> {
    pub fn randomize(&self, alpha: E::Fs) -> Self {
        let mut tmp = self.0;
        tmp.add_assign(&alpha);
        PrivateKey(tmp)
    }

    pub fn read<R: Read>(reader: R) -> io::Result<Self> {
        let pk = read_scalar::<E, R>(reader)?;
        Ok(PrivateKey(pk))
    }

    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        write_scalar::<E, W>(&self.0, writer)
    }

    pub fn sign<R: Rng>(
        &self,
        msg: &[u8],
        rng: &mut R,
        p_g: FixedGenerators,
        params: &E::Params,
    ) -> Signature {
        // T = (l_H + 128) bits of randomness
        // For H*, l_H = 512 bits
        let mut t = [0u8; 80];
        rng.fill_bytes(&mut t[..]);

        // r = H*(T || M)
        let r = h_star::<E>(&t[..], msg);

        // R = r . P_G
        let r_g = params.generator(p_g).mul(r, params);
        let mut rbar = [0u8; 32];
        r_g.write(&mut rbar[..])
            .expect("Jubjub points should serialize to 32 bytes");

        // S = r + H*(Rbar || M) . sk
        let mut s = h_star::<E>(&rbar[..], msg);
        s.mul_assign(&self.0);
        s.add_assign(&r);
        let mut sbar = [0u8; 32];
        write_scalar::<E, &mut [u8]>(&s, &mut sbar[..])
            .expect("Jubjub scalars should serialize to 32 bytes");

        Signature { rbar, sbar }
    }
}

impl<E: JubjubEngine> PublicKey<E> {
    pub fn from_private(privkey: &PrivateKey<E>, p_g: FixedGenerators, params: &E::Params) -> Self {
        let res = params.generator(p_g).mul(privkey.0, params).into();
        PublicKey(res)
    }

    pub fn randomize(&self, alpha: E::Fs, p_g: FixedGenerators, params: &E::Params) -> Self {
        let res: Point<E, Unknown> = params.generator(p_g).mul(alpha, params).into();
        let res = res.add(&self.0, params);
        PublicKey(res)
    }

    pub fn read<R: Read>(reader: R, params: &E::Params) -> io::Result<Self> {
        let p = Point::read(reader, params)?;
        Ok(PublicKey(p))
    }

    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        self.0.write(writer)
    }

    pub fn verify(
        &self,
        msg: &[u8],
        sig: &Signature,
        p_g: FixedGenerators,
        params: &E::Params,
    ) -> bool {
        // c = H*(Rbar || M)
        let c = h_star::<E>(&sig.rbar[..], msg);

        // Signature checks:
        // R != invalid
        let r = match Point::read(&sig.rbar[..], params) {
            Ok(r) => r,
            Err(_) => return false,
        };
        // S < order(G)
        // (E::Fs guarantees its representation is in the field)
        let s = match read_scalar::<E, &[u8]>(&sig.sbar[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // S . P_G = R + c . vk
        self.0.mul(c, params).add(&r, params) == params.generator(p_g).mul(s, params).into()
    }
}

#[cfg(test)]
mod tests {
    use pairing::bls12_381::Bls12;
    use rand::thread_rng;

    use jubjub::JubjubBls12;

    use super::*;

    #[test]
    fn round_trip_serialization() {
        let rng = &mut thread_rng();
        let p_g = FixedGenerators::SpendingKeyGenerator;
        let params = &JubjubBls12::new();

        for _ in 0..1000 {
            let sk = PrivateKey::<Bls12>(rng.gen());
            let vk = PublicKey::from_private(&sk, p_g, params);
            let msg = b"Foo bar";
            let sig = sk.sign(msg, rng, p_g, params);

            let mut sk_bytes = [0u8; 32];
            let mut vk_bytes = [0u8; 32];
            let mut sig_bytes = [0u8; 64];
            sk.write(&mut sk_bytes[..]).unwrap();
            vk.write(&mut vk_bytes[..]).unwrap();
            sig.write(&mut sig_bytes[..]).unwrap();

            let sk_2 = PrivateKey::<Bls12>::read(&sk_bytes[..]).unwrap();
            let vk_2 = PublicKey::from_private(&sk_2, p_g, params);
            let mut vk_2_bytes = [0u8; 32];
            vk_2.write(&mut vk_2_bytes[..]).unwrap();
            assert!(vk_bytes == vk_2_bytes);

            let vk_2 = PublicKey::<Bls12>::read(&vk_bytes[..], params).unwrap();
            let sig_2 = Signature::read(&sig_bytes[..]).unwrap();
            assert!(vk.verify(msg, &sig_2, p_g, params));
            assert!(vk_2.verify(msg, &sig, p_g, params));
            assert!(vk_2.verify(msg, &sig_2, p_g, params));
        }
    }

    #[test]
    fn random_signatures() {
        let rng = &mut thread_rng();
        let p_g = FixedGenerators::SpendingKeyGenerator;
        let params = &JubjubBls12::new();

        for _ in 0..1000 {
            let sk = PrivateKey::<Bls12>(rng.gen());
            let vk = PublicKey::from_private(&sk, p_g, params);

            let msg1 = b"Foo bar";
            let msg2 = b"Spam eggs";

            let sig1 = sk.sign(msg1, rng, p_g, params);
            let sig2 = sk.sign(msg2, rng, p_g, params);

            assert!(vk.verify(msg1, &sig1, p_g, params));
            assert!(vk.verify(msg2, &sig2, p_g, params));
            assert!(!vk.verify(msg1, &sig2, p_g, params));
            assert!(!vk.verify(msg2, &sig1, p_g, params));

            let alpha = rng.gen();
            let rsk = sk.randomize(alpha);
            let rvk = vk.randomize(alpha, p_g, params);

            let sig1 = rsk.sign(msg1, rng, p_g, params);
            let sig2 = rsk.sign(msg2, rng, p_g, params);

            assert!(rvk.verify(msg1, &sig1, p_g, params));
            assert!(rvk.verify(msg2, &sig2, p_g, params));
            assert!(!rvk.verify(msg1, &sig2, p_g, params));
            assert!(!rvk.verify(msg2, &sig1, p_g, params));
        }
    }
}
