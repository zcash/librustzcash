//! Implementation of RedJubjub, a specialization of RedDSA to the Jubjub curve.
//! See section 5.4.6 of the Sapling protocol specification.

use pairing::Field;
use rand::Rng;

use jubjub::{FixedGenerators, JubjubEngine, JubjubParams, Unknown, edwards::Point};
use util::hash_to_scalar;

fn h_star<E: JubjubEngine>(a: &[u8], b: &[u8]) -> E::Fs {
    hash_to_scalar::<E>(b"Zcash_RedJubjubH", a, b)
}

pub struct Signature<E: JubjubEngine> {
    r: Point<E, Unknown>,
    s: E::Fs,
}

pub struct PrivateKey<E: JubjubEngine>(E::Fs);

pub struct PublicKey<E: JubjubEngine>(Point<E, Unknown>);

impl<E: JubjubEngine> PrivateKey<E> {
    pub fn randomize(&self, alpha: E::Fs) -> Self {
        let mut tmp = self.0;
        tmp.add_assign(&alpha);
        PrivateKey(tmp)
    }

    pub fn sign<R: Rng>(&self, msg: &[u8], rng: &mut R, params: &E::Params) -> Signature<E> {
        // T = (l_H + 128) bits of randomness
        // For H*, l_H = 512 bits
        let mut t = [0u8; 80];
        rng.fill_bytes(&mut t[..]);

        // r = H*(T || M)
        let r = h_star::<E>(&t[..], msg);

        // R = r . G
        let g_r = params
            .generator(FixedGenerators::SpendingKeyGenerator)
            .mul(r, params);
        let mut rbar = [0u8; 32];
        g_r.write(&mut rbar[..])
            .expect("Jubjub points should serialize to 32 bytes");

        // S = r + H*(Rbar || M) . sk
        let mut s = h_star::<E>(&rbar[..], msg);
        s.mul_assign(&self.0);
        s.add_assign(&r);

        Signature { r: g_r.into(), s }
    }
}

impl<E: JubjubEngine> PublicKey<E> {
    pub fn from_private(privkey: &PrivateKey<E>, params: &E::Params) -> Self {
        let res = params
            .generator(FixedGenerators::SpendingKeyGenerator)
            .mul(privkey.0, params)
            .into();
        PublicKey(res)
    }

    pub fn randomize(&self, alpha: E::Fs, params: &E::Params) -> Self {
        let res: Point<E, Unknown> = params
            .generator(FixedGenerators::SpendingKeyGenerator)
            .mul(alpha, params)
            .into();
        let res = res.add(&self.0, params);
        PublicKey(res)
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature<E>, params: &E::Params) -> bool {
        // c = H*(Rbar || M)
        let mut rbar = [0u8; 32];
        sig.r
            .write(&mut rbar[..])
            .expect("Jubjub points should serialize to 32 bytes");
        let c = h_star::<E>(&rbar[..], msg);

        // S . G = R + c . vk
        self.0.mul(c, params).add(&sig.r, params)
            == params
                .generator(FixedGenerators::SpendingKeyGenerator)
                .mul(sig.s, params)
                .into()
    }
}

#[cfg(test)]
mod tests {
    use pairing::bls12_381::Bls12;
    use rand::thread_rng;

    use jubjub::JubjubBls12;

    use super::*;

    #[test]
    fn random_signatures() {
        let rng = &mut thread_rng();
        let params = &JubjubBls12::new();

        for _ in 0..1000 {
            let sk = PrivateKey::<Bls12>(rng.gen());
            let vk = PublicKey::from_private(&sk, params);

            let msg1 = b"Foo bar";
            let msg2 = b"Spam eggs";

            let sig1 = sk.sign(msg1, rng, params);
            let sig2 = sk.sign(msg2, rng, params);

            assert!(vk.verify(msg1, &sig1, params));
            assert!(vk.verify(msg2, &sig2, params));
            assert!(!vk.verify(msg1, &sig2, params));
            assert!(!vk.verify(msg2, &sig1, params));

            let alpha = rng.gen();
            let rsk = sk.randomize(alpha);
            let rvk = vk.randomize(alpha, params);

            let sig1 = rsk.sign(msg1, rng, params);
            let sig2 = rsk.sign(msg2, rng, params);

            assert!(rvk.verify(msg1, &sig1, params));
            assert!(rvk.verify(msg2, &sig2, params));
            assert!(!rvk.verify(msg1, &sig2, params));
            assert!(!rvk.verify(msg2, &sig1, params));
        }
    }
}
