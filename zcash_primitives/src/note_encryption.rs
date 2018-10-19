use blake2_rfc::blake2b::{Blake2b, Blake2bResult};
use byteorder::{LittleEndian, WriteBytesExt};
use chacha20_poly1305_aead;
use ff::{PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr};
use rand::{OsRng, Rng};
use sapling_crypto::{
    jubjub::{edwards, fs::Fs, PrimeOrder, ToUniform, Unknown},
    primitives::{Note, PaymentAddress},
};

use crate::{keys::OutgoingViewingKey, JUBJUB};

pub const KDF_SAPLING_PERSONALIZATION: &'static [u8; 16] = b"Zcash_SaplingKDF";
pub const PRF_OCK_PERSONALIZATION: &'static [u8; 16] = b"Zcash_Derive_ock";

pub struct Memo([u8; 512]);

impl Default for Memo {
    fn default() -> Self {
        // Empty memo field indication per ZIP 302
        let mut memo = [0u8; 512];
        memo[0] = 0xF6;
        Memo(memo)
    }
}

fn generate_esk() -> Fs {
    // create random 64 byte buffer
    let mut rng = OsRng::new().expect("should be able to construct RNG");
    let mut buffer = [0u8; 64];
    for i in 0..buffer.len() {
        buffer[i] = rng.gen();
    }

    // reduce to uniform value
    Fs::to_uniform(&buffer[..])
}

fn sapling_ka_agree(esk: &Fs, pk_d: &edwards::Point<Bls12, PrimeOrder>) -> Vec<u8> {
    let ka = pk_d
        .mul(esk.into_repr(), &JUBJUB)
        .double(&JUBJUB)
        .double(&JUBJUB)
        .double(&JUBJUB);
    let mut result = Vec::with_capacity(32);
    ka.write(&mut result).expect("length is not 32 bytes");
    result
}

fn kdf_sapling(dhsecret: &[u8], epk: &edwards::Point<Bls12, PrimeOrder>) -> Blake2bResult {
    let mut input = [0u8; 64];
    input[0..32].copy_from_slice(&dhsecret);
    epk.write(&mut input[32..64]).unwrap();

    let mut h = Blake2b::with_params(32, &[], &[], KDF_SAPLING_PERSONALIZATION);
    h.update(&input);
    h.finalize()
}

pub struct SaplingNoteEncryption {
    epk: edwards::Point<Bls12, PrimeOrder>,
    esk: Fs,
    note: Note<Bls12>,
    to: PaymentAddress<Bls12>,
    memo: Memo,
    ovk: OutgoingViewingKey,
}

impl SaplingNoteEncryption {
    pub fn new(
        ovk: OutgoingViewingKey,
        note: Note<Bls12>,
        to: PaymentAddress<Bls12>,
        memo: Memo,
    ) -> SaplingNoteEncryption {
        let esk = generate_esk();
        let epk = note.g_d.mul(esk, &JUBJUB);

        SaplingNoteEncryption {
            epk,
            esk,
            note,
            to,
            memo,
            ovk,
        }
    }

    pub fn esk(&self) -> &Fs {
        &self.esk
    }

    pub fn epk(&self) -> &edwards::Point<Bls12, PrimeOrder> {
        &self.epk
    }

    pub fn encrypt_note_plaintext(&self) -> [u8; 580] {
        let shared_secret = sapling_ka_agree(&self.esk, &self.to.pk_d);
        let key = kdf_sapling(&shared_secret, &self.epk);

        let nonce = [0u8; 12];

        let mut input = Vec::with_capacity(564);
        input.push(1);
        input.extend_from_slice(&self.to.diversifier.0);
        (&mut input)
            .write_u64::<LittleEndian>(self.note.value)
            .unwrap();
        self.note.r.into_repr().write_le(&mut input).unwrap();
        input.extend_from_slice(&self.memo.0);

        let mut ciphertext = Vec::with_capacity(564);
        let tag =
            chacha20_poly1305_aead::encrypt(&key.as_bytes(), &nonce, &[], &input, &mut ciphertext)
                .unwrap();

        let mut output = [0u8; 580];
        output[0..564].copy_from_slice(&ciphertext);
        output[564..580].copy_from_slice(&tag);
        output
    }

    pub fn encrypt_outgoing_plaintext(
        &self,
        cv: &edwards::Point<Bls12, Unknown>,
        cmu: &Fr,
    ) -> [u8; 80] {
        let mut ock_input = [0u8; 128];
        ock_input[0..32].copy_from_slice(&self.ovk.0);
        cv.write(&mut ock_input[32..64]).unwrap();
        cmu.into_repr().write_le(&mut ock_input[64..96]).unwrap();
        self.epk.write(&mut ock_input[96..128]).unwrap();

        let mut h = Blake2b::with_params(32, &[], &[], PRF_OCK_PERSONALIZATION);
        h.update(&ock_input);
        let key = h.finalize();

        let mut input = [0u8; 64];
        self.note.pk_d.write(&mut input[0..32]).unwrap();
        self.esk.into_repr().write_le(&mut input[32..64]).unwrap();

        let mut buffer = Vec::with_capacity(64);
        let nonce = [0u8; 12];
        let tag = chacha20_poly1305_aead::encrypt(key.as_bytes(), &nonce, &[], &input, &mut buffer)
            .unwrap();

        let mut output = [0u8; 80];
        output[0..64].copy_from_slice(&buffer);
        output[64..80].copy_from_slice(&tag[..]);

        output
    }
}
