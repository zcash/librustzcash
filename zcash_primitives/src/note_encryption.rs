//! Implementation of in-band secret distribution for Zcash transactions.

use blake2_rfc::blake2b::{Blake2b, Blake2bResult};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crypto_api_chachapoly::{ChaCha20Ietf, ChachaPolyIetf};
use ff::{PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr};
use rand::{OsRng, Rng};
use sapling_crypto::{
    jubjub::{
        edwards,
        fs::{Fs, FsRepr},
        PrimeOrder, ToUniform, Unknown,
    },
    primitives::{Diversifier, Note, PaymentAddress},
};
use std::fmt;
use std::str;

use crate::{keys::OutgoingViewingKey, JUBJUB};

pub const KDF_SAPLING_PERSONALIZATION: &'static [u8; 16] = b"Zcash_SaplingKDF";
pub const PRF_OCK_PERSONALIZATION: &'static [u8; 16] = b"Zcash_Derive_ock";

const COMPACT_NOTE_SIZE: usize = (
    1  + // version
    11 + // diversifier
    8  + // value
    32
    // rcv
);
const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + 512;
const OUT_PLAINTEXT_SIZE: usize = (
    32 + // pk_d
    32
    // esk
);
const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;
const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + 16;

/// Format a byte array as a colon-delimited hex string.
///
/// Source: https://github.com/tendermint/signatory
/// License: MIT / Apache 2.0
fn fmt_colon_delimited_hex<B>(f: &mut fmt::Formatter<'_>, bytes: B) -> fmt::Result
where
    B: AsRef<[u8]>,
{
    let len = bytes.as_ref().len();

    for (i, byte) in bytes.as_ref().iter().enumerate() {
        write!(f, "{:02x}", byte)?;

        if i != len - 1 {
            write!(f, ":")?;
        }
    }

    Ok(())
}

/// An unencrypted memo received alongside a shielded note in a Zcash transaction.
#[derive(Clone)]
pub struct Memo([u8; 512]);

impl fmt::Debug for Memo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Memo(")?;
        match self.to_utf8() {
            Some(Ok(memo)) => write!(f, "{}", memo)?,
            _ => fmt_colon_delimited_hex(f, &self.0[..])?,
        }
        write!(f, ")")
    }
}

impl Default for Memo {
    fn default() -> Self {
        // Empty memo field indication per ZIP 302
        let mut memo = [0u8; 512];
        memo[0] = 0xF6;
        Memo(memo)
    }
}

impl PartialEq for Memo {
    fn eq(&self, rhs: &Memo) -> bool {
        &self.0[..] == &rhs.0[..]
    }
}

impl Memo {
    /// Returns a `Memo` containing the given slice, appending with zero bytes if
    /// necessary, or `None` if the slice is too long. If the slice is empty,
    /// `Memo::default` is returned.
    pub fn from_bytes(memo: &[u8]) -> Option<Memo> {
        if memo.is_empty() {
            Some(Memo::default())
        } else if memo.len() <= 512 {
            let mut data = [0; 512];
            data[0..memo.len()].copy_from_slice(memo);
            Some(Memo(data))
        } else {
            // memo is too long
            None
        }
    }

    /// Returns a `Memo` containing the given string, or `None` if the string is too long.
    pub fn from_str(memo: &str) -> Option<Memo> {
        Memo::from_bytes(memo.as_bytes())
    }

    /// Returns the underlying bytes of the `Memo`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Returns:
    /// - `None` if the memo is not text
    /// - `Some(Ok(memo))` if the memo contains a valid UTF-8 string
    /// - `Some(Err(e))` if the memo contains invalid UTF-8
    pub fn to_utf8(&self) -> Option<Result<String, str::Utf8Error>> {
        // Check if it is a text or binary memo
        if self.0[0] < 0xF5 {
            // Drop trailing zeroes
            let mut data = &self.0[..];
            while let Some((0, next)) = data.split_last() {
                data = next;
            }
            // Check if it is valid UTF8
            Some(str::from_utf8(data).map(|memo| memo.to_owned()))
        } else {
            None
        }
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

/// Sapling key agreement for note encryption.
///
/// Implements section 5.4.4.3 of the Zcash Protocol Specification.
pub fn sapling_ka_agree<'a, P>(esk: &Fs, pk_d: &'a P) -> [u8; 32]
where
    edwards::Point<Bls12, Unknown>: From<&'a P>,
{
    let p: edwards::Point<Bls12, Unknown> = pk_d.into();

    // Multiply by 8
    let p = p.mul_by_cofactor(&JUBJUB);

    // Multiply by esk
    let p = p.mul(*esk, &JUBJUB);

    // Produce result
    let mut result = [0; 32];
    p.write(&mut result[..]).expect("length is not 32 bytes");
    result
}

/// Sapling KDF for note encryption.
///
/// Implements section 5.4.4.4 of the Zcash Protocol Specification.
fn kdf_sapling(dhsecret: &[u8], epk: &edwards::Point<Bls12, PrimeOrder>) -> Blake2bResult {
    let mut input = [0u8; 64];
    input[0..32].copy_from_slice(&dhsecret);
    epk.write(&mut input[32..64]).unwrap();

    let mut h = Blake2b::with_params(32, &[], &[], KDF_SAPLING_PERSONALIZATION);
    h.update(&input);
    h.finalize()
}

/// Sapling PRF^ock.
///
/// Implemented per section 5.4.2 of the Zcash Protocol Specification.
fn prf_ock(
    ovk: &OutgoingViewingKey,
    cv: &edwards::Point<Bls12, Unknown>,
    cmu: &Fr,
    epk: &edwards::Point<Bls12, PrimeOrder>,
) -> Blake2bResult {
    let mut ock_input = [0u8; 128];
    ock_input[0..32].copy_from_slice(&ovk.0);
    cv.write(&mut ock_input[32..64]).unwrap();
    cmu.into_repr().write_le(&mut ock_input[64..96]).unwrap();
    epk.write(&mut ock_input[96..128]).unwrap();

    let mut h = Blake2b::with_params(32, &[], &[], PRF_OCK_PERSONALIZATION);
    h.update(&ock_input);
    h.finalize()
}

/// An API for encrypting Sapling notes.
///
/// This struct provides a safe API for encrypting Sapling notes. In particular, it
/// enforces that fresh ephemeral keys are used for every note, and that the ciphertexts
/// are consistent with each other.
///
/// Implements section 4.17.1 of the Zcash Protocol Specification.
///
/// # Examples
///
/// ```
/// extern crate pairing;
/// extern crate rand;
/// extern crate sapling_crypto;
///
/// use pairing::bls12_381::Bls12;
/// use rand::{OsRng, Rand};
/// use sapling_crypto::{
///     jubjub::fs::Fs,
///     primitives::{Diversifier, PaymentAddress, ValueCommitment},
/// };
/// use zcash_primitives::{
///     keys::OutgoingViewingKey,
///     note_encryption::{Memo, SaplingNoteEncryption},
///     JUBJUB,
/// };
///
/// let mut rng = OsRng::new().unwrap();
///
/// let diversifier = Diversifier([0; 11]);
/// let pk_d = diversifier.g_d::<Bls12>(&JUBJUB).unwrap();
/// let to = PaymentAddress {
///     pk_d,
///     diversifier,
/// };
/// let ovk = OutgoingViewingKey([0; 32]);
///
/// let value = 1000;
/// let rcv = Fs::rand(&mut rng);
/// let cv = ValueCommitment::<Bls12> {
///     value,
///     randomness: rcv.clone(),
/// };
/// let note = to.create_note(value, rcv, &JUBJUB).unwrap();
/// let cmu = note.cm(&JUBJUB);
///
/// let enc = SaplingNoteEncryption::new(ovk, note, to, Memo::default());
/// let encCiphertext = enc.encrypt_note_plaintext();
/// let outCiphertext = enc.encrypt_outgoing_plaintext(&cv.cm(&JUBJUB).into(), &cmu);
/// ```
pub struct SaplingNoteEncryption {
    epk: edwards::Point<Bls12, PrimeOrder>,
    esk: Fs,
    note: Note<Bls12>,
    to: PaymentAddress<Bls12>,
    memo: Memo,
    ovk: OutgoingViewingKey,
}

impl SaplingNoteEncryption {
    /// Creates a new encryption context for the given note.
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

    /// Exposes the ephemeral secret key being used to encrypt this note.
    pub fn esk(&self) -> &Fs {
        &self.esk
    }

    /// Exposes the ephemeral public key being used to encrypt this note.
    pub fn epk(&self) -> &edwards::Point<Bls12, PrimeOrder> {
        &self.epk
    }

    /// Generates `encCiphertext` for this note.
    pub fn encrypt_note_plaintext(&self) -> [u8; ENC_CIPHERTEXT_SIZE] {
        let shared_secret = sapling_ka_agree(&self.esk, &self.to.pk_d);
        let key = kdf_sapling(&shared_secret, &self.epk);

        let mut input = Vec::with_capacity(NOTE_PLAINTEXT_SIZE);
        input.push(1);
        input.extend_from_slice(&self.to.diversifier.0);
        (&mut input)
            .write_u64::<LittleEndian>(self.note.value)
            .unwrap();
        self.note.r.into_repr().write_le(&mut input).unwrap();
        input.extend_from_slice(&self.memo.0);
        assert_eq!(input.len(), NOTE_PLAINTEXT_SIZE);

        let mut output = [0u8; ENC_CIPHERTEXT_SIZE];
        assert_eq!(
            ChachaPolyIetf::aead_cipher()
                .seal_to(&mut output, &input, &[], &key.as_bytes(), &[0u8; 12])
                .unwrap(),
            ENC_CIPHERTEXT_SIZE
        );

        output
    }

    /// Generates `outCiphertext` for this note.
    pub fn encrypt_outgoing_plaintext(
        &self,
        cv: &edwards::Point<Bls12, Unknown>,
        cmu: &Fr,
    ) -> [u8; OUT_CIPHERTEXT_SIZE] {
        let key = prf_ock(&self.ovk, &cv, &cmu, &self.epk);

        let mut buf = [0u8; OUT_CIPHERTEXT_SIZE];
        self.note.pk_d.write(&mut buf[0..32]).unwrap();
        self.esk
            .into_repr()
            .write_le(&mut buf[32..OUT_PLAINTEXT_SIZE])
            .unwrap();

        assert_eq!(
            ChachaPolyIetf::aead_cipher()
                .seal(
                    &mut buf,
                    OUT_PLAINTEXT_SIZE,
                    &[],
                    key.as_bytes(),
                    &[0u8; 12]
                )
                .unwrap(),
            OUT_CIPHERTEXT_SIZE
        );
        buf
    }
}

fn parse_note_plaintext_minus_memo(
    ivk: &Fs,
    cmu: &Fr,
    plaintext: &[u8],
) -> Option<(Note<Bls12>, PaymentAddress<Bls12>)> {
    let mut d = [0u8; 11];
    d.copy_from_slice(&plaintext[1..12]);

    let v = (&plaintext[12..20]).read_u64::<LittleEndian>().ok()?;

    let mut rcm = FsRepr::default();
    rcm.read_le(&plaintext[20..COMPACT_NOTE_SIZE]).ok()?;
    let rcm = Fs::from_repr(rcm).ok()?;

    let diversifier = Diversifier(d);
    let pk_d = diversifier
        .g_d::<Bls12>(&JUBJUB)?
        .mul(ivk.into_repr(), &JUBJUB);

    let to = PaymentAddress { pk_d, diversifier };
    let note = to.create_note(v, rcm, &JUBJUB).unwrap();

    if note.cm(&JUBJUB) != *cmu {
        // Published commitment doesn't match calculated commitment
        return None;
    }

    Some((note, to))
}

/// Trial decryption of the full note plaintext by the recipient.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ivk`.
/// If successful, the corresponding Sapling note and memo are returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements section 4.17.2 of the Zcash Protocol Specification.
pub fn try_sapling_note_decryption(
    ivk: &Fs,
    epk: &edwards::Point<Bls12, PrimeOrder>,
    cmu: &Fr,
    enc_ciphertext: &[u8],
) -> Option<(Note<Bls12>, PaymentAddress<Bls12>, Memo)> {
    assert_eq!(enc_ciphertext.len(), ENC_CIPHERTEXT_SIZE);

    let shared_secret = sapling_ka_agree(ivk, epk);
    let key = kdf_sapling(&shared_secret, &epk);

    let mut plaintext = vec![0; ENC_CIPHERTEXT_SIZE];
    assert_eq!(
        ChachaPolyIetf::aead_cipher()
            .open_to(
                &mut plaintext,
                &enc_ciphertext,
                &[],
                key.as_bytes(),
                &[0u8; 12]
            )
            .ok()?,
        NOTE_PLAINTEXT_SIZE
    );

    let (note, to) = parse_note_plaintext_minus_memo(ivk, cmu, &plaintext)?;

    let mut memo = [0u8; 512];
    memo.copy_from_slice(&plaintext[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE]);

    Some((note, to, Memo(memo)))
}

/// Trial decryption of the compact note plaintext by the recipient for light clients.
///
/// Attempts to decrypt and validate the first 52 bytes of `enc_ciphertext` using the
/// given `ivk`. If successful, the corresponding Sapling note is returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements the procedure specified in [`ZIP 307`].
///
/// [`ZIP 307`]: https://github.com/zcash/zips/pull/226
pub fn try_sapling_compact_note_decryption(
    ivk: &Fs,
    epk: &edwards::Point<Bls12, PrimeOrder>,
    cmu: &Fr,
    enc_ciphertext: &[u8],
) -> Option<(Note<Bls12>, PaymentAddress<Bls12>)> {
    assert_eq!(enc_ciphertext.len(), COMPACT_NOTE_SIZE);

    let shared_secret = sapling_ka_agree(ivk, epk);
    let key = kdf_sapling(&shared_secret, &epk);

    // Prefix plaintext with 64 zero-bytes to skip over Poly1305 keying output
    const CHACHA20_BLOCK_SIZE: usize = 64;
    let mut plaintext = Vec::with_capacity(CHACHA20_BLOCK_SIZE + COMPACT_NOTE_SIZE);
    plaintext.extend_from_slice(&[0; CHACHA20_BLOCK_SIZE]);
    plaintext.extend_from_slice(&enc_ciphertext[0..COMPACT_NOTE_SIZE]);
    assert_eq!(
        ChaCha20Ietf::cipher()
            .decrypt(
                &mut plaintext,
                CHACHA20_BLOCK_SIZE + COMPACT_NOTE_SIZE,
                key.as_bytes(),
                &[0u8; 12],
            )
            .ok()?,
        CHACHA20_BLOCK_SIZE + COMPACT_NOTE_SIZE
    );

    parse_note_plaintext_minus_memo(ivk, cmu, &plaintext[CHACHA20_BLOCK_SIZE..])
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ovk`.
/// If successful, the corresponding Sapling note and memo are returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements section 4.17.3 of the Zcash Protocol Specification.
pub fn try_sapling_output_recovery(
    ovk: &OutgoingViewingKey,
    cv: &edwards::Point<Bls12, Unknown>,
    cmu: &Fr,
    epk: &edwards::Point<Bls12, PrimeOrder>,
    enc_ciphertext: &[u8],
    out_ciphertext: &[u8],
) -> Option<(Note<Bls12>, PaymentAddress<Bls12>, Memo)> {
    assert_eq!(enc_ciphertext.len(), ENC_CIPHERTEXT_SIZE);
    assert_eq!(out_ciphertext.len(), OUT_CIPHERTEXT_SIZE);

    let ock = prf_ock(&ovk, &cv, &cmu, &epk);

    let mut op = vec![0; OUT_CIPHERTEXT_SIZE];
    assert_eq!(
        ChachaPolyIetf::aead_cipher()
            .open_to(&mut op, &out_ciphertext, &[], ock.as_bytes(), &[0u8; 12])
            .ok()?,
        OUT_PLAINTEXT_SIZE
    );

    let pk_d = edwards::Point::<Bls12, _>::read(&op[0..32], &JUBJUB)
        .ok()?
        .as_prime_order(&JUBJUB)?;

    let mut esk = FsRepr::default();
    esk.read_le(&op[32..OUT_PLAINTEXT_SIZE]).ok()?;
    let esk = Fs::from_repr(esk).ok()?;

    let shared_secret = sapling_ka_agree(&esk, &pk_d);
    let key = kdf_sapling(&shared_secret, &epk);

    let mut plaintext = vec![0; ENC_CIPHERTEXT_SIZE];
    assert_eq!(
        ChachaPolyIetf::aead_cipher()
            .open_to(
                &mut plaintext,
                &enc_ciphertext,
                &[],
                key.as_bytes(),
                &[0u8; 12]
            )
            .ok()?,
        NOTE_PLAINTEXT_SIZE
    );

    let mut d = [0u8; 11];
    d.copy_from_slice(&plaintext[1..12]);

    let v = (&plaintext[12..20]).read_u64::<LittleEndian>().ok()?;

    let mut rcm = FsRepr::default();
    rcm.read_le(&plaintext[20..COMPACT_NOTE_SIZE]).ok()?;
    let rcm = Fs::from_repr(rcm).ok()?;

    let mut memo = [0u8; 512];
    memo.copy_from_slice(&plaintext[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE]);

    let diversifier = Diversifier(d);
    if diversifier
        .g_d::<Bls12>(&JUBJUB)?
        .mul(esk.into_repr(), &JUBJUB)
        != *epk
    {
        // Published epk doesn't match calculated epk
        return None;
    }

    let to = PaymentAddress { pk_d, diversifier };
    let note = to.create_note(v, rcm, &JUBJUB).unwrap();

    if note.cm(&JUBJUB) != *cmu {
        // Published commitment doesn't match calculated commitment
        return None;
    }

    Some((note, to, Memo(memo)))
}

#[cfg(test)]
mod tests {
    use ff::{PrimeField, PrimeFieldRepr};
    use pairing::bls12_381::{Bls12, Fr, FrRepr};
    use rand::{thread_rng, Rand, Rng};
    use sapling_crypto::{
        jubjub::{
            edwards,
            fs::{Fs, FsRepr},
            PrimeOrder, Unknown,
        },
        primitives::{Diversifier, PaymentAddress, ValueCommitment},
    };

    use super::{
        kdf_sapling, prf_ock, sapling_ka_agree, try_sapling_compact_note_decryption,
        try_sapling_note_decryption, try_sapling_output_recovery, Memo, SaplingNoteEncryption,
        COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE,
    };
    use crate::{keys::OutgoingViewingKey, JUBJUB};

    #[test]
    fn memo_from_str() {
        assert_eq!(
            Memo::from_str("").unwrap(),
            Memo([
                0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ])
        );
        assert_eq!(
            Memo::from_str(
                "thiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiis \
                 iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiis \
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
                 veeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeryyyyyyyyyyyyyyyyyyyyyyyyyy \
                 looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong \
                 meeeeeeeeeeeeeeeeeeemooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo \
                 but it's just short enough"
            )
            .unwrap(),
            Memo([
                0x74, 0x68, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x73, 0x20, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
                0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x73, 0x20, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                0x61, 0x61, 0x61, 0x61, 0x20, 0x76, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
                0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
                0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
                0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
                0x65, 0x65, 0x72, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79,
                0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79,
                0x79, 0x20, 0x6c, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
                0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
                0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
                0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
                0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
                0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6e, 0x67, 0x20, 0x6d,
                0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
                0x65, 0x65, 0x65, 0x65, 0x65, 0x6d, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
                0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
                0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
                0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
                0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x20, 0x62, 0x75, 0x74, 0x20,
                0x69, 0x74, 0x27, 0x73, 0x20, 0x6a, 0x75, 0x73, 0x74, 0x20, 0x73, 0x68, 0x6f, 0x72,
                0x74, 0x20, 0x65, 0x6e, 0x6f, 0x75, 0x67, 0x68
            ])
        );
        assert!(Memo::from_str(
            "thiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiis \
             iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiis \
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
             veeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeryyyyyyyyyyyyyyyyyyyyyyyyyy \
             looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong \
             meeeeeeeeeeeeeeeeeeemooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo \
             but it's now a bit too long"
        )
        .is_none());
    }

    #[test]
    fn memo_to_utf8() {
        let memo = Memo::from_str("Test memo").unwrap();
        assert_eq!(memo.to_utf8(), Some(Ok("Test memo".to_owned())));
        assert_eq!(Memo::default().to_utf8(), None);
    }

    fn random_enc_ciphertext(
        mut rng: &mut Rng,
    ) -> (
        OutgoingViewingKey,
        Fs,
        edwards::Point<Bls12, Unknown>,
        Fr,
        edwards::Point<Bls12, PrimeOrder>,
        [u8; ENC_CIPHERTEXT_SIZE],
        [u8; OUT_CIPHERTEXT_SIZE],
    ) {
        let diversifier = Diversifier([0; 11]);
        let ivk = Fs::rand(&mut rng);
        let pk_d = diversifier.g_d::<Bls12>(&JUBJUB).unwrap().mul(ivk, &JUBJUB);
        let pa = PaymentAddress { diversifier, pk_d };

        // Construct the value commitment for the proof instance
        let value = 100;
        let value_commitment = ValueCommitment::<Bls12> {
            value,
            randomness: Fs::rand(&mut rng),
        };
        let cv = value_commitment.cm(&JUBJUB).into();

        let note = pa.create_note(value, Fs::rand(&mut rng), &JUBJUB).unwrap();
        let cmu = note.cm(&JUBJUB);

        let ovk = OutgoingViewingKey([0; 32]);
        let ne = SaplingNoteEncryption::new(ovk, note, pa, Memo([0; 512]));
        let epk = ne.epk();
        let enc_ciphertext = ne.encrypt_note_plaintext();
        let out_ciphertext = ne.encrypt_outgoing_plaintext(&cv, &cmu);

        assert!(try_sapling_note_decryption(&ivk, epk, &cmu, &enc_ciphertext).is_some());
        assert!(try_sapling_compact_note_decryption(
            &ivk,
            epk,
            &cmu,
            &enc_ciphertext[..COMPACT_NOTE_SIZE]
        )
        .is_some());
        assert!(try_sapling_output_recovery(
            &ovk,
            &cv,
            &cmu,
            &epk,
            &enc_ciphertext,
            &out_ciphertext
        )
        .is_some());

        (
            ovk,
            ivk,
            cv,
            cmu,
            epk.clone(),
            enc_ciphertext,
            out_ciphertext,
        )
    }

    #[test]
    fn decryption_with_invalid_ivk() {
        let mut rng = thread_rng();

        let (_, _, _, cmu, epk, enc_ciphertext, _) = random_enc_ciphertext(&mut rng);

        assert_eq!(
            try_sapling_note_decryption(&Fs::rand(&mut rng), &epk, &cmu, &enc_ciphertext),
            None
        );
    }

    #[test]
    fn decryption_with_invalid_epk() {
        let mut rng = thread_rng();

        let (_, ivk, _, cmu, _, enc_ciphertext, _) = random_enc_ciphertext(&mut rng);

        assert_eq!(
            try_sapling_note_decryption(
                &ivk,
                &edwards::Point::<Bls12, _>::rand(&mut rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
                &cmu,
                &enc_ciphertext
            ),
            None
        );
    }

    #[test]
    fn decryption_with_invalid_cmu() {
        let mut rng = thread_rng();

        let (_, ivk, _, _, epk, enc_ciphertext, _) = random_enc_ciphertext(&mut rng);

        assert_eq!(
            try_sapling_note_decryption(&ivk, &epk, &Fr::rand(&mut rng), &enc_ciphertext),
            None
        );
    }

    #[test]
    fn decryption_with_invalid_tag() {
        let mut rng = thread_rng();

        let (_, ivk, _, cmu, epk, mut enc_ciphertext, _) = random_enc_ciphertext(&mut rng);

        enc_ciphertext[ENC_CIPHERTEXT_SIZE - 1] ^= 0xff;
        assert_eq!(
            try_sapling_note_decryption(&ivk, &epk, &cmu, &enc_ciphertext),
            None
        );
    }

    #[test]
    fn compact_decryption_with_invalid_ivk() {
        let mut rng = thread_rng();

        let (_, _, _, cmu, epk, enc_ciphertext, _) = random_enc_ciphertext(&mut rng);

        assert_eq!(
            try_sapling_compact_note_decryption(
                &Fs::rand(&mut rng),
                &epk,
                &cmu,
                &enc_ciphertext[..COMPACT_NOTE_SIZE]
            ),
            None
        );
    }

    #[test]
    fn compact_decryption_with_invalid_epk() {
        let mut rng = thread_rng();

        let (_, ivk, _, cmu, _, enc_ciphertext, _) = random_enc_ciphertext(&mut rng);

        assert_eq!(
            try_sapling_compact_note_decryption(
                &ivk,
                &edwards::Point::<Bls12, _>::rand(&mut rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
                &cmu,
                &enc_ciphertext[..COMPACT_NOTE_SIZE]
            ),
            None
        );
    }

    #[test]
    fn compact_decryption_with_invalid_cmu() {
        let mut rng = thread_rng();

        let (_, ivk, _, _, epk, enc_ciphertext, _) = random_enc_ciphertext(&mut rng);

        assert_eq!(
            try_sapling_compact_note_decryption(
                &ivk,
                &epk,
                &Fr::rand(&mut rng),
                &enc_ciphertext[..COMPACT_NOTE_SIZE]
            ),
            None
        );
    }

    #[test]
    fn compact_decryption_with_invalid_diversifier() {
        let mut rng = thread_rng();

        let (_, ivk, _, cmu, epk, mut enc_ciphertext, _) = random_enc_ciphertext(&mut rng);

        // In compact decryption, this will result in an altered diversifier
        enc_ciphertext[1] ^= 0xff;
        assert_eq!(
            try_sapling_compact_note_decryption(
                &ivk,
                &epk,
                &cmu,
                &enc_ciphertext[..COMPACT_NOTE_SIZE]
            ),
            None
        );
    }

    #[test]
    fn recovery_with_invalid_ovk() {
        let mut rng = thread_rng();

        let (mut ovk, _, cv, cmu, epk, enc_ciphertext, out_ciphertext) =
            random_enc_ciphertext(&mut rng);

        ovk.0[0] ^= 0xff;
        assert_eq!(
            try_sapling_output_recovery(&ovk, &cv, &cmu, &epk, &enc_ciphertext, &out_ciphertext),
            None
        );
    }

    #[test]
    fn recovery_with_invalid_cv() {
        let mut rng = thread_rng();

        let (ovk, _, _, cmu, epk, enc_ciphertext, out_ciphertext) = random_enc_ciphertext(&mut rng);

        assert_eq!(
            try_sapling_output_recovery(
                &ovk,
                &edwards::Point::<Bls12, _>::rand(&mut rng, &JUBJUB),
                &cmu,
                &epk,
                &enc_ciphertext,
                &out_ciphertext
            ),
            None
        );
    }

    #[test]
    fn recovery_with_invalid_cmu() {
        let mut rng = thread_rng();

        let (ovk, _, cv, _, epk, enc_ciphertext, out_ciphertext) = random_enc_ciphertext(&mut rng);

        assert_eq!(
            try_sapling_output_recovery(
                &ovk,
                &cv,
                &Fr::rand(&mut rng),
                &epk,
                &enc_ciphertext,
                &out_ciphertext
            ),
            None
        );
    }

    #[test]
    fn recovery_with_invalid_epk() {
        let mut rng = thread_rng();

        let (ovk, _, cv, cmu, _, enc_ciphertext, out_ciphertext) = random_enc_ciphertext(&mut rng);

        assert_eq!(
            try_sapling_output_recovery(
                &ovk,
                &cv,
                &cmu,
                &edwards::Point::<Bls12, _>::rand(&mut rng, &JUBJUB).mul_by_cofactor(&JUBJUB),
                &enc_ciphertext,
                &out_ciphertext
            ),
            None
        );
    }

    #[test]
    fn recovery_with_invalid_enc_tag() {
        let mut rng = thread_rng();

        let (ovk, _, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
            random_enc_ciphertext(&mut rng);

        enc_ciphertext[ENC_CIPHERTEXT_SIZE - 1] ^= 0xff;
        assert_eq!(
            try_sapling_output_recovery(&ovk, &cv, &cmu, &epk, &enc_ciphertext, &out_ciphertext),
            None
        );
    }

    #[test]
    fn recovery_with_invalid_out_tag() {
        let mut rng = thread_rng();

        let (ovk, _, cv, cmu, epk, enc_ciphertext, mut out_ciphertext) =
            random_enc_ciphertext(&mut rng);

        out_ciphertext[OUT_CIPHERTEXT_SIZE - 1] ^= 0xff;
        assert_eq!(
            try_sapling_output_recovery(&ovk, &cv, &cmu, &epk, &enc_ciphertext, &out_ciphertext),
            None
        );
    }

    #[test]
    fn test_vectors() {
        let test_vectors = crate::test_vectors::note_encryption::make_test_vectors();

        macro_rules! read_fr {
            ($field:expr) => {{
                let mut repr = FrRepr::default();
                repr.read_le(&$field[..]).unwrap();
                Fr::from_repr(repr).unwrap()
            }};
        }

        macro_rules! read_fs {
            ($field:expr) => {{
                let mut repr = FsRepr::default();
                repr.read_le(&$field[..]).unwrap();
                Fs::from_repr(repr).unwrap()
            }};
        }

        macro_rules! read_point {
            ($field:expr) => {
                edwards::Point::<Bls12, _>::read(&$field[..], &JUBJUB).unwrap()
            };
        }

        for tv in test_vectors {
            //
            // Load the test vector components
            //

            let ivk = read_fs!(tv.ivk);
            let pk_d = read_point!(tv.default_pk_d)
                .as_prime_order(&JUBJUB)
                .unwrap();
            let rcm = read_fs!(tv.rcm);
            let cv = read_point!(tv.cv);
            let cmu = read_fr!(tv.cmu);
            let esk = read_fs!(tv.esk);
            let epk = read_point!(tv.epk).as_prime_order(&JUBJUB).unwrap();

            //
            // Test the individual components
            //

            let shared_secret = sapling_ka_agree(&esk, &pk_d);
            assert_eq!(shared_secret, tv.shared_secret);

            let k_enc = kdf_sapling(&shared_secret, &epk);
            assert_eq!(k_enc.as_bytes(), tv.k_enc);

            let ovk = OutgoingViewingKey(tv.ovk);
            let ock = prf_ock(&ovk, &cv, &cmu, &epk);
            assert_eq!(ock.as_bytes(), tv.ock);

            let to = PaymentAddress {
                pk_d,
                diversifier: Diversifier(tv.default_d),
            };
            let note = to.create_note(tv.v, rcm, &JUBJUB).unwrap();
            assert_eq!(note.cm(&JUBJUB), cmu);

            //
            // Test decryption
            // (Tested first because it only requires immutable references.)
            //

            match try_sapling_note_decryption(&ivk, &epk, &cmu, &tv.c_enc) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                    assert_eq!(&decrypted_memo.0[..], &tv.memo[..]);
                }
                None => panic!("Note decryption failed"),
            }

            match try_sapling_compact_note_decryption(
                &ivk,
                &epk,
                &cmu,
                &tv.c_enc[..COMPACT_NOTE_SIZE],
            ) {
                Some((decrypted_note, decrypted_to)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                }
                None => panic!("Compact note decryption failed"),
            }

            match try_sapling_output_recovery(&ovk, &cv, &cmu, &epk, &tv.c_enc, &tv.c_out) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                    assert_eq!(&decrypted_memo.0[..], &tv.memo[..]);
                }
                None => panic!("Output recovery failed"),
            }

            //
            // Test encryption
            //

            let mut ne = SaplingNoteEncryption::new(ovk, note, to, Memo(tv.memo));
            // Swap in the ephemeral keypair from the test vectors
            ne.esk = esk;
            ne.epk = epk;

            assert_eq!(&ne.encrypt_note_plaintext()[..], &tv.c_enc[..]);
            assert_eq!(&ne.encrypt_outgoing_plaintext(&cv, &cmu)[..], &tv.c_out[..]);
        }
    }
}
