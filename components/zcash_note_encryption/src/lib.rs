//! Implementation of in-band secret distribution abstractions
//! for Zcash transactions. The implementations here provide
//! functionality that is shared between the Sapling and Orchard
//! protocols.

use crypto_api_chachapoly::{ChaCha20Ietf, ChachaPolyIetf};
use rand_core::RngCore;

pub const COMPACT_NOTE_SIZE: usize = 1 + // version
    11 + // diversifier
    8  + // value
    32; // rcv
pub const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + 512;
pub const OUT_PLAINTEXT_SIZE: usize = 32 + // pk_d
    32; // esk
pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;
pub const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + 16;

/// A symmetric key that can be used to recover a single Sapling or Orchard output.
pub struct OutgoingCipherKey(pub [u8; 32]);

impl From<[u8; 32]> for OutgoingCipherKey {
    fn from(ock: [u8; 32]) -> Self {
        OutgoingCipherKey(ock)
    }
}

impl AsRef<[u8]> for OutgoingCipherKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

//FIXME: use constant-time checks for equality
#[derive(Eq, PartialEq)]
pub struct EphemeralKeyBytes(pub [u8; 32]);

impl From<[u8; 32]> for EphemeralKeyBytes {
    fn from(value: [u8; 32]) -> EphemeralKeyBytes {
        EphemeralKeyBytes(value)
    }
}

pub struct NotePlaintextBytes(pub [u8; NOTE_PLAINTEXT_SIZE]);
pub struct OutPlaintextBytes(pub [u8; OUT_PLAINTEXT_SIZE]);

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum EpkValidity {
    Valid,
    Invalid,
}

pub trait Domain {
    type EphemeralSecretKey;
    type EphemeralPublicKey;
    type SharedSecret;
    type SymmetricKey: AsRef<[u8]>;
    type Note;
    type Recipient;
    type DiversifiedTransmissionKey;
    type IncomingViewingKey;
    type OutgoingViewingKey;
    type ValueCommitment;
    type NoteCommitment;
    type ExtractedCommitment: Eq;
    type Memo;

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey>;

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey;

    fn ka_derive_public(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> Self::EphemeralPublicKey;

    fn ka_agree_enc(
        esk: &Self::EphemeralSecretKey,
        pk_d: &Self::DiversifiedTransmissionKey,
    ) -> Self::SharedSecret;

    fn ka_agree_dec(
        ivk: &Self::IncomingViewingKey,
        epk: &Self::EphemeralPublicKey,
    ) -> Self::SharedSecret;

    fn kdf(secret: Self::SharedSecret, epk: &Self::EphemeralPublicKey) -> Self::SymmetricKey;

    // for right now, we just need `recipient` to get `d`; in the future when we
    // can get that from a Sapling note, the recipient parameter will be able
    // to be removed.
    fn to_note_plaintext_bytes(
        note: &Self::Note,
        recipient: &Self::Recipient,
        memo: &Self::Memo,
    ) -> NotePlaintextBytes;

    fn get_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cm: &Self::NoteCommitment,
        epk: &Self::EphemeralPublicKey,
    ) -> OutgoingCipherKey;

    fn to_outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes;

    fn to_epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes;

    fn check_epk_bytes<F: Fn(&Self::EphemeralSecretKey) -> EpkValidity>(
        note: &Self::Note,
        check: F,
    ) -> EpkValidity;

    fn extract_note_commitment(note: &Self::Note) -> Self::ExtractedCommitment;

    fn parse_note_plaintext_without_memo(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)>;

    // &self is passed here in anticipation of future changes
    // to memo handling where the memos may no longer be
    // part of the note plaintext.
    fn extract_memo(&self, plaintext: &[u8]) -> Self::Memo;
}

pub trait ShieldedOutput<'a, D: Domain> {
    fn ivk(&'a self) -> &'a D::IncomingViewingKey;
    fn epk(&'a self) -> &'a D::EphemeralPublicKey;
    fn cmstar(&'a self) -> &'a D::ExtractedCommitment;
}

/// A struct containing context required for encrypting Sapling and Orchard notes.
///
/// This struct provides a safe API for encrypting Sapling and Orchard notes. In particular, it
/// enforces that fresh ephemeral keys are used for every note, and that the ciphertexts are
/// consistent with each other.
///
/// Implements section 4.17.1 of the Zcash Protocol Specification.
/// NB: the example code is only covering the pre-Canopy case.
///
/// # Examples
///
/// ```
/// extern crate ff;
/// extern crate rand_core;
/// extern crate zcash_primitives;
///
/// use ff::Field;
/// use rand_core::OsRng;
/// use zcash_primitives::{
///     consensus::TestNetwork,
///     sapling::{
///         keys::{OutgoingViewingKey, prf_expand},
///         note_encryption::{Memo, sapling_note_encryption},
///         Diversifier, PaymentAddress, Rseed, ValueCommitment
///     },
/// };
///
/// let mut rng = OsRng;
///
/// let diversifier = Diversifier([0; 11]);
/// let pk_d = diversifier.g_d().unwrap();
/// let to = PaymentAddress::from_parts(diversifier, pk_d).unwrap();
/// let ovk = Some(OutgoingViewingKey([0; 32]));
///
/// let value = 1000;
/// let rcv = jubjub::Fr::random(&mut rng);
/// let cv = ValueCommitment {
///     value,
///     randomness: rcv.clone(),
/// };
/// let rcm = jubjub::Fr::random(&mut rng);
/// let note = to.create_note(value, Rseed::BeforeZip212(rcm)).unwrap();
/// let cmu = note.cmu();
///
/// let mut enc = sapling_note_encryption::<_, TestNetwork>(ovk, note, to, Memo::default(), &mut rng);
/// let encCiphertext = enc.encrypt_note_plaintext();
/// let outCiphertext = enc.encrypt_outgoing_plaintext(&cv.commitment().into(), &cmu, &mut rng);
/// ```
pub struct NoteEncryption<D: Domain> {
    epk: D::EphemeralPublicKey,
    esk: D::EphemeralSecretKey,
    note: D::Note,
    to: D::Recipient,
    memo: D::Memo,
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<D::OutgoingViewingKey>,
}

impl<D: Domain> NoteEncryption<D> {
    /// Construct a new note encryption context for the specified note,
    /// recipient, and memo.
    pub fn new(
        ovk: Option<D::OutgoingViewingKey>,
        note: D::Note,
        to: D::Recipient,
        memo: D::Memo,
    ) -> Self {
        let esk = D::derive_esk(&note).expect("ZIP 212 is active.");
        Self::new_with_esk(esk, ovk, note, to, memo)
    }

    /// For use only with Sapling.
    pub fn new_with_esk(
        esk: D::EphemeralSecretKey,
        ovk: Option<D::OutgoingViewingKey>,
        note: D::Note,
        to: D::Recipient,
        memo: D::Memo,
    ) -> Self {
        NoteEncryption {
            epk: D::ka_derive_public(&note, &esk),
            esk,
            note,
            to,
            memo,
            ovk,
        }
    }

    /// Exposes the ephemeral secret key being used to encrypt this note.
    pub fn esk(&self) -> &D::EphemeralSecretKey {
        &self.esk
    }

    /// Exposes the ephemeral public key being used to encrypt this note.
    pub fn epk(&self) -> &D::EphemeralPublicKey {
        &self.epk
    }

    /// Generates `encCiphertext` for this note.
    pub fn encrypt_note_plaintext(&self) -> [u8; ENC_CIPHERTEXT_SIZE] {
        let pk_d = D::get_pk_d(&self.note);
        let shared_secret = D::ka_agree_enc(&self.esk, &pk_d);
        let key = D::kdf(shared_secret, &self.epk);
        let input = D::to_note_plaintext_bytes(&self.note, &self.to, &self.memo);

        let mut output = [0u8; ENC_CIPHERTEXT_SIZE];
        assert_eq!(
            ChachaPolyIetf::aead_cipher()
                .seal_to(&mut output, &input.0, &[], key.as_ref(), &[0u8; 12])
                .unwrap(),
            ENC_CIPHERTEXT_SIZE
        );

        output
    }

    /// Generates `outCiphertext` for this note.
    pub fn encrypt_outgoing_plaintext<R: RngCore>(
        &mut self,
        cv: &D::ValueCommitment,
        cm: &D::NoteCommitment,
        rng: &mut R,
    ) -> [u8; OUT_CIPHERTEXT_SIZE] {
        let (ock, input) = if let Some(ovk) = &self.ovk {
            let ock = D::get_ock(ovk, &cv, &cm, &self.epk);
            let input = D::to_outgoing_plaintext_bytes(&self.note, &self.esk);

            (ock, input)
        } else {
            // ovk = ⊥
            let mut ock = OutgoingCipherKey([0; 32]);
            let mut input = [0u8; OUT_PLAINTEXT_SIZE];

            rng.fill_bytes(&mut ock.0);
            rng.fill_bytes(&mut input);

            (ock, OutPlaintextBytes(input))
        };

        let mut output = [0u8; OUT_CIPHERTEXT_SIZE];
        assert_eq!(
            ChachaPolyIetf::aead_cipher()
                .seal_to(&mut output, &input.0, &[], ock.as_ref(), &[0u8; 12])
                .unwrap(),
            OUT_CIPHERTEXT_SIZE
        );

        output
    }
}

/// Trial decryption of the full note plaintext by the recipient.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ivk`.
/// If successful, the corresponding Sapling note and memo are returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements section 4.17.2 of the Zcash Protocol Specification.
pub fn try_note_decryption<D: Domain>(
    domain: &D,
    //output: &ShieldedOutput<D>,
    ivk: &D::IncomingViewingKey,
    epk: &D::EphemeralPublicKey,
    cmstar: &D::ExtractedCommitment,
    enc_ciphertext: &[u8],
) -> Option<(D::Note, D::Recipient, D::Memo)> {
    assert_eq!(enc_ciphertext.len(), ENC_CIPHERTEXT_SIZE);

    let shared_secret = D::ka_agree_dec(ivk, epk);
    let key = D::kdf(shared_secret, epk);

    let mut plaintext = [0; ENC_CIPHERTEXT_SIZE];
    assert_eq!(
        ChachaPolyIetf::aead_cipher()
            .open_to(
                &mut plaintext,
                &enc_ciphertext,
                &[],
                key.as_ref(),
                &[0u8; 12]
            )
            .ok()?,
        NOTE_PLAINTEXT_SIZE
    );

    let (note, to) = parse_note_plaintext_without_memo(domain, ivk, epk, cmstar, &plaintext)?;
    let memo = domain.extract_memo(&plaintext);

    Some((note, to, memo))
}

fn parse_note_plaintext_without_memo<D: Domain>(
    domain: &D,
    ivk: &D::IncomingViewingKey,
    epk: &D::EphemeralPublicKey,
    cmstar: &D::ExtractedCommitment,
    plaintext: &[u8],
) -> Option<(D::Note, D::Recipient)> {
    let (note, to) = domain.parse_note_plaintext_without_memo(ivk, &plaintext)?;

    if &D::extract_note_commitment(&note) != cmstar {
        // Published commitment doesn't match calculated commitment
        return None;
    } else {
        let epk_bytes = D::to_epk_bytes(epk);
        let validity = D::check_epk_bytes(&note, |derived_esk| {
            if D::to_epk_bytes(&D::ka_derive_public(&note, &derived_esk)) == epk_bytes {
                EpkValidity::Valid
            } else {
                EpkValidity::Invalid
            }
        });

        if validity != EpkValidity::Valid {
            return None;
        }
    }

    Some((note, to))
}

/// Trial decryption of the compact note plaintext by the recipient for light clients.
///
/// Attempts to decrypt and validate the first 52 bytes of `enc_ciphertext` using the
/// given `ivk`. If successful, the corresponding Sapling note is returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements the procedure specified in [`ZIP 307`].
///
/// [`ZIP 307`]: https://zips.z.cash/zip-0307
pub fn try_compact_note_decryption<D: Domain>(
    domain: &D,
    ivk: &D::IncomingViewingKey,
    epk: &D::EphemeralPublicKey,
    cmstar: &D::ExtractedCommitment,
    enc_ciphertext: &[u8],
) -> Option<(D::Note, D::Recipient)> {
    assert_eq!(enc_ciphertext.len(), COMPACT_NOTE_SIZE);

    let shared_secret = D::ka_agree_dec(&ivk, epk);
    let key = D::kdf(shared_secret, &epk);

    // Start from block 1 to skip over Poly1305 keying output
    let mut plaintext = [0; COMPACT_NOTE_SIZE];
    plaintext.copy_from_slice(&enc_ciphertext);
    ChaCha20Ietf::xor(key.as_ref(), &[0u8; 12], 1, &mut plaintext);

    parse_note_plaintext_without_memo(domain, ivk, epk, cmstar, &plaintext)
}
