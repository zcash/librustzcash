//! Implementation of in-band secret distribution abstractions
//! for Zcash transactions. The implementations here provide
//! functionality that is shared between the Sapling and Orchard
//! protocols.

use crypto_api_chachapoly::{ChaCha20Ietf, ChachaPolyIetf};
use rand_core::RngCore;
use subtle::{Choice, ConstantTimeEq};

pub const COMPACT_NOTE_SIZE: usize = 1 + // version
    11 + // diversifier
    8  + // value
    32; // rseed (or rcm prior to ZIP 212)
pub const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + 512;
pub const OUT_PLAINTEXT_SIZE: usize = 32 + // pk_d
    32; // esk
pub const AEAD_TAG_SIZE: usize = 16;
pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + AEAD_TAG_SIZE;
pub const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + AEAD_TAG_SIZE;

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

pub struct EphemeralKeyBytes(pub [u8; 32]);

impl AsRef<[u8]> for EphemeralKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for EphemeralKeyBytes {
    fn from(value: [u8; 32]) -> EphemeralKeyBytes {
        EphemeralKeyBytes(value)
    }
}

impl ConstantTimeEq for EphemeralKeyBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

pub struct NotePlaintextBytes(pub [u8; NOTE_PLAINTEXT_SIZE]);
pub struct OutPlaintextBytes(pub [u8; OUT_PLAINTEXT_SIZE]);

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum NoteValidity {
    Valid,
    Invalid,
}

pub trait Domain {
    type EphemeralSecretKey: ConstantTimeEq;
    type EphemeralPublicKey;
    type SharedSecret;
    type SymmetricKey: AsRef<[u8]>;
    type Note;
    type Recipient;
    type DiversifiedTransmissionKey;
    type IncomingViewingKey;
    type OutgoingViewingKey;
    type ValueCommitment;
    type ExtractedCommitment;
    type ExtractedCommitmentBytes: Eq + for<'a> From<&'a Self::ExtractedCommitment>;
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

    fn kdf(secret: Self::SharedSecret, ephemeral_key: &EphemeralKeyBytes) -> Self::SymmetricKey;

    // for right now, we just need `recipient` to get `d`; in the future when we
    // can get that from a Sapling note, the recipient parameter will be able
    // to be removed.
    fn note_plaintext_bytes(
        note: &Self::Note,
        recipient: &Self::Recipient,
        memo: &Self::Memo,
    ) -> NotePlaintextBytes;

    fn derive_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cmstar_bytes: &Self::ExtractedCommitmentBytes,
        ephemeral_key: &EphemeralKeyBytes,
    ) -> OutgoingCipherKey;

    fn outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes;

    fn epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes;

    fn epk(ephemeral_key: &EphemeralKeyBytes) -> Option<Self::EphemeralPublicKey>;

    fn check_epk_bytes<F: Fn(&Self::EphemeralSecretKey) -> NoteValidity>(
        note: &Self::Note,
        check: F,
    ) -> NoteValidity;

    fn cmstar(note: &Self::Note) -> Self::ExtractedCommitment;

    fn parse_note_plaintext_without_memo_ivk(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)>;

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        esk: &Self::EphemeralSecretKey,
        ephemeral_key: &EphemeralKeyBytes,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)>;

    // &self is passed here in anticipation of future changes
    // to memo handling where the memos may no longer be
    // part of the note plaintext.
    fn extract_memo(&self, plaintext: &[u8]) -> Self::Memo;

    fn extract_pk_d(
        out_plaintext: &[u8; OUT_PLAINTEXT_SIZE],
    ) -> Option<Self::DiversifiedTransmissionKey>;

    fn extract_esk(out_plaintext: &[u8; OUT_PLAINTEXT_SIZE]) -> Option<Self::EphemeralSecretKey>;
}

pub trait ShieldedOutput<D: Domain> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes;
    fn cmstar_bytes(&self) -> D::ExtractedCommitmentBytes;
    fn enc_ciphertext(&self) -> &[u8];
}

/// A struct containing context required for encrypting Sapling and Orchard notes.
///
/// This struct provides a safe API for encrypting Sapling and Orchard notes. In particular, it
/// enforces that fresh ephemeral keys are used for every note, and that the ciphertexts are
/// consistent with each other.
///
/// Implements section 4.19 of the
/// [Zcash Protocol Specification](https://zips.z.cash/protocol/nu5.pdf#saplingandorchardinband)
/// NB: the example code is only covering the post-Canopy case.
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
///     consensus::{TEST_NETWORK, TestNetwork, NetworkUpgrade, Parameters},
///     memo::MemoBytes,
///     sapling::{
///         keys::{OutgoingViewingKey, prf_expand},
///         note_encryption::sapling_note_encryption,
///         util::generate_random_rseed,
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
/// let height = TEST_NETWORK.activation_height(NetworkUpgrade::Canopy).unwrap();
/// let rseed = generate_random_rseed(&TEST_NETWORK, height, &mut rng);
/// let note = to.create_note(value, rseed).unwrap();
/// let cmu = note.cmu();
///
/// let mut enc = sapling_note_encryption::<_, TestNetwork>(ovk, note, to, MemoBytes::empty(), &mut rng);
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

    /// For use only with Sapling. This method is preserved in order that test code
    /// be able to generate pre-ZIP-212 ciphertexts so that tests can continue to
    /// cover pre-ZIP-212 transaction decryption.
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

    /// Exposes the encoding of the ephemeral public key being used to encrypt this note.
    pub fn epk(&self) -> &D::EphemeralPublicKey {
        &self.epk
    }

    /// Generates `encCiphertext` for this note.
    pub fn encrypt_note_plaintext(&self) -> [u8; ENC_CIPHERTEXT_SIZE] {
        let pk_d = D::get_pk_d(&self.note);
        let shared_secret = D::ka_agree_enc(&self.esk, &pk_d);
        let key = D::kdf(shared_secret, &D::epk_bytes(&self.epk));
        let input = D::note_plaintext_bytes(&self.note, &self.to, &self.memo);

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
        &self,
        cv: &D::ValueCommitment,
        cmstar: &D::ExtractedCommitment,
        rng: &mut R,
    ) -> [u8; OUT_CIPHERTEXT_SIZE] {
        let (ock, input) = if let Some(ovk) = &self.ovk {
            let ock = D::derive_ock(ovk, &cv, &cmstar.into(), &D::epk_bytes(&self.epk));
            let input = D::outgoing_plaintext_bytes(&self.note, &self.esk);

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
/// If successful, the corresponding note and memo are returned, along with the address to
/// which the note was sent.
///
/// Implements section 4.19.2 of the
/// [Zcash Protocol Specification](https://zips.z.cash/protocol/nu5.pdf#decryptivk).
pub fn try_note_decryption<D: Domain, Output: ShieldedOutput<D>>(
    domain: &D,
    ivk: &D::IncomingViewingKey,
    output: &Output,
) -> Option<(D::Note, D::Recipient, D::Memo)> {
    assert_eq!(output.enc_ciphertext().len(), ENC_CIPHERTEXT_SIZE);
    let ephemeral_key = output.ephemeral_key();

    let epk = D::epk(&ephemeral_key)?;
    let shared_secret = D::ka_agree_dec(ivk, &epk);
    let key = D::kdf(shared_secret, &ephemeral_key);

    let mut plaintext = [0; ENC_CIPHERTEXT_SIZE];
    assert_eq!(
        ChachaPolyIetf::aead_cipher()
            .open_to(
                &mut plaintext,
                output.enc_ciphertext(),
                &[],
                key.as_ref(),
                &[0u8; 12]
            )
            .ok()?,
        NOTE_PLAINTEXT_SIZE
    );

    let (note, to) = parse_note_plaintext_without_memo_ivk(
        domain,
        ivk,
        &ephemeral_key,
        &output.cmstar_bytes(),
        &plaintext,
    )?;
    let memo = domain.extract_memo(&plaintext);

    Some((note, to, memo))
}

fn parse_note_plaintext_without_memo_ivk<D: Domain>(
    domain: &D,
    ivk: &D::IncomingViewingKey,
    ephemeral_key: &EphemeralKeyBytes,
    cmstar_bytes: &D::ExtractedCommitmentBytes,
    plaintext: &[u8],
) -> Option<(D::Note, D::Recipient)> {
    let (note, to) = domain.parse_note_plaintext_without_memo_ivk(ivk, &plaintext)?;

    if let NoteValidity::Valid = check_note_validity::<D>(&note, ephemeral_key, cmstar_bytes) {
        Some((note, to))
    } else {
        None
    }
}

fn check_note_validity<D: Domain>(
    note: &D::Note,
    ephemeral_key: &EphemeralKeyBytes,
    cmstar_bytes: &D::ExtractedCommitmentBytes,
) -> NoteValidity {
    if &D::ExtractedCommitmentBytes::from(&D::cmstar(&note)) == cmstar_bytes {
        D::check_epk_bytes(&note, |derived_esk| {
            if D::epk_bytes(&D::ka_derive_public(&note, &derived_esk))
                .ct_eq(&ephemeral_key)
                .into()
            {
                NoteValidity::Valid
            } else {
                NoteValidity::Invalid
            }
        })
    } else {
        // Published commitment doesn't match calculated commitment
        NoteValidity::Invalid
    }
}

/// Trial decryption of the compact note plaintext by the recipient for light clients.
///
/// Attempts to decrypt and validate the first 52 bytes of `enc_ciphertext` using the
/// given `ivk`. If successful, the corresponding note is returned, along with the address
/// to which the note was sent.
///
/// Implements the procedure specified in [`ZIP 307`].
///
/// [`ZIP 307`]: https://zips.z.cash/zip-0307
pub fn try_compact_note_decryption<D: Domain, Output: ShieldedOutput<D>>(
    domain: &D,
    ivk: &D::IncomingViewingKey,
    output: &Output,
) -> Option<(D::Note, D::Recipient)> {
    assert_eq!(output.enc_ciphertext().len(), COMPACT_NOTE_SIZE);
    let ephemeral_key = output.ephemeral_key();

    let epk = D::epk(&ephemeral_key)?;
    let shared_secret = D::ka_agree_dec(&ivk, &epk);
    let key = D::kdf(shared_secret, &ephemeral_key);

    // Start from block 1 to skip over Poly1305 keying output
    let mut plaintext = [0; COMPACT_NOTE_SIZE];
    plaintext.copy_from_slice(output.enc_ciphertext());
    ChaCha20Ietf::xor(key.as_ref(), &[0u8; 12], 1, &mut plaintext);

    parse_note_plaintext_without_memo_ivk(
        domain,
        ivk,
        &ephemeral_key,
        &output.cmstar_bytes(),
        &plaintext,
    )
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ovk`.
/// If successful, the corresponding note and memo are returned, along with the address to
/// which the note was sent.
///
/// Implements [Zcash Protocol Specification section 4.19.3][decryptovk].
///
/// [decryptovk]: https://zips.z.cash/protocol/nu5.pdf#decryptovk
pub fn try_output_recovery_with_ovk<D: Domain, Output: ShieldedOutput<D>>(
    domain: &D,
    ovk: &D::OutgoingViewingKey,
    output: &Output,
    cv: &D::ValueCommitment,
    out_ciphertext: &[u8],
) -> Option<(D::Note, D::Recipient, D::Memo)> {
    let ock = D::derive_ock(ovk, &cv, &output.cmstar_bytes(), &output.ephemeral_key());
    try_output_recovery_with_ock(domain, &ock, output, out_ciphertext)
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ock`.
/// If successful, the corresponding note and memo are returned, along with the address to
/// which the note was sent.
///
/// Implements part of section 4.19.3 of the
/// [Zcash Protocol Specification](https://zips.z.cash/protocol/nu5.pdf#decryptovk).
/// For decryption using a Full Viewing Key see [`try_output_recovery_with_ovk`].
pub fn try_output_recovery_with_ock<D: Domain, Output: ShieldedOutput<D>>(
    domain: &D,
    ock: &OutgoingCipherKey,
    output: &Output,
    out_ciphertext: &[u8],
) -> Option<(D::Note, D::Recipient, D::Memo)> {
    assert_eq!(output.enc_ciphertext().len(), ENC_CIPHERTEXT_SIZE);
    assert_eq!(out_ciphertext.len(), OUT_CIPHERTEXT_SIZE);

    let mut op = [0; OUT_PLAINTEXT_SIZE];
    assert_eq!(
        ChachaPolyIetf::aead_cipher()
            .open_to(&mut op, &out_ciphertext, &[], ock.as_ref(), &[0u8; 12])
            .ok()?,
        OUT_PLAINTEXT_SIZE
    );

    let pk_d = D::extract_pk_d(&op)?;
    let esk = D::extract_esk(&op)?;

    let ephemeral_key = output.ephemeral_key();
    let shared_secret = D::ka_agree_enc(&esk, &pk_d);
    // The small-order point check at the point of output parsing rejects
    // non-canonical encodings, so reencoding here for the KDF should
    // be okay.
    let key = D::kdf(shared_secret, &ephemeral_key);

    let mut plaintext = [0; ENC_CIPHERTEXT_SIZE];
    assert_eq!(
        ChachaPolyIetf::aead_cipher()
            .open_to(
                &mut plaintext,
                output.enc_ciphertext(),
                &[],
                key.as_ref(),
                &[0u8; 12]
            )
            .ok()?,
        NOTE_PLAINTEXT_SIZE
    );

    let (note, to) =
        domain.parse_note_plaintext_without_memo_ovk(&pk_d, &esk, &ephemeral_key, &plaintext)?;
    let memo = domain.extract_memo(&plaintext);

    // ZIP 212: Check that the esk provided to this function is consistent with the esk we
    // can derive from the note.
    if let Some(derived_esk) = D::derive_esk(&note) {
        if (!derived_esk.ct_eq(&esk)).into() {
            return None;
        }
    }

    if let NoteValidity::Valid =
        check_note_validity::<D>(&note, &ephemeral_key, &output.cmstar_bytes())
    {
        Some((note, to, memo))
    } else {
        None
    }
}
