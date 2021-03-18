//! Implementation of in-band secret distribution for Zcash transactions.

use crate::{
    consensus::{self, BlockHeight, NetworkUpgrade::Canopy, ZIP212_GRACE_PERIOD},
    memo::MemoBytes,
    sapling::{Diversifier, Note, PaymentAddress, Rseed, SaplingIvk},
    transaction::components::amount::Amount,
};
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{LittleEndian, WriteBytesExt};
use crypto_api_chachapoly::{ChaCha20Ietf, ChachaPolyIetf};
use ff::PrimeField;
use group::{cofactor::CofactorGroup, GroupEncoding};
use rand_core::RngCore;
use std::convert::TryInto;

use crate::sapling::keys::OutgoingViewingKey;

pub const KDF_SAPLING_PERSONALIZATION: &[u8; 16] = b"Zcash_SaplingKDF";
pub const PRF_OCK_PERSONALIZATION: &[u8; 16] = b"Zcash_Derive_ock";

const COMPACT_NOTE_SIZE: usize = 1 + // version
    11 + // diversifier
    8  + // value
    32; // rcv
const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + 512;
const OUT_PLAINTEXT_SIZE: usize = 32 + // pk_d
    32; // esk
pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;
pub const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + 16;

/// Sapling key agreement for note encryption.
///
/// Implements section 5.4.4.3 of the Zcash Protocol Specification.
pub fn sapling_ka_agree(esk: &jubjub::Fr, pk_d: &jubjub::ExtendedPoint) -> jubjub::SubgroupPoint {
    // [8 esk] pk_d
    // <ExtendedPoint as CofactorGroup>::clear_cofactor is implemented using
    // ExtendedPoint::mul_by_cofactor in the jubjub crate.

    let mut wnaf = group::Wnaf::new();
    wnaf.scalar(esk).base(*pk_d).clear_cofactor()
}

/// Sapling KDF for note encryption.
///
/// Implements section 5.4.4.4 of the Zcash Protocol Specification.
fn kdf_sapling(dhsecret: jubjub::SubgroupPoint, epk: &jubjub::ExtendedPoint) -> Blake2bHash {
    Blake2bParams::new()
        .hash_length(32)
        .personal(KDF_SAPLING_PERSONALIZATION)
        .to_state()
        .update(&dhsecret.to_bytes())
        .update(&epk.to_bytes())
        .finalize()
}

/// A symmetric key that can be used to recover a single Sapling output.
pub struct OutgoingCipherKey([u8; 32]);

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

/// Sapling PRF^ock.
///
/// Implemented per section 5.4.2 of the Zcash Protocol Specification.
pub fn prf_ock(
    ovk: &OutgoingViewingKey,
    cv: &jubjub::ExtendedPoint,
    cmu: &bls12_381::Scalar,
    epk: &jubjub::ExtendedPoint,
) -> OutgoingCipherKey {
    OutgoingCipherKey(
        Blake2bParams::new()
            .hash_length(32)
            .personal(PRF_OCK_PERSONALIZATION)
            .to_state()
            .update(&ovk.0)
            .update(&cv.to_bytes())
            .update(&cmu.to_repr())
            .update(&epk.to_bytes())
            .finalize()
            .as_bytes()
            .try_into()
            .unwrap(),
    )
}

/// An API for encrypting Sapling notes.
///
/// This struct provides a safe API for encrypting Sapling notes. In particular, it
/// enforces that fresh ephemeral keys are used for every note, and that the ciphertexts
/// are consistent with each other.
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
///     memo::MemoBytes,
///     sapling::{
///         keys::{OutgoingViewingKey, prf_expand},
///         note_encryption::sapling_note_encryption,
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

//FIXME: use constant-time checks for equality
#[derive(Eq, PartialEq)]
pub struct EphemeralKeyBytes([u8; 32]);

impl From<[u8; 32]> for EphemeralKeyBytes {
    fn from(value: [u8; 32]) -> EphemeralKeyBytes {
        EphemeralKeyBytes(value)
    }
}

pub struct NotePlaintextBytes([u8; NOTE_PLAINTEXT_SIZE]);
pub struct OutPlaintextBytes([u8; OUT_PLAINTEXT_SIZE]);

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

pub struct SaplingDomain<P: consensus::Parameters> {
    params: P,
    height: BlockHeight,
}

impl<P: consensus::Parameters> Domain for SaplingDomain<P> {
    type EphemeralSecretKey = jubjub::Scalar;
    type EphemeralPublicKey = jubjub::ExtendedPoint;
    type SharedSecret = jubjub::SubgroupPoint;
    type SymmetricKey = Blake2bHash;
    type Note = Note;
    type Recipient = PaymentAddress;
    type DiversifiedTransmissionKey = jubjub::SubgroupPoint;
    type IncomingViewingKey = SaplingIvk;
    type OutgoingViewingKey = OutgoingViewingKey;
    type ValueCommitment = jubjub::ExtendedPoint;
    type NoteCommitment = bls12_381::Scalar;
    type ExtractedCommitment = [u8; 32];
    type Memo = MemoBytes;

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey> {
        note.derive_esk()
    }

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey {
        note.pk_d
    }

    fn ka_derive_public(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> Self::EphemeralPublicKey {
        // epk is an element of jubjub's prime-order subgroup,
        // but Self::EphemeralPublicKey is a full group element
        // for efficency of encryption. The conversion here is fine
        // because the output of this function is only used for
        // encoding and the byte encoding is unaffected by the conversion.
        (note.g_d * esk).into()
    }

    fn ka_agree_enc(
        esk: &Self::EphemeralSecretKey,
        pk_d: &Self::DiversifiedTransmissionKey,
    ) -> Self::SharedSecret {
        sapling_ka_agree(esk, pk_d.into())
    }

    fn ka_agree_dec(
        ivk: &Self::IncomingViewingKey,
        epk: &Self::EphemeralPublicKey,
    ) -> Self::SharedSecret {
        sapling_ka_agree(&ivk.0, epk)
    }

    /// Sapling KDF for note encryption.
    ///
    /// Implements section 5.4.4.4 of the Zcash Protocol Specification.
    fn kdf(dhsecret: jubjub::SubgroupPoint, epk: &jubjub::ExtendedPoint) -> Blake2bHash {
        Blake2bParams::new()
            .hash_length(32)
            .personal(KDF_SAPLING_PERSONALIZATION)
            .to_state()
            .update(&dhsecret.to_bytes())
            .update(&epk.to_bytes())
            .finalize()
    }

    fn to_note_plaintext_bytes(
        note: &Self::Note,
        to: &Self::Recipient,
        memo: &Self::Memo,
    ) -> NotePlaintextBytes {
        // Note plaintext encoding is defined in section 5.5 of the Zcash Protocol
        // Specification.
        let mut input = [0; NOTE_PLAINTEXT_SIZE];
        input[0] = match note.rseed {
            Rseed::BeforeZip212(_) => 1,
            Rseed::AfterZip212(_) => 2,
        };
        input[1..12].copy_from_slice(&to.diversifier().0);
        (&mut input[12..20])
            .write_u64::<LittleEndian>(note.value)
            .unwrap();

        match note.rseed {
            Rseed::BeforeZip212(rcm) => {
                input[20..COMPACT_NOTE_SIZE].copy_from_slice(rcm.to_repr().as_ref());
            }
            Rseed::AfterZip212(rseed) => {
                input[20..COMPACT_NOTE_SIZE].copy_from_slice(&rseed);
            }
        }

        input[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE].copy_from_slice(&memo.as_array()[..]);

        NotePlaintextBytes(input)
    }

    fn get_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cmu: &Self::NoteCommitment,
        epk: &Self::EphemeralPublicKey,
    ) -> OutgoingCipherKey {
        prf_ock(ovk, &cv, &cmu, epk)
    }

    fn to_outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes {
        let mut input = [0u8; OUT_PLAINTEXT_SIZE];
        input[0..32].copy_from_slice(&note.pk_d.to_bytes());
        input[32..OUT_PLAINTEXT_SIZE].copy_from_slice(esk.to_repr().as_ref());

        OutPlaintextBytes(input)
    }

    fn to_epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes {
        EphemeralKeyBytes(epk.to_bytes())
    }

    fn check_epk_bytes<F: FnOnce(&Self::EphemeralSecretKey) -> EpkValidity>(
        note: &Note,
        check: F,
    ) -> EpkValidity {
        if let Some(derived_esk) = note.derive_esk() {
            check(&derived_esk)
        } else {
            // Before ZIP 212
            EpkValidity::Valid
        }
    }

    fn parse_note_plaintext_without_memo(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)> {
        assert!(plaintext.len() >= COMPACT_NOTE_SIZE);

        // Check note plaintext version
        if !plaintext_version_is_valid(&self.params, self.height, plaintext[0]) {
            return None;
        }

        // The unwraps below are guaranteed to succeed by the assertion above
        let diversifier = Diversifier(plaintext[1..12].try_into().unwrap());
        let value = Amount::from_u64_le_bytes(plaintext[12..20].try_into().unwrap()).ok()?;
        let r: [u8; 32] = plaintext[20..COMPACT_NOTE_SIZE].try_into().unwrap();

        let rseed = if plaintext[0] == 0x01 {
            let rcm = jubjub::Fr::from_repr(r)?;
            Rseed::BeforeZip212(rcm)
        } else {
            Rseed::AfterZip212(r)
        };

        let pk_d = diversifier.g_d()? * ivk.0;

        let to = PaymentAddress::from_parts(diversifier, pk_d)?;
        let note = to.create_note(value.into(), rseed)?;
        Some((note, to))
    }

    fn extract_note_commitment(note: &Self::Note) -> Self::ExtractedCommitment {
        note.cmu().to_bytes()
    }

    fn extract_memo(&self, plaintext: &[u8]) -> Self::Memo {
        MemoBytes::from_bytes(&plaintext[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE]).unwrap()
    }
}

/// Creates a new encryption context for the given note.
///
/// Setting `ovk` to `None` represents the `ovk = ⊥` case, where the note cannot be
/// recovered by the sender.
pub fn sapling_note_encryption<R: RngCore, P: consensus::Parameters>(
    ovk: Option<OutgoingViewingKey>,
    note: Note,
    to: PaymentAddress,
    memo: MemoBytes,
    rng: &mut R,
) -> NoteEncryption<SaplingDomain<P>> {
    let esk = note.generate_or_derive_esk_internal(rng);

    NoteEncryption {
        epk: SaplingDomain::<P>::ka_derive_public(&note, &esk),
        esk,
        note,
        to,
        memo,
        ovk,
    }
}

impl<D: Domain> NoteEncryption<D> {
    pub fn new_internal(
        ovk: Option<D::OutgoingViewingKey>,
        note: D::Note,
        to: D::Recipient,
        memo: D::Memo,
    ) -> Self {
        let esk = D::derive_esk(&note).expect("ZIP 212 is active.");

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

#[allow(clippy::if_same_then_else)]
#[allow(clippy::needless_bool)]
pub fn plaintext_version_is_valid<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    leadbyte: u8,
) -> bool {
    if params.is_nu_active(Canopy, height) {
        let grace_period_end_height =
            params.activation_height(Canopy).unwrap() + ZIP212_GRACE_PERIOD;

        if height < grace_period_end_height && leadbyte != 0x01 && leadbyte != 0x02 {
            // non-{0x01,0x02} received after Canopy activation and before grace period has elapsed
            false
        } else if height >= grace_period_end_height && leadbyte != 0x02 {
            // non-0x02 received past (Canopy activation height + grace period)
            false
        } else {
            true
        }
    } else {
        // return false if non-0x01 received when Canopy is not active
        leadbyte == 0x01
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

pub fn try_sapling_note_decryption<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    ivk: &SaplingIvk,
    epk: &jubjub::ExtendedPoint,
    cmu: &bls12_381::Scalar,
    enc_ciphertext: &[u8],
) -> Option<(Note, PaymentAddress, MemoBytes)> {
    let domain = SaplingDomain {
        params: params.clone(),
        height,
    };
    try_note_decryption(&domain, ivk, epk, &cmu.to_bytes(), enc_ciphertext)
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

pub fn try_sapling_compact_note_decryption<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    ivk: &SaplingIvk,
    epk: &jubjub::ExtendedPoint,
    cmu: &bls12_381::Scalar,
    enc_ciphertext: &[u8],
) -> Option<(Note, PaymentAddress)> {
    let domain = SaplingDomain {
        params: params.clone(),
        height,
    };

    try_compact_note_decryption(&domain, ivk, epk, &cmu.to_bytes(), enc_ciphertext)
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ock`.
/// If successful, the corresponding Sapling note and memo are returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements part of section 4.17.3 of the Zcash Protocol Specification.
/// For decryption using a Full Viewing Key see [`try_sapling_output_recovery`].
pub fn try_sapling_output_recovery_with_ock<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    ock: &OutgoingCipherKey,
    cmu: &bls12_381::Scalar,
    epk: &jubjub::ExtendedPoint,
    enc_ciphertext: &[u8],
    out_ciphertext: &[u8],
) -> Option<(Note, PaymentAddress, MemoBytes)> {
    assert_eq!(enc_ciphertext.len(), ENC_CIPHERTEXT_SIZE);
    assert_eq!(out_ciphertext.len(), OUT_CIPHERTEXT_SIZE);

    let mut op = [0; OUT_CIPHERTEXT_SIZE];
    assert_eq!(
        ChachaPolyIetf::aead_cipher()
            .open_to(&mut op, &out_ciphertext, &[], ock.as_ref(), &[0u8; 12])
            .ok()?,
        OUT_PLAINTEXT_SIZE
    );

    let pk_d = {
        let pk_d = jubjub::SubgroupPoint::from_bytes(
            op[0..32].try_into().expect("slice is the correct length"),
        );
        if pk_d.is_none().into() {
            return None;
        }
        pk_d.unwrap()
    };

    let esk = jubjub::Fr::from_repr(
        op[32..OUT_PLAINTEXT_SIZE]
            .try_into()
            .expect("slice is the correct length"),
    )?;

    let shared_secret = sapling_ka_agree(&esk, &pk_d.into());
    let key = kdf_sapling(shared_secret, &epk);

    let mut plaintext = [0; ENC_CIPHERTEXT_SIZE];
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

    // Check note plaintext version
    if !plaintext_version_is_valid(params, height, plaintext[0]) {
        return None;
    }

    let mut d = [0u8; 11];
    d.copy_from_slice(&plaintext[1..12]);

    let v = Amount::from_u64_le_bytes(plaintext[12..20].try_into().unwrap()).ok()?;

    let r: [u8; 32] = plaintext[20..COMPACT_NOTE_SIZE]
        .try_into()
        .expect("slice is the correct length");

    let rseed = if plaintext[0] == 0x01 {
        let rcm = jubjub::Fr::from_repr(r)?;
        Rseed::BeforeZip212(rcm)
    } else {
        Rseed::AfterZip212(r)
    };

    let memo = MemoBytes::from_bytes(&plaintext[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE]).unwrap();

    let diversifier = Diversifier(d);
    if (diversifier.g_d()? * esk).to_bytes() != epk.to_bytes() {
        // Published epk doesn't match calculated epk
        return None;
    }

    let to = PaymentAddress::from_parts(diversifier, pk_d)?;
    let note = to.create_note(v.into(), rseed).unwrap();

    if note.cmu() != *cmu {
        // Published commitment doesn't match calculated commitment
        return None;
    }

    if let Some(derived_esk) = note.derive_esk() {
        if derived_esk != esk {
            return None;
        }
    }

    Some((note, to, memo))
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ovk`.
/// If successful, the corresponding Sapling note and memo are returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements section 4.17.3 of the Zcash Protocol Specification.
#[allow(clippy::too_many_arguments)]
pub fn try_sapling_output_recovery<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    ovk: &OutgoingViewingKey,
    cv: &jubjub::ExtendedPoint,
    cmu: &bls12_381::Scalar,
    epk: &jubjub::ExtendedPoint,
    enc_ciphertext: &[u8],
    out_ciphertext: &[u8],
) -> Option<(Note, PaymentAddress, MemoBytes)> {
    try_sapling_output_recovery_with_ock::<P>(
        params,
        height,
        &prf_ock(&ovk, &cv, &cmu, &epk),
        cmu,
        epk,
        enc_ciphertext,
        out_ciphertext,
    )
}

#[cfg(test)]
mod tests {
    use crypto_api_chachapoly::ChachaPolyIetf;
    use ff::{Field, PrimeField};
    use group::Group;
    use group::{cofactor::CofactorGroup, GroupEncoding};
    use rand_core::OsRng;
    use rand_core::{CryptoRng, RngCore};
    use std::convert::TryInto;

    use super::{
        kdf_sapling, prf_ock, sapling_ka_agree, sapling_note_encryption,
        try_sapling_compact_note_decryption, try_sapling_note_decryption,
        try_sapling_output_recovery, try_sapling_output_recovery_with_ock, OutgoingCipherKey,
        COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE, OUT_CIPHERTEXT_SIZE,
        OUT_PLAINTEXT_SIZE,
    };

    use crate::{
        consensus::{
            BlockHeight,
            NetworkUpgrade::{Canopy, Sapling},
            Parameters, TestNetwork, TEST_NETWORK, ZIP212_GRACE_PERIOD,
        },
        memo::MemoBytes,
        sapling::util::generate_random_rseed,
        sapling::{
            keys::OutgoingViewingKey, Diversifier, PaymentAddress, Rseed, SaplingIvk,
            ValueCommitment,
        },
        transaction::components::amount::Amount,
    };

    fn random_enc_ciphertext<R: RngCore + CryptoRng>(
        height: BlockHeight,
        mut rng: &mut R,
    ) -> (
        OutgoingViewingKey,
        OutgoingCipherKey,
        SaplingIvk,
        jubjub::ExtendedPoint,
        bls12_381::Scalar,
        jubjub::ExtendedPoint,
        [u8; ENC_CIPHERTEXT_SIZE],
        [u8; OUT_CIPHERTEXT_SIZE],
    ) {
        let ivk = SaplingIvk(jubjub::Fr::random(&mut rng));

        let (ovk, ock, cv, cmu, epk, enc_ciphertext, out_ciphertext) =
            random_enc_ciphertext_with(height, &ivk, rng);

        assert!(try_sapling_note_decryption(
            &TEST_NETWORK,
            height,
            &ivk,
            &epk,
            &cmu,
            &enc_ciphertext
        )
        .is_some());
        assert!(try_sapling_compact_note_decryption(
            &TEST_NETWORK,
            height,
            &ivk,
            &epk,
            &cmu,
            &enc_ciphertext[..COMPACT_NOTE_SIZE]
        )
        .is_some());

        let ovk_output_recovery = try_sapling_output_recovery(
            &TEST_NETWORK,
            height,
            &ovk,
            &cv,
            &cmu,
            &epk,
            &enc_ciphertext,
            &out_ciphertext,
        );

        let ock_output_recovery = try_sapling_output_recovery_with_ock(
            &TEST_NETWORK,
            height,
            &ock,
            &cmu,
            &epk,
            &enc_ciphertext,
            &out_ciphertext,
        );
        assert!(ovk_output_recovery.is_some());
        assert!(ock_output_recovery.is_some());
        assert_eq!(ovk_output_recovery, ock_output_recovery);

        (ovk, ock, ivk, cv, cmu, epk, enc_ciphertext, out_ciphertext)
    }

    fn random_enc_ciphertext_with<R: RngCore + CryptoRng>(
        height: BlockHeight,
        ivk: &SaplingIvk,
        mut rng: &mut R,
    ) -> (
        OutgoingViewingKey,
        OutgoingCipherKey,
        jubjub::ExtendedPoint,
        bls12_381::Scalar,
        jubjub::ExtendedPoint,
        [u8; ENC_CIPHERTEXT_SIZE],
        [u8; OUT_CIPHERTEXT_SIZE],
    ) {
        let diversifier = Diversifier([0; 11]);
        let pk_d = diversifier.g_d().unwrap() * ivk.0;
        let pa = PaymentAddress::from_parts_unchecked(diversifier, pk_d);

        // Construct the value commitment for the proof instance
        let value = Amount::from_u64(100).unwrap();
        let value_commitment = ValueCommitment {
            value: value.into(),
            randomness: jubjub::Fr::random(&mut rng),
        };
        let cv = value_commitment.commitment().into();

        let rseed = generate_random_rseed(&TEST_NETWORK, height, &mut rng);

        let note = pa.create_note(value.into(), rseed).unwrap();
        let cmu = note.cmu();

        let ovk = OutgoingViewingKey([0; 32]);
        let mut ne = sapling_note_encryption::<_, TestNetwork>(
            Some(ovk),
            note,
            pa,
            MemoBytes::empty(),
            &mut rng,
        );
        let epk = *ne.epk();
        let enc_ciphertext = ne.encrypt_note_plaintext();
        let out_ciphertext = ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng);
        let ock = prf_ock(&ovk, &cv, &cmu, &epk);

        (ovk, ock, cv, cmu, epk, enc_ciphertext, out_ciphertext)
    }

    fn reencrypt_enc_ciphertext(
        ovk: &OutgoingViewingKey,
        cv: &jubjub::ExtendedPoint,
        cmu: &bls12_381::Scalar,
        epk: &jubjub::ExtendedPoint,
        enc_ciphertext: &mut [u8; ENC_CIPHERTEXT_SIZE],
        out_ciphertext: &[u8; OUT_CIPHERTEXT_SIZE],
        modify_plaintext: impl Fn(&mut [u8; NOTE_PLAINTEXT_SIZE]),
    ) {
        let ock = prf_ock(&ovk, &cv, &cmu, &epk);

        let mut op = [0; OUT_CIPHERTEXT_SIZE];
        assert_eq!(
            ChachaPolyIetf::aead_cipher()
                .open_to(&mut op, out_ciphertext, &[], ock.as_ref(), &[0u8; 12])
                .unwrap(),
            OUT_PLAINTEXT_SIZE
        );

        let pk_d = jubjub::SubgroupPoint::from_bytes(&op[0..32].try_into().unwrap()).unwrap();

        let esk = jubjub::Fr::from_repr(op[32..OUT_PLAINTEXT_SIZE].try_into().unwrap()).unwrap();

        let shared_secret = sapling_ka_agree(&esk, &pk_d.into());
        let key = kdf_sapling(shared_secret, &epk);

        let mut plaintext = {
            let mut buf = [0; ENC_CIPHERTEXT_SIZE];
            assert_eq!(
                ChachaPolyIetf::aead_cipher()
                    .open_to(&mut buf, enc_ciphertext, &[], key.as_bytes(), &[0u8; 12])
                    .unwrap(),
                NOTE_PLAINTEXT_SIZE
            );
            let mut pt = [0; NOTE_PLAINTEXT_SIZE];
            pt.copy_from_slice(&buf[..NOTE_PLAINTEXT_SIZE]);
            pt
        };

        modify_plaintext(&mut plaintext);

        assert_eq!(
            ChachaPolyIetf::aead_cipher()
                .seal_to(enc_ciphertext, &plaintext, &[], &key.as_bytes(), &[0u8; 12])
                .unwrap(),
            ENC_CIPHERTEXT_SIZE
        );
    }

    fn find_invalid_diversifier() -> Diversifier {
        // Find an invalid diversifier
        let mut d = Diversifier([0; 11]);
        loop {
            for k in 0..11 {
                d.0[k] = d.0[k].wrapping_add(1);
                if d.0[k] != 0 {
                    break;
                }
            }
            if d.g_d().is_none() {
                break;
            }
        }
        d
    }

    fn find_valid_diversifier() -> Diversifier {
        // Find a different valid diversifier
        let mut d = Diversifier([0; 11]);
        loop {
            for k in 0..11 {
                d.0[k] = d.0[k].wrapping_add(1);
                if d.0[k] != 0 {
                    break;
                }
            }
            if d.g_d().is_some() {
                break;
            }
        }
        d
    }

    #[test]
    fn decryption_with_invalid_ivk() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (_, _, _, _, cmu, epk, enc_ciphertext, _) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &SaplingIvk(jubjub::Fr::random(&mut rng)),
                    &epk,
                    &cmu,
                    &enc_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn decryption_with_invalid_epk() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (_, _, ivk, _, cmu, _, enc_ciphertext, _) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &jubjub::ExtendedPoint::random(&mut rng),
                    &cmu,
                    &enc_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn decryption_with_invalid_cmu() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (_, _, ivk, _, _, epk, enc_ciphertext, _) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &epk,
                    &bls12_381::Scalar::random(&mut rng),
                    &enc_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn decryption_with_invalid_tag() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (_, _, ivk, _, cmu, epk, mut enc_ciphertext, _) =
                random_enc_ciphertext(height, &mut rng);

            enc_ciphertext[ENC_CIPHERTEXT_SIZE - 1] ^= 0xff;
            assert_eq!(
                try_sapling_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &epk,
                    &cmu,
                    &enc_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn decryption_with_invalid_version_byte() {
        let mut rng = OsRng;
        let canopy_activation_height = TEST_NETWORK.activation_height(Canopy).unwrap();
        let heights = [
            canopy_activation_height - 1,
            canopy_activation_height,
            canopy_activation_height + ZIP212_GRACE_PERIOD,
        ];
        let leadbytes = [0x02, 0x03, 0x01];

        for (&height, &leadbyte) in heights.iter().zip(leadbytes.iter()) {
            let (ovk, _, ivk, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &cv,
                &cmu,
                &epk,
                &mut enc_ciphertext,
                &out_ciphertext,
                |pt| pt[0] = leadbyte,
            );
            assert_eq!(
                try_sapling_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &epk,
                    &cmu,
                    &enc_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn decryption_with_invalid_diversifier() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, _, ivk, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &cv,
                &cmu,
                &epk,
                &mut enc_ciphertext,
                &out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_invalid_diversifier().0),
            );
            assert_eq!(
                try_sapling_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &epk,
                    &cmu,
                    &enc_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn decryption_with_incorrect_diversifier() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, _, ivk, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &cv,
                &cmu,
                &epk,
                &mut enc_ciphertext,
                &out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_valid_diversifier().0),
            );

            assert_eq!(
                try_sapling_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &epk,
                    &cmu,
                    &enc_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_invalid_ivk() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (_, _, _, _, cmu, epk, enc_ciphertext, _) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &SaplingIvk(jubjub::Fr::random(&mut rng)),
                    &epk,
                    &cmu,
                    &enc_ciphertext[..COMPACT_NOTE_SIZE]
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_invalid_epk() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (_, _, ivk, _, cmu, _, enc_ciphertext, _) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &jubjub::ExtendedPoint::random(&mut rng),
                    &cmu,
                    &enc_ciphertext[..COMPACT_NOTE_SIZE]
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_invalid_cmu() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (_, _, ivk, _, _, epk, enc_ciphertext, _) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &epk,
                    &bls12_381::Scalar::random(&mut rng),
                    &enc_ciphertext[..COMPACT_NOTE_SIZE]
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_invalid_version_byte() {
        let mut rng = OsRng;
        let canopy_activation_height = TEST_NETWORK.activation_height(Canopy).unwrap();
        let heights = [
            canopy_activation_height - 1,
            canopy_activation_height,
            canopy_activation_height + ZIP212_GRACE_PERIOD,
        ];
        let leadbytes = [0x02, 0x03, 0x01];

        for (&height, &leadbyte) in heights.iter().zip(leadbytes.iter()) {
            let (ovk, _, ivk, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &cv,
                &cmu,
                &epk,
                &mut enc_ciphertext,
                &out_ciphertext,
                |pt| pt[0] = leadbyte,
            );
            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &epk,
                    &cmu,
                    &enc_ciphertext[..COMPACT_NOTE_SIZE]
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_invalid_diversifier() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, _, ivk, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &cv,
                &cmu,
                &epk,
                &mut enc_ciphertext,
                &out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_invalid_diversifier().0),
            );
            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &epk,
                    &cmu,
                    &enc_ciphertext[..COMPACT_NOTE_SIZE]
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_incorrect_diversifier() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, _, ivk, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &cv,
                &cmu,
                &epk,
                &mut enc_ciphertext,
                &out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_valid_diversifier().0),
            );
            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &epk,
                    &cmu,
                    &enc_ciphertext[..COMPACT_NOTE_SIZE]
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_ovk() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (mut ovk, _, _, cv, cmu, epk, enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            ovk.0[0] ^= 0xff;
            assert_eq!(
                try_sapling_output_recovery(
                    &TEST_NETWORK,
                    height,
                    &ovk,
                    &cv,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_ock() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (_, _, _, _, cmu, epk, enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &OutgoingCipherKey([0u8; 32]),
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_cv() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, _, _, _, cmu, epk, enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_output_recovery(
                    &TEST_NETWORK,
                    height,
                    &ovk,
                    &jubjub::ExtendedPoint::random(&mut rng),
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_cmu() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, ock, _, cv, _, epk, enc_ctext, out_ctext) =
                random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_output_recovery(
                    &TEST_NETWORK,
                    height,
                    &ovk,
                    &cv,
                    &bls12_381::Scalar::random(&mut rng),
                    &epk,
                    &enc_ctext,
                    &out_ctext
                ),
                None
            );

            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &ock,
                    &bls12_381::Scalar::random(&mut rng),
                    &epk,
                    &enc_ctext,
                    &out_ctext
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_epk() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, ock, _, cv, cmu, _, enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_output_recovery(
                    &TEST_NETWORK,
                    height,
                    &ovk,
                    &cv,
                    &cmu,
                    &jubjub::ExtendedPoint::random(&mut rng),
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );

            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &ock,
                    &cmu,
                    &jubjub::ExtendedPoint::random(&mut rng),
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_enc_tag() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, ock, _, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            enc_ciphertext[ENC_CIPHERTEXT_SIZE - 1] ^= 0xff;
            assert_eq!(
                try_sapling_output_recovery(
                    &TEST_NETWORK,
                    height,
                    &ovk,
                    &cv,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &ock,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_out_tag() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, ock, _, cv, cmu, epk, enc_ciphertext, mut out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            out_ciphertext[OUT_CIPHERTEXT_SIZE - 1] ^= 0xff;
            assert_eq!(
                try_sapling_output_recovery(
                    &TEST_NETWORK,
                    height,
                    &ovk,
                    &cv,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &ock,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_version_byte() {
        let mut rng = OsRng;
        let canopy_activation_height = TEST_NETWORK.activation_height(Canopy).unwrap();
        let heights = [
            canopy_activation_height - 1,
            canopy_activation_height,
            canopy_activation_height + ZIP212_GRACE_PERIOD,
        ];
        let leadbytes = [0x02, 0x03, 0x01];

        for (&height, &leadbyte) in heights.iter().zip(leadbytes.iter()) {
            let (ovk, ock, _, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &cv,
                &cmu,
                &epk,
                &mut enc_ciphertext,
                &out_ciphertext,
                |pt| pt[0] = leadbyte,
            );
            assert_eq!(
                try_sapling_output_recovery(
                    &TEST_NETWORK,
                    height,
                    &ovk,
                    &cv,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &ock,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_diversifier() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, ock, _, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &cv,
                &cmu,
                &epk,
                &mut enc_ciphertext,
                &out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_invalid_diversifier().0),
            );
            assert_eq!(
                try_sapling_output_recovery(
                    &TEST_NETWORK,
                    height,
                    &ovk,
                    &cv,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &ock,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_incorrect_diversifier() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let (ovk, ock, _, cv, cmu, epk, mut enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &cv,
                &cmu,
                &epk,
                &mut enc_ciphertext,
                &out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_valid_diversifier().0),
            );
            assert_eq!(
                try_sapling_output_recovery(
                    &TEST_NETWORK,
                    height,
                    &ovk,
                    &cv,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &ock,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_pk_d() {
        let mut rng = OsRng;
        let heights = [
            TEST_NETWORK.activation_height(Sapling).unwrap(),
            TEST_NETWORK.activation_height(Canopy).unwrap(),
        ];

        for &height in heights.iter() {
            let ivk = SaplingIvk(jubjub::Fr::zero());
            let (ovk, ock, cv, cmu, epk, enc_ciphertext, out_ciphertext) =
                random_enc_ciphertext_with(height, &ivk, &mut rng);

            assert_eq!(
                try_sapling_output_recovery(
                    &TEST_NETWORK,
                    height,
                    &ovk,
                    &cv,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &ock,
                    &cmu,
                    &epk,
                    &enc_ciphertext,
                    &out_ciphertext
                ),
                None
            );
        }
    }

    #[test]
    fn test_vectors() {
        let test_vectors = crate::test_vectors::note_encryption::make_test_vectors();

        macro_rules! read_bls12_381_scalar {
            ($field:expr) => {{
                bls12_381::Scalar::from_repr($field[..].try_into().unwrap()).unwrap()
            }};
        }

        macro_rules! read_jubjub_scalar {
            ($field:expr) => {{
                jubjub::Fr::from_repr($field[..].try_into().unwrap()).unwrap()
            }};
        }

        macro_rules! read_point {
            ($field:expr) => {
                jubjub::ExtendedPoint::from_bytes(&$field).unwrap()
            };
        }

        let height = TEST_NETWORK.activation_height(Sapling).unwrap();

        for tv in test_vectors {
            //
            // Load the test vector components
            //

            let ivk = SaplingIvk(read_jubjub_scalar!(tv.ivk));
            let pk_d = read_point!(tv.default_pk_d).into_subgroup().unwrap();
            let rcm = read_jubjub_scalar!(tv.rcm);
            let cv = read_point!(tv.cv);
            let cmu = read_bls12_381_scalar!(tv.cmu);
            let esk = read_jubjub_scalar!(tv.esk);
            let epk = read_point!(tv.epk);

            //
            // Test the individual components
            //

            let shared_secret = sapling_ka_agree(&esk, &pk_d.into());
            assert_eq!(shared_secret.to_bytes(), tv.shared_secret);

            let k_enc = kdf_sapling(shared_secret, &epk);
            assert_eq!(k_enc.as_bytes(), tv.k_enc);

            let ovk = OutgoingViewingKey(tv.ovk);
            let ock = prf_ock(&ovk, &cv, &cmu, &epk);
            assert_eq!(ock.as_ref(), tv.ock);

            let to = PaymentAddress::from_parts(Diversifier(tv.default_d), pk_d).unwrap();
            let note = to.create_note(tv.v, Rseed::BeforeZip212(rcm)).unwrap();
            assert_eq!(note.cmu(), cmu);

            //
            // Test decryption
            // (Tested first because it only requires immutable references.)
            //

            match try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &epk, &cmu, &tv.c_enc) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                    assert_eq!(&decrypted_memo.as_array()[..], &tv.memo[..]);
                }
                None => panic!("Note decryption failed"),
            }

            match try_sapling_compact_note_decryption(
                &TEST_NETWORK,
                height,
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

            match try_sapling_output_recovery(
                &TEST_NETWORK,
                height,
                &ovk,
                &cv,
                &cmu,
                &epk,
                &tv.c_enc,
                &tv.c_out,
            ) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                    assert_eq!(&decrypted_memo.as_array()[..], &tv.memo[..]);
                }
                None => panic!("Output recovery failed"),
            }

            //
            // Test encryption
            //

            let mut ne = sapling_note_encryption::<_, TestNetwork>(
                Some(ovk),
                note,
                to,
                MemoBytes::from_bytes(&tv.memo).unwrap(),
                &mut OsRng,
            );
            // Swap in the ephemeral keypair from the test vectors
            ne.esk = esk;
            ne.epk = epk;

            assert_eq!(&ne.encrypt_note_plaintext().as_ref()[..], &tv.c_enc[..]);
            assert_eq!(
                &ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut OsRng)[..],
                &tv.c_out[..]
            );
        }
    }
}
