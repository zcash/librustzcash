//! Implementation of in-band secret distribution for Zcash transactions.
//!
//! NB: the example code is only covering the post-Canopy case.

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use memuse::DynamicUsage;
use rand_core::RngCore;

use zcash_note_encryption::{
    try_compact_note_decryption, try_note_decryption, try_output_recovery_with_ock,
    try_output_recovery_with_ovk, BatchDomain, Domain, EphemeralKeyBytes, NoteEncryption,
    OutPlaintextBytes, OutgoingCipherKey, ShieldedOutput, AEAD_TAG_SIZE, MEMO_SIZE,
    OUT_PLAINTEXT_SIZE,
};

/// The size of a compact note.
pub const COMPACT_NOTE_SIZE: usize = 1 + // version
    11 + // diversifier
    8  + // value
    32; // rseed (or rcm prior to ZIP 212)
/// The size of [`NotePlaintextBytes`] for V2.
pub const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + MEMO_SIZE;
/// The size of an encrypted note plaintext.
pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + AEAD_TAG_SIZE;

/// a type to represent the raw bytes of a note plaintext.
#[derive(Clone, Debug)]
pub struct NotePlaintextBytes(pub [u8; NOTE_PLAINTEXT_SIZE]);

/// a type to represent the raw bytes of an encrypted note plaintext.
#[derive(Clone, Debug)]
pub struct NoteCiphertextBytes(pub [u8; ENC_CIPHERTEXT_SIZE]);

/// a type to represent the raw bytes of a compact note.
#[derive(Clone, Debug)]
pub struct CompactNotePlaintextBytes(pub [u8; COMPACT_NOTE_SIZE]);

/// a type to represent the raw bytes of an encrypted compact note.
#[derive(Clone, Debug)]
pub struct CompactNoteCiphertextBytes(pub [u8; COMPACT_NOTE_SIZE]);

impl AsMut<[u8]> for NotePlaintextBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl From<&[u8]> for NotePlaintextBytes {
    fn from(s: &[u8]) -> Self
    where
        Self: Sized,
    {
        NotePlaintextBytes(s.try_into().unwrap())
    }
}

impl AsRef<[u8]> for NoteCiphertextBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<&[u8]> for NoteCiphertextBytes {
    fn from(s: &[u8]) -> Self
    where
        Self: Sized,
    {
        NoteCiphertextBytes(s.try_into().unwrap())
    }
}

impl AsMut<[u8]> for CompactNotePlaintextBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl From<&[u8]> for CompactNotePlaintextBytes {
    fn from(s: &[u8]) -> Self
    where
        Self: Sized,
    {
        CompactNotePlaintextBytes(s.try_into().unwrap())
    }
}

impl AsRef<[u8]> for CompactNoteCiphertextBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

use crate::{
    consensus::{self, BlockHeight, NetworkUpgrade::Canopy, ZIP212_GRACE_PERIOD},
    memo::MemoBytes,
    sapling::{
        keys::{
            DiversifiedTransmissionKey, EphemeralPublicKey, EphemeralSecretKey, OutgoingViewingKey,
            SharedSecret,
        },
        value::ValueCommitment,
        Diversifier, Note, PaymentAddress, Rseed,
    },
    transaction::components::{
        amount::Amount,
        sapling::{self, OutputDescription},
    },
};

use super::note::ExtractedNoteCommitment;

pub use crate::sapling::keys::{PreparedEphemeralPublicKey, PreparedIncomingViewingKey};

pub const KDF_SAPLING_PERSONALIZATION: &[u8; 16] = b"Zcash_SaplingKDF";
pub const PRF_OCK_PERSONALIZATION: &[u8; 16] = b"Zcash_Derive_ock";

/// Sapling PRF^ock.
///
/// Implemented per section 5.4.2 of the Zcash Protocol Specification.
pub fn prf_ock(
    ovk: &OutgoingViewingKey,
    cv: &ValueCommitment,
    cmu_bytes: &[u8; 32],
    ephemeral_key: &EphemeralKeyBytes,
) -> OutgoingCipherKey {
    OutgoingCipherKey(
        Blake2bParams::new()
            .hash_length(32)
            .personal(PRF_OCK_PERSONALIZATION)
            .to_state()
            .update(&ovk.0)
            .update(&cv.to_bytes())
            .update(cmu_bytes)
            .update(ephemeral_key.as_ref())
            .finalize()
            .as_bytes()
            .try_into()
            .unwrap(),
    )
}

/// `get_pk_d` must check that the diversifier contained within the note plaintext is a
/// valid Sapling diversifier.
fn sapling_parse_note_plaintext_without_memo<F, P: consensus::Parameters>(
    domain: &SaplingDomain<P>,
    plaintext: &[u8],
    get_pk_d: F,
) -> Option<(Note, PaymentAddress)>
where
    F: FnOnce(&Diversifier) -> Option<DiversifiedTransmissionKey>,
{
    assert!(plaintext.len() >= COMPACT_NOTE_SIZE);

    // Check note plaintext version
    if !plaintext_version_is_valid(&domain.params, domain.height, plaintext[0]) {
        return None;
    }

    // The unwraps below are guaranteed to succeed by the assertion above
    let diversifier = Diversifier(plaintext[1..12].try_into().unwrap());
    let value = Amount::from_u64_le_bytes(plaintext[12..20].try_into().unwrap()).ok()?;
    let r: [u8; 32] = plaintext[20..COMPACT_NOTE_SIZE].try_into().unwrap();

    let rseed = if plaintext[0] == 0x01 {
        let rcm = Option::from(jubjub::Fr::from_repr(r))?;
        Rseed::BeforeZip212(rcm)
    } else {
        Rseed::AfterZip212(r)
    };

    let pk_d = get_pk_d(&diversifier)?;

    // `diversifier` was checked by `get_pk_d`.
    let to = PaymentAddress::from_parts_unchecked(diversifier, pk_d)?;
    let note = to.create_note(value.into(), rseed);
    Some((note, to))
}

pub struct SaplingDomain<P: consensus::Parameters> {
    params: P,
    height: BlockHeight,
}

impl<P: consensus::Parameters + DynamicUsage> DynamicUsage for SaplingDomain<P> {
    fn dynamic_usage(&self) -> usize {
        self.params.dynamic_usage() + self.height.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let (params_lower, params_upper) = self.params.dynamic_usage_bounds();
        let (height_lower, height_upper) = self.height.dynamic_usage_bounds();
        (
            params_lower + height_lower,
            params_upper.zip(height_upper).map(|(a, b)| a + b),
        )
    }
}

impl<P: consensus::Parameters> SaplingDomain<P> {
    pub fn for_height(params: P, height: BlockHeight) -> Self {
        Self { params, height }
    }
}

impl<P: consensus::Parameters> Domain for SaplingDomain<P> {
    type EphemeralSecretKey = EphemeralSecretKey;
    // It is acceptable for this to be a point rather than a byte array, because we
    // enforce by consensus that points must not be small-order, and all points with
    // non-canonical serialization are small-order.
    type EphemeralPublicKey = EphemeralPublicKey;
    type PreparedEphemeralPublicKey = PreparedEphemeralPublicKey;
    type SharedSecret = SharedSecret;
    type SymmetricKey = Blake2bHash;
    type Note = Note;
    type Recipient = PaymentAddress;
    type DiversifiedTransmissionKey = DiversifiedTransmissionKey;
    type IncomingViewingKey = PreparedIncomingViewingKey;
    type OutgoingViewingKey = OutgoingViewingKey;
    type ValueCommitment = ValueCommitment;
    type ExtractedCommitment = ExtractedNoteCommitment;
    type ExtractedCommitmentBytes = [u8; 32];
    type Memo = MemoBytes;

    type NotePlaintextBytes = NotePlaintextBytes;
    type NoteCiphertextBytes = NoteCiphertextBytes;
    type CompactNotePlaintextBytes = CompactNotePlaintextBytes;
    type CompactNoteCiphertextBytes = CompactNoteCiphertextBytes;

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey> {
        note.derive_esk()
    }

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey {
        *note.recipient().pk_d()
    }

    fn prepare_epk(epk: Self::EphemeralPublicKey) -> Self::PreparedEphemeralPublicKey {
        PreparedEphemeralPublicKey::new(epk)
    }

    fn ka_derive_public(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> Self::EphemeralPublicKey {
        esk.derive_public(note.recipient().g_d().into())
    }

    fn ka_agree_enc(
        esk: &Self::EphemeralSecretKey,
        pk_d: &Self::DiversifiedTransmissionKey,
    ) -> Self::SharedSecret {
        esk.agree(pk_d)
    }

    fn ka_agree_dec(
        ivk: &Self::IncomingViewingKey,
        epk: &Self::PreparedEphemeralPublicKey,
    ) -> Self::SharedSecret {
        epk.agree(ivk)
    }

    /// Sapling KDF for note encryption.
    ///
    /// Implements section 5.4.4.4 of the Zcash Protocol Specification.
    fn kdf(dhsecret: SharedSecret, epk: &EphemeralKeyBytes) -> Blake2bHash {
        dhsecret.kdf_sapling(epk)
    }

    fn note_plaintext_bytes(note: &Self::Note, memo: &Self::Memo) -> NotePlaintextBytes {
        // Note plaintext encoding is defined in section 5.5 of the Zcash Protocol
        // Specification.
        let mut input = [0; NOTE_PLAINTEXT_SIZE];
        input[0] = match note.rseed() {
            Rseed::BeforeZip212(_) => 1,
            Rseed::AfterZip212(_) => 2,
        };
        input[1..12].copy_from_slice(&note.recipient().diversifier().0);
        (&mut input[12..20])
            .write_u64::<LittleEndian>(note.value().inner())
            .unwrap();

        match note.rseed() {
            Rseed::BeforeZip212(rcm) => {
                input[20..COMPACT_NOTE_SIZE].copy_from_slice(rcm.to_repr().as_ref());
            }
            Rseed::AfterZip212(rseed) => {
                input[20..COMPACT_NOTE_SIZE].copy_from_slice(rseed);
            }
        }

        input[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE].copy_from_slice(&memo.as_array()[..]);

        NotePlaintextBytes(input)
    }

    fn derive_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cmu_bytes: &Self::ExtractedCommitmentBytes,
        epk: &EphemeralKeyBytes,
    ) -> OutgoingCipherKey {
        prf_ock(ovk, cv, cmu_bytes, epk)
    }

    fn outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes {
        let mut input = [0u8; OUT_PLAINTEXT_SIZE];
        input[0..32].copy_from_slice(&note.recipient().pk_d().to_bytes());
        input[32..OUT_PLAINTEXT_SIZE].copy_from_slice(esk.0.to_repr().as_ref());

        OutPlaintextBytes(input)
    }

    fn epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes {
        epk.to_bytes()
    }

    fn epk(ephemeral_key: &EphemeralKeyBytes) -> Option<Self::EphemeralPublicKey> {
        // ZIP 216: We unconditionally reject non-canonical encodings, because these have
        // always been rejected by consensus (due to small-order checks).
        // https://zips.z.cash/zip-0216#specification
        EphemeralPublicKey::from_bytes(&ephemeral_key.0).into()
    }

    fn parse_note_plaintext_without_memo_ivk(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &CompactNotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        sapling_parse_note_plaintext_without_memo(self, &plaintext.0, |diversifier| {
            DiversifiedTransmissionKey::derive(ivk, diversifier)
        })
    }

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        plaintext: &CompactNotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        sapling_parse_note_plaintext_without_memo(self, &plaintext.0, |diversifier| {
            diversifier.g_d().map(|_| *pk_d)
        })
    }

    fn cmstar(note: &Self::Note) -> Self::ExtractedCommitment {
        note.cmu()
    }

    fn extract_pk_d(op: &OutPlaintextBytes) -> Option<Self::DiversifiedTransmissionKey> {
        DiversifiedTransmissionKey::from_bytes(
            op.0[0..32].try_into().expect("slice is the correct length"),
        )
        .into()
    }

    fn extract_esk(op: &OutPlaintextBytes) -> Option<Self::EphemeralSecretKey> {
        EphemeralSecretKey::from_bytes(
            op.0[32..OUT_PLAINTEXT_SIZE]
                .try_into()
                .expect("slice is the correct length"),
        )
        .into()
    }

    fn extract_memo(
        &self,
        plaintext: &NotePlaintextBytes,
    ) -> (Self::CompactNotePlaintextBytes, Self::Memo) {
        let (compact, memo) = plaintext.0.split_at(COMPACT_NOTE_SIZE);
        (
            compact.try_into().unwrap(),
            MemoBytes::from_bytes(memo).unwrap(),
        )
    }
}

impl<P: consensus::Parameters> BatchDomain for SaplingDomain<P> {
    fn batch_kdf<'a>(
        items: impl Iterator<Item = (Option<Self::SharedSecret>, &'a EphemeralKeyBytes)>,
    ) -> Vec<Option<Self::SymmetricKey>> {
        let (shared_secrets, ephemeral_keys): (Vec<_>, Vec<_>) = items.unzip();

        SharedSecret::batch_to_affine(shared_secrets)
            .zip(ephemeral_keys.into_iter())
            .map(|(secret, ephemeral_key)| {
                secret.map(|dhsecret| SharedSecret::kdf_sapling_inner(dhsecret, ephemeral_key))
            })
            .collect()
    }

    fn batch_epk(
        ephemeral_keys: impl Iterator<Item = EphemeralKeyBytes>,
    ) -> Vec<(Option<Self::PreparedEphemeralPublicKey>, EphemeralKeyBytes)> {
        let ephemeral_keys: Vec<_> = ephemeral_keys.collect();
        let epks = jubjub::AffinePoint::batch_from_bytes(ephemeral_keys.iter().map(|b| b.0));
        epks.into_iter()
            .zip(ephemeral_keys.into_iter())
            .map(|(epk, ephemeral_key)| {
                (
                    Option::from(epk)
                        .map(EphemeralPublicKey::from_affine)
                        .map(Self::prepare_epk),
                    ephemeral_key,
                )
            })
            .collect()
    }
}

/// Creates a new encryption context for the given note.
///
/// Setting `ovk` to `None` represents the `ovk = ⊥` case, where the note cannot be
/// recovered by the sender.
///
/// NB: the example code here only covers the post-Canopy case.
///
/// # Examples
///
/// ```
/// use ff::Field;
/// use rand_core::OsRng;
/// use zcash_primitives::{
///     keys::{OutgoingViewingKey, prf_expand},
///     consensus::{TEST_NETWORK, TestNetwork, NetworkUpgrade, Parameters},
///     memo::MemoBytes,
///     sapling::{
///         note_encryption::sapling_note_encryption,
///         util::generate_random_rseed,
///         value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
///         Diversifier, PaymentAddress, Rseed, SaplingIvk,
///     },
/// };
///
/// let mut rng = OsRng;
///
/// let ivk = SaplingIvk(jubjub::Scalar::random(&mut rng));
/// let diversifier = Diversifier([0; 11]);
/// let to = ivk.to_payment_address(diversifier).unwrap();
/// let ovk = Some(OutgoingViewingKey([0; 32]));
///
/// let value = NoteValue::from_raw(1000);
/// let rcv = ValueCommitTrapdoor::random(&mut rng);
/// let cv = ValueCommitment::derive(value, rcv);
/// let height = TEST_NETWORK.activation_height(NetworkUpgrade::Canopy).unwrap();
/// let rseed = generate_random_rseed(&TEST_NETWORK, height, &mut rng);
/// let note = to.create_note(value.inner(), rseed);
/// let cmu = note.cmu();
///
/// let mut enc = sapling_note_encryption::<_, TestNetwork>(ovk, note, MemoBytes::empty(), &mut rng);
/// let encCiphertext = enc.encrypt_note_plaintext();
/// let outCiphertext = enc.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng);
/// ```
pub fn sapling_note_encryption<R: RngCore, P: consensus::Parameters>(
    ovk: Option<OutgoingViewingKey>,
    note: Note,
    memo: MemoBytes,
    rng: &mut R,
) -> NoteEncryption<SaplingDomain<P>> {
    let esk = note.generate_or_derive_esk_internal(rng);
    NoteEncryption::new_with_esk(esk, ovk, note, memo)
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

pub fn try_sapling_note_decryption<
    P: consensus::Parameters,
    Output: ShieldedOutput<SaplingDomain<P>>,
>(
    params: &P,
    height: BlockHeight,
    ivk: &PreparedIncomingViewingKey,
    output: &Output,
) -> Option<(Note, PaymentAddress, MemoBytes)> {
    let domain = SaplingDomain {
        params: params.clone(),
        height,
    };
    try_note_decryption(&domain, ivk, output)
}

pub fn try_sapling_compact_note_decryption<
    P: consensus::Parameters,
    Output: ShieldedOutput<SaplingDomain<P>>,
>(
    params: &P,
    height: BlockHeight,
    ivk: &PreparedIncomingViewingKey,
    output: &Output,
) -> Option<(Note, PaymentAddress)> {
    let domain = SaplingDomain {
        params: params.clone(),
        height,
    };

    try_compact_note_decryption(&domain, ivk, output)
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ock`.
/// If successful, the corresponding Sapling note and memo are returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements part of section 4.19.3 of the Zcash Protocol Specification.
/// For decryption using a Full Viewing Key see [`try_sapling_output_recovery`].
pub fn try_sapling_output_recovery_with_ock<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    ock: &OutgoingCipherKey,
    output: &OutputDescription<sapling::GrothProofBytes>,
) -> Option<(Note, PaymentAddress, MemoBytes)> {
    let domain = SaplingDomain {
        params: params.clone(),
        height,
    };

    try_output_recovery_with_ock(&domain, ock, output, output.out_ciphertext())
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ovk`.
/// If successful, the corresponding Sapling note and memo are returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements section 4.19.3 of the Zcash Protocol Specification.
#[allow(clippy::too_many_arguments)]
pub fn try_sapling_output_recovery<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    ovk: &OutgoingViewingKey,
    output: &OutputDescription<sapling::GrothProofBytes>,
) -> Option<(Note, PaymentAddress, MemoBytes)> {
    let domain = SaplingDomain {
        params: params.clone(),
        height,
    };

    try_output_recovery_with_ovk(&domain, ovk, output, output.cv(), output.out_ciphertext())
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        ChaCha20Poly1305,
    };
    use ff::{Field, PrimeField};
    use group::Group;
    use group::GroupEncoding;
    use rand_core::OsRng;
    use rand_core::{CryptoRng, RngCore};

    use zcash_note_encryption::{
        batch, EphemeralKeyBytes, NoteEncryption, OutgoingCipherKey, OUT_CIPHERTEXT_SIZE,
        OUT_PLAINTEXT_SIZE,
    };

    use super::{
        prf_ock, sapling_note_encryption, try_sapling_compact_note_decryption,
        try_sapling_note_decryption, try_sapling_output_recovery,
        try_sapling_output_recovery_with_ock, SaplingDomain,
    };

    use crate::{
        consensus::{
            BlockHeight,
            NetworkUpgrade::{Canopy, Sapling},
            Parameters, TestNetwork, TEST_NETWORK, ZIP212_GRACE_PERIOD,
        },
        keys::OutgoingViewingKey,
        memo::MemoBytes,
        sapling::{
            keys::{DiversifiedTransmissionKey, EphemeralSecretKey},
            note::ExtractedNoteCommitment,
            note_encryption::PreparedIncomingViewingKey,
            note_encryption::{ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE},
            util::generate_random_rseed,
            value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
            Diversifier, PaymentAddress, Rseed, SaplingIvk,
        },
        transaction::components::{
            sapling::{self, CompactOutputDescription, OutputDescription},
            GROTH_PROOF_SIZE,
        },
    };

    fn random_enc_ciphertext<R: RngCore + CryptoRng>(
        height: BlockHeight,
        mut rng: &mut R,
    ) -> (
        OutgoingViewingKey,
        OutgoingCipherKey,
        PreparedIncomingViewingKey,
        OutputDescription<sapling::GrothProofBytes>,
    ) {
        let ivk = SaplingIvk(jubjub::Fr::random(&mut rng));
        let prepared_ivk = PreparedIncomingViewingKey::new(&ivk);

        let (ovk, ock, output) = random_enc_ciphertext_with(height, &ivk, rng);

        assert!(
            try_sapling_note_decryption(&TEST_NETWORK, height, &prepared_ivk, &output).is_some()
        );
        assert!(try_sapling_compact_note_decryption(
            &TEST_NETWORK,
            height,
            &prepared_ivk,
            &CompactOutputDescription::from(output.clone()),
        )
        .is_some());

        let ovk_output_recovery = try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output);

        let ock_output_recovery =
            try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output);
        assert!(ovk_output_recovery.is_some());
        assert!(ock_output_recovery.is_some());
        assert_eq!(ovk_output_recovery, ock_output_recovery);

        (ovk, ock, prepared_ivk, output)
    }

    fn random_enc_ciphertext_with<R: RngCore + CryptoRng>(
        height: BlockHeight,
        ivk: &SaplingIvk,
        mut rng: &mut R,
    ) -> (
        OutgoingViewingKey,
        OutgoingCipherKey,
        OutputDescription<sapling::GrothProofBytes>,
    ) {
        let diversifier = Diversifier([0; 11]);
        let pa = ivk.to_payment_address(diversifier).unwrap();

        // Construct the value commitment for the proof instance
        let value = NoteValue::from_raw(100);
        let rcv = ValueCommitTrapdoor::random(&mut rng);
        let cv = ValueCommitment::derive(value, rcv);

        let rseed = generate_random_rseed(&TEST_NETWORK, height, &mut rng);

        let note = pa.create_note(value.inner(), rseed);
        let cmu = note.cmu();

        let ovk = OutgoingViewingKey([0; 32]);
        let ne = sapling_note_encryption::<_, TestNetwork>(
            Some(ovk),
            note,
            MemoBytes::empty(),
            &mut rng,
        );
        let epk = ne.epk();
        let ock = prf_ock(&ovk, &cv, &cmu.to_bytes(), &epk.to_bytes());

        let out_ciphertext = ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng);
        let output = OutputDescription::from_parts(
            cv,
            cmu,
            epk.to_bytes(),
            ne.encrypt_note_plaintext().0,
            out_ciphertext,
            [0u8; GROTH_PROOF_SIZE],
        );

        (ovk, ock, output)
    }

    fn reencrypt_out_ciphertext(
        ovk: &OutgoingViewingKey,
        cv: &ValueCommitment,
        cmu: &ExtractedNoteCommitment,
        ephemeral_key: &EphemeralKeyBytes,
        out_ciphertext: &[u8; OUT_CIPHERTEXT_SIZE],
        modify_plaintext: impl Fn(&mut [u8; OUT_PLAINTEXT_SIZE]),
    ) -> [u8; OUT_CIPHERTEXT_SIZE] {
        let ock = prf_ock(ovk, cv, &cmu.to_bytes(), ephemeral_key);

        let mut op = [0; OUT_PLAINTEXT_SIZE];
        op.copy_from_slice(&out_ciphertext[..OUT_PLAINTEXT_SIZE]);

        ChaCha20Poly1305::new(ock.as_ref().into())
            .decrypt_in_place_detached(
                [0u8; 12][..].into(),
                &[],
                &mut op,
                out_ciphertext[OUT_PLAINTEXT_SIZE..].into(),
            )
            .unwrap();

        modify_plaintext(&mut op);

        let tag = ChaCha20Poly1305::new(ock.as_ref().into())
            .encrypt_in_place_detached([0u8; 12][..].into(), &[], &mut op)
            .unwrap();

        let mut out_ciphertext = [0u8; OUT_CIPHERTEXT_SIZE];
        out_ciphertext[..OUT_PLAINTEXT_SIZE].copy_from_slice(&op);
        out_ciphertext[OUT_PLAINTEXT_SIZE..].copy_from_slice(&tag);
        out_ciphertext
    }

    fn reencrypt_enc_ciphertext(
        ovk: &OutgoingViewingKey,
        cv: &ValueCommitment,
        cmu: &ExtractedNoteCommitment,
        ephemeral_key: &EphemeralKeyBytes,
        enc_ciphertext: &[u8; ENC_CIPHERTEXT_SIZE],
        out_ciphertext: &[u8; OUT_CIPHERTEXT_SIZE],
        modify_plaintext: impl Fn(&mut [u8; NOTE_PLAINTEXT_SIZE]),
    ) -> [u8; ENC_CIPHERTEXT_SIZE] {
        let ock = prf_ock(ovk, cv, &cmu.to_bytes(), ephemeral_key);

        let mut op = [0; OUT_PLAINTEXT_SIZE];
        op.copy_from_slice(&out_ciphertext[..OUT_PLAINTEXT_SIZE]);

        ChaCha20Poly1305::new(ock.as_ref().into())
            .decrypt_in_place_detached(
                [0u8; 12][..].into(),
                &[],
                &mut op,
                out_ciphertext[OUT_PLAINTEXT_SIZE..].into(),
            )
            .unwrap();

        let pk_d = DiversifiedTransmissionKey::from_bytes(&op[0..32].try_into().unwrap()).unwrap();

        let esk = jubjub::Fr::from_repr(op[32..OUT_PLAINTEXT_SIZE].try_into().unwrap()).unwrap();

        let shared_secret = EphemeralSecretKey(esk).agree(&pk_d);
        let key = shared_secret.kdf_sapling(ephemeral_key);

        let mut plaintext = [0; NOTE_PLAINTEXT_SIZE];
        plaintext.copy_from_slice(&enc_ciphertext[..NOTE_PLAINTEXT_SIZE]);

        ChaCha20Poly1305::new(key.as_bytes().into())
            .decrypt_in_place_detached(
                [0u8; 12][..].into(),
                &[],
                &mut plaintext,
                enc_ciphertext[NOTE_PLAINTEXT_SIZE..].into(),
            )
            .unwrap();

        modify_plaintext(&mut plaintext);

        let tag = ChaCha20Poly1305::new(key.as_ref().into())
            .encrypt_in_place_detached([0u8; 12][..].into(), &[], &mut plaintext)
            .unwrap();

        let mut enc_ciphertext = [0u8; ENC_CIPHERTEXT_SIZE];
        enc_ciphertext[..NOTE_PLAINTEXT_SIZE].copy_from_slice(&plaintext);
        enc_ciphertext[NOTE_PLAINTEXT_SIZE..].copy_from_slice(&tag);
        enc_ciphertext
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
            let (_, _, _, output) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &PreparedIncomingViewingKey::new(&SaplingIvk(jubjub::Fr::random(&mut rng))),
                    &output
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
            let (_, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.ephemeral_key_mut() = jubjub::ExtendedPoint::random(&mut rng).to_bytes().into();

            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output,),
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
            let (_, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);
            *output.cmu_mut() =
                ExtractedNoteCommitment::from_bytes(&bls12_381::Scalar::random(&mut rng).to_repr())
                    .unwrap();

            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output),
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
            let (_, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);
            output.enc_ciphertext_mut()[ENC_CIPHERTEXT_SIZE - 1] ^= 0xff;

            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output),
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
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.enc_ciphertext_mut() = reencrypt_enc_ciphertext(
                &ovk,
                output.cv(),
                output.cmu(),
                output.ephemeral_key(),
                output.enc_ciphertext(),
                output.out_ciphertext(),
                |pt| pt[0] = leadbyte,
            );
            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output),
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
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.enc_ciphertext_mut() = reencrypt_enc_ciphertext(
                &ovk,
                output.cv(),
                output.cmu(),
                output.ephemeral_key(),
                output.enc_ciphertext(),
                output.out_ciphertext(),
                |pt| pt[1..12].copy_from_slice(&find_invalid_diversifier().0),
            );
            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output),
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
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.enc_ciphertext_mut() = reencrypt_enc_ciphertext(
                &ovk,
                output.cv(),
                output.cmu(),
                output.ephemeral_key(),
                output.enc_ciphertext(),
                output.out_ciphertext(),
                |pt| pt[1..12].copy_from_slice(&find_valid_diversifier().0),
            );

            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output),
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
            let (_, _, _, output) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &PreparedIncomingViewingKey::new(&SaplingIvk(jubjub::Fr::random(&mut rng))),
                    &CompactOutputDescription::from(output)
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
            let (_, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);
            *output.ephemeral_key_mut() = jubjub::ExtendedPoint::random(&mut rng).to_bytes().into();

            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &CompactOutputDescription::from(output)
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
            let (_, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);
            *output.cmu_mut() =
                ExtractedNoteCommitment::from_bytes(&bls12_381::Scalar::random(&mut rng).to_repr())
                    .unwrap();

            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &CompactOutputDescription::from(output)
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
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.enc_ciphertext_mut() = reencrypt_enc_ciphertext(
                &ovk,
                output.cv(),
                output.cmu(),
                output.ephemeral_key(),
                output.enc_ciphertext(),
                output.out_ciphertext(),
                |pt| pt[0] = leadbyte,
            );
            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &CompactOutputDescription::from(output)
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
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.enc_ciphertext_mut() = reencrypt_enc_ciphertext(
                &ovk,
                output.cv(),
                output.cmu(),
                output.ephemeral_key(),
                output.enc_ciphertext(),
                output.out_ciphertext(),
                |pt| pt[1..12].copy_from_slice(&find_invalid_diversifier().0),
            );
            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &CompactOutputDescription::from(output)
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
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.enc_ciphertext_mut() = reencrypt_enc_ciphertext(
                &ovk,
                output.cv(),
                output.cmu(),
                output.ephemeral_key(),
                output.enc_ciphertext(),
                output.out_ciphertext(),
                |pt| pt[1..12].copy_from_slice(&find_valid_diversifier().0),
            );
            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &CompactOutputDescription::from(output)
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
            let (mut ovk, _, _, output) = random_enc_ciphertext(height, &mut rng);

            ovk.0[0] ^= 0xff;
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
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
            let (_, _, _, output) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &OutgoingCipherKey([0u8; 32]),
                    &output,
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
            let (ovk, _, _, mut output) = random_enc_ciphertext(height, &mut rng);
            *output.cv_mut() = ValueCommitment::derive(
                NoteValue::from_raw(7),
                ValueCommitTrapdoor::random(&mut rng),
            );

            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
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
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);
            *output.cmu_mut() =
                ExtractedNoteCommitment::from_bytes(&bls12_381::Scalar::random(&mut rng).to_repr())
                    .unwrap();

            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );

            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
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
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);
            *output.ephemeral_key_mut() = jubjub::ExtendedPoint::random(&mut rng).to_bytes().into();

            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );

            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
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
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            output.enc_ciphertext_mut()[ENC_CIPHERTEXT_SIZE - 1] ^= 0xff;
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
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
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            output.out_ciphertext_mut()[OUT_CIPHERTEXT_SIZE - 1] ^= 0xff;
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
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
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.enc_ciphertext_mut() = reencrypt_enc_ciphertext(
                &ovk,
                output.cv(),
                output.cmu(),
                output.ephemeral_key(),
                output.enc_ciphertext(),
                output.out_ciphertext(),
                |pt| pt[0] = leadbyte,
            );
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
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
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.enc_ciphertext_mut() = reencrypt_enc_ciphertext(
                &ovk,
                output.cv(),
                output.cmu(),
                output.ephemeral_key(),
                output.enc_ciphertext(),
                output.out_ciphertext(),
                |pt| pt[1..12].copy_from_slice(&find_invalid_diversifier().0),
            );
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
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
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.enc_ciphertext_mut() = reencrypt_enc_ciphertext(
                &ovk,
                output.cv(),
                output.cmu(),
                output.ephemeral_key(),
                output.enc_ciphertext(),
                output.out_ciphertext(),
                |pt| pt[1..12].copy_from_slice(&find_valid_diversifier().0),
            );
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
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
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            *output.out_ciphertext_mut() = reencrypt_out_ciphertext(
                &ovk,
                output.cv(),
                output.cmu(),
                output.ephemeral_key(),
                output.out_ciphertext(),
                |pt| pt[0..32].copy_from_slice(&jubjub::ExtendedPoint::random(rng).to_bytes()),
            );
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
                None
            );
        }
    }

    #[test]
    fn test_vectors() {
        let test_vectors = crate::test_vectors::note_encryption::make_test_vectors();

        macro_rules! read_cmu {
            ($field:expr) => {{
                ExtractedNoteCommitment::from_bytes($field[..].try_into().unwrap()).unwrap()
            }};
        }

        macro_rules! read_jubjub_scalar {
            ($field:expr) => {{
                jubjub::Fr::from_repr($field[..].try_into().unwrap()).unwrap()
            }};
        }

        macro_rules! read_pk_d {
            ($field:expr) => {
                DiversifiedTransmissionKey::from_bytes(&$field).unwrap()
            };
        }

        macro_rules! read_cv {
            ($field:expr) => {
                ValueCommitment::from_bytes_not_small_order(&$field).unwrap()
            };
        }

        let height = TEST_NETWORK.activation_height(Sapling).unwrap();

        for tv in test_vectors {
            //
            // Load the test vector components
            //

            let ivk = PreparedIncomingViewingKey::new(&SaplingIvk(read_jubjub_scalar!(tv.ivk)));
            let pk_d = read_pk_d!(tv.default_pk_d);
            let rcm = read_jubjub_scalar!(tv.rcm);
            let cv = read_cv!(tv.cv);
            let cmu = read_cmu!(tv.cmu);
            let esk = EphemeralSecretKey(read_jubjub_scalar!(tv.esk));
            let ephemeral_key = EphemeralKeyBytes(tv.epk);

            //
            // Test the individual components
            //

            let shared_secret = esk.agree(&pk_d);
            assert_eq!(shared_secret.to_bytes(), tv.shared_secret);

            let k_enc = shared_secret.kdf_sapling(&ephemeral_key);
            assert_eq!(k_enc.as_bytes(), tv.k_enc);

            let ovk = OutgoingViewingKey(tv.ovk);
            let ock = prf_ock(&ovk, &cv, &cmu.to_bytes(), &ephemeral_key);
            assert_eq!(ock.as_ref(), tv.ock);

            let to = PaymentAddress::from_parts(Diversifier(tv.default_d), pk_d).unwrap();
            let note = to.create_note(tv.v, Rseed::BeforeZip212(rcm));
            assert_eq!(note.cmu(), cmu);

            let output = OutputDescription::from_parts(
                cv.clone(),
                cmu,
                ephemeral_key,
                tv.c_enc,
                tv.c_out,
                [0u8; GROTH_PROOF_SIZE],
            );

            //
            // Test decryption
            // (Tested first because it only requires immutable references.)
            //

            match try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output) {
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
                &CompactOutputDescription::from(output.clone()),
            ) {
                Some((decrypted_note, decrypted_to)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                }
                None => panic!("Compact note decryption failed"),
            }

            match try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                    assert_eq!(&decrypted_memo.as_array()[..], &tv.memo[..]);
                }
                None => panic!("Output recovery failed"),
            }

            match &batch::try_note_decryption(
                &[ivk.clone()],
                &[(
                    SaplingDomain::for_height(TEST_NETWORK, height),
                    output.clone(),
                )],
            )[..]
            {
                [Some(((decrypted_note, decrypted_to, decrypted_memo), i))] => {
                    assert_eq!(decrypted_note, &note);
                    assert_eq!(decrypted_to, &to);
                    assert_eq!(&decrypted_memo.as_array()[..], &tv.memo[..]);
                    assert_eq!(*i, 0);
                }
                _ => panic!("Note decryption failed"),
            }

            match &batch::try_compact_note_decryption(
                &[ivk.clone()],
                &[(
                    SaplingDomain::for_height(TEST_NETWORK, height),
                    CompactOutputDescription::from(output.clone()),
                )],
            )[..]
            {
                [Some(((decrypted_note, decrypted_to), i))] => {
                    assert_eq!(decrypted_note, &note);
                    assert_eq!(decrypted_to, &to);
                    assert_eq!(*i, 0);
                }
                _ => panic!("Note decryption failed"),
            }

            //
            // Test encryption
            //

            let ne = NoteEncryption::<SaplingDomain<TestNetwork>>::new_with_esk(
                esk,
                Some(ovk),
                note,
                MemoBytes::from_bytes(&tv.memo).unwrap(),
            );

            assert_eq!(ne.encrypt_note_plaintext().as_ref(), &tv.c_enc[..]);
            assert_eq!(
                &ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut OsRng)[..],
                &tv.c_out[..]
            );
        }
    }

    #[test]
    fn batching() {
        let mut rng = OsRng;
        let height = TEST_NETWORK.activation_height(Canopy).unwrap();

        // Test batch trial-decryption with multiple IVKs and outputs.
        let invalid_ivk = PreparedIncomingViewingKey::new(&SaplingIvk(jubjub::Fr::random(rng)));
        let valid_ivk = SaplingIvk(jubjub::Fr::random(rng));
        let outputs: Vec<_> = (0..10)
            .map(|_| {
                (
                    SaplingDomain::for_height(TEST_NETWORK, height),
                    random_enc_ciphertext_with(height, &valid_ivk, &mut rng).2,
                )
            })
            .collect();
        let valid_ivk = PreparedIncomingViewingKey::new(&valid_ivk);

        // Check that batched trial decryptions with invalid_ivk fails.
        let res = batch::try_note_decryption(&[invalid_ivk.clone()], &outputs);
        assert_eq!(res.len(), 10);
        assert_eq!(&res[..], &vec![None; 10][..]);

        // Check that batched trial decryptions with valid_ivk succeeds.
        let res = batch::try_note_decryption(&[invalid_ivk, valid_ivk.clone()], &outputs);
        assert_eq!(res.len(), 10);
        for (result, (_, output)) in res.iter().zip(outputs.iter()) {
            // Confirm the successful batched trial decryptions gave the same result.
            // In all cases, the index of the valid ivk is returned.
            assert!(result.is_some());
            assert_eq!(
                result,
                &try_sapling_note_decryption(&TEST_NETWORK, height, &valid_ivk, output)
                    .map(|r| (r, 1))
            );
        }
    }
}
