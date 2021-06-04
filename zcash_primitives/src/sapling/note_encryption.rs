//! Implementation of in-band secret distribution for Zcash transactions.
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use group::{cofactor::CofactorGroup, GroupEncoding};
use rand_core::RngCore;
use std::convert::TryInto;

use zcash_note_encryption::{
    try_compact_note_decryption, try_note_decryption, try_output_recovery_with_ock,
    try_output_recovery_with_ovk, Domain, EphemeralKeyBytes, NoteEncryption, NotePlaintextBytes,
    NoteValidity, OutPlaintextBytes, OutgoingCipherKey, ShieldedOutput, COMPACT_NOTE_SIZE,
    NOTE_PLAINTEXT_SIZE, OUT_PLAINTEXT_SIZE,
};

use crate::{
    consensus::{self, BlockHeight, NetworkUpgrade::Canopy, ZIP212_GRACE_PERIOD},
    memo::MemoBytes,
    sapling::{keys::OutgoingViewingKey, Diversifier, Note, PaymentAddress, Rseed, SaplingIvk},
    transaction::components::{
        amount::Amount,
        sapling::{self, OutputDescription},
    },
};

pub const KDF_SAPLING_PERSONALIZATION: &[u8; 16] = b"Zcash_SaplingKDF";
pub const PRF_OCK_PERSONALIZATION: &[u8; 16] = b"Zcash_Derive_ock";

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
fn kdf_sapling(dhsecret: jubjub::SubgroupPoint, ephemeral_key: &EphemeralKeyBytes) -> Blake2bHash {
    Blake2bParams::new()
        .hash_length(32)
        .personal(KDF_SAPLING_PERSONALIZATION)
        .to_state()
        .update(&dhsecret.to_bytes())
        .update(ephemeral_key.as_ref())
        .finalize()
}

/// Sapling PRF^ock.
///
/// Implemented per section 5.4.2 of the Zcash Protocol Specification.
pub fn prf_ock(
    ovk: &OutgoingViewingKey,
    cv: &jubjub::ExtendedPoint,
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

fn epk_bytes(epk: &jubjub::ExtendedPoint) -> EphemeralKeyBytes {
    EphemeralKeyBytes(epk.to_bytes())
}

fn sapling_parse_note_plaintext_without_memo<F, P: consensus::Parameters>(
    domain: &SaplingDomain<P>,
    plaintext: &[u8],
    get_validated_pk_d: F,
) -> Option<(Note, PaymentAddress)>
where
    F: FnOnce(&Diversifier) -> Option<jubjub::SubgroupPoint>,
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
        let rcm = jubjub::Fr::from_repr(r)?;
        Rseed::BeforeZip212(rcm)
    } else {
        Rseed::AfterZip212(r)
    };

    let pk_d = get_validated_pk_d(&diversifier)?;

    let to = PaymentAddress::from_parts(diversifier, pk_d)?;
    let note = to.create_note(value.into(), rseed)?;
    Some((note, to))
}

pub struct SaplingDomain<P: consensus::Parameters> {
    params: P,
    height: BlockHeight,
}

impl<P: consensus::Parameters> Domain for SaplingDomain<P> {
    type EphemeralSecretKey = jubjub::Scalar;
    // It is acceptable for this to be a point because we enforce by consensus that
    // points must not be small-order, and all points with non-canonical serialization
    // are small-order.
    type EphemeralPublicKey = jubjub::ExtendedPoint;
    type SharedSecret = jubjub::SubgroupPoint;
    type SymmetricKey = Blake2bHash;
    type Note = Note;
    type Recipient = PaymentAddress;
    type DiversifiedTransmissionKey = jubjub::SubgroupPoint;
    type IncomingViewingKey = SaplingIvk;
    type OutgoingViewingKey = OutgoingViewingKey;
    type ValueCommitment = jubjub::ExtendedPoint;
    type ExtractedCommitment = bls12_381::Scalar;
    type ExtractedCommitmentBytes = [u8; 32];
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
    fn kdf(dhsecret: jubjub::SubgroupPoint, epk: &EphemeralKeyBytes) -> Blake2bHash {
        kdf_sapling(dhsecret, epk)
    }

    fn note_plaintext_bytes(
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
        input[0..32].copy_from_slice(&note.pk_d.to_bytes());
        input[32..OUT_PLAINTEXT_SIZE].copy_from_slice(esk.to_repr().as_ref());

        OutPlaintextBytes(input)
    }

    fn epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes {
        epk_bytes(epk)
    }

    fn check_epk_bytes<F: FnOnce(&Self::EphemeralSecretKey) -> NoteValidity>(
        note: &Note,
        check: F,
    ) -> NoteValidity {
        if let Some(derived_esk) = note.derive_esk() {
            check(&derived_esk)
        } else {
            // Before ZIP 212
            NoteValidity::Valid
        }
    }

    fn parse_note_plaintext_without_memo_ivk(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)> {
        sapling_parse_note_plaintext_without_memo(&self, plaintext, |diversifier| {
            Some(diversifier.g_d()? * ivk.0)
        })
    }

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        esk: &Self::EphemeralSecretKey,
        epk: &Self::EphemeralPublicKey,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)> {
        sapling_parse_note_plaintext_without_memo(&self, plaintext, |diversifier| {
            if (diversifier.g_d()? * esk).to_bytes() == epk.to_bytes() {
                Some(*pk_d)
            } else {
                None
            }
        })
    }

    fn cmstar(note: &Self::Note) -> Self::ExtractedCommitment {
        note.cmu()
    }

    fn extract_pk_d(op: &[u8; OUT_PLAINTEXT_SIZE]) -> Option<Self::DiversifiedTransmissionKey> {
        let pk_d = jubjub::SubgroupPoint::from_bytes(
            op[0..32].try_into().expect("slice is the correct length"),
        );

        if pk_d.is_none().into() {
            None
        } else {
            Some(pk_d.unwrap())
        }
    }

    fn extract_esk(op: &[u8; OUT_PLAINTEXT_SIZE]) -> Option<Self::EphemeralSecretKey> {
        jubjub::Fr::from_repr(
            op[32..OUT_PLAINTEXT_SIZE]
                .try_into()
                .expect("slice is the correct length"),
        )
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
    NoteEncryption::new_with_esk(esk, ovk, note, to, memo)
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
    ivk: &SaplingIvk,
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
    ivk: &SaplingIvk,
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

    try_output_recovery_with_ock(&domain, ock, output, &output.out_ciphertext)
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

    try_output_recovery_with_ovk(&domain, ovk, output, &output.cv, &output.out_ciphertext)
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

    use zcash_note_encryption::{
        NoteEncryption, OutgoingCipherKey, ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE,
        OUT_CIPHERTEXT_SIZE, OUT_PLAINTEXT_SIZE,
    };

    use super::{
        epk_bytes, kdf_sapling, prf_ock, sapling_ka_agree, sapling_note_encryption,
        try_sapling_compact_note_decryption, try_sapling_note_decryption,
        try_sapling_output_recovery, try_sapling_output_recovery_with_ock, SaplingDomain,
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
        transaction::components::{
            amount::Amount,
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
        SaplingIvk,
        OutputDescription<sapling::GrothProofBytes>,
    ) {
        let ivk = SaplingIvk(jubjub::Fr::random(&mut rng));

        let (ovk, ock, output) = random_enc_ciphertext_with(height, &ivk, rng);

        assert!(try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output).is_some());
        assert!(try_sapling_compact_note_decryption(
            &TEST_NETWORK,
            height,
            &ivk,
            &CompactOutputDescription::from(output.clone()),
        )
        .is_some());

        let ovk_output_recovery = try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output);

        let ock_output_recovery =
            try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output);
        assert!(ovk_output_recovery.is_some());
        assert!(ock_output_recovery.is_some());
        assert_eq!(ovk_output_recovery, ock_output_recovery);

        (ovk, ock, ivk, output)
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
        let ne = sapling_note_encryption::<_, TestNetwork>(
            Some(ovk),
            note,
            pa,
            MemoBytes::empty(),
            &mut rng,
        );
        let epk = *ne.epk();
        let ock = prf_ock(&ovk, &cv, &cmu.to_repr(), &epk_bytes(&epk));

        let output = OutputDescription {
            cv,
            cmu,
            ephemeral_key: epk,
            enc_ciphertext: ne.encrypt_note_plaintext(),
            out_ciphertext: ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng),
            zkproof: [0u8; GROTH_PROOF_SIZE],
        };

        (ovk, ock, output)
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
        let ock = prf_ock(&ovk, &cv, &cmu.to_repr(), &epk_bytes(epk));

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
        let key = kdf_sapling(shared_secret, &epk_bytes(&epk));

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
            let (_, _, _, output) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &SaplingIvk(jubjub::Fr::random(&mut rng)),
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

            output.ephemeral_key = jubjub::ExtendedPoint::random(&mut rng);

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
            output.cmu = bls12_381::Scalar::random(&mut rng);

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
            output.enc_ciphertext[ENC_CIPHERTEXT_SIZE - 1] ^= 0xff;

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

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
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

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
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

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
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
                    &SaplingIvk(jubjub::Fr::random(&mut rng)),
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
            output.ephemeral_key = jubjub::ExtendedPoint::random(&mut rng);

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
            output.cmu = bls12_381::Scalar::random(&mut rng);

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

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
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

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
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

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
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
            output.cv = jubjub::ExtendedPoint::random(&mut rng);

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
            output.cmu = bls12_381::Scalar::random(&mut rng);

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
            output.ephemeral_key = jubjub::ExtendedPoint::random(&mut rng);

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

            output.enc_ciphertext[ENC_CIPHERTEXT_SIZE - 1] ^= 0xff;
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

            output.out_ciphertext[OUT_CIPHERTEXT_SIZE - 1] ^= 0xff;
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

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
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

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
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

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
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
            let ivk = SaplingIvk(jubjub::Fr::zero());
            let (ovk, ock, output) = random_enc_ciphertext_with(height, &ivk, &mut rng);

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

            let k_enc = kdf_sapling(shared_secret, &epk_bytes(&epk));
            assert_eq!(k_enc.as_bytes(), tv.k_enc);

            let ovk = OutgoingViewingKey(tv.ovk);
            let ock = prf_ock(&ovk, &cv, &cmu.to_repr(), &epk_bytes(&epk));
            assert_eq!(ock.as_ref(), tv.ock);

            let to = PaymentAddress::from_parts(Diversifier(tv.default_d), pk_d).unwrap();
            let note = to.create_note(tv.v, Rseed::BeforeZip212(rcm)).unwrap();
            assert_eq!(note.cmu(), cmu);

            let output = OutputDescription {
                cv,
                cmu,
                ephemeral_key: epk,
                enc_ciphertext: tv.c_enc,
                out_ciphertext: tv.c_out,
                zkproof: [0u8; GROTH_PROOF_SIZE],
            };

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

            //
            // Test encryption
            //

            let ne = NoteEncryption::<SaplingDomain<TestNetwork>>::new_with_esk(
                esk,
                Some(ovk),
                note,
                to,
                MemoBytes::from_bytes(&tv.memo).unwrap(),
            );

            assert_eq!(ne.encrypt_note_plaintext().as_ref(), &tv.c_enc[..]);
            assert_eq!(
                &ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut OsRng)[..],
                &tv.c_out[..]
            );
        }
    }
}
