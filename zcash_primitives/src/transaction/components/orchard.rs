//! Functions for parsing & serialization of Orchard transaction components.
use crate::encoding::ReadBytesExt;

use alloc::vec::Vec;
use core::convert::TryFrom;
use corez::io::{self, Read, Write};

use nonempty::NonEmpty;

use core::mem::size_of;
use orchard::{
    Action, Anchor, ValuePool,
    bundle::{Authorization, Authorized, BundleVersion, Flags},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    primitives::redpallas::{self, SigType, Signature, SpendAuth, VerificationKey},
    value::ValueCommitment,
};
use zcash_encoding::{Array, CompactSize, Vector};
use zcash_note_encryption::{ENC_CIPHERTEXT_SIZE, EphemeralKeyBytes, OUT_CIPHERTEXT_SIZE};
use zcash_protocol::{
    consensus::{BranchId, OrchardProtocolRevision},
    value::ZatBalance,
};

use crate::transaction::Transaction;

pub const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;
pub const FLAG_OUTPUTS_ENABLED: u8 = 0b0000_0010;
pub const FLAGS_EXPECTED_UNSET: u8 = !(FLAG_SPENDS_ENABLED | FLAG_OUTPUTS_ENABLED);

/// The size in bytes of the encoding of a Pallas group element or base field element.
///
/// Every such value in an Orchard action — the value commitment, nullifier, randomized
/// verification key, note commitment, and ephemeral key — is encoded in this many bytes.
/// [`EphemeralKeyBytes`] is the encoding of one of them (the ephemeral key, a group element),
/// so its width is that of all of them; note that this is a property of the *encoding*, not of
/// the in-memory representation, which differs between these types.
const PALLAS_ENCODING_SIZE: usize = size_of::<EphemeralKeyBytes>();

/// The number of Pallas encodings in an Orchard action description: the value commitment,
/// nullifier, randomized verification key, note commitment, and ephemeral key.
const PALLAS_ENCODINGS_PER_ACTION: usize = 5;

/// The size in bytes of an Orchard action description, as written by
/// [`write_action_without_auth`].
///
/// This does not include the action's spend authorization signature or its share of the bundle's
/// proof, both of which are encoded separately from the action descriptions (see
/// [`write_v5_bundle`]). Dividing a size budget by this constant therefore yields an upper bound
/// on the number of actions that fit within it.
pub const ACTION_SIZE: usize =
    PALLAS_ENCODINGS_PER_ACTION * PALLAS_ENCODING_SIZE + ENC_CIPHERTEXT_SIZE + OUT_CIPHERTEXT_SIZE;

pub trait MapAuth<A: Authorization, B: Authorization> {
    fn map_spend_auth(&self, s: A::SpendAuth) -> B::SpendAuth;
    fn map_authorization(&self, a: A) -> B;
}

/// The identity map.
///
/// This can be used with [`TransactionData::map_authorization`] when you want to map the
/// authorization of a subset of the transaction's bundles.
///
/// [`TransactionData::map_authorization`]: crate::transaction::TransactionData::map_authorization
impl MapAuth<Authorized, Authorized> for () {
    fn map_spend_auth(
        &self,
        s: <Authorized as Authorization>::SpendAuth,
    ) -> <Authorized as Authorization>::SpendAuth {
        s
    }

    fn map_authorization(&self, a: Authorized) -> Authorized {
        a
    }
}

fn read_bundle<R: Read>(
    mut reader: R,
    bundle_version: Option<BundleVersion>,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    #[allow(clippy::redundant_closure)]
    let actions_without_auth = Vector::read(&mut reader, |r| read_action_without_auth(r))?;
    if actions_without_auth.is_empty() {
        Ok(None)
    } else {
        let bundle_version = bundle_version.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Orchard-protocol bundles may not be present in this transaction version \
                 under the transaction's consensus branch ID",
            )
        })?;
        let flags = read_flags(&mut reader, bundle_version)?;
        let value_balance = Transaction::read_amount(&mut reader)?;
        let anchor = read_anchor(&mut reader)?;
        let proof_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
        let actions = NonEmpty::from_vec(
            actions_without_auth
                .into_iter()
                .map(|act| act.try_map(|_| read_signature::<_, redpallas::SpendAuth>(&mut reader)))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .expect("A nonzero number of actions was read from the transaction data.");
        let binding_signature = read_signature::<_, redpallas::Binding>(&mut reader)?;

        let authorization = orchard::bundle::Authorized::from_parts(
            orchard::Proof::new(proof_bytes),
            binding_signature,
        );

        // `try_from_parts` rejects a proof whose length is not the canonical size for the number
        // of actions, preventing a proof padded with arbitrary data (GHSA-2x4w-pxqw-58v9). Proof
        // size is enforced for every version except the historical pre-NU6.2 Orchard pool
        // ([`BundleVersion::orchard_insecure_v1`]); see the `bundle_version` chosen by the caller.
        orchard::Bundle::try_from_parts(
            actions,
            flags,
            value_balance,
            anchor,
            authorization,
            bundle_version,
        )
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Returns the [`BundleVersion`] in effect for the given Orchard-protocol value pool
/// under the given consensus branch, or `None` if the pool is not supported under that
/// branch (the Orchard pool prior to NU5; the Ironwood pool prior to NU6.3).
///
/// The protocol revision is determined by
/// [`BranchId::orchard_protocol_revision`]. The `BundleVersion` fixes a bundle's
/// flag-byte grammar, cross-address semantics, and circuit generation:
///   * Orchard pool, NU5 through NU6.1: historical insecure circuit, cross-address
///     enabled, proof size not enforced;
///   * Orchard pool, NU6.2: fixed circuit, cross-address enabled;
///   * Orchard pool, NU6.3 onward: post-NU6.3 circuit, cross-address disabled
///     (consensus-mandated);
///   * Ironwood pool, NU6.3 onward: post-NU6.3 circuit, cross-address enabled.
pub fn bundle_version_for_branch(
    consensus_branch_id: BranchId,
    pool: ValuePool,
) -> Option<BundleVersion> {
    let revision = consensus_branch_id.orchard_protocol_revision()?;
    match pool {
        ValuePool::Orchard => Some(match revision {
            OrchardProtocolRevision::InsecureV1 => BundleVersion::orchard_insecure_v1(),
            OrchardProtocolRevision::V2 => BundleVersion::orchard_v2(),
            OrchardProtocolRevision::V3 => BundleVersion::orchard_v3(),
        }),
        ValuePool::Ironwood => match revision {
            OrchardProtocolRevision::InsecureV1 | OrchardProtocolRevision::V2 => None,
            OrchardProtocolRevision::V3 => Some(BundleVersion::ironwood_v3()),
        },
    }
}

/// Reads an [`orchard::Bundle`] from a v5 transaction format.
///
/// The v5 Orchard wire serialization is identical in every epoch (flag bit 2 is
/// reserved), but the returned bundle's [`BundleVersion`] — which fixes its
/// cross-address semantics and circuit generation — follows the consensus epoch
/// identified by `consensus_branch_id` (see [`bundle_version_for_branch`]). A
/// non-empty Orchard bundle under a consensus branch that predates NU5 is
/// rejected as invalid data.
pub fn read_v5_bundle<R: Read>(
    reader: R,
    consensus_branch_id: BranchId,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    read_bundle(
        reader,
        bundle_version_for_branch(consensus_branch_id, ValuePool::Orchard),
    )
}

/// Rejects bundle versions that are not valid for the v6 transaction format, which has exactly
/// two Orchard-bundle slots: the Orchard slot ([`BundleVersion::orchard_v3`]) and the Ironwood
/// slot ([`BundleVersion::ironwood_v3`]). A pre-NU6.3 version would (de)serialize the flag byte
/// with the wrong cross-address (bit 2) semantics.
fn check_v6_bundle_version(bundle_version: BundleVersion) -> io::Result<()> {
    if bundle_version == BundleVersion::orchard_v3()
        || bundle_version == BundleVersion::ironwood_v3()
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "v6 Orchard bundles require orchard_v3 or ironwood_v3",
        ))
    }
}

/// Reads an [`orchard::Bundle`] from a v6 transaction format. `pool` selects the bundle
/// slot to read: the Orchard slot ([`ValuePool::Orchard`]) or the Ironwood slot
/// ([`ValuePool::Ironwood`], whose flag-byte encoding permits the cross-address bit,
/// unlike the Orchard v6 pool). The slot's [`BundleVersion`] is derived from
/// `consensus_branch_id` (see [`bundle_version_for_branch`]); a non-empty bundle in a
/// slot whose value pool is not supported under the transaction's consensus branch is
/// rejected as invalid data.
pub fn read_v6_bundle<R: Read>(
    reader: R,
    consensus_branch_id: BranchId,
    pool: ValuePool,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    read_bundle(reader, bundle_version_for_branch(consensus_branch_id, pool))
}

pub fn read_value_commitment<R: Read>(mut reader: R) -> io::Result<ValueCommitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let cv = ValueCommitment::from_bytes(&bytes);

    if cv.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas point for value commitment",
        ))
    } else {
        Ok(cv.unwrap())
    }
}

pub fn read_nullifier<R: Read>(mut reader: R) -> io::Result<Nullifier> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let nullifier_ctopt = Nullifier::from_bytes(&bytes);
    if nullifier_ctopt.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas point for nullifier",
        ))
    } else {
        Ok(nullifier_ctopt.unwrap())
    }
}

pub fn read_verification_key<R: Read>(mut reader: R) -> io::Result<VerificationKey<SpendAuth>> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    VerificationKey::try_from(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid verification key"))
}

pub fn read_cmx<R: Read>(mut reader: R) -> io::Result<ExtractedNoteCommitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let cmx = ExtractedNoteCommitment::from_bytes(&bytes);
    Option::from(cmx).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas base for field cmx",
        )
    })
}

pub fn read_note_ciphertext<R: Read>(mut reader: R) -> io::Result<TransmittedNoteCiphertext> {
    let mut tnc = TransmittedNoteCiphertext {
        epk_bytes: [0u8; 32],
        enc_ciphertext: [0u8; 580],
        out_ciphertext: [0u8; 80],
    };

    reader.read_exact(&mut tnc.epk_bytes)?;
    reader.read_exact(&mut tnc.enc_ciphertext)?;
    reader.read_exact(&mut tnc.out_ciphertext)?;

    Ok(tnc)
}

pub fn read_action_without_auth<R: Read>(mut reader: R) -> io::Result<Action<()>> {
    let cv_net = read_value_commitment(&mut reader)?;
    let nf_old = read_nullifier(&mut reader)?;
    let rk = read_verification_key(&mut reader)?;
    let cmx = read_cmx(&mut reader)?;
    let encrypted_note = read_note_ciphertext(&mut reader)?;

    Action::from_parts(nf_old, rk, cmx, encrypted_note, cv_net, ())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn read_flags<R: Read>(mut reader: R, bundle_version: BundleVersion) -> io::Result<Flags> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Flags::from_byte(byte[0], bundle_version)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid Orchard flags"))
}

pub fn read_anchor<R: Read>(mut reader: R) -> io::Result<Anchor> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(Anchor::from_bytes(bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid Orchard anchor"))
}

pub fn read_signature<R: Read, T: SigType>(mut reader: R) -> io::Result<Signature<T>> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(Signature::from(bytes))
}

fn write_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    mut writer: W,
) -> io::Result<()> {
    if let Some(bundle) = &bundle {
        Vector::write_nonempty(&mut writer, bundle.actions(), |w, a| {
            write_action_without_auth(w, a)
        })?;

        // The flag byte is encoded under the bundle's own `BundleVersion`, which is infallible:
        // a `Bundle` is only ever constructed with flags representable under its version.
        writer.write_all(&[bundle.flag_byte()])?;
        writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;
        writer.write_all(&bundle.anchor().to_bytes())?;
        Vector::write(
            &mut writer,
            bundle.authorization().proof().as_ref(),
            |w, b| w.write_all(&[*b]),
        )?;
        Array::write(
            &mut writer,
            bundle.actions().iter().map(|a| a.authorization()),
            |w, auth| w.write_all(&<[u8; 64]>::from(*auth)),
        )?;
        writer.write_all(&<[u8; 64]>::from(
            bundle.authorization().binding_signature(),
        ))?;
    } else {
        CompactSize::write(&mut writer, 0)?;
    }

    Ok(())
}

/// Writes an [`orchard::Bundle`] in the v5 transaction format.
///
/// The Orchard flag byte is encoded under the bundle's own [`BundleVersion`]; an Orchard bundle
/// never sets the cross-address bit, so its byte is always valid for the v5 format.
pub fn write_v5_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    writer: W,
) -> io::Result<()> {
    write_bundle(bundle, writer)
}

/// Writes an [`orchard::Bundle`] in the v6 transaction format. The bundle's own
/// [`BundleVersion`] selects the pool (and hence the flag-byte grammar): the Orchard slot uses
/// [`BundleVersion::orchard_v3`], the Ironwood slot [`BundleVersion::ironwood_v3`].
pub fn write_v6_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    writer: W,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        check_v6_bundle_version(bundle.bundle_version())?;
    }
    write_bundle(bundle, writer)
}

pub fn write_value_commitment<W: Write>(mut writer: W, cv: &ValueCommitment) -> io::Result<()> {
    writer.write_all(&cv.to_bytes())
}

pub fn write_nullifier<W: Write>(mut writer: W, nf: &Nullifier) -> io::Result<()> {
    writer.write_all(&nf.to_bytes())
}

pub fn write_verification_key<W: Write>(
    mut writer: W,
    rk: &redpallas::VerificationKey<SpendAuth>,
) -> io::Result<()> {
    writer.write_all(&<[u8; 32]>::from(rk))
}

pub fn write_cmx<W: Write>(mut writer: W, cmx: &ExtractedNoteCommitment) -> io::Result<()> {
    writer.write_all(&cmx.to_bytes())
}

pub fn write_note_ciphertext<W: Write>(
    mut writer: W,
    nc: &TransmittedNoteCiphertext,
) -> io::Result<()> {
    writer.write_all(&nc.epk_bytes)?;
    writer.write_all(&nc.enc_ciphertext)?;
    writer.write_all(&nc.out_ciphertext)
}

pub fn write_action_without_auth<W: Write>(
    mut writer: W,
    act: &Action<<Authorized as Authorization>::SpendAuth>,
) -> io::Result<()> {
    write_value_commitment(&mut writer, act.cv_net())?;
    write_nullifier(&mut writer, act.nullifier())?;
    write_verification_key(&mut writer, act.rk())?;
    write_cmx(&mut writer, act.cmx())?;
    write_note_ciphertext(&mut writer, act.encrypted_note())?;
    Ok(())
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use orchard::bundle::{
        Authorized, Bundle, BundleVersion, Flags,
        testing::{self as t_orch},
    };
    use zcash_protocol::value::{ZatBalance, testing::arb_zat_balance};

    use crate::transaction::TxVersion;

    prop_compose! {
        pub fn arb_bundle(n_actions: usize)(
            orchard_value_balance in arb_zat_balance(),
            bundle in t_orch::arb_bundle(n_actions)
        ) -> Bundle<Authorized, ZatBalance> {
            // overwrite the value balance, as we can't guarantee that the
            // value doesn't exceed the MAX_MONEY bounds.
            bundle.try_map_value_balance::<_, (), _>(|_| Ok(orchard_value_balance)).unwrap()
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<Bundle<Authorized, ZatBalance>>> {
        if v.has_orchard() {
            // The Orchard slot uses `orchard_v3()` in a v6 transaction (cross-address forbidden)
            // and `orchard_v2()` in a v5 transaction; the Ironwood slot is generated separately by
            // `arb_ironwood_bundle_for_version`.
            let bundle_version = orchard_bundle_version(v);
            (1usize..100)
                .prop_flat_map(move |n| {
                    prop::option::of(
                        arb_bundle(n).prop_map(move |b| rebuild_with_version(b, bundle_version)),
                    )
                })
                .boxed()
        } else {
            Just(None).boxed()
        }
    }

    /// Generates Ironwood bundles for the v6 transaction format. Unlike the Orchard v6 pool, the
    /// Ironwood pool ([`BundleVersion::ironwood_v3`]) permits cross-address transfers, so this
    /// exercises the Ironwood serialization path the Orchard generator cannot.
    pub fn arb_ironwood_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<Bundle<Authorized, ZatBalance>>> {
        if v.has_ironwood() {
            (1usize..100)
                .prop_flat_map(|n| {
                    prop::option::of(
                        arb_bundle(n)
                            .prop_map(|b| rebuild_with_version(b, BundleVersion::ironwood_v3())),
                    )
                })
                .boxed()
        } else {
            Just(None).boxed()
        }
    }

    /// The Orchard-slot [`BundleVersion`] for a transaction version: `orchard_v3()` in v6 (where
    /// the Orchard pool forbids cross-address transfers), `orchard_v2()` otherwise.
    fn orchard_bundle_version(v: TxVersion) -> BundleVersion {
        if matches!(v, TxVersion::V6) {
            return BundleVersion::orchard_v3();
        }
        let _ = v;
        BundleVersion::orchard_v2()
    }

    /// Rebuilds an arbitrary bundle under `bundle_version`, choosing a cross-address flag value
    /// that the version can represent while preserving the generated spend/output flags.
    ///
    /// Cross-address is only encodable in bit 2 for the Ironwood pool, so bit 2 is set there (to
    /// exercise that serialization path) and left clear otherwise: pre-NU6.3 Orchard has
    /// cross-address implicitly enabled, and post-NU6.3 Orchard forbids it.
    pub(crate) fn rebuild_with_version(
        bundle: Bundle<Authorized, ZatBalance>,
        bundle_version: BundleVersion,
    ) -> Bundle<Authorized, ZatBalance> {
        let mut byte = u8::from(bundle.flags().spends_enabled())
            | (u8::from(bundle.flags().outputs_enabled()) << 1);
        if bundle_version == BundleVersion::ironwood_v3() {
            byte |= 0b100;
        }
        let flags = Flags::from_byte(byte, bundle_version)
            .expect("constructed flag byte is representable under the target version");
        ::orchard::Bundle::try_from_parts(
            bundle.actions().clone(),
            flags,
            *bundle.value_balance(),
            *bundle.anchor(),
            bundle.authorization().clone(),
            bundle_version,
        )
        .expect("flags are representable under the target version")
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use orchard::{bundle::testing::arb_action, note::NoteVersion, value::NoteValue};
    use proptest::prelude::*;

    use super::{
        ACTION_SIZE, PALLAS_ENCODING_SIZE, io, write_action_without_auth, write_cmx,
        write_note_ciphertext, write_nullifier, write_value_commitment, write_verification_key,
    };

    // Returns the number of bytes `write` emits.
    fn encoded_len(write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> usize {
        let mut buf = Vec::new();
        write(&mut buf).expect("writing to a Vec cannot fail");
        buf.len()
    }

    proptest! {
        /// `ACTION_SIZE` is what callers divide a size budget by to bound an action count, and so
        /// feeds fee estimation: it must equal what the encoder actually writes, not merely what
        /// the constant's own arithmetic says. Measure a real action rather than restating the
        /// composition, so that a change to any encoding it is built from fails here.
        #[test]
        fn action_size_matches_the_encoding(
            action in arb_action(
                NoteVersion::V2,
                NoteValue::from_raw(1),
                NoteValue::from_raw(1),
            ),
        ) {
            prop_assert_eq!(
                encoded_len(|w| write_action_without_auth(w, &action)),
                ACTION_SIZE
            );

            // Every Pallas encoding in an action is the same width, which is what lets
            // `ACTION_SIZE` count them rather than name each one's size separately.
            for encoded in [
                encoded_len(|w| write_value_commitment(w, action.cv_net())),
                encoded_len(|w| write_nullifier(w, action.nullifier())),
                encoded_len(|w| write_verification_key(w, action.rk())),
                encoded_len(|w| write_cmx(w, action.cmx())),
            ] {
                prop_assert_eq!(encoded, PALLAS_ENCODING_SIZE);
            }

            // The remainder is the note ciphertext: the ephemeral key (a fifth Pallas encoding)
            // followed by the two ciphertexts.
            prop_assert_eq!(
                encoded_len(|w| write_note_ciphertext(w, action.encrypted_note())),
                ACTION_SIZE - 4 * PALLAS_ENCODING_SIZE
            );
        }
    }
}
