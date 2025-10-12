//! Functions for parsing & serialization of Orchard transaction components.
use crate::encoding::ReadBytesExt;

#[cfg(zcash_unstable = "nu7")]
use {
    crate::encoding::WriteBytesExt,
    crate::sighash_versioning::{to_orchard_version, ORCHARD_SIGHASH_VERSION_TO_INFO_BYTES},
    crate::transaction::components::issuance::read_asset,
    orchard::{note::AssetBase, orchard_flavor::OrchardZSA, value::NoteValue},
};

use crate::transaction::{OrchardBundle, Transaction};
use alloc::vec::Vec;
use core::convert::TryFrom;
use core2::io::{self, Read, Write};
use nonempty::NonEmpty;
use orchard::{
    bundle::{Authorization, Authorized, Flags},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    orchard_flavor::OrchardVanilla,
    orchard_sighash_versioning::{OrchardSighashVersion, OrchardVersionedSig},
    primitives::redpallas::{self, SigType, Signature, SpendAuth, VerificationKey},
    primitives::OrchardPrimitives,
    value::ValueCommitment,
    Action, Anchor, Bundle,
};
use zcash_encoding::{Array, CompactSize, Vector};
use zcash_note_encryption::note_bytes::NoteBytes;

use zcash_protocol::value::ZatBalance;

pub const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;
pub const FLAG_OUTPUTS_ENABLED: u8 = 0b0000_0010;
pub const FLAGS_EXPECTED_UNSET: u8 = !(FLAG_SPENDS_ENABLED | FLAG_OUTPUTS_ENABLED);

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

/// Reads an [`orchard::Bundle`] from a v5 transaction format.
pub fn read_v5_bundle<R: Read>(
    mut reader: R,
) -> io::Result<Option<Bundle<Authorized, ZatBalance, OrchardVanilla>>> {
    #[allow(clippy::redundant_closure)]
    let actions_without_auth = Vector::read(&mut reader, |r| read_action_without_auth(r))?;
    if actions_without_auth.is_empty() {
        Ok(None)
    } else {
        let flags = read_flags(&mut reader)?;
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

        let authorization =
            Authorized::from_parts(orchard::Proof::new(proof_bytes), binding_signature);

        Ok(Some(orchard::Bundle::from_parts(
            actions,
            flags,
            value_balance,
            vec![],
            anchor,
            authorization,
        )))
    }
}

/// Reads an [`orchard::Bundle`] from a v6 transaction format.
#[cfg(zcash_unstable = "nu7")]
pub fn read_v6_bundle<R: Read>(
    mut reader: R,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance, OrchardZSA>>> {
    let num_action_groups: u32 = CompactSize::read_t::<_, u32>(&mut reader)?;
    if num_action_groups == 0 {
        return Ok(None);
    } else if num_action_groups != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "A V6 transaction must contain exactly one action group",
        ));
    }

    let actions_without_auth = Vector::read(&mut reader, |r| read_action_without_auth(r))?;
    if actions_without_auth.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "An action group must contain at least one action",
        ));
    }
    let flags = read_flags(&mut reader)?;
    let anchor = read_anchor(&mut reader)?;
    let timelimit = reader.read_u32_le()?;
    if timelimit != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Timelimit field must be set to zero",
        ));
    }
    let burn = read_burn(&mut reader)?;
    let proof_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    let actions = NonEmpty::from_vec(
        actions_without_auth
            .into_iter()
            .map(|act| {
                act.try_map(|_| read_versioned_signature::<_, redpallas::SpendAuth>(&mut reader))
            })
            .collect::<Result<Vec<_>, _>>()?,
    )
    .ok_or(io::Error::new(
        io::ErrorKind::InvalidInput,
        "The action group must contain at least one action.",
    ))?;

    let value_balance = Transaction::read_amount(&mut reader)?;

    let binding_signature = read_versioned_signature::<_, redpallas::Binding>(&mut reader)?;

    let authorization = Authorized::from_parts(orchard::Proof::new(proof_bytes), binding_signature);

    Ok(Some(orchard::Bundle::from_parts(
        actions,
        flags,
        value_balance,
        burn,
        anchor,
        authorization,
    )))
}

/// Reads burn for OrchardZSA
#[cfg(zcash_unstable = "nu7")]
pub fn read_burn<R: Read>(mut reader: &mut R) -> io::Result<Vec<(AssetBase, NoteValue)>> {
    Vector::read(&mut reader, read_burn_item)
}

#[cfg(zcash_unstable = "nu7")]
fn read_burn_item<R: Read>(reader: &mut R) -> io::Result<(AssetBase, NoteValue)> {
    Ok((read_asset(reader)?, read_note_value(reader)?))
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

pub fn read_note_ciphertext<R: Read, P: OrchardPrimitives>(
    mut reader: R,
) -> io::Result<TransmittedNoteCiphertext<P>> {
    let mut epk = [0; 32];
    let mut enc = vec![0u8; P::ENC_CIPHERTEXT_SIZE];
    let mut out = [0; 80];

    reader.read_exact(&mut epk)?;
    reader.read_exact(&mut enc)?;
    reader.read_exact(&mut out)?;

    Ok(TransmittedNoteCiphertext::<P> {
        epk_bytes: epk,
        enc_ciphertext: <P>::NoteCiphertextBytes::from_slice(&enc).unwrap(),
        out_ciphertext: out,
    })
}

pub fn read_action_without_auth<R: Read, P: OrchardPrimitives>(
    mut reader: R,
) -> io::Result<Action<(), P>> {
    let cv_net = read_value_commitment(&mut reader)?;
    let nf_old = read_nullifier(&mut reader)?;
    let rk = read_verification_key(&mut reader)?;
    let cmx = read_cmx(&mut reader)?;
    let encrypted_note = read_note_ciphertext(&mut reader)?;

    Ok(Action::from_parts(
        nf_old,
        rk,
        cmx,
        encrypted_note,
        cv_net,
        (),
    ))
}

pub fn read_flags<R: Read>(mut reader: R) -> io::Result<Flags> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Flags::from_byte(byte[0])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid Orchard flags"))
}

pub fn read_anchor<R: Read>(mut reader: R) -> io::Result<Anchor> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(Anchor::from_bytes(bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid Orchard anchor"))
}

pub fn read_signature<R: Read, T: SigType>(mut reader: R) -> io::Result<OrchardVersionedSig<T>> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(OrchardVersionedSig::new(
        OrchardSighashVersion::NoVersion,
        Signature::from(bytes),
    ))
}

#[cfg(zcash_unstable = "nu7")]
pub fn read_versioned_signature<R: Read, T: SigType>(
    mut reader: R,
) -> io::Result<OrchardVersionedSig<T>> {
    let sighash_info_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    let sighash_version = to_orchard_version(sighash_info_bytes).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "Unknown Orchard sighash info")
    })?;

    let mut signature_bytes = [0u8; 64];
    reader.read_exact(&mut signature_bytes)?;
    Ok(OrchardVersionedSig::new(
        sighash_version,
        Signature::from(signature_bytes),
    ))
}

#[cfg(zcash_unstable = "nu7")]
pub fn write_versioned_signature<W: Write, T: SigType>(
    mut writer: W,
    versioned_sig: &OrchardVersionedSig<T>,
) -> io::Result<()> {
    let sighash_info_bytes = ORCHARD_SIGHASH_VERSION_TO_INFO_BYTES
        .get(versioned_sig.version())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unknown Orchard sighash version",
            )
        })?;
    Vector::write(&mut writer, sighash_info_bytes, |w, b| w.write_u8(*b))?;
    writer.write_all(&<[u8; 64]>::from(versioned_sig.sig()))
}

/// Writes an [`orchard::Bundle`] in the v5 transaction format.
pub fn write_v5_bundle<W: Write>(
    bundle: Option<&OrchardBundle<Authorized>>,
    mut writer: W,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        let bundle = bundle.as_vanilla_bundle();
        Vector::write_nonempty(&mut writer, bundle.actions(), |w, a| {
            write_action_without_auth(w, a)
        })?;

        writer.write_all(&[bundle.flags().to_byte()])?;
        writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;
        writer.write_all(&bundle.anchor().to_bytes())?;
        Vector::write(
            &mut writer,
            bundle.authorization().proof().as_ref(),
            |w, b| w.write_all(&[*b]),
        )?;
        Array::write(
            &mut writer,
            bundle.actions().iter().map(|a| a.authorization().sig()),
            |w, auth| w.write_all(&<[u8; 64]>::from(*auth)),
        )?;
        writer.write_all(&<[u8; 64]>::from(
            bundle.authorization().binding_signature().sig(),
        ))?;
    } else {
        CompactSize::write(&mut writer, 0)?;
    }

    Ok(())
}

#[cfg(zcash_unstable = "nu7")]
fn read_note_value<R: Read>(mut reader: R) -> io::Result<NoteValue> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(NoteValue::from_bytes(bytes))
}

/// Writes burn for OrchardZSA
#[cfg(zcash_unstable = "nu7")]
pub fn write_burn<W: Write>(writer: &mut W, burn: &[(AssetBase, NoteValue)]) -> io::Result<()> {
    Vector::write(writer, burn, |w, (asset, amount)| {
        w.write_all(&asset.to_bytes())?;
        w.write_all(&amount.to_bytes())?;
        Ok(())
    })?;
    Ok(())
}

/// Writes an [`orchard::Bundle`] in the appropriate transaction format.
#[cfg(zcash_unstable = "nu7")]
pub fn write_v6_bundle<W: Write>(
    mut writer: W,
    bundle: Option<&OrchardBundle<Authorized>>,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        let bundle = bundle.as_zsa_bundle();
        // Exactly one action group for NU7
        CompactSize::write(&mut writer, 1)?;

        Vector::write_nonempty(&mut writer, bundle.actions(), |w, a| {
            write_action_without_auth(w, a)
        })?;

        writer.write_all(&[bundle.flags().to_byte()])?;
        writer.write_all(&bundle.anchor().to_bytes())?;

        // Timelimit must be zero for NU7
        writer.write_u32_le(0)?;

        write_burn(&mut writer, bundle.burn())?;

        Vector::write(
            &mut writer,
            bundle.authorization().proof().as_ref(),
            |w, b| w.write_u8(*b),
        )?;

        Array::write(
            &mut writer,
            bundle.actions().iter().map(|a| a.authorization()),
            |w, auth| write_versioned_signature(w, auth),
        )?;

        writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;

        write_versioned_signature(&mut writer, bundle.authorization().binding_signature())?;
    } else {
        CompactSize::write(&mut writer, 0)?;
    }

    Ok(())
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

pub fn write_note_ciphertext<W: Write, P: OrchardPrimitives>(
    mut writer: W,
    nc: &TransmittedNoteCiphertext<P>,
) -> io::Result<()> {
    writer.write_all(&nc.epk_bytes)?;
    writer.write_all(nc.enc_ciphertext.as_ref())?;
    writer.write_all(&nc.out_ciphertext)
}

pub fn write_action_without_auth<W: Write, P: OrchardPrimitives>(
    mut writer: W,
    act: &Action<<Authorized as Authorization>::SpendAuth, P>,
) -> io::Result<()> {
    write_value_commitment(&mut writer, act.cv_net())?;
    write_nullifier(&mut writer, act.nullifier())?;
    write_verification_key(&mut writer, act.rk())?;
    write_cmx(&mut writer, act.cmx())?;
    write_note_ciphertext(&mut writer, act.encrypted_note())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(zcash_unstable = "nu7")]
    use {
        super::{read_versioned_signature, write_versioned_signature},
        alloc::vec::Vec,
        orchard::orchard_sighash_versioning::{OrchardSighashVersion, OrchardVersionedSig},
        orchard::primitives::redpallas,
        rand::rngs::OsRng,
        rand::RngCore,
        std::io::Cursor,
    };

    #[cfg(zcash_unstable = "nu7")]
    #[test]
    fn write_read_versioned_signature_roundtrip() {
        let mut sig_bytes = [0u8; 64];
        OsRng.fill_bytes(&mut sig_bytes);
        let sig = redpallas::Signature::<redpallas::SpendAuth>::from(sig_bytes);
        let versioned_sig = OrchardVersionedSig::new(OrchardSighashVersion::V0, sig);

        // Write the versioned signature to a buffer
        let mut buf = Vec::new();
        write_versioned_signature(&mut buf, &versioned_sig).unwrap();

        // Read the versioned signature back from the buffer
        let mut reader = Cursor::new(buf);
        let read_versioned_sig =
            read_versioned_signature::<_, redpallas::SpendAuth>(&mut reader).unwrap();

        assert_eq!(versioned_sig, read_versioned_sig);
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use crate::transaction::{OrchardBundle, TxVersion};
    use orchard::bundle::{testing as t_orch, Authorized};
    use zcash_protocol::value::testing::arb_zat_balance;

    #[cfg(zcash_unstable = "nu7")]
    use orchard::orchard_flavor::OrchardZSA;

    prop_compose! {
        pub fn arb_bundle(n_actions: usize)(
            orchard_value_balance in arb_zat_balance(),
            bundle in t_orch::BundleArb::arb_bundle(n_actions)
        ) -> OrchardBundle<Authorized> {
            // overwrite the value balance, as we can't guarantee that the
            // value doesn't exceed the MAX_MONEY bounds.
            OrchardBundle::OrchardVanilla(bundle.try_map_value_balance::<_, (), _>(|_| Ok(orchard_value_balance)).unwrap())
        }
    }

    #[cfg(zcash_unstable = "nu7")]
    prop_compose! {
        pub fn arb_zsa_bundle(n_actions: usize)(
            orchard_value_balance in arb_zat_balance(),
            bundle in t_orch::BundleArb::<OrchardZSA>::arb_bundle(n_actions)
        ) -> OrchardBundle<Authorized> {
            // overwrite the value balance, as we can't guarantee that the
            // value doesn't exceed the MAX_MONEY bounds.
            OrchardBundle::OrchardZSA(bundle.try_map_value_balance::<_, (), _>(|_| Ok(orchard_value_balance)).unwrap())
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<OrchardBundle<Authorized>>> {
        #[cfg(zcash_unstable = "nu7")]
        if v.has_orchard_zsa() {
            return Strategy::boxed(
                (1usize..100).prop_flat_map(|n| prop::option::of(arb_zsa_bundle(n))),
            );
        }

        if v.has_orchard() {
            Strategy::boxed((1usize..100).prop_flat_map(|n| prop::option::of(arb_bundle(n))))
        } else {
            Strategy::boxed(Just(None))
        }
    }
}
