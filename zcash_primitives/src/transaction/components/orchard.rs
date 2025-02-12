/// Functions for parsing & serialization of Orchard transaction components.
use std::convert::TryFrom;
use std::io::{self, Read, Write};

use super::Amount;
#[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
use crate::transaction::components::issuance::read_asset;
use crate::transaction::{OrchardBundle, Transaction};
use byteorder::ReadBytesExt;
use nonempty::NonEmpty;
use orchard::{
    bundle::{Authorization, Authorized, Flags},
    domain::OrchardDomainCommon,
    note::{AssetBase, ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    orchard_flavor::{OrchardVanilla, OrchardZSA},
    primitives::redpallas::{self, SigType, Signature, SpendAuth, VerificationKey},
    value::{NoteValue, ValueCommitment},
    Action, Anchor, Bundle,
};
use zcash_encoding::{Array, CompactSize, Vector};
use zcash_note_encryption::note_bytes::NoteBytes;

use zcash_protocol::value::ZatBalance;
#[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
use {byteorder::LittleEndian, byteorder::WriteBytesExt};

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
pub fn read_orchard_bundle<R: Read>(
    mut reader: R,
) -> io::Result<Option<orchard::Bundle<Authorized, Amount, OrchardVanilla>>> {
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
#[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
pub fn read_orchard_zsa_bundle<R: Read>(
    mut reader: R,
) -> io::Result<Option<orchard::Bundle<Authorized, Amount, OrchardZSA>>> {
    // Read a number of action group
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
    let proof_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    let timelimit = reader.read_u32::<LittleEndian>()?;
    if timelimit != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Timelimit field must be set to zero".to_owned(),
        ));
    }
    let actions = NonEmpty::from_vec(
        actions_without_auth
            .into_iter()
            .map(|act| act.try_map(|_| read_signature::<_, redpallas::SpendAuth>(&mut reader)))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .expect("A nonzero number of actions was read from the transaction data.");

    let value_balance = Transaction::read_amount(&mut reader)?;

    let burn = Vector::read(&mut reader, |r| read_burn(r))?;

    let binding_signature = read_signature::<_, redpallas::Binding>(&mut reader)?;

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

#[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
fn read_burn<R: Read>(reader: &mut R) -> io::Result<(AssetBase, NoteValue)> {
    Ok((read_asset(reader)?, read_note_value(reader)?))
}

pub fn read_value_commitment<R: Read>(mut reader: R) -> io::Result<ValueCommitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let cv = ValueCommitment::from_bytes(&bytes);

    if cv.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas point for value commitment".to_owned(),
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
            "invalid Pallas point for nullifier".to_owned(),
        ))
    } else {
        Ok(nullifier_ctopt.unwrap())
    }
}

pub fn read_verification_key<R: Read>(mut reader: R) -> io::Result<VerificationKey<SpendAuth>> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    VerificationKey::try_from(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid verification key".to_owned(),
        )
    })
}

pub fn read_cmx<R: Read>(mut reader: R) -> io::Result<ExtractedNoteCommitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let cmx = ExtractedNoteCommitment::from_bytes(&bytes);
    Option::from(cmx).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas base for field cmx".to_owned(),
        )
    })
}

pub fn read_note_ciphertext<R: Read, D: OrchardDomainCommon>(
    mut reader: R,
) -> io::Result<TransmittedNoteCiphertext<D>> {
    let mut epk = [0; 32];
    let mut enc = vec![0u8; D::ENC_CIPHERTEXT_SIZE];
    let mut out = [0; 80];

    reader.read_exact(&mut epk)?;
    reader.read_exact(&mut enc)?;
    reader.read_exact(&mut out)?;

    Ok(TransmittedNoteCiphertext::<D> {
        epk_bytes: epk,
        enc_ciphertext: <D>::NoteCiphertextBytes::from_slice(&enc).unwrap(),
        out_ciphertext: out,
    })
}

pub fn read_action_without_auth<R: Read, D: OrchardDomainCommon>(
    mut reader: R,
) -> io::Result<Action<(), D>> {
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
    Flags::from_byte(byte[0]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Orchard flags".to_owned(),
        )
    })
}

pub fn read_anchor<R: Read>(mut reader: R) -> io::Result<Anchor> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(Anchor::from_bytes(bytes)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Orchard anchor".to_owned(),
        )
    })
}

pub fn read_signature<R: Read, T: SigType>(mut reader: R) -> io::Result<Signature<T>> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(Signature::from(bytes))
}

#[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
fn read_note_value<R: Read>(mut reader: R) -> io::Result<NoteValue> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(NoteValue::from_bytes(bytes))
}

pub trait WriteBurn<W: Write> {
    fn write_burn(writer: &mut W, burn: &[(AssetBase, NoteValue)]) -> io::Result<()>;
}

// Write burn for OrchardZSA
impl<W: Write> WriteBurn<W> for OrchardZSA {
    fn write_burn(writer: &mut W, burn: &[(AssetBase, NoteValue)]) -> io::Result<()> {
        Vector::write(writer, burn, |w, (asset, amount)| {
            w.write_all(&asset.to_bytes())?;
            w.write_all(&amount.to_bytes())?;
            Ok(())
        })?;
        Ok(())
    }
}

/// Writes an [`orchard::Bundle`] in the appropriate transaction format.
pub fn write_orchard_bundle<W: Write>(
    mut writer: W,
    bundle: Option<&OrchardBundle<Authorized>>,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        match bundle {
            OrchardBundle::OrchardVanilla(b) => write_v5_bundle(b, writer)?,
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            OrchardBundle::OrchardZSA(b) => write_orchard_zsa_bundle(writer, b)?,
        }
    } else {
        CompactSize::write(&mut writer, 0)?;
    }

    Ok(())
}

/// Writes an [`orchard::Bundle`] in the v5 transaction format.
pub fn write_v5_bundle<W: Write>(
    bundle: &Bundle<Authorized, ZatBalance, OrchardVanilla>,
    mut writer: W,
) -> io::Result<()> {
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
        bundle.actions().iter().map(|a| a.authorization()),
        |w, auth| w.write_all(&<[u8; 64]>::from(*auth)),
    )?;
    writer.write_all(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ))?;

    Ok(())
}

/// Writes an [`orchard::Bundle`] in the appropriate transaction format.
#[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
pub fn write_orchard_zsa_bundle<W: Write>(
    mut writer: W,
    bundle: &orchard::Bundle<Authorized, Amount, OrchardZSA>,
) -> io::Result<()> {
    // Exactly one action group for NU7
    CompactSize::write(&mut writer, 1)?;

    Vector::write_nonempty(&mut writer, bundle.actions(), |w, a| {
        write_action_without_auth(w, a)
    })?;

    writer.write_all(&[bundle.flags().to_byte()])?;
    writer.write_all(&bundle.anchor().to_bytes())?;
    Vector::write(
        &mut writer,
        bundle.authorization().proof().as_ref(),
        |w, b| w.write_u8(*b),
    )?;

    // Timelimit must be zero for NU7
    writer.write_u32::<LittleEndian>(0)?;

    Array::write(
        &mut writer,
        bundle.actions().iter().map(|a| a.authorization()),
        |w, auth| w.write_all(&<[u8; 64]>::from(*auth)),
    )?;

    writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;

    OrchardZSA::write_burn(&mut writer, bundle.burn())?;

    writer.write_all(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ))?;

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

pub fn write_note_ciphertext<W: Write, D: OrchardDomainCommon>(
    mut writer: W,
    nc: &TransmittedNoteCiphertext<D>,
) -> io::Result<()> {
    writer.write_all(&nc.epk_bytes)?;
    writer.write_all(nc.enc_ciphertext.as_ref())?;
    writer.write_all(&nc.out_ciphertext)
}

pub fn write_action_without_auth<W: Write, D: OrchardDomainCommon>(
    mut writer: W,
    act: &Action<<Authorized as Authorization>::SpendAuth, D>,
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

    use crate::transaction::components::amount::testing::arb_amount;
    use crate::transaction::{OrchardBundle, TxVersion};
    use orchard::bundle::{
        testing::{self as t_orch},
        Authorized,
    };
    use orchard::orchard_flavor::OrchardZSA;

    prop_compose! {
        pub fn arb_bundle(n_actions: usize)(
            orchard_value_balance in arb_amount(),
            bundle in t_orch::BundleArb::arb_bundle(n_actions)
        ) -> OrchardBundle<Authorized> {
            // overwrite the value balance, as we can't guarantee that the
            // value doesn't exceed the MAX_MONEY bounds.
            OrchardBundle::OrchardVanilla(bundle.try_map_value_balance::<_, (), _>(|_| Ok(orchard_value_balance)).unwrap())
        }
    }

    prop_compose! {
        #[allow(unreachable_code)]
        pub fn arb_zsa_bundle(n_actions: usize)(
            _orchard_value_balance in arb_amount(),
            _bundle in t_orch::BundleArb::<OrchardZSA>::arb_bundle(n_actions)
        ) -> OrchardBundle<Authorized> {
            // overwrite the value balance, as we can't guarantee that the
            // value doesn't exceed the MAX_MONEY bounds.
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            return OrchardBundle::OrchardZSA(_bundle.try_map_value_balance::<_, (), _>(|_| Ok(_orchard_value_balance)).unwrap());
            panic!("ZSA is not supported in this version");
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<OrchardBundle<Authorized>>> {
        if v.has_orchard_zsa() {
            Strategy::boxed((1usize..100).prop_flat_map(|n| prop::option::of(arb_zsa_bundle(n))))
        } else if v.has_orchard() {
            Strategy::boxed((1usize..100).prop_flat_map(|n| prop::option::of(arb_bundle(n))))
        } else {
            Strategy::boxed(Just(None))
        }
    }
}
