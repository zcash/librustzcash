/// Functions for parsing & serialization of Orchard transaction components.
use std::convert::TryFrom;
use std::io::{self, Read, Write};

use orchard::{
    bundle::{Action, Authorization, Authorized, Flags},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    primitives::redpallas::{self, SigType, Signature, SpendAuth, VerificationKey},
    value::ValueCommitment,
    Anchor,
};

pub const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;
pub const FLAG_OUTPUTS_ENABLED: u8 = 0b0000_0010;
pub const FLAGS_EXPECTED_UNSET: u8 = !(FLAG_SPENDS_ENABLED | FLAG_OUTPUTS_ENABLED);

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
    if byte[0] & FLAGS_EXPECTED_UNSET == 0 {
        Ok(Flags::from_parts(
            byte[0] & FLAG_SPENDS_ENABLED != 0,
            byte[0] & FLAG_OUTPUTS_ENABLED != 0,
        ))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unexpected bits set in Orchard flags value.",
        ))
    }
}

pub fn read_anchor<R: Read>(mut reader: R) -> io::Result<Anchor> {
    let mut anchor = Anchor([0u8; 32]);
    reader.read_exact(&mut anchor.0)?;
    Ok(anchor)
}

pub fn read_signature<R: Read, T: SigType>(mut reader: R) -> io::Result<Signature<T>> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(Signature::from(bytes))
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
    write_value_commitment(&mut writer, &act.cv_net())?;
    write_nullifier(&mut writer, &act.nullifier())?;
    write_verification_key(&mut writer, &act.rk())?;
    write_cmx(&mut writer, &act.cmx())?;
    write_note_ciphertext(&mut writer, &act.encrypted_note())?;
    Ok(())
}

pub fn write_flags<W: Write>(mut writer: W, flags: &Flags) -> io::Result<()> {
    let mut byte = 0u8;
    if flags.spends_enabled() {
        byte |= FLAG_SPENDS_ENABLED;
    }
    if flags.outputs_enabled() {
        byte |= FLAG_OUTPUTS_ENABLED;
    }
    writer.write_all(&[byte])
}

pub fn write_anchor<W: Write>(mut writer: W, anchor: &Anchor) -> io::Result<()> {
    writer.write_all(&anchor.0)
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use orchard::bundle::{
        testing::{self as t_orch},
        Authorized, Bundle,
    };

    use crate::transaction::{
        components::amount::{testing::arb_amount, Amount},
        TxVersion,
    };

    prop_compose! {
        pub fn arb_bundle()(
            orchard_value_balance in arb_amount(),
            bundle in t_orch::arb_bundle()
        ) -> Bundle<Authorized, Amount> {
            // overwrite the value balance, as we can't guarantee that the
            // value doesn't exceed the MAX_MONEY bounds.
            bundle.try_map_value_balance::<_, (), _>(|_| Ok(orchard_value_balance)).unwrap()
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<Bundle<Authorized, Amount>>> {
        if v.has_orchard() {
            Strategy::boxed(prop::option::of(arb_bundle()))
        } else {
            Strategy::boxed(Just(None))
        }
    }
}
