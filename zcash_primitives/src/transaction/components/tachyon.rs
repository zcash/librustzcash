//! Functions for parsing & serialization of Tachyon transaction components.

use core2::io::{self, Read, Write};

use pasta_curves::{EpAffine, Fp};

use ff::PrimeField;
use group::GroupEncoding;

use zcash_encoding::Vector;

use crate::encoding::{ReadBytesExt, WriteBytesExt};

use zcash_tachyon::{
    Action, Anchor, Bundle, Proof, Stamp, Tachygram, action, bundle,
    keys::public::ActionVerificationKey, value,
};

/// Reads a tachyon bundle from v6 transaction format.
pub fn read_v6_bundle<R: Read>(mut reader: R) -> io::Result<Option<Bundle<Option<Stamp>>>> {
    let flag = reader.read_u8()?;
    match flag {
        0 => Ok(None),
        1 => {
            // Read actions
            let actions = Vector::read(&mut reader, |r| read_action(r))?;

            // Read value_balance (i64 LE)
            let value_balance = reader.read_i64_le()?;

            // Read binding signature (64 bytes)
            let binding_sig = read_bundle_signature(&mut reader)?;

            // Read stamp (Option<Stamp>)
            let stamp = read_option_stamp(&mut reader)?;

            Ok(Some(Bundle {
                actions,
                value_balance,
                binding_sig,
                stamp,
            }))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tachyon bundle presence flag: expected 0 or 1",
        )),
    }
}

/// Writes a tachyon bundle in v6 transaction format.
pub fn write_v6_bundle<W: Write>(
    bundle: Option<&Bundle<Option<Stamp>>>,
    mut writer: W,
) -> io::Result<()> {
    match bundle {
        None => {
            writer.write_u8(0)?;
        }
        Some(bundle) => {
            writer.write_u8(1)?;

            // Write actions
            Vector::write(&mut writer, &bundle.actions, |w, a| write_action(w, a))?;

            // Write value_balance (i64 LE)
            writer.write_i64_le(bundle.value_balance)?;

            // Write binding signature (64 bytes)
            write_bundle_signature(&mut writer, &bundle.binding_sig)?;

            // Write stamp (Option<Stamp>)
            write_option_stamp(&mut writer, &bundle.stamp)?;
        }
    }
    Ok(())
}

fn read_action<R: Read>(mut reader: R) -> io::Result<Action> {
    // cv: value commitment (32 bytes, EpAffine)
    let cv = read_value_commitment(&mut reader)?;

    // rk: action verification key (32 bytes)
    let rk = read_action_verification_key(&mut reader)?;

    // sig: spend auth signature (64 bytes)
    let sig = read_action_signature(&mut reader)?;

    Ok(Action { cv, rk, sig })
}

fn write_action<W: Write>(mut writer: W, action: &Action) -> io::Result<()> {
    write_value_commitment(&mut writer, &action.cv)?;
    write_action_verification_key(&mut writer, &action.rk)?;
    write_action_signature(&mut writer, &action.sig)?;
    Ok(())
}

fn read_value_commitment<R: Read>(mut reader: R) -> io::Result<value::Commitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let point = EpAffine::from_bytes(&bytes);
    if point.is_some().into() {
        Ok(point.unwrap().into())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas point for tachyon value commitment",
        ))
    }
}

fn write_value_commitment<W: Write>(mut writer: W, cv: &value::Commitment) -> io::Result<()> {
    let point: EpAffine = (*cv).into();
    writer.write_all(&point.to_bytes())
}

fn read_action_verification_key<R: Read>(mut reader: R) -> io::Result<ActionVerificationKey> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    ActionVerificationKey::try_from(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid tachyon verification key",
        )
    })
}

fn write_action_verification_key<W: Write>(
    mut writer: W,
    rk: &ActionVerificationKey,
) -> io::Result<()> {
    writer.write_all(&<[u8; 32]>::from(*rk))
}

fn read_action_signature<R: Read>(mut reader: R) -> io::Result<action::Signature> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(action::Signature::from(bytes))
}

fn write_action_signature<W: Write>(mut writer: W, sig: &action::Signature) -> io::Result<()> {
    writer.write_all(&<[u8; 64]>::from(*sig))
}

fn read_bundle_signature<R: Read>(mut reader: R) -> io::Result<bundle::Signature> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(bundle::Signature::from(bytes))
}

fn write_bundle_signature<W: Write>(mut writer: W, sig: &bundle::Signature) -> io::Result<()> {
    writer.write_all(&<[u8; 64]>::from(*sig))
}

fn read_fp<R: Read>(mut reader: R) -> io::Result<Fp> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let fp = Fp::from_repr(bytes);
    if fp.is_some().into() {
        Ok(fp.unwrap())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid field element",
        ))
    }
}

fn read_tachygram<R: Read>(reader: R) -> io::Result<Tachygram> {
    read_fp(reader).map(Tachygram::from)
}

fn write_tachygram<W: Write>(mut writer: W, tachygram: &Tachygram) -> io::Result<()> {
    let fp: Fp = (*tachygram).into();
    writer.write_all(&fp.to_repr())
}

fn read_anchor<R: Read>(reader: R) -> io::Result<Anchor> {
    read_fp(reader).map(Anchor::from)
}

fn write_anchor<W: Write>(mut writer: W, anchor: &Anchor) -> io::Result<()> {
    let fp: Fp = (*anchor).into();
    writer.write_all(&fp.to_repr())
}

/// Serialized size of a Tachyon proof in bytes.
/// Matches `mock_ragu::proof::PROOF_SIZE_COMPRESSED`.
const TACHYON_PROOF_SIZE: usize = 23_000;

fn read_stamp<R: Read>(mut reader: R) -> io::Result<Stamp> {
    let tachygrams = Vector::read(&mut reader, |r| read_tachygram(r))?;
    let anchor = read_anchor(&mut reader)?;
    let proof = read_proof(&mut reader)?;

    Ok(Stamp {
        tachygrams,
        anchor,
        proof,
    })
}

fn write_stamp<W: Write>(mut writer: W, stamp: &Stamp) -> io::Result<()> {
    Vector::write(&mut writer, &stamp.tachygrams, |w, t| write_tachygram(w, t))?;
    write_anchor(&mut writer, &stamp.anchor)?;
    write_proof(&mut writer, &stamp.proof)?;
    Ok(())
}

fn read_proof<R: Read>(mut reader: R) -> io::Result<Proof> {
    let mut bytes = vec![0u8; TACHYON_PROOF_SIZE];
    reader.read_exact(&mut bytes)?;
    let arr: [u8; TACHYON_PROOF_SIZE] = bytes.try_into().expect("vec is TACHYON_PROOF_SIZE");
    Proof::try_from(&arr).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid tachyon proof")
    })
}

fn write_proof<W: Write>(mut writer: W, proof: &Proof) -> io::Result<()> {
    let bytes = proof.serialize();
    writer.write_all(bytes.as_ref())
}

fn read_option_stamp<R: Read>(mut reader: R) -> io::Result<Option<Stamp>> {
    let flag = reader.read_u8()?;
    match flag {
        0 => Ok(None),
        1 => Ok(Some(read_stamp(&mut reader)?)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tachyon stamp flag: expected 0 or 1",
        )),
    }
}

fn write_option_stamp<W: Write>(mut writer: W, stamp: &Option<Stamp>) -> io::Result<()> {
    match stamp {
        None => writer.write_u8(0)?,
        Some(stamp) => {
            writer.write_u8(1)?;
            write_stamp(&mut writer, stamp)?;
        }
    }
    Ok(())
}
