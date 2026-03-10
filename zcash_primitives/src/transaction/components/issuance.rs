#[cfg(zcash_unstable = "nu7")]
use {
    crate::{
        encoding::{ReadBytesExt, WriteBytesExt},
        sighash_versioning::{issue_sighash_kind_from_info, issue_sighash_kind_to_info},
    },
    core2::io::{self, Error, ErrorKind, Read, Write},
    nonempty::NonEmpty,
    orchard::{
        issuance::auth::{IssueAuthSig, IssueValidatingKey, ZSASchnorr},
        issuance::sighash_kind::BIP340IssueAuthSig,
        issuance::{IssueAction, IssueAuth, IssueBundle, Signed},
        note::{AssetBase, AssetId, RandomSeed, Rho},
        value::NoteValue,
        {Address, Note},
    },
    zcash_encoding::{CompactSize, Vector},
};

/// Reads an [`IssueBundle`] from a v6 transaction format.
#[cfg(zcash_unstable = "nu7")]
pub fn read_bundle<R: Read>(mut reader: R) -> io::Result<Option<IssueBundle<Signed>>> {
    let issuer_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    if issuer_bytes.is_empty() {
        let n_actions = CompactSize::read(&mut reader)?;
        if n_actions != 0 {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid IssueBundle: empty issuer with non-empty IssueActions",
            ))
        } else {
            Ok(None)
        }
    } else {
        let issuer = IssueValidatingKey::<ZSASchnorr>::decode(&issuer_bytes)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid issuer encoding"))?;

        let actions = Vector::read(&mut reader, |r| read_action(r, &issuer))?;

        if actions.is_empty() {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid IssueBundle: no IssueActions with non-empty issuer",
            ))
        } else {
            let authorization = read_authorization(&mut reader)?;

            Ok(Some(IssueBundle::from_parts(
                issuer,
                NonEmpty::from_vec(actions).unwrap(),
                authorization,
            )))
        }
    }
}

#[cfg(zcash_unstable = "nu7")]
fn read_authorization<R: Read>(mut reader: R) -> io::Result<Signed> {
    let sighash_info_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    let sighash_kind = issue_sighash_kind_from_info(sighash_info_bytes.as_slice()).ok_or(
        Error::new(ErrorKind::InvalidData, "Unknown issuance sighash version"),
    )?;

    let sig_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    let sig = IssueAuthSig::decode(&sig_bytes).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "Invalid signature for IssuanceAuthorization",
        )
    })?;

    Ok(Signed::new(BIP340IssueAuthSig::new(sighash_kind, sig)))
}

#[cfg(zcash_unstable = "nu7")]
fn read_action<R: Read>(
    mut reader: R,
    ik: &IssueValidatingKey<ZSASchnorr>,
) -> io::Result<IssueAction> {
    let mut asset_desc_hash = [0u8; 32];
    reader.read_exact(&mut asset_desc_hash).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "Invalid Asset Description Hash in IssueAction",
        )
    })?;
    let asset = AssetBase::custom(&AssetId::new_v0(ik, &asset_desc_hash));
    let notes = Vector::read(&mut reader, |r| read_note(r, asset))?;
    let finalize = match reader.read_u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid value for finalize",
            ));
        }
    };
    Ok(IssueAction::from_parts(asset_desc_hash, notes, finalize))
}

#[cfg(zcash_unstable = "nu7")]
pub fn read_note<R: Read>(mut reader: R, asset: AssetBase) -> io::Result<Note> {
    let recipient = read_recipient(&mut reader)?;
    let mut tmp = [0; 8];
    reader.read_exact(&mut tmp)?;
    let value = u64::from_le_bytes(tmp);
    let rho = read_rho(&mut reader)?;
    let rseed = read_rseed(&mut reader, &rho)?;

    Option::from(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        asset,
        rho,
        rseed,
    ))
    .ok_or(Error::new(ErrorKind::InvalidData, "Invalid note"))
}

#[cfg(zcash_unstable = "nu7")]
fn read_rho<R: Read>(mut reader: R) -> io::Result<Rho> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(Rho::from_bytes(&bytes)).ok_or(Error::new(
        ErrorKind::InvalidData,
        "invalid Pallas point for rho",
    ))
}

#[cfg(zcash_unstable = "nu7")]
fn read_recipient<R: Read>(mut reader: R) -> io::Result<Address> {
    let mut bytes = [0u8; 43];
    reader.read_exact(&mut bytes)?;
    Option::from(Address::from_raw_address_bytes(&bytes)).ok_or(Error::new(
        ErrorKind::InvalidData,
        "Invalid recipient address",
    ))
}

#[cfg(zcash_unstable = "nu7")]
pub fn read_asset<R: Read>(reader: &mut R) -> io::Result<AssetBase> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(AssetBase::from_bytes(&bytes))
        .ok_or(Error::new(ErrorKind::InvalidData, "Invalid asset"))
}

#[cfg(zcash_unstable = "nu7")]
fn read_rseed<R: Read>(mut reader: R, nullifier: &Rho) -> io::Result<RandomSeed> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(RandomSeed::from_bytes(bytes, nullifier))
        .ok_or(Error::new(ErrorKind::InvalidData, "Invalid rseed"))
}

/// Writes an [`IssueBundle`] in the v6 transaction format.
#[cfg(zcash_unstable = "nu7")]
pub fn write_bundle<W: Write>(
    bundle: Option<&IssueBundle<Signed>>,
    mut writer: W,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        Vector::write(&mut writer, &bundle.ik().encode(), |w, b| w.write_u8(*b))?;
        Vector::write_nonempty(&mut writer, bundle.actions(), write_action)?;
        let sighash_info_bytes =
            issue_sighash_kind_to_info(bundle.authorization().signature().sighash_kind());
        Vector::write(&mut writer, &sighash_info_bytes, |w, b| w.write_u8(*b))?;

        Vector::write(
            &mut writer,
            &bundle.authorization().signature().sig().encode(),
            |w, b| w.write_u8(*b),
        )?;
    } else {
        // Empty issuer
        CompactSize::write(&mut writer, 0)?;
        // Empty vIssueActions
        CompactSize::write(&mut writer, 0)?;
    }
    Ok(())
}

#[cfg(zcash_unstable = "nu7")]
fn write_action<W: Write>(mut writer: &mut W, action: &IssueAction) -> io::Result<()> {
    writer.write_all(action.asset_desc_hash())?;
    Vector::write(&mut writer, action.notes(), write_note)?;
    writer.write_u8(action.is_finalized() as u8)?;
    Ok(())
}

#[cfg(zcash_unstable = "nu7")]
pub fn write_note<W: Write>(writer: &mut W, note: &Note) -> io::Result<()> {
    writer.write_all(&note.recipient().to_raw_address_bytes())?;
    writer.write_all(&note.value().to_bytes())?;
    writer.write_all(&note.rho().to_bytes())?;
    writer.write_all(note.rseed().as_bytes())?;
    Ok(())
}

#[cfg(zcash_unstable = "nu7")]
pub trait MapIssueAuth<A: IssueAuth, B: IssueAuth> {
    fn map_issue_authorization(&self, a: A) -> B;
}

/// The identity map.
///
/// This can be used with [`TransactionData::map_authorization`] when you want to map the
/// authorization of a subset of the transaction's bundles.
///
/// [`TransactionData::map_authorization`]: crate::transaction::TransactionData::map_authorization
#[cfg(zcash_unstable = "nu7")]
impl MapIssueAuth<Signed, Signed> for () {
    fn map_issue_authorization(&self, a: Signed) -> Signed {
        a
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use orchard::issuance::{
        IssueBundle, Signed,
        testing::{self as t_issue},
    };

    use crate::transaction::TxVersion;

    prop_compose! {
        pub fn arb_issue_bundle(n_actions: usize)(
            bundle in t_issue::arb_signed_issue_bundle(n_actions)
        ) -> IssueBundle<Signed> {
            bundle
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<IssueBundle<Signed>>> {
        if v.has_orchard_zsa() {
            Strategy::boxed((1usize..100).prop_flat_map(|n| prop::option::of(arb_issue_bundle(n))))
        } else {
            Strategy::boxed(Just(None))
        }
    }
}
