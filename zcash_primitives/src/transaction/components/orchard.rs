/// Functions for parsing & serialization of Orchard transaction components.
use std::io::{self, Read};

use byteorder::ReadBytesExt;

use super::Amount;
use crate::{serialize::Vector, transaction::Transaction};
use blake2b_simd::{Hash as Blake2bHash, Params, State};

const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;
const FLAG_OUTPUTS_ENABLED: u8 = 0b0000_0010;
const FLAGS_EXPECTED_UNSET: u8 = !(FLAG_SPENDS_ENABLED | FLAG_OUTPUTS_ENABLED);

const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrchardHash";
const ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActCHash";
const ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActMHash";
const ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOrcActNHash";

/// Orchard-specific flags.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Flags {
    /// Flag denoting whether Orchard spends are enabled in the transaction.
    ///
    /// If `false`, spent notes within [`Action`]s in the transaction's [`Bundle`] are
    /// guaranteed to be dummy notes. If `true`, the spent notes may be either real or
    /// dummy notes.
    spends_enabled: bool,
    /// Flag denoting whether Orchard outputs are enabled in the transaction.
    ///
    /// If `false`, created notes within [`Action`]s in the transaction's [`Bundle`] are
    /// guaranteed to be dummy notes. If `true`, the created notes may be either real or
    /// dummy notes.
    outputs_enabled: bool,
}

impl Flags {
    /// Construct a set of flags from its constituent parts
    fn from_parts(spends_enabled: bool, outputs_enabled: bool) -> Self {
        Flags {
            spends_enabled,
            outputs_enabled,
        }
    }

    fn to_byte(self) -> u8 {
        let mut value = 0u8;
        if self.spends_enabled {
            value |= FLAG_SPENDS_ENABLED;
        }
        if self.outputs_enabled {
            value |= FLAG_OUTPUTS_ENABLED;
        }
        value
    }

    fn from_byte(value: u8) -> Option<Self> {
        if value & FLAGS_EXPECTED_UNSET == 0 {
            Some(Self::from_parts(
                value & FLAG_SPENDS_ENABLED != 0,
                value & FLAG_OUTPUTS_ENABLED != 0,
            ))
        } else {
            None
        }
    }
}

/// An encrypted note.
#[derive(Clone)]
pub(crate) struct TransmittedNoteCiphertext {
    pub epk_bytes: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
}

pub(crate) struct Action<A> {
    nf: [u8; 32],
    rk: [u8; 32],
    cmx: [u8; 32],
    encrypted_note: TransmittedNoteCiphertext,
    cv_net: [u8; 32],
    authorization: A,
}

impl<T> Action<T> {
    /// Transitions this action from one authorization state to another.
    pub fn try_map<U, E>(self, step: impl FnOnce(T) -> Result<U, E>) -> Result<Action<U>, E> {
        Ok(Action {
            nf: self.nf,
            rk: self.rk,
            cmx: self.cmx,
            encrypted_note: self.encrypted_note,
            cv_net: self.cv_net,
            authorization: step(self.authorization)?,
        })
    }
}

pub(crate) struct Bundle {
    actions: Vec<Action<[u8; 64]>>,
    flags: Flags,
    value_balance: Amount,
    anchor: [u8; 32],
}

/// Reads an [`orchard::Bundle`] from a v5 transaction format.
pub(crate) fn read_v5_bundle<R: Read>(mut reader: R) -> io::Result<Option<Bundle>> {
    #[allow(clippy::redundant_closure)]
    let actions_without_auth = Vector::read(&mut reader, |r| read_action_without_auth(r))?;
    if actions_without_auth.is_empty() {
        Ok(None)
    } else {
        let flags = read_flags(&mut reader)?;
        let value_balance = Transaction::read_amount(&mut reader)?;
        let anchor = read_anchor(&mut reader)?;
        let _proof_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
        let actions = actions_without_auth
            .into_iter()
            .map(|act| act.try_map(|_| read_signature(&mut reader)))
            .collect::<Result<Vec<_>, _>>()?;
        let _binding_signature = read_signature(&mut reader)?;

        Ok(Some(Bundle {
            actions,
            flags,
            value_balance,
            anchor,
        }))
    }
}

fn read_value_commitment<R: Read>(mut reader: R) -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_nullifier<R: Read>(mut reader: R) -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_verification_key<R: Read>(mut reader: R) -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_cmx<R: Read>(mut reader: R) -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_note_ciphertext<R: Read>(mut reader: R) -> io::Result<TransmittedNoteCiphertext> {
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

fn read_action_without_auth<R: Read>(mut reader: R) -> io::Result<Action<()>> {
    let cv_net = read_value_commitment(&mut reader)?;
    let nf_old = read_nullifier(&mut reader)?;
    let rk = read_verification_key(&mut reader)?;
    let cmx = read_cmx(&mut reader)?;
    let encrypted_note = read_note_ciphertext(&mut reader)?;

    Ok(Action {
        nf: nf_old,
        rk,
        cmx,
        encrypted_note,
        cv_net,
        authorization: (),
    })
}

fn read_flags<R: Read>(mut reader: R) -> io::Result<Flags> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Flags::from_byte(byte[0]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Orchard flags".to_owned(),
        )
    })
}

fn read_anchor<R: Read>(mut reader: R) -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_signature<R: Read>(mut reader: R) -> io::Result<[u8; 64]> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

/// Write disjoint parts of each Orchard shielded action as 3 separate hashes:
/// * \[(nullifier, cmx, ephemeral_key, enc_ciphertext\[..52\])*\] personalized
///   with ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized
///   with ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION
/// * \[(cv, rk, enc_ciphertext\[564..\], out_ciphertext)*\] personalized
///   with ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION
/// as defined in [ZIP-244: Transaction Identifier Non-Malleability][zip244]
///
/// Then, hash these together along with (flags, value_balance_orchard, anchor_orchard),
/// personalized with ZCASH_ORCHARD_ACTIONS_HASH_PERSONALIZATION
///
/// [zip244]: https://zips.z.cash/zip-0244
pub(crate) fn hash_bundle_txid_data(bundle: &Bundle) -> Blake2bHash {
    let mut h = hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION);
    let mut ch = hasher(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
    let mut mh = hasher(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);
    let mut nh = hasher(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

    for action in bundle.actions.iter() {
        ch.update(&action.nf);
        ch.update(&action.cmx);
        ch.update(&action.encrypted_note.epk_bytes);
        ch.update(&action.encrypted_note.enc_ciphertext[..52]);

        mh.update(&action.encrypted_note.enc_ciphertext[52..564]);

        nh.update(&action.cv_net);
        nh.update(&action.rk);
        nh.update(&action.encrypted_note.enc_ciphertext[564..]);
        nh.update(&action.encrypted_note.out_ciphertext);
    }

    h.update(ch.finalize().as_bytes());
    h.update(mh.finalize().as_bytes());
    h.update(nh.finalize().as_bytes());
    h.update(&[bundle.flags.to_byte()]);
    h.update(&bundle.value_balance.to_i64_le_bytes());
    h.update(&bundle.anchor);
    h.finalize()
}

/// Construct the commitment for the absent bundle as defined in
/// [ZIP-244: Transaction Identifier Non-Malleability][zip244]
///
/// [zip244]: https://zips.z.cash/zip-0244
pub fn hash_bundle_txid_empty() -> Blake2bHash {
    hasher(ZCASH_ORCHARD_HASH_PERSONALIZATION).finalize()
}
