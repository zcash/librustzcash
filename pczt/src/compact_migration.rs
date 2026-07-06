//! Compact migration-child PCZT transport.
//!
//! This module is intentionally narrow: it encodes the fixed Orchard-to-Ironwood
//! migration child shape as a small, signer-facing payload, then reconstructs the
//! ordinary PCZT structure before existing review and signing code runs.

use alloc::{collections::BTreeMap, format, vec::Vec};

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{Pczt, common, orchard, sapling, transparent};

pub const COMPACT_MIGRATION_CHILD_MAGIC: &[u8; 4] = b"MCC1";
pub const COMPACT_MIGRATION_BATCH_MAGIC: &[u8; 4] = b"MCB1";

/// A decoded compact migration child identifier plus its reconstructed PCZT bytes.
pub type DecodedMigrationPczt = (Vec<u8>, Vec<u8>);

#[derive(Debug)]
pub enum Error {
    NotCompactMigrationChild,
    InvalidShape(&'static str),
    Parse(crate::ParseError),
    Serialize(crate::EncodingError),
    Postcard(postcard::Error),
}

impl From<crate::ParseError> for Error {
    fn from(e: crate::ParseError) -> Self {
        Error::Parse(e)
    }
}

impl From<crate::EncodingError> for Error {
    fn from(e: crate::EncodingError) -> Self {
        Error::Serialize(e)
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompactMigrationChild {
    global: common::Global,
    #[serde_as(as = "[_; 43]")]
    address: [u8; 43],
    orchard_flags: u8,
    orchard_value_sum: (u64, bool),
    orchard_spend_value: u64,
    orchard_spend_rho: [u8; 32],
    orchard_spend_rseed: [u8; 32],
    orchard_spend_alpha: [u8; 32],
    orchard_spend_zip32_derivation: Option<common::Zip32Derivation>,
    orchard_rcv: [u8; 32],
    orchard_output_out_ciphertext: Vec<u8>,
    orchard_output_rseed: [u8; 32],
    ironwood_flags: u8,
    ironwood_value_sum: (u64, bool),
    ironwood_spend_nullifier: [u8; 32],
    ironwood_spend_rk: [u8; 32],
    ironwood_spend_value: u64,
    ironwood_rcv: [u8; 32],
    ironwood_output_value: u64,
    ironwood_output_rseed: [u8; 32],
    ironwood_output_out_ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompactMigrationBatchChild {
    orchard_flags: u8,
    orchard_value_sum: (u64, bool),
    orchard_spend_value: u64,
    orchard_spend_rho: [u8; 32],
    orchard_spend_rseed: [u8; 32],
    orchard_spend_alpha: [u8; 32],
    orchard_rcv: [u8; 32],
    orchard_output_out_ciphertext: Vec<u8>,
    orchard_output_rseed: [u8; 32],
    ironwood_flags: u8,
    ironwood_value_sum: (u64, bool),
    ironwood_spend_nullifier: [u8; 32],
    ironwood_spend_rk: [u8; 32],
    ironwood_spend_value: u64,
    ironwood_rcv: [u8; 32],
    ironwood_output_value: u64,
    ironwood_output_rseed: [u8; 32],
    ironwood_output_out_ciphertext: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompactMigrationBatch {
    global: common::Global,
    #[serde_as(as = "[_; 43]")]
    address: [u8; 43],
    orchard_spend_zip32_derivation: Option<common::Zip32Derivation>,
    first_child_index: u32,
    children: Vec<CompactMigrationBatchChild>,
}

impl CompactMigrationBatchChild {
    fn from_child(child: CompactMigrationChild) -> Self {
        Self {
            orchard_flags: child.orchard_flags,
            orchard_value_sum: child.orchard_value_sum,
            orchard_spend_value: child.orchard_spend_value,
            orchard_spend_rho: child.orchard_spend_rho,
            orchard_spend_rseed: child.orchard_spend_rseed,
            orchard_spend_alpha: child.orchard_spend_alpha,
            orchard_rcv: child.orchard_rcv,
            orchard_output_out_ciphertext: child.orchard_output_out_ciphertext,
            orchard_output_rseed: child.orchard_output_rseed,
            ironwood_flags: child.ironwood_flags,
            ironwood_value_sum: child.ironwood_value_sum,
            ironwood_spend_nullifier: child.ironwood_spend_nullifier,
            ironwood_spend_rk: child.ironwood_spend_rk,
            ironwood_spend_value: child.ironwood_spend_value,
            ironwood_rcv: child.ironwood_rcv,
            ironwood_output_value: child.ironwood_output_value,
            ironwood_output_rseed: child.ironwood_output_rseed,
            ironwood_output_out_ciphertext: child.ironwood_output_out_ciphertext,
        }
    }

    fn into_child(
        self,
        global: common::Global,
        address: [u8; 43],
        orchard_spend_zip32_derivation: Option<common::Zip32Derivation>,
    ) -> CompactMigrationChild {
        CompactMigrationChild {
            global,
            address,
            orchard_flags: self.orchard_flags,
            orchard_value_sum: self.orchard_value_sum,
            orchard_spend_value: self.orchard_spend_value,
            orchard_spend_rho: self.orchard_spend_rho,
            orchard_spend_rseed: self.orchard_spend_rseed,
            orchard_spend_alpha: self.orchard_spend_alpha,
            orchard_spend_zip32_derivation,
            orchard_rcv: self.orchard_rcv,
            orchard_output_out_ciphertext: self.orchard_output_out_ciphertext,
            orchard_output_rseed: self.orchard_output_rseed,
            ironwood_flags: self.ironwood_flags,
            ironwood_value_sum: self.ironwood_value_sum,
            ironwood_spend_nullifier: self.ironwood_spend_nullifier,
            ironwood_spend_rk: self.ironwood_spend_rk,
            ironwood_spend_value: self.ironwood_spend_value,
            ironwood_rcv: self.ironwood_rcv,
            ironwood_output_value: self.ironwood_output_value,
            ironwood_output_rseed: self.ironwood_output_rseed,
            ironwood_output_out_ciphertext: self.ironwood_output_out_ciphertext,
        }
    }
}

pub fn is_compact_migration_child_payload(payload: &[u8]) -> bool {
    payload.starts_with(COMPACT_MIGRATION_CHILD_MAGIC)
}

pub fn is_compact_migration_batch_payload(payload: &[u8]) -> bool {
    payload.starts_with(COMPACT_MIGRATION_BATCH_MAGIC)
}

pub fn encode_child_from_pczt_bytes(pczt_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let pczt = crate::parse(pczt_bytes)?;
    encode_child(&pczt)
}

pub fn encode_child(pczt: &Pczt) -> Result<Vec<u8>, Error> {
    let compact = compact_child_from_pczt(pczt)?;

    let mut out = Vec::new();
    out.extend_from_slice(COMPACT_MIGRATION_CHILD_MAGIC);
    postcard::to_extend(&compact, out).map_err(Error::Postcard)
}

fn compact_child_from_pczt(pczt: &Pczt) -> Result<CompactMigrationChild, Error> {
    if !pczt.transparent().inputs().is_empty() || !pczt.transparent().outputs().is_empty() {
        return Err(Error::InvalidShape(
            "compact migration child has transparent data",
        ));
    }
    if !pczt.sapling().spends().is_empty() || !pczt.sapling().outputs().is_empty() {
        return Err(Error::InvalidShape(
            "compact migration child has Sapling data",
        ));
    }

    let orchard_action = single_action(pczt.orchard(), "Orchard")?;
    let ironwood_action = single_action(pczt.ironwood(), "Ironwood")?;

    if pczt.orchard().raw_note_version() != orchard::NoteVersion::V2 {
        return Err(Error::InvalidShape(
            "compact migration child Orchard note version is not V2",
        ));
    }
    if pczt.ironwood().raw_note_version() != orchard::NoteVersion::V3 {
        return Err(Error::InvalidShape(
            "compact migration child Ironwood note version is not V3",
        ));
    }

    let address = orchard_action
        .spend()
        .raw_recipient()
        .ok_or(Error::InvalidShape("missing Orchard spend recipient"))?;
    let orchard_output_recipient = orchard_action
        .output()
        .raw_recipient()
        .ok_or(Error::InvalidShape("missing Orchard output recipient"))?;
    let ironwood_output_recipient = ironwood_action
        .output()
        .raw_recipient()
        .ok_or(Error::InvalidShape("missing Ironwood output recipient"))?;
    if orchard_output_recipient != address || ironwood_output_recipient != address {
        return Err(Error::InvalidShape(
            "compact migration child recipients do not share one address",
        ));
    }

    if *orchard_action.output().value() != Some(0) {
        return Err(Error::InvalidShape(
            "compact migration child Orchard output is not zero",
        ));
    }
    let compact = CompactMigrationChild {
        global: pczt.global().clone(),
        address,
        orchard_flags: *pczt.orchard().flags(),
        orchard_value_sum: *pczt.orchard().value_sum(),
        orchard_spend_value: orchard_action
            .spend()
            .value
            .ok_or(Error::InvalidShape("missing Orchard spend value"))?,
        orchard_spend_rho: orchard_action
            .spend()
            .raw_rho()
            .ok_or(Error::InvalidShape("missing Orchard spend rho"))?,
        orchard_spend_rseed: orchard_action
            .spend()
            .raw_rseed()
            .ok_or(Error::InvalidShape("missing Orchard spend rseed"))?,
        orchard_spend_alpha: orchard_action
            .spend()
            .raw_alpha()
            .ok_or(Error::InvalidShape("missing Orchard spend alpha"))?,
        orchard_spend_zip32_derivation: orchard_action.spend().raw_zip32_derivation(),
        orchard_rcv: orchard_action
            .raw_rcv()
            .ok_or(Error::InvalidShape("missing Orchard rcv"))?,
        orchard_output_out_ciphertext: orchard_action.output().out_ciphertext().clone(),
        orchard_output_rseed: orchard_action
            .output()
            .raw_rseed()
            .ok_or(Error::InvalidShape("missing Orchard output rseed"))?,
        ironwood_flags: *pczt.ironwood().flags(),
        ironwood_value_sum: *pczt.ironwood().value_sum(),
        ironwood_spend_nullifier: ironwood_action
            .spend()
            .nullifier()
            .ok_or(Error::InvalidShape("missing Ironwood spend nullifier"))?,
        ironwood_spend_rk: ironwood_action
            .spend()
            .rk()
            .ok_or(Error::InvalidShape("missing Ironwood rk"))?,
        ironwood_spend_value: ironwood_action.spend().value.unwrap_or(0),
        ironwood_rcv: ironwood_action
            .raw_rcv()
            .ok_or(Error::InvalidShape("missing Ironwood rcv"))?,
        ironwood_output_value: ironwood_action
            .output()
            .value()
            .ok_or(Error::InvalidShape("missing Ironwood output value"))?,
        ironwood_output_rseed: ironwood_action
            .output()
            .raw_rseed()
            .ok_or(Error::InvalidShape("missing Ironwood output rseed"))?,
        ironwood_output_out_ciphertext: ironwood_action.output().out_ciphertext().clone(),
    };

    validate_compact_child_recomputes_orchard_dummy_ciphertext(pczt)?;

    Ok(compact)
}

pub fn encode_batch_from_child_payloads(
    first_child_index: u32,
    child_payloads: &[&[u8]],
) -> Result<Vec<u8>, Error> {
    if child_payloads.is_empty() {
        return Err(Error::InvalidShape(
            "compact migration batch has no children",
        ));
    }

    let first = parse_child_payload(child_payloads[0])?;
    let global = first.global.clone();
    let address = first.address;
    let orchard_spend_zip32_derivation = first.orchard_spend_zip32_derivation.clone();
    let mut children = Vec::with_capacity(child_payloads.len());
    children.push(CompactMigrationBatchChild::from_child(first));

    for payload in &child_payloads[1..] {
        let child = parse_child_payload(payload)?;
        if !same_global(&global, &child.global) {
            return Err(Error::InvalidShape(
                "compact migration batch children do not share one global header",
            ));
        }
        if child.address != address {
            return Err(Error::InvalidShape(
                "compact migration batch children do not share one address",
            ));
        }
        if child.orchard_spend_zip32_derivation != orchard_spend_zip32_derivation {
            return Err(Error::InvalidShape(
                "compact migration batch children do not share one Orchard ZIP 32 derivation",
            ));
        }
        children.push(CompactMigrationBatchChild::from_child(child));
    }

    let batch = CompactMigrationBatch {
        global,
        address,
        orchard_spend_zip32_derivation,
        first_child_index,
        children,
    };

    let mut out = Vec::new();
    out.extend_from_slice(COMPACT_MIGRATION_BATCH_MAGIC);
    postcard::to_extend(&batch, out).map_err(Error::Postcard)
}

pub fn decode_child_to_pczt_bytes(payload: &[u8]) -> Result<Vec<u8>, Error> {
    decode_child(payload)?.serialize().map_err(Error::Serialize)
}

pub fn decode_child(payload: &[u8]) -> Result<Pczt, Error> {
    pczt_from_compact_child(parse_child_payload(payload)?)
}

pub fn decode_batch_to_pczt_bytes(payload: &[u8]) -> Result<Vec<DecodedMigrationPczt>, Error> {
    let batch = parse_batch_payload(payload)?;
    let mut decoded = Vec::with_capacity(batch.children.len());
    for (index, child) in batch.children.into_iter().enumerate() {
        let index =
            batch
                .first_child_index
                .checked_add(index as u32)
                .ok_or(Error::InvalidShape(
                    "compact migration batch child index overflow",
                ))?;
        let id = format!("migration-{index}").into_bytes();
        let pczt = pczt_from_compact_child(child.into_child(
            batch.global.clone(),
            batch.address,
            batch.orchard_spend_zip32_derivation.clone(),
        ))?;
        decoded.push((id, pczt.serialize().map_err(Error::Serialize)?));
    }
    Ok(decoded)
}

fn parse_child_payload(payload: &[u8]) -> Result<CompactMigrationChild, Error> {
    if !payload.starts_with(COMPACT_MIGRATION_CHILD_MAGIC) {
        return Err(Error::NotCompactMigrationChild);
    }
    postcard::from_bytes::<CompactMigrationChild>(&payload[COMPACT_MIGRATION_CHILD_MAGIC.len()..])
        .map_err(Error::Postcard)
}

fn parse_batch_payload(payload: &[u8]) -> Result<CompactMigrationBatch, Error> {
    if !payload.starts_with(COMPACT_MIGRATION_BATCH_MAGIC) {
        return Err(Error::NotCompactMigrationChild);
    }
    let batch = postcard::from_bytes::<CompactMigrationBatch>(
        &payload[COMPACT_MIGRATION_BATCH_MAGIC.len()..],
    )
    .map_err(Error::Postcard)?;
    if batch.children.is_empty() {
        return Err(Error::InvalidShape(
            "compact migration batch has no children",
        ));
    }
    Ok(batch)
}

fn validate_compact_child_recomputes_orchard_dummy_ciphertext(
    original: &Pczt,
) -> Result<(), Error> {
    let original_orchard_action_idx = match original.orchard().actions().as_slice() {
        [_] => 0,
        [] => return Err(Error::InvalidShape("Orchard")),
        _ => {
            return Err(Error::InvalidShape(
                "compact migration child has multiple actions",
            ));
        }
    };
    let original_enc_ciphertext = single_action(original.orchard(), "Orchard")?
        .output()
        .enc_ciphertext()
        .as_ref()
        .ok_or(Error::InvalidShape("missing Orchard output enc_ciphertext"))?;

    let mut candidate = original.clone();
    let candidate_output = &mut candidate.orchard.actions[original_orchard_action_idx].output;
    candidate_output.enc_ciphertext = None;
    candidate_output.memo_kind = Some(orchard::MemoKind::Zero);
    candidate.fill_derived_fields().map_err(|_| {
        Error::InvalidShape("compact migration child Orchard output enc_ciphertext did not fill")
    })?;

    let reconstructed_enc_ciphertext = single_action(candidate.orchard(), "Orchard")?
        .output()
        .enc_ciphertext()
        .as_ref()
        .ok_or(Error::InvalidShape(
            "missing reconstructed Orchard output enc_ciphertext",
        ))?;

    if reconstructed_enc_ciphertext != original_enc_ciphertext {
        return Err(Error::InvalidShape(
            "compact migration child Orchard output enc_ciphertext is not recomputable",
        ));
    }

    Ok(())
}

fn pczt_from_compact_child(compact: CompactMigrationChild) -> Result<Pczt, Error> {
    let orchard_spend = orchard::Spend::from_raw_parts(
        None,
        None,
        None,
        Some(compact.address),
        Some(compact.orchard_spend_value),
        Some(compact.orchard_spend_rho),
        Some(compact.orchard_spend_rseed),
        None,
        None,
        Some(compact.orchard_spend_alpha),
        compact.orchard_spend_zip32_derivation,
        None,
        BTreeMap::new(),
    );
    let orchard_output = orchard::Output::from_raw_parts(
        None,
        None,
        None,
        Some(orchard::MemoKind::Zero),
        compact.orchard_output_out_ciphertext,
        Some(compact.address),
        Some(0),
        Some(compact.orchard_output_rseed),
        None,
        None,
        None,
        BTreeMap::new(),
    );
    let orchard_action = orchard::Action::from_raw_parts(
        None,
        orchard_spend,
        orchard_output,
        Some(compact.orchard_rcv),
    );

    let ironwood_spend = orchard::Spend::from_raw_parts(
        Some(compact.ironwood_spend_nullifier),
        Some(compact.ironwood_spend_rk),
        None,
        None,
        Some(compact.ironwood_spend_value),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        BTreeMap::new(),
    );
    let ironwood_output = orchard::Output::from_raw_parts(
        None,
        None,
        None,
        Some(orchard::MemoKind::Empty),
        compact.ironwood_output_out_ciphertext,
        Some(compact.address),
        Some(compact.ironwood_output_value),
        Some(compact.ironwood_output_rseed),
        None,
        None,
        None,
        BTreeMap::new(),
    );
    let ironwood_action = orchard::Action::from_raw_parts(
        None,
        ironwood_spend,
        ironwood_output,
        Some(compact.ironwood_rcv),
    );

    Ok(Pczt {
        global: compact.global,
        transparent: transparent::EMPTY_BUNDLE,
        sapling: sapling::EMPTY_BUNDLE,
        orchard: orchard::Bundle::from_raw_parts(
            vec![orchard_action],
            compact.orchard_flags,
            compact.orchard_value_sum,
            None,
            orchard::NoteVersion::V2,
            None,
            None,
        ),
        ironwood: orchard::Bundle::from_raw_parts(
            vec![ironwood_action],
            compact.ironwood_flags,
            compact.ironwood_value_sum,
            None,
            orchard::NoteVersion::V3,
            None,
            None,
        ),
    })
}

fn same_global(a: &common::Global, b: &common::Global) -> bool {
    a.tx_version == b.tx_version
        && a.version_group_id == b.version_group_id
        && a.consensus_branch_id == b.consensus_branch_id
        && a.fallback_lock_time == b.fallback_lock_time
        && a.expiry_height == b.expiry_height
        && a.coin_type == b.coin_type
        && a.tx_modifiable == b.tx_modifiable
        && a.proprietary == b.proprietary
}

fn single_action<'a>(
    bundle: &'a orchard::Bundle,
    name: &'static str,
) -> Result<&'a orchard::Action, Error> {
    match bundle.actions().as_slice() {
        [action] => Ok(action),
        [] => Err(Error::InvalidShape(name)),
        _ => Err(Error::InvalidShape(
            "compact migration child has multiple actions",
        )),
    }
}
