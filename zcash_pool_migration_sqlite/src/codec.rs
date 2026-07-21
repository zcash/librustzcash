//! The pure, SQL-agnostic byte (de)serialization of the engine types to and from their stored form.
//!
//! The blob formats and the column-splits live here; the DB and SQL orchestration that stores and
//! reads them lives in [`crate::store`]. Every `encode_*` builds the exact bytes (or column tuple)
//! that the matching `decode_*` reads back, so the two are symmetric and the on-disk format has a
//! single home. Fixed-width fields are appended with a [`Writer`] and read back with a [`Reader`].

use zcash_pool_migration_backend::engine::{MigrationTxId, MigrationTxKind, MigrationTxState};
use zcash_pool_migration_backend::preparation::{
    PrepInput, PrepOutput, PrepTransaction, PreparationPlan,
};
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::error::Error;

// --- (de)serialization of the engine types to/from rows ---

/// A little cursor that appends the fixed-width fields [`Reader`] reads back, so encoding mirrors
/// decoding.
struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Writer { out: Vec::new() }
    }
    fn with_capacity(n: usize) -> Self {
        Writer {
            out: Vec::with_capacity(n),
        }
    }
    fn u8(&mut self, v: u8) {
        self.out.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    /// A `usize` count/index narrowed to `u32` (mirrors [`Reader::usize`]).
    fn usize(&mut self, v: usize) {
        self.u32(v as u32);
    }
    fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    fn into_vec(self) -> Vec<u8> {
        self.out
    }
}

/// Encode a slice of `u64` as concatenated little-endian bytes (an 8-byte-aligned blob).
fn encode_u64s(values: &[u64]) -> Vec<u8> {
    let mut w = Writer::with_capacity(values.len() * 8);
    for &v in values {
        w.u64(v);
    }
    w.into_vec()
}

/// Decode a blob produced by [`encode_u64s`]; errors (naming `field`) if the length is not a multiple
/// of 8.
fn decode_u64s(blob: &[u8], field: &'static str) -> Result<Vec<u64>, Error> {
    if blob.len() % 8 != 0 {
        return Err(Error::Corrupt(field));
    }
    Ok(blob
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().expect("chunk is 8 bytes")))
        .collect())
}

/// Encode a slice of [`Zatoshis`] as concatenated little-endian `u64` bytes (via [`encode_u64s`]).
pub(crate) fn encode_zatoshis(values: &[Zatoshis]) -> Vec<u8> {
    let raw: Vec<u64> = values.iter().map(|z| z.into_u64()).collect();
    encode_u64s(&raw)
}

/// Decode a blob produced by [`encode_zatoshis`]; errors (naming `field`) if the length is not a
/// multiple of 8 or a stored value is not a representable amount.
pub(crate) fn decode_zatoshis(blob: &[u8], field: &'static str) -> Result<Vec<Zatoshis>, Error> {
    decode_u64s(blob, field)?
        .into_iter()
        .map(|n| Zatoshis::from_u64(n).map_err(|_| Error::Corrupt(field)))
        .collect()
}

/// Decode a stored `i64` amount column back into [`Zatoshis`], naming `field` on a negative or
/// out-of-range value.
pub(crate) fn zatoshis_from_i64(v: i64, field: &'static str) -> Result<Zatoshis, Error> {
    let n = u64::try_from(v).map_err(|_| Error::Corrupt(field))?;
    Zatoshis::from_u64(n).map_err(|_| Error::Corrupt(field))
}

/// Encode transaction ids (the `depends_on` graph) as concatenated little-endian `u32` bytes.
pub(crate) fn encode_dep_ids(ids: &[MigrationTxId]) -> Vec<u8> {
    let mut w = Writer::with_capacity(ids.len() * 4);
    for id in ids {
        w.u32(u32::from(*id));
    }
    w.into_vec()
}

/// Decode a blob produced by [`encode_dep_ids`]; errors if the length is not a multiple of 4.
pub(crate) fn decode_dep_ids(blob: &[u8]) -> Result<Vec<MigrationTxId>, Error> {
    if blob.len() % 4 != 0 {
        return Err(Error::Corrupt("depends_on"));
    }
    Ok(blob
        .chunks_exact(4)
        .map(|c| MigrationTxId::new(u32::from_le_bytes(c.try_into().expect("chunk is 4 bytes"))))
        .collect())
}

// --- (de)serialization of the preparation plan (its layers and direct-funding notes) ---
//
// A tagged little-endian encoding of the `PreparationPlan`, so a resumed migration can rebuild its
// deferred preparation layers. Counts and indices are `u32` (a plan is small); note values are `u64`.
// Layout:
//   direct_funding: u32 count, then count * (u32 wallet index, u64 value)
//   layers: u32 layer count, then per layer: u32 tx count, then per transaction:
//     inputs:  u32 count, then per input: u8 tag (0=Wallet, 1=Prior)
//                Wallet: u32 index; Prior: u32 layer, u32 transaction, u32 output
//     outputs: u32 count, then per output: u8 tag (0=Funding, 1=Intermediate, 2=Change), u64 value

/// The input-tag byte for a [`PrepInput::Wallet`].
const INPUT_TAG_WALLET: u8 = 0;
/// The input-tag byte for a [`PrepInput::Prior`].
const INPUT_TAG_PRIOR: u8 = 1;
/// The output-tag byte for a [`PrepOutput::Funding`].
const OUTPUT_TAG_FUNDING: u8 = 0;
/// The output-tag byte for a [`PrepOutput::Intermediate`].
const OUTPUT_TAG_INTERMEDIATE: u8 = 1;
/// The output-tag byte for a [`PrepOutput::Change`].
const OUTPUT_TAG_CHANGE: u8 = 2;

/// Encode a [`PreparationPlan`] into the tagged little-endian blob stored in the `preparation` column.
pub(crate) fn encode_preparation(plan: &PreparationPlan) -> Vec<u8> {
    let mut w = Writer::new();

    let direct = plan.direct_funding_notes();
    w.usize(direct.len());
    for &(index, value) in direct {
        w.usize(index);
        w.u64(value.into_u64());
    }

    let layers = plan.layers();
    w.usize(layers.len());
    for layer in layers {
        w.usize(layer.len());
        for tx in layer {
            w.usize(tx.inputs().len());
            for input in tx.inputs() {
                match input {
                    PrepInput::Wallet { index, value } => {
                        w.u8(INPUT_TAG_WALLET);
                        w.usize(*index);
                        w.u64(value.into_u64());
                    }
                    PrepInput::Prior {
                        layer,
                        transaction,
                        output,
                        value,
                    } => {
                        w.u8(INPUT_TAG_PRIOR);
                        w.usize(*layer);
                        w.usize(*transaction);
                        w.usize(*output);
                        w.u64(value.into_u64());
                    }
                }
            }
            w.usize(tx.outputs().len());
            for output in tx.outputs() {
                let (tag, value) = match output {
                    PrepOutput::Funding(v) => (OUTPUT_TAG_FUNDING, *v),
                    PrepOutput::Intermediate(v) => (OUTPUT_TAG_INTERMEDIATE, *v),
                    PrepOutput::Change(v) => (OUTPUT_TAG_CHANGE, *v),
                };
                w.u8(tag);
                w.u64(value.into_u64());
            }
        }
    }
    w.into_vec()
}

/// A little cursor over a byte blob, reading the fixed-width fields [`encode_preparation`] wrote and
/// erroring (naming the field) on truncation or a bad tag.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Corrupt(field))?;
        let slice = self.bytes.get(self.pos..end).ok_or(Error::Corrupt(field))?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, Error> {
        Ok(self.take(1, field)?[0])
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, Error> {
        let b = self.take(4, field)?;
        Ok(u32::from_le_bytes(b.try_into().expect("chunk is 4 bytes")))
    }

    /// A `u32` count/index widened to `usize`.
    fn usize(&mut self, field: &'static str) -> Result<usize, Error> {
        Ok(self.u32(field)? as usize)
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, Error> {
        let b = self.take(8, field)?;
        Ok(u64::from_le_bytes(b.try_into().expect("chunk is 8 bytes")))
    }

    /// A `u64` amount wrapped as [`Zatoshis`], erroring (naming `field`) if it is not a representable
    /// amount.
    fn zatoshis(&mut self, field: &'static str) -> Result<Zatoshis, Error> {
        Zatoshis::from_u64(self.u64(field)?).map_err(|_| Error::Corrupt(field))
    }

    /// All bytes have been consumed.
    fn at_end(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

/// Decode a blob produced by [`encode_preparation`] back into a [`PreparationPlan`]; errors (naming the
/// field) on truncation, a bad tag, or trailing bytes.
pub(crate) fn decode_preparation(blob: &[u8]) -> Result<PreparationPlan, Error> {
    let mut r = Reader::new(blob);

    let direct_len = r.usize("preparation.direct_funding.len")?;
    let mut direct_funding = Vec::with_capacity(direct_len);
    for _ in 0..direct_len {
        let index = r.usize("preparation.direct_funding.index")?;
        let value = r.zatoshis("preparation.direct_funding.value")?;
        direct_funding.push((index, value));
    }

    let layer_count = r.usize("preparation.layers.len")?;
    let mut layers = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        let tx_count = r.usize("preparation.layer.len")?;
        let mut txs = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            let in_count = r.usize("preparation.tx.inputs.len")?;
            let mut inputs = Vec::with_capacity(in_count);
            for _ in 0..in_count {
                let input = match r.u8("preparation.input.tag")? {
                    INPUT_TAG_WALLET => PrepInput::Wallet {
                        index: r.usize("preparation.input.wallet.index")?,
                        value: r.zatoshis("preparation.input.wallet.value")?,
                    },
                    INPUT_TAG_PRIOR => PrepInput::Prior {
                        layer: r.usize("preparation.input.prior.layer")?,
                        transaction: r.usize("preparation.input.prior.transaction")?,
                        output: r.usize("preparation.input.prior.output")?,
                        value: r.zatoshis("preparation.input.prior.value")?,
                    },
                    _ => return Err(Error::Corrupt("preparation.input.tag")),
                };
                inputs.push(input);
            }
            let out_count = r.usize("preparation.tx.outputs.len")?;
            let mut outputs = Vec::with_capacity(out_count);
            for _ in 0..out_count {
                let tag = r.u8("preparation.output.tag")?;
                let value = r.zatoshis("preparation.output.value")?;
                let output = match tag {
                    OUTPUT_TAG_FUNDING => PrepOutput::Funding(value),
                    OUTPUT_TAG_INTERMEDIATE => PrepOutput::Intermediate(value),
                    OUTPUT_TAG_CHANGE => PrepOutput::Change(value),
                    _ => return Err(Error::Corrupt("preparation.output.tag")),
                };
                outputs.push(output);
            }
            txs.push(PrepTransaction::from_parts(inputs, outputs));
        }
        layers.push(txs);
    }

    if !r.at_end() {
        return Err(Error::Corrupt("preparation.trailing"));
    }
    Ok(PreparationPlan::from_parts(layers, direct_funding))
}

/// Split a transaction lifecycle state into its `(state, txid, mined_height)` column values. `txid` is
/// set only for `Broadcast`, `mined_height` only for `Mined`.
pub(crate) fn encode_tx_state(
    state: &MigrationTxState,
) -> (&'static str, Option<Vec<u8>>, Option<i64>) {
    match state {
        MigrationTxState::AwaitingSignature => ("awaiting_signature", None, None),
        MigrationTxState::Signed => ("signed", None, None),
        MigrationTxState::Proved => ("proved", None, None),
        MigrationTxState::Broadcast { txid } => ("broadcast", Some(txid.as_ref().to_vec()), None),
        MigrationTxState::Mined { height } => ("mined", None, Some(i64::from(u32::from(*height)))),
    }
}

/// Reassemble a transaction lifecycle state from its column values.
pub(crate) fn decode_tx_state(
    state: &str,
    txid: Option<Vec<u8>>,
    mined_height: Option<i64>,
) -> Result<MigrationTxState, Error> {
    Ok(match state {
        "awaiting_signature" => MigrationTxState::AwaitingSignature,
        "signed" => MigrationTxState::Signed,
        "proved" => MigrationTxState::Proved,
        "broadcast" => {
            let bytes = txid.ok_or(Error::Corrupt("state.broadcast.txid"))?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::Corrupt("state.broadcast.txid"))?;
            MigrationTxState::Broadcast {
                txid: TxId::from_bytes(arr),
            }
        }
        "mined" => {
            let height = mined_height.ok_or(Error::Corrupt("state.mined.height"))?;
            let height = u32::try_from(height).map_err(|_| Error::Corrupt("state.mined.height"))?;
            MigrationTxState::Mined {
                height: BlockHeight::from_u32(height),
            }
        }
        _ => return Err(Error::Corrupt("state")),
    })
}

/// Split a transaction kind into its `(kind, layer, tx_index, crossing)` column values.
pub(crate) fn encode_tx_kind(
    kind: MigrationTxKind,
) -> (&'static str, Option<i64>, Option<i64>, Option<i64>) {
    match kind {
        MigrationTxKind::Preparation { layer, index } => {
            ("preparation", Some(layer as i64), Some(index as i64), None)
        }
        MigrationTxKind::Transfer { crossing } => ("transfer", None, None, Some(crossing as i64)),
    }
}

/// Reassemble a transaction kind from its column values.
pub(crate) fn decode_tx_kind(
    kind: &str,
    layer: Option<i64>,
    tx_index: Option<i64>,
    crossing: Option<i64>,
) -> Result<MigrationTxKind, Error> {
    let to_usize = |v: Option<i64>, field| {
        v.ok_or(Error::Corrupt(field))
            .and_then(|n| usize::try_from(n).map_err(|_| Error::Corrupt(field)))
    };
    Ok(match kind {
        "preparation" => MigrationTxKind::Preparation {
            layer: to_usize(layer, "kind.preparation.layer")?,
            index: to_usize(tx_index, "kind.preparation.index")?,
        },
        "transfer" => MigrationTxKind::Transfer {
            crossing: to_usize(crossing, "kind.transfer.crossing")?,
        },
        _ => return Err(Error::Corrupt("kind")),
    })
}

#[cfg(test)]
mod tests {
    use super::{Error, decode_preparation, encode_preparation};

    use zcash_pool_migration_backend::preparation::{
        PrepInput, PrepOutput, PrepTransaction, PreparationPlan,
    };
    use zcash_protocol::value::Zatoshis;

    /// A representable amount, for terse test fixtures.
    fn zat(n: u64) -> Zatoshis {
        Zatoshis::from_u64(n).expect("valid amount")
    }

    /// A two-layer preparation plan exercising every input tag (Wallet, Prior), every output tag
    /// (Funding, Intermediate, Change), multiple layers, and a direct-funding note.
    fn sample_preparation() -> PreparationPlan {
        let layer0 = vec![PrepTransaction::from_parts(
            vec![PrepInput::Wallet {
                index: 0,
                value: zat(224_321),
            }],
            vec![
                PrepOutput::Intermediate(zat(220_000)),
                PrepOutput::Change(zat(4_321)),
            ],
        )];
        let layer1 = vec![PrepTransaction::from_parts(
            vec![PrepInput::Prior {
                layer: 0,
                transaction: 0,
                output: 0,
                value: zat(220_000),
            }],
            vec![
                PrepOutput::Funding(zat(120_000)),
                PrepOutput::Funding(zat(100_000)),
            ],
        )];
        PreparationPlan::from_parts(vec![layer0, layer1], vec![(2, zat(220_000))])
    }

    /// The two-layer preparation plan round-trips through the internal codec byte-for-byte: every
    /// layer, transaction, tagged input, tagged output, and direct-funding note is preserved.
    #[test]
    fn preparation_plan_round_trips() {
        let plan = sample_preparation();
        let encoded = encode_preparation(&plan);
        let decoded = decode_preparation(&encoded).expect("decodes");
        assert_eq!(decoded, plan);
        assert_eq!(decoded.layers().len(), 2);
        assert_eq!(decoded.direct_funding_notes(), &[(2, zat(220_000))]);

        // A truncated blob and a bad tag are rejected, not silently accepted.
        assert!(matches!(
            decode_preparation(&encoded[..encoded.len() - 1]),
            Err(Error::Corrupt(_))
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_preparation(&trailing),
            Err(Error::Corrupt("preparation.trailing"))
        ));
    }
}
