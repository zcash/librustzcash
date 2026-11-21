use blake2b_simd::Hash as Blake2bHash;
use corez::io::{self, Write};
use zcash_encoding::CompactSize;

use ::transparent::sighash::TransparentAuthorizingContext;
use zcash_protocol::value::Zatoshis;

use crate::transaction::{
    Authorization, TransactionData, TxId,
    components::transparent::{write_outpoint, write_script},
    sighash::V7SignatureContext,
    sighash_v5::TransparentInputsDigests,
    txid::hasher,
    zip248::BundleVariant,
};

/// The personalization of every [ZIP 248 variant 0] signature digest.
///
/// [ZIP 248 variant 0]: https://zips.z.cash/zip-0248#variant-0-signature-digest
const ZCASH_V7_SIGHASH_PERSONALIZATION: &[u8; 16] = b"ZcashSigHash_v7_";

/// [ZIP 248 §S.1]: the only defined sighash variant.
///
/// [ZIP 248 §S.1]: https://zips.z.cash/zip-0248#signature-digest
const V7_SIGHASH_VARIANT: u8 = 0x00;

/// Writes an input index as the two-byte little-endian encoding that [ZIP 248] uses in
/// every signature context.
///
/// Returns `InvalidInput` if `index` exceeds the two-byte encoding.
///
/// [ZIP 248]: https://zips.z.cash/zip-0248#variant-0-signature-digest
fn write_index<W: Write>(mut writer: W, index: usize) -> corez::io::Result<()> {
    let index = u16::try_from(index)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "signature index exceeds u16"))?;
    writer.write_all(&index.to_le_bytes())
}

/// Writes `value` with a compactSize encoding.
fn write_compact_size<W: Write>(writer: W, value: u64) -> corez::io::Result<()> {
    CompactSize::write(
        writer,
        usize::try_from(value).expect("bundle keys fit in usize"),
    )
}

/// Computes a [ZIP 248 variant 0] signature digest.
///
/// The preimage is `sighashVariant || txid_digest || amounts_sig_digest ||
/// scriptpubkeys_sig_digest || compactSize(bundleType) || compactSize(bundleVariant) ||
/// signature_context`, hashed under the `ZcashSigHash_v7_` personalization. The
/// signature context is the final field, with no length prefix.
///
/// `context` selects the bundle, the signing position within it and the context bytes;
/// see [`V7SignatureContext`]. `txid_digest` is the cached [ZIP 248 §S.2] digest.
/// `inputs_digests` are the [ZIP 248 §S.3] and [§S.4]
/// digests of every transparent input of the transaction, which every signature
/// commits to regardless of its bundle, including the personalized empty-list hashes
/// when the transaction has no transparent inputs.
///
/// [ZIP 248 variant 0]: https://zips.z.cash/zip-0248#variant-0-signature-digest
/// [ZIP 248 §S.2]: https://zips.z.cash/zip-0248#s-2-txid_digest
/// [ZIP 248 §S.3]: https://zips.z.cash/zip-0248#s-3-amounts_sig_digest
/// [§S.4]: https://zips.z.cash/zip-0248#s-4-scriptpubkeys_sig_digest
pub(crate) fn v7_signature_hash_precomputed<
    TA: TransparentAuthorizingContext<Zatoshis>,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    context: &V7SignatureContext<'_>,
    txid_digest: &TxId,
    inputs_digests: &TransparentInputsDigests,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_V7_SIGHASH_PERSONALIZATION);
    h.write_all(&[V7_SIGHASH_VARIANT])
        .expect("writing to a hasher is infallible");
    h.write_all(txid_digest.as_ref())
        .expect("writing to a hasher is infallible");
    h.write_all(inputs_digests.amounts().as_bytes())
        .expect("writing to a hasher is infallible");
    h.write_all(inputs_digests.scripts().as_bytes())
        .expect("writing to a hasher is infallible");

    // S.5 and S.6.
    write_compact_size(&mut h, context.bundle_type().to_u64())
        .expect("bundle types are in CompactSize range");
    write_compact_size(&mut h, BundleVariant::DEFAULT.to_u64())
        .expect("bundle variants are in CompactSize range");

    // A per-input context must name a position that exists, so that its index
    // is the index the signer actually used. Binding contexts have no position.
    #[cfg(feature = "sapling")]
    if let V7SignatureContext::SaplingSpend { index } = context {
        let bundle = tx
            .sapling_bundle()
            .expect("a Sapling Spend context requires a Sapling bundle");
        assert!(
            *index < bundle.shielded_spends().len(),
            "Sapling Spend index {index} is out of range for a bundle of {} spend(s)",
            bundle.shielded_spends().len(),
        );
    }
    #[cfg(feature = "orchard")]
    match context {
        V7SignatureContext::OrchardAction { index } => {
            let bundle = tx
                .orchard_bundle()
                .expect("an Orchard action context requires an Orchard bundle");
            assert!(
                *index < bundle.actions().len(),
                "Orchard action index {index} is out of range for a bundle of {} action(s)",
                bundle.actions().len(),
            );
        }
        V7SignatureContext::IronwoodAction { index } => {
            let bundle = tx
                .ironwood_bundle()
                .expect("an Ironwood action context requires an Ironwood bundle");
            assert!(
                *index < bundle.actions().len(),
                "Ironwood action index {index} is out of range for a bundle of {} action(s)",
                bundle.actions().len(),
            );
        }
        _ => {}
    }

    // S.7.
    if let V7SignatureContext::Transparent(input) = context {
        let txin = &tx
            .transparent_bundle()
            .expect("a transparent context requires a transparent bundle")
            .vin[*input.index()];
        write_outpoint(&mut h, txin.prevout()).expect("writing to a hasher is infallible");
        h.write_all(&input.value().to_i64_le_bytes())
            .expect("writing to a hasher is infallible");
        write_script(&mut h, input.script_pubkey()).expect("writing to a hasher is infallible");
        h.write_all(&txin.sequence().to_le_bytes())
            .expect("writing to a hasher is infallible");
    }
    if let Some(index) = context.index() {
        write_index(&mut h, index).expect("signature index must fit in two bytes");
    }

    h.finalize()
}

/// Computes uncached digests for direct digest-vector tests.
#[cfg(all(test, feature = "sapling", feature = "orchard"))]
pub(crate) fn v7_signature_hash<
    TA: TransparentAuthorizingContext<Zatoshis>,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    context: &V7SignatureContext<'_>,
    txid_parts: &crate::transaction::Zip244Digests<Blake2bHash>,
    inputs_digests: Option<&TransparentInputsDigests>,
) -> Blake2bHash {
    let txid = crate::transaction::txid::to_txid_v7(tx.consensus_branch_id.into(), txid_parts);
    let empty_inputs;
    let inputs_digests = match inputs_digests {
        Some(digests) => digests,
        None => {
            empty_inputs = TransparentInputsDigests::empty();
            &empty_inputs
        }
    };
    v7_signature_hash_precomputed(tx, context, &txid, inputs_digests)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use corez::io::ErrorKind;

    use super::write_index;

    #[test]
    fn signature_index_encoding_checks_the_two_byte_boundary() {
        let mut encoded = Vec::new();
        let last_index = usize::from(u16::MAX);
        write_index(&mut encoded, last_index).unwrap();
        assert_eq!(encoded, u16::MAX.to_le_bytes());

        encoded.clear();
        assert_eq!(
            write_index(&mut encoded, last_index + 1)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput,
        );
        assert!(
            encoded.is_empty(),
            "overflow must not write a truncated index"
        );
    }
}
