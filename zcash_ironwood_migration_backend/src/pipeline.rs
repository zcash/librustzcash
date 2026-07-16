//! The pure PCZT pipeline: prove, sign, finalize, combine, and extract.
//!
//! These operations act on a serialized or in-memory [`pczt::Pczt`] and need only `pczt`, `orchard`,
//! and the spending key; they touch no wallet database or storage. The migration engine builds an
//! unproven PCZT through the wallet backend, then drives it through this pipeline itself, so the
//! proving/signing logic is backend-agnostic.

use std::sync::OnceLock;

use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::TxId;

use crate::error::MigrationError;

/// A serialized, signed PCZT and the transaction id it extracts to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignedPcztOutcome {
    txid: TxId,
    pczt_bytes: Vec<u8>,
}

impl SignedPcztOutcome {
    /// The finalized transaction's id.
    pub(crate) fn txid(&self) -> TxId {
        self.txid
    }

    /// The serialized, proven, and signed PCZT bytes.
    pub(crate) fn pczt_bytes(&self) -> &[u8] {
        &self.pczt_bytes
    }

    /// Consumes this outcome, returning the owned serialized PCZT bytes.
    pub(crate) fn into_pczt_bytes(self) -> Vec<u8> {
        self.pczt_bytes
    }
}

/// The single shared Orchard-family proving key (`PostNu6_3`), used for both the Orchard and
/// Ironwood bundles of a migration PCZT.
///
/// Built once per process (lazily; no on-disk params). Post-NU6.3 is the only regime in which
/// Ironwood exists, and `PostNu6_3` is the sole circuit version that provides the required
/// post-NU6.3 capability and also covers the cross-address-enabled case, so one key serves the
/// Orchard bundle, the Ironwood bundle, and the note-split bundle alike.
pub(crate) fn shielded_proving_key() -> &'static orchard::circuit::ProvingKey {
    static PK: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
    PK.get_or_init(|| {
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3)
    })
}

/// Proves an assembled PCZT: the Orchard bundle, and (when the transaction carries one) the Ironwood
/// bundle. Both are proved with the same `PostNu6_3` key.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if proof generation fails.
pub(crate) fn prove_pczt(pczt: pczt::Pczt) -> Result<pczt::Pczt, MigrationError> {
    let mut prover = pczt::roles::prover::Prover::new(pczt);
    if prover.requires_orchard_proof() {
        prover = prover
            .create_orchard_proof(shielded_proving_key())
            .map_err(|e| MigrationError::Pipeline(format!("orchard proof: {e:?}")))?;
    }
    if prover.requires_ironwood_proof() {
        prover = prover
            .create_ironwood_proof(shielded_proving_key())
            .map_err(|e| MigrationError::Pipeline(format!("ironwood proof: {e:?}")))?;
    }
    Ok(prover.finish())
}

/// Signs every Orchard spend that belongs to the wallet. Action positions are randomized (qleak
/// decoys), so we try every index from 0 upward, terminating on `InvalidIndex` and ignoring
/// wrong-key actions (decoy/padding positions the wallet does not control).
///
/// The Ironwood bundle of a migration transfer is output only (value crosses into Ironwood, so
/// there are no Ironwood spends to authorize), hence `sign_ironwood` is deliberately never called.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if the signer cannot be constructed or a spend fails to
/// sign for a reason other than a wrong key.
pub(crate) fn sign_all_orchard_spends(
    pczt: pczt::Pczt,
    usk: &UnifiedSpendingKey,
) -> Result<pczt::Pczt, MigrationError> {
    let mut signer = pczt::roles::signer::Signer::new(pczt)
        .map_err(|e| MigrationError::Pipeline(format!("pczt signer init: {e:?}")))?;
    let ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());
    for index in 0.. {
        match signer.sign_orchard(index, &ask) {
            Err(pczt::roles::signer::Error::InvalidIndex) => break,
            Ok(())
            | Err(pczt::roles::signer::Error::OrchardSign(
                orchard::pczt::SignerError::WrongSpendAuthorizingKey,
            )) => {}
            Err(e) => return Err(MigrationError::Pipeline(format!("sign orchard: {e:?}"))),
        }
    }
    Ok(signer.finish())
}

/// Proves, signs, finalizes, and serializes an assembled PCZT, returning the serialized PCZT and the
/// finalized transaction id. Shared by the migration transfers and the note split.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if any of proving, signing, spend finalization,
/// serialization, or extraction fails.
pub(crate) fn prove_sign_finalize(
    pczt: pczt::Pczt,
    usk: &UnifiedSpendingKey,
) -> Result<SignedPcztOutcome, MigrationError> {
    let pczt = prove_pczt(pczt)?;
    let pczt = sign_all_orchard_spends(pczt, usk)?;
    let pczt = pczt::roles::spend_finalizer::SpendFinalizer::new(pczt)
        .finalize_spends()
        .map_err(|e| MigrationError::Pipeline(format!("finalize spends: {e:?}")))?;
    // `serialize` and `TransactionExtractor::new` both consume the PCZT, so clone before serializing
    // and extract from the original (the extractor verifies proofs, signatures, and the binding sig).
    let pczt_bytes = pczt
        .clone()
        .serialize()
        .map_err(|e| MigrationError::Pipeline(format!("serialize pczt: {e:?}")))?;
    let tx = pczt::roles::tx_extractor::TransactionExtractor::new(pczt)
        .extract()
        .map_err(|e| MigrationError::Pipeline(format!("extract tx: {e:?}")))?;
    Ok(SignedPcztOutcome {
        txid: tx.txid(),
        pczt_bytes,
    })
}

/// Merges an externally produced signature PCZT into a staged (proven, unsigned) original,
/// finalizes, and extracts: the external-signer counterpart of the signing tail of
/// [`prove_sign_finalize`].
///
/// The combine step rejects any effecting-data mismatch between the two PCZTs, so a signed PCZT that
/// does not correspond to the staged original cannot be stored; extraction then verifies the proofs
/// and every signature before the broadcastable form is returned.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if either PCZT cannot be parsed, if combining or spend
/// finalization fails, or if serialization/extraction fails.
pub(crate) fn combine_signed_pczt(
    proven: &[u8],
    signed: &[u8],
) -> Result<SignedPcztOutcome, MigrationError> {
    let proven = pczt::Pczt::parse(proven)
        .map_err(|e| MigrationError::Pipeline(format!("parse staged pczt: {e:?}")))?;
    let signed = pczt::Pczt::parse(signed)
        .map_err(|e| MigrationError::Pipeline(format!("parse signed pczt: {e:?}")))?;
    let combined = pczt::roles::combiner::Combiner::new(vec![proven, signed])
        .combine()
        .map_err(|e| MigrationError::Pipeline(format!("combine signed pczt: {e:?}")))?;
    let finalized = pczt::roles::spend_finalizer::SpendFinalizer::new(combined)
        .finalize_spends()
        .map_err(|e| MigrationError::Pipeline(format!("finalize spends: {e:?}")))?;
    let pczt_bytes = finalized
        .clone()
        .serialize()
        .map_err(|e| MigrationError::Pipeline(format!("serialize pczt: {e:?}")))?;
    let tx = pczt::roles::tx_extractor::TransactionExtractor::new(finalized)
        .extract()
        .map_err(|e| MigrationError::Pipeline(format!("extract tx: {e:?}")))?;
    Ok(SignedPcztOutcome {
        txid: tx.txid(),
        pczt_bytes,
    })
}

/// Extracts the broadcast-ready consensus transaction bytes from a serialized signed PCZT. The
/// platform calls this immediately before broadcasting.
///
/// # Errors
///
/// Returns [`MigrationError::Pipeline`] if the PCZT cannot be parsed, extracted, or the transaction
/// cannot be encoded.
pub(crate) fn extract_broadcast_tx(pczt_bytes: &[u8]) -> Result<Vec<u8>, MigrationError> {
    let pczt = pczt::Pczt::parse(pczt_bytes)
        .map_err(|e| MigrationError::Pipeline(format!("parse pczt: {e:?}")))?;
    let tx = pczt::roles::tx_extractor::TransactionExtractor::new(pczt)
        .extract()
        .map_err(|e| MigrationError::Pipeline(format!("extract tx: {e:?}")))?;
    let mut bytes = Vec::new();
    tx.write(&mut bytes)
        .map_err(|e| MigrationError::Pipeline(format!("encode tx: {e}")))?;
    Ok(bytes)
}
