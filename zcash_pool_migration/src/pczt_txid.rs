//! Derivation of a migration transaction's [`TxId`] from its stored PCZT.
//!
//! A migration transaction's txid exists from the moment the PCZT is PREPARED — before it is
//! signed, let alone proved — and never moves afterwards. That ordering is not a convenience: the
//! txid has to be computed in order to derive the signature hash, so producing one is a
//! prerequisite of signing rather than a consequence of it. Everything that happens later is
//! AUTHORIZING data — the signatures, and the anchor and spend witnesses ZIP 374 defers to
//! proving — and none of it enters the effecting data the txid digest covers. A transaction whose
//! id moved under proving would carry a signature over the wrong id, and no node would accept it.
//!
//! So the id of the transaction a consumer will eventually broadcast is knowable long before it
//! is broadcast, and knowable again afterwards from the same stored bytes. That is what
//! [`advance_migration`] uses to recognize a transaction the wallet has seen mine even when the
//! consumer never recorded broadcasting it — a crash, or a failed persist, between submitting to
//! a node and calling [`MigrationState::mark_broadcast`].
//!
//! Costs one PCZT parse and the txid digests; nothing here touches proofs, so it is available
//! under the `signer` feature alone.
//!
//! [`advance_migration`]: crate::satisfiability::advance_migration
//! [`MigrationState::mark_broadcast`]: crate::engine::MigrationState::mark_broadcast

use core::fmt;

use pczt::Pczt;
use zcash_primitives::transaction::txid::{TxIdDigester, to_txid};
use zcash_protocol::TxId;

/// A stored PCZT whose transaction id cannot be derived.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxIdError {
    /// The bytes do not parse as a PCZT.
    Parse,
    /// The PCZT parses, but its effects cannot be assembled into transaction data — a bundle is
    /// malformed, or a field the txid commits to is absent.
    Effects,
}

impl fmt::Display for TxIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxIdError::Parse => f.write_str("the stored bytes do not parse as a PCZT"),
            TxIdError::Effects => {
                f.write_str("the PCZT's effects do not assemble into transaction data")
            }
        }
    }
}

impl core::error::Error for TxIdError {}

/// The [`TxId`] of the transaction `pczt` describes.
///
/// Answerable as soon as the PCZT is prepared, and stable from there (see the module docs): an
/// unsigned PCZT, the signed PCZT it becomes, and the proven PCZT after that all yield the same
/// answer — the id the transaction carries once broadcast and mined.
pub fn pczt_txid(pczt: &Pczt) -> Result<TxId, TxIdError> {
    // `into_effects` consumes the PCZT, and callers hold stored bytes they may still need; the
    // clone is one parse's worth of owned data, not a proof-sized copy.
    let tx_data = pczt
        .clone()
        .into_effects()
        .map_err(|_| TxIdError::Effects)?;
    let digests = tx_data.digest(TxIdDigester);
    Ok(to_txid(
        tx_data.version(),
        tx_data.consensus_branch_id(),
        &digests,
    ))
}

/// [`pczt_txid`] over stored PCZT bytes, parsing them first.
pub fn stored_pczt_txid(bytes: &[u8]) -> Result<TxId, TxIdError> {
    let pczt = Pczt::parse(bytes).map_err(|_| TxIdError::Parse)?;
    pczt_txid(&pczt)
}
