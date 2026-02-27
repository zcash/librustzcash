//! Shared utilities for extracting transaction data from a PCZT.

use crate::Pczt;
use crate::common::{Global, determine_lock_time};

use zcash_primitives::transaction::{Authorization, TransactionData, TxVersion};
use zcash_protocol::consensus::BranchId;
use zcash_protocol::constants::{V5_TX_VERSION, V5_VERSION_GROUP_ID};
#[cfg(all(
    any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
    feature = "zip-233"
))]
use zcash_protocol::value::Zatoshis;

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
use blake2b_simd::Hash as Blake2bHash;
#[cfg(any(feature = "io-finalizer", feature = "signer"))]
use zcash_primitives::transaction::{
    TxDigests, sighash::SignableInput, sighash_v5::v5_signature_hash,
};

/// The result of parsing a PCZT and constructing its `TransactionData`.
#[cfg_attr(
    not(any(feature = "io-finalizer", feature = "signer")),
    allow(dead_code)
)]
pub(crate) struct ParsedPczt<A: Authorization> {
    pub(crate) global: Global,
    pub(crate) transparent: transparent::pczt::Bundle,
    pub(crate) sapling: sapling::pczt::Bundle,
    pub(crate) orchard: orchard::pczt::Bundle,
    pub(crate) tx_data: TransactionData<A>,
}

/// Parses a PCZT's bundles and constructs a `TransactionData` using caller-provided
/// bundle extraction closures.
///
/// This handles bundle parsing, version validation, consensus branch ID parsing,
/// lock time computation, and final assembly, delegating bundle extraction to the
/// caller via closures that receive references to the parsed bundles.
pub(crate) fn pczt_to_tx_data<A, E>(
    pczt: Pczt,
    extract_transparent: impl FnOnce(
        &transparent::pczt::Bundle,
    ) -> Result<
        Option<transparent::bundle::Bundle<A::TransparentAuth>>,
        E,
    >,
    extract_sapling: impl FnOnce(
        &sapling::pczt::Bundle,
    ) -> Result<
        Option<sapling::Bundle<A::SaplingAuth, zcash_protocol::value::ZatBalance>>,
        E,
    >,
    extract_orchard: impl FnOnce(
        &orchard::pczt::Bundle,
    ) -> Result<
        Option<orchard::Bundle<A::OrchardAuth, zcash_protocol::value::ZatBalance>>,
        E,
    >,
) -> Result<ParsedPczt<A>, E>
where
    A: Authorization,
    E: From<Error>,
{
    let Pczt {
        global,
        transparent,
        sapling,
        orchard,
    } = pczt;

    let transparent = transparent.into_parsed().map_err(Error::TransparentParse)?;
    let sapling = sapling.into_parsed().map_err(Error::SaplingParse)?;
    let orchard = orchard.into_parsed().map_err(Error::OrchardParse)?;

    let version = match (global.tx_version, global.version_group_id) {
        (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::V5),
        (version, version_group_id) => Err(Error::UnsupportedTxVersion {
            version,
            version_group_id,
        }),
    }?;

    let consensus_branch_id = BranchId::try_from(global.consensus_branch_id)
        .map_err(|_| Error::UnknownConsensusBranchId)?;

    let lock_time =
        determine_lock_time(&global, transparent.inputs()).ok_or(Error::IncompatibleLockTimes)?;

    let transparent_bundle = extract_transparent(&transparent)?;
    let sapling_bundle = extract_sapling(&sapling)?;
    let orchard_bundle = extract_orchard(&orchard)?;

    let tx_data = TransactionData::from_parts(
        version,
        consensus_branch_id,
        lock_time,
        global.expiry_height.into(),
        #[cfg(all(
            any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
            feature = "zip-233"
        ))]
        Zatoshis::ZERO,
        transparent_bundle,
        None,
        sapling_bundle,
        orchard_bundle,
    );

    Ok(ParsedPczt {
        global,
        transparent,
        sapling,
        orchard,
        tx_data,
    })
}

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
pub struct EffectsOnly;

#[cfg(any(feature = "io-finalizer", feature = "signer"))]
impl Authorization for EffectsOnly {
    type TransparentAuth = transparent::bundle::EffectsOnly;
    type SaplingAuth = sapling::bundle::EffectsOnly;
    type OrchardAuth = orchard::bundle::EffectsOnly;
    #[cfg(zcash_unstable = "zfuture")]
    type TzeAuth = core::convert::Infallible;
}

/// Helper to produce the correct sighash for a PCZT.
#[cfg(any(feature = "io-finalizer", feature = "signer"))]
pub(crate) fn sighash(
    tx_data: &TransactionData<EffectsOnly>,
    signable_input: &SignableInput,
    txid_parts: &TxDigests<Blake2bHash>,
) -> [u8; 32] {
    v5_signature_hash(tx_data, signable_input, txid_parts)
        .as_ref()
        .try_into()
        .expect("correct length")
}

/// Errors that can occur while parsing and constructing transaction data from PCZT fields.
#[derive(Debug)]
pub enum Error {
    IncompatibleLockTimes,
    OrchardParse(orchard::pczt::ParseError),
    SaplingParse(sapling::pczt::ParseError),
    TransparentParse(transparent::pczt::ParseError),
    UnknownConsensusBranchId,
    UnsupportedTxVersion { version: u32, version_group_id: u32 },
}
