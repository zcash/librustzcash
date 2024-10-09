use std::marker::PhantomData;

use zcash_primitives::{
    consensus::BranchId,
    transaction::{
        sighash::{signature_hash, SignableInput},
        txid::TxIdDigester,
        Authorization, Transaction, TransactionData, TxVersion,
    },
};

use crate::{Pczt, V5_TX_VERSION, V5_VERSION_GROUP_ID};

mod orchard;
pub use self::orchard::OrchardError;

mod sapling;
pub use self::sapling::SaplingError;

mod transparent;
pub use self::transparent::TransparentError;

pub struct TransactionExtractor<'a> {
    pczt: Pczt,
    sapling_vk: Option<(
        &'a ::sapling::circuit::SpendVerifyingKey,
        &'a ::sapling::circuit::OutputVerifyingKey,
    )>,
    orchard_vk: Option<&'a ::orchard::circuit::VerifyingKey>,
    _unused: PhantomData<&'a ()>,
}

impl<'a> TransactionExtractor<'a> {
    /// Instantiates the Transaction Extractor role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self {
            pczt,
            sapling_vk: None,
            orchard_vk: None,
            _unused: PhantomData,
        }
    }

    /// Provides the Sapling Spend and Output verifying keys for validating the Sapling
    /// proofs (if any).
    ///
    /// If not provided, and the PCZT has a Sapling bundle, [`Self::extract`] will return
    /// an error.
    pub fn with_sapling(
        mut self,
        spend_vk: &'a ::sapling::circuit::SpendVerifyingKey,
        output_vk: &'a ::sapling::circuit::OutputVerifyingKey,
    ) -> Self {
        self.sapling_vk = Some((spend_vk, output_vk));
        self
    }

    /// Provides an existing Orchard verifying key for validating the Orchard proof (if
    /// any).
    ///
    /// If not provided, and the PCZT has an Orchard bundle, an Orchard verifying key will
    /// be generated on the fly.
    pub fn with_orchard(mut self, orchard_vk: &'a ::orchard::circuit::VerifyingKey) -> Self {
        self.orchard_vk = Some(orchard_vk);
        self
    }

    /// Attempts to extract a valid transaction from the PCZT.
    pub fn extract(self) -> Result<Transaction, Error> {
        let Self {
            pczt,
            sapling_vk,
            orchard_vk,
            _unused,
        } = self;

        let version = match (pczt.global.tx_version, pczt.global.version_group_id) {
            (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxVersion::Zip225),
            (version, version_group_id) => Err(Error::Global(GlobalError::UnsupportedTxVersion {
                version,
                version_group_id,
            })),
        }?;

        let consensus_branch_id = BranchId::try_from(pczt.global.consensus_branch_id)
            .map_err(|_| Error::Global(GlobalError::UnknownConsensusBranchId))?;

        let lock_time = determine_lock_time(&pczt.global, &pczt.transparent.inputs)
            .map_err(|_| Error::IncompatibleLockTimes)?;

        let transparent_bundle =
            transparent::extract_bundle(pczt.transparent).map_err(Error::Transparent)?;
        let sapling_bundle = sapling::extract_bundle(pczt.sapling).map_err(Error::Sapling)?;
        let orchard_bundle = orchard::extract_bundle(pczt.orchard).map_err(Error::Orchard)?;

        let tx_data = TransactionData::<Unbound>::from_parts(
            version,
            consensus_branch_id,
            lock_time,
            pczt.global.expiry_height.into(),
            transparent_bundle,
            None,
            sapling_bundle,
            orchard_bundle,
        );

        // The commitment being signed is shared across all shielded inputs.
        let txid_parts = tx_data.digest(TxIdDigester);
        let shielded_sighash = signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts);

        // Create the binding signatures.
        let tx_data = tx_data.map_authorization(
            transparent::RemoveInputInfo,
            sapling::AddBindingSig {
                sighash: shielded_sighash.as_ref(),
            },
            orchard::AddBindingSig {
                sighash: shielded_sighash.as_ref(),
            },
        );

        let tx = tx_data.freeze().expect("v5 tx can't fail here");

        // Now that we have a supposedly fully-authorized transaction, verify it.
        if let Some(bundle) = tx.sapling_bundle() {
            let (spend_vk, output_vk) = sapling_vk.ok_or(Error::SaplingRequired)?;

            sapling::verify_bundle(bundle, spend_vk, output_vk, *shielded_sighash.as_ref())
                .map_err(Error::Sapling)?;
        }
        if let Some(bundle) = tx.orchard_bundle() {
            orchard::verify_bundle(bundle, orchard_vk, *shielded_sighash.as_ref())
                .map_err(Error::Orchard)?;
        }

        Ok(tx)
    }
}

struct Unbound;

impl Authorization for Unbound {
    type TransparentAuth = transparent::Unbound;
    type SaplingAuth = sapling::Unbound;
    type OrchardAuth = orchard::Unbound;
}

/// Errors that can occur while extracting a transaction from a PCZT.
#[derive(Debug)]
pub enum Error {
    Global(GlobalError),
    IncompatibleLockTimes,
    Orchard(OrchardError),
    Sapling(SaplingError),
    SaplingRequired,
    Transparent(TransparentError),
}

#[derive(Debug)]
pub enum GlobalError {
    UnknownConsensusBranchId,
    UnsupportedTxVersion { version: u32, version_group_id: u32 },
}

/// Determines the lock time for the transaction.
///
/// Implemented following the specification in [BIP 370], with the rationale that this
/// makes integration of PCZTs simpler for codebases that already support PSBTs.
///
/// [BIP 370]: https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time
pub(crate) fn determine_lock_time<L: LockTimeInput>(
    global: &crate::common::Global,
    inputs: &[L],
) -> Result<u32, ()> {
    // The nLockTime field of a transaction is determined by inspecting the
    // `Global.fallback_lock_time` and each input's `required_time_lock_time` and
    // `required_height_lock_time` fields.

    // If one or more inputs have a `required_time_lock_time` or `required_height_lock_time`,
    let have_required_lock_time = inputs.iter().any(|input| {
        input.required_time_lock_time().is_some() || input.required_height_lock_time().is_some()
    });
    // then the field chosen is the one which is supported by all of the inputs. This can
    // be determined by looking at all of the inputs which specify a locktime in either of
    // those fields, and choosing the field which is present in all of those inputs.
    // Inputs not specifying a lock time field can take both types of lock times, as can
    // those that specify both.
    let time_lock_time_unsupported = inputs
        .iter()
        .any(|input| input.required_height_lock_time().is_some());
    let height_lock_time_unsupported = inputs
        .iter()
        .any(|input| input.required_time_lock_time().is_some());

    // The lock time chosen is then the maximum value of the chosen type of lock time.
    match (
        have_required_lock_time,
        time_lock_time_unsupported,
        height_lock_time_unsupported,
    ) {
        (true, true, true) => Err(()),
        (true, false, true) => Ok(inputs
            .iter()
            .filter_map(|input| input.required_time_lock_time())
            .max()
            .expect("iterator is non-empty because have_required_lock_time is true")),
        // If a PSBT has both types of locktimes possible because one or more inputs
        // specify both `required_time_lock_time` and `required_height_lock_time`, then a
        // locktime determined by looking at the `required_height_lock_time` fields of the
        // inputs must be chosen.
        (true, _, false) => Ok(inputs
            .iter()
            .filter_map(|input| input.required_height_lock_time())
            .max()
            .expect("iterator is non-empty because have_required_lock_time is true")),
        // If none of the inputs have a `required_time_lock_time` and
        // `required_height_lock_time`, then `Global.fallback_lock_time` must be used. If
        // `Global.fallback_lock_time` is not provided, then it is assumed to be 0.
        (false, _, _) => Ok(global.fallback_lock_time.unwrap_or(0)),
    }
}

pub(crate) trait LockTimeInput {
    fn required_time_lock_time(&self) -> Option<u32>;
    fn required_height_lock_time(&self) -> Option<u32>;
}

impl LockTimeInput for crate::transparent::Input {
    fn required_time_lock_time(&self) -> Option<u32> {
        self.required_time_lock_time
    }

    fn required_height_lock_time(&self) -> Option<u32> {
        self.required_height_lock_time
    }
}
