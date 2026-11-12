//! Full transaction-local validation of version 7 transactions.
//!
//! The byte parser in this module's parent enforces only the ZIP 248 parsing
//! rules and the bundle encodings. This module adds the consensus rules that
//! can be checked from a single transaction, including the registry rules for
//! entries the byte layer retains without interpretation. It then converts
//! every known bundle to its typed representation, which enforces the bundle's
//! domain and canonical field checks, and applies the typed transaction-local
//! consensus rules.

use alloc::format;

use zcash_protocol::consensus::BranchId;

use crate::transaction::{
    Transaction, TxVersion, V7BundleMap, V7ValidationError,
    bytes::{TransactionBytes, V7BundleBytes, V7TransactionBodyBytes},
    zip248::{self, BundleType, BundleVariant},
};

impl TransactionBytes {
    /// Validates a version 7 transaction against the transaction-local
    /// consensus rules of [ZIP 248] and returns its typed representation.
    ///
    /// The byte parser has already enforced the parsing rules. This method
    /// additionally enforces:
    ///
    /// - bundle availability: every `(bundleType, bundleVariant)` in any map is
    ///   registered for version 7 and activated under the transaction's
    ///   consensus branch;
    /// - the registry's prohibited map columns, including the coinbase
    ///   authorizing column and the fee and ZIP 233 NSM effecting and
    ///   authorizing columns;
    /// - a corresponding effecting bundle for every value pool delta entry
    ///   whose bundle type has effecting data;
    /// - authorizing data for a transparent bundle with inputs and for every
    ///   Sapling, Orchard, or Ironwood effecting bundle;
    /// - ZEC-only fee and coinbase value pool deltas, coinbase spend
    ///   restrictions, the Orchard `enableCrossAddress` restriction, fee delta
    ///   signs, the coinbase value pool delta relation, per-asset conservation,
    ///   and the input- and output-side conditions.
    ///
    /// Every known bundle is converted to its typed representation, so the
    /// bundle's domain and canonical field checks (curve points, proofs,
    /// sighash versions, flag bits) are applied. A bundle whose type or
    /// variant is not registered is rejected rather than converted.
    ///
    /// Rules that require block or UTXO context are not checked: the per-block
    /// fee sum, the ZIP 235 NSM fee contribution and the resulting miner fee
    /// available to the coinbase transaction, exactly one coinbase transaction
    /// first in the block, the coinbase bundle's `blockHeight`, `blockSubsidy`
    /// and `lockboxValue` matching the block and issuance schedule, and the
    /// transparent bundle's value pool delta matching its input and output
    /// values.
    ///
    /// # Errors
    ///
    /// Returns [`V7ValidationError::NotV7`] if this is not a version 7
    /// transaction, [`V7ValidationError::UnrecognizedBranchId`] if the encoded
    /// consensus branch ID is not a recognized
    /// [`BranchId`](zcash_protocol::consensus::BranchId),
    /// [`V7ValidationError::NotActivated`] if version 7 is not active under the
    /// encoded consensus branch, and the other [`V7ValidationError`] variants
    /// for the rules listed above.
    ///
    /// [ZIP 248]: https://zips.z.cash/zip-0248
    pub fn validate_v7(&self) -> Result<Transaction, V7ValidationError> {
        if self.version() != TxVersion::V7 {
            return Err(V7ValidationError::NotV7);
        }
        let raw_branch_id = self
            .raw_consensus_branch_id()
            .ok_or(V7ValidationError::NotV7)?;
        let branch_id = BranchId::try_from(raw_branch_id).map_err(|_| {
            V7ValidationError::UnrecognizedBranchId {
                branch_id: raw_branch_id,
            }
        })?;
        if !TxVersion::V7.valid_in_branch(branch_id) {
            return Err(V7ValidationError::NotActivated { branch_id });
        }
        let expiry_height = u32::from(self.expiry_height());
        if expiry_height > zip248::MAX_EXPIRY_HEIGHT {
            return Err(V7ValidationError::InvalidExpiryHeight { expiry_height });
        }
        let body = self.body().as_v7().ok_or(V7ValidationError::NotV7)?;

        check_registry(body)?;
        check_required_effects(body)?;
        check_required_auth(body)?;
        check_fee_and_coinbase_zec(body)?;
        check_coinbase_restrictions(body)?;
        check_orchard_cross_address(body)?;

        let transaction =
            Transaction::from_v7_body_ref(body, branch_id, self.lock_time(), self.expiry_height())
                .map_err(|error| V7ValidationError::InvalidBundle {
                    message: format!("{error}"),
                })?;

        transaction
            .check_v7_consensus_rules()
            .map_err(V7ValidationError::Consensus)?;

        Ok(transaction)
    }
}

/// Checks that every entry in every map names a registered bundle type and
/// variant, and that the entry's map is permitted by the registry.
fn check_registry(body: &V7TransactionBodyBytes) -> Result<(), V7ValidationError> {
    for entry in body.value_pool_deltas() {
        check_registry_entry(
            entry.bundle_type(),
            entry.bundle_variant(),
            V7BundleMap::ValuePoolDeltas,
        )?;
    }
    for bundle in body.bundles() {
        check_registry_entry(
            bundle.bundle_type(),
            bundle.bundle_variant(),
            V7BundleMap::EffectBundles,
        )?;
        if bundle.has_auth() {
            check_registry_entry(
                bundle.bundle_type(),
                bundle.bundle_variant(),
                V7BundleMap::AuthBundles,
            )?;
        }
    }
    Ok(())
}

/// Checks one `(bundleType, bundleVariant)` entry against the registry.
fn check_registry_entry(
    bundle_type: BundleType,
    bundle_variant: BundleVariant,
    map: V7BundleMap,
) -> Result<(), V7ValidationError> {
    if !bundle_type.is_known() {
        return Err(V7ValidationError::UnknownBundleType {
            bundle_type: bundle_type.to_u64(),
        });
    }
    if !bundle_variant.is_known() {
        return Err(V7ValidationError::UnknownBundleVariant {
            bundle_type: bundle_type.to_u64(),
            bundle_variant: bundle_variant.to_u64(),
        });
    }
    let Some(row) = zip248::bundle_registry_row(bundle_type) else {
        return Err(V7ValidationError::UnknownBundleType {
            bundle_type: bundle_type.to_u64(),
        });
    };
    if row.reserved {
        return Err(V7ValidationError::ReservedBundleType {
            bundle_type: bundle_type.to_u64(),
        });
    }
    let permitted = match map {
        V7BundleMap::ValuePoolDeltas => row.value_pool_deltas,
        V7BundleMap::EffectBundles => row.effect_bundles,
        V7BundleMap::AuthBundles => row.auth_bundles,
    };
    if !permitted {
        return Err(V7ValidationError::ProhibitedBundleEntry {
            bundle_type: bundle_type.to_u64(),
            map,
        });
    }
    Ok(())
}

/// Checks that every value pool delta entry whose bundle type has effecting
/// data has a corresponding effecting bundle.
fn check_required_effects(body: &V7TransactionBodyBytes) -> Result<(), V7ValidationError> {
    for entry in body.value_pool_deltas() {
        let bundle_type = entry.bundle_type();
        if !bundle_type.is_known() {
            // The registry check reports the unknown type.
            continue;
        }
        let present = match bundle_type {
            BundleType::TRANSPARENT => body.transparent().is_some(),
            BundleType::COINBASE => body.coinbase().is_some(),
            BundleType::SAPLING => body.sapling().is_some(),
            BundleType::ORCHARD => body.orchard().is_some(),
            BundleType::IRONWOOD => body.ironwood().is_some(),
            BundleType::FEE | BundleType::ZIP233_NSM => true,
            _ => true,
        };
        if !present {
            return Err(V7ValidationError::MissingEffectBundle {
                bundle_type: entry.bundle_type().to_u64(),
            });
        }
    }
    Ok(())
}

/// Checks that every effecting bundle that requires authorizing data has it.
fn check_required_auth(body: &V7TransactionBodyBytes) -> Result<(), V7ValidationError> {
    for bundle in body.bundles() {
        match bundle {
            V7BundleBytes::Transparent(transparent) => {
                let tx_in_count = transparent.effects().inputs().len();
                if tx_in_count > 0 && transparent.auth().is_none() {
                    return Err(V7ValidationError::MissingTransparentAuth { tx_in_count });
                }
            }
            V7BundleBytes::Sapling(sapling)
                if (!sapling.spends().is_empty() || !sapling.outputs().is_empty())
                    && !sapling.has_auth() =>
            {
                return Err(V7ValidationError::MissingShieldedAuth {
                    bundle_type: BundleType::SAPLING.to_u64(),
                });
            }
            V7BundleBytes::Orchard(orchard)
                if !orchard.actions().is_empty() && !orchard.has_auth() =>
            {
                return Err(V7ValidationError::MissingShieldedAuth {
                    bundle_type: BundleType::ORCHARD.to_u64(),
                });
            }
            V7BundleBytes::Ironwood(ironwood)
                if !ironwood.actions().is_empty() && !ironwood.has_auth() =>
            {
                return Err(V7ValidationError::MissingShieldedAuth {
                    bundle_type: BundleType::IRONWOOD.to_u64(),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Checks that fee and coinbase value pool delta entries are denominated in
/// ZEC.
///
/// Other bundle types may carry per-asset deltas; their conservation is
/// checked per asset by the typed consensus rules. The typed consensus check
/// repeats this for directly constructed transaction data; checking it here
/// gives a rule-specific error before conversion and covers bundles whose
/// domain fields are invalid.
fn check_fee_and_coinbase_zec(body: &V7TransactionBodyBytes) -> Result<(), V7ValidationError> {
    for entry in body.value_pool_deltas() {
        let asset_class = match entry.asset_class() {
            crate::transaction::bytes::AssetClass::Zec => continue,
            crate::transaction::bytes::AssetClass::Other(_) => zip248::ASSET_CLASS_OTHER,
        };
        let error = match entry.bundle_type() {
            BundleType::FEE => {
                crate::transaction::V7ConsensusError::FeeAssetClassNotZec { asset_class }
            }
            BundleType::COINBASE => {
                crate::transaction::V7ConsensusError::CoinbaseAssetClassNotZec { asset_class }
            }
            _ => continue,
        };
        return Err(V7ValidationError::Consensus(error));
    }
    Ok(())
}

/// Checks the coinbase spend restrictions at the byte layer.
///
/// The typed consensus check repeats these for directly constructed transaction
/// data; checking them here gives a rule-specific error before conversion and
/// covers bundles whose domain fields are invalid.
fn check_coinbase_restrictions(body: &V7TransactionBodyBytes) -> Result<(), V7ValidationError> {
    if body.coinbase().is_none() {
        return Ok(());
    }

    if let Some(transparent) = body.transparent() {
        let tx_in_count = transparent.effects().inputs().len();
        if tx_in_count > 0 {
            return Err(V7ValidationError::Consensus(
                crate::transaction::V7ConsensusError::CoinbaseTransparentInputs { tx_in_count },
            ));
        }
    }

    if let Some(sapling) = body.sapling() {
        let spend_count = sapling.spends().len();
        if spend_count > 0 {
            return Err(V7ValidationError::Consensus(
                crate::transaction::V7ConsensusError::CoinbaseSaplingSpends { spend_count },
            ));
        }
    }

    /// The `enableSpends` bit of `flagsOrchard`.
    const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;

    for bundle in [body.orchard(), body.ironwood()].into_iter().flatten() {
        if bundle.flags() & FLAG_SPENDS_ENABLED != 0 {
            return Err(V7ValidationError::Consensus(
                crate::transaction::V7ConsensusError::CoinbaseEnableSpendsOrchardSet,
            ));
        }
    }

    Ok(())
}

/// Checks the Orchard `enableCrossAddress` restriction at the byte layer.
///
/// The bit is unrestricted in an Ironwood bundle. Typed conversion also
/// enforces this rule; checking it here gives a rule-specific error before
/// conversion.
fn check_orchard_cross_address(body: &V7TransactionBodyBytes) -> Result<(), V7ValidationError> {
    /// The `enableCrossAddress` bit of `flagsOrchard`.
    const FLAG_CROSS_ADDRESS_ENABLED: u8 = 0b0000_0100;

    if let Some(orchard) = body.orchard()
        && orchard.flags() & FLAG_CROSS_ADDRESS_ENABLED != 0
    {
        return Err(V7ValidationError::Consensus(
            crate::transaction::V7ConsensusError::OrchardEnableCrossAddressSet,
        ));
    }
    Ok(())
}
