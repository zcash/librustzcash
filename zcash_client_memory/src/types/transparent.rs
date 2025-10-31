use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Deref, DerefMut},
};

use ::transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};
use transparent::keys::TransparentKeyScope;
use zcash_client_backend::wallet::WalletTransparentOutput;

use zcash_protocol::{TxId, consensus::BlockHeight};

use super::AccountId;
use crate::Error;

/// Stores the transparent outputs received by the wallet.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct TransparentReceivedOutputs(pub(crate) BTreeMap<OutPoint, ReceivedTransparentOutput>);

impl TransparentReceivedOutputs {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    #[cfg(feature = "transparent-inputs")]
    pub fn detect_spending_accounts<'a>(
        &self,
        spent: impl Iterator<Item = &'a OutPoint>,
    ) -> Result<BTreeSet<AccountId>, Error> {
        let mut acc = BTreeSet::new();
        for prevout in spent {
            if let Some(output) = self.0.get(prevout) {
                acc.insert(output.account_id);
            }
        }
        Ok(acc)
    }
}

impl Deref for TransparentReceivedOutputs {
    type Target = BTreeMap<OutPoint, ReceivedTransparentOutput>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TransparentReceivedOutputs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A junction table between received transparent outputs and the transactions that spend them.
#[derive(Debug, Default, PartialEq)]
pub struct TransparentReceivedOutputSpends(pub(crate) BTreeMap<OutPoint, TxId>);

impl TransparentReceivedOutputSpends {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    #[cfg(feature = "transparent-inputs")]
    pub fn get(&self, outpoint: &OutPoint) -> Option<&TxId> {
        self.0.get(outpoint)
    }

    pub fn insert(&mut self, outpoint: OutPoint, txid: TxId) {
        self.0.insert(outpoint, txid);
    }
}

impl Deref for TransparentReceivedOutputSpends {
    type Target = BTreeMap<OutPoint, TxId>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// transparent_received_outputs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedTransparentOutput {
    // Reference to the transaction in which this TXO was created
    pub(crate) transaction_id: TxId,
    // The account that controls spend authority for this TXO
    pub(crate) account_id: AccountId,
    // The address to which this TXO was sent
    pub(crate) address: TransparentAddress,
    // The key scope at which the address was derived
    pub(crate) key_scope: TransparentKeyScope,
    // script, value_zat
    pub(crate) txout: TxOut,
    /// The maximum block height at which this TXO was either
    /// observed to be a member of the UTXO set at the start of the block, or observed
    /// to be an output of a transaction mined in the block. This is intended to be used to
    /// determine when the TXO is no longer a part of the UTXO set, in the case that the
    /// transaction that spends it is not detected by the wallet.
    pub(crate) max_observed_unspent_height: Option<BlockHeight>,
}

impl ReceivedTransparentOutput {
    pub fn new(
        transaction_id: TxId,
        account_id: AccountId,
        address: TransparentAddress,
        key_scope: TransparentKeyScope,
        txout: TxOut,
        max_observed_unspent_height: BlockHeight,
    ) -> Self {
        Self {
            transaction_id,
            account_id,
            address,
            key_scope,
            txout,
            max_observed_unspent_height: Some(max_observed_unspent_height),
        }
    }

    pub fn to_wallet_transparent_output(
        &self,
        outpoint: &OutPoint,
        mined_height: Option<BlockHeight>,
    ) -> Option<WalletTransparentOutput> {
        WalletTransparentOutput::from_parts(outpoint.clone(), self.txout.clone(), mined_height)
    }
}

/// A cache of the relationship between a transaction and the prevout data of its
/// transparent inputs.
///
/// Output may be attempted to be spent in multiple transactions, even though only one will ever be mined
/// which is why can cannot just rely on TransparentReceivedOutputSpends or implement this as as map
#[derive(Debug, Default, PartialEq)]
pub struct TransparentSpendCache(pub(crate) BTreeSet<(TxId, OutPoint)>);

impl TransparentSpendCache {
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Get all the outpoints for a given transaction ID.
    #[cfg(feature = "transparent-inputs")]
    pub fn contains(&self, txid: &TxId, outpoint: &OutPoint) -> bool {
        self.0.contains(&(*txid, outpoint.clone()))
    }
}

impl Deref for TransparentSpendCache {
    type Target = BTreeSet<(TxId, OutPoint)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

mod serialization {
    use super::*;
    use crate::{proto::memwallet as proto, read_optional};
    use transparent::address::Script;
    use zcash_keys::encoding::AddressCodec;
    use zcash_protocol::{consensus::Network::MainNetwork as EncodingParams, value::Zatoshis};

    impl From<ReceivedTransparentOutput> for proto::ReceivedTransparentOutput {
        fn from(output: ReceivedTransparentOutput) -> Self {
            Self {
                transaction_id: output.transaction_id.as_ref().to_vec(),
                account_id: *output.account_id,
                address: output.address.encode(&EncodingParams),
                txout: Some(output.txout.into()),
                max_observed_unspent_height: output.max_observed_unspent_height.map(|h| h.into()),
            }
        }
    }

    // FIXME: Key scope information needs to be added to both `proto::Address` and
    // `proto::ReceivedTransparentOutput`, with a data migration that updates stored data with
    // correct scope information.
    #[allow(unreachable_code)]
    impl TryFrom<proto::ReceivedTransparentOutput> for ReceivedTransparentOutput {
        type Error = crate::Error;

        fn try_from(output: proto::ReceivedTransparentOutput) -> Result<Self, Self::Error> {
            Ok(Self {
                transaction_id: TxId::from_bytes(output.transaction_id.clone().try_into()?),
                account_id: output.account_id.into(),
                address: TransparentAddress::decode(&EncodingParams, &output.address)?,
                key_scope: TransparentKeyScope::custom(u32::MAX).expect("FIXME"),
                txout: read_optional!(output, txout)?.try_into()?,
                max_observed_unspent_height: output.max_observed_unspent_height.map(|h| h.into()),
            })
        }
    }

    impl From<TxOut> for proto::TxOut {
        fn from(txout: TxOut) -> Self {
            Self {
                script: txout.script_pubkey().0.0.clone(),
                value: u64::from(txout.value()),
            }
        }
    }

    impl TryFrom<proto::TxOut> for TxOut {
        type Error = crate::Error;

        fn try_from(txout: proto::TxOut) -> Result<Self, Self::Error> {
            Ok(Self::new(
                Zatoshis::try_from(txout.value)?,
                Script(zcash_script::script::Code(txout.script)),
            ))
        }
    }
}
