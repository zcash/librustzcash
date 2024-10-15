//! Structs for building transactions.

use std::cmp::Ordering;
use std::error;
use std::fmt;
use std::sync::mpsc::Sender;

use rand::{CryptoRng, RngCore};

use crate::{
    consensus::{self, BlockHeight, BranchId, NetworkUpgrade},
    legacy::TransparentAddress,
    memo::MemoBytes,
    sapling::{
        self,
        builder::SaplingMetadata,
        prover::{OutputProver, SpendProver},
        Note, PaymentAddress,
    },
    transaction::{
        components::{
            amount::{Amount, BalanceError, NonNegativeAmount},
            sapling::zip212_enforcement,
            transparent::{self, builder::TransparentBuilder, TxOut},
        },
        fees::FeeRule,
        sighash::{signature_hash, SignableInput},
        txid::TxIdDigester,
        Transaction, TransactionData, TxVersion, Unauthorized,
    },
};

use orchard::builder::BundleType;
use orchard::note::AssetBase;
use orchard::orchard_flavor::OrchardVanilla;
use orchard::Address;

#[cfg(feature = "transparent-inputs")]
use crate::transaction::components::transparent::builder::TransparentInputInfo;

#[cfg(not(feature = "transparent-inputs"))]
use std::convert::Infallible;

#[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
use orchard::{
    issuance,
    issuance::{IssueBundle, IssueInfo},
    keys::{IssuanceAuthorizingKey, IssuanceValidatingKey},
    orchard_flavor::OrchardZSA,
};
#[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
use rand_core::OsRng;

#[cfg(zcash_unstable = "zfuture")]
use crate::{
    extensions::transparent::{ExtensionTxBuilder, ToPayload},
    transaction::{
        components::{
            tze::builder::TzeBuilder,
            tze::{self, TzeOut},
        },
        fees::FutureFeeRule,
    },
};

/// Since Blossom activation, the default transaction expiry delta should be 40 blocks.
/// <https://zips.z.cash/zip-0203#changes-for-blossom>
const DEFAULT_TX_EXPIRY_DELTA: u32 = 40;

/// Errors that can occur during fee calculation.
#[derive(Debug)]
pub enum FeeError<FE> {
    FeeRule(FE),
    Bundle(&'static str),
}

impl<FE: fmt::Display> fmt::Display for FeeError<FE> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FeeError::FeeRule(e) => write!(f, "An error occurred in fee calculation: {}", e),
            FeeError::Bundle(b) => write!(f, "Bundle structure invalid in fee calculation: {}", b),
        }
    }
}

/// Errors that can occur during transaction construction.
#[derive(Debug)]
pub enum Error<FE> {
    /// Insufficient funds were provided to the transaction builder; the given
    /// additional amount is required in order to construct the transaction.
    InsufficientFunds(Amount),
    /// The transaction has inputs in excess of outputs and fees; the user must
    /// add a change output.
    ChangeRequired(Amount),
    /// An error occurred in computing the fees for a transaction.
    Fee(FeeError<FE>),
    /// An overflow or underflow occurred when computing value balances
    Balance(BalanceError),
    /// An error occurred in constructing the transparent parts of a transaction.
    TransparentBuild(transparent::builder::Error),
    /// An error occurred in constructing the Sapling parts of a transaction.
    SaplingBuild(sapling::builder::Error),
    /// An error occurred in constructing the Orchard parts of a transaction.
    OrchardBuild(orchard::builder::BuildError),
    /// An error occurred in adding an Orchard Spend to a transaction.
    OrchardSpend(orchard::builder::SpendError),
    /// An error occurred in adding an Orchard Output to a transaction.
    OrchardRecipient(orchard::builder::OutputError),
    /// The builder was constructed without support for the Sapling pool, but a Sapling
    /// spend or output was added.
    SaplingBuilderNotAvailable,
    /// The builder was constructed with a target height before NU5 activation, but an Orchard
    /// spend or output was added.
    OrchardBundleNotAvailable,
    /// The issuance bundle not initialized.
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    IssuanceBuilderNotAvailable,
    /// An error occurred in constructing the Issuance bundle.
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    IssuanceBundle(issuance::Error),
    /// Issuance bundle already initialized.
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    IssuanceBundleAlreadyInitialized,
    /// An error occurred in constructing the TZE parts of a transaction.
    #[cfg(zcash_unstable = "zfuture")]
    TzeBuild(tze::builder::Error),
}

impl<FE: fmt::Display> fmt::Display for Error<FE> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InsufficientFunds(amount) => write!(
                f,
                "Insufficient funds for transaction construction; need an additional {:?} zatoshis",
                amount
            ),
            Error::ChangeRequired(amount) => write!(
                f,
                "The transaction requires an additional change output of {:?} zatoshis",
                amount
            ),
            Error::Balance(e) => write!(f, "Invalid amount {:?}", e),
            Error::Fee(e) => write!(f, "An error occurred in fee calculation: {}", e),
            Error::TransparentBuild(err) => err.fmt(f),
            Error::SaplingBuild(err) => err.fmt(f),
            Error::OrchardBuild(err) => write!(f, "{:?}", err),
            Error::OrchardSpend(err) => write!(f, "Could not add Orchard spend: {}", err),
            Error::OrchardRecipient(err) => write!(f, "Could not add Orchard recipient: {}", err),
            Error::SaplingBuilderNotAvailable => write!(
                f,
                "Cannot create Sapling transactions without a Sapling anchor"
            ),
            Error::OrchardBundleNotAvailable => write!(
                f,
                "The builder was constructed with a target height before NU5 activation, but an Orchard spend or output was added"
            ),
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            Error::IssuanceBuilderNotAvailable => write!(
                f,
                "Issuance bundle not initialized"
            ),
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            Error::IssuanceBundle(err) => write!(f, "{:?}", err),
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            Error::IssuanceBundleAlreadyInitialized => write!(
                f,
                "Issuance bundle already initialized"
            ),
            #[cfg(zcash_unstable = "zfuture")]
            Error::TzeBuild(err) => err.fmt(f),
        }
    }
}

impl<FE: fmt::Debug + fmt::Display> error::Error for Error<FE> {}

impl<FE> From<BalanceError> for Error<FE> {
    fn from(e: BalanceError) -> Self {
        Error::Balance(e)
    }
}

impl<FE> From<FeeError<FE>> for Error<FE> {
    fn from(e: FeeError<FE>) -> Self {
        Error::Fee(e)
    }
}

impl<FE> From<sapling::builder::Error> for Error<FE> {
    fn from(e: sapling::builder::Error) -> Self {
        Error::SaplingBuild(e)
    }
}

impl<FE> From<orchard::builder::SpendError> for Error<FE> {
    fn from(e: orchard::builder::SpendError) -> Self {
        Error::OrchardSpend(e)
    }
}

/// Reports on the progress made by the builder towards building a transaction.
pub struct Progress {
    /// The number of steps completed.
    cur: u32,
    /// The expected total number of steps (as of this progress update), if known.
    end: Option<u32>,
}

impl From<(u32, u32)> for Progress {
    fn from((cur, end): (u32, u32)) -> Self {
        Self {
            cur,
            end: Some(end),
        }
    }
}

impl Progress {
    /// Returns the number of steps completed so far while building the transaction.
    ///
    /// Note that each step may not be of the same complexity/duration.
    pub fn cur(&self) -> u32 {
        self.cur
    }

    /// Returns the total expected number of steps before this transaction will be ready,
    /// or `None` if the end is unknown as of this progress update.
    ///
    /// Note that each step may not be of the same complexity/duration.
    pub fn end(&self) -> Option<u32> {
        self.end
    }
}

/// Rules for how the builder should be configured for each shielded pool.
#[derive(Clone, Copy)]
pub enum BuildConfig {
    Standard {
        sapling_anchor: Option<sapling::Anchor>,
        orchard_anchor: Option<orchard::Anchor>,
    },
    Zsa {
        sapling_anchor: Option<sapling::Anchor>,
        orchard_anchor: Option<orchard::Anchor>,
    },
    Coinbase,
}

impl BuildConfig {
    /// Returns the Sapling bundle type and anchor for this configuration.
    pub fn sapling_builder_config(
        &self,
    ) -> Option<(sapling::builder::BundleType, sapling::Anchor)> {
        match self {
            BuildConfig::Standard { sapling_anchor, .. }
            | BuildConfig::Zsa { sapling_anchor, .. } => sapling_anchor
                .as_ref()
                .map(|a| (sapling::builder::BundleType::DEFAULT, *a)),
            BuildConfig::Coinbase => Some((
                sapling::builder::BundleType::Coinbase,
                sapling::Anchor::empty_tree(),
            )),
        }
    }

    /// Returns the Orchard bundle type and anchor for this configuration.
    pub fn orchard_builder_config(&self) -> Option<(BundleType, orchard::Anchor)> {
        match self {
            BuildConfig::Standard { orchard_anchor, .. } => orchard_anchor
                .as_ref()
                .map(|a| (BundleType::DEFAULT_VANILLA, *a)),
            BuildConfig::Zsa { orchard_anchor, .. } => orchard_anchor
                .as_ref()
                .map(|a| (BundleType::DEFAULT_ZSA, *a)),
            BuildConfig::Coinbase => Some((BundleType::Coinbase, orchard::Anchor::empty_tree())),
        }
    }

    pub fn orchard_bundle_type<FE>(&self) -> Result<BundleType, Error<FE>> {
        let (bundle_type, _) = self
            .orchard_builder_config()
            .ok_or(Error::OrchardBundleNotAvailable)?;
        Ok(bundle_type)
    }
}

/// The result of a transaction build operation, which includes the resulting transaction along
/// with metadata describing how spends and outputs were shuffled in creating the transaction's
/// shielded bundles.
#[derive(Debug)]
pub struct BuildResult {
    transaction: Transaction,
    sapling_meta: SaplingMetadata,
    orchard_meta: orchard::builder::BundleMetadata,
}

impl BuildResult {
    /// Returns the transaction that was constructed by the builder.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Returns the mapping from Sapling inputs and outputs to their randomized positions in the
    /// Sapling bundle in the newly constructed transaction.
    pub fn sapling_meta(&self) -> &SaplingMetadata {
        &self.sapling_meta
    }

    /// Returns the mapping from Orchard inputs and outputs to the randomized positions of the
    /// Actions that contain them in the Orchard bundle in the newly constructed transaction.
    pub fn orchard_meta(&self) -> &orchard::builder::BundleMetadata {
        &self.orchard_meta
    }

    /// Creates the transaction that was constructed by the builder.
    pub fn into_transaction(self) -> Transaction {
        self.transaction
    }
}

/// Generates a [`Transaction`] from its inputs and outputs.
pub struct Builder<'a, P, U: sapling::builder::ProverProgress> {
    params: P,
    build_config: BuildConfig,
    target_height: BlockHeight,
    expiry_height: BlockHeight,
    transparent_builder: TransparentBuilder,
    sapling_builder: Option<sapling::builder::Builder>,
    orchard_builder: Option<orchard::builder::Builder>,
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    issuance_builder: Option<IssueBundle<issuance::Unauthorized>>,
    // TODO: In the future, instead of taking the spending keys as arguments when calling
    // `add_sapling_spend` or `add_orchard_spend`, we will build an unauthorized, unproven
    // transaction, and then the caller will be responsible for using the spending keys or their
    // derivatives for proving and signing to complete transaction creation.
    sapling_asks: Vec<sapling::keys::SpendAuthorizingKey>,
    orchard_saks: Vec<orchard::keys::SpendAuthorizingKey>,
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    issuance_isk: Option<orchard::keys::IssuanceAuthorizingKey>,
    #[cfg(zcash_unstable = "zfuture")]
    tze_builder: TzeBuilder<'a, TransactionData<Unauthorized>>,
    #[cfg(not(zcash_unstable = "zfuture"))]
    tze_builder: std::marker::PhantomData<&'a ()>,
    progress_notifier: U,
}

impl<'a, P, U: sapling::builder::ProverProgress> Builder<'a, P, U> {
    /// Returns the network parameters that the builder has been configured for.
    pub fn params(&self) -> &P {
        &self.params
    }

    /// Returns the target height of the transaction under construction.
    pub fn target_height(&self) -> BlockHeight {
        self.target_height
    }

    /// Returns the set of transparent inputs currently committed to be consumed
    /// by the transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent_inputs(&self) -> &[TransparentInputInfo] {
        self.transparent_builder.inputs()
    }

    /// Returns the set of transparent outputs currently set to be produced by
    /// the transaction.
    pub fn transparent_outputs(&self) -> &[TxOut] {
        self.transparent_builder.outputs()
    }

    /// Returns the set of Sapling inputs currently committed to be consumed
    /// by the transaction.
    pub fn sapling_inputs(&self) -> &[sapling::builder::SpendInfo] {
        self.sapling_builder
            .as_ref()
            .map_or_else(|| &[][..], |b| b.inputs())
    }

    /// Returns the set of Sapling outputs currently set to be produced by
    /// the transaction.
    pub fn sapling_outputs(&self) -> &[sapling::builder::OutputInfo] {
        self.sapling_builder
            .as_ref()
            .map_or_else(|| &[][..], |b| b.outputs())
    }
}

impl<'a, P: consensus::Parameters> Builder<'a, P, ()> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height,
    /// using default values for general transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    pub fn new(params: P, target_height: BlockHeight, build_config: BuildConfig) -> Self {
        let orchard_builder = if params.is_nu_active(NetworkUpgrade::Nu5, target_height) {
            build_config
                .orchard_builder_config()
                .map(|(bundle_type, anchor)| orchard::builder::Builder::new(bundle_type, anchor))
        } else {
            None
        };

        let sapling_builder = build_config
            .sapling_builder_config()
            .map(|(bundle_type, anchor)| {
                sapling::builder::Builder::new(
                    zip212_enforcement(&params, target_height),
                    bundle_type,
                    anchor,
                )
            });

        Builder {
            params,
            build_config,
            target_height,
            expiry_height: target_height + DEFAULT_TX_EXPIRY_DELTA,
            transparent_builder: TransparentBuilder::empty(),
            sapling_builder,
            orchard_builder,
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            issuance_builder: None,
            sapling_asks: vec![],
            orchard_saks: Vec::new(),
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            issuance_isk: None,
            #[cfg(zcash_unstable = "zfuture")]
            tze_builder: TzeBuilder::empty(),
            #[cfg(not(zcash_unstable = "zfuture"))]
            tze_builder: std::marker::PhantomData,
            progress_notifier: (),
        }
    }

    /// Sets the notifier channel, where progress of building the transaction is sent.
    ///
    /// An update is sent after every Sapling Spend or Output is computed, and the `u32`
    /// sent represents the total steps completed so far. It will eventually send number
    /// of spends + outputs. If there's an error building the transaction, the channel is
    /// closed.
    pub fn with_progress_notifier(
        self,
        progress_notifier: Sender<Progress>,
    ) -> Builder<'a, P, Sender<Progress>> {
        Builder {
            params: self.params,
            build_config: self.build_config,
            target_height: self.target_height,
            expiry_height: self.expiry_height,
            transparent_builder: self.transparent_builder,
            sapling_builder: self.sapling_builder,
            orchard_builder: self.orchard_builder,
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            issuance_builder: self.issuance_builder,
            sapling_asks: self.sapling_asks,
            orchard_saks: self.orchard_saks,
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            issuance_isk: self.issuance_isk,
            tze_builder: self.tze_builder,
            progress_notifier,
        }
    }

    /// Creates IssuanceBundle and adds an Issuance action to the transaction.
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    pub fn init_issuance_bundle<FE>(
        &mut self,
        ik: IssuanceAuthorizingKey,
        asset_desc: Vec<u8>,
        issue_info: Option<IssueInfo>,
    ) -> Result<(), Error<FE>> {
        assert!(self.build_config.orchard_bundle_type()? == BundleType::DEFAULT_ZSA);

        if self.issuance_builder.is_some() {
            return Err(Error::IssuanceBundleAlreadyInitialized);
        }

        self.issuance_builder = Some(
            IssueBundle::new(
                IssuanceValidatingKey::from(&ik),
                asset_desc,
                issue_info,
                OsRng,
            )
            .map_err(Error::IssuanceBundle)?
            .0,
        );
        self.issuance_isk = Some(ik);

        Ok(())
    }

    /// Adds an Issuance action to the transaction.
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    pub fn add_recipient<FE>(
        &mut self,
        asset_desc: &[u8],
        recipient: Address,
        value: orchard::value::NoteValue,
    ) -> Result<(), Error<FE>> {
        assert!(self.build_config.orchard_bundle_type()? == BundleType::DEFAULT_ZSA);
        self.issuance_builder
            .as_mut()
            .ok_or(Error::IssuanceBuilderNotAvailable)?
            .add_recipient(asset_desc, recipient, value, OsRng)
            .map_err(Error::IssuanceBundle)?;

        Ok(())
    }

    /// Finalizes a given asset
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    pub fn finalize_asset<FE>(&mut self, asset_desc: &[u8]) -> Result<(), Error<FE>> {
        assert!(self.build_config.orchard_bundle_type()? == BundleType::DEFAULT_ZSA);
        self.issuance_builder
            .as_mut()
            .ok_or(Error::IssuanceBuilderNotAvailable)?
            .finalize_action(asset_desc)
            .map_err(Error::IssuanceBundle)?;

        Ok(())
    }

    /// Adds a Burn action to the transaction.
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    pub fn add_burn<FE>(&mut self, value: u64, asset: AssetBase) -> Result<(), Error<FE>> {
        assert!(self.build_config.orchard_bundle_type()? == BundleType::DEFAULT_ZSA);
        self.orchard_builder
            .as_mut()
            .ok_or(Error::OrchardBundleNotAvailable)?
            .add_burn(asset, orchard::value::NoteValue::from_raw(value))
            .map_err(Error::OrchardBuild)?;

        Ok(())
    }
}

impl<'a, P: consensus::Parameters, U: sapling::builder::ProverProgress> Builder<'a, P, U> {
    /// Adds an Orchard note to be spent in this bundle.
    ///
    /// Returns an error if the given Merkle path does not have the required anchor for
    /// the given note.
    pub fn add_orchard_spend<FE>(
        &mut self,
        sk: &orchard::keys::SpendingKey,
        note: orchard::Note,
        merkle_path: orchard::tree::MerklePath,
    ) -> Result<(), Error<FE>> {
        let bundle_type = self.build_config.orchard_bundle_type()?;
        if bundle_type == BundleType::DEFAULT_VANILLA {
            assert!(bool::from(note.asset().is_native()));
        }
        self.orchard_builder
            .as_mut()
            .ok_or(Error::OrchardBundleNotAvailable)?
            .add_spend(orchard::keys::FullViewingKey::from(sk), note, merkle_path)
            .map_err(Error::OrchardSpend)?;

        self.orchard_saks
            .push(orchard::keys::SpendAuthorizingKey::from(sk));

        Ok(())
    }

    /// Adds an Orchard recipient to the transaction.
    pub fn add_orchard_output<FE>(
        &mut self,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: Address,
        value: u64,
        asset: AssetBase,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        let bundle_type = self.build_config.orchard_bundle_type()?;
        if bundle_type == BundleType::DEFAULT_VANILLA {
            assert!(bool::from(asset.is_native()));
        }
        self.orchard_builder
            .as_mut()
            .ok_or(Error::OrchardBundleNotAvailable)?
            .add_output(
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value),
                asset,
                Some(*memo.as_array()),
            )
            .map_err(Error::OrchardRecipient)
    }

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_sapling_spend<FE>(
        &mut self,
        extsk: &sapling::zip32::ExtendedSpendingKey,
        note: Note,
        merkle_path: sapling::MerklePath,
    ) -> Result<(), Error<FE>> {
        if let Some(builder) = self.sapling_builder.as_mut() {
            builder.add_spend(extsk, note, merkle_path)?;

            self.sapling_asks.push(extsk.expsk.ask.clone());
            Ok(())
        } else {
            Err(Error::SaplingBuilderNotAvailable)
        }
    }

    /// Adds a Sapling address to send funds to.
    pub fn add_sapling_output<FE>(
        &mut self,
        ovk: Option<sapling::keys::OutgoingViewingKey>,
        to: PaymentAddress,
        value: NonNegativeAmount,
        memo: MemoBytes,
    ) -> Result<(), Error<FE>> {
        self.sapling_builder
            .as_mut()
            .ok_or(Error::SaplingBuilderNotAvailable)?
            .add_output(
                ovk,
                to,
                sapling::value::NoteValue::from_raw(value.into()),
                Some(*memo.as_array()),
            )
            .map_err(Error::SaplingBuild)
    }

    /// Adds a transparent coin to be spent in this transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_transparent_input(
        &mut self,
        sk: secp256k1::SecretKey,
        utxo: transparent::OutPoint,
        coin: TxOut,
    ) -> Result<(), transparent::builder::Error> {
        self.transparent_builder.add_input(sk, utxo, coin)
    }

    /// Adds a transparent address to send funds to.
    pub fn add_transparent_output(
        &mut self,
        to: &TransparentAddress,
        value: NonNegativeAmount,
    ) -> Result<(), transparent::builder::Error> {
        self.transparent_builder.add_output(to, value)
    }

    /// Returns the sum of the transparent, Sapling, Orchard, and TZE value balances.
    fn value_balance(&self) -> Result<Amount, BalanceError> {
        let value_balances = [
            self.transparent_builder.value_balance()?,
            self.sapling_builder
                .as_ref()
                .map_or_else(Amount::zero, |builder| builder.value_balance::<Amount>()),
            self.orchard_builder.as_ref().map_or_else(
                || Ok(Amount::zero()),
                |builder| {
                    builder
                        .value_balance::<Amount>()
                        .map_err(|_| BalanceError::Overflow)
                },
            )?,
            #[cfg(zcash_unstable = "zfuture")]
            self.tze_builder.value_balance()?,
        ];

        value_balances
            .into_iter()
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)
    }

    /// Reports the calculated fee given the specified fee rule.
    ///
    /// This fee is a function of the spends and outputs that have been added to the builder,
    /// pursuant to the specified [`FeeRule`].
    pub fn get_fee<FR: FeeRule>(
        &self,
        fee_rule: &FR,
    ) -> Result<NonNegativeAmount, FeeError<FR::Error>> {
        #[cfg(feature = "transparent-inputs")]
        let transparent_inputs = self.transparent_builder.inputs();

        #[cfg(not(feature = "transparent-inputs"))]
        let transparent_inputs: &[Infallible] = &[];

        let sapling_spends = self
            .sapling_builder
            .as_ref()
            .map_or(0, |builder| builder.inputs().len());

        fee_rule
            .fee_required(
                &self.params,
                self.target_height,
                transparent_inputs,
                self.transparent_builder.outputs(),
                sapling_spends,
                self.sapling_builder
                    .as_ref()
                    .zip(self.build_config.sapling_builder_config())
                    .map_or(Ok(0), |(builder, (bundle_type, _))| {
                        bundle_type
                            .num_outputs(sapling_spends, builder.outputs().len())
                            .map_err(FeeError::Bundle)
                    })?,
                self.orchard_builder
                    .as_ref()
                    .zip(self.build_config.orchard_builder_config())
                    .map_or(Ok(0), |(builder, (bundle_type, _))| {
                        bundle_type
                            .num_actions(builder.spends().len(), builder.outputs().len())
                            .map_err(FeeError::Bundle)
                    })?,
            )
            .map_err(FeeError::FeeRule)
    }

    #[cfg(zcash_unstable = "zfuture")]
    pub fn get_fee_zfuture<FR: FeeRule + FutureFeeRule>(
        &self,
        fee_rule: &FR,
    ) -> Result<NonNegativeAmount, FeeError<FR::Error>> {
        #[cfg(feature = "transparent-inputs")]
        let transparent_inputs = self.transparent_builder.inputs();

        #[cfg(not(feature = "transparent-inputs"))]
        let transparent_inputs: &[Infallible] = &[];

        let sapling_spends = self
            .sapling_builder
            .as_ref()
            .map_or(0, |builder| builder.inputs().len());

        fee_rule
            .fee_required_zfuture(
                &self.params,
                self.target_height,
                transparent_inputs,
                self.transparent_builder.outputs(),
                sapling_spends,
                self.sapling_builder
                    .as_ref()
                    .zip(self.build_config.sapling_builder_config())
                    .map_or(Ok(0), |(builder, (bundle_type, _))| {
                        bundle_type
                            .num_outputs(sapling_spends, builder.outputs().len())
                            .map_err(FeeError::Bundle)
                    })?,
                self.orchard_builder
                    .as_ref()
                    .zip(self.build_config.orchard_builder_config())
                    .map_or(Ok(0), |(builder, (bundle_type, _))| {
                        bundle_type
                            .num_actions(builder.spends().len(), builder.outputs().len())
                            .map_err(FeeError::Bundle)
                    })?,
                self.tze_builder.inputs(),
                self.tze_builder.outputs(),
            )
            .map_err(FeeError::FeeRule)
    }

    /// Builds a transaction from the configured spends and outputs.
    ///
    /// Upon success, returns a tuple containing the final transaction, and the
    /// [`SaplingMetadata`] generated during the build process.
    pub fn build<R: RngCore + CryptoRng, SP: SpendProver, OP: OutputProver, FR: FeeRule>(
        self,
        rng: R,
        spend_prover: &SP,
        output_prover: &OP,
        fee_rule: &FR,
    ) -> Result<BuildResult, Error<FR::Error>> {
        let fee = self.get_fee(fee_rule).map_err(Error::Fee)?;
        self.build_internal(rng, spend_prover, output_prover, fee)
    }

    /// Builds a transaction from the configured spends and outputs.
    ///
    /// Upon success, returns a tuple containing the final transaction, and the
    /// [`SaplingMetadata`] generated during the build process.
    #[cfg(zcash_unstable = "zfuture")]
    pub fn build_zfuture<
        R: RngCore + CryptoRng,
        SP: SpendProver,
        OP: OutputProver,
        FR: FutureFeeRule,
    >(
        self,
        rng: R,
        spend_prover: &SP,
        output_prover: &OP,
        fee_rule: &FR,
    ) -> Result<BuildResult, Error<FR::Error>> {
        let fee = self.get_fee_zfuture(fee_rule).map_err(Error::Fee)?;
        self.build_internal(rng, spend_prover, output_prover, fee)
    }

    fn build_internal<R: RngCore + CryptoRng, SP: SpendProver, OP: OutputProver, FE>(
        self,
        mut rng: R,
        spend_prover: &SP,
        output_prover: &OP,
        fee: NonNegativeAmount,
    ) -> Result<BuildResult, Error<FE>> {
        let consensus_branch_id = BranchId::for_height(&self.params, self.target_height);

        // determine transaction version
        let version = TxVersion::suggested_for_branch(consensus_branch_id);

        //
        // Consistency checks
        //

        // After fees are accounted for, the value balance of the transaction must be zero.
        let balance_after_fees =
            (self.value_balance()? - fee.into()).ok_or(BalanceError::Underflow)?;

        match balance_after_fees.cmp(&Amount::zero()) {
            Ordering::Less => {
                return Err(Error::InsufficientFunds(-balance_after_fees));
            }
            Ordering::Greater => {
                return Err(Error::ChangeRequired(balance_after_fees));
            }
            Ordering::Equal => (),
        };

        let transparent_bundle = self.transparent_builder.build();

        let (sapling_bundle, sapling_meta) = match self
            .sapling_builder
            .and_then(|builder| {
                builder
                    .build::<SP, OP, _, _>(&mut rng)
                    .map_err(Error::SaplingBuild)
                    .transpose()
                    .map(|res| {
                        res.map(|(bundle, sapling_meta)| {
                            // We need to create proofs before signatures, because we still support
                            // creating V4 transactions, which commit to the Sapling proofs in the
                            // transaction digest.
                            (
                                bundle.create_proofs(
                                    spend_prover,
                                    output_prover,
                                    &mut rng,
                                    self.progress_notifier,
                                ),
                                sapling_meta,
                            )
                        })
                    })
            })
            .transpose()?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, SaplingMetadata::empty()),
        };

        let mut unproven_orchard_bundle = None;
        #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
        let mut unproven_orchard_zsa_bundle = None;
        let mut orchard_meta = orchard::builder::BundleMetadata::empty();

        if let Some(builder) = self.orchard_builder {
            let bundle_type = self.build_config.orchard_bundle_type()?;
            if bundle_type == BundleType::DEFAULT_ZSA {
                #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
                {
                    let (bundle, meta) = builder
                        .build(&mut rng)
                        .map_err(Error::OrchardBuild)?
                        .unwrap();

                    unproven_orchard_zsa_bundle = Some(bundle);
                    orchard_meta = meta;
                }
            } else {
                let (bundle, meta) = builder
                    .build(&mut rng)
                    .map_err(Error::OrchardBuild)?
                    .unwrap();
                unproven_orchard_bundle = Some(bundle);
                orchard_meta = meta;
            }
        };

        #[cfg(zcash_unstable = "zfuture")]
        let (tze_bundle, tze_signers) = self.tze_builder.build();

        let unauthed_tx: TransactionData<Unauthorized> = TransactionData {
            version,
            consensus_branch_id: BranchId::for_height(&self.params, self.target_height),
            lock_time: 0,
            expiry_height: self.expiry_height,
            transparent_bundle,
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle: unproven_orchard_bundle,
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            orchard_zsa_bundle: unproven_orchard_zsa_bundle,
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            issue_bundle: self.issuance_builder,
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle,
        };

        //
        // Signatures -- everything but the signatures must already have been added.
        //
        let txid_parts = unauthed_tx.digest(TxIdDigester);

        let transparent_bundle = unauthed_tx.transparent_bundle.clone().map(|b| {
            b.apply_signatures(
                #[cfg(feature = "transparent-inputs")]
                &unauthed_tx,
                #[cfg(feature = "transparent-inputs")]
                &txid_parts,
            )
        });

        #[cfg(zcash_unstable = "zfuture")]
        let tze_bundle = unauthed_tx
            .tze_bundle
            .clone()
            .map(|b| b.into_authorized(&unauthed_tx, tze_signers))
            .transpose()
            .map_err(Error::TzeBuild)?;

        // the commitment being signed is shared across all Sapling inputs; once
        // V4 transactions are deprecated this should just be the txid, but
        // for now we need to continue to compute it here.
        let shielded_sig_commitment =
            signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

        let sapling_bundle = unauthed_tx
            .sapling_bundle
            .map(|b| {
                b.apply_signatures(
                    &mut rng,
                    *shielded_sig_commitment.as_ref(),
                    &self.sapling_asks,
                )
            })
            .transpose()
            .map_err(Error::SaplingBuild)?;

        let orchard_bundle = unauthed_tx
            .orchard_bundle
            .map(|b| {
                b.create_proof(
                    &orchard::circuit::ProvingKey::build::<OrchardVanilla>(),
                    &mut rng,
                )
                .and_then(|b| {
                    b.apply_signatures(
                        &mut rng,
                        *shielded_sig_commitment.as_ref(),
                        &self.orchard_saks,
                    )
                })
            })
            .transpose()
            .map_err(Error::OrchardBuild)?;

        #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
        let orchard_zsa_bundle = unauthed_tx
            .orchard_zsa_bundle
            .map(|b| {
                b.create_proof(
                    &orchard::circuit::ProvingKey::build::<OrchardZSA>(),
                    &mut rng,
                )
                .and_then(|b| {
                    b.apply_signatures(
                        &mut rng,
                        *shielded_sig_commitment.as_ref(),
                        &self.orchard_saks,
                    )
                })
            })
            .transpose()
            .map_err(Error::OrchardBuild)?;

        #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
        let issue_bundle = unauthed_tx
            .issue_bundle
            .map(|b| b.prepare(*shielded_sig_commitment.as_ref()))
            .map(|b| b.sign(self.issuance_isk.as_ref().unwrap()))
            .map(|b| b.unwrap());

        let authorized_tx = TransactionData {
            version: unauthed_tx.version,
            consensus_branch_id: unauthed_tx.consensus_branch_id,
            lock_time: unauthed_tx.lock_time,
            expiry_height: unauthed_tx.expiry_height,
            transparent_bundle,
            sprout_bundle: unauthed_tx.sprout_bundle,
            sapling_bundle,
            orchard_bundle,
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            orchard_zsa_bundle,
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            issue_bundle,
            #[cfg(zcash_unstable = "zfuture")]
            tze_bundle,
        };

        // The unwrap() here is safe because the txid hashing
        // of freeze() should be infalliable.
        Ok(BuildResult {
            transaction: authorized_tx.freeze().unwrap(),
            sapling_meta,
            orchard_meta,
        })
    }
}

#[cfg(zcash_unstable = "zfuture")]
impl<'a, P: consensus::Parameters, U: sapling::builder::ProverProgress> ExtensionTxBuilder<'a>
    for Builder<'a, P, U>
{
    type BuildCtx = TransactionData<Unauthorized>;
    type BuildError = tze::builder::Error;

    fn add_tze_input<WBuilder, W: ToPayload>(
        &mut self,
        extension_id: u32,
        mode: u32,
        prevout: (tze::OutPoint, TzeOut),
        witness_builder: WBuilder,
    ) -> Result<(), Self::BuildError>
    where
        WBuilder: 'a + (FnOnce(&Self::BuildCtx) -> Result<W, tze::builder::Error>),
    {
        self.tze_builder
            .add_input(extension_id, mode, prevout, witness_builder);

        Ok(())
    }

    fn add_tze_output<G: ToPayload>(
        &mut self,
        extension_id: u32,
        value: Amount,
        guarded_by: &G,
    ) -> Result<(), Self::BuildError> {
        self.tze_builder.add_output(extension_id, value, guarded_by)
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
mod testing {
    use super::{BuildResult, Builder, Error};
    use crate::{
        consensus,
        sapling::{
            self,
            prover::mock::{MockOutputProver, MockSpendProver},
        },
        transaction::fees::fixed::FeeRule,
    };
    use rand::RngCore;
    use rand_core::CryptoRng;
    use std::convert::Infallible;
    use zcash_protocol::value::Zatoshis;

    impl<'a, P: consensus::Parameters, U: sapling::builder::ProverProgress> Builder<'a, P, U> {
        /// Build the transaction using mocked randomness and proving capabilities.
        /// DO NOT USE EXCEPT FOR UNIT TESTING.
        pub fn mock_build<R: RngCore>(self, rng: R) -> Result<BuildResult, Error<Infallible>> {
            #[allow(deprecated)]
            self.mock_build_internal(rng, &FeeRule::standard())
        }

        /// Build the transaction using mocked randomness and proving capabilities.
        /// DO NOT USE EXCEPT FOR UNIT TESTING.
        pub fn mock_build_no_fee<R: RngCore>(
            self,
            rng: R,
        ) -> Result<BuildResult, Error<Infallible>> {
            #[allow(deprecated)]
            self.mock_build_internal(rng, &FeeRule::non_standard(Zatoshis::from_u64(0)?))
        }

        fn mock_build_internal<R: RngCore>(
            self,
            rng: R,
            fee_rule: &FeeRule,
        ) -> Result<BuildResult, Error<Infallible>> {
            struct FakeCryptoRng<R: RngCore>(R);
            impl<R: RngCore> CryptoRng for FakeCryptoRng<R> {}
            impl<R: RngCore> RngCore for FakeCryptoRng<R> {
                fn next_u32(&mut self) -> u32 {
                    self.0.next_u32()
                }

                fn next_u64(&mut self) -> u64 {
                    self.0.next_u64()
                }

                fn fill_bytes(&mut self, dest: &mut [u8]) {
                    self.0.fill_bytes(dest)
                }

                fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                    self.0.try_fill_bytes(dest)
                }
            }

            self.build(
                FakeCryptoRng(rng),
                &MockSpendProver,
                &MockOutputProver,
                fee_rule,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use assert_matches::assert_matches;
    use ff::Field;
    use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
    use rand_core::OsRng;

    use crate::{
        consensus::{NetworkUpgrade, Parameters, TEST_NETWORK},
        legacy::TransparentAddress,
        memo::MemoBytes,
        sapling::{self, zip32::ExtendedSpendingKey, Node, Rseed},
        transaction::{
            builder::BuildConfig,
            components::amount::{Amount, BalanceError, NonNegativeAmount},
        },
    };

    use super::{Builder, Error};

    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    use {
        crate::transaction::fees::zip317::FeeError,
        orchard::issuance::IssueInfo,
        orchard::keys::{
            FullViewingKey, IssuanceAuthorizingKey, IssuanceValidatingKey, SpendingKey,
        },
        orchard::note::AssetBase,
        orchard::value::NoteValue,
        orchard::Address,
        zcash_protocol::consensus::TestNetwork,
        zcash_protocol::constants::testnet::COIN_TYPE,
        zip32::Scope::External,
    };

    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    #[cfg(not(feature = "transparent-inputs"))]
    use crate::zip32::AccountId;

    #[cfg(zcash_unstable = "zfuture")]
    #[cfg(feature = "transparent-inputs")]
    use super::TzeBuilder;

    #[cfg(feature = "transparent-inputs")]
    use crate::{
        legacy::keys::{AccountPrivKey, IncomingViewingKey},
        transaction::{builder::DEFAULT_TX_EXPIRY_DELTA, OutPoint, TxOut},
        zip32::AccountId,
    };

    // This test only works with the transparent_inputs feature because we have to
    // be able to create a tx with a valid balance, without using Sapling inputs.
    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn binding_sig_absent_if_no_shielded_spend_or_output() {
        use crate::consensus::NetworkUpgrade;
        use crate::legacy::keys::NonHardenedChildIndex;
        use crate::transaction::builder::{self, TransparentBuilder};

        let sapling_activation_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        // Create a builder with 0 fee, so we can construct t outputs
        let mut builder = builder::Builder {
            params: TEST_NETWORK,
            build_config: BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
            },
            target_height: sapling_activation_height,
            expiry_height: sapling_activation_height + DEFAULT_TX_EXPIRY_DELTA,
            transparent_builder: TransparentBuilder::empty(),
            sapling_builder: None,
            #[cfg(zcash_unstable = "zfuture")]
            tze_builder: TzeBuilder::empty(),
            #[cfg(not(zcash_unstable = "zfuture"))]
            tze_builder: std::marker::PhantomData,
            progress_notifier: (),
            orchard_builder: None,
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            issuance_builder: None,
            sapling_asks: vec![],
            orchard_saks: Vec::new(),
            #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
            issuance_isk: None,
        };

        let tsk = AccountPrivKey::from_seed(&TEST_NETWORK, &[0u8; 32], AccountId::ZERO).unwrap();
        let prev_coin = TxOut {
            value: NonNegativeAmount::const_from_u64(50000),
            script_pubkey: tsk
                .to_account_pubkey()
                .derive_external_ivk()
                .unwrap()
                .derive_address(NonHardenedChildIndex::ZERO)
                .unwrap()
                .script(),
        };
        builder
            .add_transparent_input(
                tsk.derive_external_secret_key(NonHardenedChildIndex::ZERO)
                    .unwrap(),
                OutPoint::new([0u8; 32], 1),
                prev_coin,
            )
            .unwrap();

        // Create a tx with only t output. No binding_sig should be present
        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                NonNegativeAmount::const_from_u64(40000),
            )
            .unwrap();

        let res = builder.mock_build(OsRng).unwrap();
        // No binding signature, because only t input and outputs
        assert!(res.transaction().sapling_bundle.is_none());
    }

    #[test]
    fn binding_sig_present_if_shielded_spend() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1;

        let mut rng = OsRng;

        let note1 = to.create_note(
            sapling::value::NoteValue::from_raw(50000),
            Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
        );
        let cmu1 = Node::from_cmu(&note1.cmu());
        let mut tree = CommitmentTree::<Node, 32>::empty();
        tree.append(cmu1).unwrap();
        let witness1 = IncrementalWitness::from_tree(tree);

        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        let build_config = BuildConfig::Standard {
            sapling_anchor: Some(witness1.root().into()),
            orchard_anchor: None,
        };
        let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);

        // Create a tx with a sapling spend. binding_sig should be present
        builder
            .add_sapling_spend::<Infallible>(&extsk, note1, witness1.path().unwrap())
            .unwrap();

        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([0; 20]),
                NonNegativeAmount::const_from_u64(40000),
            )
            .unwrap();

        // A binding signature (and bundle) is present because there is a Sapling spend.
        let res = builder.mock_build(OsRng).unwrap();
        assert!(res.transaction().sapling_bundle().is_some());
    }

    #[test]
    fn fails_on_negative_change() {
        use crate::transaction::fees::zip317::MINIMUM_FEE;

        let mut rng = OsRng;

        // Just use the master key as the ExtendedSpendingKey for this test
        let extsk = ExtendedSpendingKey::master(&[]);
        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        // Fails with no inputs or outputs
        // 0.0001 t-ZEC fee
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
            };
            let builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            assert_matches!(
                builder.mock_build(OsRng),
                Err(Error::InsufficientFunds(expected)) if expected == MINIMUM_FEE.into()
            );
        }

        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let ovk = Some(dfvk.fvk().ovk);
        let to = dfvk.default_address().1;

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    NonNegativeAmount::const_from_u64(50000),
                    MemoBytes::empty(),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(OsRng),
                Err(Error::InsufficientFunds(expected)) if
                    expected == (NonNegativeAmount::const_from_u64(50000) + MINIMUM_FEE).unwrap().into()
            );
        }

        // Fail if there is only a transparent output
        // 0.0005 t-ZEC out, 0.0001 t-ZEC fee
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(sapling::Anchor::empty_tree()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    NonNegativeAmount::const_from_u64(50000),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(OsRng),
                Err(Error::InsufficientFunds(expected)) if expected ==
                    (NonNegativeAmount::const_from_u64(50000) + MINIMUM_FEE).unwrap().into()
            );
        }

        let note1 = to.create_note(
            sapling::value::NoteValue::from_raw(59999),
            Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
        );
        let cmu1 = Node::from_cmu(&note1.cmu());
        let mut tree = CommitmentTree::<Node, 32>::empty();
        tree.append(cmu1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(tree.clone());

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.00059999 z-ZEC in
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(witness1.root().into()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_spend::<Infallible>(&extsk, note1.clone(), witness1.path().unwrap())
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    NonNegativeAmount::const_from_u64(30000),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    NonNegativeAmount::const_from_u64(20000),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(OsRng),
                Err(Error::InsufficientFunds(expected)) if expected == Amount::const_from_i64(1)
            );
        }

        let note2 = to.create_note(
            sapling::value::NoteValue::from_raw(1),
            Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
        );
        let cmu2 = Node::from_cmu(&note2.cmu());
        tree.append(cmu2).unwrap();
        witness1.append(cmu2).unwrap();
        let witness2 = IncrementalWitness::from_tree(tree);

        // Succeeds if there is sufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.0006 z-ZEC in
        {
            let build_config = BuildConfig::Standard {
                sapling_anchor: Some(witness1.root().into()),
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
            };
            let mut builder = Builder::new(TEST_NETWORK, tx_height, build_config);
            builder
                .add_sapling_spend::<Infallible>(&extsk, note1, witness1.path().unwrap())
                .unwrap();
            builder
                .add_sapling_spend::<Infallible>(&extsk, note2, witness2.path().unwrap())
                .unwrap();
            builder
                .add_sapling_output::<Infallible>(
                    ovk,
                    to,
                    NonNegativeAmount::const_from_u64(30000),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKeyHash([0; 20]),
                    NonNegativeAmount::const_from_u64(20000),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(OsRng),
                Ok(res) if res.transaction().fee_paid(|_| Err(BalanceError::Overflow)).unwrap() == Amount::const_from_i64(10_000)
            );
        }
    }

    #[test]
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    fn init_issuance_bundle_with_finalization() {
        let (mut builder, iak, _) = prepare_zsa_test();

        let asset_desc: Vec<u8> = "asset_desc".into();

        builder
            .init_issuance_bundle::<FeeError>(iak, asset_desc.clone(), None)
            .unwrap();

        let tx = builder.mock_build_no_fee(OsRng).unwrap().into_transaction();
        let bundle = tx.issue_bundle().unwrap();

        assert_eq!(bundle.actions().len(), 1, "There should be only one action");
        let actions = bundle.get_actions_by_desc(&asset_desc);
        assert_eq!(
            actions.len(),
            1,
            "The one action should correspond to asset_desc"
        );
        let action = actions[0];
        assert!(action.is_finalized(), "Action should be finalized");
        assert_eq!(action.notes().len(), 0, "Action should have zero notes");
    }

    #[test]
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    fn init_issuance_bundle_without_finalization() {
        let (mut builder, iak, address) = prepare_zsa_test();

        let asset_desc: Vec<u8> = "asset_desc".into();

        builder
            .init_issuance_bundle::<FeeError>(
                iak,
                asset_desc.clone(),
                Some(IssueInfo {
                    recipient: address,
                    value: NoteValue::from_raw(42),
                }),
            )
            .unwrap();

        let binding = builder.mock_build_no_fee(OsRng).unwrap().into_transaction();
        let bundle = binding.issue_bundle().unwrap();

        assert_eq!(bundle.actions().len(), 1, "There should be only one action");
        let actions = bundle.get_actions_by_desc(&asset_desc);
        assert_eq!(
            actions.len(),
            1,
            "The one action should correspond to asset_desc"
        );
        let action = actions[0];
        assert!(!action.is_finalized(), "Action should not be finalized");
        assert_eq!(action.notes().len(), 1, "Action should have 1 note");
        assert_eq!(
            action.notes().first().unwrap().value().inner(),
            42,
            "Incorrect note value"
        );
    }

    #[test]
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    fn add_issuance_same_asset() {
        let (mut builder, iak, address) = prepare_zsa_test();

        let asset_desc: Vec<u8> = "asset_desc".into();

        builder
            .init_issuance_bundle::<FeeError>(
                iak,
                asset_desc.clone(),
                Some(IssueInfo {
                    recipient: address,
                    value: NoteValue::from_raw(42),
                }),
            )
            .unwrap();
        builder
            .add_recipient::<FeeError>(&asset_desc, address, NoteValue::from_raw(21))
            .unwrap();

        let binding = builder.mock_build_no_fee(OsRng).unwrap().into_transaction();
        let bundle = binding.issue_bundle().unwrap();

        assert_eq!(bundle.actions().len(), 1, "There should be only one action");
        let actions = bundle.get_actions_by_desc(&asset_desc);
        assert_eq!(
            actions.len(),
            1,
            "The one action should correspond to asset_desc"
        );
        let action = actions[0];
        assert!(!action.is_finalized(), "Action should not be finalized");
        assert_eq!(action.notes().len(), 2, "Action should have 2 notes");
        assert_eq!(
            action
                .notes()
                .iter()
                .map(|note| note.value().inner())
                .sum::<u64>(),
            42 + 21,
            "Incorrect notes sum"
        );
    }

    #[test]
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    fn add_issuance_different_asset() {
        let (mut builder, iak, address) = prepare_zsa_test();

        let asset_desc_1: Vec<u8> = "asset_desc".into();
        let asset_desc_2: Vec<u8> = "asset_desc_2".into();

        builder
            .init_issuance_bundle::<FeeError>(
                iak,
                asset_desc_1.clone(),
                Some(IssueInfo {
                    recipient: address,
                    value: NoteValue::from_raw(42),
                }),
            )
            .unwrap();
        builder
            .add_recipient::<FeeError>(&asset_desc_2, address, NoteValue::from_raw(21))
            .unwrap();

        let binding = builder.mock_build_no_fee(OsRng).unwrap().into_transaction();
        let bundle = binding.issue_bundle().unwrap();

        assert_eq!(bundle.actions().len(), 2, "There should be 2 actions");

        let actions = bundle.get_actions_by_desc(&asset_desc_1);
        assert_eq!(
            actions.len(),
            1,
            "Only one action should correspond to asset_desc_1"
        );
        let action = actions[0];
        assert!(!action.is_finalized(), "Action should not be finalized");
        assert_eq!(action.notes().len(), 1, "Action should have 1 note");
        assert_eq!(
            action
                .notes()
                .iter()
                .map(|note| note.value().inner())
                .sum::<u64>(),
            42,
            "Incorrect notes sum"
        );

        let actions_2 = bundle.get_actions_by_desc(&asset_desc_2);
        assert_eq!(
            actions_2.len(),
            1,
            "Only one action should correspond to asset_desc_2"
        );
        let action2 = actions_2[0];
        assert!(!action2.is_finalized(), "Action should not be finalized");
        assert_eq!(action2.notes().len(), 1, "Action should have 1 note");
        assert_eq!(
            action2
                .notes()
                .iter()
                .map(|note| note.value().inner())
                .sum::<u64>(),
            21,
            "Incorrect notes sum"
        );
    }

    #[test]
    #[should_panic]
    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    fn fails_on_add_burn_without_input() {
        let (mut builder, iak, _) = prepare_zsa_test();

        let asset_desc: &[u8] = b"asset_desc";
        let asset_base = AssetBase::derive(&IssuanceValidatingKey::from(&iak), asset_desc);

        builder.add_burn::<FeeError>(42, asset_base).unwrap();

        builder.mock_build_no_fee(OsRng).unwrap();
    }

    #[cfg(zcash_unstable = "nu6" /* TODO nu7 */ )]
    fn prepare_zsa_test() -> (
        Builder<'static, TestNetwork, ()>,
        IssuanceAuthorizingKey,
        Address,
    ) {
        let seed = "0123456789abcdef0123456789abcdef".as_bytes();

        let iak = IssuanceAuthorizingKey::from_zip32_seed(seed, COIN_TYPE, 0).unwrap();
        let tx_height = TEST_NETWORK.activation_height(NetworkUpgrade::Nu7).unwrap();

        let build_config = BuildConfig::Zsa {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
        };

        let builder = Builder::new(TEST_NETWORK, tx_height, build_config);

        let sk =
            SpendingKey::from_zip32_seed(seed, COIN_TYPE, AccountId::try_from(0).unwrap()).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let address = fvk.address_at(0u32, External);

        (builder, iak, address)
    }
}
