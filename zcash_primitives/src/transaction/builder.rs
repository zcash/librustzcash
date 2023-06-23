//! Structs for building transactions.

use std::cmp::Ordering;
use std::error;
use std::fmt;
use std::sync::mpsc::Sender;

use rand::{rngs::OsRng, CryptoRng, RngCore};

use crate::{
    consensus::{self, BlockHeight, BranchId, NetworkUpgrade},
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    memo::MemoBytes,
    sapling::{self, prover::TxProver, value::NoteValue, Diversifier, Note, PaymentAddress},
    transaction::{
        components::{
            amount::{Amount, BalanceError},
            sapling::{
                builder::{self as sapling_builder, SaplingBuilder, SaplingMetadata},
                fees as sapling_fees,
            },
            transparent::{self, builder::TransparentBuilder},
        },
        fees::FeeRule,
        sighash::{signature_hash, SignableInput},
        txid::TxIdDigester,
        Transaction, TransactionData, TxVersion, Unauthorized,
    },
    zip32::ExtendedSpendingKey,
};

#[cfg(feature = "transparent-inputs")]
use crate::transaction::components::transparent::TxOut;

#[cfg(feature = "zfuture")]
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

/// Errors that can occur during transaction construction.
#[derive(Debug)]
pub enum Error<FeeError> {
    /// Insufficient funds were provided to the transaction builder; the given
    /// additional amount is required in order to construct the transaction.
    InsufficientFunds(Amount),
    /// The transaction has inputs in excess of outputs and fees; the user must
    /// add a change output.
    ChangeRequired(Amount),
    /// An error occurred in computing the fees for a transaction.
    Fee(FeeError),
    /// An overflow or underflow occurred when computing value balances
    Balance(BalanceError),
    /// An error occurred in constructing the transparent parts of a transaction.
    TransparentBuild(transparent::builder::Error),
    /// An error occurred in constructing the Sapling parts of a transaction.
    SaplingBuild(sapling_builder::Error),
    /// An error occurred in constructing the Orchard parts of a transaction.
    OrchardBuild(orchard::builder::BuildError),
    /// An error occurred in adding an Orchard Spend to a transaction.
    OrchardSpend(orchard::builder::SpendError),
    /// An error occurred in adding an Orchard Output to a transaction.
    OrchardRecipient(orchard::builder::OutputError),
    /// The builder was constructed either without an Orchard anchor or before NU5
    /// activation, but an Orchard spend or recipient was added.
    OrchardAnchorNotAvailable,
    /// An error occurred in constructing the TZE parts of a transaction.
    #[cfg(feature = "zfuture")]
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
            Error::OrchardAnchorNotAvailable => write!(
                f,
                "Cannot create Orchard transactions without an Orchard anchor, or before NU5 activation"
            ),
            #[cfg(feature = "zfuture")]
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

/// Reports on the progress made by the builder towards building a transaction.
pub struct Progress {
    /// The number of steps completed.
    cur: u32,
    /// The expected total number of steps (as of this progress update), if known.
    end: Option<u32>,
}

impl Progress {
    pub fn new(cur: u32, end: Option<u32>) -> Self {
        Self { cur, end }
    }

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

/// Generates a [`Transaction`] from its inputs and outputs.
pub struct Builder<'a, P, R> {
    params: P,
    rng: R,
    target_height: BlockHeight,
    expiry_height: BlockHeight,
    transparent_builder: TransparentBuilder,
    sapling_builder: SaplingBuilder<P>,
    orchard_builder: Option<orchard::builder::Builder>,
    // TODO: In the future, instead of taking the spending keys as arguments when calling
    // `add_sapling_spend` or `add_orchard_spend`, we will build an unauthorized, unproven
    // transaction, and then the caller will be responsible for using the spending keys or their
    // derivatives for proving and signing to complete transaction creation.
    orchard_saks: Vec<orchard::keys::SpendAuthorizingKey>,
    #[cfg(feature = "zfuture")]
    tze_builder: TzeBuilder<'a, TransactionData<Unauthorized>>,
    #[cfg(not(feature = "zfuture"))]
    tze_builder: std::marker::PhantomData<&'a ()>,
    progress_notifier: Option<Sender<Progress>>,
}

impl<'a, P, R> Builder<'a, P, R> {
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
    pub fn transparent_inputs(&self) -> &[impl transparent::fees::InputView] {
        self.transparent_builder.inputs()
    }

    /// Returns the set of transparent outputs currently set to be produced by
    /// the transaction.
    pub fn transparent_outputs(&self) -> &[impl transparent::fees::OutputView] {
        self.transparent_builder.outputs()
    }

    /// Returns the set of Sapling inputs currently committed to be consumed
    /// by the transaction.
    pub fn sapling_inputs(&self) -> &[impl sapling_fees::InputView<()>] {
        self.sapling_builder.inputs()
    }

    /// Returns the set of Sapling outputs currently set to be produced by
    /// the transaction.
    pub fn sapling_outputs(&self) -> &[impl sapling_fees::OutputView] {
        self.sapling_builder.outputs()
    }
}

impl<'a, P: consensus::Parameters> Builder<'a, P, OsRng> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height,
    /// using default values for general transaction fields and the default OS random.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    pub fn new(
        params: P,
        target_height: BlockHeight,
        orchard_anchor: Option<orchard::tree::Anchor>,
    ) -> Self {
        Builder::new_with_rng(params, target_height, orchard_anchor, OsRng)
    }
}

impl<'a, P: consensus::Parameters, R: RngCore + CryptoRng> Builder<'a, P, R> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height
    /// and randomness source, using default values for general transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    pub fn new_with_rng(
        params: P,
        target_height: BlockHeight,
        orchard_anchor: Option<orchard::tree::Anchor>,
        rng: R,
    ) -> Builder<'a, P, R> {
        let orchard_builder = if params.is_nu_active(NetworkUpgrade::Nu5, target_height) {
            orchard_anchor.map(|anchor| {
                orchard::builder::Builder::new(
                    orchard::bundle::Flags::from_parts(true, true),
                    anchor,
                )
            })
        } else {
            None
        };

        Self::new_internal(params, rng, target_height, orchard_builder)
    }

    /// Common utility function for builder construction.
    fn new_internal(
        params: P,
        rng: R,
        target_height: BlockHeight,
        orchard_builder: Option<orchard::builder::Builder>,
    ) -> Self {
        Builder {
            params: params.clone(),
            rng,
            target_height,
            expiry_height: target_height + DEFAULT_TX_EXPIRY_DELTA,
            transparent_builder: TransparentBuilder::empty(),
            sapling_builder: SaplingBuilder::new(params, target_height),
            orchard_builder,
            orchard_saks: Vec::new(),
            #[cfg(feature = "zfuture")]
            tze_builder: TzeBuilder::empty(),
            #[cfg(not(feature = "zfuture"))]
            tze_builder: std::marker::PhantomData,
            progress_notifier: None,
        }
    }

    /// Adds an Orchard note to be spent in this bundle.
    ///
    /// Returns an error if the given Merkle path does not have the required anchor for
    /// the given note.
    pub fn add_orchard_spend<FeeError>(
        &mut self,
        sk: orchard::keys::SpendingKey,
        note: orchard::Note,
        merkle_path: orchard::tree::MerklePath,
    ) -> Result<(), Error<FeeError>> {
        self.orchard_builder
            .as_mut()
            .ok_or(Error::OrchardAnchorNotAvailable)?
            .add_spend(orchard::keys::FullViewingKey::from(&sk), note, merkle_path)
            .map_err(Error::OrchardSpend)?;

        self.orchard_saks
            .push(orchard::keys::SpendAuthorizingKey::from(&sk));

        Ok(())
    }

    /// Adds an Orchard recipient to the transaction.
    pub fn add_orchard_output<FeeError>(
        &mut self,
        ovk: Option<orchard::keys::OutgoingViewingKey>,
        recipient: orchard::Address,
        value: u64,
        memo: MemoBytes,
    ) -> Result<(), Error<FeeError>> {
        self.orchard_builder
            .as_mut()
            .ok_or(Error::OrchardAnchorNotAvailable)?
            .add_recipient(
                ovk,
                recipient,
                orchard::value::NoteValue::from_raw(value),
                Some(*memo.as_array()),
            )
            .map_err(Error::OrchardRecipient)
    }

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_sapling_spend(
        &mut self,
        extsk: ExtendedSpendingKey,
        diversifier: Diversifier,
        note: Note,
        merkle_path: sapling::MerklePath,
    ) -> Result<(), sapling_builder::Error> {
        self.sapling_builder
            .add_spend(&mut self.rng, extsk, diversifier, note, merkle_path)
    }

    /// Adds a Sapling address to send funds to.
    pub fn add_sapling_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: MemoBytes,
    ) -> Result<(), sapling_builder::Error> {
        if value.is_negative() {
            return Err(sapling_builder::Error::InvalidAmount);
        }
        self.sapling_builder.add_output(
            &mut self.rng,
            ovk,
            to,
            NoteValue::from_raw(value.into()),
            memo,
        )
    }

    /// Adds a transparent coin to be spent in this transaction.
    #[cfg(feature = "transparent-inputs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "transparent-inputs")))]
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
        value: Amount,
    ) -> Result<(), transparent::builder::Error> {
        self.transparent_builder.add_output(to, value)
    }

    /// Sets the notifier channel, where progress of building the transaction is sent.
    ///
    /// An update is sent after every Spend or Output is computed, and the `u32` sent
    /// represents the total steps completed so far. It will eventually send number of
    /// spends + outputs. If there's an error building the transaction, the channel is
    /// closed.
    pub fn with_progress_notifier(&mut self, progress_notifier: Sender<Progress>) {
        self.progress_notifier = Some(progress_notifier);
    }

    /// Returns the sum of the transparent, Sapling, Orchard, and TZE value balances.
    fn value_balance(&self) -> Result<Amount, BalanceError> {
        let value_balances = [
            self.transparent_builder.value_balance()?,
            self.sapling_builder.value_balance(),
            if let Some(builder) = &self.orchard_builder {
                builder
                    .value_balance()
                    .map_err(|_| BalanceError::Overflow)?
            } else {
                Amount::zero()
            },
            #[cfg(feature = "zfuture")]
            self.tze_builder.value_balance()?,
        ];

        value_balances
            .into_iter()
            .sum::<Option<_>>()
            .ok_or(BalanceError::Overflow)
    }

    /// Builds a transaction from the configured spends and outputs.
    ///
    /// Upon success, returns a tuple containing the final transaction, and the
    /// [`SaplingMetadata`] generated during the build process.
    pub fn build<FR: FeeRule>(
        self,
        prover: &impl TxProver,
        fee_rule: &FR,
    ) -> Result<(Transaction, SaplingMetadata), Error<FR::Error>> {
        let fee = fee_rule
            .fee_required(
                &self.params,
                self.target_height,
                self.transparent_builder.inputs(),
                self.transparent_builder.outputs(),
                self.sapling_builder.inputs().len(),
                self.sapling_builder.bundle_output_count(),
                match std::cmp::max(
                    self.orchard_builder
                        .as_ref()
                        .map_or(0, |builder| builder.outputs().len()),
                    self.orchard_builder
                        .as_ref()
                        .map_or(0, |builder| builder.spends().len()),
                ) {
                    1 => 2,
                    n => n,
                },
            )
            .map_err(Error::Fee)?;
        self.build_internal(prover, fee)
    }

    /// Builds a transaction from the configured spends and outputs.
    ///
    /// Upon success, returns a tuple containing the final transaction, and the
    /// [`SaplingMetadata`] generated during the build process.
    #[cfg(feature = "zfuture")]
    pub fn build_zfuture<FR: FutureFeeRule>(
        self,
        prover: &impl TxProver,
        fee_rule: &FR,
    ) -> Result<(Transaction, SaplingMetadata), Error<FR::Error>> {
        let fee = fee_rule
            .fee_required_zfuture(
                &self.params,
                self.target_height,
                self.transparent_builder.inputs(),
                self.transparent_builder.outputs(),
                self.sapling_builder.inputs().len(),
                self.sapling_builder.bundle_output_count(),
                self.tze_builder.inputs(),
                self.tze_builder.outputs(),
            )
            .map_err(Error::Fee)?;

        self.build_internal(prover, fee)
    }

    fn build_internal<FE>(
        self,
        prover: &impl TxProver,
        fee: Amount,
    ) -> Result<(Transaction, SaplingMetadata), Error<FE>> {
        let consensus_branch_id = BranchId::for_height(&self.params, self.target_height);

        // determine transaction version
        let version = TxVersion::suggested_for_branch(consensus_branch_id);

        //
        // Consistency checks
        //

        // After fees are accounted for, the value balance of the transaction must be zero.
        let balance_after_fees = (self.value_balance()? - fee).ok_or(BalanceError::Underflow)?;

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

        let mut rng = self.rng;
        let mut ctx = prover.new_sapling_proving_context();
        let sapling_bundle = self
            .sapling_builder
            .build(
                prover,
                &mut ctx,
                &mut rng,
                self.target_height,
                self.progress_notifier.as_ref(),
            )
            .map_err(Error::SaplingBuild)?;

        let orchard_bundle: Option<orchard::Bundle<_, Amount>> =
            if let Some(builder) = self.orchard_builder {
                Some(builder.build(&mut rng).map_err(Error::OrchardBuild)?)
            } else {
                None
            };

        #[cfg(feature = "zfuture")]
        let (tze_bundle, tze_signers) = self.tze_builder.build();

        let unauthed_tx: TransactionData<Unauthorized> = TransactionData {
            version,
            consensus_branch_id: BranchId::for_height(&self.params, self.target_height),
            lock_time: 0,
            expiry_height: self.expiry_height,
            transparent_bundle,
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle,
            #[cfg(feature = "zfuture")]
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

        #[cfg(feature = "zfuture")]
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

        let (sapling_bundle, tx_metadata) = match unauthed_tx
            .sapling_bundle
            .map(|b| {
                b.apply_signatures(prover, &mut ctx, &mut rng, shielded_sig_commitment.as_ref())
            })
            .transpose()
            .map_err(Error::SaplingBuild)?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, SaplingMetadata::empty()),
        };

        let orchard_bundle = unauthed_tx
            .orchard_bundle
            .map(|b| {
                b.create_proof(&orchard::circuit::ProvingKey::build(), &mut rng)
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

        let authorized_tx = TransactionData {
            version: unauthed_tx.version,
            consensus_branch_id: unauthed_tx.consensus_branch_id,
            lock_time: unauthed_tx.lock_time,
            expiry_height: unauthed_tx.expiry_height,
            transparent_bundle,
            sprout_bundle: unauthed_tx.sprout_bundle,
            sapling_bundle,
            orchard_bundle,
            #[cfg(feature = "zfuture")]
            tze_bundle,
        };

        // The unwrap() here is safe because the txid hashing
        // of freeze() should be infalliable.
        Ok((authorized_tx.freeze().unwrap(), tx_metadata))
    }
}

#[cfg(feature = "zfuture")]
impl<'a, P: consensus::Parameters, R: RngCore + CryptoRng> ExtensionTxBuilder<'a>
    for Builder<'a, P, R>
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
    use rand::RngCore;
    use rand_core::CryptoRng;
    use std::convert::Infallible;

    use super::{Builder, Error, SaplingMetadata};
    use crate::{
        consensus::{self, BlockHeight},
        sapling::prover::mock::MockTxProver,
        transaction::fees::fixed,
        transaction::Transaction,
    };

    impl<'a, P: consensus::Parameters, R: RngCore> Builder<'a, P, R> {
        /// Creates a new `Builder` targeted for inclusion in the block with the given height
        /// and randomness source, using default values for general transaction fields.
        ///
        /// # Default values
        ///
        /// The expiry height will be set to the given height plus the default transaction
        /// expiry delta.
        ///
        /// WARNING: DO NOT USE IN PRODUCTION
        pub fn test_only_new_with_rng(
            params: P,
            height: BlockHeight,
            rng: R,
        ) -> Builder<'a, P, impl RngCore + CryptoRng> {
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
            Builder::new_internal(params, FakeCryptoRng(rng), height, None)
        }
    }
    impl<'a, P: consensus::Parameters, R: RngCore + CryptoRng> Builder<'a, P, R> {
        pub fn mock_build(self) -> Result<(Transaction, SaplingMetadata), Error<Infallible>> {
            #[allow(deprecated)]
            self.build(&MockTxProver, &fixed::FeeRule::standard())
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ff::Field;
    use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
    use rand_core::OsRng;

    use crate::{
        consensus::{NetworkUpgrade, Parameters, TEST_NETWORK},
        legacy::TransparentAddress,
        memo::MemoBytes,
        sapling::{Node, Rseed},
        transaction::components::{
            amount::Amount,
            sapling::builder::{self as sapling_builder},
            transparent::builder::{self as transparent_builder},
        },
        zip32::ExtendedSpendingKey,
    };

    use super::{Builder, Error};

    #[cfg(feature = "zfuture")]
    #[cfg(feature = "transparent-inputs")]
    use super::TzeBuilder;

    #[cfg(feature = "transparent-inputs")]
    use crate::{
        legacy::keys::{AccountPrivKey, IncomingViewingKey},
        transaction::{
            builder::{SaplingBuilder, DEFAULT_TX_EXPIRY_DELTA},
            OutPoint, TxOut,
        },
        zip32::AccountId,
    };

    #[test]
    fn fails_on_negative_output() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let ovk = dfvk.fvk().ovk;
        let to = dfvk.default_address().1;

        let sapling_activation_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        let mut builder = Builder::new(TEST_NETWORK, sapling_activation_height, None);
        assert_eq!(
            builder.add_sapling_output(
                Some(ovk),
                to,
                Amount::from_i64(-1).unwrap(),
                MemoBytes::empty()
            ),
            Err(sapling_builder::Error::InvalidAmount)
        );
    }

    // This test only works with the transparent_inputs feature because we have to
    // be able to create a tx with a valid balance, without using Sapling inputs.
    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn binding_sig_absent_if_no_shielded_spend_or_output() {
        use crate::consensus::NetworkUpgrade;
        use crate::transaction::builder::{self, TransparentBuilder};

        let sapling_activation_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        // Create a builder with 0 fee, so we can construct t outputs
        let mut builder = builder::Builder {
            params: TEST_NETWORK,
            rng: OsRng,
            target_height: sapling_activation_height,
            expiry_height: sapling_activation_height + DEFAULT_TX_EXPIRY_DELTA,
            transparent_builder: TransparentBuilder::empty(),
            sapling_builder: SaplingBuilder::new(TEST_NETWORK, sapling_activation_height),
            #[cfg(feature = "zfuture")]
            tze_builder: TzeBuilder::empty(),
            #[cfg(not(feature = "zfuture"))]
            tze_builder: std::marker::PhantomData,
            progress_notifier: None,
            orchard_builder: None,
            orchard_saks: Vec::new(),
        };

        let tsk = AccountPrivKey::from_seed(&TEST_NETWORK, &[0u8; 32], AccountId::from(0)).unwrap();
        let prev_coin = TxOut {
            value: Amount::from_u64(50000).unwrap(),
            script_pubkey: tsk
                .to_account_pubkey()
                .derive_external_ivk()
                .unwrap()
                .derive_address(0)
                .unwrap()
                .script(),
        };
        builder
            .add_transparent_input(
                tsk.derive_external_secret_key(0).unwrap(),
                OutPoint::new([0u8; 32], 1),
                prev_coin,
            )
            .unwrap();

        // Create a tx with only t output. No binding_sig should be present
        builder
            .add_transparent_output(
                &TransparentAddress::PublicKey([0; 20]),
                Amount::from_u64(40000).unwrap(),
            )
            .unwrap();

        let (tx, _) = builder.mock_build().unwrap();
        // No binding signature, because only t input and outputs
        assert!(tx.sapling_bundle.is_none());
    }

    #[test]
    fn binding_sig_present_if_shielded_spend() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1;

        let mut rng = OsRng;

        let note1 = to.create_note(50000, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)));
        let cmu1 = Node::from_cmu(&note1.cmu());
        let mut tree = CommitmentTree::<Node, 32>::empty();
        tree.append(cmu1).unwrap();
        let witness1 = IncrementalWitness::from_tree(tree);

        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();
        let mut builder = Builder::new(TEST_NETWORK, tx_height, None);

        // Create a tx with a sapling spend. binding_sig should be present
        builder
            .add_sapling_spend(extsk, *to.diversifier(), note1, witness1.path().unwrap())
            .unwrap();

        builder
            .add_transparent_output(
                &TransparentAddress::PublicKey([0; 20]),
                Amount::from_u64(40000).unwrap(),
            )
            .unwrap();

        // Expect a binding signature error, because our inputs aren't valid, but this shows
        // that a binding signature was attempted
        assert_matches!(
            builder.mock_build(),
            Err(Error::SaplingBuild(sapling_builder::Error::BindingSig))
        );
    }

    #[test]
    fn fails_on_negative_transparent_output() {
        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();
        let mut builder = Builder::new(TEST_NETWORK, tx_height, None);
        assert_eq!(
            builder.add_transparent_output(
                &TransparentAddress::PublicKey([0; 20]),
                Amount::from_i64(-1).unwrap(),
            ),
            Err(transparent_builder::Error::InvalidAmount)
        );
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
            let builder = Builder::new(TEST_NETWORK, tx_height, None);
            assert_matches!(
                builder.mock_build(),
                Err(Error::InsufficientFunds(MINIMUM_FEE))
            );
        }

        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let ovk = Some(dfvk.fvk().ovk);
        let to = dfvk.default_address().1;

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = Builder::new(TEST_NETWORK, tx_height, None);
            builder
                .add_sapling_output(
                    ovk,
                    to,
                    Amount::from_u64(50000).unwrap(),
                    MemoBytes::empty(),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(),
                Err(Error::InsufficientFunds(expected)) if
                    expected == (Amount::from_i64(50000).unwrap() + MINIMUM_FEE).unwrap()
            );
        }

        // Fail if there is only a transparent output
        // 0.0005 t-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = Builder::new(TEST_NETWORK, tx_height, None);
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(50000).unwrap(),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(),
                Err(Error::InsufficientFunds(expected)) if expected ==
                    (Amount::from_i64(50000).unwrap() + MINIMUM_FEE).unwrap()
            );
        }

        let note1 = to.create_note(59999, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)));
        let cmu1 = Node::from_cmu(&note1.cmu());
        let mut tree = CommitmentTree::<Node, 32>::empty();
        tree.append(cmu1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(tree.clone());

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.00059999 z-ZEC in
        {
            let mut builder = Builder::new(TEST_NETWORK, tx_height, None);
            builder
                .add_sapling_spend(
                    extsk.clone(),
                    *to.diversifier(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output(
                    ovk,
                    to,
                    Amount::from_u64(30000).unwrap(),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(20000).unwrap(),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(),
                Err(Error::InsufficientFunds(expected)) if expected == Amount::from_i64(1).unwrap()
            );
        }

        let note2 = to.create_note(1, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)));
        let cmu2 = Node::from_cmu(&note2.cmu());
        tree.append(cmu2).unwrap();
        witness1.append(cmu2).unwrap();
        let witness2 = IncrementalWitness::from_tree(tree);

        // Succeeds if there is sufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.0006 z-ZEC in
        //
        // (Still fails because we are using a MockTxProver which doesn't correctly
        // compute bindingSig.)
        {
            let mut builder = Builder::new(TEST_NETWORK, tx_height, None);
            builder
                .add_sapling_spend(
                    extsk.clone(),
                    *to.diversifier(),
                    note1,
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_spend(extsk, *to.diversifier(), note2, witness2.path().unwrap())
                .unwrap();
            builder
                .add_sapling_output(
                    ovk,
                    to,
                    Amount::from_u64(30000).unwrap(),
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(20000).unwrap(),
                )
                .unwrap();
            assert_matches!(
                builder.mock_build(),
                Err(Error::SaplingBuild(sapling_builder::Error::BindingSig))
            )
        }
    }
}
