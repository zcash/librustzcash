//! Types and functions for building Sapling transaction components.

use core::fmt;
use std::sync::mpsc::Sender;

use ff::Field;
use rand::{seq::SliceRandom, RngCore};

use crate::{
    consensus::{self, BlockHeight},
    keys::OutgoingViewingKey,
    memo::MemoBytes,
    sapling::{
        keys::SaplingIvk,
        note_encryption::sapling_note_encryption,
        prover::TxProver,
        redjubjub::{PrivateKey, Signature},
        spend_sig_internal,
        util::generate_random_rseed_internal,
        value::{NoteValue, ValueSum},
        Diversifier, MerklePath, Node, Note, PaymentAddress,
    },
    transaction::{
        builder::Progress,
        components::{
            amount::Amount,
            sapling::{
                fees, Authorization, Authorized, Bundle, GrothProofBytes, OutputDescription,
                SpendDescription,
            },
        },
    },
    zip32::ExtendedSpendingKey,
};

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See <https://github.com/zcash/zcash/issues/3615>.
const MIN_SHIELDED_OUTPUTS: usize = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    AnchorMismatch,
    BindingSig,
    InvalidAddress,
    InvalidAmount,
    SpendProof,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AnchorMismatch => {
                write!(f, "Anchor mismatch (anchors for all spends must be equal)")
            }
            Error::BindingSig => write!(f, "Failed to create bindingSig"),
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::SpendProof => write!(f, "Failed to create Sapling spend proof"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpendDescriptionInfo {
    extsk: ExtendedSpendingKey,
    diversifier: Diversifier,
    note: Note,
    alpha: jubjub::Fr,
    merkle_path: MerklePath,
}

impl fees::InputView<()> for SpendDescriptionInfo {
    fn note_id(&self) -> &() {
        // The builder does not make use of note identifiers, so we can just return the unit value.
        &()
    }

    fn value(&self) -> Amount {
        // An existing note to be spent must have a valid amount value.
        Amount::from_u64(self.note.value().inner()).unwrap()
    }
}

/// A struct containing the information required in order to construct a
/// Sapling output to a transaction.
#[derive(Clone)]
struct SaplingOutputInfo {
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<OutgoingViewingKey>,
    note: Note,
    memo: MemoBytes,
}

impl SaplingOutputInfo {
    fn new_internal<P: consensus::Parameters, R: RngCore>(
        params: &P,
        rng: &mut R,
        target_height: BlockHeight,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: NoteValue,
        memo: MemoBytes,
    ) -> Self {
        let rseed = generate_random_rseed_internal(params, target_height, rng);

        let note = Note::from_parts(to, value, rseed);

        SaplingOutputInfo { ovk, note, memo }
    }

    fn build<P: consensus::Parameters, Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut R,
    ) -> OutputDescription<GrothProofBytes> {
        let encryptor =
            sapling_note_encryption::<R, P>(self.ovk, self.note.clone(), self.memo, rng);

        let (zkproof, cv) = prover.output_proof(
            ctx,
            encryptor.esk().0,
            self.note.recipient(),
            self.note.rcm(),
            self.note.value().inner(),
        );

        let cmu = self.note.cmu();

        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu, rng);

        let epk = encryptor.epk();

        OutputDescription {
            cv,
            cmu,
            ephemeral_key: epk.to_bytes(),
            enc_ciphertext: enc_ciphertext.0,
            out_ciphertext,
            zkproof,
        }
    }
}

impl fees::OutputView for SaplingOutputInfo {
    fn value(&self) -> Amount {
        Amount::from_u64(self.note.value().inner())
            .expect("Note values should be checked at construction.")
    }
}

/// Metadata about a transaction created by a [`SaplingBuilder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaplingMetadata {
    spend_indices: Vec<usize>,
    output_indices: Vec<usize>,
}

impl SaplingMetadata {
    pub fn empty() -> Self {
        SaplingMetadata {
            spend_indices: vec![],
            output_indices: vec![],
        }
    }

    /// Returns the index within the transaction of the [`SpendDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_spend`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first spend
    /// they added (via the first call to [`SaplingBuilder::add_spend`]) is the first
    /// [`SpendDescription`] in the transaction.
    pub fn spend_index(&self, n: usize) -> Option<usize> {
        self.spend_indices.get(n).copied()
    }

    /// Returns the index within the transaction of the [`OutputDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_output`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`SaplingBuilder::add_output`]) is the first
    /// [`OutputDescription`] in the transaction.
    pub fn output_index(&self, n: usize) -> Option<usize> {
        self.output_indices.get(n).copied()
    }
}

pub struct SaplingBuilder<P> {
    params: P,
    anchor: Option<bls12_381::Scalar>,
    target_height: BlockHeight,
    value_balance: ValueSum,
    spends: Vec<SpendDescriptionInfo>,
    outputs: Vec<SaplingOutputInfo>,
}

#[derive(Clone)]
pub struct Unauthorized {
    tx_metadata: SaplingMetadata,
}

impl std::fmt::Debug for Unauthorized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Unauthorized")
    }
}

impl Authorization for Unauthorized {
    type SpendProof = GrothProofBytes;
    type OutputProof = GrothProofBytes;
    type AuthSig = SpendDescriptionInfo;
}

impl<P> SaplingBuilder<P> {
    pub fn new(params: P, target_height: BlockHeight) -> Self {
        SaplingBuilder {
            params,
            anchor: None,
            target_height,
            value_balance: ValueSum::zero(),
            spends: vec![],
            outputs: vec![],
        }
    }

    /// Returns the list of Sapling inputs that will be consumed by the transaction being
    /// constructed.
    pub fn inputs(&self) -> &[impl fees::InputView<()>] {
        &self.spends
    }

    /// Returns the Sapling outputs that will be produced by the transaction being constructed
    pub fn outputs(&self) -> &[impl fees::OutputView] {
        &self.outputs
    }

    /// Returns the number of outputs that will be present in the Sapling bundle built by
    /// this builder.
    ///
    /// This may be larger than the number of outputs that have been added to the builder,
    /// depending on whether padding is going to be applied.
    pub(in crate::transaction) fn bundle_output_count(&self) -> usize {
        // This matches the padding behaviour in `Self::build`.
        match self.spends.len() {
            0 => self.outputs.len(),
            _ => std::cmp::max(MIN_SHIELDED_OUTPUTS, self.outputs.len()),
        }
    }

    /// Returns the net value represented by the spends and outputs added to this builder,
    /// or an error if the values added to this builder overflow the range of a Zcash
    /// monetary amount.
    fn try_value_balance(&self) -> Result<Amount, Error> {
        self.value_balance
            .try_into()
            .map_err(|_| ())
            .and_then(Amount::from_i64)
            .map_err(|()| Error::InvalidAmount)
    }

    /// Returns the net value represented by the spends and outputs added to this builder.
    pub fn value_balance(&self) -> Amount {
        self.try_value_balance()
            .expect("we check this when mutating self.value_balance")
    }
}

impl<P: consensus::Parameters> SaplingBuilder<P> {
    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_spend<R: RngCore>(
        &mut self,
        mut rng: R,
        extsk: ExtendedSpendingKey,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath,
    ) -> Result<(), Error> {
        // Consistency check: all anchors must equal the first one
        let node = Node::from_cmu(&note.cmu());
        if let Some(anchor) = self.anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(node).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.anchor = Some(merkle_path.root(node).into())
        }

        let alpha = jubjub::Fr::random(&mut rng);

        self.value_balance = (self.value_balance + note.value()).ok_or(Error::InvalidAmount)?;
        self.try_value_balance()?;

        self.spends.push(SpendDescriptionInfo {
            extsk,
            diversifier,
            note,
            alpha,
            merkle_path,
        });

        Ok(())
    }

    /// Adds a Sapling address to send funds to.
    #[allow(clippy::too_many_arguments)]
    pub fn add_output<R: RngCore>(
        &mut self,
        mut rng: R,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: NoteValue,
        memo: MemoBytes,
    ) -> Result<(), Error> {
        let output = SaplingOutputInfo::new_internal(
            &self.params,
            &mut rng,
            self.target_height,
            ovk,
            to,
            value,
            memo,
        );

        self.value_balance = (self.value_balance - value).ok_or(Error::InvalidAddress)?;
        self.try_value_balance()?;

        self.outputs.push(output);

        Ok(())
    }

    pub fn build<Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        mut rng: R,
        target_height: BlockHeight,
        progress_notifier: Option<&Sender<Progress>>,
    ) -> Result<Option<Bundle<Unauthorized>>, Error> {
        let value_balance = self.try_value_balance()?;

        // Record initial positions of spends and outputs
        let params = self.params;
        let mut indexed_spends: Vec<_> = self.spends.into_iter().enumerate().collect();
        let mut indexed_outputs: Vec<_> = self
            .outputs
            .iter()
            .enumerate()
            .map(|(i, o)| Some((i, o)))
            .collect();

        // Set up the transaction metadata that will be used to record how
        // inputs and outputs are shuffled.
        let mut tx_metadata = SaplingMetadata::empty();
        tx_metadata.spend_indices.resize(indexed_spends.len(), 0);
        tx_metadata.output_indices.resize(indexed_outputs.len(), 0);

        // Pad Sapling outputs
        if !indexed_spends.is_empty() {
            while indexed_outputs.len() < MIN_SHIELDED_OUTPUTS {
                indexed_outputs.push(None);
            }
        }

        // Randomize order of inputs and outputs
        indexed_spends.shuffle(&mut rng);
        indexed_outputs.shuffle(&mut rng);

        // Keep track of the total number of steps computed
        let total_progress = indexed_spends.len() as u32 + indexed_outputs.len() as u32;
        let mut progress = 0u32;

        // Create Sapling SpendDescriptions
        let shielded_spends: Vec<SpendDescription<Unauthorized>> = if !indexed_spends.is_empty() {
            let anchor = self
                .anchor
                .expect("Sapling anchor must be set if Sapling spends are present.");

            indexed_spends
                .into_iter()
                .enumerate()
                .map(|(i, (pos, spend))| {
                    let proof_generation_key = spend.extsk.expsk.proof_generation_key();

                    let nullifier = spend.note.nf(
                        &proof_generation_key.to_viewing_key().nk,
                        u64::try_from(spend.merkle_path.position())
                            .expect("Sapling note commitment tree position must fit into a u64"),
                    );

                    let (zkproof, cv, rk) = prover
                        .spend_proof(
                            ctx,
                            proof_generation_key,
                            spend.diversifier,
                            *spend.note.rseed(),
                            spend.alpha,
                            spend.note.value().inner(),
                            anchor,
                            spend.merkle_path.clone(),
                        )
                        .map_err(|_| Error::SpendProof)?;

                    // Record the post-randomized spend location
                    tx_metadata.spend_indices[pos] = i;

                    // Update progress and send a notification on the channel
                    progress += 1;
                    if let Some(sender) = progress_notifier {
                        // If the send fails, we should ignore the error, not crash.
                        sender
                            .send(Progress::new(progress, Some(total_progress)))
                            .unwrap_or(());
                    }

                    Ok(SpendDescription {
                        cv,
                        anchor,
                        nullifier,
                        rk,
                        zkproof,
                        spend_auth_sig: spend,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?
        } else {
            vec![]
        };

        // Create Sapling OutputDescriptions
        let shielded_outputs: Vec<OutputDescription<GrothProofBytes>> = indexed_outputs
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                let result = if let Some((pos, output)) = output {
                    // Record the post-randomized output location
                    tx_metadata.output_indices[pos] = i;

                    output.clone().build::<P, _, _>(prover, ctx, &mut rng)
                } else {
                    // This is a dummy output
                    let dummy_note = {
                        let payment_address = {
                            let mut diversifier = Diversifier([0; 11]);
                            loop {
                                rng.fill_bytes(&mut diversifier.0);
                                let dummy_ivk = SaplingIvk(jubjub::Fr::random(&mut rng));
                                if let Some(addr) = dummy_ivk.to_payment_address(diversifier) {
                                    break addr;
                                }
                            }
                        };

                        let rseed =
                            generate_random_rseed_internal(&params, target_height, &mut rng);

                        Note::from_parts(payment_address, NoteValue::from_raw(0), rseed)
                    };

                    let esk = dummy_note.generate_or_derive_esk_internal(&mut rng);
                    let epk = esk.derive_public(
                        dummy_note
                            .recipient()
                            .diversifier()
                            .g_d()
                            .expect("checked at construction")
                            .into(),
                    );

                    let (zkproof, cv) = prover.output_proof(
                        ctx,
                        esk.0,
                        dummy_note.recipient(),
                        dummy_note.rcm(),
                        dummy_note.value().inner(),
                    );

                    let cmu = dummy_note.cmu();

                    let mut enc_ciphertext = [0u8; 580];
                    let mut out_ciphertext = [0u8; 80];
                    rng.fill_bytes(&mut enc_ciphertext[..]);
                    rng.fill_bytes(&mut out_ciphertext[..]);

                    OutputDescription {
                        cv,
                        cmu,
                        ephemeral_key: epk.to_bytes(),
                        enc_ciphertext,
                        out_ciphertext,
                        zkproof,
                    }
                };

                // Update progress and send a notification on the channel
                progress += 1;
                if let Some(sender) = progress_notifier {
                    // If the send fails, we should ignore the error, not crash.
                    sender
                        .send(Progress::new(progress, Some(total_progress)))
                        .unwrap_or(());
                }

                result
            })
            .collect();

        let bundle = if shielded_spends.is_empty() && shielded_outputs.is_empty() {
            None
        } else {
            Some(Bundle {
                shielded_spends,
                shielded_outputs,
                value_balance,
                authorization: Unauthorized { tx_metadata },
            })
        };

        Ok(bundle)
    }
}

impl SpendDescription<Unauthorized> {
    pub fn apply_signature(&self, spend_auth_sig: Signature) -> SpendDescription<Authorized> {
        SpendDescription {
            cv: self.cv.clone(),
            anchor: self.anchor,
            nullifier: self.nullifier,
            rk: self.rk.clone(),
            zkproof: self.zkproof,
            spend_auth_sig,
        }
    }
}

impl Bundle<Unauthorized> {
    pub fn apply_signatures<Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut R,
        sighash_bytes: &[u8; 32],
    ) -> Result<(Bundle<Authorized>, SaplingMetadata), Error> {
        let binding_sig = prover
            .binding_sig(ctx, self.value_balance, sighash_bytes)
            .map_err(|_| Error::BindingSig)?;

        Ok((
            Bundle {
                shielded_spends: self
                    .shielded_spends
                    .iter()
                    .map(|spend| {
                        spend.apply_signature(spend_sig_internal(
                            PrivateKey(spend.spend_auth_sig.extsk.expsk.ask),
                            spend.spend_auth_sig.alpha,
                            sighash_bytes,
                            rng,
                        ))
                    })
                    .collect(),
                shielded_outputs: self.shielded_outputs,
                value_balance: self.value_balance,
                authorization: Authorized { binding_sig },
            },
            self.authorization.tx_metadata,
        ))
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        consensus::{
            testing::{arb_branch_id, arb_height},
            TEST_NETWORK,
        },
        sapling::{
            prover::mock::MockTxProver,
            testing::{arb_node, arb_note},
            value::testing::arb_positive_note_value,
            Diversifier,
        },
        transaction::components::{
            amount::MAX_MONEY,
            sapling::{Authorized, Bundle},
        },
        zip32::sapling::testing::arb_extended_spending_key,
    };
    use incrementalmerkletree::{
        frontier::testing::arb_commitment_tree, witness::IncrementalWitness,
    };

    use super::SaplingBuilder;

    prop_compose! {
        fn arb_bundle()(n_notes in 1..30usize)(
            extsk in arb_extended_spending_key(),
            spendable_notes in vec(
                arb_positive_note_value(MAX_MONEY as u64 / 10000).prop_flat_map(arb_note),
                n_notes
            ),
            commitment_trees in vec(
                arb_commitment_tree::<_, _, 32>(n_notes, arb_node()).prop_map(
                    |t| IncrementalWitness::from_tree(t).path().unwrap()
                ),
                n_notes
            ),
            diversifiers in vec(prop::array::uniform11(any::<u8>()).prop_map(Diversifier), n_notes),
            target_height in arb_branch_id().prop_flat_map(|b| arb_height(b, &TEST_NETWORK)),
            rng_seed in prop::array::uniform32(any::<u8>()),
            fake_sighash_bytes in prop::array::uniform32(any::<u8>()),
        ) -> Bundle<Authorized> {
            let mut builder = SaplingBuilder::new(TEST_NETWORK, target_height.unwrap());
            let mut rng = StdRng::from_seed(rng_seed);

            for ((note, path), diversifier) in spendable_notes.into_iter().zip(commitment_trees.into_iter()).zip(diversifiers.into_iter()) {
                builder.add_spend(
                    &mut rng,
                    extsk.clone(),
                    diversifier,
                    note,
                    path
                ).unwrap();
            }

            let prover = MockTxProver;

            let bundle = builder.build(
                &prover,
                &mut (),
                &mut rng,
                target_height.unwrap(),
                None
            ).unwrap().unwrap();

            let (bundle, _) = bundle.apply_signatures(
                &prover,
                &mut (),
                &mut rng,
                &fake_sighash_bytes,
            ).unwrap();

            bundle
        }
    }
}
