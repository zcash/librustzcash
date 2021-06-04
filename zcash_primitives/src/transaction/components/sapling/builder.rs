//! Types and functions for building Sapling transaction components.

use std::fmt;
use std::sync::mpsc::Sender;

use ff::Field;
use rand::{seq::SliceRandom, RngCore};

use crate::{
    consensus::{self, BlockHeight},
    memo::MemoBytes,
    merkle_tree::MerklePath,
    sapling::{
        keys::OutgoingViewingKey,
        note_encryption::sapling_note_encryption,
        prover::TxProver,
        redjubjub::{PrivateKey, Signature},
        spend_sig_internal,
        util::generate_random_rseed_internal,
        Diversifier, Node, Note, PaymentAddress,
    },
    transaction::{
        builder::Progress,
        components::{
            amount::Amount,
            sapling::{
                Authorization, Authorized, Bundle, GrothProofBytes, OutputDescription,
                SpendDescription,
            },
        },
    },
    zip32::ExtendedSpendingKey,
};

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See <https://github.com/zcash/zcash/issues/3615>.
const MIN_SHIELDED_OUTPUTS: usize = 2;

#[derive(Debug, PartialEq)]
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

#[derive(Clone)]
struct SpendDescriptionInfo {
    extsk: ExtendedSpendingKey,
    diversifier: Diversifier,
    note: Note,
    alpha: jubjub::Fr,
    merkle_path: MerklePath<Node>,
}

#[derive(Clone)]
struct SaplingOutput {
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<OutgoingViewingKey>,
    to: PaymentAddress,
    note: Note,
    memo: MemoBytes,
}

impl SaplingOutput {
    fn new_internal<P: consensus::Parameters, R: RngCore>(
        params: &P,
        rng: &mut R,
        target_height: BlockHeight,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<MemoBytes>,
    ) -> Result<Self, Error> {
        let g_d = to.g_d().ok_or(Error::InvalidAddress)?;
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        let rseed = generate_random_rseed_internal(params, target_height, rng);

        let note = Note {
            g_d,
            pk_d: *to.pk_d(),
            value: value.into(),
            rseed,
        };

        Ok(SaplingOutput {
            ovk,
            to,
            note,
            memo: memo.unwrap_or_else(MemoBytes::empty),
        })
    }

    fn build<P: consensus::Parameters, Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut R,
    ) -> OutputDescription<GrothProofBytes> {
        let encryptor = sapling_note_encryption::<R, P>(
            self.ovk,
            self.note.clone(),
            self.to.clone(),
            self.memo,
            rng,
        );

        let (zkproof, cv) = prover.output_proof(
            ctx,
            *encryptor.esk(),
            self.to,
            self.note.rcm(),
            self.note.value,
        );

        let cmu = self.note.cmu();

        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu, rng);

        let ephemeral_key = *encryptor.epk();

        OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        }
    }
}

/// Metadata about a transaction created by a [`SaplingBuilder`].
#[derive(Debug, Clone, PartialEq)]
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
    value_balance: Amount,
    spends: Vec<SpendDescriptionInfo>,
    outputs: Vec<SaplingOutput>,
}

#[derive(Clone)]
pub struct Unauthorized {
    spends: Vec<SpendDescriptionInfo>,
    tx_metadata: SaplingMetadata,
}

impl std::fmt::Debug for Unauthorized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Unauthorized")
    }
}

impl Authorization for Unauthorized {
    type Proof = GrothProofBytes;
    type AuthSig = ();
}

impl<P: consensus::Parameters> SaplingBuilder<P> {
    pub fn new(params: P, target_height: BlockHeight) -> Self {
        SaplingBuilder {
            params,
            anchor: None,
            target_height,
            value_balance: Amount::zero(),
            spends: vec![],
            outputs: vec![],
        }
    }

    /// Returns the net value represented by the spends and outputs added to this builder.
    pub fn value_balance(&self) -> Amount {
        self.value_balance
    }

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
        merkle_path: MerklePath<Node>,
    ) -> Result<(), Error> {
        // Consistency check: all anchors must equal the first one
        let cmu = Node::new(note.cmu().into());
        if let Some(anchor) = self.anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(cmu).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.anchor = Some(merkle_path.root(cmu).into())
        }

        let alpha = jubjub::Fr::random(&mut rng);

        self.value_balance += Amount::from_u64(note.value).map_err(|_| Error::InvalidAmount)?;

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
        value: Amount,
        memo: Option<MemoBytes>,
    ) -> Result<(), Error> {
        let output = SaplingOutput::new_internal(
            &self.params,
            &mut rng,
            self.target_height,
            ovk,
            to,
            value,
            memo,
        )?;

        self.value_balance -= value;

        self.outputs.push(output);

        Ok(())
    }

    /// Send change to the specified change address. If no change address
    /// was set, send change to the first Sapling address given as input.
    pub fn get_candidate_change_address(&self) -> Option<(OutgoingViewingKey, PaymentAddress)> {
        self.spends.first().and_then(|spend| {
            PaymentAddress::from_parts(spend.diversifier, spend.note.pk_d)
                .map(|addr| (spend.extsk.expsk.ovk, addr))
        })
    }

    pub fn build<Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        mut rng: R,
        target_height: BlockHeight,
        progress_notifier: Option<&Sender<Progress>>,
    ) -> Result<Option<Bundle<Unauthorized>>, Error> {
        // Record initial positions of spends and outputs
        let mut indexed_spends: Vec<_> = self.spends.iter().enumerate().collect();
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
                .iter()
                .enumerate()
                .map(|(i, (pos, spend))| {
                    let proof_generation_key = spend.extsk.expsk.proof_generation_key();

                    let nullifier = spend.note.nf(
                        &proof_generation_key.to_viewing_key(),
                        spend.merkle_path.position,
                    );

                    let (zkproof, cv, rk) = prover
                        .spend_proof(
                            ctx,
                            proof_generation_key,
                            spend.diversifier,
                            spend.note.rseed,
                            spend.alpha,
                            spend.note.value,
                            anchor,
                            spend.merkle_path.clone(),
                        )
                        .map_err(|_| Error::SpendProof)?;

                    // Record the post-randomized spend location
                    tx_metadata.spend_indices[*pos] = i;

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
                        spend_auth_sig: (),
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
                    let (dummy_to, dummy_note) = {
                        let (diversifier, g_d) = {
                            let mut diversifier;
                            let g_d;
                            loop {
                                let mut d = [0; 11];
                                rng.fill_bytes(&mut d);
                                diversifier = Diversifier(d);
                                if let Some(val) = diversifier.g_d() {
                                    g_d = val;
                                    break;
                                }
                            }
                            (diversifier, g_d)
                        };
                        let (pk_d, payment_address) = loop {
                            let dummy_ivk = jubjub::Fr::random(&mut rng);
                            let pk_d = g_d * dummy_ivk;
                            if let Some(addr) = PaymentAddress::from_parts(diversifier, pk_d) {
                                break (pk_d, addr);
                            }
                        };

                        let rseed =
                            generate_random_rseed_internal(&self.params, target_height, &mut rng);

                        (
                            payment_address,
                            Note {
                                g_d,
                                pk_d,
                                rseed,
                                value: 0,
                            },
                        )
                    };

                    let esk = dummy_note.generate_or_derive_esk_internal(&mut rng);
                    let epk = dummy_note.g_d * esk;

                    let (zkproof, cv) =
                        prover.output_proof(ctx, esk, dummy_to, dummy_note.rcm(), dummy_note.value);

                    let cmu = dummy_note.cmu();

                    let mut enc_ciphertext = [0u8; 580];
                    let mut out_ciphertext = [0u8; 80];
                    rng.fill_bytes(&mut enc_ciphertext[..]);
                    rng.fill_bytes(&mut out_ciphertext[..]);

                    OutputDescription {
                        cv,
                        cmu,
                        ephemeral_key: epk.into(),
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
                value_balance: self.value_balance,
                authorization: Unauthorized {
                    spends: self.spends,
                    tx_metadata,
                },
            })
        };

        Ok(bundle)
    }
}

impl SpendDescription<Unauthorized> {
    pub fn apply_signature(&self, spend_auth_sig: Signature) -> SpendDescription<Authorized> {
        SpendDescription {
            cv: self.cv,
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
        // Create Sapling spendAuth signatures. These must be properly ordered with respect to the
        // shuffle that is described by tx_metadata.
        let mut spend_sigs = vec![None; self.authorization.spends.len()];
        for (i, spend) in self.authorization.spends.into_iter().enumerate() {
            spend_sigs[self.authorization.tx_metadata.spend_indices[i]] = Some(spend_sig_internal(
                PrivateKey(spend.extsk.expsk.ask),
                spend.alpha,
                sighash_bytes,
                rng,
            ));
        }

        let spend_sigs = spend_sigs
            .into_iter()
            .collect::<Option<Vec<Signature>>>()
            .unwrap_or_default();

        let binding_sig = prover
            .binding_sig(ctx, self.value_balance, sighash_bytes)
            .map_err(|_| Error::BindingSig)?;

        Ok((
            Bundle {
                shielded_spends: self
                    .shielded_spends
                    .iter()
                    .zip(spend_sigs.iter())
                    .map(|(spend, sig)| spend.apply_signature(*sig))
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
        merkle_tree::{testing::arb_commitment_tree, IncrementalWitness},
        sapling::{
            prover::{mock::MockTxProver, TxProver},
            testing::{arb_node, arb_note, arb_positive_note_value},
            Diversifier,
        },
        transaction::components::{
            amount::MAX_MONEY,
            sapling::{Authorized, Bundle},
        },
        zip32::testing::arb_extended_spending_key,
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
                arb_commitment_tree(n_notes, arb_node()).prop_map(
                    |t| IncrementalWitness::from_tree(&t).path().unwrap()
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
            let mut ctx = prover.new_sapling_proving_context();

            let bundle = builder.build(
                &prover,
                &mut ctx,
                &mut rng,
                target_height.unwrap(),
                None
            ).unwrap().unwrap();

            let (bundle, _) = bundle.apply_signatures(
                &prover,
                &mut ctx,
                &mut rng,
                &fake_sighash_bytes,
            ).unwrap();

            bundle
        }
    }
}
