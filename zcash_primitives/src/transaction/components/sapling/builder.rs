//! Types and functions for building Sapling transaction components.

use std::fmt;
use std::marker::PhantomData;
use std::sync::mpsc::Sender;

use ff::Field;
use rand::{seq::SliceRandom, CryptoRng, RngCore};

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
        components::{amount::Amount, OutputDescription, SpendDescription},
    },
    zip32::ExtendedSpendingKey,
};

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See <https://github.com/zcash/zcash/issues/3615>.
const MIN_SHIELDED_OUTPUTS: usize = 2;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidAmount,
    InvalidAddress,
    AnchorMismatch,
    SpendProof,
    BindingSig,
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

struct SpendDescriptionInfo {
    extsk: ExtendedSpendingKey,
    diversifier: Diversifier,
    note: Note,
    alpha: jubjub::Fr,
    merkle_path: MerklePath<Node>,
}

#[derive(Clone)]
pub struct SaplingOutput<P: consensus::Parameters> {
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<OutgoingViewingKey>,
    to: PaymentAddress,
    note: Note,
    memo: MemoBytes,
    _params: PhantomData<P>,
}

impl<P: consensus::Parameters> SaplingOutput<P> {
    pub fn new<R: RngCore + CryptoRng>(
        params: &P,
        target_height: BlockHeight,
        rng: &mut R,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<MemoBytes>,
    ) -> Result<Self, Error> {
        Self::new_internal(params, target_height, rng, ovk, to, value, memo)
    }

    fn new_internal<R: RngCore>(
        params: &P,
        target_height: BlockHeight,
        rng: &mut R,
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
            _params: PhantomData::default(),
        })
    }

    pub fn build<Pr: TxProver, R: RngCore + CryptoRng>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut R,
    ) -> OutputDescription {
        self.build_internal(prover, ctx, rng)
    }

    fn build_internal<Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut R,
    ) -> OutputDescription {
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

/// Metadata about a transaction created by a [`Builder`].
#[derive(Debug, PartialEq)]
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
    /// to the `n`-th call to [`Builder::add_sapling_spend`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first spend
    /// they added (via the first call to [`Builder::add_sapling_spend`]) is the first
    /// [`SpendDescription`] in the transaction.
    pub fn spend_index(&self, n: usize) -> Option<usize> {
        self.spend_indices.get(n).copied()
    }

    /// Returns the index within the transaction of the [`OutputDescription`] corresponding
    /// to the `n`-th call to [`Builder::add_sapling_output`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`Builder::add_sapling_output`]) is the first
    /// [`OutputDescription`] in the transaction.
    pub fn output_index(&self, n: usize) -> Option<usize> {
        self.output_indices.get(n).copied()
    }
}

pub struct SaplingBuilder<P: consensus::Parameters> {
    params: P,
    anchor: Option<bls12_381::Scalar>,
    target_height: BlockHeight,
    value_balance: Amount,
    spends: Vec<SpendDescriptionInfo>,
    outputs: Vec<SaplingOutput<P>>,
}

impl<P: consensus::Parameters> SaplingBuilder<P> {
    pub fn empty(params: P, target_height: BlockHeight) -> Self {
        SaplingBuilder {
            params,
            anchor: None,
            target_height,
            value_balance: Amount::zero(),
            spends: vec![],
            outputs: vec![],
        }
    }

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
            self.target_height,
            &mut rng,
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
        &self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        mut rng: R,
        target_height: BlockHeight,
        progress_notifier: Option<&Sender<Progress>>,
    ) -> Result<
        (
            Vec<SpendDescription>,
            Vec<OutputDescription>,
            SaplingMetadata,
        ),
        Error,
    > {
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
        let spend_descs = if !indexed_spends.is_empty() {
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
                        spend_auth_sig: None,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?
        } else {
            vec![]
        };

        // Create Sapling OutputDescriptions
        let output_descs = indexed_outputs
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                if let Some((pos, output)) = output {
                    // Record the post-randomized output location
                    tx_metadata.output_indices[pos] = i;

                    output.clone().build_internal(prover, ctx, &mut rng)
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

                        let rseed = generate_random_rseed_internal(&self.params, target_height, &mut rng);

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

                    // Update progress and send a notification on the channel
                    progress += 1;
                    if let Some(sender) = progress_notifier {
                        // If the send fails, we should ignore the error, not crash.
                        sender
                            .send(Progress::new(progress, Some(total_progress)))
                            .unwrap_or(());
                    }

                    OutputDescription {
                        cv,
                        cmu,
                        ephemeral_key: epk.into(),
                        enc_ciphertext,
                        out_ciphertext,
                        zkproof,
                    }
                }
            })
            .collect();

        Ok((spend_descs, output_descs, tx_metadata))
    }

    pub fn create_signatures<Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut R,
        sighash_bytes: &[u8; 32],
        tx_metadata: &SaplingMetadata,
    ) -> Result<(Vec<Option<Signature>>, Option<Signature>), Error> {
        // Create Sapling spendAuth and binding signatures
        let mut spend_sigs = vec![None; self.spends.len()];
        for (i, spend) in self.spends.into_iter().enumerate() {
            spend_sigs[tx_metadata.spend_indices[i]] = Some(spend_sig_internal(
                PrivateKey(spend.extsk.expsk.ask),
                spend.alpha,
                sighash_bytes,
                rng,
            ));
        }

        // Add a binding signature if needed
        let binding_sig =
            if tx_metadata.spend_indices.is_empty() && tx_metadata.output_indices.is_empty() {
                None
            } else {
                Some(
                    prover
                        .binding_sig(ctx, self.value_balance, &sighash_bytes)
                        .map_err(|_| Error::BindingSig)?,
                )
            };

        Ok((spend_sigs, binding_sig))
    }
}
