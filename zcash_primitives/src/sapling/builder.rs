//! Types and functions for building Sapling transaction components.

use core::fmt;
use std::{marker::PhantomData, sync::mpsc::Sender};

use ff::Field;
use rand::{seq::SliceRandom, RngCore};
use rand_core::CryptoRng;

use crate::{
    keys::OutgoingViewingKey,
    memo::MemoBytes,
    sapling::{
        self,
        bundle::{
            Authorization, Authorized, Bundle, GrothProofBytes, MapAuth, OutputDescription,
            SpendDescription,
        },
        constants::{SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR},
        note_encryption::{sapling_note_encryption, Zip212Enforcement},
        prover::{OutputProver, SpendProver},
        redjubjub::{PrivateKey, PublicKey, Signature},
        spend_sig_internal,
        util::generate_random_rseed_internal,
        value::{
            CommitmentSum, NoteValue, TrapdoorSum, ValueCommitTrapdoor, ValueCommitment, ValueSum,
        },
        verify_spend_sig, Diversifier, MerklePath, Node, Note, PaymentAddress, ProofGenerationKey,
        SaplingIvk,
    },
    transaction::{
        builder::Progress,
        components::{
            amount::{Amount, NonNegativeAmount},
            sapling::fees,
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
    /// A signature is valid for more than one input. This should never happen if `alpha`
    /// is sampled correctly, and indicates a critical failure in randomness generation.
    DuplicateSignature,
    InvalidAddress,
    InvalidAmount,
    /// External signature is not valid.
    InvalidExternalSignature,
    /// A bundle could not be built because required signatures were missing.
    MissingSignatures,
    SpendProof,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AnchorMismatch => {
                write!(f, "Anchor mismatch (anchors for all spends must be equal)")
            }
            Error::BindingSig => write!(f, "Failed to create bindingSig"),
            Error::DuplicateSignature => write!(f, "Signature valid for more than one input"),
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::InvalidExternalSignature => write!(f, "External signature was invalid"),
            Error::MissingSignatures => write!(f, "Required signatures were missing during build"),
            Error::SpendProof => write!(f, "Failed to create Sapling spend proof"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpendDescriptionInfo {
    proof_generation_key: ProofGenerationKey,
    diversifier: Diversifier,
    note: Note,
    alpha: jubjub::Fr,
    merkle_path: MerklePath,
    rcv: ValueCommitTrapdoor,
}

impl fees::InputView<()> for SpendDescriptionInfo {
    fn note_id(&self) -> &() {
        // The builder does not make use of note identifiers, so we can just return the unit value.
        &()
    }

    fn value(&self) -> NonNegativeAmount {
        // An existing note to be spent must have a valid amount value.
        NonNegativeAmount::from_u64(self.note.value().inner()).unwrap()
    }
}

impl SpendDescriptionInfo {
    fn new_internal<R: RngCore>(
        mut rng: &mut R,
        extsk: &ExtendedSpendingKey,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath,
    ) -> Self {
        SpendDescriptionInfo {
            proof_generation_key: extsk.expsk.proof_generation_key(),
            diversifier,
            note,
            alpha: jubjub::Fr::random(&mut rng),
            merkle_path,
            rcv: ValueCommitTrapdoor::random(rng),
        }
    }

    fn build<Pr: SpendProver>(
        self,
        anchor: Option<bls12_381::Scalar>,
    ) -> Result<SpendDescription<InProgress<Unproven, Unsigned>>, Error> {
        let anchor = anchor.expect("Sapling anchor must be set if Sapling spends are present.");

        // Construct the value commitment.
        let cv = ValueCommitment::derive(self.note.value(), self.rcv.clone());

        let ak = PublicKey(self.proof_generation_key.ak.into());

        // This is the result of the re-randomization, we compute it for the caller
        let rk = ak.randomize(self.alpha, SPENDING_KEY_GENERATOR);

        let nullifier = self.note.nf(
            &self.proof_generation_key.to_viewing_key().nk,
            u64::try_from(self.merkle_path.position())
                .expect("Sapling note commitment tree position must fit into a u64"),
        );

        let zkproof = Pr::prepare_circuit(
            self.proof_generation_key,
            self.diversifier,
            *self.note.rseed(),
            self.note.value(),
            self.alpha,
            self.rcv,
            anchor,
            self.merkle_path.clone(),
        )
        .ok_or(Error::SpendProof)?;

        Ok(SpendDescription::from_parts(
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            SigningParts {
                ak,
                alpha: self.alpha,
            },
        ))
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
    rcv: ValueCommitTrapdoor,
}

impl SaplingOutputInfo {
    fn dummy<R: RngCore>(mut rng: &mut R, zip212_enforcement: Zip212Enforcement) -> Self {
        // This is a dummy output
        let dummy_to = {
            let mut diversifier = Diversifier([0; 11]);
            loop {
                rng.fill_bytes(&mut diversifier.0);
                let dummy_ivk = SaplingIvk(jubjub::Fr::random(&mut rng));
                if let Some(addr) = dummy_ivk.to_payment_address(diversifier) {
                    break addr;
                }
            }
        };

        Self::new_internal(
            rng,
            None,
            dummy_to,
            NoteValue::from_raw(0),
            MemoBytes::empty(),
            zip212_enforcement,
        )
    }

    fn new_internal<R: RngCore>(
        rng: &mut R,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: NoteValue,
        memo: MemoBytes,
        zip212_enforcement: Zip212Enforcement,
    ) -> Self {
        let rseed = generate_random_rseed_internal(zip212_enforcement, rng);

        let note = Note::from_parts(to, value, rseed);

        SaplingOutputInfo {
            ovk,
            note,
            memo,
            rcv: ValueCommitTrapdoor::random(rng),
        }
    }

    fn build<Pr: OutputProver, R: RngCore>(
        self,
        rng: &mut R,
    ) -> OutputDescription<sapling::circuit::Output> {
        let encryptor = sapling_note_encryption::<R>(self.ovk, self.note.clone(), self.memo, rng);

        // Construct the value commitment.
        let cv = ValueCommitment::derive(self.note.value(), self.rcv.clone());

        // Prepare the circuit that will be used to construct the proof.
        let zkproof = Pr::prepare_circuit(
            encryptor.esk().0,
            self.note.recipient(),
            self.note.rcm(),
            self.note.value(),
            self.rcv,
        );

        let cmu = self.note.cmu();

        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu, rng);

        let epk = encryptor.epk();

        OutputDescription::from_parts(
            cv,
            cmu,
            epk.to_bytes(),
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        )
    }
}

impl fees::OutputView for SaplingOutputInfo {
    fn value(&self) -> NonNegativeAmount {
        NonNegativeAmount::from_u64(self.note.value().inner())
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

pub struct SaplingBuilder {
    anchor: Option<bls12_381::Scalar>,
    value_balance: ValueSum,
    spends: Vec<SpendDescriptionInfo>,
    outputs: Vec<SaplingOutputInfo>,
    zip212_enforcement: Zip212Enforcement,
}

impl SaplingBuilder {
    pub fn new(zip212_enforcement: Zip212Enforcement) -> Self {
        SaplingBuilder {
            anchor: None,
            value_balance: ValueSum::zero(),
            spends: vec![],
            outputs: vec![],
            zip212_enforcement,
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
    pub(crate) fn bundle_output_count(&self) -> usize {
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

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_spend<R: RngCore>(
        &mut self,
        mut rng: R,
        extsk: &ExtendedSpendingKey,
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

        self.value_balance = (self.value_balance + note.value()).ok_or(Error::InvalidAmount)?;
        self.try_value_balance()?;

        let spend =
            SpendDescriptionInfo::new_internal(&mut rng, extsk, diversifier, note, merkle_path);

        self.spends.push(spend);

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
            &mut rng,
            ovk,
            to,
            value,
            memo,
            self.zip212_enforcement,
        );

        self.value_balance = (self.value_balance - value).ok_or(Error::InvalidAddress)?;
        self.try_value_balance()?;

        self.outputs.push(output);

        Ok(())
    }

    pub fn build<SP: SpendProver, OP: OutputProver, R: RngCore>(
        self,
        mut rng: R,
    ) -> Result<Option<(UnauthorizedBundle, SaplingMetadata)>, Error> {
        let value_balance = self.try_value_balance()?;

        // Record initial positions of spends and outputs
        let mut indexed_spends: Vec<_> = self.spends.into_iter().enumerate().collect();
        let mut indexed_outputs: Vec<_> = self
            .outputs
            .into_iter()
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

        // Record the transaction metadata and create dummy outputs.
        let spend_infos = indexed_spends
            .into_iter()
            .enumerate()
            .map(|(i, (pos, spend))| {
                // Record the post-randomized spend location
                tx_metadata.spend_indices[pos] = i;

                spend
            })
            .collect::<Vec<_>>();
        let output_infos = indexed_outputs
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                if let Some((pos, output)) = output {
                    // Record the post-randomized output location
                    tx_metadata.output_indices[pos] = i;

                    output
                } else {
                    // This is a dummy output
                    SaplingOutputInfo::dummy(&mut rng, self.zip212_enforcement)
                }
            })
            .collect::<Vec<_>>();

        // Compute the transaction binding signing key.
        let bsk = {
            let spends: TrapdoorSum = spend_infos.iter().map(|spend| &spend.rcv).sum();
            let outputs: TrapdoorSum = output_infos.iter().map(|output| &output.rcv).sum();
            (spends - outputs).into_bsk()
        };

        // Create the unauthorized Spend and Output descriptions.
        let shielded_spends = spend_infos
            .into_iter()
            .map(|a| a.build::<SP>(self.anchor))
            .collect::<Result<Vec<_>, _>>()?;
        let shielded_outputs = output_infos
            .into_iter()
            .map(|a| a.build::<OP, _>(&mut rng))
            .collect::<Vec<_>>();

        // Verify that bsk and bvk are consistent.
        let bvk = {
            let spends = shielded_spends
                .iter()
                .map(|spend| spend.cv())
                .sum::<CommitmentSum>();
            let outputs = shielded_outputs
                .iter()
                .map(|output| output.cv())
                .sum::<CommitmentSum>();
            (spends - outputs)
                .into_bvk(i64::try_from(self.value_balance).map_err(|_| Error::InvalidAmount)?)
        };
        assert_eq!(
            PublicKey::from_private(&bsk, VALUE_COMMITMENT_RANDOMNESS_GENERATOR).0,
            bvk.0,
        );

        let bundle = if shielded_spends.is_empty() && shielded_outputs.is_empty() {
            None
        } else {
            Some((
                Bundle::from_parts(
                    shielded_spends,
                    shielded_outputs,
                    value_balance,
                    InProgress {
                        sigs: Unsigned { bsk },
                        _proof_state: PhantomData::default(),
                    },
                ),
                tx_metadata,
            ))
        };

        Ok(bundle)
    }
}

/// Type alias for an in-progress bundle that has no proofs or signatures.
///
/// This is returned by [`SaplingBuilder::build`].
pub type UnauthorizedBundle = Bundle<InProgress<Unproven, Unsigned>>;

/// Marker trait representing bundle proofs in the process of being created.
pub trait InProgressProofs: fmt::Debug {
    /// The proof type of a Sapling spend in the process of being proven.
    type SpendProof: Clone + fmt::Debug;
    /// The proof type of a Sapling output in the process of being proven.
    type OutputProof: Clone + fmt::Debug;
}

/// Marker trait representing bundle signatures in the process of being created.
pub trait InProgressSignatures: fmt::Debug {
    /// The authorization type of a Sapling spend or output in the process of being
    /// authorized.
    type AuthSig: Clone + fmt::Debug;
}

/// Marker for a bundle in the process of being built.
#[derive(Clone, Debug)]
pub struct InProgress<P: InProgressProofs, S: InProgressSignatures> {
    sigs: S,
    _proof_state: PhantomData<P>,
}

impl<P: InProgressProofs, S: InProgressSignatures> Authorization for InProgress<P, S> {
    type SpendProof = P::SpendProof;
    type OutputProof = P::OutputProof;
    type AuthSig = S::AuthSig;
}

/// Marker for a [`Bundle`] without proofs.
///
/// The [`SpendDescription`]s and [`OutputDescription`]s within the bundle contain the
/// private data needed to create proofs.
#[derive(Clone, Copy, Debug)]
pub struct Unproven;

impl InProgressProofs for Unproven {
    type SpendProof = sapling::circuit::Spend;
    type OutputProof = sapling::circuit::Output;
}

/// Marker for a [`Bundle`] with proofs.
#[derive(Clone, Copy, Debug)]
pub struct Proven;

impl InProgressProofs for Proven {
    type SpendProof = GrothProofBytes;
    type OutputProof = GrothProofBytes;
}

struct CreateProofs<'a, SP: SpendProver, OP: OutputProver, R: RngCore> {
    spend_prover: &'a SP,
    output_prover: &'a OP,
    rng: R,
    progress_notifier: Option<&'a Sender<Progress>>,
    total_progress: u32,
    progress: u32,
}

impl<'a, SP: SpendProver, OP: OutputProver, R: RngCore> CreateProofs<'a, SP, OP, R> {
    fn new(
        spend_prover: &'a SP,
        output_prover: &'a OP,
        rng: R,
        progress_notifier: Option<&'a Sender<Progress>>,
        total_progress: u32,
    ) -> Self {
        // Keep track of the total number of steps computed
        Self {
            spend_prover,
            output_prover,
            rng,
            progress_notifier,
            total_progress,
            progress: 0u32,
        }
    }

    fn update_progress(&mut self) {
        // Update progress and send a notification on the channel
        self.progress += 1;
        if let Some(sender) = self.progress_notifier {
            // If the send fails, we should ignore the error, not crash.
            sender
                .send(Progress::new(self.progress, Some(self.total_progress)))
                .unwrap_or(());
        }
    }
}

impl<'a, S: InProgressSignatures, SP: SpendProver, OP: OutputProver, R: RngCore>
    MapAuth<InProgress<Unproven, S>, InProgress<Proven, S>> for CreateProofs<'a, SP, OP, R>
{
    fn map_spend_proof(&mut self, spend: sapling::circuit::Spend) -> GrothProofBytes {
        let proof = self.spend_prover.create_proof(spend, &mut self.rng);
        self.update_progress();
        SP::encode_proof(proof)
    }

    fn map_output_proof(&mut self, output: sapling::circuit::Output) -> GrothProofBytes {
        let proof = self.output_prover.create_proof(output, &mut self.rng);
        self.update_progress();
        OP::encode_proof(proof)
    }

    fn map_auth_sig(&mut self, s: S::AuthSig) -> S::AuthSig {
        s
    }

    fn map_authorization(&mut self, a: InProgress<Unproven, S>) -> InProgress<Proven, S> {
        InProgress {
            sigs: a.sigs,
            _proof_state: PhantomData::default(),
        }
    }
}

impl<S: InProgressSignatures> Bundle<InProgress<Unproven, S>> {
    /// Creates the proofs for this bundle.
    pub fn create_proofs<SP: SpendProver, OP: OutputProver>(
        self,
        spend_prover: &SP,
        output_prover: &OP,
        rng: impl RngCore,
        progress_notifier: Option<&Sender<Progress>>,
    ) -> Bundle<InProgress<Proven, S>> {
        let total_progress =
            self.shielded_spends().len() as u32 + self.shielded_outputs().len() as u32;
        self.map_authorization(CreateProofs::new(
            spend_prover,
            output_prover,
            rng,
            progress_notifier,
            total_progress,
        ))
    }
}

/// Marker for an unauthorized bundle with no signatures.
pub struct Unsigned {
    bsk: PrivateKey,
}

impl Clone for Unsigned {
    fn clone(&self) -> Self {
        Self {
            bsk: PrivateKey(self.bsk.0),
        }
    }
}

impl fmt::Debug for Unsigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unsigned").finish_non_exhaustive()
    }
}

impl InProgressSignatures for Unsigned {
    type AuthSig = SigningParts;
}

/// The parts needed to sign a [`SpendDescription`].
#[derive(Clone, Debug)]
pub struct SigningParts {
    /// The spend validating key for this spend description. Used to match spend
    /// authorizing keys to spend descriptions they can create signatures for.
    ak: PublicKey,
    /// The randomization needed to derive the actual signing key for this note.
    alpha: jubjub::Scalar,
}

/// Marker for a partially-authorized bundle, in the process of being signed.
#[derive(Clone, Debug)]
pub struct PartiallyAuthorized {
    binding_signature: Signature,
    sighash: [u8; 32],
}

impl InProgressSignatures for PartiallyAuthorized {
    type AuthSig = MaybeSigned;
}

/// A heisen[`Signature`] for a particular [`SpendDescription`].
#[derive(Clone, Debug)]
pub enum MaybeSigned {
    /// The information needed to sign this [`SpendDescription`].
    SigningMetadata(SigningParts),
    /// The signature for this [`SpendDescription`].
    Signature(Signature),
}

impl MaybeSigned {
    fn finalize(self) -> Result<Signature, Error> {
        match self {
            Self::Signature(sig) => Ok(sig),
            _ => Err(Error::MissingSignatures),
        }
    }
}

impl<P: InProgressProofs> Bundle<InProgress<P, Unsigned>> {
    /// Loads the sighash into this bundle, preparing it for signing.
    ///
    /// This API ensures that all signatures are created over the same sighash.
    pub fn prepare<R: RngCore + CryptoRng>(
        self,
        mut rng: R,
        sighash: [u8; 32],
    ) -> Bundle<InProgress<P, PartiallyAuthorized>> {
        self.map_authorization((
            |proof| proof,
            |proof| proof,
            MaybeSigned::SigningMetadata,
            |auth: InProgress<P, Unsigned>| InProgress {
                sigs: PartiallyAuthorized {
                    binding_signature: auth.sigs.bsk.sign(
                        &sighash,
                        &mut rng,
                        VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
                    ),
                    sighash,
                },
                _proof_state: PhantomData::default(),
            },
        ))
    }
}

impl Bundle<InProgress<Proven, Unsigned>> {
    /// Applies signatures to this bundle, in order to authorize it.
    ///
    /// This is a helper method that wraps [`Bundle::prepare`], [`Bundle::sign`], and
    /// [`Bundle::finalize`].
    pub fn apply_signatures<R: RngCore + CryptoRng>(
        self,
        mut rng: R,
        sighash: [u8; 32],
        signing_keys: &[PrivateKey],
    ) -> Result<Bundle<Authorized>, Error> {
        signing_keys
            .iter()
            .fold(self.prepare(&mut rng, sighash), |partial, ask| {
                partial.sign(&mut rng, ask)
            })
            .finalize()
    }
}

impl<P: InProgressProofs> Bundle<InProgress<P, PartiallyAuthorized>> {
    /// Signs this bundle with the given [`PrivateKey`].
    ///
    /// This will apply signatures for all notes controlled by this spending key.
    pub fn sign<R: RngCore + CryptoRng>(self, mut rng: R, ask: &PrivateKey) -> Self {
        let expected_ak = PublicKey::from_private(ask, SPENDING_KEY_GENERATOR);
        let sighash = self.authorization().sigs.sighash;
        self.map_authorization((
            |proof| proof,
            |proof| proof,
            |maybe| match maybe {
                MaybeSigned::SigningMetadata(parts) if parts.ak.0 == expected_ak.0 => {
                    MaybeSigned::Signature(spend_sig_internal(ask, parts.alpha, &sighash, &mut rng))
                }
                s => s,
            },
            |partial| partial,
        ))
    }

    /// Appends externally computed [`Signature`]s.
    ///
    /// Each signature will be applied to the one input for which it is valid. An error
    /// will be returned if the signature is not valid for any inputs, or if it is valid
    /// for more than one input.
    pub fn append_signatures(self, signatures: &[Signature]) -> Result<Self, Error> {
        signatures.iter().try_fold(self, Self::append_signature)
    }

    fn append_signature(self, signature: &Signature) -> Result<Self, Error> {
        let sighash = self.authorization().sigs.sighash;
        let mut signature_valid_for = 0usize;
        let bundle = self.map_authorization((
            |proof| proof,
            |proof| proof,
            |maybe| match maybe {
                MaybeSigned::SigningMetadata(parts) => {
                    if verify_spend_sig(&parts.ak, parts.alpha, &sighash, signature) {
                        signature_valid_for += 1;
                        MaybeSigned::Signature(*signature)
                    } else {
                        // Signature isn't for this input.
                        MaybeSigned::SigningMetadata(parts)
                    }
                }
                s => s,
            },
            |partial| partial,
        ));
        match signature_valid_for {
            0 => Err(Error::InvalidExternalSignature),
            1 => Ok(bundle),
            _ => Err(Error::DuplicateSignature),
        }
    }
}

impl Bundle<InProgress<Proven, PartiallyAuthorized>> {
    /// Finalizes this bundle, enabling it to be included in a transaction.
    ///
    /// Returns an error if any signatures are missing.
    pub fn finalize(self) -> Result<Bundle<Authorized>, Error> {
        self.try_map_authorization((
            Ok,
            Ok,
            |maybe: MaybeSigned| maybe.finalize(),
            |partial: InProgress<Proven, PartiallyAuthorized>| {
                Ok(Authorized {
                    binding_sig: partial.sigs.binding_signature,
                })
            },
        ))
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        sapling::{
            bundle::{Authorized, Bundle},
            note_encryption::Zip212Enforcement,
            prover::mock::{MockOutputProver, MockSpendProver},
            redjubjub::PrivateKey,
            testing::{arb_node, arb_note},
            value::testing::arb_positive_note_value,
            Diversifier,
        },
        transaction::components::amount::MAX_MONEY,
        zip32::sapling::testing::arb_extended_spending_key,
    };
    use incrementalmerkletree::{
        frontier::testing::arb_commitment_tree, witness::IncrementalWitness,
    };

    use super::SaplingBuilder;

    prop_compose! {
        fn arb_bundle(zip212_enforcement: Zip212Enforcement)(n_notes in 1..30usize)(
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
            rng_seed in prop::array::uniform32(any::<u8>()),
            fake_sighash_bytes in prop::array::uniform32(any::<u8>()),
        ) -> Bundle<Authorized> {
            let mut builder = SaplingBuilder::new(zip212_enforcement);
            let mut rng = StdRng::from_seed(rng_seed);

            for ((note, path), diversifier) in spendable_notes.into_iter().zip(commitment_trees.into_iter()).zip(diversifiers.into_iter()) {
                builder.add_spend(
                    &mut rng,
                    &extsk,
                    diversifier,
                    note,
                    path
                ).unwrap();
            }

            let (bundle, _) = builder
                .build::<MockSpendProver, MockOutputProver, _>(&mut rng)
                .unwrap()
                .unwrap();

            let bundle = bundle.create_proofs(
                &MockSpendProver,
                &MockOutputProver,
                &mut rng,
                None,
            );

            bundle.apply_signatures(
                &mut rng,
                fake_sighash_bytes,
                &[PrivateKey(extsk.expsk.ask)],
            ).unwrap()
        }
    }
}
