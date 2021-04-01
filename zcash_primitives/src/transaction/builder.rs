//! Structs for building transactions.

#[cfg(feature = "zfuture")]
use std::boxed::Box;

use std::error;
use std::fmt;
use std::marker::PhantomData;
use std::sync::mpsc::Sender;

use ff::Field;
use rand::{rngs::OsRng, seq::SliceRandom, CryptoRng, RngCore};

use crate::{
    consensus::{self, BlockHeight},
    legacy::TransparentAddress,
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
        components::{
            amount::{Amount, DEFAULT_FEE},
            OutputDescription, SpendDescription, TxIn, TxOut,
        },
        signature_hash_data, SignableInput, Transaction, TransactionData, TxVersion, SIGHASH_ALL,
    },
    zip32::ExtendedSpendingKey,
};

#[cfg(feature = "transparent-inputs")]
use crate::{legacy::Script, transaction::components::OutPoint};

#[cfg(feature = "zfuture")]
use crate::{
    extensions::transparent::{self as tze, ExtensionTxBuilder, ToPayload},
    transaction::components::{TzeIn, TzeOut, TzeOutPoint},
};

#[cfg(any(test, feature = "test-dependencies"))]
use crate::sapling::prover::mock::MockTxProver;

const DEFAULT_TX_EXPIRY_DELTA: u32 = 20;

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See <https://github.com/zcash/zcash/issues/3615>.
const MIN_SHIELDED_OUTPUTS: usize = 2;

#[derive(Debug, PartialEq)]
pub enum Error {
    AnchorMismatch,
    BindingSig,
    ChangeIsNegative(Amount),
    InvalidAddress,
    InvalidAmount,
    NoChangeAddress,
    SpendProof,
    TzeWitnessModeMismatch(u32, u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AnchorMismatch => {
                write!(f, "Anchor mismatch (anchors for all spends must be equal)")
            }
            Error::BindingSig => write!(f, "Failed to create bindingSig"),
            Error::ChangeIsNegative(amount) => {
                write!(f, "Change is negative ({:?} zatoshis)", amount)
            }
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::NoChangeAddress => write!(f, "No change address specified or discoverable"),
            Error::SpendProof => write!(f, "Failed to create Sapling spend proof"),
            Error::TzeWitnessModeMismatch(expected, actual) =>
                write!(f, "TZE witness builder returned a mode that did not match the mode with which the input was initially constructed: expected = {:?}, actual = {:?}", expected, actual),
        }
    }
}

impl error::Error for Error {}

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

#[cfg(feature = "transparent-inputs")]
struct TransparentInputInfo {
    sk: secp256k1::SecretKey,
    pubkey: [u8; secp256k1::constants::PUBLIC_KEY_SIZE],
    utxo: OutPoint,
    coin: TxOut,
}

struct TransparentBuilder {
    #[cfg(feature = "transparent-inputs")]
    secp: secp256k1::Secp256k1<secp256k1::SignOnly>,
    #[cfg(feature = "transparent-inputs")]
    inputs: Vec<TransparentInputInfo>,
    vout: Vec<TxOut>,
}

impl TransparentBuilder {
    fn new() -> Self {
        TransparentBuilder {
            #[cfg(feature = "transparent-inputs")]
            secp: secp256k1::Secp256k1::gen_new(),
            #[cfg(feature = "transparent-inputs")]
            inputs: vec![],
            vout: vec![],
        }
    }

    #[cfg(feature = "transparent-inputs")]
    fn add_input(
        &mut self,
        sk: secp256k1::SecretKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        if coin.value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        // Ensure that the RIPEMD-160 digest of the public key associated with the
        // provided secret key matches that of the address to which the provided
        // output may be spent.
        let pubkey = secp256k1::PublicKey::from_secret_key(&self.secp, &sk).serialize();
        match coin.script_pubkey.address() {
            Some(TransparentAddress::PublicKey(hash)) => {
                use ripemd160::Ripemd160;
                use sha2::{Digest, Sha256};

                if hash[..] != Ripemd160::digest(&Sha256::digest(&pubkey))[..] {
                    return Err(Error::InvalidAddress);
                }
            }
            _ => return Err(Error::InvalidAddress),
        }

        self.inputs.push(TransparentInputInfo {
            sk,
            pubkey,
            utxo,
            coin,
        });

        Ok(())
    }

    fn add_output(&mut self, to: &TransparentAddress, value: Amount) -> Result<(), Error> {
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        self.vout.push(TxOut {
            value,
            script_pubkey: to.script(),
        });

        Ok(())
    }

    fn value_balance(&self) -> Option<Amount> {
        #[cfg(feature = "transparent-inputs")]
        let input_sum = self
            .inputs
            .iter()
            .map(|input| input.coin.value)
            .sum::<Option<Amount>>()?;

        #[cfg(not(feature = "transparent-inputs"))]
        let input_sum = Amount::zero();

        input_sum
            - self
                .vout
                .iter()
                .map(|vo| vo.value)
                .sum::<Option<Amount>>()?
    }

    fn build(&self) -> (Vec<TxIn>, Vec<TxOut>) {
        #[cfg(feature = "transparent-inputs")]
        let vin = self
            .inputs
            .iter()
            .map(|i| TxIn::new(i.utxo.clone()))
            .collect();

        #[cfg(not(feature = "transparent-inputs"))]
        let vin = vec![];

        (vin, self.vout.clone())
    }

    #[cfg(feature = "transparent-inputs")]
    fn create_signatures(
        self,
        mtx: &TransactionData,
        consensus_branch_id: consensus::BranchId,
    ) -> Vec<Script> {
        self.inputs
            .iter()
            .enumerate()
            .map(|(i, info)| {
                let mut sighash = [0u8; 32];
                sighash.copy_from_slice(&signature_hash_data(
                    mtx,
                    consensus_branch_id,
                    SIGHASH_ALL,
                    SignableInput::transparent(i, &info.coin.script_pubkey, info.coin.value),
                ));

                let msg = secp256k1::Message::from_slice(sighash.as_ref()).expect("32 bytes");
                let sig = self.secp.sign(&msg, &info.sk);

                // Signature has to have "SIGHASH_ALL" appended to it
                let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
                sig_bytes.extend(&[SIGHASH_ALL as u8]);

                // P2PKH scriptSig
                Script::default() << &sig_bytes[..] << &info.pubkey[..]
            })
            .collect()
    }
}

#[cfg(feature = "zfuture")]
#[allow(clippy::type_complexity)]
struct TzeSigner<'a, BuildCtx> {
    prevout: TzeOut,
    builder: Box<dyn FnOnce(&BuildCtx) -> Result<(u32, Vec<u8>), Error> + 'a>,
}

#[cfg(feature = "zfuture")]
struct TzeBuilder<'a, BuildCtx> {
    signers: Vec<TzeSigner<'a, BuildCtx>>,
    tze_inputs: Vec<TzeIn>,
    tze_outputs: Vec<TzeOut>,
}

#[cfg(feature = "zfuture")]
impl<'a, BuildCtx> TzeBuilder<'a, BuildCtx> {
    fn new() -> Self {
        TzeBuilder {
            signers: vec![],
            tze_inputs: vec![],
            tze_outputs: vec![],
        }
    }

    fn add_input<WBuilder, W: ToPayload>(
        &mut self,
        extension_id: u32,
        mode: u32,
        (outpoint, prevout): (TzeOutPoint, TzeOut),
        witness_builder: WBuilder,
    ) where
        WBuilder: 'a + FnOnce(&BuildCtx) -> Result<W, Error>,
    {
        self.tze_inputs
            .push(TzeIn::new(outpoint, extension_id, mode));
        self.signers.push(TzeSigner {
            prevout,
            builder: Box::new(move |ctx| witness_builder(&ctx).map(|x| x.to_payload())),
        });
    }

    fn add_output<G: ToPayload>(
        &mut self,
        extension_id: u32,
        value: Amount,
        guarded_by: &G,
    ) -> Result<(), Error> {
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        let (mode, payload) = guarded_by.to_payload();
        self.tze_outputs.push(TzeOut {
            value,
            precondition: tze::Precondition {
                extension_id,
                mode,
                payload,
            },
        });

        Ok(())
    }

    fn value_balance(&self) -> Option<Amount> {
        self.signers
            .iter()
            .map(|s| s.prevout.value)
            .sum::<Option<Amount>>()?
            - self
                .tze_outputs
                .iter()
                .map(|tzo| tzo.value)
                .sum::<Option<Amount>>()?
    }

    fn build(&self) -> (Vec<TzeIn>, Vec<TzeOut>) {
        (self.tze_inputs.clone(), self.tze_outputs.clone())
    }

    fn create_signatures(self, mtx: &BuildCtx) -> Result<Vec<Vec<u8>>, Error> {
        // Create TZE input witnesses
        let tzein = self.tze_inputs;
        let payloads = self
            .signers
            .into_iter()
            .enumerate()
            .map(|(i, tze_in)| {
                // The witness builder function should have cached/closed over whatever data was
                // necessary for the witness to commit to at the time it was added to the
                // transaction builder; here, it then computes those commitments.
                let (mode, payload) = (tze_in.builder)(&mtx)?;
                let input_mode = tzein[i].witness.mode;
                if mode != input_mode {
                    return Err(Error::TzeWitnessModeMismatch(input_mode, mode));
                }

                Ok(payload)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(payloads)
    }
}

/// Metadata about a transaction created by a [`Builder`].
#[derive(Debug, PartialEq)]
pub struct SaplingMetadata {
    spend_indices: Vec<usize>,
    output_indices: Vec<usize>,
}

impl SaplingMetadata {
    fn new() -> Self {
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

/// Reports on the progress made by the builder towards building a transaction.
pub struct Progress {
    /// The number of steps completed.
    cur: u32,
    /// The expected total number of steps (as of this progress update), if known.
    end: Option<u32>,
}

impl Progress {
    fn new(cur: u32, end: Option<u32>) -> Self {
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

pub struct SaplingBuilder<P: consensus::Parameters> {
    anchor: Option<bls12_381::Scalar>,
    value_balance: Amount,
    spends: Vec<SpendDescriptionInfo>,
    outputs: Vec<SaplingOutput<P>>,
    change_address: Option<(OutgoingViewingKey, PaymentAddress)>,
}

impl<P: consensus::Parameters> SaplingBuilder<P> {
    fn new() -> Self {
        SaplingBuilder {
            anchor: None,
            value_balance: Amount::zero(),
            spends: vec![],
            outputs: vec![],
            change_address: None,
        }
    }

    pub fn value_balance(&self) -> Amount {
        self.value_balance
    }

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    fn add_spend<R: RngCore>(
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
        params: &P,
        target_height: BlockHeight,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<MemoBytes>,
    ) -> Result<(), Error> {
        let output =
            SaplingOutput::new_internal(params, target_height, &mut rng, ovk, to, value, memo)?;

        self.value_balance -= value;

        self.outputs.push(output);

        Ok(())
    }

    /// Sets the Sapling address to which any change will be sent.
    ///
    /// By default, change is sent to the Sapling address corresponding to the first note
    /// being spent (i.e. the first call to [`Builder::add_sapling_spend`]).
    pub fn send_change_to(&mut self, ovk: OutgoingViewingKey, to: PaymentAddress) {
        self.change_address = Some((ovk, to));
    }

    /// Send change to the specified change address. If no change address
    /// was set, send change to the first Sapling address given as input.
    pub fn get_change_address(&self) -> Result<(OutgoingViewingKey, PaymentAddress), Error> {
        if let Some(change_address) = &self.change_address {
            Ok(change_address.clone())
        } else if !self.spends.is_empty() {
            PaymentAddress::from_parts(self.spends[0].diversifier, self.spends[0].note.pk_d)
                .map(|addr| (self.spends[0].extsk.expsk.ovk, addr))
                .ok_or(Error::InvalidAddress)
        } else {
            Err(Error::NoChangeAddress)
        }
    }

    pub fn build<Pr: TxProver, R: RngCore>(
        &self,
        params: &P,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        mut rng: R,
        target_height: BlockHeight,
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
        let mut tx_metadata = SaplingMetadata::new();
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

                        let rseed = generate_random_rseed_internal(params, target_height, &mut rng);

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
                }
            })
            .collect();

        Ok((spend_descs, output_descs, tx_metadata))
    }

    fn create_signatures<Pr: TxProver, R: RngCore>(
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

/// Generates a [`Transaction`] from its inputs and outputs.
pub struct Builder<'a, P: consensus::Parameters, R: RngCore> {
    params: P,
    rng: R,
    target_height: BlockHeight,
    expiry_height: BlockHeight,
    fee: Amount,
    transparent_builder: TransparentBuilder,
    sapling_builder: SaplingBuilder<P>,
    #[cfg(feature = "zfuture")]
    tze_builder: TzeBuilder<'a, TransactionData>,
    #[cfg(not(feature = "zfuture"))]
    tze_builder: PhantomData<&'a ()>,
    progress_notifier: Option<Sender<Progress>>,
}

impl<'a, P: consensus::Parameters> Builder<'a, P, OsRng> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height,
    /// using default values for general transaction fields and the default OS random.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new(params: P, target_height: BlockHeight) -> Self {
        Builder::new_with_rng(params, target_height, OsRng)
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
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new_with_rng(params: P, target_height: BlockHeight, rng: R) -> Builder<'a, P, R> {
        Self::new_internal(params, target_height, rng)
    }
}

impl<'a, P: consensus::Parameters, R: RngCore> Builder<'a, P, R> {
    /// Common utility function for builder construction.
    ///
    /// WARNING: THIS MUST REMAIN PRIVATE AS IT ALLOWS CONSTRUCTION
    /// OF BUILDERS WITH NON-CryptoRng RNGs
    fn new_internal(params: P, target_height: BlockHeight, rng: R) -> Builder<'a, P, R> {
        Builder {
            params,
            rng,
            target_height,
            expiry_height: target_height + DEFAULT_TX_EXPIRY_DELTA,
            fee: DEFAULT_FEE,
            transparent_builder: TransparentBuilder::new(),
            sapling_builder: SaplingBuilder::new(),
            #[cfg(feature = "zfuture")]
            tze_builder: TzeBuilder::new(),
            #[cfg(not(feature = "zfuture"))]
            tze_builder: PhantomData,
            progress_notifier: None,
        }
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
        merkle_path: MerklePath<Node>,
    ) -> Result<(), Error> {
        self.sapling_builder
            .add_spend(&mut self.rng, extsk, diversifier, note, merkle_path)
    }

    /// Adds a Sapling address to send funds to.
    pub fn add_sapling_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<MemoBytes>,
    ) -> Result<(), Error> {
        self.sapling_builder.add_output(
            &mut self.rng,
            &self.params,
            self.target_height,
            ovk,
            to,
            value,
            memo,
        )
    }

    /// Adds a transparent coin to be spent in this transaction.
    #[cfg(feature = "transparent-inputs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "transparent-inputs")))]
    pub fn add_transparent_input(
        &mut self,
        sk: secp256k1::SecretKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        self.transparent_builder.add_input(sk, utxo, coin)
    }

    /// Adds a transparent address to send funds to.
    pub fn add_transparent_output(
        &mut self,
        to: &TransparentAddress,
        value: Amount,
    ) -> Result<(), Error> {
        self.transparent_builder.add_output(to, value)
    }

    /// Sets the Sapling address to which any change will be sent.
    ///
    /// By default, change is sent to the Sapling address corresponding to the first note
    /// being spent (i.e. the first call to [`Builder::add_sapling_spend`]).
    pub fn send_change_to(&mut self, ovk: OutgoingViewingKey, to: PaymentAddress) {
        self.sapling_builder.send_change_to(ovk, to)
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

    /// Builds a transaction from the configured spends and outputs.
    ///
    /// Upon success, returns a tuple containing the final transaction, and the
    /// [`SaplingMetadata`] generated during the build process.
    ///
    /// `consensus_branch_id` must be valid for the block height that this transaction is
    /// targeting. An invalid `consensus_branch_id` will *not* result in an error from
    /// this function, and instead will generate a transaction that will be rejected by
    /// the network.
    pub fn build(
        mut self,
        version: TxVersion,
        consensus_branch_id: consensus::BranchId,
        prover: &impl TxProver,
    ) -> Result<(Transaction, SaplingMetadata), Error> {
        //
        // Consistency checks
        //

        // Valid change
        let change = self
            .transparent_builder
            .value_balance()
            .and_then(|ta| ta + self.sapling_builder.value_balance())
            .and_then(|b| b - self.fee)
            .ok_or(Error::InvalidAmount)?;

        #[cfg(feature = "zfuture")]
        let change = self
            .tze_builder
            .value_balance()
            .and_then(|b| change + b)
            .ok_or(Error::InvalidAmount)?;

        if change.is_negative() {
            return Err(Error::ChangeIsNegative(change));
        }

        //
        // Change output
        //

        if change.is_positive() {
            let change_address = self.sapling_builder.get_change_address()?;
            self.add_sapling_output(Some(change_address.0), change_address.1, change, None)?;
        }

        let (vin, vout) = self.transparent_builder.build();

        let mut ctx = prover.new_sapling_proving_context();
        let (spend_descs, output_descs, tx_metadata) = self.sapling_builder.build(
            &self.params,
            prover,
            &mut ctx,
            &mut self.rng,
            self.target_height,
        )?;

        #[cfg(feature = "zfuture")]
        let (tze_inputs, tze_outputs) = self.tze_builder.build();

        let mut mtx = TransactionData {
            version,
            vin,
            vout,
            #[cfg(feature = "zfuture")]
            tze_inputs,
            #[cfg(feature = "zfuture")]
            tze_outputs,
            lock_time: 0,
            expiry_height: self.expiry_height,
            value_balance: self.sapling_builder.value_balance,
            shielded_spends: spend_descs,
            shielded_outputs: output_descs,
            joinsplits: vec![],
            joinsplit_pubkey: None,
            joinsplit_sig: None,
            binding_sig: None,
        };

        //
        // Signatures -- everything but the signatures must already have been added.
        //

        let mut sighash = [0u8; 32];
        sighash.copy_from_slice(&signature_hash_data(
            &mtx,
            consensus_branch_id,
            SIGHASH_ALL,
            SignableInput::Shielded,
        ));

        let (sapling_spend_auth_sigs, sapling_binding_sig) = self
            .sapling_builder
            .create_signatures(prover, &mut ctx, &mut self.rng, &sighash, &tx_metadata)?;

        for (i, spend_auth_sig) in sapling_spend_auth_sigs.into_iter().enumerate() {
            mtx.shielded_spends[i].spend_auth_sig = spend_auth_sig;
        }
        mtx.binding_sig = sapling_binding_sig;

        #[cfg(feature = "zfuture")]
        {
            // Create TZE input witnesses
            let tze_payloads = self.tze_builder.create_signatures(&mtx)?;
            for (i, payload) in tze_payloads.into_iter().enumerate() {
                mtx.tze_inputs[i].witness.payload = payload;
            }
        }

        #[cfg(feature = "transparent-inputs")]
        {
            let script_sigs = self
                .transparent_builder
                .create_signatures(&mtx, consensus_branch_id);

            for (i, sig) in script_sigs.into_iter().enumerate() {
                mtx.vin[i].script_sig = sig;
            }
        }

        Ok((
            mtx.freeze().expect("Transaction should be complete"),
            tx_metadata,
        ))
    }
}

#[cfg(feature = "zfuture")]
impl<'a, P: consensus::Parameters, R: RngCore + CryptoRng> ExtensionTxBuilder<'a>
    for Builder<'a, P, R>
{
    type BuildCtx = TransactionData;
    type BuildError = Error;

    fn add_tze_input<WBuilder, W: ToPayload>(
        &mut self,
        extension_id: u32,
        mode: u32,
        prevout: (TzeOutPoint, TzeOut),
        witness_builder: WBuilder,
    ) -> Result<(), Self::BuildError>
    where
        WBuilder: 'a + (FnOnce(&Self::BuildCtx) -> Result<W, Self::BuildError>),
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
impl<'a, P: consensus::Parameters, R: RngCore> Builder<'a, P, R> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height
    /// and randomness source, using default values for general transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    ///
    /// WARNING: DO NOT USE IN PRODUCTION
    pub fn test_only_new_with_rng(params: P, height: BlockHeight, rng: R) -> Builder<'a, P, R> {
        Self::new_internal(params, height, rng)
    }

    /// Creates a new `Builder` targeted for inclusion in the block with the given height,
    /// and randomness source, using default values for general transaction fields
    /// and the `ZFUTURE_TX_VERSION` and `ZFUTURE_VERSION_GROUP_ID` version identifiers.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    ///
    /// The transaction will be constructed and serialized according to the
    /// NetworkUpgrade::ZFuture rules. This is intended only for use in
    /// integration testing of new features.
    ///
    /// WARNING: DO NOT USE IN PRODUCTION
    #[cfg(feature = "zfuture")]
    pub fn test_only_new_with_rng_zfuture(
        params: P,
        height: BlockHeight,
        rng: R,
    ) -> Builder<'a, P, R> {
        Self::new_internal(params, height, rng)
    }

    pub fn mock_build(
        self,
        version: TxVersion,
        consensus_branch_id: consensus::BranchId,
    ) -> Result<(Transaction, SaplingMetadata), Error> {
        self.build(version, consensus_branch_id, &MockTxProver)
    }
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use rand_core::OsRng;

    use crate::{
        consensus::{self, Parameters, H0, TEST_NETWORK},
        legacy::TransparentAddress,
        merkle_tree::{CommitmentTree, IncrementalWitness},
        sapling::{prover::mock::MockTxProver, Node, Rseed},
        transaction::{
            components::{amount::Amount, amount::DEFAULT_FEE},
            TxVersion,
        },
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    use super::{Builder, Error, SaplingBuilder, DEFAULT_TX_EXPIRY_DELTA};

    #[cfg(feature = "zfuture")]
    use super::TzeBuilder;

    #[test]
    fn fails_on_negative_output() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = extfvk.fvk.ovk;
        let to = extfvk.default_address().unwrap().1;

        let mut builder = Builder::new(TEST_NETWORK, H0);
        assert_eq!(
            builder.add_sapling_output(Some(ovk), to, Amount::from_i64(-1).unwrap(), None),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
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
            fee: Amount::zero(),
            transparent_builder: TransparentBuilder::new(),
            sapling_builder: SaplingBuilder::new(),
            #[cfg(feature = "zfuture")]
            tze_builder: TzeBuilder::new(),
            progress_notifier: None,
        };

        // Create a tx with only t output. No binding_sig should be present
        builder
            .add_transparent_output(&TransparentAddress::PublicKey([0; 20]), Amount::zero())
            .unwrap();

        let (tx, _) = builder
            .build(
                TxVersion::Sapling,
                consensus::BranchId::Sapling,
                &MockTxProver,
            )
            .unwrap();
        // No binding signature, because only t input and outputs
        assert!(tx.binding_sig.is_none());
    }

    #[test]
    fn binding_sig_present_if_shielded_spend() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let to = extfvk.default_address().unwrap().1;

        let mut rng = OsRng;

        let note1 = to
            .create_note(50000, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cmu1 = Node::new(note1.cmu().to_repr());
        let mut tree = CommitmentTree::empty();
        tree.append(cmu1).unwrap();
        let witness1 = IncrementalWitness::from_tree(&tree);

        let mut builder = Builder::new(TEST_NETWORK, H0);

        // Create a tx with a sapling spend. binding_sig should be present
        builder
            .add_sapling_spend(extsk, *to.diversifier(), note1, witness1.path().unwrap())
            .unwrap();

        builder
            .add_transparent_output(&TransparentAddress::PublicKey([0; 20]), Amount::zero())
            .unwrap();

        // Expect a binding signature error, because our inputs aren't valid, but this shows
        // that a binding signature was attempted
        assert_eq!(
            builder.build(
                TxVersion::Sapling,
                consensus::BranchId::Sapling,
                &MockTxProver
            ),
            Err(Error::BindingSig)
        );
    }

    #[test]
    fn fails_on_negative_transparent_output() {
        let mut builder = Builder::new(TEST_NETWORK, H0);
        assert_eq!(
            builder.add_transparent_output(
                &TransparentAddress::PublicKey([0; 20]),
                Amount::from_i64(-1).unwrap(),
            ),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn fails_on_negative_change() {
        let mut rng = OsRng;

        // Just use the master key as the ExtendedSpendingKey for this test
        let extsk = ExtendedSpendingKey::master(&[]);

        // Fails with no inputs or outputs
        // 0.0001 t-ZEC fee
        {
            let builder = Builder::new(TEST_NETWORK, H0);
            assert_eq!(
                builder.build(
                    TxVersion::Sapling,
                    consensus::BranchId::Sapling,
                    &MockTxProver
                ),
                Err(Error::ChangeIsNegative(
                    (Amount::zero() - DEFAULT_FEE).unwrap()
                ))
            );
        }

        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = Some(extfvk.fvk.ovk);
        let to = extfvk.default_address().unwrap().1;

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.00001 t-ZEC fee
        {
            let mut builder = Builder::new(TEST_NETWORK, H0);
            builder
                .add_sapling_output(ovk, to.clone(), Amount::from_u64(50000).unwrap(), None)
                .unwrap();
            assert_eq!(
                builder.build(
                    TxVersion::Sapling,
                    consensus::BranchId::Sapling,
                    &MockTxProver
                ),
                Err(Error::ChangeIsNegative(
                    (Amount::from_i64(-50000).unwrap() - DEFAULT_FEE).unwrap()
                ))
            );
        }

        // Fail if there is only a transparent output
        // 0.0005 t-ZEC out, 0.00001 t-ZEC fee
        {
            let mut builder = Builder::new(TEST_NETWORK, H0);
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(50000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(
                    TxVersion::Sapling,
                    consensus::BranchId::Sapling,
                    &MockTxProver
                ),
                Err(Error::ChangeIsNegative(
                    (Amount::from_i64(-50000).unwrap() - DEFAULT_FEE).unwrap()
                ))
            );
        }

        let note1 = to
            .create_note(50999, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cmu1 = Node::new(note1.cmu().to_repr());
        let mut tree = CommitmentTree::empty();
        tree.append(cmu1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(&tree);

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.00001 t-ZEC fee, 0.00050999 z-ZEC in
        {
            let mut builder = Builder::new(TEST_NETWORK, H0);
            builder
                .add_sapling_spend(
                    extsk.clone(),
                    *to.diversifier(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output(ovk, to.clone(), Amount::from_u64(30000).unwrap(), None)
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(20000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(
                    TxVersion::Sapling,
                    consensus::BranchId::Sapling,
                    &MockTxProver
                ),
                Err(Error::ChangeIsNegative(Amount::from_i64(-1).unwrap()))
            );
        }

        let note2 = to
            .create_note(1, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cmu2 = Node::new(note2.cmu().to_repr());
        tree.append(cmu2).unwrap();
        witness1.append(cmu2).unwrap();
        let witness2 = IncrementalWitness::from_tree(&tree);

        // Succeeds if there is sufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.0006 z-ZEC in
        //
        // (Still fails because we are using a MockTxProver which doesn't correctly
        // compute bindingSig.)
        {
            let mut builder = Builder::new(TEST_NETWORK, H0);
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
                .add_sapling_output(ovk, to, Amount::from_u64(30000).unwrap(), None)
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(20000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(
                    TxVersion::Sapling,
                    consensus::BranchId::Sapling,
                    &MockTxProver
                ),
                Err(Error::BindingSig)
            )
        }
    }
}
