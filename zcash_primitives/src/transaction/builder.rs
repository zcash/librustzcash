//! Structs for building transactions.

use crate::primitives::{Diversifier, Note, PaymentAddress};
use crate::zip32::ExtendedSpendingKey;
use ff::Field;
use rand::{rngs::OsRng, seq::SliceRandom, CryptoRng, RngCore};
use std::error;
use std::fmt;
use std::marker::PhantomData;

use crate::{
    consensus::{self, BlockHeight},
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    merkle_tree::MerklePath,
    note_encryption::{Memo, SaplingNoteEncryption},
    prover::TxProver,
    redjubjub::PrivateKey,
    sapling::{spend_sig, Node},
    transaction::{
        components::{amount::DEFAULT_FEE, Amount, OutputDescription, SpendDescription, TxOut},
        signature_hash_data, Transaction, TransactionData, SIGHASH_ALL,
    },
    util::generate_random_rseed,
};

#[cfg(feature = "transparent-inputs")]
use crate::{
    legacy::Script,
    transaction::components::{OutPoint, TxIn},
};

const DEFAULT_TX_EXPIRY_DELTA: u32 = 20;

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See https://github.com/zcash/zcash/issues/3615
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

pub struct SaplingOutput {
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<OutgoingViewingKey>,
    to: PaymentAddress,
    note: Note,
    memo: Memo,
}

impl SaplingOutput {
    pub fn new<R: RngCore + CryptoRng, P: consensus::Parameters>(
        params: &P,
        height: BlockHeight,
        rng: &mut R,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<Memo>,
    ) -> Result<Self, Error> {
        let g_d = match to.g_d() {
            Some(g_d) => g_d,
            None => return Err(Error::InvalidAddress),
        };
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        let rseed = generate_random_rseed(params, height, rng);

        let note = Note {
            g_d,
            pk_d: to.pk_d().clone(),
            value: value.into(),
            rseed,
        };

        Ok(SaplingOutput {
            ovk,
            to,
            note,
            memo: memo.unwrap_or_default(),
        })
    }

    pub fn build<P: TxProver, R: RngCore + CryptoRng>(
        self,
        prover: &P,
        ctx: &mut P::SaplingProvingContext,
        rng: &mut R,
    ) -> OutputDescription {
        let mut encryptor = SaplingNoteEncryption::new(
            self.ovk,
            self.note.clone(),
            self.to.clone(),
            self.memo,
            rng,
        );

        let (zkproof, cv) = prover.output_proof(
            ctx,
            encryptor.esk().clone(),
            self.to,
            self.note.rcm(),
            self.note.value,
        );

        let cmu = self.note.cmu();

        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu);

        let ephemeral_key = encryptor.epk().clone().into();

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
    coin: TxOut,
}

#[cfg(feature = "transparent-inputs")]
struct TransparentInputs {
    secp: secp256k1::Secp256k1<secp256k1::SignOnly>,
    inputs: Vec<TransparentInputInfo>,
}

#[cfg(feature = "transparent-inputs")]
impl Default for TransparentInputs {
    fn default() -> Self {
        TransparentInputs {
            secp: secp256k1::Secp256k1::gen_new(),
            inputs: Default::default(),
        }
    }
}

#[cfg(not(feature = "transparent-inputs"))]
#[derive(Default)]
struct TransparentInputs;

impl TransparentInputs {
    #[cfg(feature = "transparent-inputs")]
    fn push(
        &mut self,
        mtx: &mut TransactionData,
        sk: secp256k1::SecretKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        if coin.value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        let pubkey = secp256k1::PublicKey::from_secret_key(&self.secp, &sk).serialize();
        match coin.script_pubkey.address() {
            Some(TransparentAddress::PublicKey(hash)) => {
                use ripemd160::Ripemd160;
                use sha2::{Digest, Sha256};

                if &hash[..] != &Ripemd160::digest(&Sha256::digest(&pubkey))[..] {
                    return Err(Error::InvalidAddress);
                }
            }
            _ => return Err(Error::InvalidAddress),
        }

        mtx.vin.push(TxIn::new(utxo));
        self.inputs.push(TransparentInputInfo { sk, pubkey, coin });

        Ok(())
    }

    fn value_sum(&self) -> Amount {
        #[cfg(feature = "transparent-inputs")]
        {
            self.inputs
                .iter()
                .map(|input| input.coin.value)
                .sum::<Amount>()
        }

        #[cfg(not(feature = "transparent-inputs"))]
        {
            Amount::zero()
        }
    }

    #[cfg(feature = "transparent-inputs")]
    fn apply_signatures(
        &self,
        mtx: &mut TransactionData,
        consensus_branch_id: consensus::BranchId,
    ) {
        let mut sighash = [0u8; 32];
        for (i, info) in self.inputs.iter().enumerate() {
            sighash.copy_from_slice(&signature_hash_data(
                mtx,
                consensus_branch_id,
                SIGHASH_ALL,
                Some((i, &info.coin.script_pubkey, info.coin.value)),
            ));

            let msg = secp256k1::Message::from_slice(&sighash).expect("32 bytes");
            let sig = self.secp.sign(&msg, &info.sk);

            // Signature has to have "SIGHASH_ALL" appended to it
            let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
            sig_bytes.extend(&[SIGHASH_ALL as u8]);

            // P2PKH scriptSig
            mtx.vin[i].script_sig = Script::default() << &sig_bytes[..] << &info.pubkey[..];
        }
    }

    #[cfg(not(feature = "transparent-inputs"))]
    fn apply_signatures(&self, _: &mut TransactionData, _: consensus::BranchId) {}
}

/// Metadata about a transaction created by a [`Builder`].
#[derive(Debug, PartialEq)]
pub struct TransactionMetadata {
    spend_indices: Vec<usize>,
    output_indices: Vec<usize>,
}

impl TransactionMetadata {
    fn new() -> Self {
        TransactionMetadata {
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

/// Generates a [`Transaction`] from its inputs and outputs.
pub struct Builder<P: consensus::Parameters, R: RngCore + CryptoRng> {
    params: P,
    rng: R,
    height: BlockHeight,
    mtx: TransactionData,
    fee: Amount,
    anchor: Option<bls12_381::Scalar>,
    spends: Vec<SpendDescriptionInfo>,
    outputs: Vec<SaplingOutput>,
    transparent_inputs: TransparentInputs,
    change_address: Option<(OutgoingViewingKey, PaymentAddress)>,
    phantom: PhantomData<P>,
}

impl<P: consensus::Parameters> Builder<P, OsRng> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height,
    /// using default values for general transaction fields and the default OS random.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new(params: P, height: BlockHeight) -> Self {
        Builder::new_with_rng(params, height, OsRng)
    }
}

impl<P: consensus::Parameters, R: RngCore + CryptoRng> Builder<P, R> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height
    /// and randomness source, using default values for general transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new_with_rng(params: P, height: BlockHeight, rng: R) -> Builder<P, R> {
        let mut mtx = TransactionData::new();
        mtx.expiry_height = height + DEFAULT_TX_EXPIRY_DELTA;

        Builder {
            params,
            rng,
            height,
            mtx,
            fee: DEFAULT_FEE,
            anchor: None,
            spends: vec![],
            outputs: vec![],
            transparent_inputs: TransparentInputs::default(),
            change_address: None,
            phantom: PhantomData,
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

        let alpha = jubjub::Fr::random(&mut self.rng);

        self.mtx.value_balance += Amount::from_u64(note.value).map_err(|_| Error::InvalidAmount)?;

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
    pub fn add_sapling_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<Memo>,
    ) -> Result<(), Error> {
        let output = SaplingOutput::new(
            &self.params,
            self.height,
            &mut self.rng,
            ovk,
            to,
            value,
            memo,
        )?;

        self.mtx.value_balance -= value;

        self.outputs.push(output);

        Ok(())
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
        self.transparent_inputs.push(&mut self.mtx, sk, utxo, coin)
    }

    /// Adds a transparent address to send funds to.
    pub fn add_transparent_output(
        &mut self,
        to: &TransparentAddress,
        value: Amount,
    ) -> Result<(), Error> {
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        self.mtx.vout.push(TxOut {
            value,
            script_pubkey: to.script(),
        });

        Ok(())
    }

    /// Sets the Sapling address to which any change will be sent.
    ///
    /// By default, change is sent to the Sapling address corresponding to the first note
    /// being spent (i.e. the first call to [`Builder::add_sapling_spend`]).
    pub fn send_change_to(&mut self, ovk: OutgoingViewingKey, to: PaymentAddress) {
        self.change_address = Some((ovk, to));
    }

    /// Builds a transaction from the configured spends and outputs.
    ///
    /// Upon success, returns a tuple containing the final transaction, and the
    /// [`TransactionMetadata`] generated during the build process.
    ///
    /// `consensus_branch_id` must be valid for the block height that this transaction is
    /// targeting. An invalid `consensus_branch_id` will *not* result in an error from
    /// this function, and instead will generate a transaction that will be rejected by
    /// the network.
    pub fn build(
        mut self,
        consensus_branch_id: consensus::BranchId,
        prover: &impl TxProver,
    ) -> Result<(Transaction, TransactionMetadata), Error> {
        let mut tx_metadata = TransactionMetadata::new();

        //
        // Consistency checks
        //

        // Valid change
        let change = self.mtx.value_balance - self.fee + self.transparent_inputs.value_sum()
            - self
                .mtx
                .vout
                .iter()
                .map(|output| output.value)
                .sum::<Amount>();
        if change.is_negative() {
            return Err(Error::ChangeIsNegative(change));
        }

        //
        // Change output
        //

        if change.is_positive() {
            // Send change to the specified change address. If no change address
            // was set, send change to the first Sapling address given as input.
            let change_address = if let Some(change_address) = self.change_address.take() {
                change_address
            } else if !self.spends.is_empty() {
                (
                    self.spends[0].extsk.expsk.ovk,
                    PaymentAddress::from_parts(
                        self.spends[0].diversifier,
                        self.spends[0].note.pk_d.clone(),
                    )
                    .ok_or(Error::InvalidAddress)?,
                )
            } else {
                return Err(Error::NoChangeAddress);
            };

            self.add_sapling_output(Some(change_address.0), change_address.1, change, None)?;
        }

        //
        // Record initial positions of spends and outputs
        //
        let mut spends: Vec<_> = self.spends.into_iter().enumerate().collect();
        let mut outputs: Vec<_> = self
            .outputs
            .into_iter()
            .enumerate()
            .map(|(i, o)| Some((i, o)))
            .collect();

        //
        // Sapling spends and outputs
        //

        let mut ctx = prover.new_sapling_proving_context();

        // Pad Sapling outputs
        let orig_outputs_len = outputs.len();
        if !spends.is_empty() {
            while outputs.len() < MIN_SHIELDED_OUTPUTS {
                outputs.push(None);
            }
        }

        // Randomize order of inputs and outputs
        spends.shuffle(&mut self.rng);
        outputs.shuffle(&mut self.rng);
        tx_metadata.spend_indices.resize(spends.len(), 0);
        tx_metadata.output_indices.resize(orig_outputs_len, 0);

        // Record if we'll need a binding signature
        let binding_sig_needed = !spends.is_empty() || !outputs.is_empty();

        // Create Sapling SpendDescriptions
        if !spends.is_empty() {
            let anchor = self.anchor.expect("anchor was set if spends were added");

            for (i, (pos, spend)) in spends.iter().enumerate() {
                let proof_generation_key = spend.extsk.expsk.proof_generation_key();

                let mut nullifier = [0u8; 32];
                nullifier.copy_from_slice(&spend.note.nf(
                    &proof_generation_key.to_viewing_key(),
                    spend.merkle_path.position,
                ));

                let (zkproof, cv, rk) = prover
                    .spend_proof(
                        &mut ctx,
                        proof_generation_key,
                        spend.diversifier,
                        spend.note.rseed,
                        spend.alpha,
                        spend.note.value,
                        anchor,
                        spend.merkle_path.clone(),
                    )
                    .map_err(|()| Error::SpendProof)?;

                self.mtx.shielded_spends.push(SpendDescription {
                    cv,
                    anchor,
                    nullifier,
                    rk,
                    zkproof,
                    spend_auth_sig: None,
                });

                // Record the post-randomized spend location
                tx_metadata.spend_indices[*pos] = i;
            }
        }

        // Create Sapling OutputDescriptions
        for (i, output) in outputs.into_iter().enumerate() {
            let output_desc = if let Some((pos, output)) = output {
                // Record the post-randomized output location
                tx_metadata.output_indices[pos] = i;

                output.build(prover, &mut ctx, &mut self.rng)
            } else {
                // This is a dummy output
                let (dummy_to, dummy_note) = {
                    let (diversifier, g_d) = {
                        let mut diversifier;
                        let g_d;
                        loop {
                            let mut d = [0; 11];
                            self.rng.fill_bytes(&mut d);
                            diversifier = Diversifier(d);
                            if let Some(val) = diversifier.g_d() {
                                g_d = val;
                                break;
                            }
                        }
                        (diversifier, g_d)
                    };

                    let (pk_d, payment_address) = loop {
                        let dummy_ivk = jubjub::Fr::random(&mut self.rng);
                        let pk_d = g_d * dummy_ivk;
                        if let Some(addr) = PaymentAddress::from_parts(diversifier, pk_d.clone()) {
                            break (pk_d, addr);
                        }
                    };

                    let rseed = generate_random_rseed(&self.params, self.height, &mut self.rng);

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

                let esk = dummy_note.generate_or_derive_esk(&mut self.rng);
                let epk = dummy_note.g_d * esk;

                let (zkproof, cv) = prover.output_proof(
                    &mut ctx,
                    esk,
                    dummy_to,
                    dummy_note.rcm(),
                    dummy_note.value,
                );

                let cmu = dummy_note.cmu();

                let mut enc_ciphertext = [0u8; 580];
                let mut out_ciphertext = [0u8; 80];
                self.rng.fill_bytes(&mut enc_ciphertext[..]);
                self.rng.fill_bytes(&mut out_ciphertext[..]);

                OutputDescription {
                    cv,
                    cmu,
                    ephemeral_key: epk.into(),
                    enc_ciphertext,
                    out_ciphertext,
                    zkproof,
                }
            };

            self.mtx.shielded_outputs.push(output_desc);
        }

        //
        // Signatures
        //

        let mut sighash = [0u8; 32];
        sighash.copy_from_slice(&signature_hash_data(
            &self.mtx,
            consensus_branch_id,
            SIGHASH_ALL,
            None,
        ));

        // Create Sapling spendAuth and binding signatures
        for (i, (_, spend)) in spends.into_iter().enumerate() {
            self.mtx.shielded_spends[i].spend_auth_sig = Some(spend_sig(
                PrivateKey(spend.extsk.expsk.ask),
                spend.alpha,
                &sighash,
                &mut self.rng,
            ));
        }

        // Add a binding signature if needed
        if binding_sig_needed {
            self.mtx.binding_sig = Some(
                prover
                    .binding_sig(&mut ctx, self.mtx.value_balance, &sighash)
                    .map_err(|()| Error::BindingSig)?,
            );
        } else {
            self.mtx.binding_sig = None;
        }

        // Transparent signatures
        self.transparent_inputs
            .apply_signatures(&mut self.mtx, consensus_branch_id);

        Ok((
            self.mtx.freeze().expect("Transaction should be complete"),
            tx_metadata,
        ))
    }
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use rand_core::OsRng;
    use std::marker::PhantomData;

    use super::{Builder, Error};
    use crate::{
        consensus::{self, Network::TestNetwork, H0},
        legacy::TransparentAddress,
        merkle_tree::{CommitmentTree, IncrementalWitness},
        primitives::Rseed,
        prover::mock::MockTxProver,
        sapling::Node,
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
    };

    #[test]
    fn fails_on_negative_output() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = extfvk.fvk.ovk;
        let to = extfvk.default_address().unwrap().1;

        let mut builder = Builder::new(TestNetwork, H0);
        assert_eq!(
            builder.add_sapling_output(Some(ovk), to, Amount::from_i64(-1).unwrap(), None),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn binding_sig_absent_if_no_shielded_spend_or_output() {
        use crate::consensus::{NetworkUpgrade, Parameters};
        use crate::transaction::{
            builder::{self, TransparentInputs},
            TransactionData,
        };

        let sapling_activation_height = TestNetwork
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        // Create a builder with 0 fee, so we can construct t outputs
        let mut builder = builder::Builder {
            params: TestNetwork,
            rng: OsRng,
            height: sapling_activation_height,
            mtx: TransactionData::new(),
            fee: Amount::zero(),
            anchor: None,
            spends: vec![],
            outputs: vec![],
            transparent_inputs: TransparentInputs::default(),
            change_address: None,
            phantom: PhantomData,
        };

        // Create a tx with only t output. No binding_sig should be present
        builder
            .add_transparent_output(&TransparentAddress::PublicKey([0; 20]), Amount::zero())
            .unwrap();

        let (tx, _) = builder
            .build(consensus::BranchId::Sapling, &MockTxProver)
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
        let mut tree = CommitmentTree::new();
        tree.append(cmu1).unwrap();
        let witness1 = IncrementalWitness::from_tree(&tree);

        let mut builder = Builder::new(TestNetwork, H0);

        // Create a tx with a sapling spend. binding_sig should be present
        builder
            .add_sapling_spend(
                extsk.clone(),
                *to.diversifier(),
                note1.clone(),
                witness1.path().unwrap(),
            )
            .unwrap();

        builder
            .add_transparent_output(&TransparentAddress::PublicKey([0; 20]), Amount::zero())
            .unwrap();

        // Expect a binding signature error, because our inputs aren't valid, but this shows
        // that a binding signature was attempted
        assert_eq!(
            builder.build(consensus::BranchId::Sapling, &MockTxProver),
            Err(Error::BindingSig)
        );
    }

    #[test]
    fn fails_on_negative_transparent_output() {
        let mut builder = Builder::new(TestNetwork, H0);
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
            let builder = Builder::new(TestNetwork, H0);
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-10000).unwrap()))
            );
        }

        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = Some(extfvk.fvk.ovk);
        let to = extfvk.default_address().unwrap().1;

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = Builder::new(TestNetwork, H0);
            builder
                .add_sapling_output(
                    ovk.clone(),
                    to.clone(),
                    Amount::from_u64(50000).unwrap(),
                    None,
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-60000).unwrap()))
            );
        }

        // Fail if there is only a transparent output
        // 0.0005 t-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = Builder::new(TestNetwork, H0);
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(50000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-60000).unwrap()))
            );
        }

        let note1 = to
            .create_note(59999, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cmu1 = Node::new(note1.cmu().to_repr());
        let mut tree = CommitmentTree::new();
        tree.append(cmu1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(&tree);

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.00059999 z-ZEC in
        {
            let mut builder = Builder::new(TestNetwork, H0);
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
                    ovk.clone(),
                    to.clone(),
                    Amount::from_u64(30000).unwrap(),
                    None,
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(20000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
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
            let mut builder = Builder::new(TestNetwork, H0);
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
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::BindingSig)
            )
        }
    }
}
