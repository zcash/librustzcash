//! Structs for building transactions.

use ff::Field;
use pairing::bls12_381::{Bls12, Fr};
use rand::{rngs::OsRng, seq::SliceRandom, CryptoRng, RngCore};
use sapling_crypto::{
    jubjub::fs::Fs,
    primitives::{Diversifier, Note, PaymentAddress},
    redjubjub::PrivateKey,
};
use zip32::ExtendedSpendingKey;

use crate::{
    keys::OutgoingViewingKey,
    merkle_tree::{CommitmentTreeWitness, IncrementalWitness},
    note_encryption::{generate_esk, Memo, SaplingNoteEncryption},
    prover::TxProver,
    sapling::{spend_sig, Node},
    transaction::{
        components::{Amount, OutputDescription, SpendDescription},
        signature_hash_data, Transaction, TransactionData, SIGHASH_ALL,
    },
    JUBJUB,
};

const DEFAULT_FEE: Amount = Amount(10000);
const DEFAULT_TX_EXPIRY_DELTA: u32 = 20;

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See https://github.com/zcash/zcash/issues/3615
const MIN_SHIELDED_OUTPUTS: usize = 2;

#[derive(Debug)]
pub struct Error(ErrorKind);

impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    AnchorMismatch,
    BindingSig,
    ChangeIsNegative(i64),
    InvalidAddress,
    InvalidAmount,
    InvalidWitness,
    NoChangeAddress,
    SpendProof,
}

struct SpendDescriptionInfo {
    extsk: ExtendedSpendingKey,
    diversifier: Diversifier,
    note: Note<Bls12>,
    alpha: Fs,
    witness: CommitmentTreeWitness<Node>,
}

pub struct SaplingOutput {
    ovk: OutgoingViewingKey,
    to: PaymentAddress<Bls12>,
    note: Note<Bls12>,
    memo: Memo,
}

impl SaplingOutput {
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        ovk: OutgoingViewingKey,
        to: PaymentAddress<Bls12>,
        value: Amount,
        memo: Option<Memo>,
    ) -> Result<Self, Error> {
        let g_d = match to.g_d(&JUBJUB) {
            Some(g_d) => g_d,
            None => return Err(Error(ErrorKind::InvalidAddress)),
        };
        if value.0 < 0 {
            return Err(Error(ErrorKind::InvalidAmount));
        }

        let rcm = Fs::random(rng);

        let note = Note {
            g_d,
            pk_d: to.pk_d.clone(),
            value: value.0 as u64,
            r: rcm,
        };

        Ok(SaplingOutput {
            ovk,
            to,
            note,
            memo: memo.unwrap_or_default(),
        })
    }

    pub fn build<P: TxProver>(
        self,
        prover: &P,
        ctx: &mut P::SaplingProvingContext,
    ) -> OutputDescription {
        let encryptor =
            SaplingNoteEncryption::new(self.ovk, self.note.clone(), self.to.clone(), self.memo);

        let (zkproof, cv) = prover.output_proof(
            ctx,
            encryptor.esk().clone(),
            self.to,
            self.note.r,
            self.note.value,
        );

        let cmu = self.note.cm(&JUBJUB);

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

/// Metadata about a transaction created by a [`Builder`].
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
        self.spend_indices.get(n).map(|i| *i)
    }

    /// Returns the index within the transaction of the [`OutputDescription`] corresponding
    /// to the `n`-th call to [`Builder::add_sapling_output`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`Builder::add_sapling_output`]) is the first
    /// [`OutputDescription`] in the transaction.
    pub fn output_index(&self, n: usize) -> Option<usize> {
        self.output_indices.get(n).map(|i| *i)
    }
}

/// Generates a [`Transaction`] from its inputs and outputs.
pub struct Builder {
    rng: OsRng,
    mtx: TransactionData,
    fee: Amount,
    anchor: Option<Fr>,
    spends: Vec<SpendDescriptionInfo>,
    outputs: Vec<SaplingOutput>,
    change_address: Option<(OutgoingViewingKey, PaymentAddress<Bls12>)>,
}

impl Builder {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height,
    /// using default values for general transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new(height: u32) -> Builder {
        let mut mtx = TransactionData::new();
        mtx.expiry_height = height + DEFAULT_TX_EXPIRY_DELTA;

        Builder {
            rng: OsRng,
            mtx,
            fee: DEFAULT_FEE,
            anchor: None,
            spends: vec![],
            outputs: vec![],
            change_address: None,
        }
    }

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given witness does not have the same anchor as previous
    /// witnesses, or has no path.
    pub fn add_sapling_spend(
        &mut self,
        extsk: ExtendedSpendingKey,
        diversifier: Diversifier,
        note: Note<Bls12>,
        witness: IncrementalWitness<Node>,
    ) -> Result<(), Error> {
        // Consistency check: all anchors must equal the first one
        if let Some(anchor) = self.anchor {
            let witness_root: Fr = witness.root().into();
            if witness_root != anchor {
                return Err(Error(ErrorKind::AnchorMismatch));
            }
        } else {
            self.anchor = Some(witness.root().into())
        }
        let witness = witness.path().ok_or(Error(ErrorKind::InvalidWitness))?;

        let alpha = Fs::random(&mut self.rng);

        self.mtx.value_balance.0 += note.value as i64;

        self.spends.push(SpendDescriptionInfo {
            extsk,
            diversifier,
            note,
            alpha,
            witness,
        });

        Ok(())
    }

    /// Adds a Sapling address to send funds to.
    pub fn add_sapling_output(
        &mut self,
        ovk: OutgoingViewingKey,
        to: PaymentAddress<Bls12>,
        value: Amount,
        memo: Option<Memo>,
    ) -> Result<(), Error> {
        let output = SaplingOutput::new(&mut self.rng, ovk, to, value, memo)?;

        self.mtx.value_balance.0 -= value.0;

        self.outputs.push(output);

        Ok(())
    }

    /// Sets the Sapling address to which any change will be sent.
    ///
    /// By default, change is sent to the Sapling address corresponding to the first note
    /// being spent (i.e. the first call to [`Builder::add_sapling_spend`]).
    pub fn send_change_to(&mut self, ovk: OutgoingViewingKey, to: PaymentAddress<Bls12>) {
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
        consensus_branch_id: u32,
        prover: impl TxProver,
    ) -> Result<(Transaction, TransactionMetadata), Error> {
        let mut tx_metadata = TransactionMetadata::new();

        //
        // Consistency checks
        //

        // Valid change
        let change = self.mtx.value_balance.0 - self.fee.0;
        if change.is_negative() {
            return Err(Error(ErrorKind::ChangeIsNegative(change)));
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
                    PaymentAddress {
                        diversifier: self.spends[0].diversifier,
                        pk_d: self.spends[0].note.pk_d.clone(),
                    },
                )
            } else {
                return Err(Error(ErrorKind::NoChangeAddress));
            };

            self.add_sapling_output(change_address.0, change_address.1, Amount(change), None)?;
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
        let anchor = self.anchor.expect("anchor was set if spends were added");

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

        // Create Sapling SpendDescriptions
        for (i, (pos, spend)) in spends.iter().enumerate() {
            let proof_generation_key = spend.extsk.expsk.proof_generation_key(&JUBJUB);

            let mut nullifier = [0u8; 32];
            nullifier.copy_from_slice(&spend.note.nf(
                &proof_generation_key.into_viewing_key(&JUBJUB),
                spend.witness.position,
                &JUBJUB,
            ));

            let (zkproof, cv, rk) = prover
                .spend_proof(
                    &mut ctx,
                    proof_generation_key,
                    spend.diversifier,
                    spend.note.r,
                    spend.alpha,
                    spend.note.value,
                    anchor,
                    spend.witness.clone(),
                )
                .map_err(|()| Error(ErrorKind::SpendProof))?;

            self.mtx.shielded_spends.push(SpendDescription {
                cv,
                anchor: anchor,
                nullifier,
                rk,
                zkproof,
                spend_auth_sig: None,
            });

            // Record the post-randomized spend location
            tx_metadata.spend_indices[*pos] = i;
        }

        // Create Sapling OutputDescriptions
        for (i, output) in outputs.into_iter().enumerate() {
            let output_desc = if let Some((pos, output)) = output {
                // Record the post-randomized output location
                tx_metadata.output_indices[pos] = i;

                output.build(&prover, &mut ctx)
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
                            if let Some(val) = diversifier.g_d::<Bls12>(&JUBJUB) {
                                g_d = val;
                                break;
                            }
                        }
                        (diversifier, g_d)
                    };

                    let pk_d = {
                        let dummy_ivk = Fs::random(&mut self.rng);
                        g_d.mul(dummy_ivk, &JUBJUB)
                    };

                    (
                        PaymentAddress {
                            diversifier,
                            pk_d: pk_d.clone(),
                        },
                        Note {
                            g_d,
                            pk_d,
                            r: Fs::random(&mut self.rng),
                            value: 0,
                        },
                    )
                };

                let esk = generate_esk();
                let epk = dummy_note.g_d.mul(esk, &JUBJUB);

                let (zkproof, cv) =
                    prover.output_proof(&mut ctx, esk, dummy_to, dummy_note.r, dummy_note.value);

                let cmu = dummy_note.cm(&JUBJUB);

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
                &JUBJUB,
            ));
        }
        self.mtx.binding_sig = Some(
            prover
                .binding_sig(&mut ctx, self.mtx.value_balance.0, &sighash)
                .map_err(|()| Error(ErrorKind::BindingSig))?,
        );

        Ok((
            self.mtx.freeze().expect("Transaction should be complete"),
            tx_metadata,
        ))
    }
}

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use rand::rngs::OsRng;
    use sapling_crypto::jubjub::fs::Fs;

    use super::{Builder, ErrorKind};
    use crate::{
        merkle_tree::{CommitmentTree, IncrementalWitness},
        prover::mock::MockTxProver,
        sapling::Node,
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
        JUBJUB,
    };

    #[test]
    fn fails_on_negative_output() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = extfvk.fvk.ovk;
        let to = extfvk.default_address().unwrap().1;

        let mut builder = Builder::new(0);
        match builder.add_sapling_output(ovk, to, Amount(-1), None) {
            Err(e) => assert_eq!(e.kind(), &ErrorKind::InvalidAmount),
            Ok(_) => panic!("Should have failed"),
        }
    }

    #[test]
    fn fails_on_negative_change() {
        let mut rng = OsRng;

        // Just use the master key as the ExtendedSpendingKey for this test
        let extsk = ExtendedSpendingKey::master(&[]);

        // Fails with no inputs or outputs
        // 0.0001 t-ZEC fee
        {
            let builder = Builder::new(0);
            match builder.build(1, MockTxProver) {
                Err(e) => assert_eq!(e.kind(), &ErrorKind::ChangeIsNegative(-10000)),
                Ok(_) => panic!("Should have failed"),
            }
        }

        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = extfvk.fvk.ovk;
        let to = extfvk.default_address().unwrap().1;

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = Builder::new(0);
            builder
                .add_sapling_output(ovk.clone(), to.clone(), Amount(50000), None)
                .unwrap();
            match builder.build(1, MockTxProver) {
                Err(e) => assert_eq!(e.kind(), &ErrorKind::ChangeIsNegative(-60000)),
                Ok(_) => panic!("Should have failed"),
            }
        }

        let note1 = to
            .create_note(59999, Fs::random(&mut rng), &JUBJUB)
            .unwrap();
        let cm1 = Node::new(note1.cm(&JUBJUB).into_repr());
        let mut tree = CommitmentTree::new();
        tree.append(cm1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(&tree);

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee, 0.00059999 z-ZEC in
        {
            let mut builder = Builder::new(0);
            builder
                .add_sapling_spend(
                    extsk.clone(),
                    to.diversifier,
                    note1.clone(),
                    witness1.clone(),
                )
                .unwrap();
            builder
                .add_sapling_output(ovk.clone(), to.clone(), Amount(50000), None)
                .unwrap();
            match builder.build(1, MockTxProver) {
                Err(e) => assert_eq!(e.kind(), &ErrorKind::ChangeIsNegative(-1)),
                Ok(_) => panic!("Should have failed"),
            }
        }

        let note2 = to.create_note(1, Fs::random(&mut rng), &JUBJUB).unwrap();
        let cm2 = Node::new(note2.cm(&JUBJUB).into_repr());
        tree.append(cm2).unwrap();
        witness1.append(cm2).unwrap();
        let witness2 = IncrementalWitness::from_tree(&tree);

        // Succeeds if there is sufficient input
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee, 0.0006 z-ZEC in
        //
        // (Still fails because we are using a MockTxProver which doesn't correctly
        // compute bindingSig.)
        {
            let mut builder = Builder::new(0);
            builder
                .add_sapling_spend(extsk.clone(), to.diversifier, note1, witness1)
                .unwrap();
            builder
                .add_sapling_spend(extsk, to.diversifier, note2, witness2)
                .unwrap();
            builder
                .add_sapling_output(ovk, to, Amount(50000), None)
                .unwrap();
            match builder.build(1, MockTxProver) {
                Err(e) => assert_eq!(e.kind(), &ErrorKind::BindingSig),
                Ok(_) => panic!("Should have failed"),
            }
        }
    }
}
