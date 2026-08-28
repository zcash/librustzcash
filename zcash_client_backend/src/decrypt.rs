use std::collections::HashMap;

use sapling::note_encryption::{PreparedIncomingViewingKey, SaplingDomain};
use zcash_keys::keys::{OutgoingViewingKey, UnifiedFullViewingKey};
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};
use zcash_primitives::{
    transaction::Transaction, transaction::components::sapling::zip212_enforcement,
};
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BlockHeight, NetworkUpgrade},
    memo::MemoBytes,
    value::Zatoshis,
};
use zip32::Scope;

use crate::data_api::DecryptedTransaction;

#[cfg(feature = "orchard")]
use orchard::note_encryption::{
    DomainVersion, IronwoodVersion, NoteEncryptionDomain, OrchardVersion,
};

/// An enumeration of the possible relationships a TXO can have to the wallet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransferType {
    /// The output was received on one of the wallet's external addresses via decryption using the
    /// associated incoming viewing key, or at one of the wallet's transparent addresses.
    Incoming,
    /// The output is internal to a single wallet account, e.g. change: the recipient and the
    /// funder are the same wallet account. For shielded outputs, this corresponds to decryption
    /// using the account's internal incoming viewing key.
    AccountInternal,
    /// The output is internal to the wallet but spans accounts: a wallet account funded the
    /// transaction and a different wallet account received the output. Only produced for
    /// transparent outputs; shielded cross-account transfers are observed as separate `Outgoing`
    /// (from the funder) and `Incoming` (to the recipient) outputs.
    WalletInternal,
    /// The output was decrypted using one of the wallet's outgoing viewing keys, or was created
    /// in a transaction constructed by this wallet.
    Outgoing,
}

/// A decrypted shielded output.
pub struct DecryptedOutput<Note, AccountId> {
    index: usize,
    note: Note,
    value_pool: ShieldedPool,
    account: AccountId,
    memo: MemoBytes,
    transfer_type: TransferType,
}

impl<Note, AccountId> DecryptedOutput<Note, AccountId> {
    pub fn new(
        index: usize,
        note: Note,
        value_pool: ShieldedPool,
        account: AccountId,
        memo: MemoBytes,
        transfer_type: TransferType,
    ) -> Self {
        Self {
            index,
            note,
            value_pool,
            account,
            memo,
            transfer_type,
        }
    }

    /// The index of the output within the shielded outputs of the Sapling bundle or the actions of
    /// the Orchard bundle, depending upon the type of [`Self::note`].
    pub fn index(&self) -> usize {
        self.index
    }

    /// The note within the output.
    pub fn note(&self) -> &Note {
        &self.note
    }
    /// Returns the value pool to which the note contributes its value.
    pub fn value_pool(&self) -> ShieldedPool {
        self.value_pool
    }
    /// The account that decrypted the note.
    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// The memo bytes included with the note.
    pub fn memo(&self) -> &MemoBytes {
        &self.memo
    }

    /// Returns a [`TransferType`] value that is determined based upon what type of key was used to
    /// decrypt the transaction.
    pub fn transfer_type(&self) -> TransferType {
        self.transfer_type
    }
}

impl<A> DecryptedOutput<sapling::Note, A> {
    pub fn note_value(&self) -> Zatoshis {
        Zatoshis::from_u64(self.note.value().inner())
            .expect("Sapling note value is expected to have been validated by consensus.")
    }
}

#[cfg(feature = "orchard")]
impl<A> DecryptedOutput<orchard::note::Note, A> {
    pub fn note_value(&self) -> Zatoshis {
        Zatoshis::from_u64(self.note.value().inner())
            .expect("Orchard note value is expected to have been validated by consensus.")
    }
}

/// Returns every outgoing viewing key that a [ZIP 316]-compliant sender may have used to encrypt
/// the outgoing ciphertexts of a transaction funded from the account that `ufvk` belongs to.
///
/// A sender selects one `(external, internal)` OVK pair for the entire transaction, taken from the
/// protocol that the spent funds came from, and uses that pair for every shielded output of the
/// transaction irrespective of the pool each output lands in; an OVK is pool-agnostic input to the
/// outgoing-ciphertext KDF. The pool that funded a transaction cannot be determined from the
/// transaction alone, so recovery must try each key the account is able to produce: Orchard
/// external and internal, Sapling external and internal, and the transparent-derived pair.
///
/// [ZIP 316]: https://zips.z.cash/zip-0316#usage-of-outgoing-viewing-keys
fn candidate_ovks(ufvk: &UnifiedFullViewingKey) -> Vec<OutgoingViewingKey> {
    // Candidates are ordered by the ZIP 316 preference order of the item that produced them, with
    // the external scope before the internal scope, so that the most likely candidate is tried
    // first; correctness does not depend upon the order.
    let mut ovks = Vec::with_capacity(6);

    #[cfg(feature = "orchard")]
    if let Some(fvk) = ufvk.orchard() {
        ovks.push(fvk.to_ovk(Scope::External).into());
        ovks.push(fvk.to_ovk(Scope::Internal).into());
    }

    if let Some(dfvk) = ufvk.sapling() {
        ovks.push(dfvk.to_ovk(Scope::External).into());
        ovks.push(dfvk.to_ovk(Scope::Internal).into());
    }

    #[cfg(feature = "transparent-inputs")]
    if let Some(pubkey) = ufvk.transparent() {
        let (internal, external) = pubkey.ovks_for_shielding();
        ovks.push(external.as_bytes().into());
        ovks.push(internal.as_bytes().into());
    }

    ovks
}

/// Scans a [`Transaction`] for any information that can be decrypted by the set of
/// [`UnifiedFullViewingKey`]s.
///
/// # Parameters
/// - `params`: The network parameters corresponding to the network the transaction
///   was created for.
/// - `mined_height`: The height at which the transaction was mined, or `None` for
///   unmined transactions.
/// - `chain_tip_height`: The current chain tip height, if known. This parameter
///   will be unused if `mined_height.is_some()`.
/// - `tx`: The transaction to decrypt.
/// - `ufvks`: The [`UnifiedFullViewingKey`]s to use in trial decryption, keyed
///   by the identifiers for the wallet accounts they correspond to.
pub fn decrypt_transaction<'a, P: consensus::Parameters, AccountId: Copy>(
    params: &P,
    mined_height: Option<BlockHeight>,
    chain_tip_height: Option<BlockHeight>,
    tx: &'a Transaction,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
) -> DecryptedTransaction<'a, Transaction, AccountId> {
    let zip212_enforcement = zip212_enforcement(
        params,
        // Height is block height for mined transactions, and the "mempool height" (chain height + 1)
        // for mempool transactions. We fall back to Sapling activation if we have no other
        // information.
        mined_height.unwrap_or_else(|| {
            chain_tip_height
                .map(|max_height| max_height + 1) // "mempool height"
                .or_else(|| params.activation_height(NetworkUpgrade::Sapling))
                // Fall back to the genesis block in regtest mode.
                .unwrap_or_else(|| BlockHeight::from(0))
        }),
    );
    let sapling_bundle = tx.sapling_bundle();
    let sapling_outputs = sapling_bundle
        .iter()
        .flat_map(|bundle| {
            ufvks.iter().flat_map(|(account, ufvk)| {
                let account = *account;
                let sapling_domain = SaplingDomain::new(zip212_enforcement);
                // An account can only receive a Sapling output if its UFVK has a Sapling item,
                // but it can fund one from any pool, so outgoing recovery is attempted for
                // every account.
                let ivks = ufvk.sapling().map(|dfvk| {
                    (
                        PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::External)),
                        PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::Internal)),
                    )
                });
                let ovks = candidate_ovks(ufvk)
                    .into_iter()
                    .map(::sapling::keys::OutgoingViewingKey::from)
                    .collect::<Vec<_>>();

                bundle
                    .shielded_outputs()
                    .iter()
                    .enumerate()
                    .flat_map(move |(index, output)| {
                        ivks.as_ref()
                            .and_then(|(ivk_external, ivk_internal)| {
                                try_note_decryption(&sapling_domain, ivk_external, output)
                                    .map(|ret| (ret, TransferType::Incoming))
                                    .or_else(|| {
                                        try_note_decryption(&sapling_domain, ivk_internal, output)
                                            .map(|ret| (ret, TransferType::AccountInternal))
                                    })
                            })
                            .or_else(|| {
                                // Recovery under any candidate OVK yields `Outgoing`
                                // unconditionally: the incoming and internal trial decryptions
                                // above have already run and failed, so this account is not the
                                // recipient of the output. Which candidate matched identifies
                                // only the pool the sender spent from, not the recipient.
                                ovks.iter()
                                    .find_map(|ovk| {
                                        try_output_recovery_with_ovk(
                                            &sapling_domain,
                                            ovk,
                                            output,
                                            output.cv(),
                                            output.out_ciphertext(),
                                        )
                                    })
                                    .map(|ret| (ret, TransferType::Outgoing))
                            })
                            .into_iter()
                            .map(move |((note, _, memo), transfer_type)| {
                                DecryptedOutput::new(
                                    index,
                                    note,
                                    ShieldedPool::Sapling,
                                    account,
                                    MemoBytes::from_bytes(&memo).expect("correct length"),
                                    transfer_type,
                                )
                            })
                    })
            })
        })
        .collect();

    // Trial-decrypt an Orchard-family (Orchard or Ironwood) bundle. The two bundle kinds are
    // protocol-equivalent for trial decryption: both are Orchard-shaped and use the account's
    // Orchard viewing keys. They differ only in the note plaintext version their domain accepts
    // (selected by `V`: version 2 for [`OrchardVersion`], version 3 for [`IronwoodVersion`]) and
    // in the value pool their notes belong to. Decrypting a bundle under the other kind's domain
    // would silently detect nothing.
    #[cfg(feature = "orchard")]
    fn decrypt_orchard_protocol_bundle<V: DomainVersion, AccountId: Copy>(
        ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
        bundle: &orchard::bundle::Bundle<
            orchard::bundle::Authorized,
            zcash_protocol::value::ZatBalance,
        >,
        pool: orchard::ValuePool,
    ) -> impl Iterator<Item = DecryptedOutput<(orchard::Note, orchard::ValuePool), AccountId>> {
        let shielded_pool = crate::wallet::shielded_pool_for_value_pool(pool);
        ufvks.iter().flat_map(move |(account, ufvk)| {
            let account = *account;
            // An account can only receive an Orchard-family output if its UFVK has an Orchard
            // item, but it can fund one from any pool, so outgoing recovery is attempted for
            // every account.
            let ivks = ufvk.orchard().map(|fvk| {
                (
                    orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External)),
                    orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::Internal)),
                )
            });
            let ovks = candidate_ovks(ufvk)
                .into_iter()
                .map(orchard::keys::OutgoingViewingKey::from)
                .collect::<Vec<_>>();

            bundle
                .actions()
                .iter()
                .enumerate()
                .flat_map(move |(index, action)| {
                    let domain = NoteEncryptionDomain::<V>::for_action(action);
                    ivks.as_ref()
                        .and_then(|(ivk_external, ivk_internal)| {
                            try_note_decryption(&domain, ivk_external, action)
                                .map(|ret| (ret, TransferType::Incoming))
                                .or_else(|| {
                                    try_note_decryption(&domain, ivk_internal, action)
                                        .map(|ret| (ret, TransferType::AccountInternal))
                                })
                        })
                        .or_else(|| {
                            // Recovery under any candidate OVK yields `Outgoing`
                            // unconditionally: the incoming and internal trial decryptions
                            // above have already run and failed, so this account is not the
                            // recipient of the output. Which candidate matched identifies only
                            // the pool the sender spent from, not the recipient.
                            ovks.iter()
                                .find_map(|ovk| {
                                    try_output_recovery_with_ovk(
                                        &domain,
                                        ovk,
                                        action,
                                        action.cv_net(),
                                        &action.encrypted_note().out_ciphertext,
                                    )
                                })
                                .map(|ret| (ret, TransferType::Outgoing))
                        })
                        .into_iter()
                        .map(move |((note, _, memo), transfer_type)| {
                            DecryptedOutput::new(
                                index,
                                (note, pool),
                                shielded_pool,
                                account,
                                MemoBytes::from_bytes(&memo).expect("correct length"),
                                transfer_type,
                            )
                        })
                })
        })
    }

    #[cfg(feature = "orchard")]
    let orchard_outputs = tx
        .orchard_bundle()
        .iter()
        .flat_map(|bundle| {
            decrypt_orchard_protocol_bundle::<OrchardVersion, _>(
                ufvks,
                bundle,
                orchard::ValuePool::Orchard,
            )
        })
        .collect();

    #[cfg(feature = "orchard")]
    let ironwood_outputs = tx
        .ironwood_bundle()
        .iter()
        .flat_map(|bundle| {
            decrypt_orchard_protocol_bundle::<IronwoodVersion, _>(
                ufvks,
                bundle,
                orchard::ValuePool::Ironwood,
            )
        })
        .collect();

    DecryptedTransaction::new(
        mined_height,
        tx,
        sapling_outputs,
        #[cfg(feature = "orchard")]
        orchard_outputs,
        #[cfg(feature = "orchard")]
        ironwood_outputs,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rand_chacha::ChaChaRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};
    use sapling::{
        note_encryption::sapling_note_encryption,
        util::generate_random_rseed,
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    };
    use zcash_keys::keys::{OutgoingViewingKey, UnifiedFullViewingKey, UnifiedSpendingKey};
    use zcash_note_encryption::Domain;
    use zcash_primitives::transaction::{
        Authorized, Transaction, TransactionData, TxVersion,
        components::sapling::zip212_enforcement,
    };
    use zcash_protocol::{
        consensus::{BlockHeight, BranchId, Network},
        memo::MemoBytes,
        value::{ZatBalance, Zatoshis},
    };
    use zip32::{AccountId, Scope};

    use super::{SaplingDomain, TransferType, decrypt_transaction};

    /// A height at which ZIP 212 is fully enforced on the test network, so that the note
    /// plaintexts built here and the domain `decrypt_transaction` reconstructs agree.
    const MINED_HEIGHT: u32 = 2_000_000;

    const VALUE: Zatoshis = Zatoshis::const_from_u64(100_000);

    /// The account whose keys are used to attempt recovery.
    fn wallet_ufvk() -> UnifiedFullViewingKey {
        UnifiedSpendingKey::from_seed(&Network::TestNetwork, &[0xab; 32], AccountId::ZERO)
            .expect("seed produces a valid unified spending key")
            .to_unified_full_viewing_key()
    }

    /// A key belonging to someone else, used to produce recipient addresses that the wallet
    /// cannot detect with any of its incoming viewing keys.
    fn counterparty_ufvk() -> UnifiedFullViewingKey {
        UnifiedSpendingKey::from_seed(&Network::TestNetwork, &[0xcd; 32], AccountId::ZERO)
            .expect("seed produces a valid unified spending key")
            .to_unified_full_viewing_key()
    }

    /// Every outgoing viewing key that a ZIP 316-compliant sender may select for a transaction
    /// funded from the account that `ufvk` belongs to, labelled by the item and scope it is
    /// derived from. Derived here directly from the UFVK's items, independently of the candidate
    /// set that `decrypt_transaction` builds.
    fn zip316_sender_ovks(ufvk: &UnifiedFullViewingKey) -> Vec<(&'static str, OutgoingViewingKey)> {
        let mut ovks: Vec<(&'static str, OutgoingViewingKey)> = Vec::new();

        #[cfg(feature = "orchard")]
        {
            let fvk = ufvk.orchard().expect("UFVK has an Orchard item");
            ovks.push(("Orchard external", fvk.to_ovk(Scope::External).into()));
            ovks.push(("Orchard internal", fvk.to_ovk(Scope::Internal).into()));
        }

        let dfvk = ufvk.sapling().expect("UFVK has a Sapling item");
        ovks.push(("Sapling external", dfvk.to_ovk(Scope::External).into()));
        ovks.push(("Sapling internal", dfvk.to_ovk(Scope::Internal).into()));

        #[cfg(feature = "transparent-inputs")]
        {
            let tfvk = ufvk.transparent().expect("UFVK has a transparent item");
            let (internal, external) = tfvk.ovks_for_shielding();
            // `ovks_for_shielding` returns the pair in (internal, external) order, and both halves
            // become raw bytes as soon as they are used, so only this destructure records which is
            // which. Pin each half against the accessor that names it, so that a swap here cannot
            // pass by relabelling both ends consistently.
            assert_eq!(external.as_bytes(), tfvk.external_ovk().as_bytes());
            assert_eq!(internal.as_bytes(), tfvk.internal_ovk().as_bytes());
            ovks.push(("transparent external", external.as_bytes().into()));
            ovks.push(("transparent internal", internal.as_bytes().into()));
        }

        ovks
    }

    /// A 32-byte value that is not derivable from any wallet key.
    fn foreign_ovk() -> OutgoingViewingKey {
        OutgoingViewingKey::from([0x5a; 32])
    }

    /// Builds a v5 transaction whose sole Sapling output pays `recipient`, with the outgoing
    /// ciphertext encrypted under `ovk`.
    ///
    /// The zero-knowledge proof and binding signature are dummies; neither participates in note
    /// decryption or outgoing-ciphertext recovery.
    fn sapling_tx_paying(
        recipient: ::sapling::PaymentAddress,
        ovk: OutgoingViewingKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Transaction {
        let enforcement =
            zip212_enforcement(&Network::TestNetwork, BlockHeight::from_u32(MINED_HEIGHT));
        let value = NoteValue::from_raw(VALUE.into_u64());
        let rseed = generate_random_rseed(enforcement, rng);
        let note = ::sapling::Note::from_parts(recipient, value, rseed);
        let cv = ValueCommitment::derive(value, ValueCommitTrapdoor::random(&mut *rng));
        let cmu = note.cmu();

        let encryptor =
            sapling_note_encryption(Some(ovk.into()), note, MemoBytes::empty().into_bytes(), rng);
        let ephemeral_key = SaplingDomain::epk_bytes(encryptor.epk());
        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu, rng);

        let output = ::sapling::bundle::OutputDescription::from_parts(
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            [0u8; core::mem::size_of::<::sapling::bundle::GrothProofBytes>()],
        );

        let bundle = ::sapling::Bundle::from_parts(
            vec![],
            vec![output],
            ZatBalance::const_from_i64(-(VALUE.into_u64() as i64)),
            ::sapling::bundle::Authorized {
                binding_sig: redjubjub::Signature::from([0u8; 64]),
            },
        )
        .expect("the bundle has an output");

        TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            BlockHeight::from_u32(MINED_HEIGHT + 100),
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            Zatoshis::ZERO,
            None,
            None,
            Some(bundle),
            None,
        )
        .freeze()
        .expect("the transaction data is well-formed")
    }

    /// Recovers the wallet's view of a transaction, returning the transfer type and value of each
    /// Sapling output that could be decrypted.
    fn decrypt_sapling(tx: &Transaction) -> Vec<(TransferType, Zatoshis)> {
        let mut ufvks = HashMap::new();
        ufvks.insert(0u32, wallet_ufvk());

        decrypt_transaction(
            &Network::TestNetwork,
            Some(BlockHeight::from_u32(MINED_HEIGHT)),
            None,
            tx,
            &ufvks,
        )
        .sapling_outputs()
        .iter()
        .map(|output| (output.transfer_type(), output.note_value()))
        .collect()
    }

    /// A Sapling output is recovered under every OVK a ZIP 316-compliant sender might have chosen
    /// for the transaction, not only the Sapling external-scope one.
    #[test]
    fn sapling_output_recovered_with_every_zip316_ovk() {
        let mut rng = ChaChaRng::seed_from_u64(0);
        let recipient = counterparty_ufvk()
            .sapling()
            .expect("UFVK has a Sapling item")
            .default_address()
            .1;

        for (label, ovk) in zip316_sender_ovks(&wallet_ufvk()) {
            let tx = sapling_tx_paying(recipient, ovk, &mut rng);
            assert_eq!(
                decrypt_sapling(&tx),
                vec![(TransferType::Outgoing, VALUE)],
                "output encrypted under the {label} OVK was not recovered"
            );
        }
    }

    /// An outgoing ciphertext that no wallet key can open is not reported.
    #[test]
    fn sapling_output_not_recovered_with_foreign_ovk() {
        let mut rng = ChaChaRng::seed_from_u64(1);
        let recipient = counterparty_ufvk()
            .sapling()
            .expect("UFVK has a Sapling item")
            .default_address()
            .1;

        let tx = sapling_tx_paying(recipient, foreign_ovk(), &mut rng);
        assert_eq!(decrypt_sapling(&tx), vec![]);
    }

    /// Builds a v5 transaction whose sole Orchard action creates a note paying `recipient`, with
    /// the outgoing ciphertext encrypted under `ovk`.
    ///
    /// The action's spend half is vestigial here: it carries an arbitrary nullifier, whose only
    /// role is to seed the note's `rho`. The zero-knowledge proof and signatures are dummies;
    /// none of them participates in note decryption or outgoing-ciphertext recovery.
    #[cfg(feature = "orchard")]
    fn orchard_tx_paying(
        recipient: ::orchard::Address,
        ovk: OutgoingViewingKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Transaction {
        use ::orchard::{
            Anchor, Proof,
            bundle::{Authorized as OrchardAuthorized, BundleVersion, Flags},
            note::{
                ExtractedNoteCommitment, Nullifier, RandomSeed, Rho, TransmittedNoteCiphertext,
            },
            note_encryption::OrchardNoteEncryption,
            primitives::redpallas::{SigningKey, SpendAuth, VerificationKey},
            value::{NoteValue as OrchardNoteValue, ValueCommitTrapdoor, ValueCommitment},
        };
        use nonempty::NonEmpty;

        let mut nf_bytes = [0u8; 32];
        rng.fill_bytes(&mut nf_bytes);
        let nf_old = loop {
            let nf = Nullifier::from_bytes(&nf_bytes);
            if nf.is_some().into() {
                break nf.unwrap();
            }
            rng.fill_bytes(&mut nf_bytes);
        };
        // `Rho::from_nf_old(nf)` is `Rho(nf.inner())`, which this reproduces through the
        // public byte encodings so that the domain reconstructed from the action's revealed
        // nullifier matches the one the note was created under.
        let rho = Rho::from_bytes(&nf_old.to_bytes()).expect("a nullifier is a canonical Rho");
        let rseed = loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            let rseed = RandomSeed::from_bytes(bytes, &rho);
            if rseed.is_some().into() {
                break rseed.unwrap();
            }
        };

        let value = OrchardNoteValue::from_raw(VALUE.into_u64());
        let note =
            ::orchard::Note::from_parts(recipient, value, rho, rseed, ::orchard::NoteVersion::V2)
                .expect("the note parts are consistent");
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let cv_net = ValueCommitment::derive(
            OrchardNoteValue::from_raw(0) - value,
            ValueCommitTrapdoor::from_bytes([0u8; 32]).expect("zero is a canonical scalar"),
        );

        let encryptor = OrchardNoteEncryption::new(Some(ovk.into()), note, [0u8; 512]);
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: ::orchard::note_encryption::OrchardDomain::epk_bytes(encryptor.epk()).0,
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, rng),
        };

        let rk = loop {
            let mut rk_bytes = [0u8; 32];
            rng.fill_bytes(&mut rk_bytes);
            if let Ok(sk) = SigningKey::<SpendAuth>::try_from(rk_bytes) {
                break VerificationKey::<SpendAuth>::from(&sk);
            }
        };

        let action = ::orchard::Action::from_parts(
            nf_old,
            rk,
            cmx,
            encrypted_note,
            cv_net,
            ::orchard::primitives::redpallas::Signature::from([0u8; 64]),
        )
        .expect("the action parts are valid");

        let bundle = ::orchard::Bundle::try_from_parts(
            NonEmpty::new(action),
            Flags::ENABLED,
            ZatBalance::const_from_i64(-(VALUE.into_u64() as i64)),
            Anchor::empty_tree(),
            OrchardAuthorized::from_parts(
                Proof::new(vec![0u8; Proof::expected_proof_size(1)]),
                ::orchard::primitives::redpallas::Signature::from([0u8; 64]),
            ),
            BundleVersion::orchard_v2(),
        )
        .expect("the bundle parts are valid");

        TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            BlockHeight::from_u32(MINED_HEIGHT + 100),
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            Zatoshis::ZERO,
            None,
            None,
            None,
            Some(bundle),
        )
        .freeze()
        .expect("the transaction data is well-formed")
    }

    /// Recovers the wallet's view of a transaction, returning the transfer type and value of each
    /// Orchard output that could be decrypted.
    #[cfg(feature = "orchard")]
    fn decrypt_orchard_with(
        ufvk: UnifiedFullViewingKey,
        tx: &Transaction,
    ) -> Vec<(TransferType, Zatoshis)> {
        let mut ufvks = HashMap::new();
        ufvks.insert(0u32, ufvk);

        decrypt_transaction(
            &Network::TestNetwork,
            Some(BlockHeight::from_u32(MINED_HEIGHT)),
            None,
            tx,
            &ufvks,
        )
        .orchard_outputs()
        .iter()
        .map(|output| {
            let (note, _) = output.note();
            (
                output.transfer_type(),
                Zatoshis::from_u64(note.value().inner()).expect("note value is in range"),
            )
        })
        .collect()
    }

    #[cfg(feature = "orchard")]
    fn decrypt_orchard(tx: &Transaction) -> Vec<(TransferType, Zatoshis)> {
        decrypt_orchard_with(wallet_ufvk(), tx)
    }

    /// An Orchard action is recovered under every OVK a ZIP 316-compliant sender might have chosen
    /// for the transaction, including the Sapling and transparent-derived ones that a sender
    /// spending from those pools uses. This is the cross-pool case: an OVK is pool-agnostic input
    /// to the outgoing-ciphertext KDF, so the pool an output lands in says nothing about which key
    /// encrypted it.
    #[cfg(feature = "orchard")]
    #[test]
    fn orchard_action_recovered_with_every_zip316_ovk() {
        let mut rng = ChaChaRng::seed_from_u64(2);
        let recipient = counterparty_ufvk()
            .orchard()
            .expect("UFVK has an Orchard item")
            .address_at(0u32, Scope::External);

        for (label, ovk) in zip316_sender_ovks(&wallet_ufvk()) {
            let tx = orchard_tx_paying(recipient, ovk, &mut rng);
            assert_eq!(
                decrypt_orchard(&tx),
                vec![(TransferType::Outgoing, VALUE)],
                "action encrypted under the {label} OVK was not recovered"
            );
        }
    }

    /// An outgoing ciphertext that no wallet key can open is not reported.
    #[cfg(feature = "orchard")]
    #[test]
    fn orchard_action_not_recovered_with_foreign_ovk() {
        let mut rng = ChaChaRng::seed_from_u64(3);
        let recipient = counterparty_ufvk()
            .orchard()
            .expect("UFVK has an Orchard item")
            .address_at(0u32, Scope::External);

        let tx = orchard_tx_paying(recipient, foreign_ovk(), &mut rng);
        assert_eq!(decrypt_orchard(&tx), vec![]);
    }

    /// An account whose UFVK has no Orchard item still recovers an Orchard action that it funded
    /// from its Sapling notes. Having no Orchard item only means the account cannot be the
    /// *recipient* of an Orchard action; it can still be the sender, in which case the outgoing
    /// ciphertext is encrypted under its Sapling OVK.
    #[cfg(feature = "orchard")]
    #[test]
    fn orchard_action_recovered_by_ufvk_without_orchard_item() {
        let mut rng = ChaChaRng::seed_from_u64(4);
        let recipient = counterparty_ufvk()
            .orchard()
            .expect("UFVK has an Orchard item")
            .address_at(0u32, Scope::External);

        let wallet = wallet_ufvk();
        let dfvk = wallet.sapling().expect("UFVK has a Sapling item").clone();
        let sapling_only = UnifiedFullViewingKey::new(
            #[cfg(feature = "transparent-inputs")]
            None,
            Some(dfvk.clone()),
            #[cfg(feature = "orchard")]
            None,
        )
        .expect("a Sapling-only UFVK is valid");

        let tx = orchard_tx_paying(recipient, dfvk.to_ovk(Scope::External).into(), &mut rng);
        assert_eq!(
            decrypt_orchard_with(sapling_only, &tx),
            vec![(TransferType::Outgoing, VALUE)]
        );
    }
}
