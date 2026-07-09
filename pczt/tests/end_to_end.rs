use std::sync::OnceLock;

use ::transparent::{
    address::{Script, TransparentAddress},
    bundle as transparent,
    keys::{AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex},
    sighash::SighashType,
    zip48,
};
use orchard::tree::MerkleHashOrchard;
use pczt::{
    Pczt,
    roles::{
        combiner::Combiner,
        creator::Creator,
        io_finalizer::IoFinalizer,
        low_level_signer,
        prover::Prover,
        redactor::Redactor,
        signer::Signer,
        spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor,
        updater::{SpendWitnessUpdateError, Updater},
        verifier::Verifier,
    },
    v1, v2,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, PcztResult},
    fees::zip317,
    sighash::SignableInput,
    sighash_v5::v5_signature_hash,
    txid::TxIdDigester,
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::MainNetwork,
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zcash_script::script::{self, Evaluable};

static ORCHARD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
static POST_NU6_3_ORCHARD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

fn orchard_proving_key() -> &'static orchard::circuit::ProvingKey {
    ORCHARD_PROVING_KEY.get_or_init(|| {
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2)
    })
}

fn post_nu6_3_orchard_proving_key() -> &'static orchard::circuit::ProvingKey {
    POST_NU6_3_ORCHARD_PROVING_KEY.get_or_init(|| {
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3)
    })
}

fn check_round_trip(pczt: &Pczt) {
    // The v1 encoding remains available explicitly.
    v1::Pczt::try_from(pczt.clone())
        .expect("v1 encoding succeeds")
        .serialize();

    // The default encoding is the latest (v2) encoding.
    let v2_encoded = v2::Pczt::try_from(pczt.clone())
        .expect("v2 encoding succeeds")
        .serialize();

    let encoded = pczt.clone().serialize().expect("serialization succeeds");
    assert_eq!(encoded, v2_encoded);

    let reencoded = Pczt::parse(&encoded)
        .expect("can parse encoded PCZT")
        .serialize()
        .expect("serialization succeeds");
    assert_eq!(encoded, reencoded);
}

#[test]
fn transparent_to_orchard() {
    let params = MainNetwork;
    let rng = OsRng;

    // Create a transparent account to send funds from.
    let transparent_account_sk =
        AccountPrivKey::from_seed(&params, &[1; 32], zip32::AccountId::ZERO).unwrap();
    let (transparent_addr, address_index) = transparent_account_sk
        .to_account_pubkey()
        .derive_external_ivk()
        .unwrap()
        .default_address();
    let transparent_sk = transparent_account_sk
        .derive_external_secret_key(address_index)
        .unwrap();
    let secp = secp256k1::Secp256k1::signing_only();
    let transparent_pubkey = transparent_sk.public_key(&secp);
    let p2pkh_addr = TransparentAddress::from_pubkey(&transparent_pubkey);

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already have a transparent coin.
    let utxo = transparent::OutPoint::fake();
    let coin = transparent::TxOut::new(
        Zatoshis::const_from_u64(1_000_000),
        transparent_addr.script().into(),
    );

    // Create the transaction's I/O.
    let mut builder = Builder::new(
        params,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(transparent_pubkey, utxo, coin.clone())
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_fvk.to_ovk(zip32::Scope::Internal)),
            orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            Zatoshis::const_from_u64(885_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(rng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    let memo_redacted = Redactor::new(pczt.clone())
        .redact_orchard_with(|mut orchard| {
            orchard.redact_actions(|mut actions| {
                actions.replace_enc_ciphertext_with_decrypted_memo_plaintext(
                    orchard::note::NoteVersion::V2,
                );
            });
        })
        .finish();
    assert!(memo_redacted.orchard().actions().iter().all(|action| {
        matches!(
            action.output().enc_ciphertext(),
            pczt::orchard::EncCiphertext::MemoPlaintext(_)
        )
    }));

    let memo_resolved = IoFinalizer::new(memo_redacted).finalize_io().unwrap();
    assert!(memo_resolved.orchard().actions().iter().all(|action| {
        matches!(
            action.output().enc_ciphertext(),
            pczt::orchard::EncCiphertext::Encrypted(_)
        )
    }));
    check_round_trip(&memo_resolved);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    check_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    // Apply signatures.
    let mut signer = Signer::new(pczt).unwrap();
    signer.sign_transparent(0, &transparent_sk).unwrap();
    let pczt = signer.finish();
    check_round_trip(&pczt);

    // Finalize spends.
    let pczt = SpendFinalizer::new(pczt).finalize_spends().unwrap();
    check_round_trip(&pczt);

    // Grab the transaction's effects here, as it's easier.
    let tx_effects = pczt.clone().into_effects().unwrap();

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt).extract().unwrap();
    let tx_digests = tx.digest(TxIdDigester);

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);

    // Validate the transaction.
    let bundle = tx.transparent_bundle().unwrap();
    assert_eq!(bundle.vin.len(), 1);
    let txin = bundle.vin.first().unwrap();
    let sighasher = |script_code: &script::Code, hash_type: &zcash_script::signature::HashType| {
        Some(
            v5_signature_hash(
                &tx_effects,
                &SignableInput::Transparent(
                    ::transparent::sighash::SignableInput::from_parts(
                        bundle,
                        match (hash_type.signed_outputs(), hash_type.anyone_can_pay()) {
                            (zcash_script::signature::SignedOutputs::All, false) => {
                                SighashType::ALL
                            }
                            (zcash_script::signature::SignedOutputs::All, true) => {
                                SighashType::ALL_ANYONECANPAY
                            }
                            (zcash_script::signature::SignedOutputs::Single, false) => {
                                SighashType::SINGLE
                            }
                            (zcash_script::signature::SignedOutputs::Single, true) => {
                                SighashType::SINGLE_ANYONECANPAY
                            }
                            (zcash_script::signature::SignedOutputs::None, false) => {
                                SighashType::NONE
                            }
                            (zcash_script::signature::SignedOutputs::None, true) => {
                                SighashType::NONE_ANYONECANPAY
                            }
                        },
                        0,
                        &Script(script_code.clone()),
                        coin.script_pubkey(),
                        coin.value(),
                    )
                    .unwrap(),
                ),
                &tx_digests,
            )
            .as_ref()
            .try_into()
            .unwrap(),
        )
    };
    let checker = zcash_script::interpreter::CallbackTransactionSignatureChecker {
        sighash: &sighasher,
        lock_time: tx.lock_time().into(),
        is_final: txin.sequence() == 0xFFFFFFFF,
    };
    assert_eq!(
        script::Raw::from_raw_parts(
            txin.script_sig().0.to_bytes(),
            p2pkh_addr.script().to_bytes()
        )
        .eval(zcash_script::interpreter::Flags::all(), &checker),
        Ok(true)
    );
}

#[test]
fn transparent_p2sh_multisig_to_orchard() {
    let params = MainNetwork;
    let rng = OsRng;

    // Construct a 2-of-3 ZIP 48 P2SH account.
    let account_sk =
        |i| zip48::AccountPrivKey::from_seed(&params, &[i; 32], zip32::AccountId::ZERO).unwrap();
    let account_sks = [account_sk(1), account_sk(2), account_sk(3)];
    let key_info = account_sks
        .iter()
        .map(|sk| sk.to_account_pubkey())
        .collect();
    let fvk = zip48::FullViewingKey::standard(2, key_info).unwrap();

    // Derive its first external address, and corresponding spending keys.
    let (p2sh_addr, redeem_script) =
        fvk.derive_address(zip32::Scope::External, NonHardenedChildIndex::ZERO);
    let transparent_sks = account_sks
        .map(|sk| sk.derive_signing_key(zip32::Scope::External, NonHardenedChildIndex::ZERO));

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already have a transparent coin.
    let utxo = transparent::OutPoint::fake();
    let coin = transparent::TxOut::new(
        Zatoshis::const_from_u64(1_000_000),
        p2sh_addr.script().into(),
    );

    // The transaction builder can't assume that the P2SH address receiving the coin was
    // generated from a redeem script that didn't contain bad opcodes.
    let redeem_script = redeem_script.weaken();

    // Create the transaction's I/O.
    let mut builder = Builder::new(
        params,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_transparent_p2sh_input(redeem_script, utxo, coin.clone())
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_fvk.to_ovk(zip32::Scope::Internal)),
            orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            Zatoshis::const_from_u64(880_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(rng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    check_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    // If we only sign with one of the signers, we can't finalize spends.
    {
        let mut signer = Signer::new(pczt.clone()).unwrap();
        signer.sign_transparent(0, &transparent_sks[0]).unwrap();
        assert!(matches!(
            SpendFinalizer::new(signer.finish()).finalize_spends(),
            Err(pczt::roles::spend_finalizer::Error::TransparentFinalize(
                ::transparent::pczt::SpendFinalizerError::MissingSignature
            ))
        ));
    }

    // Sign the input with all three signers.
    let mut signer = Signer::new(pczt).unwrap();
    for sk in &transparent_sks {
        signer.sign_transparent(0, sk).unwrap();
    }
    let pczt = signer.finish();
    check_round_trip(&pczt);

    // Finalize spends. This will pick 2 of the signatures to use in the P2SH scriptSig.
    let pczt = SpendFinalizer::new(pczt).finalize_spends().unwrap();
    check_round_trip(&pczt);

    // Grab the transaction's effects here, as it's easier.
    let tx_effects = pczt.clone().into_effects().unwrap();

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt).extract().unwrap();
    let tx_digests = tx.digest(TxIdDigester);

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);

    // Validate the transaction.
    let bundle = tx.transparent_bundle().unwrap();
    assert_eq!(bundle.vin.len(), 1);
    let txin = bundle.vin.first().unwrap();
    let sighasher = |script_code: &script::Code, hash_type: &zcash_script::signature::HashType| {
        Some(
            v5_signature_hash(
                &tx_effects,
                &SignableInput::Transparent(
                    ::transparent::sighash::SignableInput::from_parts(
                        bundle,
                        match (hash_type.signed_outputs(), hash_type.anyone_can_pay()) {
                            (zcash_script::signature::SignedOutputs::All, false) => {
                                SighashType::ALL
                            }
                            (zcash_script::signature::SignedOutputs::All, true) => {
                                SighashType::ALL_ANYONECANPAY
                            }
                            (zcash_script::signature::SignedOutputs::Single, false) => {
                                SighashType::SINGLE
                            }
                            (zcash_script::signature::SignedOutputs::Single, true) => {
                                SighashType::SINGLE_ANYONECANPAY
                            }
                            (zcash_script::signature::SignedOutputs::None, false) => {
                                SighashType::NONE
                            }
                            (zcash_script::signature::SignedOutputs::None, true) => {
                                SighashType::NONE_ANYONECANPAY
                            }
                        },
                        0,
                        &Script(script_code.clone()),
                        coin.script_pubkey(),
                        coin.value(),
                    )
                    .unwrap(),
                ),
                &tx_digests,
            )
            .as_ref()
            .try_into()
            .unwrap(),
        )
    };
    let checker = zcash_script::interpreter::CallbackTransactionSignatureChecker {
        sighash: &sighasher,
        lock_time: tx.lock_time().into(),
        is_final: txin.sequence() == 0xFFFFFFFF,
    };
    assert_eq!(
        script::Raw::from_raw_parts(
            txin.script_sig().0.to_bytes(),
            p2sh_addr.script().to_bytes()
        )
        .eval(zcash_script::interpreter::Flags::all(), &checker),
        Ok(true)
    );
}

#[test]
fn sapling_to_orchard() {
    let mut rng = OsRng;

    // Create a Sapling account to send funds from.
    let sapling_extsk = sapling::zip32::ExtendedSpendingKey::master(&[1; 32]);
    let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
    let sapling_internal_dfvk = sapling_extsk
        .derive_internal()
        .to_diversifiable_full_viewing_key();
    let sapling_recipient = sapling_dfvk.default_address().1;

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received a note.
    let value = sapling::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut sapling_builder = sapling::builder::Builder::new(
            sapling::note_encryption::Zip212Enforcement::On,
            sapling::builder::BundleType::DEFAULT,
            sapling::Anchor::empty_tree(),
        );
        sapling_builder
            .add_output(
                None,
                sapling_recipient,
                value,
                Memo::Empty.encode().into_bytes(),
            )
            .unwrap();
        let (bundle, meta) = sapling_builder
            .build::<LocalTxProver, LocalTxProver, _, i64>(&[], &mut rng)
            .unwrap()
            .unwrap();
        let output = bundle
            .shielded_outputs()
            .get(meta.output_index(0).unwrap())
            .unwrap();
        let domain = sapling::note_encryption::SaplingDomain::new(
            sapling::note_encryption::Zip212Enforcement::On,
        );
        let (note, _, _) =
            try_note_decryption(&domain, &sapling_dfvk.to_external_ivk().prepare(), output)
                .unwrap();
        note
    };

    // Use the tree with a single leaf.
    let (anchor, merkle_path) = {
        let cmu = note.cmu();
        let leaf = sapling::Node::from_cmu(&cmu);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<sapling::Node, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path)
    };

    // Build the Orchard bundle we'll be using.
    let mut builder = Builder::new(
        MainNetwork,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_sapling_spend::<zip317::FeeRule>(sapling_dfvk.fvk().clone(), note, merkle_path)
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(sapling_dfvk.to_ovk(zip32::Scope::External).0.into()),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_sapling_output::<zip317::FeeRule>(
            Some(sapling_dfvk.to_ovk(zip32::Scope::Internal)),
            sapling_internal_dfvk.find_address(0u32.into()).unwrap().1,
            Zatoshis::const_from_u64(880_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        sapling_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    check_round_trip(&pczt);

    // Update the Sapling bundle with its proof generation key.
    let index = sapling_meta.spend_index(0).unwrap();
    let pczt = Updater::new(pczt)
        .update_sapling_with(|mut updater| {
            updater.update_spend_with(index, |mut spend_updater| {
                spend_updater.set_proof_generation_key(sapling_extsk.expsk.proof_generation_key())
            })
        })
        .unwrap()
        .finish();

    // To test the Combiner, we will create the Sapling proofs, Sapling signatures, and
    // Orchard proof "in parallel".

    // Create Sapling proofs.
    let sapling_prover = LocalTxProver::bundled();
    let pczt_with_sapling_proofs = Prover::new(pczt.clone())
        .create_sapling_proofs(&sapling_prover, &sapling_prover)
        .unwrap()
        .finish();
    check_round_trip(&pczt_with_sapling_proofs);

    // Create Orchard proof.
    let pczt_with_orchard_proof = Prover::new(pczt.clone())
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt_with_orchard_proof);

    // Pass the PCZT to be signed through a serialization cycle to ensure we don't lose
    // any information. This emulates passing it to another device.
    let pczt = Pczt::parse(&pczt.serialize().unwrap()).unwrap();

    // Apply signatures.
    let mut signer = Signer::new(pczt).unwrap();
    signer
        .sign_sapling(index, &sapling_extsk.expsk.ask)
        .unwrap();
    let pczt_with_sapling_signatures = signer.finish();
    check_round_trip(&pczt_with_sapling_signatures);

    // Emulate passing the signed PCZT back to the first device.
    let pczt_with_sapling_signatures =
        Pczt::parse(&pczt_with_sapling_signatures.serialize().unwrap()).unwrap();

    // Combine the three PCZTs into one.
    let pczt = Combiner::new(vec![
        pczt_with_sapling_proofs,
        pczt_with_orchard_proof,
        pczt_with_sapling_signatures,
    ])
    .combine()
    .unwrap();
    check_round_trip(&pczt);

    // We should now be able to extract the fully authorized transaction.
    let (spend_vk, output_vk) = sapling_prover.verifying_keys();
    let tx = TransactionExtractor::new(pczt)
        .with_sapling(&spend_vk, &output_vk)
        .extract()
        .unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[test]
fn orchard_to_orchard() {
    let mut rng = OsRng;

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received a note.
    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut orchard_builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            orchard::bundle::BundleVersion::orchard_v2(),
            orchard::bundle::BundleVersion::orchard_v2().default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        orchard_builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = orchard_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
        note
    };

    // Use the tree with a single leaf.
    let (anchor, merkle_path) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };

    // Build the Orchard bundle we'll be using.
    let mut builder = Builder::new(
        MainNetwork,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_fvk.to_ovk(zip32::Scope::Internal)),
            orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            Zatoshis::const_from_u64(890_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        orchard_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    check_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    // Apply signatures.
    let index = orchard_meta.spend_action_index(0).unwrap();
    let mut signer = Signer::new(pczt).unwrap();
    signer.sign_orchard(index, &orchard_ask).unwrap();
    let pczt = signer.finish();
    check_round_trip(&pczt);

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt).extract().unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

/// Extracts each action's wire `fvk` bytes from the Orchard or Ironwood pool of the
/// PCZT, via the Verifier role's full (FVK-deriving) parse.
fn wire_spend_fvks(pczt: &Pczt, ironwood: bool) -> Vec<Option<[u8; 96]>> {
    use std::convert::Infallible;

    fn collect(bundle: &orchard::pczt::Bundle) -> Vec<Option<[u8; 96]>> {
        bundle
            .actions()
            .iter()
            .map(|action| action.spend().fvk().as_ref().map(|fvk| fvk.to_bytes()))
            .collect()
    }

    let mut fvks = None;
    let verifier = Verifier::new(pczt.clone());
    if ironwood {
        verifier
            .with_ironwood::<Infallible, _>(|bundle| {
                fvks = Some(collect(bundle));
                Ok(())
            })
            .expect("Ironwood bundle parses fully");
    } else {
        verifier
            .with_orchard::<Infallible, _>(|bundle| {
                fvks = Some(collect(bundle));
                Ok(())
            })
            .expect("Orchard bundle parses fully");
    }
    fvks.expect("closure ran")
}

/// Computes the spend authorization signature for the action at `index` of the
/// Orchard or Ironwood pool, over the Verifier role's full (FVK-deriving) parse of
/// the PCZT, using a [`ChaCha20Rng`] seeded with `seed`.
///
/// This is the reference value for asserting that the low-level Signer's preverified
/// signing parse produces a byte-identical signature.
fn expected_spend_auth_sig(
    pczt: &Pczt,
    ironwood: bool,
    index: usize,
    ask: &orchard::keys::SpendAuthorizingKey,
    sighash: [u8; 32],
    seed: [u8; 32],
) -> [u8; 64] {
    use std::convert::Infallible;

    let mut sig = None;
    let mut compute = |bundle: &orchard::pczt::Bundle| {
        let spend = bundle.actions()[index].spend();
        // The full parse derives the FVK (in contrast to the preverified parse).
        assert!(spend.fvk().is_some());
        let alpha = spend
            .alpha()
            .as_ref()
            .expect("alpha is set after IO finalization");
        let rsk = ask.randomize(alpha);
        sig = Some(<[u8; 64]>::from(
            &rsk.sign(ChaCha20Rng::from_seed(seed), &sighash),
        ));
        Ok::<(), pczt::roles::verifier::OrchardError<Infallible>>(())
    };

    let verifier = Verifier::new(pczt.clone());
    if ironwood {
        verifier
            .with_ironwood(&mut compute)
            .expect("Ironwood bundle parses fully");
    } else {
        verifier
            .with_orchard(&mut compute)
            .expect("Orchard bundle parses fully");
    }
    sig.expect("closure ran")
}

/// Asserts that `sig` is a valid RedPallas spend authorization signature for the
/// randomized verification key `rk`, over `sighash`.
///
/// This proves the signature the preverified path produced actually authorizes the
/// spend (matching what [`orchard::pczt::Action::apply_signature`] checks), not just
/// that it is byte-equal to the reference.
fn assert_valid_spend_auth_sig(rk: &[u8; 32], sighash: [u8; 32], sig: [u8; 64]) {
    use orchard::primitives::redpallas::{self, SpendAuth};

    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(*rk).expect("`rk` is a valid key");
    let sig = redpallas::Signature::<SpendAuth>::from(sig);
    rk.verify(&sighash, &sig)
        .expect("spend authorization signature verifies against `rk`");
}

#[test]
fn orchard_low_level_signer_uses_preverified_signing_parse() {
    let mut rng = OsRng;

    // Create an Orchard account to send funds from.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received a note.
    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut orchard_builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            orchard::bundle::BundleVersion::orchard_v2(),
            orchard::bundle::BundleVersion::orchard_v2().default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        orchard_builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = orchard_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
        note
    };

    // Use the tree with a single leaf.
    let (anchor, merkle_path) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };

    // Build the Orchard bundle we'll be using.
    let mut builder = Builder::new(
        MainNetwork,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_fvk.to_ovk(zip32::Scope::Internal)),
            orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            Zatoshis::const_from_u64(890_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        orchard_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT, and finalize the I/O.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();

    // Create the proof before signing, so that the byte-losslessness check below
    // covers a maximal bundle (witnesses, proof, and FVKs all present).
    let pczt = Prover::new(pczt)
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    // A no-op signing pass must be byte-lossless: the preverified parse drops the
    // wire `fvk` bytes, but the Signer restores them after serialization.
    let noop = low_level_signer::Signer::new(pczt.clone())
        .sign_orchard_with::<low_level_signer::OrchardParseError, _>(|_, _, _| Ok(()))
        .unwrap()
        .finish();
    assert_eq!(
        noop.serialize().unwrap(),
        pczt.clone().serialize().unwrap(),
        "no-op low-level Orchard signing pass must preserve every wire byte",
    );

    let index = orchard_meta.spend_action_index(0).unwrap();
    let sighash = Signer::new(pczt.clone()).unwrap().shielded_sighash();
    let seed = [42; 32];

    // Compute the reference signature over the Verifier's full parse, and snapshot
    // the wire `fvk` bytes it observes.
    let expected_sig = expected_spend_auth_sig(&pczt, false, index, &orchard_ask, sighash, seed);
    let fvks_before = wire_spend_fvks(&pczt, false);
    assert_eq!(fvks_before[index], Some(orchard_fvk.to_bytes()));

    // Sign through the low-level Signer's preverified path with the same seed.
    let signed = low_level_signer::Signer::new(pczt.clone())
        .sign_orchard_with::<low_level_signer::OrchardParseError, _>(|_, bundle, _| {
            // The preverified signing parse skips FVK derivation entirely.
            assert!(bundle.actions()[index].spend().fvk().is_none());
            bundle.actions_mut()[index]
                .sign(sighash, &orchard_ask, ChaCha20Rng::from_seed(seed))
                .expect("signing succeeds");
            Ok(())
        })
        .unwrap()
        .finish();
    check_round_trip(&signed);

    // The preverified signing parse must yield a byte-identical signature to the
    // full-parse path.
    let produced_sig = signed.orchard().actions()[index]
        .spend()
        .spend_auth_sig()
        .expect("action was signed");
    assert_eq!(produced_sig, expected_sig);

    // ...and that signature must actually verify against the spend's `rk`.
    assert_valid_spend_auth_sig(
        signed.orchard().actions()[index].spend().rk(),
        sighash,
        produced_sig,
    );

    // The wire `fvk` bytes must be preserved (unchanged) after signing.
    assert_eq!(wire_spend_fvks(&signed, false), fvks_before);

    // The signed PCZT remains fully usable: we should be able to extract the fully
    // authorized transaction.
    let tx = TransactionExtractor::new(signed).extract().unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

/// Checks that the PCZT round-trips through the default (v2) encoding.
///
/// This is [`check_round_trip`] minus the v1 encoding check: v6 PCZTs (which carry
/// an Ironwood bundle) are not representable in the legacy v1 encoding.
fn check_v2_round_trip(pczt: &Pczt) {
    let encoded = pczt.clone().serialize().expect("serialization succeeds");
    let reencoded = Pczt::parse(&encoded)
        .expect("can parse encoded PCZT")
        .serialize()
        .expect("serialization succeeds");
    assert_eq!(encoded, reencoded);
}

#[derive(Clone, Copy)]
enum ShieldedPool {
    Sapling,
    Orchard,
    Ironwood,
}

fn pczt_with_anchor(pool: ShieldedPool) -> Pczt {
    if matches!(pool, ShieldedPool::Sapling) {
        return Creator::new(
            zcash_protocol::consensus::BranchId::Nu6.into(),
            10_000_000,
            133,
            Some([9; 32]),
            Some([0; 32]),
        )
        .unwrap()
        .build()
        .unwrap();
    }

    if matches!(pool, ShieldedPool::Orchard) {
        return Creator::new(
            zcash_protocol::consensus::BranchId::Nu6_3.into(),
            10_000_000,
            133,
            Some([0; 32]),
            Some([9; 32]),
        )
        .unwrap()
        .build()
        .unwrap();
    }

    let transparent_account_sk =
        AccountPrivKey::from_seed(&MainNetwork, &[1; 32], zip32::AccountId::ZERO).unwrap();
    let (transparent_addr, address_index) = transparent_account_sk
        .to_account_pubkey()
        .derive_external_ivk()
        .unwrap()
        .default_address();
    let transparent_sk = transparent_account_sk
        .derive_external_secret_key(address_index)
        .unwrap();
    let secp = secp256k1::Secp256k1::signing_only();
    let transparent_pubkey = transparent_sk.public_key(&secp);

    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    let mut builder = Builder::new(
        nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: matches!(pool, ShieldedPool::Orchard).then(orchard::Anchor::empty_tree),
            ironwood_anchor: matches!(pool, ShieldedPool::Ironwood)
                .then(orchard::Anchor::empty_tree),
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            transparent_pubkey,
            transparent::OutPoint::fake(),
            transparent::TxOut::new(
                Zatoshis::const_from_u64(1_000_000),
                transparent_addr.script().into(),
            ),
        )
        .unwrap();

    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(985_000),
            MemoBytes::empty(),
        )
        .unwrap();

    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io()
        .unwrap()
}

fn redact_anchor(pczt: Pczt, pool: ShieldedPool) -> Pczt {
    match pool {
        ShieldedPool::Sapling => Redactor::new(pczt)
            .redact_sapling_with(|mut r| r.clear_anchor())
            .finish(),
        ShieldedPool::Orchard => Redactor::new(pczt)
            .redact_orchard_with(|mut r| r.clear_anchor())
            .finish(),
        ShieldedPool::Ironwood => Redactor::new(pczt)
            .redact_ironwood_with(|mut r| r.clear_anchor())
            .finish(),
    }
}

fn assert_anchor_redacted(pczt: &Pczt, pool: ShieldedPool) {
    match pool {
        ShieldedPool::Sapling => assert!(pczt.sapling().anchor().is_none()),
        ShieldedPool::Orchard => assert!(pczt.orchard().anchor().is_none()),
        ShieldedPool::Ironwood => assert!(pczt.ironwood().anchor().is_none()),
    }
}

fn assert_redacted_anchor_v2_round_trip(pczt: Pczt, pool: ShieldedPool) {
    let redacted = redact_anchor(pczt, pool);
    assert_anchor_redacted(&redacted, pool);
    check_v2_round_trip(&redacted);

    let reparsed = Pczt::parse(&redacted.serialize().unwrap()).unwrap();
    assert_anchor_redacted(&reparsed, pool);
}

#[test]
fn redacted_sapling_anchor_round_trips_v2() {
    assert_redacted_anchor_v2_round_trip(
        pczt_with_anchor(ShieldedPool::Sapling),
        ShieldedPool::Sapling,
    );
}

#[test]
fn redacted_sapling_anchor_can_be_restored_after_signing() {
    let mut rng = OsRng;

    let sapling_extsk = sapling::zip32::ExtendedSpendingKey::master(&[1; 32]);
    let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
    let sapling_internal_dfvk = sapling_extsk
        .derive_internal()
        .to_diversifiable_full_viewing_key();
    let sapling_recipient = sapling_dfvk.default_address().1;

    let value = sapling::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut sapling_builder = sapling::builder::Builder::new(
            sapling::note_encryption::Zip212Enforcement::On,
            sapling::builder::BundleType::DEFAULT,
            sapling::Anchor::empty_tree(),
        );
        sapling_builder
            .add_output(
                None,
                sapling_recipient,
                value,
                Memo::Empty.encode().into_bytes(),
            )
            .unwrap();
        let (bundle, meta) = sapling_builder
            .build::<LocalTxProver, LocalTxProver, _, i64>(&[], &mut rng)
            .unwrap()
            .unwrap();
        let output = bundle
            .shielded_outputs()
            .get(meta.output_index(0).unwrap())
            .unwrap();
        let domain = sapling::note_encryption::SaplingDomain::new(
            sapling::note_encryption::Zip212Enforcement::On,
        );
        let (note, _, _) =
            try_note_decryption(&domain, &sapling_dfvk.to_external_ivk().prepare(), output)
                .unwrap();
        note
    };

    let (anchor, merkle_path) = {
        let cmu = note.cmu();
        let leaf = sapling::Node::from_cmu(&cmu);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<sapling::Node, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path)
    };

    let mut builder = Builder::new(
        nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_sapling_spend::<zip317::FeeRule>(sapling_dfvk.fvk().clone(), note, merkle_path)
        .unwrap();
    builder
        .add_sapling_output::<zip317::FeeRule>(
            Some(sapling_dfvk.to_ovk(zip32::Scope::Internal)),
            sapling_internal_dfvk.find_address(0u32.into()).unwrap().1,
            Zatoshis::const_from_u64(990_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        sapling_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io()
        .unwrap();
    let index = sapling_meta.spend_index(0).unwrap();
    let pczt = Updater::new(pczt)
        .update_sapling_with(|mut updater| {
            updater.update_spend_with(index, |mut spend_updater| {
                spend_updater.set_proof_generation_key(sapling_extsk.expsk.proof_generation_key())
            })
        })
        .unwrap()
        .finish();
    check_v2_round_trip(&pczt);

    assert!(matches!(
        Updater::new(pczt.clone()).set_sapling_anchor(sapling::Anchor::empty_tree()),
        Err(pczt::roles::updater::AnchorUpdateError::ConflictingAnchor)
    ));

    let mut signer = Signer::new(pczt).unwrap();
    let sighash = signer.shielded_sighash();
    signer
        .sign_sapling(index, &sapling_extsk.expsk.ask)
        .unwrap();
    let signed = signer.finish();

    let redacted = Redactor::new(signed)
        .redact_sapling_with(|mut r| r.clear_anchor())
        .finish();
    assert!(redacted.sapling().anchor().is_none());
    assert!(
        Prover::new(redacted.clone())
            .create_sapling_proofs(&LocalTxProver::bundled(), &LocalTxProver::bundled())
            .is_err()
    );

    let updated = Updater::new(redacted)
        .set_sapling_anchor(anchor)
        .unwrap()
        .finish();
    assert_eq!(updated.sapling().anchor(), &Some(anchor.to_bytes()));
    assert_eq!(
        Signer::new(updated.clone()).unwrap().shielded_sighash(),
        sighash
    );

    let sapling_prover = LocalTxProver::bundled();
    let proved = Prover::new(updated)
        .create_sapling_proofs(&sapling_prover, &sapling_prover)
        .unwrap()
        .finish();
    assert!(matches!(
        Updater::new(proved.clone()).set_sapling_anchor(anchor),
        Err(pczt::roles::updater::AnchorUpdateError::ProofAlreadyPresent)
    ));

    let (spend_vk, output_vk) = sapling_prover.verifying_keys();
    let tx = TransactionExtractor::new(proved)
        .with_sapling(&spend_vk, &output_vk)
        .extract()
        .unwrap();
    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[test]
fn wallet_can_set_sapling_witness_after_signing() {
    let mut rng = OsRng;

    // Create a Sapling account to spend from and send back to.
    let sapling_extsk = sapling::zip32::ExtendedSpendingKey::master(&[1; 32]);
    let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
    let sapling_internal_dfvk = sapling_extsk
        .derive_internal()
        .to_diversifiable_full_viewing_key();
    let sapling_recipient = sapling_dfvk.default_address().1;

    // Pretend we already received a Sapling note.
    let value = sapling::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut sapling_builder = sapling::builder::Builder::new(
            sapling::note_encryption::Zip212Enforcement::On,
            sapling::builder::BundleType::DEFAULT,
            sapling::Anchor::empty_tree(),
        );
        sapling_builder
            .add_output(
                None,
                sapling_recipient,
                value,
                Memo::Empty.encode().into_bytes(),
            )
            .unwrap();
        let (bundle, meta) = sapling_builder
            .build::<LocalTxProver, LocalTxProver, _, i64>(&[], &mut rng)
            .unwrap()
            .unwrap();
        let output = bundle
            .shielded_outputs()
            .get(meta.output_index(0).unwrap())
            .unwrap();
        let domain = sapling::note_encryption::SaplingDomain::new(
            sapling::note_encryption::Zip212Enforcement::On,
        );
        let (note, _, _) =
            try_note_decryption(&domain, &sapling_dfvk.to_external_ivk().prepare(), output)
                .unwrap();
        note
    };

    // Use the Sapling tree with a single leaf.
    let (anchor, merkle_path) = {
        let cmu = note.cmu();
        let leaf = sapling::Node::from_cmu(&cmu);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<sapling::Node, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path)
    };
    let merkle_path_for_update = merkle_path.clone();
    let merkle_path_for_invalid_index = merkle_path.clone();
    let merkle_path_after_proof = merkle_path.clone();

    // Build the Sapling transaction that a wallet will sign before proof creation.
    let mut builder = Builder::new(
        MainNetwork,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_sapling_spend::<zip317::FeeRule>(sapling_dfvk.fvk().clone(), note, merkle_path)
        .unwrap();
    builder
        .add_sapling_output::<zip317::FeeRule>(
            Some(sapling_dfvk.to_ovk(zip32::Scope::Internal)),
            sapling_internal_dfvk.find_address(0u32.into()).unwrap().1,
            Zatoshis::const_from_u64(990_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        sapling_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io()
        .unwrap();
    let index = sapling_meta.spend_index(0).unwrap();
    let pczt = Updater::new(pczt)
        .update_sapling_with(|mut updater| {
            updater.update_spend_with(index, |mut spend_updater| {
                spend_updater.set_proof_generation_key(sapling_extsk.expsk.proof_generation_key())
            })
        })
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    let mut signer = Signer::new(pczt).unwrap();
    let sighash = signer.shielded_sighash();
    signer
        .sign_sapling(index, &sapling_extsk.expsk.ask)
        .unwrap();
    let signed = signer.finish();

    let redacted = Redactor::new(signed)
        .redact_sapling_with(|mut r| {
            r.redact_spend(index, |mut s| {
                s.clear_witness();
            });
        })
        .finish();
    assert!(
        Prover::new(redacted.clone())
            .create_sapling_proofs(&LocalTxProver::bundled(), &LocalTxProver::bundled())
            .is_err()
    );

    assert_eq!(
        Signer::new(redacted.clone()).unwrap().shielded_sighash(),
        sighash
    );
    let invalid_index = redacted.sapling().spends().len();
    assert!(matches!(
        Updater::new(redacted.clone())
            .set_sapling_spend_witnesses([(invalid_index, merkle_path_for_invalid_index)]),
        Err(SpendWitnessUpdateError::InvalidSpendIndex(_))
    ));

    let updated = Updater::new(redacted)
        .set_sapling_spend_witnesses([(index, merkle_path_for_update)])
        .unwrap()
        .finish();
    assert_eq!(
        Signer::new(updated.clone()).unwrap().shielded_sighash(),
        sighash
    );

    let sapling_prover = LocalTxProver::bundled();
    let proved = Prover::new(updated)
        .create_sapling_proofs(&sapling_prover, &sapling_prover)
        .unwrap()
        .finish();
    assert!(matches!(
        Updater::new(proved.clone())
            .set_sapling_spend_witnesses([(index, merkle_path_after_proof)]),
        Err(SpendWitnessUpdateError::ProofAlreadyPresent)
    ));
    check_round_trip(&proved);
}

/// A regtest network with NU6.3 activated, for exercising the Ironwood pool.
fn nu6_3_test_network() -> zcash_protocol::local_consensus::LocalNetwork {
    use zcash_protocol::consensus::BlockHeight;

    zcash_protocol::local_consensus::LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(2)),
        blossom: Some(BlockHeight::from_u32(3)),
        heartwood: Some(BlockHeight::from_u32(4)),
        canopy: Some(BlockHeight::from_u32(5)),
        nu5: Some(BlockHeight::from_u32(6)),
        nu6: Some(BlockHeight::from_u32(7)),
        nu6_1: Some(BlockHeight::from_u32(8)),
        nu6_2: Some(BlockHeight::from_u32(9)),
        nu6_3: Some(BlockHeight::from_u32(10)),
        #[cfg(zcash_unstable = "nu7")]
        nu7: None,
    }
}

#[test]
fn redacted_orchard_anchor_round_trips_v2() {
    assert_redacted_anchor_v2_round_trip(
        pczt_with_anchor(ShieldedPool::Orchard),
        ShieldedPool::Orchard,
    );
}

#[test]
fn redacted_orchard_anchor_can_be_restored_after_signing() {
    let mut rng = OsRng;

    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let orchard_bundle_version = orchard::bundle::BundleVersion::orchard_v2();
        let mut orchard_builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            orchard_bundle_version,
            orchard_bundle_version.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        orchard_builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = orchard_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
        assert_eq!(note.version(), orchard::note::NoteVersion::V2);
        note
    };

    let (anchor, merkle_path): (orchard::Anchor, orchard::tree::MerklePath) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };

    let mut builder = Builder::new(
        nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(orchard_fvk, note, merkle_path)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(980_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        orchard_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io()
        .unwrap();
    let index = orchard_meta.spend_action_index(0).unwrap();
    check_v2_round_trip(&pczt);

    Updater::new(pczt.clone())
        .set_orchard_anchor(anchor)
        .unwrap();
    assert!(matches!(
        Updater::new(pczt.clone()).set_orchard_anchor(orchard::Anchor::empty_tree()),
        Err(pczt::roles::updater::AnchorUpdateError::ConflictingAnchor)
    ));

    let redacted = Redactor::new(pczt)
        .redact_orchard_with(|mut r| r.clear_anchor())
        .finish();
    assert!(redacted.orchard().anchor().is_none());
    assert!(
        Prover::new(redacted.clone())
            .create_orchard_proof(post_nu6_3_orchard_proving_key())
            .is_err()
    );

    let mut signer = Signer::new(redacted).unwrap();
    let sighash = signer.shielded_sighash();
    signer.sign_orchard(index, &orchard_ask).unwrap();
    let signed = signer.finish();

    let updated = Updater::new(signed)
        .set_orchard_anchor(anchor)
        .unwrap()
        .finish();
    assert_eq!(updated.orchard().anchor(), &Some(anchor.to_bytes()));
    assert_eq!(
        Signer::new(updated.clone()).unwrap().shielded_sighash(),
        sighash
    );
    let produced_sig = updated.orchard().actions()[index]
        .spend()
        .spend_auth_sig()
        .expect("action was signed");
    assert_valid_spend_auth_sig(
        updated.orchard().actions()[index].spend().rk(),
        sighash,
        produced_sig,
    );

    let proved = Prover::new(updated)
        .create_orchard_proof(post_nu6_3_orchard_proving_key())
        .unwrap()
        .create_ironwood_proof(post_nu6_3_orchard_proving_key())
        .unwrap()
        .finish();
    check_v2_round_trip(&proved);

    assert!(matches!(
        Updater::new(proved.clone()).set_orchard_anchor(anchor),
        Err(pczt::roles::updater::AnchorUpdateError::ProofAlreadyPresent)
    ));

    let tx = TransactionExtractor::new(proved).extract().unwrap();
    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[test]
fn wallet_can_set_orchard_witness_after_signing() {
    let mut rng = OsRng;

    // Create an Orchard account to spend from and send back to.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received an Orchard note.
    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut orchard_builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            orchard::bundle::BundleVersion::orchard_v2(),
            orchard::bundle::BundleVersion::orchard_v2().default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        orchard_builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = orchard_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
        note
    };

    // Use the Orchard tree with a single leaf.
    let (anchor, merkle_path): (orchard::Anchor, orchard::tree::MerklePath) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };
    let merkle_path_for_update = merkle_path.clone();
    let merkle_path_for_invalid_index = merkle_path.clone();
    let merkle_path_after_proof = merkle_path.clone();

    // Build the Orchard transaction that a wallet will sign before proof creation.
    let mut builder = Builder::new(
        MainNetwork,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(990_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        orchard_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io()
        .unwrap();
    let index = orchard_meta.spend_action_index(0).unwrap();
    check_round_trip(&pczt);

    let redacted = Redactor::new(pczt)
        .redact_orchard_with(|mut r| {
            r.redact_action(index, |mut a| {
                a.clear_spend_witness();
            });
        })
        .finish();
    assert!(
        Prover::new(redacted.clone())
            .create_orchard_proof(orchard_proving_key())
            .is_err()
    );

    let mut signer = Signer::new(redacted.clone()).unwrap();
    let sighash = signer.shielded_sighash();
    signer.sign_orchard(index, &orchard_ask).unwrap();
    let signed = signer.finish();
    let invalid_index = signed.orchard().actions().len();
    assert!(matches!(
        Updater::new(signed.clone())
            .set_orchard_spend_witnesses([(invalid_index, merkle_path_for_invalid_index)]),
        Err(SpendWitnessUpdateError::InvalidSpendIndex(_))
    ));

    let updated = Updater::new(signed)
        .set_orchard_spend_witnesses([(index, merkle_path_for_update)])
        .unwrap()
        .finish();
    assert_eq!(
        Signer::new(updated.clone()).unwrap().shielded_sighash(),
        sighash
    );

    let proved = Prover::new(updated)
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    assert!(matches!(
        Updater::new(proved.clone())
            .set_orchard_spend_witnesses([(index, merkle_path_after_proof)]),
        Err(SpendWitnessUpdateError::ProofAlreadyPresent)
    ));
    let tx = TransactionExtractor::new(proved).extract().unwrap();
    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[test]
fn redacted_ironwood_anchor_round_trips_v2() {
    assert_redacted_anchor_v2_round_trip(
        pczt_with_anchor(ShieldedPool::Ironwood),
        ShieldedPool::Ironwood,
    );
}

#[test]
fn redacted_ironwood_anchor_survives_signer_finish() {
    let anchor = orchard::Anchor::empty_tree();
    let redacted = redact_anchor(
        pczt_with_anchor(ShieldedPool::Ironwood),
        ShieldedPool::Ironwood,
    );
    assert_anchor_redacted(&redacted, ShieldedPool::Ironwood);

    let signed = Signer::new(redacted).unwrap().finish();
    assert_anchor_redacted(&signed, ShieldedPool::Ironwood);
    check_v2_round_trip(&signed);

    let reparsed = Pczt::parse(&signed.clone().serialize().unwrap()).unwrap();
    assert_anchor_redacted(&reparsed, ShieldedPool::Ironwood);

    let updated = Updater::new(signed)
        .set_ironwood_anchor(anchor)
        .unwrap()
        .finish();
    assert_eq!(updated.ironwood().anchor(), &Some(anchor.to_bytes()));
    check_v2_round_trip(&updated);
}

#[test]
fn wallet_can_set_ironwood_witness_after_signing() {
    let mut rng = OsRng;

    // Create an Orchard account to spend from and send back to through Ironwood.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received an Ironwood note.
    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let ironwood_bundle_version = orchard::bundle::BundleVersion::ironwood_v3();
        let mut orchard_builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            ironwood_bundle_version,
            ironwood_bundle_version.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        orchard_builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = orchard_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
        assert_eq!(note.version(), orchard::note::NoteVersion::V3);
        note
    };

    // Use the Ironwood tree with a single leaf.
    let (anchor, merkle_path): (orchard::Anchor, orchard::tree::MerklePath) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };
    let merkle_path_for_update = merkle_path.clone();
    let merkle_path_for_invalid_index = merkle_path.clone();
    let merkle_path_after_proof = merkle_path.clone();

    // Build the Ironwood transaction that a wallet will sign before proof creation.
    let mut builder = Builder::new(
        nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_ironwood_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(990_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        ironwood_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io()
        .unwrap();
    let index = ironwood_meta.spend_action_index(0).unwrap();
    check_v2_round_trip(&pczt);

    let redacted = Redactor::new(pczt)
        .redact_ironwood_with(|mut r| {
            r.redact_action(index, |mut a| {
                a.clear_spend_witness();
            });
        })
        .finish();
    assert!(
        Prover::new(redacted.clone())
            .create_ironwood_proof(post_nu6_3_orchard_proving_key())
            .is_err()
    );

    let mut signer = Signer::new(redacted.clone()).unwrap();
    let sighash = signer.shielded_sighash();
    signer.sign_ironwood(index, &orchard_ask).unwrap();
    let signed = signer.finish();
    let invalid_index = signed.ironwood().actions().len();
    assert!(matches!(
        Updater::new(signed.clone())
            .set_ironwood_spend_witnesses([(invalid_index, merkle_path_for_invalid_index)]),
        Err(SpendWitnessUpdateError::InvalidSpendIndex(_))
    ));

    let updated = Updater::new(signed)
        .set_ironwood_spend_witnesses([(index, merkle_path_for_update)])
        .unwrap()
        .finish();
    assert_eq!(
        Signer::new(updated.clone()).unwrap().shielded_sighash(),
        sighash
    );

    let proved = Prover::new(updated)
        .create_ironwood_proof(post_nu6_3_orchard_proving_key())
        .unwrap()
        .finish();
    assert!(matches!(
        Updater::new(proved.clone())
            .set_ironwood_spend_witnesses([(index, merkle_path_after_proof)]),
        Err(SpendWitnessUpdateError::ProofAlreadyPresent)
    ));
    let tx = TransactionExtractor::new(proved).extract().unwrap();
    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[test]
fn anchor_setters_reject_unsupported_transaction_formats() {
    let sapling_anchor = sapling::Anchor::empty_tree();
    let orchard_anchor = orchard::Anchor::empty_tree();
    let pczt = Creator::new(
        zcash_protocol::consensus::BranchId::Nu6.into(),
        10_000_000,
        133,
        Some(sapling_anchor.to_bytes()),
        Some(orchard_anchor.to_bytes()),
    )
    .unwrap()
    .build()
    .unwrap();

    assert!(matches!(
        Updater::new(pczt.clone()).set_sapling_anchor(sapling_anchor),
        Err(pczt::roles::updater::AnchorUpdateError::UnsupportedTransactionFormat)
    ));
    assert!(matches!(
        Updater::new(pczt.clone()).set_orchard_anchor(orchard_anchor),
        Err(pczt::roles::updater::AnchorUpdateError::UnsupportedTransactionFormat)
    ));
    assert!(matches!(
        Updater::new(pczt).set_ironwood_anchor(orchard_anchor),
        Err(pczt::roles::updater::AnchorUpdateError::UnsupportedTransactionFormat)
    ));
}

#[test]
fn ironwood_low_level_signer_uses_preverified_signing_parse() {
    let mut rng = OsRng;

    // Create an Orchard account to send funds from.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received an Ironwood note.
    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let ironwood_bundle_version = orchard::bundle::BundleVersion::ironwood_v3();
        let mut orchard_builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            ironwood_bundle_version,
            ironwood_bundle_version.default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        orchard_builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = orchard_builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::IronwoodDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
        assert_eq!(note.version(), orchard::note::NoteVersion::V3);
        note
    };

    // Use the Ironwood tree with a single leaf.
    let (anchor, merkle_path) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let position = 0.into();
        let merkle_path = tree
            .witness_at_checkpoint_depth(position, 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };

    // Build the Ironwood bundle we'll be using.
    let mut builder = Builder::new(
        nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_pool_bundle_type: orchard::builder::BundleType::DEFAULT,
        },
    );
    builder
        .add_ironwood_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(990_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        ironwood_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT, and finalize the I/O.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_v2_round_trip(&pczt);
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    check_v2_round_trip(&pczt);

    // A no-op signing pass must be byte-lossless: the preverified parse drops the
    // wire `fvk` bytes, but the Signer restores them after serialization.
    let noop = low_level_signer::Signer::new(pczt.clone())
        .sign_ironwood_with::<low_level_signer::OrchardParseError, _>(|_, _, _| Ok(()))
        .unwrap()
        .finish();
    assert_eq!(
        noop.serialize().unwrap(),
        pczt.clone().serialize().unwrap(),
        "no-op low-level Ironwood signing pass must preserve every wire byte",
    );

    let index = ironwood_meta.spend_action_index(0).unwrap();
    let sighash = Signer::new(pczt.clone()).unwrap().shielded_sighash();
    let seed = [7; 32];

    // Compute the reference signature over the Verifier's full parse, and snapshot
    // the wire `fvk` bytes it observes.
    let expected_sig = expected_spend_auth_sig(&pczt, true, index, &orchard_ask, sighash, seed);
    let fvks_before = wire_spend_fvks(&pczt, true);
    assert_eq!(fvks_before[index], Some(orchard_fvk.to_bytes()));

    let redacted = Redactor::new(pczt.clone())
        .redact_ironwood_with(|mut r| {
            r.clear_anchor();
            r.redact_actions(|mut a| {
                a.clear_cv_net();
            });
        })
        .finish();
    assert!(redacted.ironwood().anchor().is_none());
    assert!(
        redacted
            .ironwood()
            .actions()
            .iter()
            .all(|action| action.cv_net().is_none())
    );
    let verified = Verifier::new(redacted.clone())
        .with_ironwood::<std::convert::Infallible, _>(|_| {
            Ok::<(), pczt::roles::verifier::OrchardError<std::convert::Infallible>>(())
        })
        .unwrap()
        .finish();
    assert!(verified.ironwood().anchor().is_none());
    let updated = Updater::new(redacted.clone())
        .update_ironwood_with(|_| Ok(()))
        .unwrap()
        .finish();
    assert!(updated.ironwood().anchor().is_none());

    let mut resolved = redacted.clone();
    resolved.resolve_fields().unwrap();
    assert!(resolved.ironwood().anchor().is_none());
    assert_eq!(
        resolved.ironwood().actions()[index].cv_net(),
        pczt.ironwood().actions()[index].cv_net()
    );
    assert!(IoFinalizer::new(redacted.clone()).finalize_io().is_err());
    assert!(
        Prover::new(redacted.clone())
            .create_ironwood_proof(orchard_proving_key())
            .is_err()
    );
    assert_eq!(
        Signer::new(redacted.clone()).unwrap().shielded_sighash(),
        sighash
    );

    let cv_net_redacted = Redactor::new(pczt.clone())
        .redact_ironwood_with(|mut r| {
            r.redact_actions(|mut a| {
                a.clear_cv_net();
            });
        })
        .finish();
    assert_eq!(
        Signer::new(cv_net_redacted.clone())
            .unwrap()
            .shielded_sighash(),
        sighash
    );

    let signed_redacted = low_level_signer::Signer::new(cv_net_redacted)
        .sign_ironwood_with::<low_level_signer::OrchardParseError, _>(|_, bundle, _| {
            bundle.actions_mut()[index]
                .sign(sighash, &orchard_ask, ChaCha20Rng::from_seed(seed))
                .expect("signing succeeds");
            Ok(())
        })
        .unwrap()
        .finish();
    assert_eq!(
        signed_redacted.ironwood().actions()[index]
            .spend()
            .spend_auth_sig()
            .expect("action was signed"),
        expected_sig
    );
    check_v2_round_trip(&signed_redacted);

    // Sign through the low-level Signer's preverified path with the same seed.
    let signed = low_level_signer::Signer::new(pczt.clone())
        .sign_ironwood_with::<low_level_signer::OrchardParseError, _>(|_, bundle, _| {
            // The preverified signing parse skips FVK derivation entirely.
            assert!(bundle.actions()[index].spend().fvk().is_none());
            bundle.actions_mut()[index]
                .sign(sighash, &orchard_ask, ChaCha20Rng::from_seed(seed))
                .expect("signing succeeds");
            Ok(())
        })
        .unwrap()
        .finish();
    check_v2_round_trip(&signed);

    // The preverified signing parse must yield a byte-identical signature to the
    // full-parse path.
    let produced_sig = signed.ironwood().actions()[index]
        .spend()
        .spend_auth_sig()
        .expect("action was signed");
    assert_eq!(produced_sig, expected_sig);

    // ...and that signature must actually verify against the spend's `rk`.
    assert_valid_spend_auth_sig(
        signed.ironwood().actions()[index].spend().rk(),
        sighash,
        produced_sig,
    );

    // The wire `fvk` bytes must be preserved (unchanged) after signing.
    assert_eq!(wire_spend_fvks(&signed, true), fvks_before);
}

#[test]
fn redacted_anchor_is_not_resolved() {
    let pczt = Creator::new(
        zcash_protocol::consensus::BranchId::Nu6.into(),
        10_000_000,
        133,
        Some([0; 32]),
        Some([9; 32]),
    )
    .unwrap()
    .build()
    .unwrap();

    let mut redacted = Redactor::new(pczt)
        .redact_orchard_with(|mut r| {
            r.clear_anchor();
        })
        .finish();

    redacted.resolve_fields().unwrap();
    assert!(redacted.orchard().anchor().is_none());
}
