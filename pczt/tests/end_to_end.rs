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
    EncodingError, Pczt,
    orchard::MemoKind,
    roles::{
        combiner::Combiner, creator::Creator, io_finalizer::IoFinalizer, low_level_signer,
        prover::Prover, redactor::Redactor, signer::Signer, spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor, updater::Updater, verifier::Verifier,
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
    consensus::{BranchId, MainNetwork},
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zcash_script::script::{self, Evaluable};

static ORCHARD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

fn orchard_proving_key() -> &'static orchard::circuit::ProvingKey {
    ORCHARD_PROVING_KEY.get_or_init(|| {
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2)
    })
}

fn check_round_trip(pczt: &Pczt) {
    // The v1 encoding remains available explicitly.
    v1::Pczt::try_from(pczt.clone())
        .expect("v1 encoding succeeds")
        .serialize();

    // The default encoding is the latest (v2) encoding.
    let v2_encoded = v2::Pczt::from(pczt.clone()).serialize();

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
        signed.orchard().actions()[index]
            .spend()
            .rk()
            .as_ref()
            .expect("signing populates `rk`"),
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
        signed.ironwood().actions()[index]
            .spend()
            .rk()
            .as_ref()
            .expect("signing populates `rk`"),
        sighash,
        produced_sig,
    );

    // The wire `fvk` bytes must be preserved (unchanged) after signing.
    assert_eq!(wire_spend_fvks(&signed, true), fvks_before);
}

/// Reads the version field of an encoded PCZT header.
fn pczt_version(encoded: &[u8]) -> u32 {
    u32::from_le_bytes(encoded[4..8].try_into().unwrap())
}

/// The wire encodings of an action's derived Orchard-shaped fields, plus its
/// memo-kind tag.
#[derive(Debug, PartialEq, Eq)]
struct DerivedFieldBytes {
    cv_net: Option<[u8; 32]>,
    nullifier: Option<[u8; 32]>,
    rk: Option<[u8; 32]>,
    cmx: Option<[u8; 32]>,
    ephemeral_key: Option<[u8; 32]>,
    enc_ciphertext: Option<Vec<u8>>,
    out_ciphertext: Vec<u8>,
    memo_kind: Option<MemoKind>,
}

/// Snapshots the derived fields of every action in an Orchard-shaped wire bundle, for
/// per-field byte-identity assertions.
fn derived_fields(bundle: &pczt::orchard::Bundle) -> Vec<DerivedFieldBytes> {
    bundle
        .actions()
        .iter()
        .map(|action| DerivedFieldBytes {
            cv_net: *action.cv_net(),
            nullifier: *action.spend().nullifier(),
            rk: *action.spend().rk(),
            cmx: *action.output().cmx(),
            ephemeral_key: *action.output().ephemeral_key(),
            enc_ciphertext: action.output().enc_ciphertext().clone(),
            out_ciphertext: action.output().out_ciphertext().clone(),
            memo_kind: *action.output().memo_kind(),
        })
        .collect()
}

/// Builds a full, IO-finalized Orchard PCZT whose two outputs carry the two memo
/// constants a migration wallet elides ciphertexts under: requested output 0 the
/// ZIP 302 empty memo ([`MemoKind::Empty`]) and requested output 1 the all-zero memo
/// ([`MemoKind::Zero`]).
///
/// Returns the PCZT, its spend authorizing key, the spend's action index, and the two
/// outputs' action indices in that memo order. Used by the recompute-and-fill tests,
/// which need derived fields holding genuine cryptographic values so that
/// reconstruction can be checked to be byte-identical.
fn orchard_pczt_with_migration_memos()
-> (Pczt, orchard::keys::SpendAuthorizingKey, usize, [usize; 2]) {
    let mut rng = OsRng;

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

    let mut builder = Builder::new(
        MainNetwork,
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
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
            MemoBytes::from_bytes(&[0u8; 512]).unwrap(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        orchard_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();

    let spend_index = orchard_meta.spend_action_index(0).unwrap();
    let output_indices = [
        orchard_meta.output_action_index(0).unwrap(),
        orchard_meta.output_action_index(1).unwrap(),
    ];
    (pczt, orchard_ask, spend_index, output_indices)
}

/// The Ironwood analogue of [`orchard_pczt_with_migration_memos`]: a full,
/// IO-finalized Ironwood PCZT with a real Ironwood spend and the same two memo
/// constants on its outputs.
fn ironwood_pczt_with_migration_memos()
-> (Pczt, orchard::keys::SpendAuthorizingKey, usize, [usize; 2]) {
    let mut rng = OsRng;

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

    let mut builder = Builder::new(
        nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
        },
    );
    builder
        .add_ironwood_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(orchard_fvk.to_ovk(zip32::Scope::Internal)),
            orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal),
            Zatoshis::const_from_u64(890_000),
            MemoBytes::from_bytes(&[0u8; 512]).unwrap(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        ironwood_meta,
        ..
    } = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();

    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();

    let spend_index = ironwood_meta.spend_action_index(0).unwrap();
    let output_indices = [
        ironwood_meta.output_action_index(0).unwrap(),
        ironwood_meta.output_action_index(1).unwrap(),
    ];
    (pczt, orchard_ask, spend_index, output_indices)
}

/// Redacts every derived Orchard-shaped field the migration wire format elides: the
/// five recomputable fields on every action, each output's `enc_ciphertext` under its
/// memo-kind tag, and (when requested) the bundle anchor.
fn redact_derived_fields(
    pczt: Pczt,
    ironwood: bool,
    [empty_memo_action, zero_memo_action]: [usize; 2],
    clear_anchor: bool,
) -> Pczt {
    let redact = |mut r: pczt::roles::redactor::orchard::OrchardRedactor<'_>| {
        r.redact_actions(|mut a| {
            a.clear_cv_net();
            a.clear_nullifier();
            a.clear_rk();
            a.clear_cmx();
            a.clear_ephemeral_key();
        });
        r.redact_action(empty_memo_action, |mut a| {
            a.clear_enc_ciphertext(MemoKind::Empty);
        });
        r.redact_action(zero_memo_action, |mut a| {
            a.clear_enc_ciphertext(MemoKind::Zero);
        });
        if clear_anchor {
            r.clear_anchor();
        }
    };

    let redactor = Redactor::new(pczt);
    if ironwood {
        redactor.redact_ironwood_with(redact).finish()
    } else {
        redactor.redact_orchard_with(redact).finish()
    }
}

/// The on-chain-safety gate for the optional-field wire format: eliding every derived
/// Orchard field (plus both ciphertexts under their memo-kind tags), round-tripping
/// through the v2 encoding, and recomputing with `fill_derived_fields` must yield a
/// PCZT BYTE-IDENTICAL to the never-redacted one — first checked field-by-field for
/// diagnostics, then over the full serialization. The refilled PCZT must then prove,
/// sign, and extract exactly like the original.
#[test]
fn fill_derived_fields_is_byte_identical_to_never_redacted_orchard() {
    let (full, orchard_ask, spend_index, output_indices) = orchard_pczt_with_migration_memos();
    let full_bytes = full.clone().serialize().unwrap();
    assert_eq!(pczt_version(&full_bytes), 2);
    let original_fields = derived_fields(full.orchard());
    for f in &original_fields {
        assert!(f.cv_net.is_some());
        assert!(f.nullifier.is_some());
        assert!(f.rk.is_some());
        assert!(f.cmx.is_some());
        assert!(f.ephemeral_key.is_some());
        assert!(f.enc_ciphertext.is_some());
        assert_eq!(f.memo_kind, None);
    }

    // Filling an already-complete PCZT is a byte-identical no-op.
    let mut already_full = full.clone();
    already_full.fill_derived_fields().unwrap();
    assert_eq!(already_full.serialize().unwrap(), full_bytes);

    // Elide the derived fields; the v2 encoding carries the omissions directly, and
    // parsing must preserve them as absent (parse of the wire fields does not
    // recompute). The released v1 encoding cannot represent them and refuses.
    let redacted = redact_derived_fields(full, false, output_indices, false);
    assert!(matches!(
        v1::Pczt::try_from(redacted.clone()),
        Err(EncodingError::RequiresV2)
    ));
    let encoded = redacted.serialize().unwrap();
    assert_eq!(pczt_version(&encoded), 2);

    let mut reparsed = Pczt::parse(&encoded).unwrap();
    for (i, f) in derived_fields(reparsed.orchard()).into_iter().enumerate() {
        assert_eq!(f.cv_net, None);
        assert_eq!(f.nullifier, None);
        assert_eq!(f.rk, None);
        assert_eq!(f.cmx, None);
        assert_eq!(f.ephemeral_key, None);
        assert_eq!(f.enc_ciphertext, None);
        let expected_kind = if i == output_indices[0] {
            MemoKind::Empty
        } else {
            MemoKind::Zero
        };
        assert_eq!(f.memo_kind, Some(expected_kind));
    }

    // Recompute-and-fill reproduces every elided field byte-for-byte...
    reparsed.fill_derived_fields().unwrap();
    assert_eq!(derived_fields(reparsed.orchard()), original_fields);
    // ...and the whole PCZT encoding.
    assert_eq!(reparsed.clone().serialize().unwrap(), full_bytes);

    // The refilled PCZT still proves, signs, and extracts.
    let pczt = Prover::new(reparsed)
        .create_orchard_proof(orchard_proving_key())
        .unwrap()
        .finish();
    let mut signer = Signer::new(pczt).unwrap();
    signer.sign_orchard(spend_index, &orchard_ask).unwrap();
    let tx = TransactionExtractor::new(signer.finish())
        .extract()
        .unwrap();
    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

/// The Ironwood (note version V3) analogue of the byte-identity gate. This is the
/// load-bearing check for the `note_version` threading: the recomputed
/// `enc_ciphertext`s must use the V3 note plaintext lead byte, including the ZIP 302
/// empty memo carried by the real migrated output. It then drives the low-level
/// Signer over the still-redacted PCZT (the device's inbound path), asserting the
/// implicit fill produces a signature byte-identical to signing the never-redacted
/// PCZT.
#[test]
fn fill_derived_fields_is_byte_identical_to_never_redacted_ironwood() {
    let (full, orchard_ask, spend_index, output_indices) = ironwood_pczt_with_migration_memos();
    let full_bytes = full.clone().serialize().unwrap();
    assert_eq!(pczt_version(&full_bytes), 2);
    let original_fields = derived_fields(full.ironwood());
    assert!(!original_fields.is_empty());

    let redacted = redact_derived_fields(full.clone(), true, output_indices, false);
    let encoded = redacted.serialize().unwrap();
    assert_eq!(pczt_version(&encoded), 2);

    let mut reparsed = Pczt::parse(&encoded).unwrap();
    for f in derived_fields(reparsed.ironwood()) {
        assert_eq!(f.cv_net, None);
        assert_eq!(f.enc_ciphertext, None);
        assert!(f.memo_kind.is_some());
    }
    reparsed.fill_derived_fields().unwrap();
    assert_eq!(derived_fields(reparsed.ironwood()), original_fields);
    assert_eq!(reparsed.serialize().unwrap(), full_bytes);

    // Device path: sign the redacted PCZT directly through the low-level Signer,
    // which fills the elided fields itself before its preverified signing parse (in
    // particular, the recomputed `rk` must not trip the modified-actions check).
    let sighash = Signer::new(full.clone()).unwrap().shielded_sighash();
    // A signer given only the redacted wire bytes derives the identical sighash: the
    // full (Verifier-style) parse also recomputes the elided fields.
    let redacted_bytes = redact_derived_fields(full.clone(), true, output_indices, false)
        .serialize()
        .unwrap();
    assert_eq!(
        Signer::new(Pczt::parse(&redacted_bytes).unwrap())
            .unwrap()
            .shielded_sighash(),
        sighash,
    );
    let seed = [9; 32];
    let expected_sig =
        expected_spend_auth_sig(&full, true, spend_index, &orchard_ask, sighash, seed);
    let fvks_full = wire_spend_fvks(&full, true);

    let sign = |pczt: Pczt| {
        low_level_signer::Signer::new(pczt)
            .sign_ironwood_with::<low_level_signer::OrchardParseError, _>(|_, bundle, _| {
                bundle.actions_mut()[spend_index]
                    .sign(sighash, &orchard_ask, ChaCha20Rng::from_seed(seed))
                    .expect("signing succeeds");
                Ok(())
            })
            .unwrap()
            .finish()
    };
    let signed_redacted = sign(Pczt::parse(&redacted_bytes).unwrap());
    let signed_full = sign(full);

    // Eliding fields on the wire changes nothing about what is signed: the signature
    // (and the entire signed PCZT) is byte-identical to the never-redacted path, and
    // the wire `fvk` bytes are preserved.
    let produced_sig = signed_redacted.ironwood().actions()[spend_index]
        .spend()
        .spend_auth_sig()
        .expect("action was signed");
    assert_eq!(produced_sig, expected_sig);
    assert_eq!(wire_spend_fvks(&signed_redacted, true), fvks_full);
    assert_eq!(
        signed_redacted.serialize().unwrap(),
        signed_full.serialize().unwrap()
    );
}

/// A single redacted derived field is representable directly in the v2 encoding: the
/// omission survives a serialize/parse round-trip unchanged, alongside the fields the
/// redactor left in place.
#[test]
fn redacted_derived_field_round_trips() {
    let (full, _, _, _) = orchard_pczt_with_migration_memos();

    let redacted = Redactor::new(full)
        .redact_orchard_with(|mut r| {
            r.redact_actions(|mut a| {
                a.clear_cmx();
            });
        })
        .finish();

    let encoded = redacted.serialize().unwrap();
    assert_eq!(pczt_version(&encoded), 2);

    // The omission survives a parse round-trip unchanged, and the neighboring derived
    // fields stay populated.
    let reparsed = Pczt::parse(&encoded).unwrap();
    assert_eq!(reparsed.orchard().actions()[0].output().cmx(), &None);
    assert!(
        reparsed.orchard().actions()[0]
            .output()
            .ephemeral_key()
            .is_some()
    );
    assert_eq!(reparsed.serialize().unwrap(), encoded);
}

/// An elided anchor refills as the fixed `Anchor::empty_tree()` placeholder: byte-
/// identically when the producer's anchor already was that constant (the migration
/// shape), and as a documented divergence otherwise (the extracting wallet installs
/// the real anchor).
#[test]
fn anchor_elision_refills_the_empty_tree_placeholder() {
    let empty_tree = orchard::Anchor::empty_tree().to_bytes();

    // Both Orchard-shaped anchors are the placeholder: elision round-trips
    // byte-identically.
    let full = Creator::new(BranchId::Nu6_3.into(), 10_000_000, 133, [0; 32], empty_tree)
        .unwrap()
        .with_ironwood_anchor(empty_tree)
        .unwrap()
        .build();
    let full_bytes = full.clone().serialize().unwrap();
    assert_eq!(pczt_version(&full_bytes), 2);

    let redacted = Redactor::new(full)
        .redact_orchard_with(|mut r| r.clear_anchor())
        .redact_ironwood_with(|mut r| r.clear_anchor())
        .finish();
    let encoded = redacted.serialize().unwrap();
    assert_eq!(pczt_version(&encoded), 2);

    let mut reparsed = Pczt::parse(&encoded).unwrap();
    assert_eq!(reparsed.orchard().anchor(), &None);
    assert_eq!(reparsed.ironwood().anchor(), &None);
    reparsed.fill_derived_fields().unwrap();
    assert_eq!(reparsed.serialize().unwrap(), full_bytes);

    // A non-placeholder anchor is NOT reproduced: the fill installs the placeholder.
    let mut real_anchor = Redactor::new(
        Creator::new(BranchId::Nu6_3.into(), 10_000_000, 133, [0; 32], [9; 32])
            .unwrap()
            .build(),
    )
    .redact_orchard_with(|mut r| r.clear_anchor())
    .finish();
    real_anchor.fill_derived_fields().unwrap();
    assert_eq!(real_anchor.orchard().anchor(), &Some(empty_tree));
}

/// The Combiner restores elided derived fields (and an elided anchor) from a
/// fully-populated peer copy. The memo-kind tag merges like any other optional field
/// and is scrubbed by `fill_derived_fields` (without recomputation, `enc_ciphertext`
/// being present), restoring the never-redacted bytes.
#[test]
fn combiner_restores_elided_fields_from_a_full_copy() {
    let (full, _, _, output_indices) = orchard_pczt_with_migration_memos();
    let full_bytes = full.clone().serialize().unwrap();

    let redacted = redact_derived_fields(full.clone(), false, output_indices, true);

    let mut merged = Combiner::new(vec![redacted, full]).combine().unwrap();
    merged.fill_derived_fields().unwrap();
    assert_eq!(merged.serialize().unwrap(), full_bytes);
}
