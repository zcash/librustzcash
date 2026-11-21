use std::{convert::Infallible, sync::OnceLock};

use ::transparent::{
    address::{Script, TransparentAddress},
    bundle as transparent,
    sighash::SighashType,
};
use orchard::{
    primitives::redpallas::{self, SpendAuth},
    tree::MerkleHashOrchard,
};
use pczt::{
    Pczt,
    roles::{
        combiner::Combiner,
        creator::Creator,
        io_finalizer::IoFinalizer,
        low_level_signer,
        prover::Prover,
        redactor::Redactor,
        signer::{Signer, extract_orchard_spend_auth_signatures},
        spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor,
        updater::{SpendWitnessUpdateError, Updater},
        verifier::Verifier,
    },
    v1, v2,
};
use rand::{SeedableRng, rand_core::UnwrapErr, rngs::SysRng};
use rand_chacha::ChaCha20Rng;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
#[cfg(zcash_unstable = "nu8")]
use std::num::NonZeroU8;
use zcash_keys::keys::transparent::{AccountPrivKey, IncomingViewingKey};
#[cfg(zcash_unstable = "nu8")]
use zcash_keys::keys::transparent::{NonHardenedChildIndex, zip48};
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, DeferredPcztBuilder, PcztResult},
    fees::zip317,
    sighash::{PrecomputedSighashData, SignableInput},
    txid::to_txid,
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::BlockHeight,
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
    // The v1 and v2 encodings both remain available explicitly.
    v1::Pczt::try_from(pczt.clone())
        .expect("v1 encoding succeeds")
        .serialize();
    v2::Pczt::try_from(pczt.clone())
        .expect("v2 encoding succeeds")
        .serialize();

    // The default encoding is the minimal encoding capable of representing the
    // PCZT's content (v1 or v2), and round-trips losslessly through parsing and
    // re-serialization.
    let encoded = pczt.clone().serialize().expect("serialization succeeds");
    let reencoded = Pczt::parse(&encoded)
        .expect("can parse encoded PCZT")
        .serialize()
        .expect("serialization succeeds");
    assert_eq!(encoded, reencoded);
}

/// Emulates an external signer returning Orchard-protocol spend authorization
/// signatures separately from the PCZT, and asserts that reapplying the complete
/// signature set reproduces the signed PCZT.
fn assert_external_orchard_signature_round_trip(
    unsigned_pczt: Pczt,
    signed_pczt: &Pczt,
    value_pool: orchard::ValuePool,
    expected_action_index: usize,
) -> Pczt {
    let signatures = extract_orchard_spend_auth_signatures(signed_pczt);
    assert!(
        signatures
            .iter()
            .all(|signature| signature.value_pool() == value_pool)
    );
    assert!(
        signatures
            .iter()
            .any(|signature| signature.action_index() == expected_action_index)
    );

    let mut signer = Signer::new(unsigned_pczt).unwrap();
    for signature in &signatures {
        signer
            .apply_orchard_spend_auth_signature(signature)
            .unwrap();
    }
    let reapplied_pczt = signer.finish();
    assert_eq!(
        reapplied_pczt.clone().serialize().unwrap(),
        signed_pczt.clone().serialize().unwrap()
    );
    reapplied_pczt
}

#[test]
fn transparent_to_orchard() {
    let params = pre_nu6_3_test_network();
    let rng = UnwrapErr(SysRng);

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
    let transparent_pubkey = transparent_sk.public_key();
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
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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

    let memo_resolved = IoFinalizer::new(memo_redacted)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    assert!(memo_resolved.orchard().actions().iter().all(|action| {
        matches!(
            action.output().enc_ciphertext(),
            pczt::orchard::EncCiphertext::Encrypted(_)
        )
    }));
    check_round_trip(&memo_resolved);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    check_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_orchard_proof(UnwrapErr(SysRng), orchard_proving_key())
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
    let tx_effects =
        PrecomputedSighashData::new_zip244(pczt.clone().into_effects().unwrap()).unwrap();

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt)
        .extract(UnwrapErr(SysRng))
        .unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);

    // Validate the transaction.
    let bundle = tx.transparent_bundle().unwrap();
    assert_eq!(bundle.vin.len(), 1);
    let txin = bundle.vin.first().unwrap();
    let sighasher = |script_code: &script::Code, hash_type: &zcash_script::signature::HashType| {
        Some(
            tx_effects
                .signature_hash(&SignableInput::Transparent(
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
                ))
                .as_ref()
                .to_owned(),
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
    let params = pre_nu6_3_test_network();
    let rng = UnwrapErr(SysRng);

    // Construct a 2-of-3 ZIP 48 P2SH account.
    let account_sk =
        |i| zip48::AccountPrivKey::from_seed(&params, &[i; 32], zip32::AccountId::ZERO).unwrap();
    let account_sks = [account_sk(1), account_sk(2), account_sk(3)];
    let key_info = account_sks
        .iter()
        .map(|sk| sk.to_account_pubkey())
        .collect();
    let fvk = zip48::FullViewingKey::standard(NonZeroU8::new(2).unwrap(), key_info).unwrap();

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
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    check_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_orchard_proof(UnwrapErr(SysRng), orchard_proving_key())
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
    let tx_effects =
        PrecomputedSighashData::new_zip244(pczt.clone().into_effects().unwrap()).unwrap();

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt)
        .extract(UnwrapErr(SysRng))
        .unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);

    // Validate the transaction.
    let bundle = tx.transparent_bundle().unwrap();
    assert_eq!(bundle.vin.len(), 1);
    let txin = bundle.vin.first().unwrap();
    let sighasher = |script_code: &script::Code, hash_type: &zcash_script::signature::HashType| {
        Some(
            tx_effects
                .signature_hash(&SignableInput::Transparent(
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
                ))
                .as_ref()
                .to_owned(),
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
#[cfg(zcash_unstable = "nu8")]
fn v7_transparent_p2sh_multisig_to_orchard() {
    let params = nu8_test_network();
    let rng = UnwrapErr(SysRng);

    // Construct a 2-of-3 ZIP 48 P2SH account.
    let account_sk =
        |i| zip48::AccountPrivKey::from_seed(&params, &[i; 32], zip32::AccountId::ZERO).unwrap();
    let account_sks = [account_sk(1), account_sk(2), account_sk(3)];
    let key_info = account_sks
        .iter()
        .map(|sk| sk.to_account_pubkey())
        .collect();
    let fvk = zip48::FullViewingKey::standard(NonZeroU8::new(2).unwrap(), key_info).unwrap();

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
        12.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .propose_version::<zip317::FeeRule>(zcash_primitives::transaction::TxVersion::V7)
        .unwrap();
    builder
        .add_transparent_p2sh_input(redeem_script.clone(), utxo, coin.clone())
        .unwrap();
    builder
        .add_orchard_change_output::<zip317::FeeRule>(
            orchard_fvk.clone(),
            Some(orchard_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_change_output::<zip317::FeeRule>(
            orchard_fvk.clone(),
            Some(orchard_fvk.to_ovk(zip32::Scope::Internal)),
            recipient,
            Zatoshis::const_from_u64(880_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(rng, &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_v2_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    check_v2_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_orchard_proof(UnwrapErr(SysRng), post_nu6_3_orchard_proving_key())
        .unwrap()
        .finish();
    check_v2_round_trip(&pczt);

    // The Orchard bundle has actions (the change outputs pair with fabricated
    // spends), so sign them.
    let pczt = {
        let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
        let action_count = pczt.orchard().actions().len();
        let mut signer = Signer::new(pczt).unwrap();
        for index in 0..action_count {
            match signer.sign_orchard(UnwrapErr(SysRng), index, &orchard_ask) {
                Ok(())
                | Err(pczt::roles::signer::Error::OrchardSign(
                    orchard::pczt::SignerError::WrongSpendAuthorizingKey,
                )) => {}
                Err(e) => panic!("orchard action {index}: {e:?}"),
            }
        }
        signer.finish()
    };
    check_v2_round_trip(&pczt);

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
    check_v2_round_trip(&pczt);

    // A non-`SIGHASH_ALL` partial signature is refused at finalization even
    // though three signatures are present, so a missing signature cannot mask
    // it.
    {
        let partial = low_level_signer::Signer::new(pczt.clone())
            .sign_transparent_with(|_, bundle, _| {
                let input = &mut bundle.inputs_mut()[0];
                let key = input.partial_signatures().keys().next().copied().unwrap();
                let mut bad = vec![0xab; 64];
                bad.push(SighashType::NONE.encode());
                // Only the non-`ALL` signature remains, so a missing
                // signature cannot mask the rejected one.
                input.set_sighash_type(SighashType::NONE);
                input.partial_signatures_mut().clear();
                input.partial_signatures_mut().insert(key, bad);
                Ok::<_, ::transparent::pczt::ParseError>(())
            })
            .unwrap()
            .finish();
        assert!(matches!(
            SpendFinalizer::new(partial).finalize_spends(),
            Err(pczt::roles::spend_finalizer::Error::TransparentFinalize(
                ::transparent::pczt::SpendFinalizerError::DisallowedSighashType(_)
            ))
        ));
    }

    // Finalize spends. This will pick 2 of the signatures to use in the P2SH scriptSig.
    let pczt = SpendFinalizer::new(pczt).finalize_spends().unwrap();
    check_v2_round_trip(&pczt);

    // Grab the transaction's effects here, as it's easier.
    let tx_effects =
        PrecomputedSighashData::new_zip244(pczt.clone().into_effects().unwrap()).unwrap();

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt)
        .extract(UnwrapErr(SysRng))
        .unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 132);

    // Validate the transaction.
    let bundle = tx.transparent_bundle().unwrap();
    assert_eq!(bundle.vin.len(), 1);
    let txin = bundle.vin.first().unwrap();
    // The scriptSig is OP_0, the two signatures the Finalizer chose, then the
    // redeem script.
    let script_sig = txin.script_sig().0.to_bytes();
    assert_eq!(script_sig.first(), Some(&0x00)); // OP_0
    let redeem_bytes = redeem_script.to_bytes();
    assert!(script_sig.ends_with(&redeem_bytes[..]));
    assert_ne!(script_sig.len(), redeem_bytes.len() + 1);
    let sighasher = |script_code: &script::Code, hash_type: &zcash_script::signature::HashType| {
        let script_code = Script(script_code.clone());
        let signable = ::transparent::sighash::SignableInput::from_parts(
            bundle,
            match (hash_type.signed_outputs(), hash_type.anyone_can_pay()) {
                (zcash_script::signature::SignedOutputs::All, false) => SighashType::ALL,
                (zcash_script::signature::SignedOutputs::All, true) => {
                    SighashType::ALL_ANYONECANPAY
                }
                (zcash_script::signature::SignedOutputs::Single, false) => SighashType::SINGLE,
                (zcash_script::signature::SignedOutputs::Single, true) => {
                    SighashType::SINGLE_ANYONECANPAY
                }
                (zcash_script::signature::SignedOutputs::None, false) => SighashType::NONE,
                (zcash_script::signature::SignedOutputs::None, true) => {
                    SighashType::NONE_ANYONECANPAY
                }
            },
            0,
            &script_code,
            coin.script_pubkey(),
            coin.value(),
        )
        .unwrap();
        Some(
            tx_effects
                .signature_hash(&SignableInput::V7(
                    zcash_primitives::transaction::sighash::V7SignatureContext::Transparent(
                        signable,
                    ),
                ))
                .as_ref()
                .to_owned(),
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
    let mut rng = UnwrapErr(SysRng);

    // Create a Sapling account to send funds from.
    let sapling_extsk = sapling::zip32::ExtendedSpendingKey::master(&[1; 32])
        .expect("the derivation path yields a valid key");
    let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
    let sapling_internal_dfvk = sapling_extsk
        .derive_internal()
        .expect("the derivation path yields a valid key")
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
        pre_nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    check_round_trip(&pczt);

    // Update the Sapling bundle with its proof generation key.
    let index = sapling_meta.spend_index(0).unwrap();
    let pczt = Updater::new(pczt)
        .update_sapling_with(|mut updater| {
            updater.update_spend_with(index, |mut spend_updater| {
                spend_updater.set_proof_generation_key(sapling_extsk.expsk().proof_generation_key())
            })
        })
        .unwrap()
        .finish();

    // To test the Combiner, we will create the Sapling proofs, Sapling signatures, and
    // Orchard proof "in parallel".

    // Create Sapling proofs.
    let sapling_prover = LocalTxProver::bundled();
    let pczt_with_sapling_proofs = Prover::new(pczt.clone())
        .create_sapling_proofs(UnwrapErr(SysRng), &sapling_prover, &sapling_prover)
        .unwrap()
        .finish();
    check_round_trip(&pczt_with_sapling_proofs);

    // Create Orchard proof.
    let pczt_with_orchard_proof = Prover::new(pczt.clone())
        .create_orchard_proof(UnwrapErr(SysRng), orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt_with_orchard_proof);

    // Pass the PCZT to be signed through a serialization cycle to ensure we don't lose
    // any information. This emulates passing it to another device.
    let pczt = Pczt::parse(&pczt.serialize().unwrap()).unwrap();

    // Apply signatures.
    let mut signer = Signer::new(pczt).unwrap();
    signer
        .sign_sapling(UnwrapErr(SysRng), index, sapling_extsk.expsk().ask())
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
        .extract(UnwrapErr(SysRng))
        .unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[test]
fn orchard_to_orchard() {
    let mut rng = UnwrapErr(SysRng);

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
        pre_nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_round_trip(&pczt);

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    check_round_trip(&pczt);

    // Create proofs.
    let pczt = Prover::new(pczt)
        .create_orchard_proof(UnwrapErr(SysRng), orchard_proving_key())
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    // Apply signatures.
    let index = orchard_meta.spend_action_index(0).unwrap();
    let pczt_without_signatures = pczt.clone();
    let mut signer = Signer::new(pczt).unwrap();
    signer
        .sign_orchard(UnwrapErr(SysRng), index, &orchard_ask)
        .unwrap();
    let signed_pczt = signer.finish();
    check_round_trip(&signed_pczt);

    let pczt = assert_external_orchard_signature_round_trip(
        pczt_without_signatures,
        &signed_pczt,
        orchard::ValuePool::Orchard,
        index,
    );
    check_round_trip(&pczt);

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt)
        .extract(UnwrapErr(SysRng))
        .unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

/// Extracts each action's wire `fvk` bytes from the Orchard or Ironwood pool of the
/// PCZT, via the Verifier role's full (FVK-deriving) parse.
fn wire_spend_fvks(pczt: &Pczt, ironwood: bool) -> Vec<Option<[u8; 96]>> {
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
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(*rk).expect("`rk` is a valid key");
    let sig = redpallas::Signature::<SpendAuth>::from(sig);
    rk.verify(&sighash, &sig)
        .expect("spend authorization signature verifies against `rk`");
}

#[test]
fn orchard_low_level_signer_uses_preverified_signing_parse() {
    let mut rng = UnwrapErr(SysRng);

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
        pre_nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT, and finalize the I/O.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();

    // Create the proof before signing, so that the byte-losslessness check below
    // covers a maximal bundle (witnesses, proof, and FVKs all present).
    let pczt = Prover::new(pczt)
        .create_orchard_proof(UnwrapErr(SysRng), orchard_proving_key())
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
    let tx = TransactionExtractor::new(signed)
        .extract(UnwrapErr(SysRng))
        .unwrap();

    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

/// Checks that the PCZT round-trips through the v2 encoding, forced explicitly.
///
/// This is [`check_round_trip`] minus the v1 encoding check: v6 PCZTs (which carry
/// an Ironwood bundle) are not representable in the legacy v1 encoding. The v2
/// encoding is forced explicitly (rather than using the default [`Pczt::serialize`])
/// because some content that is v1-representable would otherwise take the minimal
/// (v1) encoding, silently discarding v2-only information such as an absent anchor.
fn check_v2_round_trip(pczt: &Pczt) {
    let encoded = v2::Pczt::try_from(pczt.clone())
        .expect("v2 encoding succeeds")
        .serialize();
    let reencoded = v2::Pczt::try_from(Pczt::parse(&encoded).expect("can parse encoded PCZT"))
        .expect("v2 encoding succeeds")
        .serialize();
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
        AccountPrivKey::from_seed(&nu6_3_test_network(), &[1; 32], zip32::AccountId::ZERO).unwrap();
    let (transparent_addr, address_index) = transparent_account_sk
        .to_account_pubkey()
        .derive_external_ivk()
        .unwrap()
        .default_address();
    let transparent_sk = transparent_account_sk
        .derive_external_secret_key(address_index)
        .unwrap();
    let transparent_pubkey = transparent_sk.public_key();

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
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io(UnwrapErr(SysRng))
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

    // Force the v2 encoding explicitly here too: for an output-only Sapling
    // bundle, an absent anchor is also v1-representable (v1 substitutes a
    // placeholder), but this assertion is specifically checking the v2
    // encoding's ability to preserve an absent anchor losslessly.
    let v2_encoded = v2::Pczt::try_from(redacted)
        .expect("v2 encoding succeeds")
        .serialize();
    let reparsed = Pczt::parse(&v2_encoded).unwrap();
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
    let mut rng = UnwrapErr(SysRng);

    let sapling_extsk = sapling::zip32::ExtendedSpendingKey::master(&[1; 32])
        .expect("the derivation path yields a valid key");
    let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
    let sapling_internal_dfvk = sapling_extsk
        .derive_internal()
        .expect("the derivation path yields a valid key")
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
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    let index = sapling_meta.spend_index(0).unwrap();
    let pczt = Updater::new(pczt)
        .update_sapling_with(|mut updater| {
            updater.update_spend_with(index, |mut spend_updater| {
                spend_updater.set_proof_generation_key(sapling_extsk.expsk().proof_generation_key())
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
        .sign_sapling(UnwrapErr(SysRng), index, sapling_extsk.expsk().ask())
        .unwrap();
    let signed = signer.finish();

    let redacted = Redactor::new(signed)
        .redact_sapling_with(|mut r| r.clear_anchor())
        .finish();
    assert!(redacted.sapling().anchor().is_none());
    assert!(
        Prover::new(redacted.clone())
            .create_sapling_proofs(
                UnwrapErr(SysRng),
                &LocalTxProver::bundled(),
                &LocalTxProver::bundled()
            )
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
        .create_sapling_proofs(UnwrapErr(SysRng), &sapling_prover, &sapling_prover)
        .unwrap()
        .finish();
    assert!(matches!(
        Updater::new(proved.clone()).set_sapling_anchor(anchor),
        Err(pczt::roles::updater::AnchorUpdateError::ProofAlreadyPresent)
    ));

    let (spend_vk, output_vk) = sapling_prover.verifying_keys();
    let tx = TransactionExtractor::new(proved)
        .with_sapling(&spend_vk, &output_vk)
        .extract(UnwrapErr(SysRng))
        .unwrap();
    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[test]
fn wallet_can_set_sapling_witness_after_signing() {
    let mut rng = UnwrapErr(SysRng);

    // Create a Sapling account to spend from and send back to.
    let sapling_extsk = sapling::zip32::ExtendedSpendingKey::master(&[1; 32])
        .expect("the derivation path yields a valid key");
    let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
    let sapling_internal_dfvk = sapling_extsk
        .derive_internal()
        .expect("the derivation path yields a valid key")
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
        pre_nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    let index = sapling_meta.spend_index(0).unwrap();
    let pczt = Updater::new(pczt)
        .update_sapling_with(|mut updater| {
            updater.update_spend_with(index, |mut spend_updater| {
                spend_updater.set_proof_generation_key(sapling_extsk.expsk().proof_generation_key())
            })
        })
        .unwrap()
        .finish();
    check_round_trip(&pczt);

    let mut signer = Signer::new(pczt).unwrap();
    let sighash = signer.shielded_sighash();
    signer
        .sign_sapling(UnwrapErr(SysRng), index, sapling_extsk.expsk().ask())
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
            .create_sapling_proofs(
                UnwrapErr(SysRng),
                &LocalTxProver::bundled(),
                &LocalTxProver::bundled()
            )
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
        .create_sapling_proofs(UnwrapErr(SysRng), &sapling_prover, &sapling_prover)
        .unwrap()
        .finish();
    assert!(matches!(
        Updater::new(proved.clone())
            .set_sapling_spend_witnesses([(index, merkle_path_after_proof)]),
        Err(SpendWitnessUpdateError::ProofAlreadyPresent)
    ));
    check_round_trip(&proved);
}

/// A regtest network on which NU6.2 is the most recent network upgrade, for exercising
/// pre-Ironwood (V5 transaction) flows independently of the mainnet NU6.3 activation
/// height.
fn pre_nu6_3_test_network() -> zcash_protocol::local_consensus::LocalNetwork {
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
        nu6_3: None,
        nu7: None,
        #[cfg(zcash_unstable = "nu8")]
        nu8: None,
        #[cfg(zcash_unstable = "nutachyon")]
        nu_tachyon: None,
    }
}

/// A regtest network with NU6.3 activated, for exercising the Ironwood pool.
fn nu6_3_test_network() -> zcash_protocol::local_consensus::LocalNetwork {
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
        nu7: None,
        #[cfg(zcash_unstable = "nu8")]
        nu8: None,
        #[cfg(zcash_unstable = "nutachyon")]
        nu_tachyon: None,
    }
}

/// A regtest network with NU7 activated at height 11 and NU8 at height 12,
/// for exercising v7 transactions.
#[cfg(zcash_unstable = "nu8")]
fn nu8_test_network() -> zcash_protocol::local_consensus::LocalNetwork {
    zcash_protocol::local_consensus::LocalNetwork {
        nu7: Some(BlockHeight::from_u32(11)),
        nu8: Some(BlockHeight::from_u32(12)),
        ..nu6_3_test_network()
    }
}

/// Builds an I/O-finalized PCZT that spends an Orchard note into an Ironwood
/// output, with no transparent inputs.
fn orchard_to_ironwood_pczt(
    params: zcash_protocol::local_consensus::LocalNetwork,
    target_height: BlockHeight,
) -> Pczt {
    let spend_fvk = orchard::keys::FullViewingKey::from(
        &orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap(),
    );
    let recipient = spend_fvk.address_at(0u32, orchard::keys::Scope::External);
    let rho = orchard::note::Rho::from_bytes(&[1; 32]).unwrap();
    let rseed = (0u8..=255)
        .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
        .expect("at least one test rseed is valid");
    let note = orchard::Note::from_parts(
        recipient,
        orchard::value::NoteValue::from_raw(100_000),
        rho,
        rseed,
        orchard::note::NoteVersion::V2,
    )
    .unwrap();
    let zero = MerkleHashOrchard::from_bytes(&[0; 32]).unwrap();
    let merkle_path = orchard::tree::MerklePath::from_parts(0, [zero; 32]);
    let orchard_anchor = merkle_path.root(note.commitment().into());

    let mut builder = Builder::new(
        params,
        target_height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard_anchor),
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::UNPADDED,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(spend_fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            None,
            recipient,
            Zatoshis::const_from_u64(85_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_change_output::<zip317::FeeRule>(
            spend_fvk,
            None,
            recipient,
            Zatoshis::const_from_u64(0),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io(UnwrapErr(SysRng))
        .unwrap()
}

/// With no transparent inputs, a v6 transaction's shielded sighash is its txid, so the
/// effects a Signer signs over must carry every bundle of the transaction and be
/// digested under the rules of its version.
fn assert_shielded_sighash_is_txid(pczt: Pczt) {
    let sighash = Signer::new(pczt.clone()).unwrap().shielded_sighash();
    let effects = pczt.into_effects().unwrap();
    assert!(effects.transparent_bundle().is_none());
    assert!(
        effects.ironwood_bundle().is_some(),
        "extracting the PCZT's effects must keep its Ironwood bundle",
    );

    let txid = to_txid(
        effects.version(),
        effects.consensus_branch_id(),
        &effects.txid_digests(),
    )
    .expect("a PCZT's effects are a v5 or later transaction");
    assert_eq!(&sighash, txid.as_ref());
}

#[test]
fn v6_ironwood_pczt_signs_over_its_txid() {
    assert_shielded_sighash_is_txid(orchard_to_ironwood_pczt(
        nu6_3_test_network(),
        BlockHeight::from_u32(10),
    ));
}

/// A v7 PCZT signs a distinct digest per action, per pool and per binding signature.
///
/// Every signature is created through the Signer's per-index accessors, extracted, and
/// then verified against its own digest and against a sibling's. The Orchard bundle is
/// padded to more than one action, so a shared digest cannot satisfy the check. The
/// Transaction Extractor has to create the per-pool binding signatures itself, which
/// only succeeds if the Orchard and Ironwood binding digests differ.
#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_pczt_signs_each_action_and_binding_over_its_own_digest() {
    use zcash_primitives::transaction::sighash::V7SignatureContext;

    let rng = UnwrapErr(SysRng);

    let sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
    let ask = orchard::keys::SpendAuthorizingKey::from(&sk);
    let spend_fvk = orchard::keys::FullViewingKey::from(&sk);
    let recipient = spend_fvk.address_at(0u32, orchard::keys::Scope::External);
    // Two notes from the same account, each spent by its own action.
    let notes = [1u8, 2].map(|rho_byte| {
        let rho = orchard::note::Rho::from_bytes(&[rho_byte; 32]).unwrap();
        let rseed = (0u8..=255)
            .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
            .expect("at least one test rseed is valid");
        orchard::Note::from_parts(
            recipient,
            orchard::value::NoteValue::from_raw(100_000),
            rho,
            rseed,
            orchard::note::NoteVersion::V2,
        )
        .unwrap()
    });
    // Both notes share one anchor and have their own witness.
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
    for note in &notes {
        tree.append(
            MerkleHashOrchard::from_cmx(&note.commitment().into()),
            incrementalmerkletree::Retention::Marked,
        )
        .unwrap();
    }
    tree.checkpoint(9_999_999).unwrap();
    let (orchard_anchor, merkle_paths) = {
        let paths = [0u64, 1].map(|position| {
            tree.witness_at_checkpoint_depth(position.into(), 0)
                .unwrap()
                .unwrap()
        });
        let anchor = paths[0].root(MerkleHashOrchard::from_cmx(&notes[0].commitment().into()));
        (anchor, paths)
    };

    let mut builder = Builder::new(
        nu8_test_network(),
        BlockHeight::from_u32(12),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard_anchor.into()),
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::UNPADDED,
        },
    );
    builder
        .propose_version::<zip317::FeeRule>(zcash_primitives::transaction::TxVersion::V7)
        .unwrap();
    for (note, merkle_path) in notes.iter().zip(merkle_paths) {
        builder
            .add_orchard_spend::<zip317::FeeRule>(spend_fvk.clone(), *note, merkle_path.into())
            .unwrap();
    }
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            None,
            recipient,
            Zatoshis::const_from_u64(85_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_change_output::<zip317::FeeRule>(
            spend_fvk.clone(),
            None,
            recipient,
            Zatoshis::const_from_u64(95_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult { pczt_parts, .. } = builder
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();
    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();

    let effects = pczt.clone().into_effects().unwrap();
    assert_eq!(
        effects.version(),
        zcash_primitives::transaction::TxVersion::V7
    );
    effects
        .check_v7_consensus_rules()
        .expect("the extracted transaction's value pool deltas must balance");

    let orchard_action_count = pczt.orchard().actions().len();
    assert!(
        orchard_action_count >= 2,
        "two spends plus padding give the bundle two or more actions",
    );
    assert!(!pczt.ironwood().actions().is_empty());

    let mut signer = Signer::new(pczt.clone()).unwrap();
    let mut orchard_sighashes = Vec::new();
    for index in 0..orchard_action_count {
        let sighash = signer.orchard_sighash(index).unwrap();
        assert!(
            orchard_sighashes.iter().all(|other| other != &sighash),
            "each Orchard action has its own digest",
        );
        // Padding actions use a dummy key already signed by the IO Finalizer.
        match signer.sign_orchard(rng, index, &ask) {
            Ok(())
            | Err(pczt::roles::signer::Error::OrchardSign(
                orchard::pczt::SignerError::WrongSpendAuthorizingKey,
            )) => {}
            Err(e) => panic!("orchard {index}: {e:?}"),
        }
        orchard_sighashes.push(sighash);
    }

    let mut ironwood_sighashes = Vec::new();
    for index in 0..pczt.ironwood().actions().len() {
        let sighash = signer.ironwood_sighash(index).unwrap();
        assert!(
            orchard_sighashes.iter().all(|other| other != &sighash),
            "each Ironwood action has its own digest, distinct from Orchard's",
        );
        // The Ironwood bundle holds output-pairing dummy spends.
        match signer.sign_ironwood(rng, index, &ask) {
            Ok(())
            | Err(pczt::roles::signer::Error::IronwoodSign(
                orchard::pczt::SignerError::WrongSpendAuthorizingKey,
            )) => {}
            Err(e) => panic!("ironwood {index}: {e:?}"),
        }
        ironwood_sighashes.push(sighash);
    }
    let pczt = signer.finish();

    // The Orchard and Ironwood binding signatures are created by the extractor over the
    // empty context of their own pool, so their digests differ.
    let sighash_data = PrecomputedSighashData::new_zip244(effects).unwrap();
    let binding = |context| {
        *sighash_data
            .signature_hash(&SignableInput::V7(context))
            .as_ref()
    };
    let orchard_binding = binding(V7SignatureContext::OrchardBinding);
    let ironwood_binding = binding(V7SignatureContext::IronwoodBinding);
    assert_ne!(orchard_binding, ironwood_binding);
    assert!(
        orchard_sighashes
            .iter()
            .chain(&ironwood_sighashes)
            .all(|sighash| sighash != &orchard_binding && sighash != &ironwood_binding),
        "a binding digest is distinct from every action digest",
    );

    let pczt = Prover::new(pczt)
        .create_orchard_proof(rng, post_nu6_3_orchard_proving_key())
        .unwrap()
        .create_ironwood_proof(rng, post_nu6_3_orchard_proving_key())
        .unwrap()
        .finish();
    let pczt = SpendFinalizer::new(pczt).finalize_spends().unwrap();
    check_v2_round_trip(&pczt);

    let tx = TransactionExtractor::new(pczt).extract(rng).unwrap();

    let orchard = tx.orchard_bundle().unwrap();
    for (index, action) in orchard.actions().iter().enumerate() {
        action
            .rk()
            .verify(&orchard_sighashes[index], action.authorization())
            .expect("Orchard action verifies over its own digest");
    }
    orchard
        .binding_validating_key()
        .verify(
            &orchard_binding,
            orchard.authorization().binding_signature(),
        )
        .expect("Orchard binding verifies over the Orchard binding digest");

    let ironwood = tx.ironwood_bundle().unwrap();
    for (index, action) in ironwood.actions().iter().enumerate() {
        action
            .rk()
            .verify(&ironwood_sighashes[index], action.authorization())
            .expect("Ironwood action verifies over its own digest");
    }
    ironwood
        .binding_validating_key()
        .verify(
            &ironwood_binding,
            ironwood.authorization().binding_signature(),
        )
        .expect("Ironwood binding verifies over the Ironwood binding digest");

    // Cross-checks: a sibling digest does not verify the same signature.
    let first_orchard = &orchard.actions()[0];
    let first_ironwood = &ironwood.actions()[0];
    first_orchard
        .rk()
        .verify(&ironwood_sighashes[0], first_orchard.authorization())
        .expect_err("an Orchard action does not verify over an Ironwood digest");
    first_ironwood
        .rk()
        .verify(&orchard_sighashes[0], first_ironwood.authorization())
        .expect_err("an Ironwood action does not verify over an Orchard digest");
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
    let mut rng = UnwrapErr(SysRng);

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
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io(UnwrapErr(SysRng))
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
            .create_orchard_proof(UnwrapErr(SysRng), post_nu6_3_orchard_proving_key())
            .is_err()
    );

    let mut signer = Signer::new(redacted).unwrap();
    let sighash = signer.shielded_sighash();
    signer
        .sign_orchard(UnwrapErr(SysRng), index, &orchard_ask)
        .unwrap();
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
        .create_orchard_proof(UnwrapErr(SysRng), post_nu6_3_orchard_proving_key())
        .unwrap()
        .create_ironwood_proof(UnwrapErr(SysRng), post_nu6_3_orchard_proving_key())
        .unwrap()
        .finish();
    check_v2_round_trip(&proved);

    assert!(matches!(
        Updater::new(proved.clone()).set_orchard_anchor(anchor),
        Err(pczt::roles::updater::AnchorUpdateError::ProofAlreadyPresent)
    ));

    let tx = TransactionExtractor::new(proved)
        .extract(UnwrapErr(SysRng))
        .unwrap();
    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[test]
fn wallet_can_set_orchard_witness_after_signing() {
    let mut rng = UnwrapErr(SysRng);

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
        pre_nu6_3_test_network(),
        10_000_000.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io(UnwrapErr(SysRng))
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
            .create_orchard_proof(UnwrapErr(SysRng), orchard_proving_key())
            .is_err()
    );

    let mut signer = Signer::new(redacted.clone()).unwrap();
    let sighash = signer.shielded_sighash();
    signer
        .sign_orchard(UnwrapErr(SysRng), index, &orchard_ask)
        .unwrap();
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
        .create_orchard_proof(UnwrapErr(SysRng), orchard_proving_key())
        .unwrap()
        .finish();
    assert!(matches!(
        Updater::new(proved.clone())
            .set_orchard_spend_witnesses([(index, merkle_path_after_proof)]),
        Err(SpendWitnessUpdateError::ProofAlreadyPresent)
    ));
    let tx = TransactionExtractor::new(proved)
        .extract(UnwrapErr(SysRng))
        .unwrap();
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
    let mut rng = UnwrapErr(SysRng);

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
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    let pczt = IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
        .finalize_io(UnwrapErr(SysRng))
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
            .create_ironwood_proof(UnwrapErr(SysRng), post_nu6_3_orchard_proving_key())
            .is_err()
    );

    let mut signer = Signer::new(redacted.clone()).unwrap();
    let sighash = signer.shielded_sighash();
    signer
        .sign_ironwood(UnwrapErr(SysRng), index, &orchard_ask)
        .unwrap();
    let signed = signer.finish();

    let signed = assert_external_orchard_signature_round_trip(
        redacted,
        &signed,
        orchard::ValuePool::Ironwood,
        index,
    );
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
        .create_ironwood_proof(UnwrapErr(SysRng), post_nu6_3_orchard_proving_key())
        .unwrap()
        .finish();
    assert!(matches!(
        Updater::new(proved.clone())
            .set_ironwood_spend_witnesses([(index, merkle_path_after_proof)]),
        Err(SpendWitnessUpdateError::ProofAlreadyPresent)
    ));
    let tx = TransactionExtractor::new(proved)
        .extract(UnwrapErr(SysRng))
        .unwrap();
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
    let mut rng = UnwrapErr(SysRng);

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
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    // Create the base PCZT, and finalize the I/O.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    check_v2_round_trip(&pczt);
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
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
            r.compact_resolvable_fields();
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
    assert!(
        redacted
            .ironwood()
            .actions()
            .iter()
            .all(|action| action.output().cmx().is_none())
    );
    assert!(redacted.ironwood().actions().iter().any(|action| {
        matches!(
            action.output().enc_ciphertext(),
            pczt::orchard::EncCiphertext::MemoPlaintext(_)
        )
    }));
    let transported = Pczt::parse(&redacted.clone().serialize().unwrap()).unwrap();
    let verified = Verifier::new(transported.clone())
        .with_ironwood::<std::convert::Infallible, _>(|_| {
            Ok::<(), pczt::roles::verifier::OrchardError<std::convert::Infallible>>(())
        })
        .unwrap()
        .finish();
    assert!(verified.ironwood().anchor().is_none());
    let updated = Updater::new(transported.clone())
        .update_ironwood_with(|_| Ok(()))
        .unwrap()
        .finish();
    assert!(updated.ironwood().anchor().is_none());

    let mut resolved = transported.clone();
    resolved.resolve_fields().unwrap();
    assert!(resolved.ironwood().anchor().is_none());
    assert_eq!(
        resolved.ironwood().actions()[index].cv_net(),
        pczt.ironwood().actions()[index].cv_net()
    );
    for (resolved, original) in resolved
        .ironwood()
        .actions()
        .iter()
        .zip(pczt.ironwood().actions())
    {
        assert_eq!(resolved.cv_net(), original.cv_net());
        assert_eq!(resolved.output().cmx(), original.output().cmx());
        assert_eq!(
            resolved.output().enc_ciphertext(),
            original.output().enc_ciphertext()
        );
    }
    let finalized = IoFinalizer::new(transported.clone())
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    assert!(finalized.ironwood().anchor().is_none());
    assert!(
        Prover::new(transported.clone())
            .create_ironwood_proof(UnwrapErr(SysRng), orchard_proving_key())
            .is_err()
    );
    assert_eq!(
        Signer::new(transported.clone()).unwrap().shielded_sighash(),
        sighash
    );

    let signed_redacted = low_level_signer::Signer::new(transported)
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

    let combined = Combiner::new(vec![pczt.clone(), signed_redacted])
        .combine()
        .unwrap();
    assert_eq!(combined.ironwood().anchor(), pczt.ironwood().anchor());
    for (combined, original) in combined
        .ironwood()
        .actions()
        .iter()
        .zip(pczt.ironwood().actions())
    {
        assert_eq!(combined.cv_net(), original.cv_net());
        assert_eq!(combined.output().cmx(), original.output().cmx());
        assert_eq!(
            combined.output().enc_ciphertext(),
            original.output().enc_ciphertext()
        );
    }
    assert_eq!(
        combined.ironwood().actions()[index]
            .spend()
            .spend_auth_sig()
            .expect("combined action carries the Signer's contribution"),
        expected_sig
    );

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

#[test]
fn builder_can_defer_anchors_until_proving() {
    let mut rng = UnwrapErr(SysRng);

    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(&orchard_sk);
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

    // Pretend we already received an Orchard note.
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
        note
    };

    // The REAL tree state, available only at "proving time": the builder below never sees
    // it, and neither does the signer.
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

    // Build the transaction with BOTH shielded anchors deferred to proving time (ZIP 374):
    // no anchor and no witness is supplied at build time.
    let mut builder = DeferredPcztBuilder::new::<zip317::FeeRule>(
        nu6_3_test_network(),
        10_000_000.into(),
        BundlePadding::DEFAULT,
        BundlePadding::DEFAULT,
    )
    .unwrap();
    builder
        .add_orchard_spend::<zip317::FeeRule>(orchard_fvk.clone(), note)
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
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();
    // The Creator strips the builder's internal placeholders: both anchors and the real
    // spend's witness are ABSENT. The fabricated dummy spends keep their (dummy) witnesses:
    // the prover needs a path for every spend, and any path is valid for a zero-valued
    // note.
    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    assert!(pczt.orchard().anchor().is_none());
    assert!(pczt.ironwood().anchor().is_none());
    let index = orchard_meta.spend_action_index(0).unwrap();
    for (i, action) in pczt.orchard().actions().iter().enumerate() {
        if i == index {
            assert!(action.spend().witness().is_none());
        } else {
            assert!(action.spend().witness().is_some());
        }
    }
    check_v2_round_trip(&pczt);

    // I/O finalization and signing need neither anchors nor witnesses under V6.
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();
    let mut signer = Signer::new(pczt).unwrap();
    let sighash = signer.shielded_sighash();
    signer
        .sign_orchard(UnwrapErr(SysRng), index, &orchard_ask)
        .unwrap();
    let signed = signer.finish();

    // Proving without the real anchor fails: the deferral cannot be silently ignored.
    assert!(
        Prover::new(signed.clone())
            .create_orchard_proof(UnwrapErr(SysRng), post_nu6_3_orchard_proving_key())
            .is_err()
    );

    // At proving time, install the real anchor and witness. The sighash is unchanged and
    // the pre-made signature still verifies, because V6 signatures commit to neither
    // shielded anchors nor witnesses.
    let updated = Updater::new(signed)
        .set_orchard_anchor(anchor)
        .unwrap()
        .set_orchard_spend_witnesses([(index, merkle_path)])
        .unwrap()
        .set_ironwood_anchor(orchard::Anchor::empty_tree())
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
        .create_orchard_proof(UnwrapErr(SysRng), post_nu6_3_orchard_proving_key())
        .unwrap()
        .create_ironwood_proof(UnwrapErr(SysRng), post_nu6_3_orchard_proving_key())
        .unwrap()
        .finish();
    check_v2_round_trip(&proved);

    let tx = TransactionExtractor::new(proved)
        .extract(UnwrapErr(SysRng))
        .unwrap();
    assert_eq!(u32::from(tx.expiry_height()), 10_000_040);
}

#[test]
fn deferred_anchors_require_v6() {
    // Under a pre-NU6.3 branch the transaction version (V5) commits its signatures to the
    // shielded anchors, so anchor deferral is refused at construction.
    assert!(matches!(
        DeferredPcztBuilder::new::<zip317::FeeRule>(
            pre_nu6_3_test_network(),
            10_000_000.into(),
            BundlePadding::DEFAULT,
            BundlePadding::DEFAULT,
        ),
        Err(zcash_primitives::transaction::builder::Error::AnchorDeferralUnsupported(_))
    ));
}

/// A complete v7 Sapling round trip: two spends, one signed through the Signer
/// and one applied externally, each verified against its own digest after
/// extraction.
#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_sapling_spends_use_per_index_sighashes() {
    use zcash_primitives::transaction::sighash::V7SignatureContext;

    let mut rng = UnwrapErr(SysRng);

    // A Sapling account whose first two addresses receive a note each.
    let sapling_extsk = sapling::zip32::ExtendedSpendingKey::master(&[1; 32])
        .expect("the derivation path yields a valid key")
        .derive_child(zip32::ChildIndex::hardened(32))
        .expect("the derivation path yields a valid key")
        .derive_child(zip32::ChildIndex::hardened(133))
        .expect("the derivation path yields a valid key")
        .derive_child(zip32::ChildIndex::hardened(0))
        .expect("the derivation path yields a valid key");
    let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
    let sapling_extsk_1 = sapling_extsk
        .derive_child(zip32::ChildIndex::hardened(0))
        .expect("the derivation path yields a valid key");
    let dfvk_1 = sapling_extsk_1.to_diversifiable_full_viewing_key();
    let (_, recipient_0) = sapling_dfvk.default_address();
    let in_0 = zip32::Scope::External;
    let (_, recipient_1) = dfvk_1.default_address();
    let in_1 = zip32::Scope::External;

    // Two spent notes in one tree.
    let mut tree =
        ShardTree::<_, 32, 16>::new(MemoryShardStore::<sapling::Node, u32>::empty(), 100);
    let mut notes = Vec::new();
    let mut note_fvks = Vec::new();
    for (dfvk, recipient) in [(&sapling_dfvk, recipient_0), (&dfvk_1, recipient_1)] {
        let note = {
            let mut sapling_builder = sapling::builder::Builder::new(
                sapling::note_encryption::Zip212Enforcement::On,
                sapling::builder::BundleType::DEFAULT,
                sapling::Anchor::empty_tree(),
            );
            sapling_builder
                .add_output(
                    None,
                    recipient,
                    sapling::value::NoteValue::from_raw(100_000),
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
                try_note_decryption(&domain, &dfvk.to_external_ivk().prepare(), output).unwrap();
            note
        };
        tree.append(
            sapling::Node::from_cmu(&note.cmu()),
            incrementalmerkletree::Retention::Marked,
        )
        .unwrap();
        notes.push(note);
        note_fvks.push(dfvk.fvk().clone());
    }
    tree.checkpoint(9_999_999).unwrap();
    let (anchor, merkle_paths) = {
        let paths = [0u64, 1].map(|position| {
            tree.witness_at_checkpoint_depth(position.into(), 0)
                .unwrap()
                .unwrap()
        });
        let anchor = paths[0].root(sapling::Node::from_cmu(&notes[0].cmu()));
        (anchor.into(), paths)
    };

    let mut builder = Builder::new(
        nu8_test_network(),
        BlockHeight::from_u32(1_000_000),
        BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .propose_version::<zip317::FeeRule>(zcash_primitives::transaction::TxVersion::V7)
        .unwrap();
    for ((note, fvk), merkle_path) in notes.iter().zip(&note_fvks).zip(merkle_paths) {
        builder
            .add_sapling_spend::<zip317::FeeRule>(fvk.clone(), note.clone(), merkle_path)
            .unwrap();
    }
    builder
        .add_sapling_output::<zip317::FeeRule>(
            Some(sapling_dfvk.to_ovk(in_0)),
            recipient_0,
            Zatoshis::const_from_u64(80_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_sapling_output::<zip317::FeeRule>(
            Some(dfvk_1.to_ovk(in_1)),
            recipient_1,
            Zatoshis::const_from_u64(110_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let PcztResult {
        pczt_parts,
        sapling_meta,
        ..
    } = builder
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();

    let pczt = Creator::build_from_parts(pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt)
        .finalize_io(UnwrapErr(SysRng))
        .unwrap();

    // The prover needs each spend's proof generation key.
    let indices = [
        sapling_meta.spend_index(0).unwrap(),
        sapling_meta.spend_index(1).unwrap(),
    ];
    let extsks = [&sapling_extsk, &sapling_extsk_1];
    let pczt = Updater::new(pczt)
        .update_sapling_with(|mut updater| {
            for (index, extsk) in indices.iter().zip(extsks) {
                updater.update_spend_with(*index, |mut spend| {
                    spend.set_proof_generation_key(extsk.expsk().proof_generation_key())
                })?;
            }
            Ok(())
        })
        .unwrap()
        .finish();

    let sapling_prover = LocalTxProver::bundled();
    let pczt = Prover::new(pczt)
        .create_sapling_proofs(UnwrapErr(SysRng), &sapling_prover, &sapling_prover)
        .unwrap()
        .finish();

    // Sign spend 0 through the Signer, and apply spend 1's signature from a
    // separate Signer over the same committed state.
    let mut signer = Signer::new(pczt.clone()).unwrap();
    let sighashes = [
        signer.sapling_sighash(indices[0]).unwrap(),
        signer.sapling_sighash(indices[1]).unwrap(),
    ];
    signer
        .sign_sapling(UnwrapErr(SysRng), indices[0], extsks[0].expsk().ask())
        .unwrap();
    let external_sig = {
        let mut other = Signer::new(pczt).unwrap();
        other
            .sign_sapling(UnwrapErr(SysRng), indices[1], extsks[1].expsk().ask())
            .unwrap();
        redjubjub::Signature::from(
            other.finish().sapling().spends()[indices[1]]
                .spend_auth_sig()
                .unwrap(),
        )
    };
    signer
        .apply_sapling_signature(indices[1], external_sig)
        .unwrap();
    let pczt = signer.finish();

    let tx_effects =
        PrecomputedSighashData::new_zip244(pczt.clone().into_effects().unwrap()).unwrap();

    let (spend_vk, output_vk) = sapling_prover.verifying_keys();
    let tx = TransactionExtractor::new(pczt)
        .with_sapling(&spend_vk, &output_vk)
        .extract(UnwrapErr(SysRng))
        .unwrap();

    let bundle = tx.sapling_bundle().unwrap();
    for (position, sighash) in sighashes.iter().enumerate() {
        let spend = &bundle.shielded_spends()[indices[position]];
        // Its own digest verifies, and its sibling's does not.
        assert!(spend.rk().verify(sighash, spend.spend_auth_sig()).is_ok());
        let sibling = &sighashes[1 - position];
        assert!(spend.rk().verify(sibling, spend.spend_auth_sig()).is_err());
    }

    // The binding signature verifies against the Sapling binding digest.
    let binding_sighash =
        tx_effects.signature_hash(&SignableInput::V7(V7SignatureContext::SaplingBinding));
    let bundle = tx.sapling_bundle().unwrap();
    let spends = bundle
        .shielded_spends()
        .iter()
        .map(|spend| spend.cv())
        .sum::<sapling::value::CommitmentSum>();
    let outputs = bundle
        .shielded_outputs()
        .iter()
        .map(|output| output.cv())
        .sum::<sapling::value::CommitmentSum>();
    let bvk = (spends - outputs).into_bvk(i64::from(*bundle.value_balance()));
    assert!(
        bvk.verify(
            binding_sighash.as_ref(),
            &bundle.authorization().binding_sig
        )
        .is_ok()
    );
}

/// A v7 PCZT's transparent and shielded digests both commit to the transparent
/// input's `scriptPubKey`, so changing that alone changes every one of them.
/// The input value, all output values, and the rest of the transaction are
/// identical between the two fixtures.
#[test]
#[cfg(zcash_unstable = "nu8")]
fn v7_transparent_and_shielded_sighashes_commit_to_the_whole_transaction() {
    let params = nu8_test_network();

    // Two transparent keys: only the input's key, and so its `scriptPubKey`,
    // differs between the fixtures. Outputs always pay the first one.
    let sk_a = secp256k1::SecretKey::from_secret_bytes([1; 32]).unwrap();
    let sk_b = secp256k1::SecretKey::from_secret_bytes([2; 32]).unwrap();
    let p2pkh_addr = TransparentAddress::from_pubkey(&sk_a.public_key());

    // A Sapling account with one note to spend.
    let sapling_extsk = sapling::zip32::ExtendedSpendingKey::master(&[1; 32])
        .expect("the derivation path yields a valid key")
        .derive_child(zip32::ChildIndex::hardened(32))
        .expect("the derivation path yields a valid key")
        .derive_child(zip32::ChildIndex::hardened(133))
        .expect("the derivation path yields a valid key")
        .derive_child(zip32::ChildIndex::hardened(0))
        .expect("the derivation path yields a valid key");
    let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
    let (_, sapling_recipient) = sapling_dfvk.default_address();

    let mut rng = UnwrapErr(SysRng);
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
                sapling::value::NoteValue::from_raw(100_000),
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
        let leaf = sapling::Node::from_cmu(&note.cmu());
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<sapling::Node, u32>::empty(), 100);
        tree.append(leaf, incrementalmerkletree::Retention::Marked)
            .unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let merkle_path = tree
            .witness_at_checkpoint_depth(0.into(), 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path)
    };

    // Both fixtures use identical, deterministic randomness so that every
    // Sapling effect, proof, and the transparent effects other than the input
    // `scriptPubKey` are identical between them.
    const FIXTURE_SEED: [u8; 32] = [0x42; 32];

    // Builds the whole pipeline for a given transparent spending key.
    let build = |sk: &secp256k1::SecretKey| {
        let mut rng = ChaCha20Rng::from_seed(FIXTURE_SEED);
        let pubkey = sk.public_key();
        let input_addr = TransparentAddress::from_pubkey(&pubkey);
        let coin = transparent::TxOut::new(
            Zatoshis::const_from_u64(1_000_000),
            input_addr.script().into(),
        );
        let mut builder = Builder::new(
            params,
            BlockHeight::from_u32(1_000_000),
            BuildConfig::Standard {
                sapling_anchor: Some(anchor),
                orchard_anchor: None,
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .propose_version::<zip317::FeeRule>(zcash_primitives::transaction::TxVersion::V7)
            .unwrap();
        builder
            .add_transparent_p2pkh_input(pubkey, transparent::OutPoint::fake(), coin)
            .unwrap();
        builder
            .add_sapling_spend::<zip317::FeeRule>(
                sapling_dfvk.fvk().clone(),
                note.clone(),
                merkle_path.clone(),
            )
            .unwrap();
        builder
            .add_sapling_output::<zip317::FeeRule>(
                Some(sapling_dfvk.to_ovk(zip32::Scope::External)),
                sapling_recipient,
                Zatoshis::const_from_u64(500_000),
                MemoBytes::empty(),
            )
            .unwrap();
        builder
            .add_transparent_output(&p2pkh_addr, Zatoshis::const_from_u64(585_000))
            .unwrap();
        let PcztResult {
            pczt_parts,
            sapling_meta,
            ..
        } = builder
            .build_for_pczt(&mut rng, &zip317::FeeRule::standard())
            .unwrap();
        let spend_index = sapling_meta.spend_index(0).unwrap();

        let pczt = Creator::build_from_parts(pczt_parts).unwrap();
        let pczt = IoFinalizer::new(pczt).finalize_io(&mut rng).unwrap();
        let pczt = Updater::new(pczt)
            .update_sapling_with(|mut updater| {
                updater.update_spend_with(spend_index, |mut spend| {
                    spend.set_proof_generation_key(sapling_extsk.expsk().proof_generation_key())
                })?;
                Ok(())
            })
            .unwrap()
            .finish();
        let prover = LocalTxProver::bundled();
        let pczt = Prover::new(pczt)
            .create_sapling_proofs(&mut rng, &prover, &prover)
            .unwrap()
            .finish();

        let unsigned = pczt.clone();
        let mut signer = Signer::new(pczt).unwrap();
        let transparent_sighash = signer.transparent_sighash(0).unwrap();
        let sapling_sighash = signer.sapling_sighash(spend_index).unwrap();
        signer.sign_transparent(0, sk).unwrap();
        signer
            .sign_sapling(&mut rng, spend_index, sapling_extsk.expsk().ask())
            .unwrap();
        let (spend_vk, output_vk) = prover.verifying_keys();
        let pczt = SpendFinalizer::new(signer.finish())
            .finalize_spends()
            .unwrap();
        let tx = TransactionExtractor::new(pczt)
            .with_sapling(&spend_vk, &output_vk)
            .extract(&mut rng)
            .unwrap();

        (
            unsigned,
            tx,
            transparent_sighash,
            sapling_sighash,
            spend_index,
        )
    };

    let (pczt_a, tx, transparent_sighash, sapling_sighash, spend_index) = build(&sk_a);
    let (pczt_b, other_tx, other_transparent_sighash, other_sapling_sighash, _) = build(&sk_b);

    // Everything except the input `scriptPubKey` is identical, so the digest
    // differences below cannot come from fresh randomness.
    assert_eq!(pczt_a.sapling(), pczt_b.sapling());
    assert_eq!(pczt_a.ironwood(), pczt_b.ironwood());
    assert_eq!(pczt_a.orchard(), pczt_b.orchard());

    assert_eq!(
        pczt_a.transparent().outputs(),
        pczt_b.transparent().outputs()
    );
    assert_eq!(pczt_a.transparent().inputs().len(), 1);
    assert_eq!(pczt_b.transparent().inputs().len(), 1);
    let input_a = &pczt_a.transparent().inputs()[0];
    let input_b = &pczt_b.transparent().inputs()[0];
    assert_eq!(input_a.value(), input_b.value());
    assert_eq!(input_a.prevout_txid(), input_b.prevout_txid());
    assert_eq!(input_a.prevout_index(), input_b.prevout_index());
    assert_eq!(input_a.sequence(), input_b.sequence());

    assert_ne!(input_a.script_pubkey(), input_b.script_pubkey());

    // The extracted effecting data agrees everywhere but the input script.
    let tx_bundle = tx.transparent_bundle().unwrap();
    let other_tx_bundle = other_tx.transparent_bundle().unwrap();
    assert_eq!(tx_bundle.vout, other_tx_bundle.vout);
    assert_eq!(tx_bundle.vin[0].prevout(), other_tx_bundle.vin[0].prevout());
    assert_ne!(
        tx_bundle.vin[0].script_sig().0.to_bytes(),
        other_tx_bundle.vin[0].script_sig().0.to_bytes()
    );

    // Every per-input digest changed with the input `scriptPubKey`.
    assert_ne!(transparent_sighash, other_transparent_sighash);
    assert_ne!(sapling_sighash, other_sapling_sighash);

    let bundle = tx.transparent_bundle().unwrap();
    let txin = &bundle.vin[0];
    let script_sig = txin.script_sig().0.to_bytes();
    let (sig_bytes, pubkey_bytes) = {
        // `push(sig) push(pubkey)`.
        let (len, rest) = (script_sig[0] as usize, &script_sig[1..]);
        let sig = &rest[..len];
        let (len, rest) = (rest[len] as usize, &rest[len + 1..]);
        (sig, &rest[..len])
    };
    let signature = secp256k1::ecdsa::Signature::from_der(&sig_bytes[..sig_bytes.len() - 1])
        .expect("the extracted signature is DER");
    let pubkey = secp256k1::PublicKey::from_slice(pubkey_bytes).unwrap();
    assert!(
        signature
            .verify(
                secp256k1::Message::from_digest(transparent_sighash),
                &pubkey
            )
            .is_ok()
    );
    assert!(
        signature
            .verify(
                secp256k1::Message::from_digest(other_transparent_sighash),
                &pubkey
            )
            .is_err()
    );

    let sapling_bundle = tx.sapling_bundle().unwrap();
    let spend = &sapling_bundle.shielded_spends()[spend_index];
    assert!(
        spend
            .rk()
            .verify(&sapling_sighash, spend.spend_auth_sig())
            .is_ok()
    );
    assert!(
        spend
            .rk()
            .verify(&other_sapling_sighash, spend.spend_auth_sig())
            .is_err()
    );
}
