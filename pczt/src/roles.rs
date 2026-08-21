//! Implementations of the PCZT roles.
//!
//! The roles currently without an implementation are:
//! - Constructor (anyone can contribute)
//!   - Adds spends and outputs to the PCZT.
//!   - Before any input or output may be added, the constructor must check the
//!     `Global.tx_modifiable` field. Inputs may only be added if the Inputs Modifiable
//!     flag is True. Outputs may only be added if the Outputs Modifiable flag is True.
//!   - A single entity is likely to be both a Creator and Constructor.

pub mod creator;

#[cfg(feature = "io-finalizer")]
pub mod io_finalizer;

pub mod verifier;

pub mod updater;

pub mod redactor;

#[cfg(feature = "prover")]
pub mod prover;

#[cfg(feature = "signer")]
pub mod signer;

pub mod low_level_signer;

pub mod combiner;

#[cfg(feature = "spend-finalizer")]
pub mod spend_finalizer;

#[cfg(feature = "tx-extractor")]
pub mod tx_extractor;

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "io-finalizer", feature = "tx-extractor"))]
    use {crate::roles::creator::Creator, zcash_protocol::consensus::BranchId};

    #[cfg(feature = "io-finalizer")]
    use crate::roles::io_finalizer::{self, IoFinalizer};

    #[cfg(feature = "tx-extractor")]
    use crate::roles::tx_extractor::{self, TransactionExtractor};

    #[cfg(feature = "tx-extractor")]
    #[test]
    fn extract_fails_on_empty() {
        let pczt = Creator::new(
            BranchId::Nu6.into(),
            10_000_000,
            133,
            Some([0; 32]),
            Some([0; 32]),
        )
        .unwrap()
        .build()
        .unwrap();

        // Extraction fails because we haven't run the IO Finalizer.
        // Extraction fails in Sapling because we happen to extract it before Orchard.
        assert!(matches!(
            TransactionExtractor::new(pczt).extract().unwrap_err(),
            tx_extractor::Error::Sapling(tx_extractor::SaplingError::Extract(
                sapling::pczt::TxExtractorError::MissingBindingSignatureSigningKey
            )),
        ));
    }

    #[cfg(feature = "io-finalizer")]
    #[test]
    fn io_finalizer_fails_on_empty() {
        let pczt = Creator::new(
            BranchId::Nu6.into(),
            10_000_000,
            133,
            Some([0; 32]),
            Some([0; 32]),
        )
        .unwrap()
        .build()
        .unwrap();

        // IO finalization fails on spends because we happen to check them first.
        assert!(matches!(
            IoFinalizer::new(pczt).finalize_io().unwrap_err(),
            io_finalizer::Error::NoSpends,
        ));
    }

    /// Tests that a hostile Creator, Updater, or Combiner cannot induce the Signer or the
    /// Spend Finalizer into producing a spend authorization over data that the coin being
    /// spent does not commit to.
    ///
    /// These use a transparent-only PCZT so that the IO Finalizer does no shielded work
    /// and no proving keys are needed.
    #[cfg(all(
        feature = "io-finalizer",
        feature = "signer",
        feature = "spend-finalizer",
        feature = "zcp-builder"
    ))]
    mod transparent_authentication {
        use alloc::vec::Vec;

        use ::transparent::{
            address::TransparentAddress,
            bundle::{OutPoint, TxOut},
            pczt::{SignerError, SpendFinalizerError, VerifyError},
            sighash::{
                SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE, SighashPolicy,
            },
        };
        use rand_core::OsRng;
        use zcash_primitives::transaction::{
            builder::{BuildConfig, Builder, BundlePadding, PcztResult},
            fees::zip317,
        };
        use zcash_protocol::{consensus::MainNetwork, value::Zatoshis};

        use crate::{
            Pczt,
            common::{
                FLAG_HAS_SIGHASH_SINGLE, FLAG_TRANSPARENT_INPUTS_MODIFIABLE,
                FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE,
            },
            roles::{
                creator::Creator, io_finalizer::IoFinalizer, signer, signer::Signer,
                spend_finalizer, spend_finalizer::SpendFinalizer,
            },
        };

        const SIGHASH_ALL_ANYONECANPAY: u8 = SIGHASH_ALL | SIGHASH_ANYONECANPAY;

        fn secret_key() -> secp256k1::SecretKey {
            secp256k1::SecretKey::from_slice(&[1; 32]).expect("valid")
        }

        fn public_key(sk: &secp256k1::SecretKey) -> secp256k1::PublicKey {
            sk.public_key(&secp256k1::Secp256k1::signing_only())
        }

        /// The coin the victim is being asked to spend.
        fn victim_coin() -> (OutPoint, TxOut) {
            let addr = TransparentAddress::from_pubkey(&public_key(&secret_key()));
            (
                OutPoint::new([1; 32], 1),
                TxOut::new(Zatoshis::const_from_u64(1_000_000), addr.script().into()),
            )
        }

        fn builder() -> Builder<MainNetwork, ()> {
            Builder::new(
                MainNetwork,
                10_000_000.into(),
                BuildConfig::Standard {
                    sapling_anchor: None,
                    orchard_anchor: None,
                    ironwood_anchor: None,
                    orchard_padding: BundlePadding::DEFAULT,
                    ironwood_padding: BundlePadding::DEFAULT,
                },
            )
        }

        fn finalize(builder: Builder<MainNetwork, ()>) -> Pczt {
            let PcztResult { pczt_parts, .. } = builder
                .build_for_pczt(OsRng, &zip317::FeeRule::standard())
                .unwrap();

            IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
                .finalize_io()
                .unwrap()
        }

        /// A PCZT spending a single P2PKH coin back to the victim's own address: the
        /// transaction the victim believes it is authorizing.
        fn transparent_pczt() -> Pczt {
            let pubkey = public_key(&secret_key());
            let addr = TransparentAddress::from_pubkey(&pubkey);
            let (utxo, coin) = victim_coin();

            let mut builder = builder();
            builder
                .add_transparent_p2pkh_input(pubkey, utxo, coin)
                .unwrap();
            builder
                .add_transparent_output(&addr, Zatoshis::const_from_u64(990_000))
                .unwrap();
            finalize(builder)
        }

        /// A PCZT whose single input has been tampered with by a hostile counterparty.
        fn tampered_pczt(f: impl FnOnce(&mut crate::transparent::Input)) -> Pczt {
            let mut pczt = transparent_pczt();
            f(&mut pczt.transparent.inputs[0]);
            pczt
        }

        /// A Signer over a PCZT tampered with by `f`, under `sighash_policy`.
        fn signer(
            f: impl FnOnce(&mut crate::transparent::Input),
            sighash_policy: SighashPolicy,
        ) -> Signer {
            Signer::new(tampered_pczt(f))
                .unwrap()
                .with_transparent_sighash_policy(sighash_policy)
        }

        /// The sighash for the single input of `pczt`, computed under a policy wide
        /// enough to admit whatever sighash type it carries.
        fn unguarded_sighash(pczt: Pczt) -> [u8; 32] {
            Signer::new(pczt)
                .unwrap()
                .with_transparent_sighash_policy(SighashPolicy::ANY)
                .transparent_sighash(0)
                .unwrap()
        }

        /// Signs `sighash` externally — as the counterparty who chose the input's
        /// sighash type would — and offers the signature to a Signer with the default
        /// policy.
        fn append(pczt: Pczt, sighash: [u8; 32]) -> Result<(), signer::Error> {
            let sig = secp256k1::Secp256k1::new()
                .sign_ecdsa(&secp256k1::Message::from_digest(sighash), &secret_key());
            Signer::new(pczt)
                .unwrap()
                .append_transparent_signature(0, sig)
        }

        #[test]
        fn signer_rejects_unauthenticated_redeem_script() {
            // The coin being spent is P2PKH, so it commits to no redeem script at all;
            // `Input::sign` would otherwise search this one for the signer’s pubkey and
            // commit to it in the sighash.
            let mut signer = signer(
                |input| input.redeem_script = Some(vec![0x51]),
                SighashPolicy::ALL_ONLY,
            );

            assert!(matches!(
                signer.sign_transparent(0, &secret_key()),
                Err(signer::Error::TransparentSign(SignerError::InvalidInput(
                    VerifyError::NotP2sh
                ))),
            ));
        }

        /// The external-signature path has to authenticate the input for the same reason.
        #[test]
        fn signer_rejects_unauthenticated_redeem_script_when_appending() {
            // The input is refused before the signature is examined, so what was signed
            // does not matter — and the Signer will not compute a sighash over this input
            // for us to sign in the first place.
            assert!(matches!(
                append(
                    tampered_pczt(|input| input.redeem_script = Some(vec![0x51])),
                    [0; 32],
                ),
                Err(signer::Error::TransparentSign(SignerError::InvalidInput(
                    VerifyError::NotP2sh
                ))),
            ));
        }

        /// The same holds for the sighash the Signer hands to an external signer: whoever
        /// signs it is authorizing whatever it commits to.
        #[test]
        fn signer_rejects_unauthenticated_redeem_script_when_computing_sighash() {
            let signer = signer(
                |input| input.redeem_script = Some(vec![0x51]),
                SighashPolicy::ALL_ONLY,
            );

            assert!(matches!(
                signer.transparent_sighash(0),
                Err(signer::Error::TransparentSign(SignerError::InvalidInput(
                    VerifyError::NotP2sh
                ))),
            ));
        }

        #[test]
        fn signer_rejects_hostile_sighash_type() {
            let mut signer = signer(
                |input| input.sighash_type = SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                SighashPolicy::ALL_ONLY,
            );

            assert!(matches!(
                signer.sign_transparent(0, &secret_key()),
                Err(signer::Error::TransparentSign(
                    SignerError::DisallowedSighashType(_)
                )),
            ));
        }

        #[test]
        fn signer_rejects_hostile_sighash_type_when_appending() {
            let pczt =
                tampered_pczt(|input| input.sighash_type = SIGHASH_NONE | SIGHASH_ANYONECANPAY);
            let sighash = unguarded_sighash(pczt.clone());

            assert!(matches!(
                append(pczt, sighash),
                Err(signer::Error::TransparentSign(
                    SignerError::DisallowedSighashType(_)
                )),
            ));
        }

        #[test]
        fn signer_rejects_hostile_sighash_type_when_computing_sighash() {
            let signer = signer(
                |input| input.sighash_type = SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                SighashPolicy::ALL_ONLY,
            );

            assert!(matches!(
                signer.transparent_sighash(0),
                Err(signer::Error::TransparentSign(
                    SignerError::DisallowedSighashType(_)
                )),
            ));
        }

        #[test]
        fn signer_accepts_hostile_sighash_type_under_explicit_policy() {
            let mut signer = signer(
                |input| input.sighash_type = SIGHASH_NONE | SIGHASH_ANYONECANPAY,
                SighashPolicy::ANY,
            );

            assert!(signer.sign_transparent(0, &secret_key()).is_ok());
        }

        /// Signs the single input of a PCZT tampered with by `f`, under `sighash_policy`.
        fn signed(
            f: impl FnOnce(&mut crate::transparent::Input),
            sighash_policy: SighashPolicy,
        ) -> Pczt {
            let mut signer = signer(f, sighash_policy);
            signer.sign_transparent(0, &secret_key()).unwrap();
            signer.finish()
        }

        /// A signed PCZT whose `SIGHASH_NONE` input is consistent with
        /// `Global.tx_modifiable`, so that the sighash policy is the only thing left to
        /// gate on.
        ///
        /// The flag has to be restored by hand: the in-tree builder only ever uses
        /// `SIGHASH_ALL`, so the Creator clears both transparent modifiability flags at
        /// the outset, whereas a genuine `SIGHASH_NONE` flow would leave the outputs one
        /// set.
        fn signed_sighash_none() -> Pczt {
            let mut pczt = signed(
                |input| input.sighash_type = SIGHASH_NONE,
                SighashPolicy::ANY,
            );
            pczt.global.tx_modifiable |= FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE;
            pczt
        }

        #[test]
        fn finalizer_rejects_non_all_sighash_type() {
            assert!(matches!(
                SpendFinalizer::new(signed_sighash_none()).finalize_spends(),
                Err(spend_finalizer::Error::TransparentFinalize(
                    SpendFinalizerError::DisallowedSighashType(_)
                )),
            ));
        }

        #[test]
        fn finalizer_accepts_non_all_sighash_type_under_explicit_policy() {
            assert!(
                SpendFinalizer::new(signed_sighash_none())
                    .with_sighash_policy(SighashPolicy::ANY)
                    .finalize_spends()
                    .is_ok()
            );
        }

        #[test]
        fn finalizer_rejects_sighash_type_inconsistent_with_modifiability() {
            for (sighash_type, flag) in [
                (SIGHASH_NONE, FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE),
                (SIGHASH_ALL_ANYONECANPAY, FLAG_TRANSPARENT_INPUTS_MODIFIABLE),
                (SIGHASH_SINGLE, FLAG_HAS_SIGHASH_SINGLE),
            ] {
                let mut pczt = signed(
                    |input| input.sighash_type = sighash_type,
                    SighashPolicy::ANY,
                );

                // The flag recording the part of the transaction that this signature
                // leaves uncommitted is not set, so the sighash type did not come from a
                // deliberate multi-party flow. Not even an explicit policy allows this.
                pczt.global.tx_modifiable &= !flag;

                assert!(
                    matches!(
                        SpendFinalizer::new(pczt)
                            .with_sighash_policy(SighashPolicy::ANY)
                            .finalize_spends(),
                        Err(spend_finalizer::Error::InconsistentSighashType { index: 0, .. }),
                    ),
                    "expected sighash type {sighash_type:#04x} to be refused",
                );
            }
        }

        /// The `Global.tx_modifiable` gate is not an alternative to the sighash policy.
        /// The flags are PCZT data, so a hostile Creator sets them as freely as it sets
        /// `sighash_type`, and can always make the two agree.
        ///
        /// What the gate catches is a PCZT whose flags and sighash types *disagree* —
        /// see `finalizer_rejects_sighash_type_inconsistent_with_modifiability`. Refusing
        /// a signature that does not commit to the whole transaction is the policy's job,
        /// which is why neither stands in for the other.
        #[test]
        fn modifiability_flags_are_not_a_substitute_for_the_policy() {
            let mut pczt =
                tampered_pczt(|input| input.sighash_type = SIGHASH_NONE | SIGHASH_ANYONECANPAY);

            // Exactly the flags that such a signature requires. The Signer will leave
            // both set, because a `SIGHASH_NONE | SIGHASH_ANYONECANPAY` signature clears
            // neither: it commits to no other input and to none of the outputs.
            pczt.global.tx_modifiable |=
                FLAG_TRANSPARENT_INPUTS_MODIFIABLE | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE;

            // `SighashPolicy::ANY` throughout models what this library would do if the
            // policy did not exist.
            let mut signer = Signer::new(pczt)
                .unwrap()
                .with_transparent_sighash_policy(SighashPolicy::ANY);
            signer.sign_transparent(0, &secret_key()).unwrap();

            assert!(
                SpendFinalizer::new(signer.finish())
                    .with_sighash_policy(SighashPolicy::ANY)
                    .finalize_spends()
                    .is_ok(),
                "the gate cannot object: the hostile PCZT is internally consistent",
            );
        }

        #[test]
        fn finalizer_accepts_all_sighash_type() {
            let pczt = signed(|_| (), SighashPolicy::ALL_ONLY);
            assert!(SpendFinalizer::new(pczt).finalize_spends().is_ok());
        }

        /// The attacker's own coin, which they contribute to their own transaction.
        fn attacker_coin() -> (secp256k1::PublicKey, OutPoint, TxOut) {
            let pubkey = public_key(&secp256k1::SecretKey::from_slice(&[2; 32]).expect("valid"));
            let addr = TransparentAddress::from_pubkey(&pubkey);
            (
                pubkey,
                OutPoint::new([2; 32], 0),
                TxOut::new(Zatoshis::const_from_u64(1_000_000), addr.script().into()),
            )
        }

        /// A PCZT for a *different* transaction, which the victim never sees: it spends
        /// the same coin of theirs alongside one of the attacker's, and pays the whole
        /// balance to the attacker.
        fn attacker_pczt(sighash_type: u8) -> Pczt {
            let (attacker_pubkey, attacker_utxo, attacker_coin) = attacker_coin();
            let attacker_addr = TransparentAddress::from_pubkey(&attacker_pubkey);
            let (victim_utxo, victim_coin) = victim_coin();

            let mut builder = builder();
            builder
                .add_transparent_p2pkh_input(public_key(&secret_key()), victim_utxo, victim_coin)
                .unwrap();
            builder
                .add_transparent_p2pkh_input(attacker_pubkey, attacker_utxo, attacker_coin)
                .unwrap();
            builder
                .add_transparent_output(&attacker_addr, Zatoshis::const_from_u64(1_990_000))
                .unwrap();

            let mut pczt = finalize(builder);
            pczt.transparent.inputs[0].sighash_type = sighash_type;
            pczt
        }

        /// The victim's signature over the single input of the transaction they were
        /// shown, with the trailing sighash byte stripped.
        fn victim_signature(sighash_type: u8, sighash_policy: SighashPolicy) -> Vec<u8> {
            let pczt = signed(|input| input.sighash_type = sighash_type, sighash_policy);
            let mut sig = pczt.transparent.inputs[0]
                .partial_signatures
                .get(&public_key(&secret_key()).serialize())
                .expect("the victim signed")
                .clone();
            assert_eq!(
                sig.pop(),
                Some(sighash_type),
                "signature carries its sighash type"
            );
            sig
        }

        /// Whether `sig` authorizes the victim's input of `pczt`.
        fn authorizes(sig: &[u8], pczt: Pczt) -> bool {
            let sighash = unguarded_sighash(pczt);

            secp256k1::Secp256k1::new()
                .verify_ecdsa(
                    &secp256k1::Message::from_digest(sighash),
                    &secp256k1::ecdsa::Signature::from_der(sig).expect("DER-encoded"),
                    &public_key(&secret_key()),
                )
                .is_ok()
        }

        /// Why `SighashPolicy::ALL_ONLY` is the default: a signature the victim was
        /// induced to make under `SIGHASH_NONE | SIGHASH_ANYONECANPAY` commits to
        /// neither the outputs nor the other inputs, so it is equally a valid
        /// authorization of a transaction the victim never saw, which pays the attacker.
        ///
        /// The Signer refuses to produce this signature at all unless the caller opts in,
        /// which is what `signer_rejects_hostile_sighash_type` covers; this test is what
        /// makes that refusal worth having.
        #[test]
        fn a_non_all_signature_authorizes_the_attackers_transaction() {
            let hostile = SIGHASH_NONE | SIGHASH_ANYONECANPAY;
            let sig = victim_signature(hostile, SighashPolicy::ANY);

            assert!(
                authorizes(&sig, tampered_pczt(|input| input.sighash_type = hostile)),
                "the victim's signature should authorize the transaction they were shown",
            );
            assert!(
                authorizes(&sig, attacker_pczt(hostile)),
                "and, because it commits to neither the outputs nor the other inputs, \
                 the attacker's transaction as well",
            );
        }

        /// The contrast: a `SIGHASH_ALL` signature over the same input commits to the
        /// whole transaction the victim was shown, so it authorizes nothing else.
        #[test]
        fn an_all_signature_authorizes_nothing_else() {
            let sig = victim_signature(SIGHASH_ALL, SighashPolicy::ALL_ONLY);

            // Establishes that the negative below is a real refusal rather than, say, a
            // signature that fails to verify against anything at all.
            assert!(
                authorizes(&sig, transparent_pczt()),
                "the victim's signature should authorize the transaction they were shown",
            );
            assert!(
                !authorizes(&sig, attacker_pczt(SIGHASH_ALL)),
                "but not the attacker's",
            );
        }

        /// Guards against the modifiability gate rejecting a `SIGHASH_SINGLE` signature
        /// that the Signer correctly recorded.
        #[test]
        fn finalizer_accepts_recorded_sighash_single() {
            let pczt = signed(
                |input| input.sighash_type = SIGHASH_SINGLE,
                SighashPolicy::ANY,
            );

            assert!(
                SpendFinalizer::new(pczt)
                    .with_sighash_policy(SighashPolicy::ANY)
                    .finalize_spends()
                    .is_ok()
            );
        }
    }
}
