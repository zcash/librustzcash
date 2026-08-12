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
    #[cfg(feature = "tx-extractor")]
    #[test]
    fn extract_fails_on_empty() {
        use zcash_protocol::consensus::BranchId;

        use crate::roles::{
            creator::Creator,
            tx_extractor::{self, TransactionExtractor},
        };

        let pczt = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32]).build();

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
        use zcash_protocol::consensus::BranchId;

        use crate::roles::{
            creator::Creator,
            io_finalizer::{self, IoFinalizer},
        };

        let pczt = Creator::new(BranchId::Nu6.into(), 10_000_000, 133, [0; 32], [0; 32]).build();

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
        use ::transparent::{
            address::TransparentAddress,
            bundle::{OutPoint, TxOut},
            pczt::{SignerError, SpendFinalizerError, VerifyError},
            sighash::{SighashPolicy, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE},
        };
        use rand_core::OsRng;
        use zcash_primitives::transaction::{
            builder::{BuildConfig, Builder, PcztResult},
            fees::zip317,
        };
        use zcash_protocol::{consensus::MainNetwork, value::Zatoshis};

        use crate::{
            common::{
                FLAG_HAS_SIGHASH_SINGLE, FLAG_TRANSPARENT_INPUTS_MODIFIABLE,
                FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE,
            },
            roles::{
                creator::Creator, io_finalizer::IoFinalizer, signer, signer::Signer,
                spend_finalizer, spend_finalizer::SpendFinalizer,
            },
            Pczt,
        };

        const SIGHASH_ALL_ANYONECANPAY: u8 =
            ::transparent::sighash::SIGHASH_ALL | SIGHASH_ANYONECANPAY;

        fn secret_key() -> secp256k1::SecretKey {
            secp256k1::SecretKey::from_slice(&[1; 32]).expect("valid")
        }

        /// A PCZT spending a single P2PKH coin to a transparent address.
        fn transparent_pczt() -> Pczt {
            let sk = secret_key();
            let pubkey = sk.public_key(&secp256k1::Secp256k1::signing_only());
            let addr = TransparentAddress::from_pubkey(&pubkey);

            let coin = TxOut::new(Zatoshis::const_from_u64(1_000_000), addr.script().into());

            let mut builder = Builder::new(
                MainNetwork,
                10_000_000.into(),
                BuildConfig::Standard {
                    sapling_anchor: None,
                    orchard_anchor: None,
                },
            );
            builder
                .add_transparent_input(pubkey, OutPoint::new([1; 32], 1), coin)
                .unwrap();
            builder
                .add_transparent_output(&addr, Zatoshis::const_from_u64(990_000))
                .unwrap();
            let PcztResult { pczt_parts, .. } = builder
                .build_for_pczt(OsRng, &zip317::FeeRule::standard())
                .unwrap();

            IoFinalizer::new(Creator::build_from_parts(pczt_parts).unwrap())
                .finalize_io()
                .unwrap()
        }

        /// A PCZT whose single input has been tampered with by a hostile counterparty.
        fn tampered_pczt(f: impl FnOnce(&mut crate::transparent::Input)) -> Pczt {
            let mut pczt = transparent_pczt();
            f(&mut pczt.transparent.inputs[0]);
            pczt
        }

        #[test]
        fn signer_rejects_unauthenticated_redeem_script() {
            // The coin being spent is P2PKH, so it commits to no redeem script at all;
            // `Input::sign` would otherwise search this one for the signer’s pubkey and
            // commit to it in the sighash.
            let pczt = tampered_pczt(|input| input.redeem_script = Some(vec![0x51]));

            assert!(matches!(
                Signer::new(pczt)
                    .unwrap()
                    .sign_transparent(0, &secret_key()),
                Err(signer::Error::TransparentSign(SignerError::InvalidInput(
                    VerifyError::NotP2sh
                ))),
            ));
        }

        #[test]
        fn signer_rejects_hostile_sighash_type() {
            let pczt = tampered_pczt(|input| {
                input.sighash_type = SIGHASH_NONE | SIGHASH_ANYONECANPAY;
            });

            assert!(matches!(
                Signer::new(pczt)
                    .unwrap()
                    .sign_transparent(0, &secret_key()),
                Err(signer::Error::TransparentSign(
                    SignerError::DisallowedSighashType(_)
                )),
            ));
        }

        #[test]
        fn signer_accepts_hostile_sighash_type_under_explicit_policy() {
            let pczt = tampered_pczt(|input| {
                input.sighash_type = SIGHASH_NONE | SIGHASH_ANYONECANPAY;
            });

            assert!(Signer::new(pczt)
                .unwrap()
                .with_transparent_sighash_policy(SighashPolicy::ANY)
                .sign_transparent(0, &secret_key())
                .is_ok());
        }

        /// Signs the single input of a PCZT tampered with by `f`, under `sighash_policy`.
        fn signed(
            f: impl FnOnce(&mut crate::transparent::Input),
            sighash_policy: SighashPolicy,
        ) -> Pczt {
            let mut signer = Signer::new(tampered_pczt(f))
                .unwrap()
                .with_transparent_sighash_policy(sighash_policy);
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
            assert!(SpendFinalizer::new(signed_sighash_none())
                .with_sighash_policy(SighashPolicy::ANY)
                .finalize_spends()
                .is_ok());
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

        #[test]
        fn finalizer_accepts_all_sighash_type() {
            let pczt = signed(|_| (), SighashPolicy::ALL_ONLY);
            assert!(SpendFinalizer::new(pczt).finalize_spends().is_ok());
        }

        /// Guards against the modifiability gate rejecting a `SIGHASH_SINGLE` signature
        /// that the Signer correctly recorded.
        #[test]
        fn finalizer_accepts_recorded_sighash_single() {
            let pczt = signed(
                |input| input.sighash_type = SIGHASH_SINGLE,
                SighashPolicy::ANY,
            );

            assert!(SpendFinalizer::new(pczt)
                .with_sighash_policy(SighashPolicy::ANY)
                .finalize_spends()
                .is_ok());
        }
    }
}
