//! The Spend Finalizer role (anyone can execute).
//!
//! - Combines partial transparent signatures into `script_sig`s.

use ::transparent::sighash::SighashPolicy;

use crate::Pczt;

pub struct SpendFinalizer {
    pczt: Pczt,
    sighash_policy: SighashPolicy,
}

impl SpendFinalizer {
    /// Instantiates the Spend Finalizer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self {
            pczt,
            sighash_policy: SighashPolicy::ALL_ONLY,
        }
    }

    /// Sets the sighash policy that this Spend Finalizer applies to partial signatures.
    ///
    /// The default is [`SighashPolicy::ALL_ONLY`]; see [`SighashPolicy`] for why.
    ///
    /// Version 7 variant 0 signatures support only `SIGHASH_ALL`. A policy that permits
    /// it is therefore applied as [`SighashPolicy::ALL_ONLY`]; a policy that does not is
    /// applied as [`SighashPolicy::EMPTY`], under which every input is refused.
    ///
    /// This policy governs which signatures are assembled into `script_sig`s; it does not
    /// protect whoever produced them. A partial signature that does not commit to the
    /// whole transaction can be lifted out of the PCZT and used directly, without this
    /// role ever running, so the decision that protects a signer is the Signer's own
    /// [`Signer::with_transparent_sighash_policy`].
    ///
    /// [`Signer::with_transparent_sighash_policy`]: crate::roles::signer::Signer::with_transparent_sighash_policy
    pub fn with_sighash_policy(mut self, sighash_policy: SighashPolicy) -> Self {
        self.sighash_policy = sighash_policy;
        self
    }

    /// Finalizes the spends of the PCZT.
    ///
    /// Version 7 variant 0 transparent signatures support only `SIGHASH_ALL`. A policy
    /// that permits it is applied as [`SighashPolicy::ALL_ONLY`]; one that does not is
    /// applied as [`SighashPolicy::EMPTY`], so every input is refused.
    pub fn finalize_spends(self) -> Result<Pczt, Error> {
        let Self {
            pczt,
            sighash_policy,
        } = self;

        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = pczt;

        // version 7 signs only `SIGHASH_ALL`.
        let sighash_policy = if crate::is_v7_version(global.tx_version) {
            crate::roles::v7_sighash_policy(sighash_policy)
        } else {
            sighash_policy
        };

        let mut transparent = transparent.into_parsed().map_err(Error::TransparentParse)?;

        transparent
            .finalize_spends_with_sighash_policy(sighash_policy)
            .map_err(Error::TransparentFinalize)?;

        Ok(Pczt {
            global,
            transparent: crate::transparent::Bundle::serialize_from(transparent),
            sapling,
            orchard,
            ironwood,
        })
    }
}

/// Errors that can occur while finalizing the spends of a PCZT.
#[derive(Debug)]
pub enum Error {
    TransparentFinalize(transparent::pczt::SpendFinalizerError),
    TransparentParse(transparent::pczt::ParseError),
}

/// Version 7 variant 0 transparent signatures support only `SIGHASH_ALL`, so the Spend
/// Finalizer refuses every other sighash type, and refuses everything under a policy that
/// does not permit `SIGHASH_ALL`.
#[cfg(all(test, zcash_unstable = "nu8"))]
mod v7_policy_tests {
    use alloc::{collections::BTreeMap, vec};

    use ::transparent::sighash::{SighashPolicy, SighashType};
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    use zcash_protocol::consensus::BranchId;

    use super::{Error, SpendFinalizer};
    use crate::{Pczt, roles::creator::Creator, transparent};

    /// A version 7 PCZT with one signed P2PKH input whose sighash type is `sighash_type`.
    fn pczt_with_input(sighash_type: SighashType) -> Pczt {
        let sk = secp256k1::SecretKey::from_secret_bytes([1; 32]).unwrap();
        let pubkey = sk.public_key().serialize();
        let hash160: [u8; 20] = Ripemd160::digest(Sha256::digest(pubkey)).into();

        let mut script_pubkey = vec![0x76, 0xa9, 0x14];
        script_pubkey.extend_from_slice(&hash160);
        script_pubkey.extend_from_slice(&[0x88, 0xac]);

        // 64 signature bytes plus the sighash type byte.
        let mut signature = vec![0xab; 64];
        signature.push(sighash_type.encode());

        let mut pczt = Creator::new_v7(BranchId::Nu8.into(), 100, 133, None, None)
            .unwrap()
            .build()
            .unwrap();
        pczt.transparent.inputs.push(transparent::Input {
            prevout_txid: [1; 32],
            prevout_index: 0,
            sequence: None,
            required_time_lock_time: None,
            required_height_lock_time: None,
            script_sig: None,
            value: 1_000,
            script_pubkey,
            redeem_script: None,
            partial_signatures: BTreeMap::from([(pubkey, signature)]),
            sighash_type: sighash_type.encode(),
            bip32_derivation: BTreeMap::new(),
            ripemd160_preimages: BTreeMap::new(),
            sha256_preimages: BTreeMap::new(),
            hash160_preimages: BTreeMap::new(),
            hash256_preimages: BTreeMap::new(),
            proprietary: BTreeMap::new(),
        });
        pczt.transparent.outputs.push(transparent::Output {
            value: 500,
            script_pubkey: vec![0x51],
            redeem_script: None,
            bip32_derivation: BTreeMap::new(),
            user_address: None,
            proprietary: BTreeMap::new(),
        });
        pczt
    }

    fn assert_rejected(policy: SighashPolicy, sighash_type: SighashType) {
        assert!(matches!(
            SpendFinalizer::new(pczt_with_input(sighash_type))
                .with_sighash_policy(policy)
                .finalize_spends(),
            Err(Error::TransparentFinalize(
                ::transparent::pczt::SpendFinalizerError::DisallowedSighashType(_)
            ))
        ));
    }

    /// A policy excluding `ALL`, built on top of the empty policy.
    fn non_all_policy() -> SighashPolicy {
        SighashPolicy::EMPTY.permitting(SighashType::NONE)
    }

    #[test]
    fn v7_spend_finalizer_rejects_non_all_sighash_under_any() {
        assert_rejected(SighashPolicy::ANY, SighashType::NONE);
    }

    #[test]
    fn v7_spend_finalizer_rejects_non_all_sighash_under_all_only() {
        assert_rejected(SighashPolicy::ALL_ONLY, SighashType::NONE);
    }

    #[test]
    fn v7_spend_finalizer_rejects_all_sighash_under_empty() {
        assert_rejected(SighashPolicy::EMPTY, SighashType::ALL);
    }

    #[test]
    fn v7_spend_finalizer_rejects_all_sighash_under_non_all_policy() {
        assert_rejected(non_all_policy(), SighashType::ALL);
    }

    #[test]
    fn v7_spend_finalizer_accepts_all_sighash_under_permissive_policy() {
        for policy in [SighashPolicy::ALL_ONLY, SighashPolicy::ANY] {
            let pczt = SpendFinalizer::new(pczt_with_input(SighashType::ALL))
                .with_sighash_policy(policy)
                .finalize_spends()
                .unwrap();
            assert!(pczt.transparent.inputs[0].script_sig.is_some());
        }
    }
}
