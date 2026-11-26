//! The Signer role (capability holders can contribute).
//!
//! - Needs the spend authorization randomizers to create signatures.
//! - Needs sufficient information to verify that the proof is over the correct data,
//!   without needing to verify the proof itself.
//! - A Signer should only need to implement:
//!   - Pedersen commitments using Jubjub / Pallas arithmetic (for note and value
//!     commitments)
//!   - BLAKE2b and BLAKE2s (and the various PRFs / CRHs they are used in)
//!   - Nullifier check (using Jubjub / Pallas arithmetic)
//!   - KDF plus note decryption (AEAD_CHACHA20_POLY1305)
//!   - SignatureHash algorithm
//!   - Signatures (RedJubjub / RedPallas)
//!   - A source of randomness.
//!
//! # Outputs a Signer must tolerate
//!
//! A zero-valued Orchard-protocol output whose `enc_ciphertext` does not decrypt is
//! well-formed. A Signer MUST classify it as a tolerable dummy output, and MUST NOT
//! reconstruct an expected ciphertext and reject the mismatch.
//!
//! After NU6.3 every Orchard-pool action is subject to the same-address restriction, so
//! spending in the Orchard pool pairs each real spend with a fabricated zero-valued
//! output addressed to the spent note's own receiver. That output's `enc_ciphertext` is
//! random bytes rather than an encryption of the note plaintext ([ZIP 326]): a real
//! encryption would trial-decrypt under the receiver's incoming viewing key in the same
//! action that carries the spend's nullifier, letting any holder of that key link the
//! nullifier to the address and so detect the spend.
//!
//! Such an output carries explicit `recipient`, `value`, and `rseed` fields but no
//! `user_address`, so a Signer reads a value of zero and recovers nothing from the
//! ciphertext. The note and its commitment are unaffected, so `cmx` is derived and
//! checked as for any other output.
//!
//! # Signing before the anchor and witnesses are known
//!
//! For v6 and later transaction formats, a Signer MAY sign a spend whose `witness` is
//! absent, in a bundle whose `anchor` is absent ([ZIP 374]).
//!
//! A v6 txid digest excludes shielded anchors, committing them in the authorizing-data
//! digest instead, and a witness never enters the transaction. The sighash therefore
//! binds every economically meaningful field — nullifiers, value commitments, outputs,
//! and value balances — while the anchor, witnesses, and proofs govern only whether the
//! transaction can be mined, not what it does once it is. They are installed by
//! [`Updater`] before proving.
//!
//! This is what allows a chain of transactions to be signed in one session, before the
//! parent whose outputs they spend has been mined or even broadcast. A Signer's user
//! interface should be able to convey that a batch contains transactions spending the
//! outputs of an in-batch, not-yet-mined parent.
//!
//! For v5 the sighash commits to the anchor, so it must be present before signing.
//!
//! [ZIP 326]: https://zips.z.cash/zip-0326#fabricatedsame-addressoutputsandrandomizednoteciphertexts
//! [ZIP 374]: https://zips.z.cash/zip-0374#anchorsandpre-authorization
//! [`Updater`]: crate::roles::updater::Updater

use alloc::vec::Vec;

use orchard::primitives::redpallas;
use rand_core::{CryptoRng, Rng};

use ::transparent::sighash::{SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE, SighashPolicy};
use zcash_primitives::transaction::sighash::{PrecomputedSighashData, SignableInput};

#[cfg(zcash_unstable = "nu8")]
use zcash_primitives::transaction::sighash::V7SignatureContext;

use crate::{
    ExtractError, ParsedPczt, Pczt,
    common::{
        FLAG_HAS_SIGHASH_SINGLE, FLAG_SHIELDED_MODIFIABLE, FLAG_TRANSPARENT_INPUTS_MODIFIABLE,
        FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE, Global,
    },
    is_v7_version, precompute_sighash_data, sighash,
};

pub use crate::EffectsOnly;

pub mod batch;

/// A spend authorization signature for an action in an Orchard-protocol value pool.
///
/// This type only represents signatures for the Orchard and Ironwood value pools; it
/// does not represent Sapling spend authorization signatures. It can be used by external
/// signers that return signatures separately from a PCZT. The value pool and action index
/// identify where the signature belongs when it is later applied with
/// [`Signer::apply_orchard_spend_auth_signature`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendAuthSignature {
    value_pool: orchard::ValuePool,
    action_index: usize,
    signature: [u8; 64],
}

impl SpendAuthSignature {
    /// Constructs a spend authorization signature for the action at `action_index`
    /// in `value_pool`.
    pub fn from_parts(
        value_pool: orchard::ValuePool,
        action_index: usize,
        signature: [u8; 64],
    ) -> Self {
        Self {
            value_pool,
            action_index,
            signature,
        }
    }

    /// Returns the Orchard-protocol value pool containing the signed action.
    pub fn value_pool(&self) -> orchard::ValuePool {
        self.value_pool
    }

    /// Returns the index of the signed action within its value pool's bundle.
    pub fn action_index(&self) -> usize {
        self.action_index
    }

    /// Returns the raw RedPallas spend authorization signature bytes.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Extracts the Orchard-protocol spend authorization signatures present in `pczt`.
///
/// The returned signatures are tagged with their Orchard or Ironwood value pool and
/// action index, so they can be transported independently and later applied to a
/// corresponding PCZT with [`Signer::apply_orchard_spend_auth_signature`]. Actions
/// without a spend authorization signature are omitted.
pub fn extract_orchard_spend_auth_signatures(pczt: &Pczt) -> Vec<SpendAuthSignature> {
    fn extract_from_bundle(
        signatures: &mut Vec<SpendAuthSignature>,
        value_pool: orchard::ValuePool,
        bundle: &crate::orchard::Bundle,
    ) {
        for (action_index, action) in bundle.actions().iter().enumerate() {
            if let Some(signature) = action.spend().spend_auth_sig() {
                signatures.push(SpendAuthSignature::from_parts(
                    value_pool,
                    action_index,
                    *signature,
                ));
            }
        }
    }

    let mut signatures = Vec::new();
    extract_from_bundle(&mut signatures, orchard::ValuePool::Orchard, pczt.orchard());
    extract_from_bundle(
        &mut signatures,
        orchard::ValuePool::Ironwood,
        pczt.ironwood(),
    );
    signatures
}

pub struct Signer {
    global: Global,
    transparent: transparent::pczt::Bundle<zcash_protocol::value::Zatoshis>,
    sapling: crate::sapling::Parsed,
    orchard: crate::orchard::Parsed,
    ironwood: crate::orchard::Parsed,
    empty_ironwood: Option<crate::orchard::Bundle>,
    /// Cached across multiple signatures.
    sighash_data: PrecomputedSighashData<EffectsOnly>,
    shielded_sighash: [u8; 32],
    transparent_sighash_policy: SighashPolicy,
}

impl Signer {
    /// Instantiates the Signer role with the given PCZT.
    ///
    /// Returns [`Error::Extract`] if the transaction version, branch, v7 expiry
    /// height or signature counts are unsupported, or a bundle cannot be extracted.
    pub fn new(pczt: Pczt) -> Result<Self, Error> {
        let anchor_requirement =
            crate::common::AnchorRequirement::for_pre_authorization(pczt.global.tx_version);
        let empty_ironwood = pczt
            .ironwood
            .actions
            .is_empty()
            .then(|| pczt.ironwood.clone());

        let ParsedPczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
            tx_data,
        } = pczt.extract_tx_data(
            anchor_requirement,
            |t| {
                t.extract_effects()
                    .map_err(ExtractError::TransparentExtract)
            },
            |s| {
                crate::extract_sapling_effects(s, anchor_requirement)
                    .map_err(ExtractError::SaplingExtract)
            },
            |o| {
                crate::extract_orchard_effects(o, anchor_requirement)
                    .map_err(ExtractError::OrchardExtract)
            },
            |i| {
                crate::extract_orchard_effects(i, anchor_requirement)
                    .map_err(ExtractError::IronwoodExtract)
            },
        )?;
        let sighash_data = precompute_sighash_data(&global, tx_data, &transparent)?;
        let is_v7 = is_v7_version(global.tx_version);
        // Version 7 signs a distinct digest per shielded Spend, action and binding
        // signature, so the shared digest is only meaningful before it.
        let shielded_sighash = if is_v7 {
            [0; 32]
        } else {
            sighash(&sighash_data, &SignableInput::Shielded)
        };

        Ok(Self {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
            empty_ironwood,
            sighash_data,
            shielded_sighash,
            transparent_sighash_policy: SighashPolicy::ALL_ONLY,
        })
    }

    /// Sets the sighash policy that this Signer applies to transparent inputs.
    ///
    /// The default is [`SighashPolicy::ALL_ONLY`]; see [`SighashPolicy`] for why the
    /// sighash type a counterparty placed in the PCZT is only used if this Signer’s own
    /// policy permits it.
    ///
    /// Version 7 variant 0 signatures support only `SIGHASH_ALL`. A policy that permits
    /// it is therefore applied as [`SighashPolicy::ALL_ONLY`]; a policy that does not is
    /// applied as [`SighashPolicy::EMPTY`], under which every input is refused.
    pub fn with_transparent_sighash_policy(mut self, sighash_policy: SighashPolicy) -> Self {
        self.transparent_sighash_policy = sighash_policy;
        self
    }

    /// Returns the policy applied to transparent inputs.
    fn transparent_sighash_policy(&self) -> SighashPolicy {
        if is_v7_version(self.global.tx_version) {
            crate::roles::v7_sighash_policy(self.transparent_sighash_policy)
        } else {
            self.transparent_sighash_policy
        }
    }

    /// Calculates the signature digest that must be signed to authorize shielded spends.
    ///
    /// This is the shared digest used by version 5 and version 6 transactions, where
    /// every shielded bundle, Spend, action and binding signature signs the same value.
    /// Version 7 signs each shielded Spend, action and binding signature over its own
    /// digest; use [`Self::sapling_sighash`], [`Self::orchard_sighash`] or
    /// [`Self::ironwood_sighash`] for those.
    ///
    /// This can be used to produce a signature externally suitable for passing to e.g.
    /// [`Self::apply_orchard_signature`].}
    ///
    /// Returns [`Error::NoSharedShieldedSighash`] for version 7.
    pub fn shielded_sighash(&self) -> Result<[u8; 32], Error> {
        self.try_shielded_sighash()
    }

    /// Returns the shared shielded signature digest for a pre-v7 transaction.
    ///
    /// Returns [`Error::NoSharedShieldedSighash`] for v7, whose Spend, action and
    /// binding signatures each use a distinct digest.
    pub fn try_shielded_sighash(&self) -> Result<[u8; 32], Error> {
        if is_v7_version(self.global.tx_version) {
            Err(Error::NoSharedShieldedSighash)
        } else {
            Ok(self.shielded_sighash)
        }
    }

    /// Calculates the signature digest that must be signed to authorize the Sapling Spend
    /// at `index`.
    ///
    /// Before version 7 this is the shared shielded digest; version 7 signs each Spend
    /// over its own index. This can be used to produce a signature externally suitable
    /// for passing to [`Self::apply_sapling_signature`].
    ///
    /// Returns an error if `index` is invalid for this PCZT.
    pub fn sapling_sighash(&self, index: usize) -> Result<[u8; 32], Error> {
        if index >= self.sapling.bundle.spends().len() {
            return Err(Error::InvalidIndex);
        }
        #[cfg(zcash_unstable = "nu8")]
        if is_v7_version(self.global.tx_version) {
            return Ok(sighash(
                &self.sighash_data,
                &SignableInput::V7(V7SignatureContext::SaplingSpend { index }),
            ));
        }
        Ok(self.shielded_sighash)
    }

    /// Calculates the signature digest that must be signed to authorize the Orchard action
    /// at `index`.
    ///
    /// Before version 7 this is the shared shielded digest; version 7 signs each action
    /// over its own index and pool. This can be used to produce a signature externally
    /// suitable for passing to [`Self::apply_orchard_signature`] or
    /// [`Self::apply_orchard_spend_auth_signature`].
    ///
    /// Returns an error if `index` is invalid for this PCZT.
    pub fn orchard_sighash(&self, index: usize) -> Result<[u8; 32], Error> {
        if index >= self.orchard.bundle.actions().len() {
            return Err(Error::InvalidIndex);
        }
        #[cfg(zcash_unstable = "nu8")]
        if is_v7_version(self.global.tx_version) {
            return Ok(sighash(
                &self.sighash_data,
                &SignableInput::V7(V7SignatureContext::OrchardAction { index }),
            ));
        }
        Ok(self.shielded_sighash)
    }

    /// Calculates the signature digest that must be signed to authorize the Ironwood action
    /// at `index`.
    ///
    /// Before version 7 this is the shared shielded digest; version 7 signs each action
    /// over its own index and pool. This can be used to produce a signature externally
    /// suitable for passing to [`Self::apply_ironwood_signature`] or
    /// [`Self::apply_orchard_spend_auth_signature`].
    ///
    /// Returns an error if `index` is invalid for this PCZT.
    pub fn ironwood_sighash(&self, index: usize) -> Result<[u8; 32], Error> {
        if index >= self.ironwood.bundle.actions().len() {
            return Err(Error::InvalidIndex);
        }
        #[cfg(zcash_unstable = "nu8")]
        if is_v7_version(self.global.tx_version) {
            return Ok(sighash(
                &self.sighash_data,
                &SignableInput::V7(V7SignatureContext::IronwoodAction { index }),
            ));
        }
        Ok(self.shielded_sighash)
    }

    /// Calculates the signature digest that must be signed to authorize the transparent
    /// spend at the given index.
    ///
    /// This can be used to produce a signature externally suitable for passing to e.g.
    /// [`Self::append_transparent_signature`].}
    ///
    /// Whoever signs the returned sighash is authorizing whatever it commits to, so the
    /// consistency of the input and the acceptability of its sighash type are checked
    /// here, exactly as they are when this Signer produces the signature itself.
    ///
    /// Returns an error if `index` is invalid for this PCZT.
    pub fn transparent_sighash(&self, index: usize) -> Result<[u8; 32], Error> {
        let input = self
            .transparent
            .inputs()
            .get(index)
            .ok_or(Error::InvalidIndex)?;

        input
            .with_signable_input_with_sighash_policy(
                index,
                |signable_input| {
                    sighash(
                        &self.sighash_data,
                        &SignableInput::transparent(
                            self.sighash_data.tx().version(),
                            signable_input,
                        ),
                    )
                },
                self.transparent_sighash_policy(),
            )
            .map_err(Error::TransparentSign)
    }

    /// Signs the transparent spend at the given index with the given spending key.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn sign_transparent(
        &mut self,
        index: usize,
        sk: &secp256k1::SecretKey,
    ) -> Result<(), Error> {
        let sighash_policy = self.transparent_sighash_policy();
        self.generate_or_append_transparent_signature(index, |input, sighash_data| {
            input.sign_with_sighash_policy(
                index,
                |input| {
                    sighash(
                        sighash_data,
                        &SignableInput::transparent(sighash_data.tx().version(), input),
                    )
                },
                sk,
                sighash_policy,
            )
        })
    }

    /// Appends the given signature to the transparent spend.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn append_transparent_signature(
        &mut self,
        index: usize,
        signature: secp256k1::ecdsa::Signature,
    ) -> Result<(), Error> {
        let sighash_policy = self.transparent_sighash_policy();
        self.generate_or_append_transparent_signature(index, |input, sighash_data| {
            input.append_signature_with_sighash_policy(
                index,
                |input| {
                    sighash(
                        sighash_data,
                        &SignableInput::transparent(sighash_data.tx().version(), input),
                    )
                },
                signature,
                sighash_policy,
            )
        })
    }

    fn generate_or_append_transparent_signature<F>(
        &mut self,
        index: usize,
        f: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(
            &mut transparent::pczt::Input<zcash_protocol::value::Zatoshis>,
            &PrecomputedSighashData<EffectsOnly>,
        ) -> Result<(), transparent::pczt::SignerError>,
    {
        let input = self
            .transparent
            .inputs_mut()
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // The consistency of the input being signed, and the acceptability of its sighash
        // type, are checked by the `zcash_transparent` methods that `f` calls. They are
        // enforced there rather than here because `crate::roles::low_level_signer` hands
        // out the transparent bundle and calls those methods directly.

        // Generate or apply the signature.
        f(input, &self.sighash_data).map_err(Error::TransparentSign)?;

        // Update transaction modifiability:
        // - If the Signer added a signature that does not use `SIGHASH_ANYONECANPAY`, the
        //   Transparent Inputs Modifiable Flag must be set to False (because the
        //   signature commits to all inputs, not just the one at `index`).
        if input.sighash_type().encode() & SIGHASH_ANYONECANPAY == 0 {
            self.global.tx_modifiable &= !FLAG_TRANSPARENT_INPUTS_MODIFIABLE;
        }
        // - If the Signer added a signature that does not use `SIGHASH_NONE`, the
        //   Transparent Outputs Modifiable Flag must be set to False. Note that this
        //   applies to `SIGHASH_SINGLE` because we could otherwise remove the output at
        //   `index`, which would not remove the signature.
        if (input.sighash_type().encode() & !SIGHASH_ANYONECANPAY) != SIGHASH_NONE {
            self.global.tx_modifiable &= !FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE;
        }
        // - If the Signer added a signature that uses `SIGHASH_SINGLE`, the Has
        //   `SIGHASH_SINGLE` flag must be set to True.
        if (input.sighash_type().encode() & !SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE {
            self.global.tx_modifiable |= FLAG_HAS_SIGHASH_SINGLE;
        }
        // - Always set the Shielded Modifiable Flag to False.
        self.global.tx_modifiable &= !FLAG_SHIELDED_MODIFIABLE;

        Ok(())
    }

    /// Signs the Sapling spend at the given index with the given spend authorizing key.
    ///
    /// Requires the spend's `proof_generation_key` field to be set (because the API does
    /// not take an FVK).
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    ///
    /// `rng` provides the randomness for the signature.
    pub fn sign_sapling<R: Rng + CryptoRng>(
        &mut self,
        rng: R,
        index: usize,
        ask: &sapling::keys::SpendAuthorizingKey,
    ) -> Result<(), Error> {
        self.generate_or_apply_sapling_signature(index, |spend, shielded_sighash| {
            spend.sign(shielded_sighash, ask, rng)
        })
    }

    /// Applies the given signature to the Sapling spend.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn apply_sapling_signature(
        &mut self,
        index: usize,
        signature: redjubjub::Signature<redjubjub::SpendAuth>,
    ) -> Result<(), Error> {
        self.generate_or_apply_sapling_signature(index, |spend, shielded_sighash| {
            spend.apply_signature(shielded_sighash, signature)
        })
    }

    fn generate_or_apply_sapling_signature<F>(&mut self, index: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut sapling::pczt::Spend, [u8; 32]) -> Result<(), sapling::pczt::SignerError>,
    {
        let sighash = self.sapling_sighash(index)?;
        let spend = self
            .sapling
            .bundle
            .spends_mut()
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // Check consistency of the input being signed if we have its note components.
        match spend.verify_nullifier(None) {
            Err(
                sapling::pczt::VerifyError::MissingRecipient
                | sapling::pczt::VerifyError::MissingValue
                | sapling::pczt::VerifyError::MissingRandomSeed,
            ) => Ok(()),
            r => r,
        }
        .map_err(Error::SaplingVerify)?;

        // Generate or apply the signature.
        f(spend, sighash).map_err(Error::SaplingSign)?;

        // Update transaction modifiability: all transaction effects have been committed
        // to by the signature.
        self.global.tx_modifiable &= !(FLAG_TRANSPARENT_INPUTS_MODIFIABLE
            | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
            | FLAG_SHIELDED_MODIFIABLE);

        Ok(())
    }

    /// Signs the Orchard spend at the given index with the given spend authorizing key.
    ///
    /// Requires the spend's `fvk` field to be set (because the API does not take an FVK).
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    ///
    /// `rng` provides the randomness for the signature.
    pub fn sign_orchard<R: Rng + CryptoRng>(
        &mut self,
        rng: R,
        index: usize,
        ask: &orchard::keys::SpendAuthorizingKey,
    ) -> Result<(), Error> {
        self.generate_or_apply_orchard_signature(index, |spend, shielded_sighash| {
            spend.sign(shielded_sighash, ask, rng)
        })
    }

    /// Applies the given signature to the Orchard spend.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn apply_orchard_signature(
        &mut self,
        index: usize,
        signature: redpallas::Signature<redpallas::SpendAuth>,
    ) -> Result<(), Error> {
        self.generate_or_apply_orchard_signature(index, |action, shielded_sighash| {
            action.apply_signature(shielded_sighash, signature)
        })
    }

    /// Applies an externally produced Orchard-protocol spend authorization signature.
    ///
    /// The signature's value pool selects the Orchard or Ironwood bundle, and its
    /// action index selects the spend within that bundle. The signature is verified
    /// against the action's randomized verification key before it is stored.
    ///
    /// Returns an error if the action index is invalid, the action data is
    /// inconsistent, or the signature does not verify.
    pub fn apply_orchard_spend_auth_signature(
        &mut self,
        signature: &SpendAuthSignature,
    ) -> Result<(), Error> {
        let spend_auth_sig =
            redpallas::Signature::<redpallas::SpendAuth>::from(*signature.signature());
        match signature.value_pool() {
            orchard::ValuePool::Orchard => {
                self.apply_orchard_signature(signature.action_index(), spend_auth_sig)
            }
            orchard::ValuePool::Ironwood => {
                self.apply_ironwood_signature(signature.action_index(), spend_auth_sig)
            }
        }
    }

    fn generate_or_apply_orchard_signature<F>(&mut self, index: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut orchard::pczt::Action, [u8; 32]) -> Result<(), orchard::pczt::SignerError>,
    {
        let sighash = self.orchard_sighash(index)?;
        let action = self
            .orchard
            .bundle
            .actions_mut()
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // Check consistency of the input being signed if we have its note components.
        match action.spend().verify_nullifier(None) {
            Err(
                orchard::pczt::VerifyError::MissingRecipient
                | orchard::pczt::VerifyError::MissingValue
                | orchard::pczt::VerifyError::MissingRho
                | orchard::pczt::VerifyError::MissingRandomSeed,
            ) => Ok(()),
            r => r,
        }
        .map_err(Error::OrchardVerify)?;

        // Generate or apply the signature.
        f(action, sighash).map_err(Error::OrchardSign)?;

        // Update transaction modifiability: all transaction effects have been committed
        // to by the signature.
        self.global.tx_modifiable &= !(FLAG_TRANSPARENT_INPUTS_MODIFIABLE
            | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
            | FLAG_SHIELDED_MODIFIABLE);

        Ok(())
    }

    /// Signs the Ironwood spend at the given index with the given spend authorizing key.
    ///
    /// Requires the spend's `fvk` field to be set (because the API does not take an FVK).
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    ///
    /// `rng` provides the randomness for the signature.
    pub fn sign_ironwood<R: Rng + CryptoRng>(
        &mut self,
        rng: R,
        index: usize,
        ask: &orchard::keys::SpendAuthorizingKey,
    ) -> Result<(), Error> {
        self.generate_or_apply_ironwood_signature(index, |spend, shielded_sighash| {
            spend.sign(shielded_sighash, ask, rng)
        })
    }

    /// Applies the given signature to the Ironwood spend.
    ///
    /// It is the caller's responsibility to perform any semantic validity checks on the
    /// PCZT (for example, comfirming that the change amounts are correct) before calling
    /// this method.
    pub fn apply_ironwood_signature(
        &mut self,
        index: usize,
        signature: redpallas::Signature<redpallas::SpendAuth>,
    ) -> Result<(), Error> {
        self.generate_or_apply_ironwood_signature(index, |action, shielded_sighash| {
            action.apply_signature(shielded_sighash, signature)
        })
    }

    fn generate_or_apply_ironwood_signature<F>(&mut self, index: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut orchard::pczt::Action, [u8; 32]) -> Result<(), orchard::pczt::SignerError>,
    {
        let sighash = self.ironwood_sighash(index)?;
        let action = self
            .ironwood
            .bundle
            .actions_mut()
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // Check consistency of the input being signed if we have its note components.
        match action.spend().verify_nullifier(None) {
            Err(
                orchard::pczt::VerifyError::MissingRecipient
                | orchard::pczt::VerifyError::MissingValue
                | orchard::pczt::VerifyError::MissingRho
                | orchard::pczt::VerifyError::MissingRandomSeed,
            ) => Ok(()),
            r => r,
        }
        .map_err(Error::IronwoodVerify)?;

        // Generate or apply the signature.
        f(action, sighash).map_err(Error::IronwoodSign)?;

        // Update transaction modifiability: all transaction effects have been committed
        // to by the signature.
        self.global.tx_modifiable &= !(FLAG_TRANSPARENT_INPUTS_MODIFIABLE
            | FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE
            | FLAG_SHIELDED_MODIFIABLE);

        Ok(())
    }

    /// Finishes the Signer role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        let Self {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
            empty_ironwood,
            sighash_data: _,
            shielded_sighash: _,
            transparent_sighash_policy: _,
        } = self;

        Pczt {
            global,
            transparent: crate::transparent::Bundle::serialize_from(transparent),
            sapling: sapling.reserialize(),
            orchard: orchard.reserialize(),
            ironwood: empty_ironwood.unwrap_or_else(|| ironwood.reserialize()),
        }
    }
}

/// Errors that can occur while creating signatures for a PCZT.
#[derive(Debug)]
pub enum Error {
    Extract(crate::ExtractError),
    InvalidIndex,
    /// The transaction uses distinct per-signature digests, not a shared shielded digest.
    NoSharedShieldedSighash,
    IronwoodSign(orchard::pczt::SignerError),
    IronwoodVerify(orchard::pczt::VerifyError),
    OrchardSign(orchard::pczt::SignerError),
    OrchardVerify(orchard::pczt::VerifyError),
    SaplingSign(sapling::pczt::SignerError),
    SaplingVerify(sapling::pczt::VerifyError),
    TransparentSign(transparent::pczt::SignerError),
}

impl From<crate::ExtractError> for Error {
    fn from(e: crate::ExtractError) -> Self {
        Error::Extract(e)
    }
}

#[cfg(all(test, feature = "io-finalizer", feature = "orchard"))]
mod tests {
    #[cfg(zcash_unstable = "nu8")]
    use alloc::collections::BTreeMap;
    use ff::{Field, PrimeField};
    use pasta_curves::pallas;
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use zcash_protocol::consensus::BranchId;

    use super::Signer;
    use crate::{
        orchard::{Action, Spend},
        roles::{creator::Creator, io_finalizer::IoFinalizer, updater::Updater},
    };

    #[test]
    fn legacy_sighash_accessors_reject_missing_spends_and_actions() {
        /// No expiry or keys are needed to check an empty bundle's bounds.
        const EXPIRY_DISABLED: u32 = 0;
        /// Mainnet's registered coin type.
        const COIN_TYPE: u32 = 133;
        for branch in [BranchId::Nu6, BranchId::Nu7] {
            let pczt = Creator::new(
                branch.into(),
                EXPIRY_DISABLED,
                COIN_TYPE,
                Some([0; 32]),
                Some([0; 32]),
            )
            .unwrap()
            .build()
            .unwrap();
            let signer = Signer::new(pczt).unwrap();
            assert_eq!(
                signer.try_shielded_sighash().unwrap(),
                signer.shielded_sighash().unwrap()
            );
            for index in [0, usize::MAX] {
                assert!(matches!(
                    signer.sapling_sighash(index),
                    Err(super::Error::InvalidIndex)
                ));
                assert!(matches!(
                    signer.orchard_sighash(index),
                    Err(super::Error::InvalidIndex)
                ));
                assert!(matches!(
                    signer.ironwood_sighash(index),
                    Err(super::Error::InvalidIndex)
                ));
            }
        }
    }

    #[test]
    fn legacy_action_sighashes_are_shared_only_for_existing_indices() {
        /// No expiry or keys are needed to check the one-action bundle's bounds.
        const EXPIRY_DISABLED: u32 = 0;
        /// Mainnet's registered coin type.
        const COIN_TYPE: u32 = 133;
        let mut pczt = Creator::new(BranchId::Nu7.into(), EXPIRY_DISABLED, COIN_TYPE, None, None)
            .unwrap()
            .build()
            .unwrap();
        pczt.orchard
            .actions
            .push(crate::orchard::testing::dummy_action());
        pczt.ironwood
            .actions
            .push(crate::orchard::testing::dummy_action());
        let signer = Signer::new(pczt).unwrap();
        assert_eq!(
            signer.orchard_sighash(0).unwrap(),
            signer.shielded_sighash().unwrap()
        );
        assert_eq!(
            signer.ironwood_sighash(0).unwrap(),
            signer.shielded_sighash().unwrap()
        );
        assert!(matches!(
            signer.orchard_sighash(1),
            Err(super::Error::InvalidIndex)
        ));
        assert!(matches!(
            signer.ironwood_sighash(1),
            Err(super::Error::InvalidIndex)
        ));
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_shared_sighash_is_fallible_without_panicking() {
        /// No expiry or keys are needed to check the version contract.
        const EXPIRY_DISABLED: u32 = 0;
        /// Mainnet's registered coin type.
        const COIN_TYPE: u32 = 133;
        let pczt = Creator::new_v7(BranchId::Nu8.into(), EXPIRY_DISABLED, COIN_TYPE, None, None)
            .unwrap()
            .build()
            .unwrap();
        let signer = Signer::new(pczt).unwrap();
        assert!(matches!(
            signer.shielded_sighash(),
            Err(super::Error::NoSharedShieldedSighash)
        ));
        assert!(matches!(
            signer.try_shielded_sighash(),
            Err(super::Error::NoSharedShieldedSighash)
        ));
        assert!(matches!(
            signer.sapling_sighash(0),
            Err(super::Error::InvalidIndex)
        ));
        assert!(matches!(
            signer.orchard_sighash(0),
            Err(super::Error::InvalidIndex)
        ));
        assert!(matches!(
            signer.ironwood_sighash(0),
            Err(super::Error::InvalidIndex)
        ));
    }

    #[cfg(zcash_unstable = "nu8")]
    #[test]
    fn v7_external_signatures_reject_wrong_digests_without_mutation() {
        let mut pczt = Creator::new_v7(BranchId::Nu8.into(), 100, 133, None, None)
            .unwrap()
            .build()
            .unwrap();
        let sapling_key = sapling::zip32::ExtendedSpendingKey::master(&[7; 32]).unwrap();
        let sapling_rsk = sapling_key.expsk().ask().randomize(&jubjub::Fr::ONE);
        let sapling_rk = redjubjub::VerificationKey::from(&sapling_rsk);
        let spend = crate::sapling::Spend {
            cv: sapling::value::ValueCommitment::derive(
                sapling::value::NoteValue::from_raw(0),
                sapling::value::ValueCommitTrapdoor::random(UnwrapErr(SysRng)),
            )
            .to_bytes(),
            nullifier: [2; 32],
            rk: sapling_rk.into(),
            zkproof: None,
            spend_auth_sig: None,
            recipient: None,
            value: None,
            rcm: None,
            rseed: None,
            rcv: None,
            proof_generation_key: Some((
                sapling_key.expsk().proof_generation_key().ak().to_bytes(),
                sapling_key.expsk().proof_generation_key().nsk().to_bytes(),
            )),
            witness: None,
            alpha: None,
            zip32_derivation: None,
            dummy_ask: None,
            proprietary: BTreeMap::new(),
        };
        pczt.sapling.spends.extend([spend.clone(), spend]);
        pczt.orchard.actions.extend([
            crate::orchard::testing::dummy_action(),
            crate::orchard::testing::dummy_action(),
        ]);
        pczt.ironwood.actions.extend([
            crate::orchard::testing::dummy_action(),
            crate::orchard::testing::dummy_action(),
        ]);
        let sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
        for bundle in [&mut pczt.orchard, &mut pczt.ironwood] {
            for action in &mut bundle.actions {
                action.spend.fvk = Some(orchard::keys::FullViewingKey::from(&sk).to_bytes());
            }
        }
        let baseline = Signer::new(pczt.clone()).unwrap().finish();
        let mut signer = Signer::new(pczt).unwrap();
        let own = signer.sapling_sighash(0).unwrap();
        let sibling = signer.sapling_sighash(1).unwrap();
        assert_ne!(own, sibling);
        let signature = sapling_rsk.sign(UnwrapErr(SysRng), &sibling);
        let error = signer.apply_sapling_signature(0, signature).unwrap_err();
        assert!(
            matches!(
                error,
                super::Error::SaplingSign(sapling::pczt::SignerError::InvalidExternalSignature)
            ),
            "{error:?}"
        );
        let rejected = signer.finish();
        assert!(rejected.sapling.spends[0].spend_auth_sig.is_none());
        assert_eq!(
            rejected.serialize().unwrap(),
            baseline.clone().serialize().unwrap()
        );

        let rsk = orchard::keys::SpendAuthorizingKey::from(&sk).randomize(&pallas::Scalar::ONE);
        for pool in [orchard::ValuePool::Orchard, orchard::ValuePool::Ironwood] {
            let mut signer = Signer::new(baseline.clone()).unwrap();
            let (own, wrong) = match pool {
                orchard::ValuePool::Orchard => (
                    signer.orchard_sighash(0).unwrap(),
                    signer.ironwood_sighash(0).unwrap(),
                ),
                orchard::ValuePool::Ironwood => (
                    signer.ironwood_sighash(0).unwrap(),
                    signer.orchard_sighash(0).unwrap(),
                ),
            };
            assert_ne!(own, wrong);
            let signature = super::SpendAuthSignature::from_parts(
                pool,
                0,
                (&rsk.sign(UnwrapErr(SysRng), &wrong)).into(),
            );
            let error = signer
                .apply_orchard_spend_auth_signature(&signature)
                .unwrap_err();
            assert!(matches!(
                (pool, error),
                (
                    orchard::ValuePool::Orchard,
                    super::Error::OrchardSign(orchard::pczt::SignerError::InvalidExternalSignature)
                ) | (
                    orchard::ValuePool::Ironwood,
                    super::Error::IronwoodSign(
                        orchard::pczt::SignerError::InvalidExternalSignature
                    )
                )
            ));
            assert_eq!(
                signer.finish().serialize().unwrap(),
                baseline.clone().serialize().unwrap()
            );
            let mut signer = Signer::new(baseline.clone()).unwrap();
            let signature = super::SpendAuthSignature::from_parts(
                pool,
                0,
                (&rsk.sign(UnwrapErr(SysRng), &own)).into(),
            );
            signer
                .apply_orchard_spend_auth_signature(&signature)
                .unwrap();
        }
        let mut signer = Signer::new(baseline).unwrap();
        signer
            .apply_sapling_signature(0, sapling_rsk.sign(UnwrapErr(SysRng), &own))
            .unwrap();
    }

    /// Builds a fully-dummy (zero-valued, freshly-random-key) Ironwood action, whose
    /// spend the IO Finalizer signs itself via `dummy_sk`. This lets the IO Finalizer
    /// and Signer roles be exercised without going through the transaction builder
    /// (which requires a concrete anchor to add any real spend).
    fn dummy_action() -> Action {
        let sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
        let alpha = pallas::Scalar::ONE;
        let base = crate::orchard::testing::dummy_action();

        Action {
            spend: Spend {
                alpha: Some(alpha.to_repr()),
                dummy_sk: Some(crate::common::SecretKeyBytes::new(*sk.to_bytes())),
                ..base.spend
            },
            rcv: Some([3; 32]),
            ..base
        }
    }

    /// [ZIP 374] permits signing before the authorizing anchor is supplied.
    /// Effects-only extraction must not expose the parser's internal placeholder.
    ///
    /// [ZIP 374]: https://zips.z.cash/zip-0374#anchorsandpre-authorization
    #[test]
    fn io_finalizer_and_signer_succeed_with_absent_ironwood_anchor() {
        /// A height below the lock-time threshold.
        const EXPIRY_HEIGHT: u32 = 100;
        /// Mainnet's registered coin type.
        const COIN_TYPE: u32 = 133;
        let creators = core::iter::once(
            Creator::new(BranchId::Nu6_3.into(), EXPIRY_HEIGHT, COIN_TYPE, None, None).unwrap(),
        );
        #[cfg(zcash_unstable = "nu8")]
        let creators = creators.chain(core::iter::once(
            Creator::new_v7(BranchId::Nu8.into(), EXPIRY_HEIGHT, COIN_TYPE, None, None).unwrap(),
        ));
        for creator in creators {
            let mut pczt = creator.build().unwrap();
            pczt.ironwood.actions.push(dummy_action());

            assert!(pczt.ironwood.anchor.is_none());

            let pczt = IoFinalizer::new(pczt)
                .finalize_io(UnwrapErr(SysRng))
                .unwrap();
            assert!(pczt.ironwood.anchor.is_none());
            assert!(pczt.ironwood.bsk.is_some());
            // The IO Finalizer signs and clears the dummy spending key.
            assert!(pczt.ironwood.actions[0].spend.dummy_sk.is_none());
            assert!(pczt.ironwood.actions[0].spend.spend_auth_sig.is_some());
            let effects = pczt.clone().into_effects().unwrap();
            assert!(effects.ironwood_bundle().unwrap().anchor().is_none());

            // `Signer::new` computes the shielded sighash and extracts transaction
            // effects; this must succeed with the anchor still absent (a v6 sighash
            // does not commit to it).
            let signer = Signer::new(pczt).unwrap();
            let pczt = signer.finish();
            assert!(pczt.ironwood.anchor.is_none());

            // The anchor may now be set by an Updater, at any point before the Prover
            // runs; nothing about signing required it to be present.
            let anchor = orchard::Anchor::empty_tree();
            let pczt = Updater::new(pczt)
                .set_ironwood_anchor(anchor)
                .unwrap()
                .finish();
            assert_eq!(pczt.ironwood.anchor, Some(anchor.to_bytes()));
        }
    }

    /// [ZIP 326] requires the zero-valued output fabricated for a real Orchard-pool
    /// spend to carry a randomized `enc_ciphertext` instead of an encryption to the
    /// spent note's receiver. Such an output is well-formed: the Signer role neither
    /// decrypts it nor reconstructs an expected ciphertext to compare it against, so
    /// signing succeeds and the ciphertext reaches the finished PCZT byte-identical.
    ///
    /// [ZIP 326]: https://zips.z.cash/zip-0326#fabricatedsame-addressoutputsandrandomizednoteciphertexts
    #[test]
    fn signer_tolerates_fabricated_output_with_randomized_ciphertext() {
        use orchard::{
            keys::{FullViewingKey, Scope},
            note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
            note_encryption::OrchardNoteEncryption,
            value::NoteValue,
        };

        let mut action = dummy_action();

        // The fabricated output is addressed to a real receiver and carries explicit
        // `recipient`, `value` and `rseed` fields, so its note commitment is ordinary.
        let rho = Option::from(Rho::from_bytes(&action.spend.nullifier)).unwrap();
        let rseed = (0u8..)
            .find_map(|i| {
                let mut bytes = [0; 32];
                bytes[0] = i;
                Option::from(RandomSeed::from_bytes(bytes, &rho))
            })
            .unwrap();
        let recipient =
            FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap())
                .address_at(0u32, Scope::External);
        let value = NoteValue::from_raw(0);
        let note = Option::from(orchard::Note::from_parts(
            recipient,
            value,
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .unwrap();

        // Only the ephemeral key comes from the encryptor; the ciphertext is replaced
        // with bytes that trial-decryption cannot recover a note from.
        let encryptor = OrchardNoteEncryption::new(None, note, [0; 512]);
        let mut randomized_ciphertext = encryptor.encrypt_note_plaintext().0.to_vec();
        randomized_ciphertext.fill(0xab);

        action.output.cmx = Some(ExtractedNoteCommitment::from(note.commitment()).to_bytes());
        action.output.ephemeral_key =
            <orchard::note_encryption::IronwoodDomain as zcash_note_encryption::Domain>::epk_bytes(
                encryptor.epk(),
            )
            .0;
        action.output.recipient = Some(recipient.to_raw_address_bytes());
        action.output.value = Some(value.inner());
        action.output.rseed = Some(*note.rseed().as_bytes());
        action.output.user_address = None;
        action.output.enc_ciphertext =
            crate::orchard::EncCiphertext::Encrypted(randomized_ciphertext.clone());

        let mut pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build()
            .unwrap();
        pczt.ironwood.actions.push(action);

        let pczt = IoFinalizer::new(pczt)
            .finalize_io(UnwrapErr(SysRng))
            .unwrap();
        let pczt = Signer::new(pczt).unwrap().finish();

        assert_eq!(
            pczt.ironwood.actions[0].output.enc_ciphertext,
            crate::orchard::EncCiphertext::Encrypted(randomized_ciphertext)
        );
        assert_eq!(pczt.ironwood.actions[0].output.value, Some(0));
    }
}

/// Version 7 variant 0 transparent signatures support only `SIGHASH_ALL`, so the Signer
/// refuses any other sighash type even under [`SighashPolicy::ANY`].
#[cfg(all(
    test,
    feature = "io-finalizer",
    feature = "spend-finalizer",
    feature = "tx-extractor",
    zcash_unstable = "nu8"
))]
mod v7_policy_tests {
    use alloc::{collections::BTreeMap, vec};

    use ::transparent::sighash::{SighashPolicy, SighashType};
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    use zcash_protocol::consensus::BranchId;

    use super::{Error, Signer};
    use crate::{
        Pczt,
        roles::{
            creator::Creator, io_finalizer::IoFinalizer, spend_finalizer::SpendFinalizer,
            tx_extractor::TransactionExtractor,
        },
        transparent,
    };

    /// A version 7 PCZT with one P2PKH input of the given sighash type, spendable by the
    /// returned key.
    fn pczt_with_p2pkh_input(sighash_type: SighashType) -> (Pczt, secp256k1::SecretKey) {
        let sk = secp256k1::SecretKey::from_secret_bytes([1; 32]).unwrap();
        let pubkey = sk.public_key().serialize();
        let hash160: [u8; 20] = Ripemd160::digest(Sha256::digest(pubkey)).into();

        let mut script_pubkey = vec![0x76, 0xa9, 0x14];
        script_pubkey.extend_from_slice(&hash160);
        script_pubkey.extend_from_slice(&[0x88, 0xac]);

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
            partial_signatures: BTreeMap::new(),
            sighash_type: sighash_type.encode(),
            bip32_derivation: BTreeMap::new(),
            ripemd160_preimages: BTreeMap::new(),
            sha256_preimages: BTreeMap::new(),
            hash160_preimages: BTreeMap::from([(hash160, pubkey.to_vec())]),
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
        (pczt, sk)
    }

    fn assert_rejected(policy: SighashPolicy, sighash_type: SighashType) {
        let (pczt, sk) = pczt_with_p2pkh_input(sighash_type);
        let pczt = IoFinalizer::new(pczt)
            .finalize_io(UnwrapErr(SysRng))
            .unwrap();
        let mut signer = Signer::new(pczt)
            .unwrap()
            .with_transparent_sighash_policy(policy);

        fn disallowed<T>(result: Result<T, Error>) -> bool {
            matches!(
                result,
                Err(Error::TransparentSign(
                    ::transparent::pczt::SignerError::DisallowedSighashType(_)
                ))
            )
        }

        assert!(disallowed(signer.transparent_sighash(0)));

        assert!(disallowed(signer.sign_transparent(0, &sk)));

        let signature = secp256k1::ecdsa::sign(secp256k1::Message::from_digest([0; 32]), &sk);
        assert!(disallowed(
            signer.append_transparent_signature(0, signature)
        ));
    }

    /// A policy excluding `ALL`, built on top of the empty policy.
    fn non_all_policy() -> SighashPolicy {
        SighashPolicy::EMPTY.permitting(SighashType::NONE)
    }

    #[test]
    fn v7_signer_rejects_non_all_sighash_under_any() {
        assert_rejected(SighashPolicy::ANY, SighashType::NONE);
    }

    #[test]
    fn v7_signer_rejects_non_all_sighash_under_all_only() {
        assert_rejected(SighashPolicy::ALL_ONLY, SighashType::NONE);
    }

    #[test]
    fn v7_signer_rejects_all_sighash_under_empty() {
        assert_rejected(SighashPolicy::EMPTY, SighashType::ALL);
    }

    #[test]
    fn v7_signer_rejects_all_sighash_under_non_all_policy() {
        assert_rejected(non_all_policy(), SighashType::ALL);
    }

    /// The Signer produces a transparent signature over the version 7 per-input digest,
    /// and the Spend Finalizer accepts it.
    #[test]
    fn v7_signer_signs_transparent_over_the_v7_digest() {
        let (pczt, sk) = pczt_with_p2pkh_input(SighashType::ALL);
        let pczt = IoFinalizer::new(pczt)
            .finalize_io(UnwrapErr(SysRng))
            .unwrap();
        let mut signer = Signer::new(pczt).unwrap();
        let sighash = signer.transparent_sighash(0).unwrap();
        signer.sign_transparent(0, &sk).unwrap();
        let pczt = signer.finish();

        let pubkey = sk.public_key().serialize();
        let signature = pczt.transparent.inputs[0].partial_signatures[&pubkey].clone();
        let (hash_type, der) = signature.split_last().unwrap();
        assert_eq!(*hash_type, SighashType::ALL.encode());
        secp256k1::ecdsa::Signature::from_der(der)
            .unwrap()
            .verify(secp256k1::Message::from_digest(sighash), &sk.public_key())
            .expect("the signature verifies over the Signer's version 7 digest");

        let pczt = SpendFinalizer::new(pczt)
            .with_sighash_policy(SighashPolicy::ANY)
            .finalize_spends()
            .unwrap();
        assert!(pczt.transparent.inputs[0].script_sig.is_some());

        let tx = TransactionExtractor::new(pczt)
            .extract(UnwrapErr(SysRng))
            .unwrap();
        assert!(tx.transparent_bundle().is_some());
    }

    /// An externally produced transparent signature is applied over the same version 7
    /// per-input digest that the Signer exposes.
    #[test]
    fn v7_signer_applies_external_transparent_signature_over_the_v7_digest() {
        let (pczt, sk) = pczt_with_p2pkh_input(SighashType::ALL);
        let pczt = IoFinalizer::new(pczt)
            .finalize_io(UnwrapErr(SysRng))
            .unwrap();
        let mut signer = Signer::new(pczt).unwrap();
        let sighash = signer.transparent_sighash(0).unwrap();
        let signature = secp256k1::ecdsa::sign(secp256k1::Message::from_digest(sighash), &sk);
        signer.append_transparent_signature(0, signature).unwrap();
        let pczt = signer.finish();

        let pczt = SpendFinalizer::new(pczt)
            .with_sighash_policy(SighashPolicy::ANY)
            .finalize_spends()
            .unwrap();
        assert!(pczt.transparent.inputs[0].script_sig.is_some());
    }
}
