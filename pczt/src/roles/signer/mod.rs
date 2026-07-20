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

use alloc::vec::Vec;

use blake2b_simd::Hash as Blake2bHash;
use orchard::primitives::redpallas;
use rand_core::OsRng;

use ::transparent::sighash::{SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE};
use zcash_primitives::transaction::{
    TransactionData, TxDigests, sighash::SignableInput, txid::TxIdDigester,
};

use crate::{
    ExtractError, ParsedPczt, Pczt,
    common::{
        FLAG_HAS_SIGHASH_SINGLE, FLAG_SHIELDED_MODIFIABLE, FLAG_TRANSPARENT_INPUTS_MODIFIABLE,
        FLAG_TRANSPARENT_OUTPUTS_MODIFIABLE, Global,
    },
};

pub use crate::EffectsOnly;
use crate::sighash;

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
    transparent: transparent::pczt::Bundle,
    sapling: crate::sapling::Parsed,
    orchard: crate::orchard::Parsed,
    ironwood: crate::orchard::Parsed,
    empty_ironwood: Option<crate::orchard::Bundle>,
    /// Cached across multiple signatures.
    tx_data: TransactionData<EffectsOnly>,
    txid_parts: TxDigests<Blake2bHash>,
    shielded_sighash: [u8; 32],
    secp: secp256k1::Secp256k1<secp256k1::All>,
}

impl Signer {
    /// Instantiates the Signer role with the given PCZT.
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
            |s| s.extract_effects().map_err(ExtractError::SaplingExtract),
            |o| o.extract_effects().map_err(ExtractError::OrchardExtract),
            |i| i.extract_effects().map_err(ExtractError::IronwoodExtract),
        )?;
        let txid_parts = tx_data.digest(TxIdDigester);
        let shielded_sighash = sighash(&tx_data, &SignableInput::Shielded, &txid_parts);

        Ok(Self {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
            empty_ironwood,
            tx_data,
            txid_parts,
            shielded_sighash,
            secp: secp256k1::Secp256k1::new(),
        })
    }

    /// Calculates the signature digest that must be signed to authorize shielded spends.
    ///
    /// This can be used to produce a signature externally suitable for passing to e.g.
    /// [`Self::apply_orchard_signature`].}
    pub fn shielded_sighash(&self) -> [u8; 32] {
        self.shielded_sighash
    }

    /// Calculates the signature digest that must be signed to authorize the transparent
    /// spend at the given index.
    ///
    /// This can be used to produce a signature externally suitable for passing to e.g.
    /// [`Self::append_transparent_signature`].}
    ///
    /// Returns an error if `index` is invalid for this PCZT.
    pub fn transparent_sighash(&self, index: usize) -> Result<[u8; 32], Error> {
        let input = self
            .transparent
            .inputs()
            .get(index)
            .ok_or(Error::InvalidIndex)?;

        input.with_signable_input(index, |signable_input| {
            Ok(sighash(
                &self.tx_data,
                &SignableInput::Transparent(signable_input),
                &self.txid_parts,
            ))
        })
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
        self.generate_or_append_transparent_signature(index, |input, tx_data, txid_parts, secp| {
            input.sign(
                index,
                |input| sighash(tx_data, &SignableInput::Transparent(input), txid_parts),
                sk,
                secp,
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
        self.generate_or_append_transparent_signature(index, |input, tx_data, txid_parts, secp| {
            input.append_signature(
                index,
                |input| sighash(tx_data, &SignableInput::Transparent(input), txid_parts),
                signature,
                secp,
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
            &mut transparent::pczt::Input,
            &TransactionData<EffectsOnly>,
            &TxDigests<Blake2bHash>,
            &secp256k1::Secp256k1<secp256k1::All>,
        ) -> Result<(), transparent::pczt::SignerError>,
    {
        let input = self
            .transparent
            .inputs_mut()
            .get_mut(index)
            .ok_or(Error::InvalidIndex)?;

        // Check consistency of the input being signed.
        // TODO

        // Generate or apply the signature.
        f(input, &self.tx_data, &self.txid_parts, &self.secp).map_err(Error::TransparentSign)?;

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
    pub fn sign_sapling(
        &mut self,
        index: usize,
        ask: &sapling::keys::SpendAuthorizingKey,
    ) -> Result<(), Error> {
        self.generate_or_apply_sapling_signature(index, |spend, shielded_sighash| {
            spend.sign(shielded_sighash, ask, OsRng)
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
        f(spend, self.shielded_sighash).map_err(Error::SaplingSign)?;

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
    pub fn sign_orchard(
        &mut self,
        index: usize,
        ask: &orchard::keys::SpendAuthorizingKey,
    ) -> Result<(), Error> {
        self.generate_or_apply_orchard_signature(index, |spend, shielded_sighash| {
            spend.sign(shielded_sighash, ask, OsRng)
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
        f(action, self.shielded_sighash).map_err(Error::OrchardSign)?;

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
    pub fn sign_ironwood(
        &mut self,
        index: usize,
        ask: &orchard::keys::SpendAuthorizingKey,
    ) -> Result<(), Error> {
        self.generate_or_apply_ironwood_signature(index, |spend, shielded_sighash| {
            spend.sign(shielded_sighash, ask, OsRng)
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
        f(action, self.shielded_sighash).map_err(Error::IronwoodSign)?;

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
            tx_data: _,
            txid_parts: _,
            shielded_sighash: _,
            secp: _,
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

#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use pasta_curves::pallas;
    use zcash_protocol::consensus::BranchId;

    use super::Signer;
    use crate::{
        orchard::{Action, Spend},
        roles::{creator::Creator, io_finalizer::IoFinalizer, updater::Updater},
    };

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
                dummy_sk: Some(*sk.to_bytes()),
                ..base.spend
            },
            rcv: Some([3; 32]),
            ..base
        }
    }

    /// [ZIP 374] "Anchors and pre-authorization" requires that, for a v6 transaction,
    /// signing (including the IO Finalizer's dummy-spend signing) works even while a
    /// shielded bundle's anchor is absent. The Ironwood bundle here is built by
    /// hand (rather than via the transaction builder, which requires a concrete
    /// anchor up front to add any spend) specifically to exercise that state; the
    /// full sign-then-prove-then-extract pipeline is covered by the end-to-end
    /// Ironwood tests, whose transaction builder requires the anchor to be set at the
    /// point the spend is added.
    ///
    /// [ZIP 374]: https://zips.z.cash/zip-0374#anchors-and-pre-authorization
    #[test]
    fn io_finalizer_and_signer_succeed_with_absent_ironwood_anchor() {
        let mut pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build()
            .unwrap();
        pczt.ironwood.actions.push(dummy_action());

        assert!(pczt.ironwood.anchor.is_none());

        let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
        assert!(pczt.ironwood.anchor.is_none());
        assert!(pczt.ironwood.bsk.is_some());
        // The IO Finalizer signs and clears the dummy spending key.
        assert!(pczt.ironwood.actions[0].spend.dummy_sk.is_none());
        assert!(pczt.ironwood.actions[0].spend.spend_auth_sig.is_some());

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
