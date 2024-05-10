use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use ff::PrimeField;
use zcash_protocol::value::ZatBalance;

use crate::{
    consensus::BranchId,
    sapling::{
        self,
        bundle::{GrothProofBytes, OutputDescription, SpendDescription},
    },
};

use super::{
    components::{
        sapling as sapling_serialization,
        sprout::JsDescription,
        transparent::{self, TxIn, TxOut},
        Bundles, Sapling, SaplingPart, ShieldedBundle, Sprout, SproutPart, Transparent,
        TransparentPart,
    },
    sighash::{SignableInput, SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE, SIGHASH_SINGLE},
    TransactionData,
};

const ZCASH_SIGHASH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashSigHash";
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashOutputsHash";
const ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSOutputHash";

macro_rules! update_hash {
    ($h:expr, $cond:expr, $value:expr) => {
        if $cond {
            $h.update(&$value.as_ref());
        } else {
            $h.update(&[0; 32]);
        }
    };
}

/// Trait representing the transparent parts of a [ZIP 143] or [ZIP 243] transaction digest.
///
/// [ZIP 143]: https://zips.z.cash/zip-0143
/// [ZIP 243]: https://zips.z.cash/zip-0243
pub trait TransparentSigDigester: TransparentPart {
    fn digest_prevout(transparent_bundle: Option<&Self::Bundle>) -> Blake2bHash;
    fn digest_sequence(transparent_bundle: Option<&Self::Bundle>) -> Blake2bHash;
    fn digest_outputs(transparent_bundle: Option<&Self::Bundle>) -> Blake2bHash;
    fn digest_single_output(
        transparent_bundle: Option<&Self::Bundle>,
        signable_input: &SignableInput<'_>,
    ) -> [u8; 32];
    fn digest_signable_input(
        transparent_bundle: Option<&Self::Bundle>,
        signable_input: &SignableInput<'_>,
    ) -> Vec<u8>;
}

impl<A: transparent::Authorization> TransparentSigDigester for Transparent<A> {
    fn digest_prevout(transparent_bundle: Option<&Self::Bundle>) -> Blake2bHash {
        prevout_hash(transparent_bundle.map_or(&[], |b| b.vin.as_slice()))
    }

    fn digest_sequence(transparent_bundle: Option<&Self::Bundle>) -> Blake2bHash {
        sequence_hash(transparent_bundle.map_or(&[], |b| b.vin.as_slice()))
    }

    fn digest_outputs(transparent_bundle: Option<&Self::Bundle>) -> Blake2bHash {
        outputs_hash(transparent_bundle.map_or(&[], |b| b.vout.as_slice()))
    }

    fn digest_single_output(
        transparent_bundle: Option<&Self::Bundle>,
        signable_input: &SignableInput<'_>,
    ) -> [u8; 32] {
        match (transparent_bundle.as_ref(), signable_input) {
            (Some(b), SignableInput::Transparent { index, .. }) if index < &b.vout.len() => {
                single_output_hash(&b.vout[*index])
                    .as_bytes()
                    .try_into()
                    .expect("correct length")
            }
            _ => [0; 32],
        }
    }

    fn digest_signable_input(
        transparent_bundle: Option<&Self::Bundle>,
        signable_input: &SignableInput<'_>,
    ) -> Vec<u8> {
        match signable_input {
            SignableInput::Shielded => vec![],
            SignableInput::Transparent {
                index,
                script_code,
                value,
                ..
            } => {
                if let Some(bundle) = transparent_bundle {
                    let mut data = vec![];
                    bundle.vin[*index].prevout.write(&mut data).unwrap();
                    script_code.write(&mut data).unwrap();
                    data.extend_from_slice(&value.to_i64_le_bytes());
                    data.extend_from_slice(&bundle.vin[*index].sequence.to_le_bytes());
                    data
                } else {
                    panic!("A request has been made to sign a transparent input, but none are present.");
                }
            }

            #[cfg(zcash_unstable = "zfuture")]
            SignableInput::Tze { .. } => {
                panic!("A request has been made to sign a TZE input, but the transaction version is not ZFuture");
            }
        }
    }
}

fn prevout_hash<TA: transparent::Authorization>(vin: &[TxIn<TA>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vin.len() * 36);
    for t_in in vin {
        t_in.prevout.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_PREVOUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn sequence_hash<TA: transparent::Authorization>(vin: &[TxIn<TA>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vin.len() * 4);
    for t_in in vin {
        data.extend_from_slice(&t_in.sequence.to_le_bytes());
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SEQUENCE_HASH_PERSONALIZATION)
        .hash(&data)
}

fn outputs_hash(vout: &[TxOut]) -> Blake2bHash {
    let mut data = Vec::with_capacity(vout.len() * (4 + 1));
    for t_out in vout {
        t_out.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn single_output_hash(tx_out: &TxOut) -> Blake2bHash {
    let mut data = vec![];
    tx_out.write(&mut data).unwrap();
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

/// Trait representing the Sprout parts of a [ZIP 143] or [ZIP 243] transaction digest.
///
/// [ZIP 143]: https://zips.z.cash/zip-0143
/// [ZIP 243]: https://zips.z.cash/zip-0243
pub trait SproutSigDigester: SproutPart {
    fn digest_joinsplits(
        consensus_branch_id: BranchId,
        sprout_bundle: Option<&Self::Bundle>,
    ) -> [u8; 32];
}

impl SproutSigDigester for Sprout {
    fn digest_joinsplits(
        consensus_branch_id: BranchId,
        sprout_bundle: Option<&Self::Bundle>,
    ) -> [u8; 32] {
        if !sprout_bundle.map_or(true, |b| b.joinsplits.is_empty()) {
            let bundle = sprout_bundle.unwrap();
            joinsplits_hash(
                consensus_branch_id,
                &bundle.joinsplits,
                &bundle.joinsplit_pubkey,
            )
            .as_bytes()
            .try_into()
            .expect("correct length")
        } else {
            [0; 32]
        }
    }
}

fn joinsplits_hash(
    consensus_branch_id: BranchId,
    joinsplits: &[JsDescription],
    joinsplit_pubkey: &[u8; 32],
) -> Blake2bHash {
    let mut data = Vec::with_capacity(
        joinsplits.len()
            * if consensus_branch_id.sprout_uses_groth_proofs() {
                1698 // JSDescription with Groth16 proof
            } else {
                1802 // JsDescription with PHGR13 proof
            },
    );
    for js in joinsplits {
        js.write(&mut data).unwrap();
    }
    data.extend_from_slice(joinsplit_pubkey);
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_JOINSPLITS_HASH_PERSONALIZATION)
        .hash(&data)
}

/// Trait representing the Sapling parts of a [ZIP 243] transaction digest.
///
/// [ZIP 243]: https://zips.z.cash/zip-0243
pub trait SaplingSigDigester: SaplingPart {
    fn digest_spends(sapling_bundle: Option<&Self::Bundle>) -> [u8; 32];
    fn digest_outputs(sapling_bundle: Option<&Self::Bundle>) -> [u8; 32];
}

impl<A> SaplingSigDigester for Sapling<A>
where
    A: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
{
    fn digest_spends(sapling_bundle: Option<&Self::Bundle>) -> [u8; 32] {
        if !sapling_bundle.map_or(true, |b| b.shielded_spends().is_empty()) {
            shielded_spends_hash(sapling_bundle.unwrap().shielded_spends())
                .as_bytes()
                .try_into()
                .expect("correct length")
        } else {
            [0; 32]
        }
    }

    fn digest_outputs(sapling_bundle: Option<&Self::Bundle>) -> [u8; 32] {
        if !sapling_bundle.map_or(true, |b| b.shielded_outputs().is_empty()) {
            shielded_outputs_hash(sapling_bundle.unwrap().shielded_outputs())
                .as_bytes()
                .try_into()
                .expect("correct length")
        } else {
            [0; 32]
        }
    }
}

fn shielded_spends_hash<
    A: sapling::bundle::Authorization<SpendProof = GrothProofBytes, OutputProof = GrothProofBytes>,
>(
    shielded_spends: &[SpendDescription<A>],
) -> Blake2bHash {
    let mut data = Vec::with_capacity(shielded_spends.len() * 384);
    for s_spend in shielded_spends {
        data.extend_from_slice(&s_spend.cv().to_bytes());
        data.extend_from_slice(s_spend.anchor().to_repr().as_ref());
        data.extend_from_slice(s_spend.nullifier().as_ref());
        data.extend_from_slice(&<[u8; 32]>::from(*s_spend.rk()));
        data.extend_from_slice(s_spend.zkproof());
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn shielded_outputs_hash(shielded_outputs: &[OutputDescription<GrothProofBytes>]) -> Blake2bHash {
    let mut data = Vec::with_capacity(shielded_outputs.len() * 948);
    for s_out in shielded_outputs {
        sapling_serialization::write_output_v4(&mut data, s_out).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

pub fn v4_signature_hash<B>(
    tx: &TransactionData<B>,
    signable_input: &SignableInput<'_>,
) -> Blake2bHash
where
    B: Bundles,
    B::Transparent: TransparentSigDigester,
    B::Sprout: SproutSigDigester,
    B::Sapling: SaplingSigDigester,
{
    let hash_type = signable_input.hash_type();
    if tx.version.has_overwinter() {
        let mut personal = [0; 16];
        personal[..12].copy_from_slice(ZCASH_SIGHASH_PERSONALIZATION_PREFIX);
        personal[12..].copy_from_slice(&u32::from(tx.consensus_branch_id).to_le_bytes());

        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(&personal)
            .to_state();

        h.update(&tx.version.header().to_le_bytes());
        h.update(&tx.version.version_group_id().to_le_bytes());
        update_hash!(
            h,
            hash_type & SIGHASH_ANYONECANPAY == 0,
            B::Transparent::digest_prevout(tx.transparent_bundle.as_ref())
        );
        update_hash!(
            h,
            (hash_type & SIGHASH_ANYONECANPAY) == 0
                && (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                && (hash_type & SIGHASH_MASK) != SIGHASH_NONE,
            B::Transparent::digest_sequence(tx.transparent_bundle.as_ref())
        );

        if (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
            && (hash_type & SIGHASH_MASK) != SIGHASH_NONE
        {
            h.update(B::Transparent::digest_outputs(tx.transparent_bundle.as_ref()).as_bytes());
        } else if (hash_type & SIGHASH_MASK) == SIGHASH_SINGLE {
            h.update(&B::Transparent::digest_single_output(
                tx.transparent_bundle.as_ref(),
                signable_input,
            ));
        } else {
            h.update(&[0; 32]);
        };

        h.update(&B::Sprout::digest_joinsplits(
            tx.consensus_branch_id,
            tx.sprout_bundle.as_ref(),
        ));

        if tx.version.has_sapling() {
            h.update(&B::Sapling::digest_spends(tx.sapling_bundle.as_ref()));
            h.update(&B::Sapling::digest_outputs(tx.sapling_bundle.as_ref()));
        }
        h.update(&tx.lock_time.to_le_bytes());
        h.update(&u32::from(tx.expiry_height).to_le_bytes());
        if tx.version.has_sapling() {
            h.update(
                &tx.sapling_bundle
                    .as_ref()
                    .map_or(ZatBalance::zero(), ShieldedBundle::value_balance)
                    .to_i64_le_bytes(),
            );
        }
        h.update(&u32::from(hash_type).to_le_bytes());

        match signable_input {
            SignableInput::Shielded => (),
            SignableInput::Transparent { .. } => {
                h.update(&B::Transparent::digest_signable_input(
                    tx.transparent_bundle.as_ref(),
                    signable_input,
                ));
            }

            #[cfg(zcash_unstable = "zfuture")]
            SignableInput::Tze { .. } => {
                panic!("A request has been made to sign a TZE input, but the transaction version is not ZFuture");
            }
        }

        h.finalize()
    } else {
        panic!("Signature hashing for pre-overwinter transactions is not supported.")
    }
}
