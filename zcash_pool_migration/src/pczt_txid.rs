//! Derivation of a migration transaction's [`TxId`] from its stored PCZT.
//!
//! A migration transaction's txid exists from the moment the PCZT is PREPARED — before it is
//! signed, let alone proved — and never moves afterwards. That ordering is not a convenience: the
//! txid has to be computed in order to derive the signature hash, so producing one is a
//! prerequisite of signing rather than a consequence of it. Everything that happens later is
//! AUTHORIZING data — the signatures, and the anchor and spend witnesses ZIP 374 defers to
//! proving — and none of it enters the effecting data the txid digest covers. A transaction whose
//! id moved under proving would carry a signature over the wrong id, and no node would accept it.
//!
//! So the id of the transaction a consumer will eventually broadcast is knowable long before it
//! is broadcast, and knowable again afterwards from the same stored bytes. That is what
//! [`advance_migration`] uses to recognize a transaction the wallet has seen mine even when the
//! consumer never recorded broadcasting it — a crash, or a failed persist, between submitting to
//! a node and calling [`MigrationState::mark_broadcast`].
//!
//! Costs one PCZT parse and the txid digests; nothing here touches proofs, so it is available
//! under the `signer` feature alone.
//!
//! [`advance_migration`]: crate::satisfiability::advance_migration
//! [`MigrationState::mark_broadcast`]: crate::engine::MigrationState::mark_broadcast

use core::fmt;

use pczt::Pczt;
use zcash_primitives::transaction::txid::to_txid;
use zcash_protocol::TxId;

/// A stored PCZT whose transaction id cannot be derived.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxIdError {
    /// The bytes do not parse as a PCZT.
    Parse,
    /// The PCZT parses, but its effects cannot be assembled into transaction data — a bundle is
    /// malformed, or a field the txid commits to is absent.
    Effects,
}

impl fmt::Display for TxIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxIdError::Parse => f.write_str("the stored bytes do not parse as a PCZT"),
            TxIdError::Effects => {
                f.write_str("the PCZT's effects do not assemble into transaction data")
            }
        }
    }
}

impl core::error::Error for TxIdError {}

/// The [`TxId`] of the transaction `pczt` describes.
///
/// Answerable as soon as the PCZT is prepared, and stable from there (see the module docs): an
/// unsigned PCZT, the signed PCZT it becomes, and the proven PCZT after that all yield the same
/// answer — the id the transaction carries once broadcast and mined.
pub fn pczt_txid(pczt: &Pczt) -> Result<TxId, TxIdError> {
    // `into_effects` consumes the PCZT, and callers hold stored bytes they may still need; the
    // clone is one parse's worth of owned data, not a proof-sized copy.
    let tx_data = pczt
        .clone()
        .into_effects()
        .map_err(|_| TxIdError::Effects)?;
    let digests = tx_data.txid_digests();
    Ok(
        to_txid(tx_data.version(), tx_data.consensus_branch_id(), &digests)
            .expect("version compatibility checked by Pczt::into_effects"),
    )
}

/// [`pczt_txid`] over stored PCZT bytes, parsing them first.
pub fn stored_pczt_txid(bytes: &[u8]) -> Result<TxId, TxIdError> {
    let pczt = Pczt::parse(bytes).map_err(|_| TxIdError::Parse)?;
    pczt_txid(&pczt)
}

#[cfg(all(test, zcash_unstable = "nu8"))]
mod tests {
    use alloc::vec::Vec;

    use pczt::{
        Pczt,
        roles::{
            creator::Creator, io_finalizer::IoFinalizer, signer::Signer,
            spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor,
        },
    };
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_primitives::transaction::{
        TxVersion,
        builder::{BuildConfig, Builder, BundlePadding},
        bytes::TransactionBytes,
        components::transparent::{read_outpoint, read_txout},
        fees::fixed,
        zip248::{BundleType, SuppliedBundleDigests},
    };
    use zcash_protocol::{
        consensus::{BlockHeight, BranchId},
        value::{ZatBalance, Zatoshis},
    };

    use super::{pczt_txid, stored_pczt_txid};

    /// Fixed deterministic construction and extraction randomness.
    const SEED: u64 = 248;
    /// A transparent funding coin with enough value to pay the test fee.
    const INPUT_VALUE: Zatoshis = Zatoshis::const_from_u64(100_000);
    /// The recipient receives the input less a fee.
    const OUTPUT_VALUE: Zatoshis = Zatoshis::const_from_u64(90_000);
    /// A value mutation that changes the pool delta without changing transparent effects.
    const MUTATED_INPUT_VALUE: Zatoshis = Zatoshis::const_from_u64(110_000);
    /// A value mutation that changes both the output and the pool delta.
    const MUTATED_OUTPUT_VALUE: Zatoshis = Zatoshis::const_from_u64(80_000);
    /// The compressed secp256k1 generator, matching secret scalar one.
    const PUBLIC_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// Secret scalar one, used only for the synthetic funding coin.
    const SECRET_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    /// P2PKH for HASH160 of the compressed secp256k1 generator.
    const SCRIPT_PUBKEY: [u8; 25] = [
        0x76, 0xa9, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45,
        0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6, 0x88, 0xac,
    ];

    fn fixture(input: Zatoshis, output: Zatoshis) -> Pczt {
        let mut params = zcash_pool_migration_memory::regtest_network(true);
        let height = BlockHeight::from_u32(zcash_pool_migration_memory::TARGET_HEIGHT);
        params.nu8 = Some(height);
        let mut coin_bytes = input.to_i64_le_bytes().to_vec();
        // A standard P2PKH script fits in a single-byte CompactSize length.
        coin_bytes.push(SCRIPT_PUBKEY.len().try_into().unwrap());
        coin_bytes.extend_from_slice(&SCRIPT_PUBKEY);
        let coin = read_txout(&coin_bytes[..]).unwrap();
        let recipient = coin.recipient_address().unwrap();
        /// A non-null synthetic outpoint with output index zero.
        const OUTPOINT: [u8; 36] = [
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 0, 0, 0, 0,
        ];
        let mut builder = Builder::new(
            params,
            height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .propose_version::<fixed::FeeRule>(TxVersion::V7)
            .unwrap();
        builder
            .add_transparent_p2pkh_input(
                PUBLIC_KEY.parse().unwrap(),
                read_outpoint(&OUTPOINT[..]).unwrap(),
                coin,
            )
            .unwrap();
        builder.add_transparent_output(&recipient, output).unwrap();
        let fee = (input - output).unwrap();
        let parts = builder
            .build_for_pczt(
                ChaCha8Rng::seed_from_u64(SEED),
                &fixed::FeeRule::non_standard(fee),
            )
            .unwrap();
        IoFinalizer::new(Creator::build_from_parts(parts.pczt_parts).unwrap())
            .finalize_io(ChaCha8Rng::seed_from_u64(SEED))
            .unwrap()
    }

    #[test]
    fn v7_pczt_txids_match_authorized_transactions_and_commit_to_value_deltas() {
        let mut ids = Vec::new();
        for (input, output) in [
            (INPUT_VALUE, OUTPUT_VALUE),
            (MUTATED_INPUT_VALUE, OUTPUT_VALUE),
            (INPUT_VALUE, MUTATED_OUTPUT_VALUE),
        ] {
            let pczt = fixture(input, output);
            let expected_delta = ZatBalance::from((input - output).unwrap());
            let effects = pczt.clone().into_effects().unwrap();
            assert_eq!(effects.version(), TxVersion::V7);
            assert_eq!(effects.consensus_branch_id(), BranchId::Nu8);
            assert_eq!(
                effects
                    .value_pool_deltas()
                    .zec_value(BundleType::TRANSPARENT),
                Some(expected_delta)
            );
            assert_eq!(
                effects.value_pool_deltas().zec_value(BundleType::FEE),
                Some(-expected_delta)
            );
            let prepared_id = pczt_txid(&pczt).unwrap();
            assert_eq!(
                stored_pczt_txid(&pczt.clone().serialize().unwrap()).unwrap(),
                prepared_id
            );

            let mut signer = Signer::new(pczt).unwrap();
            signer
                .sign_transparent(0, &SECRET_KEY.parse().unwrap())
                .unwrap();
            let signed = signer.finish();
            assert_eq!(pczt_txid(&signed).unwrap(), prepared_id);
            let finalized = SpendFinalizer::new(signed).finalize_spends().unwrap();
            assert_eq!(
                stored_pczt_txid(&finalized.clone().serialize().unwrap()).unwrap(),
                prepared_id
            );
            let tx = TransactionExtractor::new(finalized)
                .extract(ChaCha8Rng::seed_from_u64(SEED))
                .unwrap();
            assert_eq!(prepared_id, tx.txid());
            // The byte-layer digest is an independent path from PCZT's typed digester.
            let mut bytes = Vec::new();
            tx.write(&mut bytes).unwrap();
            let wire = TransactionBytes::read(&bytes[..]).unwrap();
            assert_eq!(
                prepared_id,
                wire.v7_txid(&SuppliedBundleDigests::new()).unwrap()
            );
            ids.push(prepared_id);
        }
        assert_ne!(
            ids[0], ids[1],
            "input value changes only the value delta map"
        );
        assert_ne!(
            ids[0], ids[2],
            "output value changes the output and value delta map"
        );
    }
}
