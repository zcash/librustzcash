//! Pre-signing a migration PCZT: adding the Orchard spend-authorization signatures.
//!
//! The migration signs UP FRONT (capturing the account's authorization in as few signing sessions
//! as possible) and proves LATER, at scheduling time. This works because a spend-authorization
//! signature is over the transaction's sighash, which is fixed once the effecting data is finalized,
//! independent of the (still-absent) zk proofs: a finalized but unproven PCZT can be signed. The
//! signed, unproven PCZT is safe to persist and schedule; it cannot be broadcast until it is also
//! proven and extracted.

use orchard::keys::SpendAuthorizingKey;
use pczt::roles::signer::{Error as SignerError, Signer};

use super::BuildError;

/// Sign every Orchard spend in an assembled migration PCZT that `ask` authorizes, returning the
/// signed (still unproven) PCZT. Spends the key does not own are left unsigned: the builder's
/// fabricated zero-valued dummy spends, and any real spend belonging to another account.
///
/// # Errors
///
/// Returns [`BuildError::Build`] if the signer cannot be initialized, or if a spend fails to sign
/// for a reason other than the spend not being authorized by `ask`.
pub fn sign_pczt(pczt: pczt::Pczt, ask: &SpendAuthorizingKey) -> Result<pczt::Pczt, BuildError> {
    let mut signer =
        Signer::new(pczt).map_err(|e| BuildError::Build(format!("signer init: {e:?}")))?;
    for index in 0.. {
        match signer.sign_orchard(index, ask) {
            Ok(()) => {}
            // Past the last Orchard spend.
            Err(SignerError::InvalidIndex) => break,
            // A dummy spend, or a real spend from another account: not ours to authorize.
            Err(SignerError::OrchardSign(orchard::pczt::SignerError::WrongSpendAuthorizingKey)) => {
            }
            Err(e) => return Err(BuildError::Build(format!("sign orchard: {e:?}"))),
        }
    }
    Ok(signer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::FullViewingKey;
    use proptest::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;
    use zcash_protocol::value::COIN;

    use crate::build::build_split_pczt;
    use crate::build::test_util::{
        TARGET_HEIGHT, regtest_network, single_note_witness, spending_key,
    };

    /// Builds a two-output split PCZT spending one note owned by `fvk`. Deterministic in `note_seed`.
    fn build_split(fvk: &FullViewingKey, note_seed: u64) -> pczt::Pczt {
        let outputs = [40 * COIN, 40 * COIN];
        let note_value = 100 * COIN;
        let (note, path, anchor) = single_note_witness(fvk, note_value, note_seed);
        let params = regtest_network(true);
        let spends = vec![(note, path)];
        let rng = ChaCha8Rng::seed_from_u64(note_seed);
        let (pczt, _split) =
            build_split_pczt(&params, TARGET_HEIGHT, fvk, anchor, spends, &outputs, rng)
                .expect("the split builds");
        pczt
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Pre-signing a finalized (unproven) split PCZT adds the account's Orchard spend
        /// authorization: the serialized PCZT changes when signed with the account's own key, and is
        /// unchanged when signed with a foreign key, whose spends it does not own.
        #[test]
        fn pre_signing_authorizes_only_the_accounts_own_spend(
            account_seed in any::<u64>(),
            note_seed in any::<u64>(),
        ) {
            let sk = spending_key(account_seed);
            let fvk = FullViewingKey::from(&sk);
            let ask = SpendAuthorizingKey::from(&sk);

            // `Pczt::serialize` consumes the PCZT, and the build is deterministic in `note_seed`, so
            // each comparison builds a fresh (identical) unsigned PCZT.
            let unsigned = build_split(&fvk, note_seed).serialize().expect("serialize");

            let signed = sign_pczt(build_split(&fvk, note_seed), &ask)
                .expect("signing the account's own spend")
                .serialize()
                .expect("serialize");
            prop_assert_ne!(signed, unsigned.clone());

            // A foreign key authorizes nothing: the real spend is skipped as a key mismatch.
            let foreign_ask = SpendAuthorizingKey::from(&spending_key(account_seed ^ 0x5a5a_5a5a));
            let untouched = sign_pczt(build_split(&fvk, note_seed), &foreign_ask)
                .expect("a foreign key signs nothing")
                .serialize()
                .expect("serialize");
            prop_assert_eq!(untouched, unsigned);
        }
    }
}
