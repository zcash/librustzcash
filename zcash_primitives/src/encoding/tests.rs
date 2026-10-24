use corez::io::{self, Write};
use orchard::{
    Bundle, Proof,
    bundle::{Authorized, BundleVersion},
};
use proptest::{
    strategy::{Strategy, ValueTree},
    test_runner::TestRunner,
};
use zcash_encoding::{Array, MAX_COMPACT_SIZE, Vector};
use zcash_protocol::value::ZatBalance;

use crate::{
    merkle_tree::HashSer,
    transaction::components::orchard::{self as codec, testing},
};

#[test]
fn bulk_string_writes() {
    let max_len = usize::try_from(MAX_COMPACT_SIZE).unwrap();
    for len in [0, 8, 252, 253, 65535, 65536, max_len, max_len + 1] {
        let string = "a".repeat(len);
        let mut expected = vec![];
        let old = Vector::write(&mut expected, string.as_bytes(), |w, b| w.write_all(&[*b]))
            .map_err(|e| e.kind());
        let mut actual = vec![];
        let result = HashSer::write(&string, &mut actual).map_err(|e| e.kind());
        assert_eq!(result, old);
        if len > max_len {
            assert_eq!(result, Err(io::ErrorKind::InvalidInput));
        } else {
            result.unwrap();
            assert_eq!(actual, expected);
        }
    }
}

fn old_bundle(bundle: &Bundle<Authorized, ZatBalance>, mut writer: impl Write) -> io::Result<()> {
    Vector::write_nonempty(&mut writer, bundle.actions(), |w, a| {
        codec::write_action_without_auth(w, a)
    })?;
    writer.write_all(&[bundle.flag_byte()])?;
    writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;
    writer.write_all(&bundle.anchor().to_bytes())?;
    Vector::write(
        &mut writer,
        bundle.authorization().proof().as_ref(),
        |w, b| w.write_all(&[*b]),
    )?;
    Array::write(
        &mut writer,
        bundle.actions().iter().map(|a| a.authorization()),
        |w, auth| w.write_all(&<[u8; 64]>::from(*auth)),
    )?;
    writer.write_all(&<[u8; 64]>::from(
        bundle.authorization().binding_signature(),
    ))
}

#[test]
fn bulk_proof_writes() {
    let seed = testing::arb_bundle(2)
        .new_tree(&mut TestRunner::deterministic())
        .unwrap()
        .current();
    // Historical bundles permit arbitrary proof lengths, including the encoding boundaries.
    let version = BundleVersion::orchard_insecure_v1();
    let seed = testing::rebuild_with_version(seed, version);
    let max_len = usize::try_from(MAX_COMPACT_SIZE).unwrap();
    for len in [0, 8, 252, 253, 65535, 65536, max_len, max_len + 1] {
        let proof = (0..=255).cycle().take(len).collect();
        let bundle = Bundle::try_from_parts(
            seed.actions().clone(),
            *seed.flags(),
            *seed.value_balance(),
            *seed.anchor(),
            Authorized::from_parts(
                Proof::new(proof),
                seed.authorization().binding_signature().clone(),
            ),
            version,
        )
        .unwrap();
        let mut expected = vec![];
        let old = old_bundle(&bundle, &mut expected).map_err(|e| e.kind());
        let mut actual = vec![];
        let result = codec::write_v5_bundle(Some(&bundle), &mut actual).map_err(|e| e.kind());
        assert_eq!(result, old);
        if len > max_len {
            assert_eq!(result, Err(io::ErrorKind::InvalidInput));
        } else {
            result.unwrap();
            assert_eq!(actual, expected);
        }
    }
}
