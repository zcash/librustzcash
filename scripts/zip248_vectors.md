# ZIP 248 digest fixtures

Run from the repository root with Python 3 (standard library only):

```sh
python3 scripts/zip248_vectors.py --check
python3 scripts/zip248_vectors.py --json
python3 -m unittest discover -s scripts -p test_zip248_vectors.py
```

The first command checks the fixed expectations and the inventory of v7
64-character hex literals in the original Rust test files, plus the null-prevout
regression when present. The second emits named
digest nodes, including the directional and multi-element fixtures whose Rust
tests assemble preimages instead of embedding hex constants. Neither command
builds or executes Rust, reads build products, downloads anything, or uses
randomness. Output hex is in raw digest order, not reversed txid display order.

## Source and scope

The digest algorithms and field encodings follow
[ZIP 248 at revision `825c98effcd7b11eefa4c70aa2fca8d67a15c85f`](https://raw.githubusercontent.com/zcash/zips/825c98effcd7b11eefa4c70aa2fca8d67a15c85f/zips/zip-0248.rst).
The version group ID `0x6e755f38` and branch ID `0xfffffffb` are provisional
values used by the repository's Nu8 fixtures, not assignments made by that ZIP.

Fixtures use the exact field values in
`zcash_primitives/src/transaction/tests.rs` and
`zcash_primitives/src/transaction/bytes/tests.rs`, plus the null-prevout fixture
in `zcash_primitives/src/transaction/sighash.rs`. Repeated ciphertext, proof,
and signature bytes are constructed, not copied as large hex blobs. In
particular, the single-output Sapling fixture's `(cv, cmu)` is `(0x55, 0x66)`,
while the directional/multi-element fixtures use `(0x66, 0x55)`.

This is a separately executable Python transcription using `hashlib.blake2b`,
not a guarantee of independently developed or independently reviewed consensus
logic. It does not validate curves, proofs, signatures, transaction balance,
bundle activation, or contextual consensus rules. Some fixtures intentionally
are not valid transactions. Mock supplied-digest domains for unknown bundles
belong to the tests, not to ZIP 248; opaque payloads cannot generally be hashed
directly to obtain bundle digests.

## Coverage

The default run checks **42 distinct existing v7 hex constants**: all 38 in
the two original test files (27 in `EXPECTED` and eleven in
`SIGNATURE_EXPECTED`), plus four in `sighash.rs`'s null-prevout regression
test (`NULL_PREVOUT_EXPECTED`). The source inventory checks the additional
four when that separately integrable regression test is present.

| Python fixture | Rust test / constants |
| --- | --- |
| `empty`, `fee` | `v7_empty_transaction_matches_zip248_digests`, `v7_fee_delta_matches_zip248_digests`, and their byte-layer counterparts: txid/auth and fee txid |
| `transparent` | `transparent_effects_and_auth_match_independent_digests`: both leaves, txid, auth |
| `sapling` | `sapling_effects_and_auth_match_independent_digests`: both leaves and txid; `v7_sapling_spends_digest_hashes_cv_and_rk_under_the_v6_personalization`: spends digest; the same leaf/txid constants in `sapling_effects_digest_needs_no_anchor` |
| `orchard`, `ironwood` | `orchard_and_ironwood_effects_match_independent_digests`: both pools' leaves, txids, auth commitments |
| `coinbase`, `coinbase-signals` | `coinbase_effects_match_independent_digest`, `multi_signal_coinbase_matches_independent_digest`: both leaves and txids |
| `unknown-indexer`, `unknown-keys` | `v7_indexer_round_trips_unknown_bundle_without_typed_conversion`, `unknown_bundle_keys_match_independent_digests`: both txids and auth commitments |
| `signature-mixed` | `v7_variant0_signature_digests_match_independent_vectors`: all eleven unchanged `expected_digest` signatures |
| `signature-null-prevout` | `sighash.rs`'s `context_tests::v7_null_prevout_commits_input_amounts_and_scripts`: S.2 txid, S.3 amounts, S.4 scripts, and Sapling binding sighash |

The generator also covers T.1/T.2/T.3/A.1 for the byte-layer
`multi_bundle_txid_and_auth_match_independent_preimages`,
`sapling_spend_only_matches_independent_preimages`,
`sapling_output_only_auth_omits_the_anchor`,
`transparent_input_only_matches_independent_preimages`,
`transparent_output_only_omits_the_auth_entry`, and
`multi_byte_compact_size_keys_match_independent_preimages` fixtures.
Their root outputs are checked against Python reference constants, not new Rust
hex literals. `signature-no-inputs` covers the two S.1–S.7 preimages in
`v7_signature_without_transparent_inputs_uses_empty_input_digests`.

`signature-null-prevout` recomputes S.2 from the full explicit envelope:
Nu8 provisional identifiers; zero lock/expiry heights; one transparent input
with null outpoint and maximal sequence; no outputs, deltas, or shielded
bundles. Its S.3/S.4 inputs are one spent coin worth 7000 zatoshis with an
empty script; S.7 is the empty Sapling binding context. Unlike
`signature-mixed`, this fixture does not use a production-derived S.2 input.

`signature-encoding` checks eleven S.1–S.7 encodings: two transparent input
contexts; Sapling spends 0/1 and binding; Orchard actions 0/1 and binding;
Ironwood actions 0/1 and binding. Its S.3/S.4/S.7 inputs exactly match
`v7_signature_digest_vectors`; S.2 is computed from an explicitly specified
transparent-only envelope. Shielded contexts here are encoding-only inputs;
they do not claim that the envelope contains those shielded bundles.

### Seeded signature input provenance

`zip248_signature_effects.txt` contains the complete Sapling, Orchard, and
Ironwood effecting payloads of `v7_signature_digest_vectors::sighash_tx()`,
using proptest seed `0x5a17` and the locked dependencies. Each named line is
hex wire data, not a hash. Sapling records counts and the `(cv, nullifier, rk)`
spends and `(cv, cmu, ephemeralKey, encCiphertext, outCiphertext)` outputs.
Orchard and Ironwood record the action count, every action's
`(cv, nullifier, rk, cmx, ephemeralKey, encCiphertext, outCiphertext)`, and flags.
No anchors, proofs, signatures, or production-derived digests are stored.

The Rust signature-vector test checks that its generated effects match this
fixed input file. Python decodes those explicit fields, derives their
effecting leaves and T.1–T.3, computes S.2, and then recomputes S.1–S.7.
All eleven existing signature expectations remain unchanged. This is a
separate transcription over identical inputs, not an external implementation
or an independently developed consensus oracle.

Changing the seeded strategy or its dependencies can require an explicit
input-fixture update. Do not replace expected signatures with production
digest output. `--signature-txid <64-hex-digits>` deliberately overrides S.2
for mismatch diagnostics; it is not needed for normal verification.
`--check-rust` remains an alias for `--check`.

Pre-v7 constants, property-test-generated inputs, and builder/PCZT signing
integration fixtures are outside this generator's scope.
