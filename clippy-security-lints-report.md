# Security clippy lints: rollout report

Tracking the fallout of the proposed `[workspace.lints]` config (see
`Cargo.toml` on branch `experiment/crypto-clippy-lints`). Each lint that
cannot be enabled at `deny` yet gets a tracking issue below.

Baseline (library code only): 247 deny-level hits, 233 warn-level.
Line numbers are branch-relative; re-grep before acting on an issue.

---

## Deny-level lints (block compilation until cleared)

### 1. `clippy::todo` -- 11 lib hits

Quick explanation: real unimplemented methods, not stale markers; almost all in
the in-progress `zcash_client_memory` crate.

Suggested title: `zcash_client_memory: resolve todo!() sites to enable clippy::todo`

Locations:

- `zcash_client_memory/src/wallet_read.rs`: 735, 751, 756, 765
- `zcash_client_memory/src/wallet_write.rs`: 107, 713, 787, 955, 1076, 1084,
  1269, 1278, 1287, 1296
- `zcash_client_memory/src/input_source.rs`: 411, 412
- `zcash_client_memory/src/types/memory_wallet/mod.rs`: 1176

Resolution: implement, or return an explicit "unsupported" `Err(...)`.

### 2. `clippy::unimplemented` -- 5 lib hits

Quick explanation: same situation as todo, all in `zcash_client_memory`.

Suggested title: `zcash_client_memory: resolve unimplemented!() sites`

Locations:

- `zcash_client_memory/src/input_source.rs`: 149, 297
- `zcash_client_memory/src/wallet_read.rs`: 270
- `zcash_client_memory/src/wallet_write.rs`: 69, 1095

### 3. `clippy::panic` -- 18 lib hits

Quick explanation: explicit `panic!`/`unreachable`-style aborts in production
paths; each needs review (return `Result` or justify the invariant).

Suggested title: `Replace or document panic!() sites to enable clippy::panic`

Locations:

- `zcash_primitives/src/transaction/sighash_v4.rs`: 246, 262
- `zcash_keys/src/keys.rs`: 72, 243
- `zcash_client_sqlite/src/lib.rs`: 1304, 1647
- `zcash_client_sqlite/src/wallet.rs`: 3344
- `zcash_client_sqlite/src/wallet/init/migrations/receiving_key_scopes.rs`: 196
- `zcash_address/src/kind/unified.rs`: 257
- `zcash_client_memory/src/types/notes/mod.rs`: 31, 49, 109, 131
- `zcash_client_memory/src/types/notes/sent.rs`: 284
- `zcash_client_memory/src/types/memory_wallet/mod.rs`: 891
- `zcash_client_memory/src/types/data_requests.rs`: 96
- `zcash_client_memory/src/wallet_write.rs`: 615, 1160

### 4. `clippy::indexing_slicing` -- 62 lib hits

Quick explanation: `a[i]` / slice ops that panic on out-of-range; replace with
`.get()` or document the bound. Spread across crypto-core crates.

Suggested title: `Replace panicking indexing with .get() to enable clippy::indexing_slicing`

Per-crate counts: zcash_primitives 11, zcash_proofs 9, zcash_address 7,
equihash 7, zcash_protocol 6, zcash_keys 6, zcash_client_backend 5,
zcash_history 3, pczt 3, zcash_transparent 2, eip681 2, f4jumble 1.
List: `cargo clippy --workspace --lib 2>&1 | grep -A2 'may panic'`.

### 5. `clippy::unwrap_used` -- 151 lib hits

Quick explanation: largest backlog; `.unwrap()` on `Result`/`Option` in
production. Convert to `?`/`expect` with context, or restrict the lint to
non-test code first.

Suggested title: `Reduce unwrap() in production code to enable clippy::unwrap_used`

Per-crate counts: zcash_primitives 71, zcash_client_memory 41,
zcash_client_backend 17, zcash_address 8, zcash_client_sqlite 6, equihash 3,
zip321 2, zcash_protocol 1, zcash_proofs 1, pczt 1.
List: `cargo clippy -p <crate> --lib 2>&1 | grep -A2 unwrap`.

---

## Warn-level lints (non-blocking cleanup)

### 6. `clippy::expect_used` -- 140 lib hits (warn)

Quick explanation: `.expect()` in production; mostly fine but worth auditing
messages. Concentrated in `zcash_client_backend`.

Suggested title: `Audit expect() usage in production code`

Per-crate counts: zcash_client_backend 54, zcash_client_sqlite 16,
zcash_proofs 15, zcash_transparent 14, zcash_client_memory 11, zcash_history 8,
zcash_primitives 5, zcash_keys 5, eip681 4, zcash_address 3, pczt 3, build 2.

### 7. `clippy::unreachable` -- 32 lib hits (warn)

Quick explanation: `unreachable!()` invariant assertions; confirm each is truly
unreachable.

Suggested title: `Review unreachable!() invariants`

Per-crate counts: zcash_client_sqlite 12, zcash_client_backend 8,
zcash_client_memory 5, zcash_proofs 2, zcash_primitives 2, zcash_protocol 1,
zcash_keys 1, zcash_address 1.

### 8. `clippy::cast_possible_truncation` -- 21 lib hits (warn)

Quick explanation: narrowing casts that can silently truncate; use
`try_into()` or document the range.

Suggested title: `Audit truncating casts (cast_possible_truncation)`

Locations:

- `zcash_history/src/node_data.rs`: 83, 86, 90
- `zcash_history/src/version.rs`: 56, 89
- `zcash_history/src/tree.rs`: 48
- `zcash_encoding/src/lib.rs`: 96, 99, 103
- `zcash_address/src/kind/unified.rs`: 294 (x2)
- `zcash_client_backend/src/data_api/wallet.rs`: 1936
- `zcash_client_backend/src/sync.rs`: 245
- `zcash_client_memory/src/types/block.rs`: 110
- `zcash_client_memory/src/types/notes/received.rs`: 103, 105, 148
- `equihash/src/params.rs`: 25
- `f4jumble/src/lib.rs`: 155
- `eip681/src/parse.rs`: 124
- `zcash_proofs/src/sprout.rs`: 63

### 9. `clippy::integer_division` -- 17 lib hits (warn) -- DONE (production)

Status: all 17 production sites resolved. Each was reviewed and confirmed to be
either exact-by-invariant or an intended floor; intent is now explicit (an
`#[allow(clippy::integer_division)]` with a justifying comment, `div_ceil`, or a
compile-time `const _` assertion) and locked down with tests.

`cargo clippy --workspace --lib` reports 0 integer-division warnings.

Resolutions:

- `equihash/src/{params,minimal,verify}.rs`: allow + comments; new tests
  `params::tests::{division_invariants_hold_for_valid_params,
  node_byte_offsets_stay_in_bounds, zcash_params_derived_values}` and
  `minimal::tests::indices_from_minimal_length_is_exact`.
- `f4jumble/src/lib.rs:186`: `(num + den - 1) / den` -> `num.div_ceil(den)`;
  `:138` allow (floor split, covered by round-trip tests).
- `zcash_protocol/src/value.rs:371,477`: allow + comment; new test
  `value::tests::div_with_remainder_reconstructs` (proves
  `quotient * divisor + remainder == self`).
- `zip321/src/lib.rs:556`: allow + comment; new test
  `tests::amount_str_known_values`.
- `zcash_client_backend/src/data_api.rs:158` (+ orchard): allow + compile-time
  `const _` exactness assertions.
- `zcash_client_sqlite/src/wallet/common.rs:891`: allow + comment; index is read
  via `.get()`, so it is bounds-safe by construction (no panic).

Remaining (not in the production scope above): ~12 `integer_division` hits in
other crates' *test* code surface under `cargo clippy --all-targets` (CI's
flag). equihash's test sites are fixed; the rest can be cleared with
module-level `#![allow(clippy::integer_division)]` on those test modules.

### 10. `clippy::cast_lossless` -- 16 lib hits (warn) -- DONE

Status: all sites resolved by replacing `expr as T` with `T::from(expr)`. These
are widening casts, so the conversion is value-identical; no behaviour change
and no new tests required. `cargo clippy --workspace --lib --all-features`
reports 0 cast-lossless warnings. All affected crates compile and their existing
tests pass (eip681 49, zcash_address 33, zcash_protocol 11, zcash_encoding 4,
equihash 9).

Resolved (default-feature sites):

- `eip681/src/parse.rs`: 85, 521, 538, 546
- `zcash_encoding/src/lib.rs`: 39, 48, 58
- `zcash_protocol/src/consensus.rs`: 80, 102
- `zcash_address/src/kind/unified.rs`: 93
- `zcash_client_memory/src/types/memory_wallet/mod.rs`: 944 (x2), 964, 977
- `zcash_client_memory/src/types/notes/mod.rs`: 35
- `zcash_client_sqlite/src/wallet.rs`: 541

Plus three feature-gated sites the default-feature scan missed, fixed for
`--all-features` cleanliness:

- `zcash_client_memory` orchard paths: the orchard analogues of 964 and 977.
- `equihash/src/minimal.rs:40` (`solver`/`test` gated): outer `u8 -> u32`.

Note discovered while building `--all-features`: with `unsafe_code = "deny"`,
`equihash` fails to compile under its `tromp` FFI feature ("usage of an
`unsafe extern` block"). This is the `unsafe_code` lint, not `cast_lossless`,
and reinforces the config caveat below: FFI paths need a per-item
`#[allow(unsafe_code)]` (or the crate must opt out of the workspace lint).

### 11. `clippy::cast_possible_wrap` -- 7 lib hits (warn)

Quick explanation: unsigned->signed casts that can wrap; all in the value type.

Suggested title: `Audit signed-cast wraps in zcash_protocol::value`

Locations:

- `zcash_protocol/src/value.rs`: 15, 50, 84, 301, 352, 379, 385

---

## Ready to enable now (0 lib hits)

`clippy::float_arithmetic`, `clippy::mem_forget`, `clippy::modulo_arithmetic`,
`clippy::cast_sign_loss` produce no library hits and can go straight to `deny`.

---

## Config caveat: `unsafe_code`

`unsafe_code = "forbid"` breaks `equihash` (E0453: `allow(unsafe_code)`
incompatible with `forbid`; 32 errors). FFI crates cannot carve out a `forbid`.
Use `unsafe_code = "deny"` instead, which `equihash`'s existing
`#![allow(unsafe_code)]` can override.
