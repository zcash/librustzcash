# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial scaffolding of the backend-agnostic Orchard -> Ironwood value-pool migration engine crate.
- Note-split planning (the `note_splitting` module): decomposing a spendable source-pool balance into
  the self-funding notes that cross the turnstile. The module is pool-agnostic (its code names no
  specific pool); Zcash's first use is the Orchard -> Ironwood migration. The composition rule is abstracted behind the
  `DenominationStrategy` trait, so the (still-open) design choice can be made later by selecting a
  strategy rather than by rewriting code. Three implementations are provided:
  - `RandomizedOneTwoFive`: samples a random decomposition from a supplied RNG whose crossing values
    follow the `{1, 2, 5} * 10^k` series, so the same balance yields different, unlinkable crossings
    on each run (privacy from per-wallet unpredictability). Each plan keeps the best of several draws
    so an unlucky draw that exhausts the note cap while leaving a remainder is discarded.
  - `CanonicalOneTwoFive`: the deterministic, descending greedy decomposition over the same
    `{1, 2, 5} * 10^k` series (e.g. 12,345 ZEC -> 10,000 + 2,000 + 200 + 100 + 20 + 20 + 5).
  - `CanonicalPowerOfTen`: the deterministic decimal-digit expansion into pure powers of ten
    (`..., 100, 10, 1, 0.1, 0.01, ...` ZEC) of the Ironwood migration ZIP draft (privacy from
    cross-wallet value collision).
  Every strategy produces a `NoteSplitPlan` of self-funding notes (each holding its crossing value
  plus a fee buffer), mints denominations from a maximum (bounding a whale's crossings to the shared
  denomination set) down to a sub-1-ZEC dust floor, and leaves any residual below that floor as
  source-pool change rather than folded into a fee. The fee model is pluggable via the `FeePolicy` trait (`Zip317FeePolicy`
  provided), and the maximum denomination, dust floor, and note cap are strategy parameters.
  `plan_note_split` is a convenience wrapper over the recommended `RandomizedOneTwoFive`. Depends on
  `zcash_protocol`, `zcash_primitives`, and `rand_core`.
