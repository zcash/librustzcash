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
  specific pool); Zcash's first use is the Orchard -> Ironwood migration. The composition rule is
  abstracted behind the `DenominationStrategy` trait, with one implementation aligned with ZIP 318:
  - `CanonicalOneTwoFive`: the canonical `{1, 2, 5} * 10^k` quantization of ZIP 318, a deterministic
    descending greedy decomposition over that series (equivalently, decimal-digit expansion into
    `{5, 2, 1}` times each place value), e.g. 12,345 ZEC -> 10,000 + 2,000 + 200 + 100 + 20 + 20 + 5.
    Privacy rests on cross-wallet value collision, as ZIP 318 prescribes.
  The trait is retained as the seam for a future variant (such as ZIP 318's optional
  frequency-constrained randomized substitution). The strategy produces a `NoteSplitPlan` of
  self-funding notes (each holding its crossing value plus a fee buffer), mints denominations from a
  maximum (ZIP 318's `DENOM_CAP`, bounding a whale's crossings to the shared denomination set) down to
  a sub-1-ZEC dust floor (ZIP 318's `MAX_RESIDUAL_VALUE`), and leaves any residual below that floor as
  source-pool change rather than folded into a fee. The fee model is pluggable via the `FeePolicy`
  trait (`Zip317FeePolicy` provided), and the maximum denomination, dust floor, and note cap are
  strategy parameters. `plan_note_split` is a convenience wrapper over the recommended
  `CanonicalOneTwoFive`. Depends on `zcash_protocol`, `zcash_primitives`, and `rand_core`.
