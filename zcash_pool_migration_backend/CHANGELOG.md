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
  `CanonicalOneTwoFive`. The crate is `no_std` (it needs only `alloc`), depending on
  `zcash_protocol`, `zcash_primitives`, and `rand_core`.
- The pure PCZT split builder (the `build` module, behind the `orchard` feature):
  `build_split_pczt` (and `build_split_pczt_for_plan`, which reads a `NoteSplitPlan`'s
  `migration_outputs`) turn the split plan plus the cryptographic ingredients a wallet supplies (the
  spendable Orchard notes and their witnesses, the anchor, the full viewing key) into an unproven
  `pczt::Pczt` for the same-pool send-to-self that mints the self-funding notes, plus a `SplitOutputs`
  mapping each output to its real Orchard action index. It is pure (no database or wallet-backend
  access) and takes the RNG as a parameter. `finalize_split_outputs` keeps each migration note at its
  exact planned value and reconciles the real ZIP-317 fee against the plan by adding a plain change
  output (or, for a sub-action-fee leftover, folding it into the fee). The shared transaction-builder
  plumbing (build config, PCZT finalization, action-index mapping, fees) is factored into the module
  root so the transfer builder reuses it. Adds optional `orchard` and `pczt` dependencies, enabled
  only by the feature.
- The pure PCZT transfer builder (`build::build_transfer_pczt`, behind the `orchard` feature): spends
  one self-funding note the split minted and outputs its crossing value into the Ironwood pool as an
  unproven `pczt::Pczt`, sent to the account's own internal Ironwood change address (derived inside the
  builder, per ZIP 318). It has no change output; the note's fee buffer funds the transfer's fee
  exactly (the Orchard spend and the Ironwood output each pad to the two-action minimum, so the
  transfer is four logical actions, matching the buffer of `2 source + 2 destination` actions). It
  runs post-NU6.3 (when the Ironwood pool is live), and like the split builder is pure (no database
  or wallet-backend access) and takes the RNG as a parameter.
- Pre-signing (`build::sign_pczt`, behind the `orchard` feature): adds the Orchard spend-authorization
  signatures for a given `orchard::keys::SpendAuthorizingKey` to an assembled migration PCZT, leaving
  the spends the key does not own (the builder's dummy spends, and any spend from another account)
  unsigned. It signs a finalized but still UNPROVEN PCZT: the spend-authorization signature is over
  the transaction's sighash, which is fixed independently of the zk proofs, so the migration signs up
  front (capturing the account's authorization) and proves later, at scheduling time.
