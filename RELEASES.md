# 0.2.0

This release switches to `subtle 2.1` to bring in the `CtOption` type, and also makes a few useful API changes.

* Implemented `Mul<Fr>` for `AffineNielsPoint` and `ExtendedNielsPoint`
* Changed `AffinePoint::to_niels()` to be a `const` function so that constant curve points can be constructed without statics.
* Implemented `multiply_bits` for `AffineNielsPoint`, `ExtendedNielsPoint`
* Removed `CtOption` and replaced it with `CtOption` from `subtle` crate.
* Modified receivers of some methods to reduce stack usage
* Changed various `into_bytes` methods into `to_bytes`

# 0.1.0

Initial release.
