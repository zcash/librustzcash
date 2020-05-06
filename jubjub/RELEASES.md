# 0.3.0

This release now depends on the `bls12_381` crate, which exposes the `Fq` field type that we re-export.

* The `Fq` and `Fr` field types now have better constant function support for various operations and constructors.
* We no longer depend on the `byteorder` crate.
* We've bumped our `rand_core` dev-dependency up to 0.5.
* We've removed the `std` and `nightly` features.
* We've bumped our dependency of `subtle` up to `^2.2.1`.

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
