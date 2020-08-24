# 0.2.0

This release adds implementations of the `ff`, `group`, and `pairing` traits (with the
latter two being gated by the `groups` and `pairings` feature flags respectively).
Additional trait implementations (for standard traits) have been added where the `ff`,
`group`, and `pairing` trait bounds require them.

## Added
* `bls12_381::Bls12`, a `pairing::Engine` for BLS12-381 pairing operations. It implements
  the following traits:
  * `pairing::{Engine, MultiMillerLoop}`
* New trait implementations for `bls12_381::G1Projective`:
  * `group::{Curve, Group, GroupEncoding, WnafGroup}`
  * `group::prime::{PrimeCurve, PrimeGroup}`
* New trait implementations for `bls12_381::G1Affine`:
  * `group::{GroupEncoding, UncompressedEncoding}`
  * `group::prime::PrimeCurveAffine`
  * `pairing::PairingCurveAffine`
* New trait implementations for `bls12_381::G2Projective`:
  * `group::{Curve, Group, GroupEncoding, WnafGroup}`
  * `group::prime::{PrimeCurve, PrimeGroup}`
* New trait implementations for `bls12_381::G2Affine`:
  * `group::{GroupEncoding, UncompressedEncoding}`
  * `group::prime::PrimeCurveAffine`
  * `pairing::PairingCurveAffine`
* New trait implementations for `bls12_381::Gt`:
  * `group::Group`
* New trait implementations for `bls12_381::MillerLoopResult`:
  * `pairing::MillerLoopResult`
* New trait implementations for `bls12_381::Scalar`:
  * `ff::{Field, PrimeField}`

# 0.1.1

Added `clear_cofactor` methods to `G1Projective` and `G2Projective`. If the crate feature `endo`
is enabled the G2 cofactor clearing will use the curve endomorphism technique described by
[Budroni-Pintore](https://ia.cr/2017/419). If the crate feature `endo` is _not_ enabled then
the code will simulate the effects of the Budroni-Pintore cofactor clearing in order to keep
the API consistent. In September 2020, when patents US7110538B2 and US7995752B2 expire, the
endo feature will be made default. However, for now it must be explicitly enabled.

# 0.1.0

Initial release.
