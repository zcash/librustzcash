# jubjub [![Crates.io](https://img.shields.io/crates/v/jubjub.svg)](https://crates.io/crates/jubjub) #

This is an implementation of the **Jubjub** elliptic curve group and its associated fields.

* **This implementation has not been reviewed or audited. Use at your own risk.**
* This implementation targets Rust `1.28` or later.
* This crate is `#![no_std]` and so does not require the standard library.
* All operations are constant-time unless explicitly noted.

## [Documentation](https://docs.rs/jubjub)

Jubjub is the twisted Edwards curve `-x^2 + y^2 = 1 + d.x^2.y^2` of rational points over `GF(q)` with a subgroup of prime order `r` and cofactor `8`.

```
q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
d = -(10240/10241)
```

`GF(q)` is the scalar field of the BLS12-381 elliptic curve group. Jubjub is birationally equivalent to a Montgomery curve `y^2 = x^3 + Ax^2 + x` over the same field with `A = 40962`. `A` is the smallest integer such that `(A - 2) / 4` is a small integer, `A^2 - 4` is nonsquare in `GF(q)`, and the Montgomery curve and its quadratic twist have small cofactors `8` and `4`, respectively.

Please see [./doc/evidence/](./doc/evidence/) for supporting evidence that Jubjub meets the [SafeCurves](https://safecurves.cr.yp.to/index.html) criteria. The tool in [./doc/derive/](./doc/derive/) will derive the curve parameters via the above criteria.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
