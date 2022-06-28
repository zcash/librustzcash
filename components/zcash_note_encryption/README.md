# zcash_note_encryption

This crate implements the [in-band secret distribution scheme] for the Sapling and
Orchard protocols. It provides reusable methods that implement common note encryption
and trial decryption logic, and enforce protocol-agnostic verification requirements.

Protocol-specific logic is handled via the `Domain` trait. Implementations of this
trait are provided in the [`zcash_primitives`] (for Sapling) and [`orchard`] crates;
users with their own existing types can similarly implement the trait themselves.

[in-band secret distribution scheme]: https://zips.z.cash/protocol/protocol.pdf#saplingandorchardinband
[`zcash_primitives`]: https://crates.io/crates/zcash_primitives
[`orchard`]: https://crates.io/crates/orchard

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Downstream code forks should note that 'zcash_note_encryption' depends on the
'orchard' crate, which is licensed under the
[Bootstrap Open Source License](https://github.com/zcash/orchard/blob/main/LICENSE-BOSL).
A license exception is provided allowing some derived works that are linked or
combined with the 'orchard' crate to be copied or distributed under the original
licenses (in this case MIT / Apache 2.0), provided that the included portions of
the 'orchard' code remain subject to BOSL.
See https://github.com/zcash/orchard/blob/main/COPYING for details of which
derived works can make use of this exception.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
