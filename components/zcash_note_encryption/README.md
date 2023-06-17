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

## Cross-Workspace Dependency Cycle

There is a cross-workspace cyclic dependency: `zcash_client_backend` (local)
depends on [`orchard`](https://github.com/zcash/orchard) which depends on this crate
`zcash_note_encryption`. For this reason `zcash_client_backend` does not depend on the local
`zcash_note_encryption` crate, but rather the published crate release.

This issue is tracked in [#768](https://github.com/zcash/librustzcash/issues/768).

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
