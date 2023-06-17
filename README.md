# Zcash Rust crates

This repository contains a (work-in-progress) set of Rust crates for
working with Zcash.

## Security Warnings

These libraries are currently under development and have not been fully-reviewed.

## Cross-Workspace Dependency Cycle

There is a complication in crate dependencies documented in
[`components/zcash_note_encryption/README.md`](./components/zcash_note_encryption/README.md)
and [issue #768](https://github.com/zcash/librustzcash/issues/768).

### `cargo doc` Warning

A consequence of the cross-workspace dependency above is that there's a name collision for the
two distinct `zcash_note_encryption` crates when running `cargo doc`:

```
warning: output filename collision.
The lib target `zcash_note_encryption` in package `zcash_note_encryption v0.4.0` has the same output filename as the lib target `zcash_note_encryption` in package `zcash_note_encryption v0.4.0 (/home/user/src/gi
thub.com/zcash/librustzcash/components/zcash_note_encryption)`.
Colliding filename is: /home/user/src/github.com/zcash/librustzcash/target/doc/zcash_note_encryption/index.html
```

**Workarounds:**

- To view rendered docs for the local crate run: `cargo doc -p zcash_note_encryption --open`
- To view docs for the released crate, see [docs.rs/zcash_note_encryption](https://docs.rs/zcash_note_encryption/).

## License

All code in this workspace is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Downstream code forks should note that some (but not all) of these crates
and components depend on the 'orchard' crate, which is licensed under the
[Bootstrap Open Source License](https://github.com/zcash/orchard/blob/main/LICENSE-BOSL).
A license exception is provided allowing some derived works that are linked or
combined with the 'orchard' crate to be copied or distributed under the original
licenses (in this case MIT / Apache 2.0), provided that the included portions of
the 'orchard' code remain subject to BOSL.
See <https://github.com/zcash/orchard/blob/main/COPYING> for details of which
derived works can make use of this exception, and the `README.md` files in
subdirectories for which crates and components this applies to.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
