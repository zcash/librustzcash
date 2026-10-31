# zcash_client_backend

This library contains Rust structs and traits for creating shielded Zcash light
clients.

## Building

Ordinary builds use the checked-in Protobuf bindings. After changing files in
`./proto/`, regenerate the bindings from a non-Windows source checkout with:

```sh
cargo check -p zcash_client_backend --features regenerate-protobuf
```

This requires `protoc` on your `$PATH` or specified by `PROTOC`. Use the same
version as the Protobuf consistency CI job. The `.proto` files are not included
in published crates, which always use the checked-in bindings.

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

