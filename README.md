# Zcash Rust crates

This repository contains a (work-in-progress) set of Rust crates for working
with Zcash.

```mermaid
graph TB
    subgraph librustzcash
        direction TB
        subgraph main
        zcash_address
        zcash_primitives
        zcash_transparent
        zcash_proofs
        zcash_protocol
        pczt
        zcash_client_backend
        zcash_client_sqlite
        zcash_keys
        zip321
        end

        subgraph standalone_components
        equihash
        f4jumble
        zcash_encoding
        end
    end

    subgraph shielded_protocols
    sapling[sapling-crypto]
    orchard[orchard]
    end

    subgraph protocol_components
    zcash_note_encryption
    zip32
    zcash_spec
    end

    zcash_client_sqlite --> zcash_client_backend
    zcash_client_backend --> zcash_primitives
    zcash_client_backend --> zip321
    zcash_client_backend --> zcash_keys
    pczt --> zcash_primitives
    zcash_proofs --> zcash_primitives
    zcash_primitives --> zcash_protocol
    zcash_primitives --> equihash
    zcash_primitives --> zcash_encoding
    zcash_primitives --> zcash_address
    zcash_primitives --> zcash_transparent
    zcash_primitives --> sapling
    zcash_primitives --> orchard
    zcash_keys --> zcash_address
    zcash_keys --> zcash_encoding
    zcash_keys --> zip32
    zcash_keys --> zcash_transparent
    zcash_keys --> orchard
    zcash_keys --> sapling
    zcash_transparent --> zcash_protocol
    zcash_transparent --> zcash_address
    zcash_transparent --> zip32
    zip321 --> zcash_address
    zip321 --> zcash_protocol
    zcash_address --> zcash_protocol
    zcash_address --> f4jumble
    zcash_address --> zcash_encoding
    sapling --> zcash_note_encryption
    sapling --> zip32
    sapling --> zcash_spec
    orchard --> zcash_note_encryption
    orchard --> zip32
    orchard --> zcash_spec

    main --> standalone_components

    librustzcash --> shielded_protocols
    shielded_protocols --> protocol_components
```

## Security Warnings

These libraries are under development and have not been fully reviewed.

## License

All code in this workspace is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
