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
    zcash_client_backend --> pczt
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

    click zcash_address "https://docs.rs/zcash_address/" _blank
    click zcash_primitives "https://docs.rs/zcash_primitives/" _blank
    click zcash_transparent "https://docs.rs/zcash_transparent/" _blank
    click zcash_proofs "https://docs.rs/zcash_proofs/" _blank
    click zcash_protocol "https://docs.rs/zcash_protocol/" _blank
    click zcash_keys "https://docs.rs/zcash_keys/" _blank
    click zip321 "https://docs.rs/zip321/" _blank
    click pczt "https://docs.rs/pczt/" _blank
    click zcash_client_backend "https://docs.rs/zcash_client_backend/" _blank
    click zcash_client_sqlite "https://docs.rs/zcash_client_sqlite/" _blank
    click equihash "https://docs.rs/equihash/" _blank
    click f4jumble "https://docs.rs/f4jumble/" _blank
    click zcash_encoding "https://docs.rs/zcash_encoding/" _blank
    click sapling "https://docs.rs/sapling-crypto/" _blank
    click orchard "https://docs.rs/orchard/" _blank
    click zcash_note_encryption "https://docs.rs/zcash_note_encryption/" _blank
    click zip32 "https://docs.rs/zip32/" _blank
    click zcash_spec "https://docs.rs/zcash_spec/" _blank
```

### Crates

[librustzcash: a Rust Crates Walkthrough w/ nuttycom](https://free2z.cash/uploadz/public/ZcashTutorial/librustzcash-a-rust-crates.mp4)

#### Zcash Protocol

* `zcash_protocol`: Constants & common types
  - consensus parameters
  - bounded value types (Zatoshis, ZatBalance)
  - memo types
* `zcash_transparent`: Bitcoin-derived transparent transaction components
  - transparent addresses
  - transparent input, output, and bundle types
  - support for transparent parts of pczt construction
* `zcash_primitives`: Core utilities for working with Zcash transactions
  - the primary transaction data type
  - transaction builder(s)
  - proving, signing, & serialization
  - low-level fee types
* `zcash_proofs`: The Sprout circuit & proving system

#### Keys, Addresses & Wallet Support

* `zcash_address`: Parsing & serialization of Zcash addresses
  - unified address, fvk & ivk containers
  - no dependencies on protocol-specific types
  - serialization API definitions
* `zip321`: Parsing & serizalization for ZIP 321 payment requests
* `zcash_keys`: Spending Keys, Viewing Keys, & Addresses
  - protocol-specific & Unified address types
  - ZIP 32 key & address derivation implementations
  - Unified spending keys & viewing keys
  - Sapling spending & viewing key types
* `pczt`: Data types & interfaces for PCZT construction
  - partially constructed transaction types
  - transaction construction role interfaces & partial implementations
* `zcash_client_backend`: A wallet framework for Zcash
  - wallet data storage APIs
  - chain scanning
  - light client protocol support
  - fee calculation
  - transaction proposals & high-level transaction construction APIs
* `zcash_client_sqlite`: SQLite-based implementation of `zcash_client_backend` storage APIs

#### Utilities & Common Dependencies

* `f4jumble`: Encoding for Unified addresses
* `zcash_encoding`: Bitcoin-derived transaction encoding utilities for Zcash
* `equihash`: Proof-of-work protocol implementation


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
