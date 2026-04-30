# Light Wallet Protocol Canonical files

This repository contains the canonical Protobuf definitions for the Zcash Light Wallet protocol.

## Rationale
Before the creation of this repository, copies of wallet RPC `.proto` files existed in several
repositories across the Zcash ecosystem. This posed a challenge for protocol developers,
wallet maintainers, and infrastructure providers who would have to look up the _Ad Hoc_
canonical files for their own use and changes were hard to propagate and communicate. There was also
a danger of projects deploying incompatible changes, such as using the same field or tag number for
a new message field.

This repository IS _not_ a specification of the Zcash Light Client protocol. The Zcash Light Client
Protocol is described in [ZIP-307](https://zips.z.cash/zip-0307).

These files define the GRPC API for the ZIP 307 light wallet service using [proto 3](https://protobuf.dev/programming-guides/proto3/).

## How to use these files
We recommend using `git subtree` to update downstream repositories to use the lastest tagged versions
of this repository.

```git subtree --prefix=$(TARGET_PATH) pull git@github.com:zcash/lightwallet-protocol.git $(LATEST_VERSION) --squash```

### Example: YourProject
We assume YourProject is a git repository. Begin with a clean working tree.
(Pulling in lightwallet-protocol creates its own commit;
any changes you're making to your project should be in separate commits.)

You can install the `tree` command using your OS package manager of choice (although is not necessary).
(Replace the version tag with the appropriate one, usually the latest.)
```
$ cd YourProject
$ git subtree --prefix=lightwallet-protocol/ pull git@github.com:zcash/lightwallet-protocol.git v0.4.0 --squash
$ tree .
├── lightwallet-protocol
│   ├── LICENSE
│   └── walletrpc
│       ├── compact_formats.proto
│       └── service.proto
... (other directories)
```
## Current implementations
### Servers
- [Lightwalletd (Go)](https://github.com/zcash/lightwalletd/)
- [Zaino (Rust)](https://github.com/zingolabs/zaino)
### Clients
#### CLI and Dev Tooling
- [Zingo Lib CLI (Rust)](https://github.com/zingolabs/zingolib/)
- [Zcash dev-tool (Rust)](https://github.com/zcash/zcash-devtool)
- [zcash_client_backend Rust crate](https://docs.rs/zcash_client_backend/latest/zcash_client_backend/)
#### Light Wallets
- Zashi [[iOS](https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/) | [Android](https://github.com/Electric-Coin-Company/zcash-android-wallet-sdk/)]
- [Ywallet (Dart/Flutter)](https://github.com/hhanh00/zwallet)

## Discussing and developing the Zcash Light Client Protocol
Light client protocol development is steered by the [Light Client Working Group](https://github.com/zcash/lcwg).

This workgroup meets bi-weekly and is invite-only, but you can reach out through
[this channel](https://discord.com/channels/809218587167293450/809250822579028008)
of the Zcash R&D Discord server.
