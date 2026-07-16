# zcash_client_privacy_nym

Experimental [Nym](https://nymtech.net) **mixnet-proxy** network-privacy backend for Zcash
`lightwalletd` clients.

This crate provides an implementation of
[`zcash_client_backend::privacy::PrivateNetwork`] (behind the `mixnet-proxy` feature) so
that a wallet's `lightwalletd` gRPC traffic, HTTP requests, and exchange-rate lookups can
ride over the Nym Sphinx mixnet instead of (or in addition to) the reference Tor backend.

> **Status: experimental.** This backend is new, depends on rapidly-evolving Nym code, and
> has not been audited. The privacy properties below are the *design intent*; they have not
> been independently verified. Do not treat it as a drop-in replacement for Tor in a threat
> model that requires strong network anonymity until this crate leaves experimental status.

The crate is **excluded from the librustzcash Cargo workspace** (it carries its own
`Cargo.lock`), is **not published to crates.io**, and has a **higher MSRV than the
workspace** (see below).

> A sibling Nym backend — a `smol-dvpn` userspace-WireGuard dVPN — lives in the separate
> crate [`../zcash_client_privacy_nym_dvpn`](../zcash_client_privacy_nym_dvpn). It is kept
> separate because its `git`-only dependency tree currently cannot be resolved in the same
> Cargo lockfile as `zcash_client_backend`; see that crate's `README.md` for the full,
> evidence-backed reason.

## The `mixnet-proxy` backend

`mixnet_proxy::MixnetProxyNetwork` sends traffic through the full Nym **Sphinx mixnet**
(mixing + cover traffic) to a Nym `Recipient`. The mixnet is client-to-client, so it cannot
reach an arbitrary internet host directly: each reachable `lightwalletd` must be fronted by
a `mixnet_proxy::proxy_listener::ProxyListener` running next to it (typically operated by
the `lightwalletd` operator or a community). The backend is configured with a **routing
table** mapping each `(host, port)` to the `Recipient` address of its proxy listener.

**What it protects:** full Nym mixnet properties for the wallet↔proxy path — IP privacy
plus resistance to traffic-analysis by a global passive adversary (Sphinx mixing, cover
traffic, per-hop bit-unlinkability).

**What it does NOT provide:**

- It can only reach **pre-configured** endpoints; a `connect()` to any `(host, port)` not
  in the routing table returns [`zcash_client_backend::privacy::Error::NoRoute`].
- It requires proxy infrastructure to exist.
- The final hop (proxy → `lightwalletd`) is an ordinary TCP connection made by the proxy
  operator, so it does not hide the wallet's traffic from the proxy operator; run the proxy
  adjacent to (or co-operated with) the `lightwalletd` it fronts.

**Credentials / economics:** the Nym mixnet currently has a **free tier** that requires
**no credentials**. This backend builds clients in that free, ephemeral, no-credentials
mode by default (with optional persistent storage). This may change as Nym's economics
evolve.

### Isolation and dormancy

- `isolated_handle()` builds a **fresh ephemeral `MixnetClient`** (a new mixnet identity),
  which genuinely unlinks subsequent traffic. The fresh client is built lazily on first
  use.
- `set_dormant(Soft)` drops the underlying mixnet client and lazily rebuilds it on next
  use. A disconnected Nym mixnet client **cannot** reconnect, so "dormancy" is modelled as
  teardown + rebuild; expect a multi-second (~5–10s) reconnection cost on the next
  `connect()`. (The teardown is a synchronous, non-graceful drop rather than a full
  `MixnetClient::disconnect`.)

### Running a proxy listener

Operators run a `ProxyListener` next to a `lightwalletd`:

```rust,ignore
use zcash_client_privacy_nym::mixnet_proxy::proxy_listener::ProxyListener;

let proxy = ProxyListener::new_ephemeral("127.0.0.1:9067").await?;
println!("configure wallets with recipient: {}", proxy.nym_address());
proxy.run().await?; // accept mixnet streams, forward to the lightwalletd
```

Wallets then map that endpoint to the listener's address:

```rust,ignore
use zcash_client_privacy_nym::mixnet_proxy::{MixnetProxyConfig, MixnetProxyNetwork};

let config = MixnetProxyConfig::new().route("lightwalletd.example", 443, recipient);
let net = MixnetProxyNetwork::new(config);
```

## MSRV

This crate's effective MSRV is **Rust 1.89** — higher than the librustzcash workspace's
1.88. Its Nym dependency tree pulls `libcrux-psq 0.0.8`, which does not compile on rustc
1.88 (an upstream borrow-check pattern accepted from 1.89 onward). A crate-local
`rust-toolchain.toml` selects a compatible toolchain so `cargo` in this directory does not
inherit the repo-root 1.88 pin.

## Testing

Unit tests (no network) cover config/routing and the `NoRoute` behaviour:

```text
cargo test -p zcash_client_privacy_nym --features mixnet-proxy
```

There is also an `#[ignore]`d in-process end-to-end test that uses the **live, free** Nym
mixnet (spawns a local echo server, fronts it with a `ProxyListener`, and round-trips bytes
through a `MixnetProxyNetwork`). Run it explicitly:

```text
cargo test -p zcash_client_privacy_nym --features mixnet-proxy --test mixnet_proxy_e2e -- --ignored --nocapture
```

## License

Licensed under either of

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
