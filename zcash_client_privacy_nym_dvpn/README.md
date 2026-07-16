# zcash_client_privacy_nym_dvpn

Experimental [Nym](https://nymtech.net) **`smol-dvpn`** (userspace WireGuard dVPN)
network-privacy backend for Zcash `lightwalletd` clients.

This crate provides `dvpn::DvpnNetwork`, an implementation of
[`zcash_client_backend::privacy::PrivateNetwork`] that tunnels a wallet's traffic through a
Nym `smol-dvpn` 1-/2-hop WireGuard tunnel. Provisioning (turning a funded NYX session into
tunnel material) lives in `dvpn::provision`, kept decoupled from the datapath in
object-capability style.

> **Status: experimental, and currently NOT BUILDABLE against this `zcash_client_backend`
> revision.** See [Build status](#-build-status-blocked) below. The source is complete and
> written against the real `nym-smol-dvpn` / `nym-sdk-session` API, ready to build once the
> upstream dependency conflict is resolved.

## Privacy semantics (read this)

`DvpnNetwork` is a **dVPN, not a mixnet**. It hides the client's IP address from the
destination (and, in 2-hop mode, splits knowledge of source and destination across two
gateways), but it performs **no Sphinx packet mixing and adds no cover traffic**. Traffic
timing and volume are not obscured, so it does not resist a global passive traffic-analysis
adversary. Its guarantees are weaker than Tor's and much weaker than a true mixnet's (such
as the sibling [`zcash_client_privacy_nym`](../zcash_client_privacy_nym) crate's
mixnet-proxy backend). Unlike that backend, it *can* reach arbitrary hosts, so it works as
a general-purpose Tor replacement.

**Credentials / economics:** dVPN gateways are paid. A tunnel is built from zk-nym
**ticketbooks** issued against a funded **NYX mnemonic**. Provisioning is caller-supplied
and decoupled from the datapath: a `DvpnNetwork` is built from a `DvpnConfig` that carries
only registered WireGuard peer material, never a mnemonic. The `dvpn::provision` module
performs the funded registration (`Session::ensure_ticketbooks`, `register_single_hop` /
`register_two_hop` / `register_two_hop_quic`) and yields a `DvpnConfig`.

### Isolation and dormancy

- `isolated_handle()` returns a handle sharing the **same** tunnel (and WireGuard session).
  **Isolation is best-effort only** — traffic through the returned handle is *not*
  network-level unlinkable from the original. A genuinely-isolated tunnel requires a fresh
  registration + ticketbook; build a second `DvpnNetwork` from independently-provisioned
  material. (A built-in fresh-tunnel-per-isolation-domain mode is left as future work; it
  would recouple the datapath to provisioning.)
- `set_dormant(Soft)` tears the tunnel down and rebuilds it lazily (from the retained peer
  material, with **no** re-registration) on the next `connect()`.

## ⚠️ Build status: blocked

**`cargo` cannot currently produce a lockfile for this crate.** The Nym `git` dependency
tree and `zcash_client_backend` have an irreconcilable transitive version conflict on
`crypto-common`:

- `zcash_client_backend` → `zcash_primitives` pins **`crypto-common = "=0.2.0-rc.1"`**
  (deliberately; the librustzcash workspace comment notes "later RCs require edition2024").
- The Nym `smol-dvpn` credential stack requires a **newer** `crypto-common`:

  ```text
  nym-smol-dvpn / nym-sdk-session
    └─ nym-credentials-interface → nym-upgrade-mode-check → jwt-simple (naive_jwt)
         └─ superboring (pure-rust)
              ├─ aes-keywrap → aes → cipher  →  crypto-common >= 0.2.0-rc.5
              └─ ml-dsa                       →  crypto-common ^0.2 (>= 0.2.1)
  ```

No single `crypto-common` version satisfies both `=0.2.0-rc.1` and `>= 0.2.0-rc.5`, so
resolution fails. The conflict is structural, not a defect in this crate.

The version matrix has no escape for `jwt-simple >= 0.12.12` (the floor the Nym crates
require):

- `jwt-simple 0.12.15+` uses `rand ^0.8.6` but pulls `superboring >= 0.1.8`, which hard-deps
  `aes-keywrap` → `crypto-common >= 0.2.0-rc.5` (conflict above).
- `jwt-simple 0.12.12`/`0.12.13` can use `superboring 0.1.5` (no `aes-keywrap`, no `ml-dsa`,
  `crypto-common` compatible), but they hard-pin **`rand = 0.8.5`**, which conflicts with
  the Nym git crates' `rand ^0.8.6`.

### What would unblock it

Any one of:

1. `zcash` advancing its pinned `crypto-common` past `rc.1` (its edition-2024 era), so it
   can share `crypto-common >= 0.2.0-rc.5` with the Nym stack; **or**
2. the Nym `smol-dvpn` credential stack relaxing to a `crypto-common`-`rc.1`-compatible set
   (e.g. `jwt-simple` with `superboring <= 0.1.5`, and `rand ^0.8.5` throughout the git
   crates); **or**
3. an upstream Nym release that removes the `jwt-simple`/`superboring` credential path from
   the `smol-dvpn` datapath.

Until then this crate is retained as a complete, reviewed artifact. Its `Cargo.toml` pins
the studied Nym monorepo revision (`1fd9ae8817b2c6e49283e8e5597f031ce7f6091c`).

## MSRV

Like its sibling, this crate would require **Rust >= 1.89** once buildable (the Nym tree
pulls `libcrux-psq 0.0.8`, which does not compile on 1.88).

## License

Licensed under either of

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.
