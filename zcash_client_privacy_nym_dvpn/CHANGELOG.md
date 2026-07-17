# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog], and this crate adheres to Rust's notion of
[Semantic Versioning].

## [Unreleased]

### Added

- Initial (experimental) implementation of `zcash_client_privacy_nym_dvpn`, providing a
  [`zcash_client_backend::privacy::PrivateNetwork`] backend built on the Nym `smol-dvpn`
  userspace WireGuard dVPN:
  - `dvpn::DvpnNetwork`, wrapping a `nym-smol-dvpn` `Tunnel` (1-hop, 2-hop, or 2-hop-QUIC)
    and opening TCP streams through it.
  - `dvpn::DvpnConfig` / `dvpn::TunnelParams`, the datapath configuration carrying
    already-registered WireGuard peer material (no credentials).
  - `dvpn::provision`, the object-capability provisioning path that turns a funded
    `nym-sdk-session` `Session` into a `DvpnConfig`.

### Known issues

- **This crate does not currently build.** Its Nym `git` credential stack requires
  `crypto-common >= 0.2.0-rc.5`, while `zcash_client_backend` pins
  `crypto-common = "=0.2.0-rc.1"`; `cargo` cannot resolve a lockfile satisfying both. See
  `README.md` for the full analysis and the conditions that would unblock it. The source is
  retained as a complete, reviewed artifact against the Nym monorepo revision
  `1fd9ae8817b2c6e49283e8e5597f031ce7f6091c`.

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
