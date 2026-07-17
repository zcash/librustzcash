# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog], and this crate adheres to Rust's notion of
[Semantic Versioning].

## [Unreleased]

### Added

- Initial (experimental) release of `zcash_client_privacy_nym`, providing a
  [`zcash_client_backend::privacy::PrivateNetwork`] backend built on the
  [Nym](https://nymtech.net) Sphinx mixnet:
  - `mixnet-proxy` feature: `mixnet_proxy::MixnetProxyNetwork`, which reaches a fixed set of
    pre-configured endpoints — each fronted by a `mixnet_proxy::proxy_listener::ProxyListener`
    — over the Nym mixnet (via `nym-sdk`). Provides Sphinx mixing and cover traffic for the
    wallet↔proxy path.
  - `mixnet_proxy::proxy_listener::ProxyListener`, the server-side helper that accepts
    inbound mixnet streams and forwards them to a TCP upstream (run by `lightwalletd`
    operators; also used by the in-process end-to-end test).

This crate is **experimental**, is deliberately excluded from the librustzcash workspace,
is unpublished, and has a higher MSRV than the workspace (Rust 1.89). See `README.md` for
its maturity and privacy caveats, and for the sibling dVPN backend crate.

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
