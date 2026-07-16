//! Experimental [Nym](https://nymtech.net) mixnet-proxy network-privacy backend for Zcash
//! `lightwalletd` clients.
//!
//! This crate provides an implementation of
//! [`zcash_client_backend::privacy::PrivateNetwork`] that routes a wallet's traffic over
//! the Nym Sphinx mixnet, so that the gRPC, HTTP, and exchange-rate machinery in
//! [`zcash_client_backend::privacy`] can run over the mixnet instead of (or in addition
//! to) the reference Tor backend.
//!
//! The backend lives in [`mixnet_proxy`] (feature `mixnet-proxy`):
//! [`mixnet_proxy::MixnetProxyNetwork`] provides full Sphinx-mixnet privacy but can only
//! reach a fixed set of pre-configured endpoints, each fronted by a
//! [`mixnet_proxy::proxy_listener`]. See the crate `README.md` for the full privacy
//! semantics.
//!
//! # A note on the dVPN backend
//!
//! A sibling Nym backend — a `smol-dvpn` userspace-WireGuard dVPN — is implemented in the
//! separate crate `zcash_client_privacy_nym_dvpn` (a directory alongside this one). It is
//! kept separate because its `git`-only dependency tree currently cannot be resolved in
//! the same Cargo lockfile as `zcash_client_backend`; see that crate's `README.md` for
//! the precise, evidence-backed reason. Merging the two backends into one crate is
//! blocked until that conflict is resolved upstream.
//!
//! # Maturity
//!
//! **This crate is experimental.** It depends on rapidly-evolving Nym code, has not been
//! audited, and its privacy properties are design intent rather than independently-verified
//! guarantees. It is deliberately excluded from the librustzcash Cargo workspace and is
//! not published to crates.io.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "mixnet-proxy")]
#[cfg_attr(docsrs, doc(cfg(feature = "mixnet-proxy")))]
pub mod mixnet_proxy;
