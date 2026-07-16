//! Experimental Nym `smol-dvpn` network-privacy backend for Zcash `lightwalletd` clients.
//!
//! This crate provides [`dvpn::DvpnNetwork`], an implementation of
//! [`zcash_client_backend::privacy::PrivateNetwork`] that tunnels wallet traffic through a
//! Nym `smol-dvpn` userspace 1-/2-hop WireGuard dVPN. Its provisioning capability (turning
//! a funded NYX session into datapath material) lives in [`dvpn::provision`], kept
//! decoupled from the datapath in object-capability style.
//!
//! # Privacy semantics
//!
//! This backend is a **dVPN, not a mixnet**: it hides the client IP address but performs
//! **no** Sphinx mixing and adds **no** cover traffic. See the crate `README.md` and the
//! [`dvpn`] module docs for the full, honest privacy comparison, and for the isolation and
//! dormancy semantics.
//!
//! # ⚠️ Build status: currently blocked
//!
//! **This crate does not currently build against this revision of `zcash_client_backend`.**
//! Its Nym `git` dependency tree cannot be resolved in the same Cargo lockfile as
//! `zcash_client_backend`, because of a `crypto-common` version conflict:
//!
//! - `zcash_client_backend` (via `zcash_primitives`) pins `crypto-common = "=0.2.0-rc.1"`
//!   (deliberately — later release candidates require edition 2024).
//! - The Nym `smol-dvpn` credential stack requires a newer `crypto-common`
//!   (`nym-credentials` → `jwt-simple` → `superboring` → `aes-keywrap`/`ml-dsa` →
//!   `crypto-common >= 0.2.0-rc.5`).
//!
//! No single `crypto-common` version satisfies both, so `cargo` cannot produce a lockfile.
//! This is a genuine upstream-alignment problem, not a defect in this crate: the code here
//! is written and reviewed against the real `nym-smol-dvpn` / `nym-sdk-session` API and is
//! ready to build the moment the conflict is resolved (by `zcash`'s `crypto-common`
//! advancing past `rc.1`, or by the Nym credential stack relaxing its requirement). See
//! `README.md` for the full analysis.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod dvpn;
