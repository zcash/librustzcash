//! A [`PrivateNetwork`] backed by the Nym `smol-dvpn` userspace WireGuard dVPN.
//!
//! [`DvpnNetwork`] wraps a `nym-smol-dvpn` [`Tunnel`] (1-hop, 2-hop, or 2-hop-QUIC) and
//! opens TCP streams through it. Because it is a full IP tunnel it can reach arbitrary
//! `host:port` endpoints, so it works as a drop-in replacement for the Tor backend when
//! talking to any `lightwalletd`.
//!
//! # Privacy semantics (read this)
//!
//! This backend is a **dVPN**, not a mixnet. It hides the client's IP address from the
//! destination (and, in 2-hop mode, splits knowledge of source and destination across two
//! gateways), but it performs **no Sphinx packet mixing and adds no cover traffic**.
//! Traffic timing and volume are not obscured, so it does not resist a global passive
//! traffic-analysis adversary. Its guarantees are weaker than Tor's and much weaker than a
//! Sphinx mixnet backend's (such as the sibling `zcash_client_privacy_nym` crate's
//! mixnet-proxy backend). Choose it deliberately.
//!
//! # Provisioning is decoupled from the datapath
//!
//! A [`DvpnNetwork`] is constructed from a [`DvpnConfig`], which carries only
//! already-registered WireGuard peer material ([`nym_smol_dvpn::PeerConfig`]). Obtaining
//! that material requires zk-nym ticketbooks funded from a NYX mnemonic; that
//! (object-capability) provisioning step lives in [`provision`] and is kept out of the
//! connection path, so a wallet never has to embed a mnemonic in its transport. Callers
//! that already hold registered peer material can build a [`DvpnConfig`] directly and skip
//! `provision` entirely.
//!
//! # Isolation and dormancy
//!
//! - [`PrivateNetwork::isolated_handle`] returns a handle sharing the **same** tunnel (and
//!   therefore the same WireGuard session). **Isolation is best-effort only**: traffic
//!   through the returned handle is not network-level unlinkable from this handle's. A
//!   genuinely-isolated tunnel requires a fresh registration + ticketbook; build a second
//!   [`DvpnNetwork`] from independently-provisioned material if you need that. (A built-in
//!   fresh-tunnel-per-isolation-domain mode is left as future work; it would couple the
//!   datapath back to provisioning.)
//! - [`PrivateNetwork::set_dormant`] with [`DormantMode::Soft`] tears the tunnel down and
//!   rebuilds it lazily (from the retained peer material, with no re-registration) on the
//!   next [`connect`](PrivateNetwork::connect).

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use nym_smol_dvpn::{BridgeParams, PeerConfig, TcpStream, Tunnel, TunnelBuilder, TunnelConfig};
use tokio::sync::Mutex as AsyncMutex;

use zcash_client_backend::privacy::{DormantMode, Error as PrivacyError, PrivateNetwork};

pub mod provision;

/// The WireGuard hop material for a dVPN tunnel.
///
/// Each variant selects one of the three `nym-smol-dvpn` tunnel modes. The contained
/// [`PeerConfig`]s are the already-registered per-hop WireGuard material (obtain them via
/// [`provision`] or from a caller-supplied registration).
#[derive(Clone)]
pub enum TunnelParams {
    /// A single-hop tunnel: the client connects directly to one dVPN gateway.
    SingleHop {
        /// The sole gateway hop.
        gateway: PeerConfig,
    },
    /// A two-hop tunnel: entry gateway then exit gateway (WireGuard-in-WireGuard).
    TwoHop {
        /// The entry gateway hop.
        entry: PeerConfig,
        /// The exit gateway hop.
        exit: PeerConfig,
    },
    /// A two-hop tunnel whose entry leg is carried over a QUIC bridge (useful where plain
    /// WireGuard UDP is blocked).
    TwoHopQuic {
        /// The entry gateway hop.
        entry: PeerConfig,
        /// The exit gateway hop.
        exit: PeerConfig,
        /// The QUIC bridge parameters for the entry leg.
        bridge: BridgeParams,
    },
}

/// Datapath configuration for a [`DvpnNetwork`].
///
/// This carries only registered peer material and tunnel tuning; it contains no
/// credentials or mnemonic. Build one with [`DvpnConfig::new`], optionally set a
/// [`TunnelConfig`] with [`DvpnConfig::with_tunnel_config`], or obtain one from a
/// [`nym_sdk_session::Registration`] via [`DvpnConfig::from_registration`].
#[derive(Clone)]
pub struct DvpnConfig {
    params: TunnelParams,
    tunnel_config: Option<TunnelConfig>,
}

impl DvpnConfig {
    /// Creates a datapath configuration from pre-registered tunnel material.
    pub fn new(params: TunnelParams) -> Self {
        Self {
            params,
            tunnel_config: None,
        }
    }

    /// Overrides the `nym-smol-dvpn` [`TunnelConfig`] (MTU, DNS mode, exit client port).
    ///
    /// When unset, `nym-smol-dvpn`'s own defaults are used.
    #[must_use]
    pub fn with_tunnel_config(mut self, config: TunnelConfig) -> Self {
        self.tunnel_config = Some(config);
        self
    }

    async fn build_tunnel(&self) -> Result<Tunnel, Error> {
        let mut builder = match &self.params {
            TunnelParams::SingleHop { gateway } => TunnelBuilder::single_hop(gateway.clone()),
            TunnelParams::TwoHop { entry, exit } => {
                TunnelBuilder::two_hop(entry.clone(), exit.clone())
            }
            TunnelParams::TwoHopQuic {
                entry,
                exit,
                bridge,
            } => TunnelBuilder::two_hop(entry.clone(), exit.clone()).quic_bridge(bridge.clone()),
        };
        if let Some(config) = &self.tunnel_config {
            builder = builder.config(config.clone());
        }
        builder.connect().await.map_err(Error::Tunnel)
    }
}

struct Inner {
    config: DvpnConfig,
    /// The current tunnel, if one is built. Guarded by a `std` mutex that is never held
    /// across an `await`, so that [`DvpnNetwork::set_dormant`] can clear it synchronously.
    tunnel: Mutex<Option<Arc<Tunnel>>>,
    /// Serializes tunnel (re)builds so a burst of concurrent `connect`s builds only once.
    build_lock: AsyncMutex<()>,
}

/// A [`PrivateNetwork`] that tunnels wallet traffic through a Nym `smol-dvpn` WireGuard
/// tunnel.
///
/// Cloning a `DvpnNetwork` yields another handle to the **same** tunnel; see the
/// module-level notes on isolation.
#[derive(Clone)]
pub struct DvpnNetwork {
    inner: Arc<Inner>,
}

impl DvpnNetwork {
    /// Creates a handle that builds its tunnel lazily on first use.
    ///
    /// No network activity happens until the first [`connect`](PrivateNetwork::connect).
    pub fn lazy(config: DvpnConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                tunnel: Mutex::new(None),
                build_lock: AsyncMutex::new(()),
            }),
        }
    }

    /// Builds the tunnel eagerly, returning an error if it cannot be established.
    ///
    /// Equivalent to [`DvpnNetwork::lazy`] followed by forcing the first connection, but
    /// surfaces tunnel-setup failures immediately rather than on first use.
    pub async fn connect(config: DvpnConfig) -> Result<Self, Error> {
        let net = Self::lazy(config);
        net.tunnel().await?;
        Ok(net)
    }

    /// Returns the current tunnel, building it if necessary.
    async fn tunnel(&self) -> Result<Arc<Tunnel>, Error> {
        // Fast path: a tunnel already exists.
        if let Some(tunnel) = self.current_tunnel() {
            return Ok(tunnel);
        }

        // Slow path: serialize builds, re-checking after acquiring the build lock so that
        // only the first waiter actually builds.
        let _guard = self.inner.build_lock.lock().await;
        if let Some(tunnel) = self.current_tunnel() {
            return Ok(tunnel);
        }

        let tunnel = Arc::new(self.inner.config.build_tunnel().await?);
        *self.inner.tunnel.lock().expect("tunnel mutex poisoned") = Some(tunnel.clone());
        Ok(tunnel)
    }

    fn current_tunnel(&self) -> Option<Arc<Tunnel>> {
        self.inner
            .tunnel
            .lock()
            .expect("tunnel mutex poisoned")
            .clone()
    }
}

impl PrivateNetwork for DvpnNetwork {
    type Stream = TcpStream;

    async fn connect(&self, host: &str, port: u16) -> Result<Self::Stream, PrivacyError> {
        let tunnel = self
            .tunnel()
            .await
            .map_err(|e| PrivacyError::Backend(Box::new(e)))?;
        tunnel
            .tcp_connect_host(host, port)
            .await
            .map_err(|e| PrivacyError::Backend(Box::new(Error::Tunnel(e))))
    }

    fn isolated_handle(&self) -> Self {
        // Best-effort: shares the same tunnel/WireGuard session. See the module docs.
        self.clone()
    }

    fn set_dormant(&self, mode: DormantMode) {
        match mode {
            // Drop the tunnel; it will be rebuilt lazily (no re-registration) on next use.
            // Dropping the `Arc` tears the tunnel down once the last handle releases it.
            DormantMode::Soft => {
                *self.inner.tunnel.lock().expect("tunnel mutex poisoned") = None;
            }
            // Nothing to wake; the tunnel is (re)built lazily on demand.
            DormantMode::Normal => {}
        }
    }
}

/// Errors that can occur while building or using a [`DvpnNetwork`].
#[derive(Debug)]
pub enum Error {
    /// An error from the `nym-smol-dvpn` tunnel (build, connect, or transfer).
    Tunnel(nym_smol_dvpn::DvpnError),
    /// An error from the `nym-sdk-session` provisioning path.
    Session(nym_sdk_session::SessionError),
    /// A QUIC two-hop tunnel was requested, but the entry hop carried no bridge material.
    MissingBridge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Tunnel(e) => write!(f, "dVPN tunnel error: {e}"),
            Error::Session(e) => write!(f, "dVPN provisioning error: {e}"),
            Error::MissingBridge => {
                write!(
                    f,
                    "QUIC two-hop requested but the entry hop has no bridge params"
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Tunnel(e) => Some(e),
            Error::Session(e) => Some(e),
            Error::MissingBridge => None,
        }
    }
}
