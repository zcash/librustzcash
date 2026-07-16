//! Object-capability dVPN provisioning: turning a funded [`Session`] into datapath
//! material.
//!
//! Building a [`super::DvpnNetwork`] requires WireGuard peer material that has been
//! registered with dVPN gateways and paid for with zk-nym ticketbooks. That step needs a
//! **funded NYX mnemonic** and is intentionally separated from the connection path here,
//! so the datapath ([`super::DvpnNetwork`] / [`super::DvpnConfig`]) never touches a
//! mnemonic.
//!
//! Typical use: construct a [`nym_sdk_session::SessionConfig`] (with the funded mnemonic
//! and network details) elsewhere, hand it to [`provision`] together with the desired
//! [`HopTopology`], and receive a [`super::DvpnConfig`] that can be used to build (and
//! later lazily rebuild) a tunnel without any further on-chain activity.
//!
//! This module is compiled only with the `dvpn` feature; callers that already hold
//! registered [`nym_smol_dvpn::PeerConfig`] material can skip it entirely and build a
//! [`super::DvpnConfig`] directly.

use nym_sdk_session::{GatewaySpec, HopConfig, QuicBridge, Registration, Session, SessionConfig};
use nym_smol_dvpn::{BridgeParams, PeerConfig};
use tokio_util::sync::CancellationToken;

use super::{DvpnConfig, Error, TunnelParams};

/// The gateway selection for each hop of a tunnel to be provisioned.
///
/// Each [`GatewaySpec`] selects a gateway by exact identity, by country, or at random.
pub enum HopTopology {
    /// A single-hop tunnel through one gateway.
    SingleHop {
        /// The sole gateway.
        gateway: GatewaySpec,
    },
    /// A two-hop tunnel (entry then exit gateway).
    TwoHop {
        /// The entry gateway.
        entry: GatewaySpec,
        /// The exit gateway.
        exit: GatewaySpec,
    },
    /// A two-hop tunnel whose entry leg is carried over a QUIC bridge.
    TwoHopQuic {
        /// The entry gateway.
        entry: GatewaySpec,
        /// The exit gateway.
        exit: GatewaySpec,
    },
}

impl HopTopology {
    fn is_two_hop(&self) -> bool {
        !matches!(self, HopTopology::SingleHop { .. })
    }

    fn uses_quic(&self) -> bool {
        matches!(self, HopTopology::TwoHopQuic { .. })
    }
}

/// Provisions dVPN datapath material from a funded session.
///
/// This performs the paid, on-chain-touching steps: it opens a [`Session`], ensures the
/// required zk-nym ticketbooks exist (issuing them from the session's funded mnemonic if
/// necessary), and registers with the selected gateways. The returned [`DvpnConfig`]
/// carries only the resulting WireGuard peer material and can be reused to build tunnels
/// repeatedly without re-registering.
///
/// `cancel` allows the (potentially long-running) provisioning to be aborted.
pub async fn provision(
    config: SessionConfig,
    topology: HopTopology,
    cancel: CancellationToken,
) -> Result<DvpnConfig, Error> {
    let session = Session::new(config, cancel).await.map_err(Error::Session)?;

    session
        .ensure_ticketbooks(topology.is_two_hop())
        .await
        .map_err(Error::Session)?;

    let registration = match &topology {
        HopTopology::SingleHop { gateway } => session.register_single_hop(gateway).await,
        HopTopology::TwoHop { entry, exit } => session.register_two_hop(entry, exit).await,
        HopTopology::TwoHopQuic { entry, exit } => session.register_two_hop_quic(entry, exit).await,
    }
    .map_err(Error::Session)?;

    DvpnConfig::from_registration(&registration, topology.uses_quic())
}

impl DvpnConfig {
    /// Builds a datapath configuration from a completed [`Registration`].
    ///
    /// `use_quic` selects the QUIC-bridged two-hop mode; it is only meaningful for a
    /// two-hop registration and requires the entry hop to carry bridge material (otherwise
    /// [`Error::MissingBridge`] is returned).
    pub fn from_registration(registration: &Registration, use_quic: bool) -> Result<Self, Error> {
        let entry = peer_from_hop(&registration.entry);

        let params = match &registration.exit {
            None => TunnelParams::SingleHop { gateway: entry },
            Some(exit_hop) => {
                let exit = peer_from_hop(exit_hop);
                if use_quic {
                    let bridge = registration
                        .entry
                        .bridge
                        .as_ref()
                        .ok_or(Error::MissingBridge)?;
                    TunnelParams::TwoHopQuic {
                        entry,
                        exit,
                        bridge: bridge_params(bridge),
                    }
                } else {
                    TunnelParams::TwoHop { entry, exit }
                }
            }
        };

        Ok(DvpnConfig::new(params))
    }
}

/// Maps a session-layer [`HopConfig`] to a datapath [`PeerConfig`].
fn peer_from_hop(hop: &HopConfig) -> PeerConfig {
    PeerConfig {
        gateway_public_key: hop.wg_config.public_key.to_bytes(),
        client_private_key: hop.client_private_key.to_bytes(),
        preshared_key: hop.wg_config.psk.as_ref().map(|psk| *psk.as_bytes()),
        endpoint: hop.wg_config.endpoint,
        assigned_ipv4: hop.wg_config.private_ipv4,
        assigned_ipv6: Some(hop.wg_config.private_ipv6),
    }
}

/// Maps session-layer [`QuicBridge`] parameters to datapath [`BridgeParams`].
fn bridge_params(bridge: &QuicBridge) -> BridgeParams {
    BridgeParams {
        addresses: bridge.addresses.clone(),
        sni_host: bridge.sni_host.clone(),
        id_pubkey_base64: bridge.id_pubkey_base64.clone(),
    }
}
