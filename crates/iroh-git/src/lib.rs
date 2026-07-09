//! Shared types and helpers for sharing git repositories over iroh.
//!
//! Binaries built on this crate:
//! - `git-iroh`        - human porcelain (`git iroh show-id` / `grant` / `list` / `lfs-*`)
//! - `git-remote-iroh` - the git remote helper, invoked for `iroh://` URLs
//! - `git-lfs-iroh`    - the Git LFS custom transfer agent (objects over iroh)
//! - `iroh-git-daemon` - the long-running service that serves repositories

pub mod config;
pub mod identity;
pub mod lfs;
pub mod paths;
pub mod protocol;
pub mod share;
pub mod ticket;

use anyhow::{Context, Result};
use iroh::address_lookup::DnsAddressLookup;
use iroh::endpoint::{default_relay_mode, presets, Connection};
use iroh::{Endpoint, EndpointAddr, RelayUrl};

use crate::identity::Role;

pub use config::Grants;
pub use protocol::{LfsOp, LfsRequest, LfsResponse, Request, Response, Service};
pub use ticket::{RepoId, Ticket};

/// ALPN advertised by the daemon and dialed by the remote helper for the git
/// pack protocol.
pub const ALPN: &[u8] = b"iroh-git/0";

/// ALPN for the Git LFS sub-protocol. Advertised alongside [`ALPN`] by daemons
/// that support LFS; a client dialing this against an older daemon fails ALPN
/// negotiation cleanly, which is exactly the capability check we want.
pub const LFS_ALPN: &[u8] = b"iroh-git-lfs/0";

/// Dial the daemon named by `ticket` with the given `alpn`, using this machine's
/// persistent client identity. Returns the bound endpoint (keep it alive for the
/// connection's lifetime) and the connection. Shared by the `git-remote-iroh`
/// helper (pack) and [`lfs::Session`] (LFS) so the relay/identity wiring lives once.
pub async fn dial(ticket: &Ticket, alpn: &[u8]) -> Result<(Endpoint, Connection)> {
    let secret = identity::load_or_create(Role::Client)?;
    // Not presets::N0: that would add a PkarrPublisher announcing this client's
    // address record to n0's DNS service on every dial. Nothing ever dials the
    // client, so publish nothing. Keep the DNS *resolver* (fallback for tickets
    // without a relay hint) and the default relay mode (the dial reaches the
    // daemon through the relay named in the ticket).
    let endpoint = Endpoint::builder(presets::Minimal)
        .address_lookup(DnsAddressLookup::n0_dns())
        .relay_mode(default_relay_mode())
        .secret_key(secret)
        .bind()
        .await
        .map_err(|e| anyhow::anyhow!("binding endpoint: {e}"))?;

    let mut addr = EndpointAddr::new(ticket.node_id);
    if let Some(relay) = &ticket.relay_url {
        let relay: RelayUrl = relay.parse().context("ticket relay url")?;
        addr = addr.with_relay_url(relay);
    }
    let conn = endpoint
        .connect(addr, alpn)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to daemon: {e}"))?;
    Ok((endpoint, conn))
}
