//! Shared types and helpers for sharing git repositories over iroh.
//!
//! Three binaries build on this crate:
//! - `git-iroh`        - human porcelain (`git iroh show-id` / `grant` / `list`)
//! - `git-remote-iroh` - the git remote helper, invoked for `iroh://` URLs
//! - `iroh-git-daemon` - the long-running service that serves repositories

pub mod config;
pub mod identity;
pub mod paths;
pub mod protocol;
pub mod share;
pub mod ticket;

pub use config::Grants;
pub use protocol::{Request, Response, Service};
pub use ticket::{RepoId, Ticket};

/// ALPN advertised by the daemon and dialed by the remote helper.
pub const ALPN: &[u8] = b"iroh-git/0";
